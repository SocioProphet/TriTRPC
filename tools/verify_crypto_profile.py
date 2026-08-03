#!/usr/bin/env python3
"""Verify TriTRPC crypto profiles — FIPS is the standard, aligned to the v4 suite selector (fail-closed).

The v1 lane is XChaCha20-Poly1305 (NOT FIPS). This gate makes the sealing suite a checkable choice
aligned to v4 §13.4 (suite 0 research / 1 fips-classical / 2 cnsa2-ready / 3 reserved):

  * `mode` stays for back-compat; `suite` (absent => standard->0, fips->1) MUST be consistent with it.
  * suite 0 (research): the v1 XChaCha20 lane is permitted.
  * suite 1 (fips-classical): FIPS-approved AEAD (AES-GCM/CCM) + hash (SHA-2/3); XChaCha/BLAKE refused;
    AND the approved-mode assertions (§13.5/§5.3-5.6): encode-before-authenticate, canonical-only,
    nonce/IV policy, RNG from the module, self-tests complete.
  * suite 2 (cnsa2-ready): STRICTER — AES-256-GCM only, SHA-384/512 only, and ML-KEM-1024 / ML-DSA-87
    when a KEM/signature is declared. A merely-FIPS profile (AES-128 / SHA-256) claiming suite 2 is
    REFUSED — this is the silent-under-assurance break, now closed.
  * suite 3 (reserved): refused.

Selects the sealing suite only; MUST NOT alter the v1/v4/vNext wire. Self-testing (stdlib) + a
validate_schema drift-guard.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "jsonschema" / "crypto-profile.v0.schema.json"
EX = ROOT / "examples" / "transport"
VALID = [EX / "crypto_profile.fips.example.json", EX / "crypto_profile.standard.example.json",
         EX / "crypto_profile.cnsa.example.json"]
INVALID = [EX / "crypto_profile.fips-chacha.invalid.json", EX / "crypto_profile.fips-blake.invalid.json",
           EX / "crypto_profile.cnsa-underassured.invalid.json", EX / "crypto_profile.fips-no-approved-mode.invalid.json",
           EX / "crypto_profile.suite-reserved.invalid.json", EX / "crypto_profile.suite-mode-mismatch.invalid.json"]

FIPS_AEAD = {"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "AES-256-CCM"}   # SP 800-38D
FIPS_HASH = {"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"}      # FIPS 180-4 / 202
CNSA_AEAD = {"AES-256-GCM"}
CNSA_HASH = {"SHA-384", "SHA-512"}
CNSA_KEM = {"ML-KEM-1024"}
CNSA_SIG = {"ML-DSA-87"}
KEYS = {"profileId", "mode", "suite", "aead", "hash", "kem", "sig", "approvedMode", "wireFormat"}


class CryptoError(Exception):
    pass


def fail(m: str) -> None:
    raise CryptoError(m)


def load(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def derived_suite(rec: dict) -> int:
    if "suite" in rec:
        return rec["suite"]
    return 1 if rec.get("mode") == "fips" else 0


def verify_profile(rec: Any) -> None:
    if not isinstance(rec, dict):
        fail("profile must be an object")
    if sorted(set(rec) - KEYS):
        fail(f"unexpected fields: {sorted(set(rec) - KEYS)}")
    if not isinstance(rec.get("profileId"), str) or not rec["profileId"]:
        fail("profileId: expected non-empty string")
    if rec.get("mode") not in ("fips", "standard"):
        fail("mode must be 'fips' or 'standard'")
    aead, h = rec.get("aead"), rec.get("hash")
    if not isinstance(aead, str) or not isinstance(h, str):
        fail("aead and hash are required strings")

    suite = derived_suite(rec)
    # suite <-> mode consistency.
    if suite == 3:
        fail("suite 3 is reserved and MUST NOT be used")
    if suite == 0 and rec["mode"] != "standard":
        fail("suite 0 (research-nonapproved) requires mode 'standard'")
    if suite in (1, 2) and rec["mode"] != "fips":
        fail(f"suite {suite} (approved) requires mode 'fips'")

    if suite >= 1:
        # FIPS classical floor.
        if aead not in FIPS_AEAD:
            fail(f"approved suite requires a FIPS-approved AEAD {sorted(FIPS_AEAD)} — {aead!r} refused")
        if h not in FIPS_HASH:
            fail(f"approved suite requires a FIPS-approved hash {sorted(FIPS_HASH)} — {h!r} refused")
        # Approved-mode assertions (§13.5 / §5.3-5.6).
        am = rec.get("approvedMode")
        if not isinstance(am, dict):
            fail("approved suite (>=1) requires an approvedMode block (encode-before-auth, canonical-only, nonce, RNG, self-tests)")
        if am.get("encodeBeforeAuth") is not True:
            fail("approved mode requires encodeBeforeAuth=true (§5.6 authenticate canonical bytes only)")
        if am.get("canonicalOnly") is not True:
            fail("approved mode requires canonicalOnly=true (§5.6 reject non-canonical encodings)")
        if am.get("rngSource") not in ("module", "approved-bound"):
            fail("approved mode requires rngSource from the validated module (§5.5)")
        if am.get("selfTests") is not True:
            fail("approved mode requires selfTests=true (§5.3 module self-tests complete)")

    if suite == 2:
        # CNSA 2.0 — stricter than FIPS classical. Catches the silent-under-assurance break.
        if aead not in CNSA_AEAD:
            fail(f"CNSA suite 2 requires AES-256-GCM — {aead!r} is under-assured for CNSA")
        if h not in CNSA_HASH:
            fail(f"CNSA suite 2 requires SHA-384/512 — {h!r} is under-assured for CNSA")
        if "kem" in rec and rec["kem"] not in CNSA_KEM:
            fail(f"CNSA suite 2 requires ML-KEM-1024 — {rec['kem']!r} refused")
        if "sig" in rec and rec["sig"] not in CNSA_SIG:
            fail(f"CNSA suite 2 requires ML-DSA-87 — {rec['sig']!r} refused")


def validate_schema(schema: Any) -> None:
    if not isinstance(schema, dict) or schema.get("additionalProperties") is not False:
        fail("schema root must be strict")
    props = schema.get("properties", {})
    if props.get("mode", {}).get("enum") != ["fips", "standard"]:
        fail("schema mode enum drifted")
    if props.get("suite", {}).get("enum") != [0, 1, 2, 3]:
        fail("schema suite enum drifted from the v4 selector (0/1/2/3)")
    if not FIPS_AEAD <= set(props.get("aead", {}).get("enum", [])):
        fail("schema aead enum missing a FIPS AEAD the validator accepts")
    if not FIPS_HASH <= set(props.get("hash", {}).get("enum", [])):
        fail("schema hash enum missing a FIPS hash the validator accepts")
    if not (CNSA_KEM <= set(props.get("kem", {}).get("enum", [])) and CNSA_SIG <= set(props.get("sig", {}).get("enum", []))):
        fail("schema kem/sig enum missing the CNSA PQC primitives the validator requires")


def main() -> int:
    try:
        validate_schema(load(SCHEMA))
        for path in VALID:
            verify_profile(load(path))
        for path in INVALID:
            try:
                verify_profile(load(path))
            except CryptoError:
                continue
            fail(f"expected {path.name} to be rejected, but it passed")
    except CryptoError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 2
    print(f"OK: crypto profile validated ({len(VALID)} suites accepted, {len(INVALID)} under-assured/non-FIPS rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
