#!/usr/bin/env python3
"""Verify FederationCryptoProfile — FIPS/CNSA for the Merkle-log P2P layer, v4 suite-aligned (fail-closed).

Two surfaces gated: the content HASH (Merkle CIDs) and the feed SIGNATURE. Aligned to the v4 suite
selector (§13.4):

  * `mode` stays for back-compat; `suite` (absent => standard->0, fips->1) must be consistent.
  * suite 0 (research): BLAKE / non-186-5 permitted.
  * suite 1 (fips-classical): FIPS hash (SHA-2/3; BLAKE refused) + FIPS 186-5 signature (ECDSA/RSA/
    EdDSA) + approved-mode assertions (sign canonical bytes only, self-tests).
  * suite 2 (cnsa2-ready): SHA-384/512 + an ML-DSA-87 signature. An Ed25519/ECDSA feed claiming
    suite 2 is REFUSED (under-assured for CNSA).
  * suite 3 (reserved): refused.

Self-testing (stdlib) + a validate_schema drift-guard.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "jsonschema" / "federation-crypto-profile.v0.schema.json"
EX = ROOT / "examples" / "transport"
VALID = [EX / "federation_crypto_profile.fips-ecdsa.example.json", EX / "federation_crypto_profile.fips-eddsa.example.json",
         EX / "federation_crypto_profile.standard.example.json", EX / "federation_crypto_profile.cnsa.example.json"]
INVALID = [EX / "federation_crypto_profile.fips-blake2b.invalid.json", EX / "federation_crypto_profile.fips-blake3.invalid.json",
           EX / "federation_crypto_profile.cnsa-underassured.invalid.json", EX / "federation_crypto_profile.fips-no-approved-mode.invalid.json",
           EX / "federation_crypto_profile.suite-reserved.invalid.json"]

FIPS_HASH = {"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"}          # FIPS 180-4 / 202
FIPS_SIG = {"ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "RSA-3072", "RSA-4096",  # FIPS 186-5
            "Ed25519", "Ed448"}
CNSA_HASH = {"SHA-384", "SHA-512"}
CNSA_SIG = {"ML-DSA-87"}
KEYS = {"profileId", "mode", "suite", "contentHash", "signature", "approvedMode", "contentAddressing"}


class FedError(Exception):
    pass


def fail(m: str) -> None:
    raise FedError(m)


def load(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def derived_suite(rec: dict) -> int:
    return rec["suite"] if "suite" in rec else (1 if rec.get("mode") == "fips" else 0)


def verify(rec: Any) -> None:
    if not isinstance(rec, dict) or sorted(set(rec) - KEYS):
        fail(f"unexpected/invalid fields: {sorted(set(rec) - KEYS) if isinstance(rec, dict) else rec}")
    if not isinstance(rec.get("profileId"), str) or not rec["profileId"]:
        fail("profileId: expected non-empty string")
    if rec.get("mode") not in ("fips", "standard"):
        fail("mode must be 'fips' or 'standard'")
    ch, sig = rec.get("contentHash"), rec.get("signature")
    if not isinstance(ch, str) or not isinstance(sig, str):
        fail("contentHash and signature are required strings")

    suite = derived_suite(rec)
    if suite == 3:
        fail("suite 3 is reserved and MUST NOT be used")
    if suite == 0 and rec["mode"] != "standard":
        fail("suite 0 requires mode 'standard'")
    if suite in (1, 2) and rec["mode"] != "fips":
        fail(f"suite {suite} (approved) requires mode 'fips'")

    if suite >= 1:
        if ch not in FIPS_HASH:
            fail(f"approved suite requires a FIPS hash {sorted(FIPS_HASH)} — {ch!r} (BLAKE) refused")
        if sig not in FIPS_SIG | CNSA_SIG:
            fail(f"approved suite requires a FIPS 186-5 / CNSA signature — {sig!r} refused")
        am = rec.get("approvedMode")
        if not isinstance(am, dict):
            fail("approved suite (>=1) requires an approvedMode block (encode-before-auth, canonical-only, self-tests)")
        if am.get("encodeBeforeAuth") is not True or am.get("canonicalOnly") is not True or am.get("selfTests") is not True:
            fail("approved mode requires encodeBeforeAuth, canonicalOnly, and selfTests all true (§5.3/§5.6)")

    if suite == 2:
        if ch not in CNSA_HASH:
            fail(f"CNSA suite 2 requires SHA-384/512 — {ch!r} under-assured")
        if sig not in CNSA_SIG:
            fail(f"CNSA suite 2 requires an ML-DSA-87 signature — {sig!r} (e.g. Ed25519/ECDSA) under-assured")


def validate_schema(schema: Any) -> None:
    if not isinstance(schema, dict) or schema.get("additionalProperties") is not False:
        fail("schema root must be strict")
    props = schema.get("properties", {})
    if props.get("mode", {}).get("enum") != ["fips", "standard"]:
        fail("schema mode enum drifted")
    if props.get("suite", {}).get("enum") != [0, 1, 2, 3]:
        fail("schema suite enum drifted from the v4 selector")
    if not FIPS_HASH <= set(props.get("contentHash", {}).get("enum", [])):
        fail("schema contentHash enum missing a FIPS hash the validator accepts")
    if not (FIPS_SIG | CNSA_SIG) <= set(props.get("signature", {}).get("enum", [])):
        fail("schema signature enum missing a FIPS 186-5 / CNSA signature the validator accepts")
    if not {"BLAKE2b", "BLAKE3"} <= set(props.get("contentHash", {}).get("enum", [])):
        fail("schema must offer BLAKE2b/BLAKE3 (the non-FIPS defaults the gate refuses in approved suites)")


def main() -> int:
    try:
        validate_schema(load(SCHEMA))
        for p in VALID:
            verify(load(p))
        for p in INVALID:
            try:
                verify(load(p))
            except FedError:
                continue
            fail(f"expected {p.name} to be rejected, but it passed")
    except FedError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 2
    print(f"OK: federation crypto profile validated ({len(VALID)} suites accepted, {len(INVALID)} rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
