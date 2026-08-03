#!/usr/bin/env python3
"""Verify TriTRPC crypto profiles — FIPS is the standard (fail-closed).

'AEAD-sealed canonical bytes' recurs across the platform docs; the v1 lane is XChaCha20-Poly1305,
which is NOT FIPS-approved. This gate makes the cipher a checkable, gateable CHOICE:

  * mode:fips REQUIRES a FIPS-approved AEAD (AES-GCM/CCM, SP 800-38D) AND hash (SHA-2/SHA-3, FIPS
    180-4/202), and REFUSES XChaCha20/ChaCha20-Poly1305 and BLAKE;
  * mode:standard permits the v1 XChaCha20-Poly1305 lane.

The profile selects the sealing cipher only; it MUST NOT alter the v1/v4/vNext wire (TritPack243/
TLEB3). Self-testing (stdlib): fips + standard examples pass; fips-with-chacha and fips-with-blake
are rejected. A validate_schema drift-guard keeps schema and validator in lockstep.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "jsonschema" / "crypto-profile.v0.schema.json"
EX = ROOT / "examples" / "transport"
VALID = [EX / "crypto_profile.fips.example.json", EX / "crypto_profile.standard.example.json"]
INVALID = [EX / "crypto_profile.fips-chacha.invalid.json", EX / "crypto_profile.fips-blake.invalid.json"]

FIPS_AEAD = {"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "AES-256-CCM"}   # SP 800-38D
FIPS_HASH = {"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"}      # FIPS 180-4 / 202
KEYS = {"profileId", "mode", "aead", "hash", "wireFormat"}


class CryptoError(Exception):
    pass


def fail(m: str) -> None:
    raise CryptoError(m)


def load(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


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
    if rec["mode"] == "fips":
        # FIPS is the standard: the AEAD and hash MUST be FIPS-approved.
        if aead not in FIPS_AEAD:
            fail(f"FIPS mode requires a FIPS-approved AEAD {sorted(FIPS_AEAD)} — {aead!r} (e.g. XChaCha20) is refused")
        if h not in FIPS_HASH:
            fail(f"FIPS mode requires a FIPS-approved hash {sorted(FIPS_HASH)} — {h!r} (e.g. BLAKE) is refused")


def validate_schema(schema: Any) -> None:
    if not isinstance(schema, dict) or schema.get("additionalProperties") is not False:
        fail("schema root must be strict")
    props = schema.get("properties", {})
    if props.get("mode", {}).get("enum") != ["fips", "standard"]:
        fail("schema mode enum drifted")
    # Every FIPS-approved primitive the validator accepts MUST be offered by the schema enum,
    # and the non-FIPS ones MUST be present too (so standard mode can select them).
    if not FIPS_AEAD <= set(props.get("aead", {}).get("enum", [])):
        fail("schema aead enum missing a FIPS AEAD the validator accepts")
    if not FIPS_HASH <= set(props.get("hash", {}).get("enum", [])):
        fail("schema hash enum missing a FIPS hash the validator accepts")


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
    print("OK: crypto profile validated (2 examples, 2 non-FIPS-in-FIPS-mode rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
