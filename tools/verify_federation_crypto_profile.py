#!/usr/bin/env python3
"""Verify Merkle-log federation crypto profiles — FIPS for the P2P knowledge-log layer.

The federation stacks (SSB / Hypercore-Dat / IPFS, Merkle-DAG) secure a CONTENT HASH and a feed
SIGNATURE. mode:fips requires a FIPS-approved hash (SHA-2/SHA-3) and a FIPS 186-5 signature (ECDSA /
RSA / EdDSA). The genuine non-FIPS default is the HASH — BLAKE2b (SSB/Hypercore) and BLAKE3 (IPFS)
are refused; Ed25519/Ed448 pass under 186-5. Self-testing (stdlib): fips-ecdsa + fips-eddsa +
standard pass; fips-blake2b + fips-blake3 rejected. A validate_schema drift-guard keeps them in sync.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "jsonschema" / "federation-crypto-profile.v0.schema.json"
EX = ROOT / "examples" / "transport"
VALID = [EX / "federation_crypto_profile.fips-ecdsa.example.json",
         EX / "federation_crypto_profile.fips-eddsa.example.json",
         EX / "federation_crypto_profile.standard.example.json"]
INVALID = [EX / "federation_crypto_profile.fips-blake2b.invalid.json",
           EX / "federation_crypto_profile.fips-blake3.invalid.json"]

FIPS_HASH = {"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"}          # FIPS 180-4 / 202
FIPS_SIG = {"ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "RSA-3072", "RSA-4096",  # FIPS 186-5
            "Ed25519", "Ed448"}                                               # EdDSA, approved in 186-5
KEYS = {"profileId", "mode", "contentHash", "signature", "contentAddressing"}


class FedError(Exception):
    pass


def fail(m: str) -> None:
    raise FedError(m)


def load(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def verify(rec: Any) -> None:
    if not isinstance(rec, dict) or sorted(set(rec) - KEYS):
        fail(f"unexpected/invalid fields: {sorted(set(rec) - KEYS)}")
    if not isinstance(rec.get("profileId"), str) or not rec["profileId"]:
        fail("profileId: expected non-empty string")
    if rec.get("mode") not in ("fips", "standard"):
        fail("mode must be 'fips' or 'standard'")
    ch, sig = rec.get("contentHash"), rec.get("signature")
    if not isinstance(ch, str) or not isinstance(sig, str):
        fail("contentHash and signature are required strings")
    if rec["mode"] == "fips":
        if ch not in FIPS_HASH:
            fail(f"FIPS mode requires a FIPS hash {sorted(FIPS_HASH)} — {ch!r} (BLAKE2b/BLAKE3) is refused")
        if sig not in FIPS_SIG:
            fail(f"FIPS mode requires a FIPS 186-5 signature {sorted(FIPS_SIG)} — {sig!r} refused")


def validate_schema(schema: Any) -> None:
    if not isinstance(schema, dict) or schema.get("additionalProperties") is not False:
        fail("schema root must be strict")
    props = schema.get("properties", {})
    if props.get("mode", {}).get("enum") != ["fips", "standard"]:
        fail("schema mode enum drifted")
    if not FIPS_HASH <= set(props.get("contentHash", {}).get("enum", [])):
        fail("schema contentHash enum missing a FIPS hash the validator accepts")
    if not FIPS_SIG <= set(props.get("signature", {}).get("enum", [])):
        fail("schema signature enum missing a FIPS 186-5 signature the validator accepts")
    # the non-FIPS hashes MUST be offered (so standard mode can select them and fips can refuse them)
    if not {"BLAKE2b", "BLAKE3"} <= set(props.get("contentHash", {}).get("enum", [])):
        fail("schema must offer BLAKE2b/BLAKE3 (the non-FIPS defaults the gate refuses in fips mode)")


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
    print("OK: federation crypto profile validated (3 examples, 2 non-FIPS-hash-in-fips rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
