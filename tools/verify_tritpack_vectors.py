#!/usr/bin/env python3
"""Verify the canonical TritPack243 vectors against the reference codec (recompute, don't trust).

For each vector: re-pack the trits with the reference codec and assert the bytes equal the recorded
tritpack243_hex; unpack the bytes and assert they equal the recorded trits (round-trip); recompute
SHA3-256 and assert it matches. This is the cross-language parity gate — a port that diverges on any
byte or digest fails here. Also confirms the digest is SHA3-256 (FIPS 202).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import tritrpc_v1 as t  # noqa: E402

VEC = ROOT / "fixtures" / "tritpack243_vectors.json"


def main() -> int:
    doc = json.loads(VEC.read_text(encoding="utf-8"))
    fails = []
    for v in doc["vectors"]:
        trits = v["trits"]
        packed = t.tritpack243_pack(trits)
        if packed.hex() != v["tritpack243_hex"]:
            fails.append(f"{v['name']}: pack bytes {packed.hex()} != recorded {v['tritpack243_hex']}")
            continue
        if t.tritpack243_unpack(packed)[:len(trits)] != trits:
            fails.append(f"{v['name']}: unpack did not round-trip to the recorded trits")
            continue
        if hashlib.sha3_256(packed).hexdigest() != v["sha3_256"]:
            fails.append(f"{v['name']}: SHA3-256 digest mismatch")
    if "SHA3-256" not in doc.get("digest", ""):
        fails.append("digest must be SHA3-256 (FIPS 202)")
    for m in fails:
        print(f"FAIL: {m}", file=sys.stderr)
    if fails:
        return 1
    print(f"OK: {len(doc['vectors'])} TritPack243 vectors verified (pack/unpack/SHA3-256 parity)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
