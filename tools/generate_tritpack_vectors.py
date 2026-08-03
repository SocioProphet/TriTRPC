#!/usr/bin/env python3
"""Generate canonical TritPack243 test vectors with the REAL reference codec.

Closes the 'ten canonical test frames' the whitepaper owes, at the primitive-codec level: for each
named trit sequence, emit the canonical TritPack243 bytes and a SHA3-256 digest of them, with the
pack->unpack round-trip asserted at generation. These are cross-language parity anchors — any port
(Rust/Go/TS) MUST reproduce identical bytes + digests. FIPS-clean: SHA3-256 is FIPS 202; the AEAD
suite is NOT baked in here — it is selected by the CryptoProfile (spec/transport/crypto_profile.md),
so these primitive vectors carry no non-FIPS cipher. Does not touch the wire (uses tritpack243_pack).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import tritrpc_v1 as t  # noqa: E402

OUT = ROOT / "fixtures" / "tritpack243_vectors.json"

# 10 canonical trit sequences (unbalanced ternary {0,1,2}, 5 trits/byte).
CASES = {
    "empty": [],
    "single-zero": [0],
    "single-max": [2],
    "one-byte-mixed": [0, 1, 2, 0, 1],
    "all-max-7": [2, 2, 2, 2, 2, 2, 2],
    "ascending-9": [0, 1, 2, 0, 1, 2, 0, 1, 2],
    "boundary-5": [2, 2, 2, 2, 2],
    "boundary-6": [2, 2, 2, 2, 2, 0],
    "long-zeros-20": [0] * 20,
    "pattern-31": ([1, 0, 2] * 11)[:31],
}


def build() -> dict:
    vectors = []
    for name, trits in CASES.items():
        packed = t.tritpack243_pack(trits)
        back = t.tritpack243_unpack(packed)[:len(trits)]
        if back != trits:
            raise SystemExit(f"round-trip FAILED for {name}: {trits} != {back}")
        vectors.append({
            "name": name,
            "trits": trits,
            "tritpack243_hex": packed.hex(),
            "sha3_256": hashlib.sha3_256(packed).hexdigest(),
        })
    return {
        "codec": "TritPack243",
        "alphabet": "unbalanced-ternary {0,1,2}, 5 trits/byte (3^5=243)",
        "digest": "SHA3-256 (FIPS 202) over the packed bytes",
        "aeadNote": "AEAD suite is selected by the CryptoProfile; not baked into these primitive vectors",
        "vectors": vectors,
    }


def main() -> int:
    OUT.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(CASES)} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
