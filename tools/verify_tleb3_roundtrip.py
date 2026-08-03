#!/usr/bin/env python3
"""Round-trip gate for TLEB3 length encode<->decode (wire primitive).

tleb3_len_decode was broken (raised 'trunc tail marker' for every value) because it unpacked one
byte at a time while TritPack243 tail markers are 2-byte sequences. This asserts encode->decode is
identity across boundary and multi-byte lengths, that stream decode stops exactly at the value
boundary (leaving trailing bytes intact), and that a truncated tail still fails closed. Encode (the
wire format) is unchanged; this locks the decoder's correctness in CI.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "reference"))
import tritrpc_v1 as t  # noqa: E402

# boundaries around the base-9 digit rollovers and the 5-trit TritPack243 group boundary
VALUES = [0, 1, 2, 8, 9, 10, 80, 81, 242, 243, 244, 300, 728, 729, 730,
          1000, 6560, 6561, 100000, 531440, 531441, 1_000_000]
TRAILER = b"\xAB\xCD\xEF"


def main() -> int:
    fails = []
    for n in VALUES:
        enc = t.tleb3_len_encode(n)
        v, off = t.tleb3_len_decode(enc, 0)
        if v != n or off != len(enc):
            fails.append(f"round-trip {n}: got value={v} offset={off} (enc {enc.hex()}, len {len(enc)})")
        # stream: decode must consume exactly enc and leave the trailer untouched
        v2, off2 = t.tleb3_len_decode(enc + TRAILER, 0)
        if v2 != n or (enc + TRAILER)[off2:] != TRAILER:
            fails.append(f"stream {n}: value={v2} offset={off2} did not stop at the boundary")
    # fail-closed: a truncated tail marker must raise, not silently mis-decode
    try:
        t.tleb3_len_decode(t.tleb3_len_encode(0)[:1], 0)
        fails.append("a truncated tail marker must raise ValueError, not decode")
    except ValueError:
        pass

    for m in fails:
        print(f"FAIL: {m}", file=sys.stderr)
    if fails:
        return 1
    print(f"OK: TLEB3 round-trip verified for {len(VALUES)} lengths (incl multi-byte) + stream + truncation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
