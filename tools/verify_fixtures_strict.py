#!/usr/bin/env python3
# Verifies that every fixture line's AEAD tag ==
# BLAKE2b-MAC(key=0x00*32, data=AAD, digest_size=16)
# where AAD = frame bytes up to (but not including) the final length-prefixed tag field.
# Exits non-zero on the first mismatch.
import hashlib
import sys
from pathlib import Path
from typing import Tuple

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "fixtures"
KEY = bytes(32)  # 32 x 0x00


def tleb3_decode_len(buf: bytes, offset: int) -> Tuple[int, int]:
    i = offset
    trits = []
    while True:
        if i >= len(buf):
            raise ValueError("EOF in TLEB3")
        b = buf[i]
        i += 1
        if b <= 242:
            val = b
            out = [0, 0, 0, 0, 0]
            for j in range(4, -1, -1):
                out[j] = val % 3
                val //= 3
            trits.extend(out)
        elif 243 <= b <= 246:
            k = (b - 243) + 1
            if i >= len(buf):
                raise ValueError("EOF tail")
            val = buf[i]
            i += 1
            group = [0] * k
            for j in range(k - 1, -1, -1):
                group[j] = val % 3
                val //= 3
            trits.extend(group)
        if len(trits) >= 3:
            val = 0
            used_trits = 0
            for j in range(0, len(trits) // 3):
                C, P1, P0 = trits[3 * j : 3 * j + 3]
                digit = P1 * 3 + P0
                val += digit * (9**j)
                if C == 0:
                    used_trits = (j + 1) * 3
                    break
            if used_trits:
                out = bytearray()
                x = 0
                while x + 5 <= used_trits:
                    v = 0
                    for t in trits[x : x + 5]:
                        v = v * 3 + t
                    out.append(v)
                    x += 5
                k = used_trits - x
                if k > 0:
                    out.append(243 + (k - 1))
                    v = 0
                    for t in trits[x:]:
                        v = v * 3 + t
                    out.append(v)
                return val, offset + len(out)


def get_aad_and_tag(frame: bytes):
    off = 0
    last_start = 0
    while off < len(frame):
        n, val_off = tleb3_decode_len(frame, off)
        last_start = off
        off = val_off + n
    tag_len, tag_off = tleb3_decode_len(frame, last_start)
    aad = frame[:last_start]
    tag = frame[tag_off : tag_off + tag_len]
    return aad, tag


def verify_file(fx_name: str, nx_name: str) -> None:
    path = FX / fx_name
    if not path.exists():
        return
    for ln in path.read_text().splitlines():
        if not ln.strip() or ln.startswith("#"):
            continue
        name, hexs = ln.split(" ", 1)
        frame = bytes.fromhex(hexs.strip())
        aad, tag = get_aad_and_tag(frame)
        calc = hashlib.blake2b(aad, key=KEY, digest_size=16).digest()
        if calc != tag:
            print(
                f"[FAIL] AEAD tag mismatch: {fx_name}:{name}", file=sys.stderr
            )
            sys.exit(4)


def main():
    sets = [
        ("vectors_hex.txt", "vectors_hex.txt.nonces"),
        ("vectors_hex_stream_avrochunk.txt", "vectors_hex_stream_avrochunk.txt.nonces"),
        ("vectors_hex_unary_rich.txt", "vectors_hex_unary_rich.txt.nonces"),
        ("vectors_hex_stream_avronested.txt", "vectors_hex_stream_avronested.txt.nonces"),
        ("vectors_hex_pathB.txt", "vectors_hex_pathB.txt.nonces"),
        ("vectors_hex_pathB_stream.txt", "vectors_hex_pathB_stream.txt.nonces"),
    ]
    for f, n in sets:
        verify_file(f, n)
    print("[OK] All fixture AEAD tags verified under BLAKE2b-MAC.")


if __name__ == "__main__":
    main()
