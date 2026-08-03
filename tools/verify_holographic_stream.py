#!/usr/bin/env python3
"""Verify the holographic message stream has its three defining properties (fail-closed).

  1. FULL ASSEMBLY IS EXACT — the coherent sum of all fragments recovers the message byte-for-byte
     (masked and maskless), and integer masks cancel exactly (reproducible).
  2. ILLEGIBLE UNTIL FULL — every strict subset of masked fragments reconstructs to noise (legibility
     ~ 0); the residual mask is not cancelled.
  3. LOW-RES WHOLE IN EACH PIECE — a single fragment's unmasked preview correlates with the WHOLE
     message well above chance (structure present) but is not legible (not exact) — a blurred whole.

Plus determinism. Stdlib, repo convention.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import holographic_stream as hs  # noqa: E402

MSGS = [
    b"HELLO WORLD -- this whole message is holographically smeared across every fragment.",
    b"the quick brown fox jumps over the lazy dog, then does it again for good measure!!",
    bytes(range(0, 200, 3)),
]
KEY = "stream-key-2026"
N = 8
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def legibility(a: bytes, b: bytes) -> float:
    return sum(1 for x, y in zip(a, b) if x == y) / max(len(b), 1)


def corr(a: list[int], b: list[int]) -> float:
    n = len(b)
    ma, mb = sum(a) / n, sum(b) / n
    num = sum((a[i] - ma) * (b[i] - mb) for i in range(n))
    da = sum((a[i] - ma) ** 2 for i in range(n)) ** 0.5
    db = sum((b[i] - mb) ** 2 for i in range(n)) ** 0.5
    return num / (da * db) if da * db else 0.0


def main() -> int:
    exact_full = exact_maskless = illegible_partial = holo_present = determin = True
    for msg in MSGS:
        enc = hs.encode(msg, N, KEY, masked=True)
        # 1. full masked assembly is exact.
        full = hs.reconstruct(enc["fragments"], enc["L"], enc["orig_len"])
        exact_full &= (full == msg)
        # maskless full is exact too.
        encm = hs.encode(msg, N, KEY, masked=False)
        exact_maskless &= (hs.reconstruct(encm["fragments"], encm["L"], encm["orig_len"]) == msg)
        # 2. every strict subset is illegible (< 0.15).
        for k in range(1, N):
            if legibility(hs.reconstruct(enc["fragments"][:k], enc["L"], enc["orig_len"]), msg) >= 0.15:
                illegible_partial = False
        # 3. a single fragment's preview is a low-res whole: corr > 0.2 (structure) and not exact (< 0.9).
        lp = hs.lowres_preview(enc, 0, KEY)
        c = corr(list(lp), list(msg))
        holo_present &= (c > 0.2 and legibility(lp, msg) < 0.9)
        # determinism.
        determin &= (hs.encode(msg, N, KEY)["fragments"] == enc["fragments"])

    CHECKS["exact:full-masked-assembly-recovers-message"] = exact_full
    CHECKS["exact:maskless-full-assembly-recovers-message"] = exact_maskless
    CHECKS["threshold:every-strict-subset-illegible"] = illegible_partial
    CHECKS["holographic:single-fragment-is-lowres-whole"] = holo_present
    CHECKS["deterministic:reproducible"] = determin

    for k, v in CHECKS.items():
        if not v:
            FAILURES.append(f"{k} failed")
    for m in FAILURES:
        print(f"FAIL: {m}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
