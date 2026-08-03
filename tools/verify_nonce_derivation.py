#!/usr/bin/env python3
"""Verify nonce/session derivation is unique + fail-closed (vNext hot-path gap #5).

Asserts: the derivation matches the frame AEAD lane (context||seq => 12 bytes) and equals the demo
provider's nonce for "TRPC"||seq; distinct (session, seq) yield distinct nonces; a bad context length
or an out-of-range sequence is refused; and the NonceLedger refuses reuse and non-monotonic sequences
within a session while allowing the same sequence under a DIFFERENT session. Determinism. Stdlib.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import nonce_derivation as nd  # noqa: E402

FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def refused(fn) -> bool:
    try:
        fn(); return False
    except nd.NonceError:
        return True


def main() -> int:
    # 1. matches the frame AEAD lane: "TRPC" || seq, 12 bytes.
    n1 = nd.derive_nonce(b"TRPC", 1)
    CHECKS["derive:matches-frame-lane"] = (n1 == b"TRPC" + (1).to_bytes(8, "big") and len(n1) == 12)
    # 2. distinct (session,seq) -> distinct nonces.
    seen = {nd.derive_nonce(b"TRPC", s) for s in range(1000)}
    seen |= {nd.derive_nonce(b"BEAC", s) for s in range(1000)}
    CHECKS["derive:distinct-inputs-distinct-nonces"] = (len(seen) == 2000)
    # 3. bad context length + out-of-range sequence refused.
    CHECKS["fail-closed:bad-context-len-refused"] = refused(lambda: nd.derive_nonce(b"TRP", 1))
    CHECKS["fail-closed:seq-overflow-refused"] = refused(lambda: nd.derive_nonce(b"TRPC", 1 << 64))
    CHECKS["fail-closed:negative-seq-refused"] = refused(lambda: nd.derive_nonce(b"TRPC", -1))
    # 4. ledger: monotonic ok; reuse + non-monotonic refused; same seq under a different session ok.
    led = nd.NonceLedger()
    led.issue(b"SESA", 1); led.issue(b"SESA", 2); led.issue(b"SESA", 5)
    CHECKS["ledger:monotonic-issue-ok"] = True
    CHECKS["fail-closed:reuse-refused"] = refused(lambda: led.issue(b"SESA", 5))
    CHECKS["fail-closed:non-monotonic-refused"] = refused(lambda: led.issue(b"SESA", 3))
    led.issue(b"SESB", 1)  # same seq value, different session -> allowed
    CHECKS["ledger:cross-session-same-seq-ok"] = True
    # 5. determinism.
    CHECKS["deterministic"] = (nd.derive_nonce(b"TRPC", 42) == nd.derive_nonce(b"TRPC", 42))

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
