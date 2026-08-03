#!/usr/bin/env python3
"""Verify Q3 (qutrit/ternary) ECC profiles are VALID codes — multi-vendor interop gate.

Checks each declared code is a real code, not just well-typed:
  * RS-GF3m (classical-ternary): n = 3^m - 1, 1 <= k < n, t = floor((n-k)/2) >= 1 (and t matches);
  * ternary-stabilizer (qutrit-quantum): 0 <= k < n, d >= 1, quantum Singleton bound n-k >= 2(d-1).
The canonical default (RS over GF(9), [8,4], t=2) must be present and marked default. Self-testing:
the default + stabilizer examples pass; bad-blocklen + Singleton-violation are refused.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EX = ROOT / "examples" / "qutrit"
VALID = [EX / "q3_ecc_profile.default.example.json", EX / "q3_ecc_profile.stabilizer.example.json"]
INVALID = [EX / "q3_ecc_profile.bad-blocklen.invalid.json", EX / "q3_ecc_profile.singleton-violation.invalid.json"]


class ECCError(Exception):
    pass


def fail(m: str) -> None:
    raise ECCError(m)


def load(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def verify(p: Any) -> None:
    code = (p or {}).get("code") or {}
    kind = code.get("kind")
    if kind == "RS-GF3m":
        m, n, k = code.get("m"), code.get("n"), code.get("k")
        if not all(isinstance(x, int) for x in (m, n, k)):
            fail("RS-GF3m requires integer m, n, k")
        if n != 3 ** m - 1:
            fail(f"RS-GF3m block length must be 3^m-1 = {3 ** m - 1} over GF(3^{m}), got n={n}")
        if not (1 <= k < n):
            fail(f"RS-GF3m requires 1 <= k < n (k={k}, n={n})")
        t_exp = (n - k) // 2
        if t_exp < 1:
            fail("RS-GF3m corrects no errors (t = floor((n-k)/2) < 1)")
        if code.get("t") is not None and code["t"] != t_exp:
            fail(f"RS-GF3m t must equal floor((n-k)/2) = {t_exp}, got {code['t']}")
    elif kind == "ternary-stabilizer":
        n, k, d = code.get("n"), code.get("k"), code.get("d")
        if not all(isinstance(x, int) for x in (n, k, d)):
            fail("ternary-stabilizer requires integer n, k, d")
        if not (0 <= k < n):
            fail(f"stabilizer requires 0 <= k < n (k={k}, n={n})")
        if d < 1:
            fail("stabilizer requires d >= 1")
        if (n - k) < 2 * (d - 1):
            fail(f"stabilizer violates the quantum Singleton bound n-k >= 2(d-1): {n - k} < {2 * (d - 1)}")
    else:
        fail(f"unknown code.kind {kind!r}")


def main() -> int:
    try:
        defaults = 0
        for path in VALID:
            p = load(path)
            verify(p)
            if p.get("default"):
                defaults += 1
                if not (p["rail"] == "classical-ternary" and p["code"] == {"kind": "RS-GF3m", "m": 2, "n": 8, "k": 4, "t": 2}):
                    fail("the default profile must be RS over GF(9): {m:2,n:8,k:4,t:2}")
        if defaults != 1:
            fail(f"exactly one canonical default profile required, found {defaults}")
        for path in INVALID:
            try:
                verify(load(path))
            except ECCError:
                continue
            fail(f"expected {path.name} to be rejected, but it passed")
    except ECCError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 2
    print("OK: Q3 ECC profiles valid (default RS-GF9 + stabilizer; 2 invalid codes rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
