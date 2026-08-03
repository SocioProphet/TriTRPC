#!/usr/bin/env python3
"""Verify v4 §15.1 suite-separation conformance — the matrix + the per-suite profile classes.

Three properties, all fail-closed:
  1. the required-suite gate's accept/refuse matches the monotone law (accept iff profileSuite >=
     requiredSuite) over the whole matrix — RECOMPUTED here and compared to the recorded fixture
     (recompute-don't-trust);
  2. each per-suite crypto profile the matrix anchors actually resolves to that suite;
  3. the CryptoProfile and FederationCryptoProfile validators both still pass (their approved suites
     accepted, their under-assured/non-FIPS profiles refused) — i.e. suite separation is enforced end
     to end. Stdlib, repo convention.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
sys.path.insert(0, str(ROOT / "tools"))
import suite_gate as sg  # noqa: E402
import verify_crypto_profile as vcp  # noqa: E402
import verify_federation_crypto_profile as vfp  # noqa: E402

FIX = ROOT / "fixtures" / "conformance" / "suite_separation_matrix.json"
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def main() -> int:
    vec = json.loads(FIX.read_text())

    # 1. Recompute the gate matrix and compare to the recorded fixture.
    ok_matrix = True
    for cell in vec["gateMatrix"]:
        r, p = cell["requiredSuite"], cell["profileSuite"]
        pack = {"policy": {"requiredSuite": r}}
        profile = {"suite": p}
        try:
            sg.require_suite(pack, profile)
            got = True
        except sg.SuiteError:
            got = False
        if got != cell["accept"] or cell["accept"] != (p >= r):
            ok_matrix = False
            FAILURES.append(f"matrix cell r={r} p={p}: expected accept={p>=r}, fixture={cell['accept']}, gate={got}")
    CHECKS["matrix:gate-matches-monotone-law"] = ok_matrix

    # 2. Each anchored crypto profile resolves to its claimed suite.
    ok_anchor = True
    for suite_str, rel in vec["cryptoProfilesBySuite"].items():
        prof = json.loads((ROOT / rel).read_text())
        if sg.profile_suite(prof) != int(suite_str):
            ok_anchor = False
            FAILURES.append(f"{rel} does not resolve to suite {suite_str}")
    CHECKS["anchors:profiles-resolve-to-suite"] = ok_anchor

    # 3. Both crypto validators still enforce separation (approved accepted, under-assured refused).
    CHECKS["separation:crypto-profile-validator-green"] = (vcp.main() == 0)
    CHECKS["separation:federation-validator-green"] = (vfp.main() == 0)

    for m in FAILURES:
        print(f"FAIL: {m}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
