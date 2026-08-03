#!/usr/bin/env python3
"""Verify the suite gate refuses under-assured placement (fail-closed).

A CNSA-required (suite 2) workload MUST NOT run on a merely-FIPS (suite 1) or research (suite 0)
profile; a FIPS-required (suite 1) workload MUST NOT run on a research (suite 0) profile; a workload
with no requiredSuite (=> 0) runs anywhere. Profile suites resolve explicitly or derive from mode.
Stdlib self-test + a schema drift-guard that requiredSuite is an accepted policy field.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import suite_gate as sg  # noqa: E402

SCHEMA = ROOT / "schemas" / "jsonschema" / "work-unit-pack.v0.schema.json"
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def pack(req=None):
    p = {"wu_id": "wu-x", "policy": {"residency": "EU", "isolation": "strong", "slo_ms": 1000}}
    if req is not None:
        p["policy"]["requiredSuite"] = req
    return p


def refused(fn):
    try:
        fn(); return False
    except sg.SuiteError:
        return True


def main() -> int:
    schema = json.loads(SCHEMA.read_text())
    if schema["properties"]["policy"]["properties"].get("requiredSuite", {}).get("enum") == [0, 1, 2, 3]:
        CHECKS["schema:requiredSuite-present"] = True
    else:
        FAILURES.append("schema policy.requiredSuite drift")

    cnsa = {"suite": 2, "mode": "fips"}
    fips = {"suite": 1, "mode": "fips"}
    fips_derived = {"mode": "fips"}   # no explicit suite -> 1
    research = {"mode": "standard"}   # -> 0

    # 1. CNSA workload on CNSA profile -> ok.
    CHECKS["ok:cnsa-workload-cnsa-profile"] = (sg.require_suite(pack(2), cnsa) == 2)
    # 2. THE BREAK: CNSA workload on FIPS profile -> refused.
    CHECKS["fail-closed:cnsa-workload-fips-profile-refused"] = refused(lambda: sg.require_suite(pack(2), fips))
    # 3. CNSA workload on research profile -> refused.
    CHECKS["fail-closed:cnsa-workload-research-refused"] = refused(lambda: sg.require_suite(pack(2), research))
    # 4. FIPS workload on research profile -> refused.
    CHECKS["fail-closed:fips-workload-research-refused"] = refused(lambda: sg.require_suite(pack(1), research))
    # 5. FIPS workload on derived-fips profile (no explicit suite) -> ok.
    CHECKS["ok:derived-suite-fips"] = (sg.require_suite(pack(1), fips_derived) == 1)
    # 6. No requiredSuite (=>0) runs anywhere.
    CHECKS["ok:no-requirement-runs-anywhere"] = (sg.require_suite(pack(), research) == 0)
    # 7. Determinism.
    CHECKS["deterministic"] = (sg.require_suite(pack(2), cnsa) == sg.require_suite(pack(2), cnsa))

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
