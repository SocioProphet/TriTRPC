#!/usr/bin/env python3
"""Verify the mesh orchestrator composes EVERY stage end-to-end and stays fail-closed (fabric proof).

Runs the full pipeline (admit -> register/liveness -> schedule -> dispatch -> collect -> settle) and
asserts: three qualified reputations are admitted, scheduled, and settle a redundant WU with all three
credited; a low-civility reputation is NEVER admitted, scheduled, or credited; requiredSuite is
enforced (suite-2 requirement on suite-1 nodes does not settle); too few admitted nodes refuses to
schedule. Since the orchestrator imports node_admission + mesh_scheduler + mesh_runtime +
mesh_coordinator (which itself uses suite_gate + proof_envelope + attestation_verifier), a green run
proves every stage is consumed — the fabric, not a set of patches. Stdlib.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import mesh_orchestrator as orch  # noqa: E402
import mesh_scheduler as ms  # noqa: E402

NOW = 1_000_000
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def rep(ref, civility=0.8, obs=40):
    return {"node_ref": ref, "attestationRef": f"att://{ref[7:]}", "region": "EU",
            "trust": {"credibility": 0.9, "reliability": 0.85, "intimacy": 0.7, "selfOrientation": 0.2},
            "energy": {"knowledge": 0.8, "creativity": 0.6, "civility": civility},
            "history": {"observations": obs, "decayHalfLifeDays": 30}}


POLICY = {"minTrust": 0.5, "maxSelfOrientation": 0.4, "minObservations": 30, "minCivility": 0.5, "requireAttestation": True}
CID = "sha256:" + "a" * 64


def runtime(refs, suite=1):
    return {r: {"suite": suite, "capacity": {"freeSlots": 2, "sandboxes": ["wasm", "docker"]},
                "liveness": {"lastSeenMs": NOW - 500, "ttlMs": 5000}} for r in refs}


def results(refs):
    return [{"wu_id": "wu-1", "node_ref": r, "region": "EU", "result_cid": CID,
             "received_ms": NOW + 100, "proof": {"mode": "redundant"}} for r in refs]


def pack(required_suite=1, replication=3):
    return {"wu_id": "wu-1", "proof_mode": "redundant", "sandbox": "wasm", "replication": replication,
            "policy": {"residency": "EU", "isolation": "strong", "slo_ms": 30000, "requiredSuite": required_suite}}


def main() -> int:
    good = ["node://eu-1", "node://eu-2", "node://eu-3"]
    reps = [rep(r) for r in good] + [rep("node://eu-bad", civility=0.1)]  # eu-bad fails civility floor
    rt = runtime(good + ["node://eu-bad"])
    res = results(good + ["node://eu-bad"])

    # 1. full pipeline: 3 admitted, scheduled, settle with all 3 credited.
    out = orch.run_work_unit(reps, POLICY, pack(), rt, res, NOW)
    st = out["settlement"]
    if out["admitted"] == good and set(out["scheduled"]) == set(good) and st["settled"] and set(st["rlc_credit"]) == set(good):
        CHECKS["fabric:full-pipeline-admit-schedule-settle"] = True
    else:
        FAILURES.append(f"full pipeline did not compose: {out}")

    # 2. the low-civility node is never admitted / scheduled / credited.
    if "node://eu-bad" not in out["admitted"] and "node://eu-bad" not in out["scheduled"] and "node://eu-bad" not in st["rlc_credit"]:
        CHECKS["fail-closed:unadmitted-node-never-settles"] = True
    else:
        FAILURES.append("an unadmitted node leaked into schedule/settlement")

    # 3. requiredSuite enforced end-to-end: suite-2 requirement on suite-1 nodes does not settle.
    out2 = orch.run_work_unit(reps, POLICY, pack(required_suite=2), rt, res, NOW)
    if not out2["settlement"]["settled"]:
        CHECKS["fabric:required-suite-enforced-end-to-end"] = True
    else:
        FAILURES.append("a suite-2 workload settled on suite-1 nodes through the orchestrator")

    # 4. too few admitted -> schedule refuses (fail-closed).
    try:
        orch.run_work_unit([rep("node://eu-1"), rep("node://eu-2")], POLICY, pack(replication=3), runtime(["node://eu-1", "node://eu-2"]), results(["node://eu-1", "node://eu-2"]), NOW)
        FAILURES.append("scheduling must refuse when fewer nodes are admitted than replication requires")
    except ms.ScheduleError:
        CHECKS["fail-closed:insufficient-admitted-refuses-schedule"] = True

    # 5. determinism.
    if orch.run_work_unit(reps, POLICY, pack(), rt, res, NOW) == out:
        CHECKS["deterministic:reproducible"] = True
    else:
        FAILURES.append("orchestrator is not deterministic")

    for m in FAILURES:
        print(f"FAIL: {m}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
