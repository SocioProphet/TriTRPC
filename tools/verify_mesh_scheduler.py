#!/usr/bin/env python3
"""Verify the mesh scheduler/collector is fail-closed and composes end-to-end (schedule->collect->settle).

Runs reference/mesh_scheduler.py on the shipped registry + example WU pack and asserts: a residency-,
sandbox-, liveness-, capacity-filtered eligible set is ranked by trust and scheduled to exactly
`replication` nodes; a US node (wrong residency), a stale node (past ttl), a no-wasm node, and a
zero-slot node are each excluded; too few eligible nodes REFUSES scheduling (fail-closed); collect
keeps on-time assigned results and drops late/unassigned ones; and the whole chain composes — the
collected set settles in mesh_coordinator. Plus determinism + a schema drift-guard. Stdlib.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import mesh_scheduler as ms  # noqa: E402
import mesh_coordinator as mc  # noqa: E402

EX = ROOT / "examples" / "mesh"
SCHEMA = ROOT / "schemas" / "jsonschema" / "node-registration.v0.schema.json"
NOW = 1_000_000
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def load(n: str):
    return json.loads((EX / n).read_text())


def refused(fn) -> bool:
    try:
        fn()
        return False
    except ms.ScheduleError:
        return True


def main() -> int:
    # schema drift-guard.
    schema = json.loads(SCHEMA.read_text())
    cap = schema["properties"]["capacity"]["properties"]
    if schema.get("additionalProperties") is not False or set(cap["sandboxes"]["items"]["enum"]) != {"docker", "lightning", "wasm", "kata"}:
        FAILURES.append("schema drift (root strict / sandbox enum)")
    else:
        CHECKS["schema:no-drift"] = True

    registry = load("node_registry.example.json")
    pack = load("work_unit_pack.example.json")  # redundant, wasm, EU, replication 3

    # 1. Happy schedule: 3 EU wasm nodes, ranked by trust, US excluded by residency.
    sch = ms.schedule(registry, pack, NOW)
    refs = [a["node_ref"] for a in sch["assignments"]]
    if refs == ["node://eu-1", "node://eu-2", "node://eu-3"] and all(a["region"] == "EU" for a in sch["assignments"]):
        CHECKS["schedule:eligible-ranked-residency-filtered"] = True
    else:
        FAILURES.append(f"schedule picked the wrong set/order: {refs}")

    # 2. Liveness: stale a node -> only 2 eligible -> refuse (fail-closed).
    stale = copy.deepcopy(registry)
    stale[2]["liveness"]["lastSeenMs"] = 900_000  # now-900000 = 100000 > ttl 5000 => dead
    CHECKS["fail-closed:stale-node-excluded->underfilled-refused"] = refused(lambda: ms.schedule(stale, pack, NOW))
    if not CHECKS["fail-closed:stale-node-excluded->underfilled-refused"]:
        FAILURES.append("a stale node must be excluded (and underfilled schedule refused)")

    # 3. Sandbox: strip wasm from one node -> underfilled -> refuse.
    nowasm = copy.deepcopy(registry)
    nowasm[2]["capacity"]["sandboxes"] = ["docker"]
    CHECKS["fail-closed:no-sandbox-excluded"] = refused(lambda: ms.schedule(nowasm, pack, NOW))

    # 4. Capacity: zero free slots on one node -> underfilled -> refuse.
    noslot = copy.deepcopy(registry)
    noslot[2]["capacity"]["freeSlots"] = 0
    CHECKS["fail-closed:no-capacity-excluded"] = refused(lambda: ms.schedule(noslot, pack, NOW))

    # 5. Insufficient eligible outright (only US) -> refuse.
    CHECKS["fail-closed:insufficient-eligible-refused"] = refused(lambda: ms.schedule([registry[3]], pack, NOW))
    for k in ("fail-closed:no-sandbox-excluded", "fail-closed:no-capacity-excluded", "fail-closed:insufficient-eligible-refused"):
        if not CHECKS[k]:
            FAILURES.append(f"{k} did not fire")

    # 6. Collect: on-time assigned kept, late + unassigned dropped.
    deadline = NOW + pack["policy"]["slo_ms"]
    results = [
        {"wu_id": pack["wu_id"], "node_ref": "node://eu-1", "received_ms": deadline - 10, "result_cid": "sha256:" + "a" * 64, "region": "EU", "proof": {"mode": "redundant"}},
        {"wu_id": pack["wu_id"], "node_ref": "node://eu-2", "received_ms": deadline - 5,  "result_cid": "sha256:" + "a" * 64, "region": "EU", "proof": {"mode": "redundant"}},
        {"wu_id": pack["wu_id"], "node_ref": "node://eu-3", "received_ms": deadline + 500, "result_cid": "sha256:" + "a" * 64, "region": "EU", "proof": {"mode": "redundant"}},  # late
        {"wu_id": pack["wu_id"], "node_ref": "node://us-1", "received_ms": deadline - 1,  "result_cid": "sha256:" + "a" * 64, "region": "US", "proof": {"mode": "redundant"}},  # unassigned
    ]
    col = ms.collect(sch, results, deadline)
    kept_refs = {r["node_ref"] for r in col["collected"]}
    if kept_refs == {"node://eu-1", "node://eu-2"} and len(col["dropped"]) == 2:
        CHECKS["collect:on-time-assigned-kept"] = True
    else:
        FAILURES.append(f"collect kept/dropped wrong: kept={kept_refs} dropped={len(col['dropped'])}")

    # 7. END-TO-END: schedule -> collect -> settle. Two on-time agree, but replication=3 so NOT settled
    #    (a real SLO shortfall must not settle). Give a lower-replication pack to show a clean settle.
    trusted = [{"node_ref": a["node_ref"], "attestationRef": "att://x", "region": a["region"]} for a in sch["assignments"]]
    p2 = copy.deepcopy(pack); p2["replication"] = 2
    settle = mc.reduce(p2, col["collected"], trusted)
    if settle["settled"] and set(settle["rlc_credit"]) == {"node://eu-1", "node://eu-2"}:
        CHECKS["e2e:collected-set-settles-in-coordinator"] = True
    else:
        FAILURES.append(f"collected set did not settle end-to-end: {settle}")

    # 8. Determinism.
    if ms.schedule(registry, pack, NOW) == sch:
        CHECKS["deterministic:reproducible"] = True
    else:
        FAILURES.append("schedule is not deterministic")

    for m in FAILURES:
        print(f"FAIL: {m}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
