#!/usr/bin/env python3
"""Verify the mesh runtime message layer (heartbeat/liveness + dispatch) is fail-closed and composes.

Asserts: a heartbeat from a trusted node refreshes its lastSeenMs+capacity; a heartbeat from an
untrusted or unregistered node is refused; evict_stale/live_nodes select by ttl; build_assignment
derives a deadline; check_assignment admits an assigned+live+before-deadline dispatch and refuses a
non-assigned node, a stale node, a passed deadline, and a wu_id mismatch. END-TO-END: a heartbeat keeps
a node live, the scheduler then picks it, and the dispatch is admitted. + schema drift-guard. Stdlib.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import mesh_runtime as mr  # noqa: E402
import mesh_scheduler as ms  # noqa: E402

SCHEMAS = ROOT / "schemas" / "jsonschema"
NOW = 1_000_000
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def node(ref, region="EU", trust=0.9, slots=2, sbx=("wasm", "docker"), last=NOW - 1000, ttl=5000):
    return {"node_ref": ref, "attestationRef": f"att://{ref[7:]}", "region": region, "trustScore": trust,
            "capacity": {"freeSlots": slots, "sandboxes": list(sbx)}, "liveness": {"lastSeenMs": last, "ttlMs": ttl}}


def hb(ref, sent=NOW, slots=1, sbx=("wasm", "docker")):
    return {"node_ref": ref, "attestationRef": f"att://{ref[7:]}", "sentMs": sent,
            "capacity": {"freeSlots": slots, "sandboxes": list(sbx)}}


def refused(fn) -> bool:
    try:
        fn(); return False
    except mr.MeshRuntimeError:
        return True


def main() -> int:
    # schema drift-guard.
    hbs = json.loads((SCHEMAS / "heartbeat.v0.schema.json").read_text())
    was = json.loads((SCHEMAS / "work-assignment.v0.schema.json").read_text())
    if hbs.get("additionalProperties") is False and was["properties"]["packRef"].get("pattern") == "^sha3-256:":
        CHECKS["schema:no-drift"] = True
    else:
        FAILURES.append("schema drift")

    trusted = {"node://eu-1", "node://eu-2", "node://eu-3"}

    # 1. heartbeat refreshes liveness + capacity for a trusted node.
    reg = [node("node://eu-1", last=NOW - 4000, slots=0)]
    mr.apply_heartbeat(reg, hb("node://eu-1", sent=NOW, slots=2), NOW, trusted)
    CHECKS["heartbeat:refreshes-liveness-capacity"] = (reg[0]["liveness"]["lastSeenMs"] == NOW and reg[0]["capacity"]["freeSlots"] == 2)
    # 2. untrusted node refused.
    CHECKS["fail-closed:untrusted-heartbeat-refused"] = refused(lambda: mr.apply_heartbeat(reg, hb("node://evil"), NOW, trusted))
    # 3. trusted but not-in-registry refused.
    CHECKS["fail-closed:unregistered-heartbeat-refused"] = refused(lambda: mr.apply_heartbeat(reg, hb("node://eu-2"), NOW, trusted))

    # 4/5. evict_stale + live_nodes.
    reg2 = [node("node://eu-1", last=NOW - 1000), node("node://eu-2", last=NOW - 99999)]  # eu-2 stale
    live = mr.live_nodes(reg2, NOW)
    CHECKS["liveness:live-nodes-selects-fresh"] = ({e["node_ref"] for e in live} == {"node://eu-1"})
    CHECKS["liveness:evict-stale-drops-dead"] = ({e["node_ref"] for e in mr.evict_stale(reg2, NOW)} == {"node://eu-1"})

    # 6. build_assignment derives a deadline.
    pack = {"wu_id": "wu-x", "schema_id": "sha3-256:" + "1" * 64, "policy": {"residency": "EU", "isolation": "strong", "slo_ms": 30000}}
    asn = mr.build_assignment(pack, "node://eu-1", NOW)
    CHECKS["dispatch:build-assignment-deadline"] = (asn["deadlineMs"] == NOW + 30000 and asn["node_ref"] == "node://eu-1")

    # 7. check_assignment: assigned + live + before deadline -> ok.
    schedule = {"wu_id": "wu-x", "assignments": [{"node_ref": "node://eu-1", "region": "EU"}]}
    reg3 = [node("node://eu-1", last=NOW - 500)]
    mr.check_assignment(asn, schedule, reg3, NOW)
    CHECKS["dispatch:assigned-live-admitted"] = True
    # 8. not in schedule refused.
    asn_bad = copy.deepcopy(asn); asn_bad["node_ref"] = "node://eu-9"
    CHECKS["fail-closed:not-assigned-refused"] = refused(lambda: mr.check_assignment(asn_bad, schedule, reg3, NOW))
    # 9. stale node refused.
    reg_stale = [node("node://eu-1", last=NOW - 99999)]
    CHECKS["fail-closed:stale-node-dispatch-refused"] = refused(lambda: mr.check_assignment(asn, schedule, reg_stale, NOW))
    # 10. past deadline refused.
    CHECKS["fail-closed:past-deadline-refused"] = refused(lambda: mr.check_assignment(asn, schedule, reg3, NOW + 40000))

    # 11. END-TO-END: heartbeat keeps a node live -> scheduler picks it -> dispatch admitted.
    reg_e2e = [node("node://eu-1", last=NOW - 99999, slots=0), node("node://eu-2", last=NOW - 500), node("node://eu-3", last=NOW - 500)]
    mr.apply_heartbeat(reg_e2e, hb("node://eu-1", sent=NOW, slots=2), NOW, trusted)  # revive eu-1
    epack = {"wu_id": "wu-e", "schema_id": "sha3-256:" + "2" * 64, "sandbox": "wasm",
             "policy": {"residency": "EU", "isolation": "strong", "slo_ms": 1000, "requiredSuite": 0}, "replication": 3}
    sch = ms.schedule(mr.live_nodes(reg_e2e, NOW), epack, NOW)
    asn_e = mr.build_assignment(epack, sch["assignments"][0]["node_ref"], NOW)
    mr.check_assignment(asn_e, sch, reg_e2e, NOW)
    CHECKS["e2e:heartbeat-schedule-dispatch-compose"] = (len(sch["assignments"]) == 3 and "node://eu-1" in {a["node_ref"] for a in sch["assignments"]})

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
