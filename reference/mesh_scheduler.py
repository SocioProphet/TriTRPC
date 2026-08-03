"""Reference mesh scheduler + collector — the coordinator's front-half (fail-closed, decidable).

Between admission (node_admission) and settlement (mesh_coordinator) sits the part a coordinator
decides from the registry alone: which eligible nodes a Work-Unit is assigned to (schedule) and which
assigned nodes returned in time (collect). This is the POLICY logic, not the wire — the actual packet
transport (QUIC/libp2p) that carries the dispatch and gathers results is the layer below and is out of
scope here (delegated). What this decides is fully checkable:

  * eligible(registry, pack, now): a node is eligible iff it is LIVE (now - lastSeenMs <= ttlMs),
    its region satisfies pack.policy.residency, it offers pack.sandbox, and it has a free slot.
  * schedule(registry, pack, now): assign pack.replication eligible nodes, highest trust first
    (ties broken by node_ref for determinism). Fewer than replication eligible => REFUSE to schedule
    (the redundancy the proof_mode needs cannot be met — fail-closed, never silently under-replicate).
  * collect(assignment, results, deadlineMs): keep only results from ASSIGNED nodes that arrived by
    the SLO deadline; late or unassigned results are dropped. The kept set is what feeds reduce().

FIPS: no cryptographic primitive here (scheduling policy). Does not touch the tritrpc v4/vNext wire.
"""
from __future__ import annotations


class ScheduleError(Exception):
    pass


def _live(entry: dict, now: int) -> bool:
    lv = entry.get("liveness") or {}
    return 0 <= (now - lv.get("lastSeenMs", -1)) <= lv.get("ttlMs", 0)


def eligible(registry: list, pack: dict, now: int) -> list:
    """Eligible nodes for a pack, ranked highest-trust first (deterministic tie-break by node_ref)."""
    residency = (pack.get("policy") or {}).get("residency", "any")
    sandbox = pack.get("sandbox")
    out = []
    for e in registry or []:
        cap = e.get("capacity") or {}
        if not _live(e, now):
            continue
        if residency != "any" and e.get("region") != residency:
            continue
        if sandbox not in (cap.get("sandboxes") or []):
            continue
        if cap.get("freeSlots", 0) < 1:
            continue
        out.append(e)
    out.sort(key=lambda e: (-e.get("trustScore", 0.0), e["node_ref"]))
    return out


def schedule(registry: list, pack: dict, now: int) -> dict:
    """Assign replication eligible nodes to a WU. Fail-closed if redundancy cannot be met."""
    need = int(pack.get("replication", 1))
    picks = eligible(registry, pack, now)[:need]
    if len(picks) < need:
        raise ScheduleError(
            f"cannot schedule wu {pack.get('wu_id')!r}: need {need} eligible nodes, found {len(picks)} "
            f"(residency={pack.get('policy',{}).get('residency')}, sandbox={pack.get('sandbox')})")
    return {
        "wu_id": pack.get("wu_id"),
        "replication": need,
        "assignments": [{"node_ref": e["node_ref"], "region": e["region"]} for e in picks],
    }


def collect(assignment: dict, results: list, deadline_ms: int) -> dict:
    """Keep results from assigned nodes that arrived by the SLO deadline; drop late/unassigned ones."""
    assigned = {a["node_ref"] for a in assignment.get("assignments", [])}
    kept, dropped = [], []
    for r in results or []:
        if r.get("node_ref") not in assigned:
            dropped.append({"node_ref": r.get("node_ref"), "reason": "not assigned to this WU"})
        elif int(r.get("received_ms", 1 << 62)) > deadline_ms:
            dropped.append({"node_ref": r.get("node_ref"), "reason": "arrived after SLO deadline"})
        else:
            kept.append(r)
    return {"wu_id": assignment.get("wu_id"), "collected": kept, "dropped": dropped}


if __name__ == "__main__":
    import json
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    ex = root / "examples" / "mesh"
    registry = json.loads((ex / "node_registry.example.json").read_text())
    pack = json.loads((ex / "work_unit_pack.example.json").read_text())
    print(json.dumps(schedule(registry, pack, now=1_000_000), indent=2))
