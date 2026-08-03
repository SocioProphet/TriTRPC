"""Mesh runtime message layer — heartbeat/liveness + work dispatch (fail-closed).

Between the scheduler (which picks nodes) and the coordinator (which settles results) sits the message
flow that keeps the registry live and dispatches units. This reference pins the DECIDABLE part; the
transport that moves the bytes (QUIC/libp2p) is delegated.

  * apply_heartbeat(registry, hb, now, trusted): refresh a node's lastSeenMs + capacity from its
    heartbeat. Fail-closed: only a node already in the trusted registry may heartbeat.
  * evict_stale / live_nodes(registry, now): drop / select nodes whose (now - lastSeenMs) <= ttlMs.
  * build_assignment(pack, node_ref, now): a dispatch envelope binding wu_id -> node_ref + deadline.
  * check_assignment(assignment, schedule, registry, now): admit a dispatch only to a node the
    scheduler assigned, that is currently live, before the deadline — else refuse.

FIPS: no primitive (message-flow logic); packRef is a SHA3 SCHEMA-ID. Does not touch the wire.
"""
from __future__ import annotations


class MeshRuntimeError(Exception):
    pass


def _entry(registry: list, node_ref: str):
    for e in registry:
        if e.get("node_ref") == node_ref:
            return e
    return None


def apply_heartbeat(registry: list, hb: dict, now: int, trusted: set) -> dict:
    """Refresh a node's liveness + capacity from a heartbeat. Fail-closed on an untrusted node."""
    ref = hb.get("node_ref")
    if ref not in trusted:
        raise MeshRuntimeError(f"heartbeat from untrusted node {ref!r} refused")
    e = _entry(registry, ref)
    if e is None:
        raise MeshRuntimeError(f"heartbeat from node {ref!r} not in registry refused")
    e["liveness"]["lastSeenMs"] = int(hb.get("sentMs", now))
    e["capacity"]["freeSlots"] = hb["capacity"]["freeSlots"]
    e["capacity"]["sandboxes"] = list(hb["capacity"]["sandboxes"])
    return e


def _is_live(e: dict, now: int) -> bool:
    lv = e.get("liveness") or {}
    return 0 <= (now - lv.get("lastSeenMs", -1)) <= lv.get("ttlMs", 0)


def live_nodes(registry: list, now: int) -> list:
    return [e for e in registry if _is_live(e, now)]


def evict_stale(registry: list, now: int) -> list:
    return [e for e in registry if _is_live(e, now)]


def build_assignment(pack: dict, node_ref: str, now: int) -> dict:
    """A dispatch envelope binding a WU pack to one node, with an SLO-derived deadline."""
    slo = int((pack.get("policy") or {}).get("slo_ms", 0))
    if slo < 1:
        raise MeshRuntimeError("pack.policy.slo_ms must be >= 1 to derive a deadline")
    return {
        "wu_id": pack.get("wu_id"),
        "node_ref": node_ref,
        "deadlineMs": now + slo,
        "packRef": pack.get("schema_id", "sha3-256:" + "0" * 64),
    }


def check_assignment(assignment: dict, schedule: dict, registry: list, now: int) -> None:
    """Admit a dispatch only to an assigned, currently-live node before its deadline. Fail-closed."""
    ref = assignment.get("node_ref")
    assigned = {a["node_ref"] for a in schedule.get("assignments", [])}
    if ref not in assigned:
        raise MeshRuntimeError(f"dispatch to {ref!r} refused: not in the schedule's assignments")
    e = _entry(registry, ref)
    if e is None or not _is_live(e, now):
        raise MeshRuntimeError(f"dispatch to {ref!r} refused: node is not currently live")
    if now >= int(assignment.get("deadlineMs", 0)):
        raise MeshRuntimeError("dispatch refused: deadline already passed")
    if assignment.get("wu_id") != schedule.get("wu_id"):
        raise MeshRuntimeError("dispatch wu_id does not match the schedule")
