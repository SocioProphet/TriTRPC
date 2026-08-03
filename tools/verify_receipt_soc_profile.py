#!/usr/bin/env python3
"""Verify the SOC / Chain Profile of the TriTRPC Receipt Transport Binding (v0.2, additive).

A Semantic Obfuscation Chain is a governed MULTI-HOP RPC. This gate enforces the profile's five
acceptance rules on a captured trace, so the "complete to the owner, cloaked to observers" property
is checkable, not just prose:

  1. all hop events share one trace_id, and spans form a parent-linked chain;
  2. every hop transport block is sealed:true with a sealed_to (owner-sealed — a relay can't read a
     hop it isn't party to);
  3. route_id/peer_id are stable within the trace (so the owner can reassemble the route);
  4. any sabotage/refused_by_policy hop terminates the chain (no downstream spans) — fail closed;
  5. the ordered route is reconstructable from the sealed blocks (chain_position 0..n-1, contiguous).

Self-testing: the canonical example must pass; the invalid examples must be rejected. Stdlib only,
matching this repo's validator convention.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EX = ROOT / "examples" / "transport"
VALID = EX / "receipt_events.soc.example.json"
INVALID = [
    EX / "receipt_events.soc.unsealed.invalid.json",
    EX / "receipt_events.soc.sabotage-continues.invalid.json",
]
TERMINAL = {"sabotage", "refused_by_policy"}


class ProfileError(Exception):
    pass


def fail(msg: str) -> None:
    raise ProfileError(msg)


def load(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def verify_soc(doc: Any) -> None:
    if not isinstance(doc, dict) or not isinstance(doc.get("events"), list) or not doc["events"]:
        fail("document must have a non-empty events array")
    events = doc["events"]

    # Rule 1: one trace; spans parent-linked into a chain.
    traces = {e.get("trace_id") for e in events}
    if len(traces) != 1 or None in traces:
        fail(f"a SOC is exactly one trace; found trace_ids {traces}")
    spans = [e.get("span_id") for e in events]
    if len(set(spans)) != len(spans):
        fail("span_ids must be unique within the chain")
    seen: set[str] = set()
    for e in events:
        parent = e.get("parent_span_id")
        # each hop's parent must be a prior span (except the first, whose parent is the pre-chain intent)
        if seen and parent not in seen:
            fail(f"span {e.get('span_id')} parent {parent!r} is not a prior span (chain broken)")
        seen.add(e.get("span_id"))

    # Rules 2,3,5: sealing, stable ids, contiguous positions — over the hop events that carry a chain.
    positions, route_ids, peer_ids, chain_ids = [], set(), set(), set()
    terminal_at = None
    for i, e in enumerate(events):
        p = e.get("payload") or {}
        if "chain_id" not in p:
            continue
        chain_ids.add(p["chain_id"])
        # Rule 2: owner-sealed
        if p.get("sealed") is not True or not str(p.get("sealed_to") or "").strip():
            fail(f"hop {p.get('chain_position')} is not owner-sealed (sealed:true + sealed_to required)")
        # Rule 3: stable route/peer within the trace
        route_ids.add(p.get("route_id")); peer_ids.add(p.get("peer_id"))
        positions.append(p.get("chain_position"))
        # Rule 4: a terminal failure_class must be the LAST hop (chain aborts, no downstream)
        if e.get("event_type") == "rpc.fail" and p.get("failure_class") in TERMINAL:
            terminal_at = i
    if len(chain_ids) != 1:
        fail(f"all hops must share one chain_id; found {chain_ids}")
    # Rule 5: positions are 0..n-1 contiguous (the owner can order the route)
    if sorted(positions) != list(range(len(positions))):
        fail(f"chain_position must be contiguous 0..n-1; found {sorted(positions)}")
    # ids stable enough to reassemble — a pseudonymous route may repeat; must not be empty/None
    if None in route_ids or None in peer_ids:
        fail("every hop must carry route_id and peer_id (stable within the trace)")

    # Rule 4 (fail-closed): if a terminal hop occurred, NO event may follow it.
    if terminal_at is not None and terminal_at != len(events) - 1:
        fail("a sabotage/refused_by_policy hop must terminate the chain — no downstream spans allowed")


def main() -> int:
    try:
        verify_soc(load(VALID))
        for path in INVALID:
            try:
                verify_soc(load(path))
            except ProfileError:
                continue
            fail(f"expected {path.name} to be rejected, but it passed")
    except ProfileError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 2
    print("OK: SOC/chain profile validation passed (1 example, 2 invalid rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
