#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def load(path: str):
    return json.loads(Path(path).read_text())


def collect_beacon_refs(doc: dict) -> dict:
    refs = {
        "bundle_h": set(),
        "semantic_refs": set(),
        "manifest_ref": set(),
        "hash_ref": set(),
        "semaphore_id": set(),
        "route_h": set(),
        "context_h": set(),
    }
    for ev in doc.get("events", []):
        for key in refs:
            val = ev.get(key)
            if isinstance(val, list):
                refs[key].update(str(x) for x in val)
            elif val:
                refs[key].add(str(val))
        defaults = ev.get("defaults", {})
        for key in ("route_h", "context_h"):
            val = defaults.get(key)
            if val:
                refs[key].add(str(val))
    return {k: sorted(v) for k, v in refs.items() if v}


def collect_coordination_refs(doc: dict) -> dict:
    sems, witnesses, bundles, actions = set(), set(), set(), []
    for ev in doc.get("events", []):
        if ev.get("semaphore_id"):
            sems.add(str(ev["semaphore_id"]))
        if ev.get("bundle_h"):
            bundles.add(str(ev["bundle_h"]))
        if isinstance(ev.get("witness_refs"), list):
            witnesses.update(str(x) for x in ev["witness_refs"])
        if ev.get("action"):
            actions.append(str(ev["action"]))
        elif ev.get("kind"):
            actions.append(str(ev["kind"]))
    return {
        "semaphore_ids": sorted(sems),
        "witness_refs": sorted(witnesses),
        "bundle_refs": sorted(bundles),
        "actions": actions,
    }


def bridge_bench(scenario: dict, tri: dict, comp: dict) -> dict:
    return {
        "scenario_id": scenario.get("scenario_id"),
        "description": scenario.get("description"),
        "runs": [tri, comp],
        "summary": {
            "transport_a": tri.get("transport"),
            "transport_b": comp.get("transport"),
            "metric_keys": sorted(set(tri.get("metrics", {})) | set(comp.get("metrics", {}))),
        },
    }


def main() -> int:
    if len(sys.argv) != 6:
        print("usage: run_reference_slice.py <semantic_fixture.json> <boundary_fixture.json> <scenario.json> <tri_capture.json> <comp_capture.json>")
        return 2

    semantic_fixture = load(sys.argv[1])
    boundary_fixture = load(sys.argv[2])
    scenario = load(sys.argv[3])
    tri = load(sys.argv[4])
    comp = load(sys.argv[5])

    out = {
        "semantic": {
            "sequence_id": semantic_fixture.get("sequence_id"),
            "refs": collect_beacon_refs(semantic_fixture),
        },
        "boundary": {
            "sequence_id": boundary_fixture.get("sequence_id"),
            "refs": collect_coordination_refs(boundary_fixture),
        },
        "benchmark": bridge_bench(scenario, tri, comp),
    }

    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
