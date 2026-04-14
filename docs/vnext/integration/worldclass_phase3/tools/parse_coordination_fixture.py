#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def load(path: str):
    return json.loads(Path(path).read_text())


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: parse_coordination_fixture.py <fixture.json>")
        return 2

    doc = load(sys.argv[1])
    out = {
        "sequence_id": doc.get("sequence_id"),
        "semaphore_ids": [],
        "witness_refs": [],
        "bundle_refs": [],
        "actions": [],
    }

    sems = set()
    witnesses = set()
    bundles = set()
    actions = []

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

    out["semaphore_ids"] = sorted(sems)
    out["witness_refs"] = sorted(witnesses)
    out["bundle_refs"] = sorted(bundles)
    out["actions"] = actions

    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
