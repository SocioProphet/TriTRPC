#!/usr/bin/env python3
import json
import sys
from pathlib import Path


BEACON_KINDS = {
    "beacon-intent",
    "beacon-commit",
    "beacon-semaphore",
    "beacon-boundary-delta",
    "env-cap",
}


def load(path: str):
    return json.loads(Path(path).read_text())


def collect_refs(doc: dict) -> dict:
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
        kind = ev.get("kind")
        if kind not in BEACON_KINDS and kind != "stream-open":
            continue
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


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: parse_typed_beacon_refs.py <fixture.json>")
        return 2
    doc = load(sys.argv[1])
    out = {
        "sequence_id": doc.get("sequence_id"),
        "refs": collect_refs(doc),
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
