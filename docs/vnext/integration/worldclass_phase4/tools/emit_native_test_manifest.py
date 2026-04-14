#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def load(path: str):
    return json.loads(Path(path).read_text())


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: emit_native_test_manifest.py <semantic_fixture.json>")
        return 2

    fixture = load(sys.argv[1])
    events = fixture.get("events", [])

    manifest = {
        "fixture_family": "semantic_beacon_sequence",
        "sequence_id": fixture.get("sequence_id"),
        "event_count": len(events),
        "required_assertions": [],
    }

    for i, ev in enumerate(events):
        kind = ev.get("kind")
        assertion = {"index": i, "kind": kind}
        if ev.get("bundle_h"):
            assertion["bundle_h"] = ev.get("bundle_h")
        if ev.get("semantic_refs"):
            assertion["semantic_refs"] = ev.get("semantic_refs")
        defaults = ev.get("defaults", {})
        if defaults.get("braid"):
            assertion["braid"] = defaults.get("braid")
        if defaults.get("state"):
            assertion["state"] = defaults.get("state")
        manifest["required_assertions"].append(assertion)

    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
