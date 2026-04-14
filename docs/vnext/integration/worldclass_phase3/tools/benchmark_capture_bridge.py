#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def load(path: str):
    return json.loads(Path(path).read_text())


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: benchmark_capture_bridge.py <input_template.json> <tritrpc_capture.json> <competitor_capture.json>")
        return 2

    scenario = load(sys.argv[1])
    tri = load(sys.argv[2])
    comp = load(sys.argv[3])

    out = {
        "scenario_id": scenario.get("scenario_id"),
        "description": scenario.get("description"),
        "runs": [tri, comp],
        "summary": {
            "transport_a": tri.get("transport"),
            "transport_b": comp.get("transport"),
            "metric_keys": sorted(set(tri.get("metrics", {})) | set(comp.get("metrics", {})))
        }
    }

    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
