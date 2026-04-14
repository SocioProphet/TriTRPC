#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def load(path: str):
    return json.loads(Path(path).read_text())


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: compare_results.py <tritrpc_capture.json> <competitor_capture.json>")
        return 2

    tri = load(sys.argv[1])
    comp = load(sys.argv[2])

    tri_metrics = tri.get("metrics", {})
    comp_metrics = comp.get("metrics", {})

    out = {
        "scenario_id": tri.get("scenario_id") or comp.get("scenario_id"),
        "transport_a": tri.get("transport", "TriTRPC"),
        "transport_b": comp.get("transport", "competitor"),
        "comparisons": {},
    }

    for key in sorted(set(tri_metrics) | set(comp_metrics)):
        a = tri_metrics.get(key)
        b = comp_metrics.get(key)
        out["comparisons"][key] = {
            "a": a,
            "b": b,
            "delta": None if a is None or b is None else a - b,
        }

    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
