#!/usr/bin/env python3
"""Verify route-handle dictionary negotiation is fail-closed (vNext hot-path gap #3).

Builds a dictionary, resolves a known handle, and asserts fail-closed refusals: an unknown handle, a
duplicate handle, an out-of-range handle, a tampered dictionary (token no longer matches entries), and
a peer mismatch during negotiation are each refused. Plus determinism (same map -> same SHA-256 token),
a schema drift-guard, and example conformance. Stdlib.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import route_dictionary as rd  # noqa: E402

SCHEMA = ROOT / "schemas" / "jsonschema" / "route-dictionary.v0.schema.json"
EX = ROOT / "examples" / "transport" / "route_dictionary.example.json"
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def refused(fn) -> bool:
    try:
        fn(); return False
    except rd.RouteDictError:
        return True


def main() -> int:
    schema = json.loads(SCHEMA.read_text())
    item = schema["properties"]["entries"]["items"]["properties"]
    if schema.get("additionalProperties") is False and item["handle"]["maximum"] == 242 \
       and schema["properties"]["dictionaryId"].get("pattern") == "^sha256:":
        CHECKS["schema:no-drift"] = True
    else:
        FAILURES.append("schema drift (handle range / dictionaryId prefix)")

    d = rd.build_dictionary({7: "route://agentplane/executor", 9: "route://agentplane/planner"})
    # example matches a freshly-built dictionary (recompute-don't-trust).
    ex = json.loads(EX.read_text())
    CHECKS["example:token-recomputes"] = (rd.dictionary_id(ex) == ex["dictionaryId"])

    # 1. resolve a known handle.
    CHECKS["resolve:known-handle"] = (rd.resolve(d, 7) == "route://agentplane/executor")
    # 2. unknown handle refused.
    CHECKS["fail-closed:unknown-handle-refused"] = refused(lambda: rd.resolve(d, 200))
    # 3. duplicate handle refused at build (a mapping whose items() yields the same handle twice).
    CHECKS["fail-closed:duplicate-handle-refused"] = refused(lambda: rd.build_dictionary(_DupMap()))
    # 4. out-of-range handle refused.
    CHECKS["fail-closed:out-of-range-handle-refused"] = refused(lambda: rd.build_dictionary({243: "x"}))
    # 5. tampered dictionary (entries changed, token stale) refused.
    tampered = copy.deepcopy(d); tampered["entries"][0]["route"] = "route://evil"
    CHECKS["fail-closed:tampered-dictionary-refused"] = refused(lambda: rd.resolve(tampered, 7))
    # 6. negotiate: matching agree, mismatch refused.
    d2 = rd.build_dictionary({7: "route://agentplane/executor", 9: "route://agentplane/planner"})
    CHECKS["negotiate:matching-agree"] = (rd.negotiate(d, d2)["dictionaryId"] == d["dictionaryId"])
    d3 = rd.build_dictionary({7: "route://different"})
    CHECKS["fail-closed:mismatch-refused"] = refused(lambda: rd.negotiate(d, d3))
    # 7. determinism.
    CHECKS["deterministic:same-map-same-token"] = (
        rd.build_dictionary({9: "route://b", 7: "route://a"})["dictionaryId"]
        == rd.build_dictionary({7: "route://a", 9: "route://b"})["dictionaryId"])

    for k, v in CHECKS.items():
        if not v:
            FAILURES.append(f"{k} failed")
    for m in FAILURES:
        print(f"FAIL: {m}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


class _DupMap(dict):
    """A mapping whose items() yields the same handle twice — to exercise duplicate detection."""
    def items(self):
        return [(7, "route://a"), (7, "route://b")]


if __name__ == "__main__":
    raise SystemExit(main())
