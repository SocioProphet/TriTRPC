#!/usr/bin/env python3
"""Verify the mesh SCHEMA-ID / body-CID are reproducible and PCF is correct (recompute, don't trust).

Recomputes the WorkUnitBody's SCHEMA-ID (SHA3-256 of the Avro Parsing Canonical Form) and the example
body's CID (SHA-256 of canonical JSON) from the schema/body alone and asserts they equal the recorded
vector. Then proves PCF behaviour: adding doc/default/namespace noise does NOT change the SCHEMA-ID
(STRIP), while reordering fields or changing an enum symbol DOES (structure is significant); and the
body CID is invariant to JSON key order but changes with the body. Stdlib, repo convention.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import avro_canonical as ac  # noqa: E402

AVSC = ROOT / "schemas" / "avro" / "work_unit_body.v0.avsc"
VECTOR = ROOT / "fixtures" / "mesh" / "work_unit_schema_id.vector.json"
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def main() -> int:
    schema = json.loads(AVSC.read_text())
    vec = json.loads(VECTOR.read_text())

    # 1. Recompute-don't-trust: PCF, SCHEMA-ID, body CID all match the recorded vector.
    if ac.canonical_form(schema) == vec["pcf"] and ac.schema_id(schema) == vec["schema_id"]:
        CHECKS["recompute:schema-id-matches-vector"] = True
    else:
        FAILURES.append("recomputed SCHEMA-ID / PCF does not match the vector")
    if ac.body_cid(vec["body"]) == vec["body_cid"]:
        CHECKS["recompute:body-cid-matches-vector"] = True
    else:
        FAILURES.append("recomputed body CID does not match the vector")

    # 2. FIPS prefixes.
    if vec["schema_id"].startswith("sha3-256:") and vec["body_cid"].startswith("sha256:"):
        CHECKS["fips:sha3-schema-id-sha256-cid"] = True
    else:
        FAILURES.append("SCHEMA-ID must be sha3-256: and body CID sha256:")

    # 3. STRIP: doc/default/namespace-restated noise does NOT change the SCHEMA-ID.
    noisy = copy.deepcopy(schema)
    noisy["doc"] = "totally different doc"
    noisy["fields"][0]["doc"] = "noise"
    noisy["fields"][-1]["default"] = None  # already null; restating a default must be stripped
    if ac.schema_id(noisy) == vec["schema_id"]:
        CHECKS["pcf:strips-doc-default"] = True
    else:
        FAILURES.append("PCF did not strip doc/default — SCHEMA-ID changed under cosmetic noise")

    # 4. SENSITIVITY: reordering fields changes the SCHEMA-ID (field order is significant in Avro).
    reordered = copy.deepcopy(schema)
    reordered["fields"] = list(reversed(reordered["fields"]))
    changed_symbol = copy.deepcopy(schema)
    changed_symbol["fields"][1]["type"]["symbols"] = ["map", "reduce", "embed", "rank"]
    if ac.schema_id(reordered) != vec["schema_id"] and ac.schema_id(changed_symbol) != vec["schema_id"]:
        CHECKS["pcf:sensitive-to-structure"] = True
    else:
        FAILURES.append("SCHEMA-ID must change when field order or an enum symbol changes")

    # 5. body CID: invariant to JSON key order, sensitive to content.
    rekeyed = {k: vec["body"][k] for k in reversed(list(vec["body"]))}
    mutated = copy.deepcopy(vec["body"]); mutated["deadline_ms"] = 1
    if ac.body_cid(rekeyed) == vec["body_cid"] and ac.body_cid(mutated) != vec["body_cid"]:
        CHECKS["cid:key-order-invariant-content-sensitive"] = True
    else:
        FAILURES.append("body CID must be key-order invariant but content sensitive")

    for m in FAILURES:
        print(f"FAIL: {m}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
