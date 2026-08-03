#!/usr/bin/env python3
"""Verify the reference Mesh Coordinator settles Work-Units fail-closed (Dual-Orchestration plane B).

Runs reference/mesh_coordinator.py on the shipped example WU pack + results + trusted nodes and asserts:
a redundant WU whose replicas AGREE settles with all replicas credited; and then, fail-closed —
an UNTRUSTED node, a PROOF-MODE MISMATCH, and a RESIDENCY VIOLATION are each refused; a redundant
SPLIT (no strict majority) and INSUFFICIENT replicas do NOT settle and pay no credit; a tee result
missing its measurement is refused. Plus determinism (identical inputs -> identical receipt). Stdlib.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import mesh_coordinator as mc  # noqa: E402

EX = ROOT / "examples" / "mesh"
SCHEMAS = ROOT / "schemas" / "jsonschema"
PACK_SCHEMA = SCHEMAS / "work-unit-pack.v0.schema.json"
RESULT_SCHEMA = SCHEMAS / "work-unit-result.v0.schema.json"
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def load(name: str):
    return json.loads((EX / name).read_text())


def _schema(p: Path):
    return json.loads(p.read_text())


def validate_schemas() -> None:
    """Drift-guard (stdlib): the schemas and the coordinator constants must stay in lockstep."""
    pack, res = _schema(PACK_SCHEMA), _schema(RESULT_SCHEMA)
    for name, s in (("pack", pack), ("result", res)):
        if s.get("additionalProperties") is not False:
            raise mc.MeshCoordinatorError(f"{name} schema root must be strict (additionalProperties:false)")
    pp = pack["properties"]
    if set(pp["proof_mode"]["enum"]) != mc.PROOF_MODES:
        raise mc.MeshCoordinatorError("pack.proof_mode enum drifted from mesh_coordinator.PROOF_MODES")
    if set(res["properties"]["proof"]["properties"]["mode"]["enum"]) != mc.PROOF_MODES:
        raise mc.MeshCoordinatorError("result.proof.mode enum drifted from mesh_coordinator.PROOF_MODES")
    if pp["sandbox"]["enum"] != ["docker", "lightning", "wasm", "kata"]:
        raise mc.MeshCoordinatorError("pack.sandbox enum drifted")
    if pp["body_cid"].get("pattern") != "^sha256:" or pp["schema_id"].get("pattern") != "^sha3-256:":
        raise mc.MeshCoordinatorError("pack CID/SCHEMA-ID hash prefixes drifted (SHA-256 CID / SHA3 SCHEMA-ID)")
    if pp["policy"].get("additionalProperties") is not False:
        raise mc.MeshCoordinatorError("pack.policy must be strict")
    # example structural conformance — no keys outside the declared properties.
    for rec, s in ((load("work_unit_pack.example.json"), pack),
                   *[(r, res) for r in load("work_unit_results.example.json")]):
        extra = set(rec) - set(s["properties"])
        if extra:
            raise mc.MeshCoordinatorError(f"example has keys not in schema: {sorted(extra)}")


def refused(fn) -> bool:
    try:
        fn()
        return False
    except mc.MeshCoordinatorError:
        return True


def main() -> int:
    try:
        validate_schemas()
        CHECKS["schema:no-drift-and-example-conformant"] = True
    except mc.MeshCoordinatorError as exc:
        FAILURES.append(f"schema drift-guard failed: {exc}")

    pack = load("work_unit_pack.example.json")
    results = load("work_unit_results.example.json")
    trusted = load("trusted_nodes.example.json")

    # 1. Happy path: 3 agreeing replicas settle, all 3 credited.
    rec = mc.reduce(pack, results, trusted)
    if rec["settled"] and rec["accepted_result_cid"] == results[0]["result_cid"] and len(rec["rlc_credit"]) == 3 and not rec["rejected"]:
        CHECKS["redundant:agree-settles-credits-all"] = True
    else:
        FAILURES.append(f"agreeing redundant WU did not settle cleanly: {rec}")

    # 2. Untrusted node refused.
    r_untrusted = copy.deepcopy(results[0]); r_untrusted["node_ref"] = "node://evil-9"
    CHECKS["fail-closed:untrusted-node-refused"] = refused(lambda: mc.verify_result(pack, r_untrusted, trusted))
    if not CHECKS["fail-closed:untrusted-node-refused"]:
        FAILURES.append("an untrusted node's result must be refused")

    # 3. Proof-mode mismatch refused.
    r_mode = copy.deepcopy(results[0]); r_mode["proof"] = {"mode": "zk", "statement": "s", "proof_blob": "p"}
    CHECKS["fail-closed:proof-mode-mismatch-refused"] = refused(lambda: mc.verify_result(pack, r_mode, trusted))
    if not CHECKS["fail-closed:proof-mode-mismatch-refused"]:
        FAILURES.append("a proof.mode != pack.proof_mode must be refused")

    # 4. Residency violation refused (pack requires EU; node reports US).
    r_res = copy.deepcopy(results[0]); r_res["region"] = "US"
    CHECKS["fail-closed:residency-violation-refused"] = refused(lambda: mc.verify_result(pack, r_res, trusted))
    if not CHECKS["fail-closed:residency-violation-refused"]:
        FAILURES.append("a residency violation must be refused")

    # 5. Redundant split: 2 vs 1 => no strict majority is impossible; make a true split (1/1/1).
    split = copy.deepcopy(results)
    split[1]["result_cid"] = "sha256:" + "c" * 64
    split[2]["result_cid"] = "sha256:" + "d" * 64
    rec_split = mc.reduce(pack, split, trusted)
    if not rec_split["settled"] and not rec_split["rlc_credit"]:
        CHECKS["fail-closed:redundant-split-no-settle"] = True
    else:
        FAILURES.append(f"a redundant split must NOT settle: {rec_split}")

    # 6. Insufficient replicas (only 2, replication=3) => no settle.
    rec_few = mc.reduce(pack, results[:2], trusted)
    if not rec_few["settled"] and not rec_few["rlc_credit"]:
        CHECKS["fail-closed:insufficient-replicas-no-settle"] = True
    else:
        FAILURES.append(f"below-replication WU must NOT settle: {rec_few}")

    # 7. tee mode: present quote+measurement settles; missing measurement refused.
    tee_pack = copy.deepcopy(pack); tee_pack["proof_mode"] = "tee"; tee_pack["replication"] = 1
    r_tee = copy.deepcopy(results[0]); r_tee["proof"] = {"mode": "tee", "quote": "q", "measurement": "sha256:" + "e" * 64}
    rec_tee = mc.reduce(tee_pack, [r_tee], trusted)
    r_tee_bad = copy.deepcopy(r_tee); r_tee_bad["proof"] = {"mode": "tee", "quote": "q"}
    if rec_tee["settled"] and refused(lambda: mc.verify_result(tee_pack, r_tee_bad, trusted)):
        CHECKS["tee:present-settles-missing-refused"] = True
    else:
        FAILURES.append("tee: a valid quote+measurement must settle and a missing measurement be refused")

    # 8. Determinism.
    if mc.reduce(pack, results, trusted) == rec:
        CHECKS["deterministic:reproducible"] = True
    else:
        FAILURES.append("reduce is not deterministic")

    # 9. FABRIC: the coordinator ENFORCES pack.policy.requiredSuite via suite_gate (not just declares it).
    #    A suite-2 (CNSA) workload must NOT settle on suite-1 (FIPS) nodes, but settles on suite-2 nodes.
    cnsa_pack = copy.deepcopy(pack)
    cnsa_pack["policy"]["requiredSuite"] = 2
    fips_nodes = [{"node_ref": n["node_ref"], "attestationRef": n["attestationRef"], "region": n["region"], "suite": 1} for n in trusted]
    cnsa_nodes = [{"node_ref": n["node_ref"], "attestationRef": n["attestationRef"], "region": n["region"], "suite": 2} for n in trusted]
    on_fips = mc.reduce(cnsa_pack, results, fips_nodes)
    on_cnsa = mc.reduce(cnsa_pack, results, cnsa_nodes)
    if not on_fips["settled"] and len(on_fips["rejected"]) == len(results) and on_cnsa["settled"]:
        CHECKS["fabric:coordinator-enforces-required-suite"] = True
    else:
        FAILURES.append(f"coordinator did not enforce requiredSuite: on_fips={on_fips['settled']} on_cnsa={on_cnsa['settled']}")

    for m in FAILURES:
        print(f"FAIL: {m}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
