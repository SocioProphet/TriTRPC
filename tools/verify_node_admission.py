#!/usr/bin/env python3
"""Verify the reference node-admission gate is fail-closed AND closes the loop into the coordinator.

Runs reference/node_admission.py on the shipped example reputation + policy and asserts: a qualified
node is admitted and yields a trustedNode record; that record plugs straight into
reference/mesh_coordinator.py (an admitted node's WU result settles) — the loop-closure proof; and
then, fail-closed — unattested, under-observed (n<min), self-oriented, low-civility, and below-trust
reputations are each NOT admitted with the right reason. Plus trust monotonicity, determinism, and a
schema drift-guard. Stdlib, repo convention.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import node_admission as na  # noqa: E402
import mesh_coordinator as mc  # noqa: E402

EX = ROOT / "examples" / "mesh"
SCHEMAS = ROOT / "schemas" / "jsonschema"
REP_SCHEMA = SCHEMAS / "node-reputation.v0.schema.json"
POL_SCHEMA = SCHEMAS / "admission-policy.v0.schema.json"
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def load(name: str):
    return json.loads((EX / name).read_text())


def not_admitted_for(rep, policy, needle: str) -> bool:
    d = na.admit(rep, policy)
    return (not d["admitted"]) and any(needle in r for r in d["reasons"])


def validate_schemas() -> None:
    rep = json.loads(REP_SCHEMA.read_text())
    pol = json.loads(POL_SCHEMA.read_text())
    for name, s in (("reputation", rep), ("policy", pol)):
        if s.get("additionalProperties") is not False:
            raise na.AdmissionError(f"{name} schema root must be strict")
    if set(rep["properties"]["trust"]["required"]) != {"credibility", "reliability", "intimacy", "selfOrientation"}:
        raise na.AdmissionError("reputation.trust.required drifted from the Trust-Equation dimensions")
    if set(rep["properties"]["energy"]["required"]) != {"knowledge", "creativity", "civility"}:
        raise na.AdmissionError("reputation.energy.required drifted")
    need_pol = {"minTrust", "maxSelfOrientation", "minObservations", "minCivility", "requireAttestation"}
    if set(pol["required"]) != need_pol:
        raise na.AdmissionError("admission-policy.required drifted from the enforced gates")
    # example conformance: no keys outside declared properties.
    for rec, s in ((load("node_reputation.example.json"), rep), (load("admission_policy.example.json"), pol)):
        extra = set(rec) - set(s["properties"])
        if extra:
            raise na.AdmissionError(f"example has keys not in schema: {sorted(extra)}")


def main() -> int:
    try:
        validate_schemas()
        CHECKS["schema:no-drift-and-example-conformant"] = True
    except na.AdmissionError as exc:
        FAILURES.append(f"schema drift-guard failed: {exc}")

    rep = load("node_reputation.example.json")
    policy = load("admission_policy.example.json")

    # 1. Qualified node admitted + emits a trustedNode record.
    d = na.admit(rep, policy)
    if d["admitted"] and d.get("trustedNode", {}).get("node_ref") == rep["node_ref"] and not d["reasons"]:
        CHECKS["admit:qualified-node-admitted"] = True
    else:
        FAILURES.append(f"qualified node was not admitted cleanly: {d}")

    # 2. LOOP CLOSURE: the admitted trustedNode plugs into the coordinator and a result settles.
    trusted = [d["trustedNode"]] if d["admitted"] else []
    pack = {"wu_id": "wu-x", "proof_mode": "tee", "sandbox": "wasm",
            "policy": {"residency": "EU", "isolation": "strong", "slo_ms": 1000},
            "replication": 1}
    import hashlib as _hl
    _rc = "sha256:" + "a" * 64
    _nonce = "n-adm-1"
    _rd = "sha256:" + _hl.sha256(f"{_nonce}|{_rc}".encode()).hexdigest()
    result = {"wu_id": "wu-x", "node_ref": rep["node_ref"], "region": rep["region"],
              "result_cid": _rc,
              "proof": {"mode": "tee", "quote": "q", "measurement": "sha256:" + "e" * 64,
                        "nonce": _nonce, "report_data": _rd}}
    rec = mc.reduce(pack, [result], trusted)
    if rec["settled"] and rec["rlc_credit"] == [rep["node_ref"]]:
        CHECKS["loop:admitted-node-settles-in-coordinator"] = True
    else:
        FAILURES.append(f"admitted node did not settle in the coordinator: {rec}")

    # 3-7. Fail-closed refusals (each mutates one dimension).
    no_att = copy.deepcopy(rep); no_att["attestationRef"] = ""
    CHECKS["fail-closed:unattested-refused"] = not_admitted_for(no_att, policy, "no attestation")
    few = copy.deepcopy(rep); few["history"]["observations"] = 10
    CHECKS["fail-closed:under-observed-refused"] = not_admitted_for(few, policy, "insufficient history")
    selfish = copy.deepcopy(rep); selfish["trust"]["selfOrientation"] = 0.9
    CHECKS["fail-closed:self-oriented-refused"] = not_admitted_for(selfish, policy, "self-orientation")
    rude = copy.deepcopy(rep); rude["energy"]["civility"] = 0.1
    CHECKS["fail-closed:low-civility-refused"] = not_admitted_for(rude, policy, "civility")
    weak = copy.deepcopy(rep)
    weak["trust"].update(credibility=0.2, reliability=0.2, intimacy=0.2)
    CHECKS["fail-closed:below-trust-refused"] = not_admitted_for(weak, policy, "trust score")
    for k in ("fail-closed:unattested-refused", "fail-closed:under-observed-refused",
              "fail-closed:self-oriented-refused", "fail-closed:low-civility-refused", "fail-closed:below-trust-refused"):
        if not CHECKS[k]:
            FAILURES.append(f"{k} did not fire")

    # 8. Monotonicity: raising credibility never lowers the trust score.
    prev = -1.0
    mono = True
    for c in [i / 20 for i in range(21)]:
        r = copy.deepcopy(rep); r["trust"]["credibility"] = c
        s = na.trust_score(r)
        if s + 1e-12 < prev:
            mono = False
            break
        prev = s
    CHECKS["monotone:credibility-nondecreasing"] = mono
    if not mono:
        FAILURES.append("trust score is not monotone non-decreasing in credibility")

    # 9. Determinism.
    if na.admit(rep, policy) == d:
        CHECKS["deterministic:reproducible"] = True
    else:
        FAILURES.append("admit is not deterministic")

    for m in FAILURES:
        print(f"FAIL: {m}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
