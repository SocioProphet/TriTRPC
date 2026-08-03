#!/usr/bin/env python3
"""Reference Mesh Coordinator — makes the Work-Unit contracts LIVE and fail-closed.

Dual-Orchestration plane B: a coordinator dispatches a `WorkUnitPack` to volunteer nodes and
collects `WorkUnitResult`s. This module implements the two steps a coordinator can decide
*deterministically* from the artifacts alone — VERIFY (per-result admission) and REDUCE (settlement)
— and emits an auditable settlement receipt. It is a reference settler, not a network stack: it does
not schedule or transport; it produces the checkable artifact a conformant coordinator must.

  * verify_result(pack, result, trusted): fail-closed admission of ONE result —
      - the node must be TRUSTED and ATTESTED (unattested / unknown node -> refused);
      - the node's region must satisfy pack.policy.residency (residency violation -> refused);
      - result.wu_id must match; the proof.mode must equal pack.proof_mode; and the proof must
        carry that mode's REQUIRED material (a mode mismatch or missing material -> refused).
  * reduce(pack, results, trusted): settle admissible results by proof_mode and assign RLC credit —
      - redundant: needs >= pack.replication admissible results; the accepted result is the CID held
        by a STRICT MAJORITY. No majority (a split / sabotage) -> NOT settled, no credit.
      - spot_check / tee / zk: the coordinator confirms the required proof material is present and
        well-formed (structural), then accepts; cryptographic proof-checking of a TEE quote or a zk
        proof is delegated to that mode's verifier (out of scope here, stated honestly). RLC credit
        goes ONLY to nodes whose result matches the accepted CID.

FIPS: content-addressing / agreement is over SHA-256 CIDs (FIPS 180-4) and SCHEMA-IDs over SHA3
(FIPS 202) — no non-FIPS primitive is used or required. This module performs no AEAD; the transport
AEAD is the CryptoProfile lane's job (AES-256-GCM in a FIPS deployment, never XChaCha20). It does not
touch the tritrpc v4/vNext wire format.
"""
from __future__ import annotations

import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(__file__))
import suite_gate  # noqa: E402  (the coordinator ENFORCES the suite gate — not just declares it)

PROOF_MODES = {"redundant", "spot_check", "tee", "zk"}
# The material each proof mode's result MUST carry to be admissible (beyond schema shape).
REQUIRED_PROOF_FIELDS = {
    "redundant": (),                                  # agreement is decided across replicas, not per-result
    "spot_check": ("challenge_index", "revealed_cid"),
    "tee": ("quote", "measurement"),
    "zk": ("statement", "proof_blob"),
}


class MeshCoordinatorError(Exception):
    pass


def _fail(m: str) -> None:
    raise MeshCoordinatorError(m)


def _trusted_index(trusted: Any) -> dict:
    """node_ref -> node record, admitting ONLY attested nodes (fail-closed: no attestationRef => not admitted)."""
    idx = {}
    for n in trusted or []:
        if not isinstance(n, dict):
            continue
        ref = n.get("node_ref")
        if str(ref or "").startswith("node://") and str(n.get("attestationRef") or "").strip():
            idx[ref] = n
    return idx


def _residency_ok(policy_region: str, node_region: str) -> bool:
    return policy_region == "any" or policy_region == node_region


def verify_result(pack: dict, result: dict, trusted: list) -> None:
    """Fail-closed admission of one result. Raises MeshCoordinatorError on any violation."""
    mode = pack.get("proof_mode")
    if mode not in PROOF_MODES:
        _fail(f"pack.proof_mode invalid: {mode!r}")
    if result.get("wu_id") != pack.get("wu_id"):
        _fail("result.wu_id does not match pack.wu_id")

    idx = _trusted_index(trusted)
    node_ref = result.get("node_ref")
    node = idx.get(node_ref)
    if node is None:
        _fail(f"node {node_ref!r} is not a trusted+attested mesh node (refused)")

    policy = pack.get("policy") or {}
    if not _residency_ok(policy.get("residency", "any"), result.get("region", "")):
        _fail(f"residency violation: pack requires {policy.get('residency')!r}, node in {result.get('region')!r}")

    # Enforce the workload's required assurance suite against the executing node (fabric, not a patch):
    # a suite-N workload MUST NOT settle on a node whose crypto profile suite is below N.
    if int(policy.get("requiredSuite", 0)) > 0:
        try:
            suite_gate.require_suite(pack, node)
        except suite_gate.SuiteError as exc:
            _fail(str(exc))

    proof = result.get("proof") or {}
    if proof.get("mode") != mode:
        _fail(f"proof.mode {proof.get('mode')!r} != pack.proof_mode {mode!r} (mode mismatch)")
    for field in REQUIRED_PROOF_FIELDS[mode]:
        if not str(proof.get(field) or "").strip() and proof.get(field) != 0:
            _fail(f"proof for mode {mode!r} is missing required material: {field!r}")


def reduce(pack: dict, results: list, trusted: list) -> dict:
    """Settle a WU from its collected results. Deterministic + fail-closed. Returns a settlement receipt."""
    mode = pack["proof_mode"]

    admissible, rejected = [], []
    for r in results or []:
        try:
            verify_result(pack, r, trusted)
            admissible.append(r)
        except MeshCoordinatorError as exc:
            rejected.append({"node_ref": r.get("node_ref"), "reason": str(exc)})

    settled = False
    accepted_cid = None
    method = mode
    quorum = {"admissible": len(admissible), "rejected": len(rejected)}

    if mode == "redundant":
        need = int(pack.get("replication", 1))
        quorum["required"] = need
        if len(admissible) >= need:
            tally: dict[str, int] = {}
            for r in admissible:
                tally[r["result_cid"]] = tally.get(r["result_cid"], 0) + 1
            top_cid, top_n = max(tally.items(), key=lambda kv: kv[1])
            quorum["agree"] = top_n
            # STRICT majority of the admissible set — a tie/split is a possible sabotage, so no settlement.
            if top_n * 2 > len(admissible):
                settled, accepted_cid = True, top_cid
    else:
        # spot_check / tee / zk: verify_result already confirmed the required proof material is present.
        if admissible:
            accepted_cid = admissible[0]["result_cid"]
            settled = True

    # RLC credit: only nodes whose result matches the accepted CID (nothing is paid on a failed settle).
    credited = [r["node_ref"] for r in admissible if settled and r["result_cid"] == accepted_cid]

    return {
        "wu_id": pack.get("wu_id"),
        "settled": settled,
        "method": method,
        "accepted_result_cid": accepted_cid,
        "quorum": quorum,
        "rlc_credit": credited,
        "rejected": rejected,
    }


if __name__ == "__main__":  # tiny demo on the shipped examples
    import json
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    ex = root / "examples" / "mesh"
    pack = json.loads((ex / "work_unit_pack.example.json").read_text())
    results = json.loads((ex / "work_unit_results.example.json").read_text())
    trusted = json.loads((ex / "trusted_nodes.example.json").read_text())
    print(json.dumps(reduce(pack, results, trusted), indent=2))
