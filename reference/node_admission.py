#!/usr/bin/env python3
"""Reference node-admission gate — decides which nodes ENTER the mesh trusted set (fail-closed).

This is the loop-closer for the Mesh Coordinator: reference/mesh_coordinator.py refuses any result
from a node that is not in its `trusted` set; this module decides who gets INTO that set. It scores a
NodeReputation with a bounded rendering of the Trust Equation and applies an AdmissionPolicy whose
every gate must pass. On admission it emits EXACTLY the trusted-node record shape the coordinator
consumes ({node_ref, attestationRef, region}), so an admitted reputation plugs straight in.

Trust score (bounded [0,1] rendering of the classic Trust Equation T=(C+R+I)/S):
    trust = mean(credibility, reliability, intimacy) * (1 - selfOrientation)
Monotone: raising any of C/R/I (or lowering self-orientation) never lowers trust. History with fewer
than the policy's minimum observations is not statistically admissible (estate default >= 30).

FIPS: no cryptographic primitive is used here (pure scoring); attestation VERIFICATION is delegated
to the attestation lane — this gate only requires that an attestationRef is PRESENT when the policy
demands it. Does not touch the tritrpc v4/vNext wire format.
"""
from __future__ import annotations

from typing import Any


class AdmissionError(Exception):
    pass


def trust_score(rep: dict) -> float:
    """Bounded Trust-Equation score in [0,1]."""
    t = rep["trust"]
    mean_cri = (t["credibility"] + t["reliability"] + t["intimacy"]) / 3.0
    return mean_cri * (1.0 - t["selfOrientation"])


def admit(rep: dict, policy: dict) -> dict:
    """Decide admission. Returns {admitted, node_ref, trustScore, reasons, trustedNode?}. Fail-closed:
    a malformed reputation raises AdmissionError; a well-formed but under-qualified one is NOT admitted
    (admitted:false) with the failing reasons. Only a fully-passing node yields a trustedNode record."""
    for key in ("node_ref", "attestationRef", "region", "trust", "energy", "history"):
        if key not in rep:
            raise AdmissionError(f"reputation missing required field: {key!r}")
    if not str(rep["node_ref"]).startswith("node://"):
        raise AdmissionError("node_ref must use the node:// URI shape")

    score = trust_score(rep)
    reasons: list[str] = []

    if policy.get("requireAttestation") and not str(rep.get("attestationRef") or "").strip():
        reasons.append("no attestation presented (policy requires attestation)")
    obs = rep["history"]["observations"]
    if obs < policy["minObservations"]:
        reasons.append(f"insufficient history: {obs} observations < minimum {policy['minObservations']}")
    if rep["trust"]["selfOrientation"] > policy["maxSelfOrientation"]:
        reasons.append(f"self-orientation {rep['trust']['selfOrientation']} exceeds max {policy['maxSelfOrientation']}")
    if rep["energy"]["civility"] < policy["minCivility"]:
        reasons.append(f"civility {rep['energy']['civility']} below floor {policy['minCivility']} (abuse guard)")
    if score < policy["minTrust"]:
        reasons.append(f"trust score {score:.4f} < minimum {policy['minTrust']}")

    admitted = not reasons
    out: dict[str, Any] = {
        "admitted": admitted,
        "node_ref": rep["node_ref"],
        "trustScore": round(score, 4),
        "reasons": reasons,
    }
    if admitted:
        # the exact record shape reference/mesh_coordinator.py's trusted set consumes.
        out["trustedNode"] = {
            "node_ref": rep["node_ref"],
            "attestationRef": rep["attestationRef"],
            "region": rep["region"],
        }
    return out


if __name__ == "__main__":  # demo: admit the shipped example, then feed the coordinator
    import json
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    ex = root / "examples" / "mesh"
    rep = json.loads((ex / "node_reputation.example.json").read_text())
    policy = json.loads((ex / "admission_policy.example.json").read_text())
    print(json.dumps(admit(rep, policy), indent=2))
