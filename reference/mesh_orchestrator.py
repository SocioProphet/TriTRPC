"""Mesh orchestrator — the one pipeline that consumes every mesh stage (the fabric, not a patch).

Runs a Work-Unit end to end by composing the stages, so no stage is an orphan:

    admit (node_admission) -> register + heartbeat/liveness (mesh_runtime) -> schedule (mesh_scheduler)
    -> dispatch (mesh_runtime) -> collect (mesh_scheduler) -> settle (mesh_coordinator, which itself
    enforces suite_gate + proof_envelope + attestation_verifier)

Fail-closed throughout: a node that is not admitted never enters the trusted set, so it can never be
scheduled, dispatched to, or credited. FIPS-clean (SHA-256/SHA3 downstream); does not touch the wire.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import mesh_coordinator  # noqa: E402
import mesh_runtime  # noqa: E402
import mesh_scheduler  # noqa: E402
import node_admission  # noqa: E402


class OrchestratorError(Exception):
    pass


def run_work_unit(reputations: list, admission_policy: dict, pack: dict,
                  node_runtime: dict, results: list, now: int) -> dict:
    """Compose the full mesh pipeline for one WU. `node_runtime` maps node_ref -> {suite, capacity,
    liveness} (the runtime facts admission/reputation doesn't carry). Returns the settlement receipt
    plus the admitted set and schedule, so the whole chain is auditable."""
    # 1. ADMIT — only admitted reputations become trusted nodes / registry entries.
    trusted, registry = [], []
    for rep in reputations:
        decision = node_admission.admit(rep, admission_policy)
        if not decision["admitted"]:
            continue
        tn = dict(decision["trustedNode"])
        rt = node_runtime.get(tn["node_ref"], {})
        tn["suite"] = rt.get("suite", 0)
        trusted.append(tn)
        registry.append({
            "node_ref": tn["node_ref"], "attestationRef": tn["attestationRef"], "region": tn["region"],
            "trustScore": decision["trustScore"],
            "capacity": rt.get("capacity", {"freeSlots": 1, "sandboxes": [pack.get("sandbox", "wasm")]}),
            "liveness": rt.get("liveness", {"lastSeenMs": now, "ttlMs": 10_000}),
        })
    trusted_refs = {t["node_ref"] for t in trusted}

    # 2. SCHEDULE — over the LIVE registry only (fail-closed if too few eligible).
    schedule = mesh_scheduler.schedule(mesh_runtime.live_nodes(registry, now), pack, now)

    # 3. DISPATCH — every assignment must be admissible (assigned + live + before deadline).
    for a in schedule["assignments"]:
        asn = mesh_runtime.build_assignment(pack, a["node_ref"], now)
        mesh_runtime.check_assignment(asn, schedule, registry, now)

    # 4. COLLECT — keep only assigned results that arrived by the SLO deadline.
    deadline = now + int((pack.get("policy") or {}).get("slo_ms", 0))
    collected = mesh_scheduler.collect(schedule, results, deadline)["collected"]

    # 5. SETTLE — the coordinator enforces suite_gate + proof_envelope + attestation_verifier internally.
    settlement = mesh_coordinator.reduce(pack, collected, trusted)

    return {
        "admitted": sorted(trusted_refs),
        "scheduled": [a["node_ref"] for a in schedule["assignments"]],
        "collected": len(collected),
        "settlement": settlement,
    }
