from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .telemetry import ArtifactOutcome, ControlSnapshot, PolicyDecisionRecord, RunRecord, SessionRecord


def render_run_card(
    session: SessionRecord,
    run: RunRecord,
    control: ControlSnapshot | None,
    artifacts: list[ArtifactOutcome] | None = None,
) -> dict[str, Any]:
    return {
        "session_id": session.session_id,
        "run_id": run.run_id,
        "turn_index": run.turn_index,
        "surface": session.surface,
        "execution_venue": session.execution_venue,
        "model_canonical": run.model_canonical,
        "api_version": run.api_version,
        "beta_headers": list(run.beta_headers),
        "stop_reason": run.stop_reason,
        "control_snapshot": asdict(control) if control else None,
        "artifacts": [asdict(item) for item in (artifacts or [])],
    }


def render_policy_posture(decisions: list[PolicyDecisionRecord]) -> dict[str, Any]:
    counters: dict[str, int] = {}
    for decision in decisions:
        key = f"{decision.decision_layer}:{decision.decision}"
        counters[key] = counters.get(key, 0) + 1
    return {
        "decision_counts": counters,
        "latched_transitions": [
            asdict(item) for item in decisions if item.new_state and item.new_state.endswith("latched")
        ],
    }


def render_context_health(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {"events": events, "count": len(events)}


def render_release_attestation(attestation: dict[str, Any]) -> dict[str, Any]:
    return dict(attestation)


def render_operational_health(
    has_reasoning: bool,
    web_sources: int,
    citations: int,
    artifacts: int,
) -> dict[str, Any]:
    return {
        "hidden_reasoning": {"available": True, "used": has_reasoning},
        "web_verification": {"used": web_sources > 0, "source_count": web_sources},
        "citation_pipeline": {"used": citations > 0, "citation_count": citations},
        "artifact_generation": {"used": artifacts > 0, "artifact_count": artifacts},
    }
