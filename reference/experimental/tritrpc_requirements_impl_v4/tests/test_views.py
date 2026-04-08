from tritrpc_requirements_impl.telemetry import ArtifactOutcome, ControlSnapshot, PolicyDecisionRecord, RunRecord, SessionRecord
from tritrpc_requirements_impl.views import render_operational_health, render_policy_posture, render_run_card



def test_render_run_card() -> None:
    session = SessionRecord(session_id="sess_demo", resource_id="resource_demo", execution_venue="local_terminal")
    run = RunRecord(run_id="run_demo", session_id="sess_demo", turn_index=1, model_canonical="demo-model", api_version="v1")
    control = ControlSnapshot(control_snapshot_id="ctrl_demo", session_id="sess_demo", permission_mode="default")
    artifact = ArtifactOutcome(artifact_id="art_demo", session_id="sess_demo", artifact_type="report")
    card = render_run_card(session=session, run=run, control=control, artifacts=[artifact])
    assert card["run_id"] == "run_demo"
    assert card["execution_venue"] == "local_terminal"
    assert len(card["artifacts"]) == 1



def test_render_policy_posture() -> None:
    decisions = [
        PolicyDecisionRecord(decision_id="d1", session_id="sess", decision_layer="policy", decision="allow"),
        PolicyDecisionRecord(decision_id="d2", session_id="sess", decision_layer="policy", decision="deny", new_state="incident_latched"),
    ]
    posture = render_policy_posture(decisions)
    assert posture["decision_counts"]["policy:allow"] == 1
    assert posture["decision_counts"]["policy:deny"] == 1
    assert len(posture["latched_transitions"]) == 1



def test_render_operational_health() -> None:
    health = render_operational_health(has_reasoning=True, web_sources=2, citations=3, artifacts=1)
    assert health["hidden_reasoning"]["used"] is True
    assert health["web_verification"]["source_count"] == 2
    assert health["citation_pipeline"]["citation_count"] == 3
    assert health["artifact_generation"]["artifact_count"] == 1
