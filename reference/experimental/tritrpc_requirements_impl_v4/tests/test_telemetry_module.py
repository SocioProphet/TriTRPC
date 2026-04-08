from tritrpc_requirements_impl.telemetry import (
    ArtifactOutcome,
    ControlSnapshot,
    EvidenceRecord,
    PolicyDecisionRecord,
    ReleaseBuildAttestation,
    ResourceIdentity,
    RunRecord,
    SessionRecord,
    ToolCallRecord,
)



def test_resource_identity_defaults() -> None:
    resource = ResourceIdentity(resource_id="resource_demo", service_name="tritrpc")
    assert resource.surface == "cli"
    assert resource.provider_name == "internal"



def test_release_build_attestation_round_trip() -> None:
    attestation = ReleaseBuildAttestation(
        build_id="build_demo",
        package_digest="sha256:pkg",
        artifact_manifest_digest="sha256:manifest",
        release_channel="draft",
        sourcemap_policy="private_only",
        debug_symbols_policy="private_only",
    )
    assert attestation.build_id == "build_demo"
    assert attestation.release_channel == "draft"



def test_session_run_and_control_snapshot() -> None:
    session = SessionRecord(session_id="sess_demo", resource_id="resource_demo")
    run = RunRecord(run_id="run_demo", session_id=session.session_id, turn_index=1, model_canonical="demo-model", api_version="v1")
    control = ControlSnapshot(control_snapshot_id="ctrl_demo", session_id=session.session_id, run_id=run.run_id, permission_mode="default")
    assert run.session_id == session.session_id
    assert control.run_id == run.run_id
    assert control.permission_mode == "default"



def test_policy_decision_and_tool_call() -> None:
    decision = PolicyDecisionRecord(
        decision_id="dec_demo",
        session_id="sess_demo",
        decision_layer="policy",
        decision="deny",
        semaphore_family="review_mode",
        old_state="auto",
        new_state="human_required",
    )
    tool_call = ToolCallRecord(
        tool_call_id="tool_demo",
        session_id="sess_demo",
        tool_name="web_search",
        tool_origin="server",
        allowed=False,
        retention_class="canonical",
    )
    assert decision.new_state == "human_required"
    assert tool_call.tool_origin == "server"
    assert tool_call.allowed is False



def test_evidence_and_artifact_outcome() -> None:
    evidence = EvidenceRecord(evidence_id="e1", session_id="sess_demo", source_class="web", source_role="authority")
    artifact = ArtifactOutcome(artifact_id="a1", session_id="sess_demo", artifact_type="report", accepted_by_user=True)
    assert evidence.source_class == "web"
    assert artifact.accepted_by_user is True
