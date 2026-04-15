from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ResourceIdentity:
    resource_id: str
    service_name: str
    service_version: str | None = None
    surface: str = "cli"
    provider_name: str = "internal"
    provider_route: str | None = None
    region: str | None = None
    terminal_type: str | None = None


@dataclass(frozen=True)
class ReleaseBuildAttestation:
    build_id: str
    package_digest: str
    artifact_manifest_digest: str
    release_channel: str
    sourcemap_policy: str
    debug_symbols_policy: str
    policy_bundle_hash: str | None = None


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    resource_id: str
    build_id: str | None = None
    transcript_ref: str | None = None
    surface: str = "cli"
    execution_venue: str = "local_terminal"
    initial_permission_mode: str | None = None
    initial_control_snapshot_id: str | None = None


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    session_id: str
    turn_index: int
    model_canonical: str
    api_version: str
    beta_headers: tuple[str, ...] = ()
    stop_reason: str | None = None
    request_ids: tuple[str, ...] = ()
    control_snapshot_id: str | None = None
    usage_snapshot_id: str | None = None


@dataclass(frozen=True)
class ControlSnapshot:
    control_snapshot_id: str
    session_id: str
    run_id: str | None = None
    settings_hash: str | None = None
    system_prompt_hash: str | None = None
    memory_manifest_hash: str | None = None
    permission_mode: str | None = None
    tool_catalog_hash: str | None = None
    execution_venue: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecisionRecord:
    decision_id: str
    session_id: str
    run_id: str | None = None
    decision_layer: str = "policy"
    decision: str = "allow"
    reason: str | None = None
    policy_bundle_hash: str | None = None
    semaphore_family: str | None = None
    old_state: str | None = None
    new_state: str | None = None


@dataclass(frozen=True)
class ToolCallRecord:
    tool_call_id: str
    session_id: str
    run_id: str | None = None
    tool_use_id: str | None = None
    parent_tool_use_id: str | None = None
    tool_name: str = ""
    tool_origin: str = "client"
    execution_venue: str = "local_terminal"
    allowed: bool = True
    retention_class: str = "canonical"


@dataclass(frozen=True)
class ContextManagementEvent:
    event_id: str
    session_id: str
    run_id: str | None = None
    context_strategy: str = "compaction"
    trigger: str = "manual"
    context_loss_risk_score: float = 0.0


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    session_id: str
    run_id: str | None = None
    source_class: str = "web"
    source_role: str = "authority"
    source_ref: str | None = None
    trust_rank: str = "standard"


@dataclass(frozen=True)
class ArtifactOutcome:
    artifact_id: str
    session_id: str
    run_id: str | None = None
    artifact_type: str = "report"
    artifact_digest: str | None = None
    accepted_by_user: bool | None = None
