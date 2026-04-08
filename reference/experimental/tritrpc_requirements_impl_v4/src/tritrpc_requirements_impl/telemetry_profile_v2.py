from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import yaml


@dataclass(frozen=True)
class TelemetryProfileV2:
    schema_version: str
    redaction_profile: str
    retention_profile: str
    otel_export_profile: str | None = None
    control_snapshot_required: bool = True
    event_ledger_required: bool = True
    release_attestation_required: bool = True
    context_management_logging: bool = True
    subagent_lineage_required: bool = True
    materialized_views: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "TelemetryProfileV2":
        return cls(
            schema_version=str(mapping["schema_version"]),
            redaction_profile=str(mapping["redaction_profile"]),
            retention_profile=str(mapping["retention_profile"]),
            otel_export_profile=mapping.get("otel_export_profile"),
            control_snapshot_required=bool(mapping.get("control_snapshot_required", True)),
            event_ledger_required=bool(mapping.get("event_ledger_required", True)),
            release_attestation_required=bool(mapping.get("release_attestation_required", True)),
            context_management_logging=bool(mapping.get("context_management_logging", True)),
            subagent_lineage_required=bool(mapping.get("subagent_lineage_required", True)),
            materialized_views=tuple(mapping.get("materialized_views", [])),
        )

    @classmethod
    def load_yaml(cls, path: str) -> "TelemetryProfileV2":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_mapping(yaml.safe_load(handle) or {})

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)


def validate_telemetry_profile_v2(profile: TelemetryProfileV2) -> list[str]:
    errors: list[str] = []
    if not profile.schema_version.strip():
        errors.append("REQ-TELEM-001")
    if not profile.redaction_profile.strip():
        errors.append("REQ-TELEM-002")
    if not profile.retention_profile.strip():
        errors.append("REQ-TELEM-003")
    return errors
