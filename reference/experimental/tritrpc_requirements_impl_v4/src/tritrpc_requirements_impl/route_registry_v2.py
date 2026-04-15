from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .codec import TritPack243Error
from .naming import BraidedId


@dataclass(frozen=True)
class RouteDescriptorV2:
    service: str
    method: str
    schema: str
    context_policy: str
    default_profile: str
    reply_semantics: str
    semantic_topic: int | None = None
    default_braid: int | None = None
    default_state_policy: str | None = None
    observability_class: str = "standard"
    privacy_class: str = "internal"
    retention_class: str = "canonical"
    evidence_min_grade: str = "exact"
    policy_bundle_ref: str | None = None
    telemetry_profile_ref: str | None = None
    allowed_execution_venues: tuple[str, ...] = ()
    allowed_tool_origins: tuple[str, ...] = ()
    default_semaphores: tuple[str, ...] = ()
    latched_semaphores: tuple[str, ...] = ()
    allowed_overrides: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "RouteDescriptorV2":
        return cls(
            service=str(mapping["service"]),
            method=str(mapping["method"]),
            schema=str(mapping["schema"]),
            context_policy=str(mapping["context_policy"]),
            default_profile=str(mapping["default_profile"]),
            reply_semantics=str(mapping["reply_semantics"]),
            semantic_topic=mapping.get("semantic_topic"),
            default_braid=mapping.get("default_braid"),
            default_state_policy=mapping.get("default_state_policy"),
            observability_class=str(mapping.get("observability_class", "standard")),
            privacy_class=str(mapping.get("privacy_class", "internal")),
            retention_class=str(mapping.get("retention_class", "canonical")),
            evidence_min_grade=str(mapping.get("evidence_min_grade", "exact")),
            policy_bundle_ref=mapping.get("policy_bundle_ref"),
            telemetry_profile_ref=mapping.get("telemetry_profile_ref"),
            allowed_execution_venues=tuple(mapping.get("allowed_execution_venues", [])),
            allowed_tool_origins=tuple(mapping.get("allowed_tool_origins", [])),
            default_semaphores=tuple(mapping.get("default_semaphores", [])),
            latched_semaphores=tuple(mapping.get("latched_semaphores", [])),
            allowed_overrides=tuple(mapping.get("allowed_overrides", [])),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "method": self.method,
            "schema": self.schema,
            "context_policy": self.context_policy,
            "default_profile": self.default_profile,
            "reply_semantics": self.reply_semantics,
            "semantic_topic": self.semantic_topic,
            "default_braid": self.default_braid,
            "default_state_policy": self.default_state_policy,
            "observability_class": self.observability_class,
            "privacy_class": self.privacy_class,
            "retention_class": self.retention_class,
            "evidence_min_grade": self.evidence_min_grade,
            "policy_bundle_ref": self.policy_bundle_ref,
            "telemetry_profile_ref": self.telemetry_profile_ref,
            "allowed_execution_venues": list(self.allowed_execution_venues),
            "allowed_tool_origins": list(self.allowed_tool_origins),
            "default_semaphores": list(self.default_semaphores),
            "latched_semaphores": list(self.latched_semaphores),
            "allowed_overrides": list(self.allowed_overrides),
        }


@dataclass
class RouteRegistryV2:
    routes: dict[int, RouteDescriptorV2] = field(default_factory=dict)
    identities: dict[int, BraidedId] = field(default_factory=dict)

    @classmethod
    def load_yaml(cls, path: str | Path) -> "RouteRegistryV2":
        with open(path, "r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
        routes: dict[int, RouteDescriptorV2] = {}
        for key, value in (raw.get("routes") or {}).items():
            routes[int(key)] = RouteDescriptorV2.from_mapping(value)
        identities: dict[int, BraidedId] = {}
        for key, value in (raw.get("identities") or {}).items():
            identities[int(key)] = BraidedId.parse(value["canonical_id"])
        return cls(routes=routes, identities=identities)

    def route(self, handle: int) -> RouteDescriptorV2:
        try:
            return self.routes[handle]
        except KeyError as exc:
            raise TritPack243Error(f"unknown route handle {handle}") from exc

    def identity(self, handle: int) -> BraidedId:
        try:
            return self.identities[handle]
        except KeyError as exc:
            raise TritPack243Error(f"unknown identity handle {handle}") from exc
