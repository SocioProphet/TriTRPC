from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import yaml

from .boundary import BoundaryManifest, validate_boundary, validate_boundary_for_profile
from .policy import ProfileConfig, Severity, ValidationFinding, has_errors, validate_profile


class AssuranceTarget(str, Enum):
    RESEARCH = "research"
    STANDARDS_INSPIRED = "standards-inspired"
    APPROVED_LIKE = "approved-like"


@dataclass(frozen=True)
class DeploymentManifest:
    name: str
    assurance_target: AssuranceTarget
    profile: ProfileConfig
    boundary: BoundaryManifest | None
    ai_system: bool
    registry_version: str
    canonical_wire_locked: bool
    golden_vectors_path: str | None
    negative_tests: bool
    audit_enabled: bool
    audit_hash: str
    algorithm_transition_plan_path: str | None
    key_management_plan_path: str | None
    logging_plan_path: str | None
    cscrm_plan_path: str | None
    ssdf_aligned: bool
    ai_profile_aligned: bool
    separate_research_build: bool
    provenance_attested: bool
    cryptographic_inventory: bool
    manifest_signed: bool
    incident_response_hooks: bool
    base_dir: str

    @classmethod
    def load_yaml(cls, path: str | Path) -> "DeploymentManifest":
        path = Path(path)
        with path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
        base_dir = path.parent
        profile_path = base_dir / raw["profile"]
        with profile_path.open("r", encoding="utf-8") as handle:
            profile = ProfileConfig.from_mapping(yaml.safe_load(handle) or {})
        boundary = None
        if raw.get("boundary"):
            boundary = BoundaryManifest.load_yaml(base_dir / raw["boundary"])
        return cls(
            name=str(raw["name"]),
            assurance_target=AssuranceTarget(str(raw["assurance_target"])),
            profile=profile,
            boundary=boundary,
            ai_system=bool(raw.get("ai_system", True)),
            registry_version=str(raw.get("registry_version", "topic23.placeholder.v0")),
            canonical_wire_locked=bool(raw.get("canonical_wire_locked", False)),
            golden_vectors_path=raw.get("golden_vectors_path"),
            negative_tests=bool(raw.get("negative_tests", False)),
            audit_enabled=bool(raw.get("audit_enabled", False)),
            audit_hash=str(raw.get("audit_hash", "SHA-384")),
            algorithm_transition_plan_path=raw.get("algorithm_transition_plan_path"),
            key_management_plan_path=raw.get("key_management_plan_path"),
            logging_plan_path=raw.get("logging_plan_path"),
            cscrm_plan_path=raw.get("cscrm_plan_path"),
            ssdf_aligned=bool(raw.get("ssdf_aligned", False)),
            ai_profile_aligned=bool(raw.get("ai_profile_aligned", False)),
            separate_research_build=bool(raw.get("separate_research_build", False)),
            provenance_attested=bool(raw.get("provenance_attested", False)),
            cryptographic_inventory=bool(raw.get("cryptographic_inventory", False)),
            manifest_signed=bool(raw.get("manifest_signed", False)),
            incident_response_hooks=bool(raw.get("incident_response_hooks", False)),
            base_dir=str(base_dir),
        )

    def resolve(self, path_value: str | None) -> Path | None:
        if path_value is None:
            return None
        path = Path(path_value)
        if path.is_absolute():
            return path
        return Path(self.base_dir) / path



def _append(findings: list[ValidationFinding], requirement_id: str, severity: str, message: str) -> None:
    findings.append(ValidationFinding(requirement_id=requirement_id, severity=severity, message=message))



def validate_deployment(manifest: DeploymentManifest) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []

    require_cert = manifest.assurance_target == AssuranceTarget.APPROVED_LIKE
    findings.extend(validate_profile(manifest.profile, require_validated_module=require_cert))

    if manifest.assurance_target != AssuranceTarget.RESEARCH and manifest.boundary is None:
        _append(findings, "REQ-DEPLOY-001", Severity.ERROR, "Standards-inspired and approved-like deployments require an explicit boundary manifest")
    if manifest.boundary is not None:
        findings.extend(validate_boundary(manifest.boundary, require_certificate=require_cert))
        findings.extend(validate_boundary_for_profile(manifest.boundary, manifest.profile))

    if manifest.assurance_target != AssuranceTarget.RESEARCH:
        if not manifest.canonical_wire_locked:
            _append(findings, "REQ-DEPLOY-002", Severity.ERROR, "Deployment must lock canonical wire encoding")
        vectors = manifest.resolve(manifest.golden_vectors_path)
        if vectors is None or not vectors.exists():
            _append(findings, "REQ-DEPLOY-003", Severity.ERROR, "Deployment must point to existing golden vectors")
        if not manifest.negative_tests:
            _append(findings, "REQ-DEPLOY-004", Severity.ERROR, "Deployment must require negative / tamper tests")
        if not manifest.audit_enabled:
            _append(findings, "REQ-DEPLOY-005", Severity.ERROR, "Deployment must enable audit logging")
        if manifest.audit_hash.upper() not in {"SHA-384", "SHA-512"}:
            _append(findings, "REQ-DEPLOY-006", Severity.ERROR, "Deployment must use SHA-384 or SHA-512 for the audit chain")
        if not manifest.separate_research_build:
            _append(findings, "REQ-DEPLOY-007", Severity.ERROR, "Deployment must separate research and production/standards builds")
        if not manifest.provenance_attested:
            _append(findings, "REQ-DEPLOY-008", Severity.ERROR, "Deployment must require provenance attestation")
        if not manifest.cryptographic_inventory:
            _append(findings, "REQ-DEPLOY-009", Severity.ERROR, "Deployment must maintain a cryptographic inventory")
        if not manifest.manifest_signed:
            _append(findings, "REQ-DEPLOY-010", Severity.WARNING, "Deployment should sign the configuration/manifest set")
        if not manifest.incident_response_hooks:
            _append(findings, "REQ-DEPLOY-011", Severity.WARNING, "Deployment should wire audit outputs into incident response hooks")
        if not manifest.ssdf_aligned:
            _append(findings, "REQ-DEPLOY-012", Severity.ERROR, "Deployment must align to SSDF-like secure development practices")
        if manifest.ai_system and not manifest.ai_profile_aligned:
            _append(findings, "REQ-DEPLOY-013", Severity.ERROR, "AI deployments should align to the AI-focused SSDF profile")
        for req_id, doc_path, label in (
            ("REQ-DEPLOY-014", manifest.algorithm_transition_plan_path, "algorithm transition plan"),
            ("REQ-DEPLOY-015", manifest.key_management_plan_path, "key management plan"),
            ("REQ-DEPLOY-016", manifest.logging_plan_path, "logging plan"),
            ("REQ-DEPLOY-017", manifest.cscrm_plan_path, "supply-chain risk plan"),
        ):
            resolved = manifest.resolve(doc_path)
            if resolved is None or not resolved.exists():
                _append(findings, req_id, Severity.ERROR, f"Deployment must point to an existing {label}")

    if manifest.registry_version.strip() == "":
        _append(findings, "REQ-DEPLOY-018", Severity.ERROR, "Deployment must pin a registry version")
    return findings



def deployment_has_errors(manifest: DeploymentManifest) -> bool:
    return has_errors(validate_deployment(manifest))
