from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from .policy import ProfileConfig, Severity, ValidationFinding


@dataclass(frozen=True)
class BoundaryManifest:
    module_name: str
    certificate: str | None = None
    standard: str | None = None
    status: str | None = None
    approved_mode: bool = False
    module_type: str = "software"
    runtime_binding: str = ""
    operational_environment: dict[str, str] = field(default_factory=dict)
    selected_aead: tuple[str, ...] = ()
    selected_hashes: tuple[str, ...] = ()
    selected_key_establishment: tuple[str, ...] = ()
    selected_signatures: tuple[str, ...] = ()
    selected_transports: tuple[str, ...] = ()
    self_tests_power_up: bool = False
    self_tests_conditional: bool = False
    error_state_on_self_test_failure: bool = False
    entropy_source_documented: bool = False
    sbom_path: str | None = None
    provenance_path: str | None = None
    security_policy_url: str | None = None
    source_revision: str | None = None
    fail_closed: bool = False
    zeroization_attempted: bool = False
    key_separation_documented: bool = False
    notes: dict[str, Any] = field(default_factory=dict)
    base_dir: str | None = None

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any], base_dir: str | None = None) -> "BoundaryManifest":
        return cls(
            module_name=str(mapping["module_name"]),
            certificate=mapping.get("certificate"),
            standard=mapping.get("standard"),
            status=mapping.get("status"),
            approved_mode=bool(mapping.get("approved_mode", False)),
            module_type=str(mapping.get("module_type", "software")),
            runtime_binding=str(mapping.get("runtime_binding", "")),
            operational_environment=dict(mapping.get("operational_environment", {})),
            selected_aead=tuple(mapping.get("selected_aead", [])),
            selected_hashes=tuple(mapping.get("selected_hashes", [])),
            selected_key_establishment=tuple(mapping.get("selected_key_establishment", [])),
            selected_signatures=tuple(mapping.get("selected_signatures", [])),
            selected_transports=tuple(mapping.get("selected_transports", [])),
            self_tests_power_up=bool(mapping.get("self_tests_power_up", False)),
            self_tests_conditional=bool(mapping.get("self_tests_conditional", False)),
            error_state_on_self_test_failure=bool(mapping.get("error_state_on_self_test_failure", False)),
            entropy_source_documented=bool(mapping.get("entropy_source_documented", False)),
            sbom_path=mapping.get("sbom_path"),
            provenance_path=mapping.get("provenance_path"),
            security_policy_url=mapping.get("security_policy_url"),
            source_revision=mapping.get("source_revision"),
            fail_closed=bool(mapping.get("fail_closed", False)),
            zeroization_attempted=bool(mapping.get("zeroization_attempted", False)),
            key_separation_documented=bool(mapping.get("key_separation_documented", False)),
            notes=dict(mapping.get("notes", {})),
            base_dir=base_dir,
        )

    @classmethod
    def load_yaml(cls, path: str | Path) -> "BoundaryManifest":
        path = Path(path)
        with path.open("r", encoding="utf-8") as handle:
            return cls.from_mapping(yaml.safe_load(handle) or {}, base_dir=str(path.parent))

    def resolve_path(self, maybe_relative: str | None) -> Path | None:
        if maybe_relative is None:
            return None
        path = Path(maybe_relative)
        if path.is_absolute():
            return path
        if self.base_dir is None:
            return path
        return Path(self.base_dir) / path



def _append(findings: list[ValidationFinding], requirement_id: str, severity: str, message: str) -> None:
    findings.append(ValidationFinding(requirement_id=requirement_id, severity=severity, message=message))



def validate_boundary(boundary: BoundaryManifest, require_certificate: bool = False) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []

    if not boundary.module_name:
        _append(findings, "REQ-BOUNDARY-001", Severity.ERROR, "Boundary manifest must declare a module_name")
    if not boundary.runtime_binding:
        _append(findings, "REQ-BOUNDARY-002", Severity.ERROR, "Boundary manifest must declare a runtime_binding")
    if len(boundary.operational_environment) < 2:
        _append(findings, "REQ-BOUNDARY-003", Severity.WARNING, "Boundary manifest should pin the tested operational environment (for example os + arch)")
    if not boundary.self_tests_power_up or not boundary.self_tests_conditional:
        _append(findings, "REQ-BOUNDARY-004", Severity.ERROR, "Boundary manifest must document both power-up and conditional self-tests")
    if not boundary.error_state_on_self_test_failure:
        _append(findings, "REQ-BOUNDARY-005", Severity.ERROR, "Boundary manifest must fail closed on self-test failure")
    if not boundary.entropy_source_documented:
        _append(findings, "REQ-BOUNDARY-006", Severity.ERROR, "Boundary manifest must document the entropy source / RNG boundary")
    if not boundary.fail_closed:
        _append(findings, "REQ-BOUNDARY-007", Severity.ERROR, "Boundary manifest must require fail_closed behavior")
    if not boundary.zeroization_attempted:
        _append(findings, "REQ-BOUNDARY-008", Severity.WARNING, "Boundary manifest should document zeroization / key erasure behavior")
    if not boundary.key_separation_documented:
        _append(findings, "REQ-BOUNDARY-009", Severity.WARNING, "Boundary manifest should document separation of key roles / key usage")
    if not boundary.source_revision:
        _append(findings, "REQ-BOUNDARY-010", Severity.WARNING, "Boundary manifest should pin the source revision or build identity")
    if not boundary.security_policy_url:
        _append(findings, "REQ-BOUNDARY-011", Severity.INFO, "Boundary manifest should reference a security policy or local equivalent")

    sbom = boundary.resolve_path(boundary.sbom_path)
    if sbom is None or not sbom.exists():
        _append(findings, "REQ-SUPPLY-001", Severity.ERROR, "Boundary manifest must point to an existing SBOM artifact")
    provenance = boundary.resolve_path(boundary.provenance_path)
    if provenance is None or not provenance.exists():
        _append(findings, "REQ-SUPPLY-002", Severity.ERROR, "Boundary manifest must point to an existing provenance artifact")

    if require_certificate:
        if not boundary.certificate:
            _append(findings, "REQ-BOUNDARY-012", Severity.ERROR, "Approved-like boundary requires a certificate number")
        if boundary.standard != "FIPS 140-3":
            _append(findings, "REQ-BOUNDARY-013", Severity.ERROR, "Approved-like boundary requires FIPS 140-3 as the referenced module standard")
        if (boundary.status or "").lower() != "active":
            _append(findings, "REQ-BOUNDARY-014", Severity.ERROR, "Approved-like boundary requires an active module status")
        if not boundary.approved_mode:
            _append(findings, "REQ-BOUNDARY-015", Severity.ERROR, "Approved-like boundary requires approved_mode=true")
    else:
        if not boundary.certificate:
            _append(findings, "REQ-BOUNDARY-012A", Severity.WARNING, "No certificate number is attached; this boundary can mimic standards but not claim validation pedigree")

    if not boundary.selected_aead:
        _append(findings, "REQ-BOUNDARY-016", Severity.ERROR, "Boundary manifest must declare the selected AEAD set")
    if not boundary.selected_hashes:
        _append(findings, "REQ-BOUNDARY-017", Severity.ERROR, "Boundary manifest must declare the selected hash set")
    if not boundary.selected_transports:
        _append(findings, "REQ-BOUNDARY-018", Severity.ERROR, "Boundary manifest must declare the selected transport set")

    return findings



def validate_boundary_for_profile(boundary: BoundaryManifest, profile: ProfileConfig) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    aead = profile.aead.upper()
    hsh = profile.hash_function.upper()
    if aead not in {item.upper() for item in boundary.selected_aead}:
        _append(findings, "REQ-BOUNDARY-019", Severity.ERROR, f"Boundary manifest does not list selected AEAD {profile.aead}")
    if hsh not in {item.upper() for item in boundary.selected_hashes}:
        _append(findings, "REQ-BOUNDARY-020", Severity.ERROR, f"Boundary manifest does not list selected hash {profile.hash_function}")
    if profile.key_establishment:
        if profile.key_establishment.upper() not in {item.upper() for item in boundary.selected_key_establishment}:
            _append(findings, "REQ-BOUNDARY-021", Severity.ERROR, f"Boundary manifest does not list selected key establishment {profile.key_establishment}")
    if profile.signature:
        if profile.signature.upper() not in {item.upper() for item in boundary.selected_signatures}:
            _append(findings, "REQ-BOUNDARY-022", Severity.ERROR, f"Boundary manifest does not list selected signature {profile.signature}")
    if profile.transport not in {item.lower() for item in boundary.selected_transports}:
        _append(findings, "REQ-BOUNDARY-023", Severity.ERROR, f"Boundary manifest does not list selected transport {profile.transport}")
    return findings
