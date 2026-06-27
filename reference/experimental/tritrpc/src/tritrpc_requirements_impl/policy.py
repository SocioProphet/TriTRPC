from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Iterable


class Severity(str):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class SuiteName(IntEnum):
    RESEARCH_NONAPPROVED = 0
    FIPS_CLASSICAL = 1
    CNSA2_READY = 2
    RESERVED = 3


@dataclass(frozen=True)
class ValidatedModuleRef:
    certificate: str
    name: str
    vendor: str | None = None
    standard: str = "FIPS 140-3"
    status: str = "Active"
    sunset_date: str | None = None
    security_policy_url: str | None = None


@dataclass(frozen=True)
class ProfileConfig:
    suite: int
    approved_mode: bool
    aead: str
    hash_function: str
    transport: str
    tag_length_bytes: int = 16
    nonce_strategy: str = "module-managed"
    key_establishment: str | None = None
    signature: str | None = None
    validated_module: ValidatedModuleRef | None = None
    allow_research_algorithms: bool = False
    tls_version: str | None = None
    notes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "ProfileConfig":
        validated = mapping.get("validated_module")
        module = None
        if validated:
            module = ValidatedModuleRef(**validated)
        return cls(
            suite=int(mapping["suite"]),
            approved_mode=bool(mapping["approved_mode"]),
            aead=str(mapping["aead"]),
            hash_function=str(mapping["hash_function"]),
            transport=str(mapping["transport"]),
            tag_length_bytes=int(mapping.get("tag_length_bytes", 16)),
            nonce_strategy=str(mapping.get("nonce_strategy", "module-managed")),
            key_establishment=mapping.get("key_establishment"),
            signature=mapping.get("signature"),
            validated_module=module,
            allow_research_algorithms=bool(mapping.get("allow_research_algorithms", False)),
            tls_version=mapping.get("tls_version"),
            notes=dict(mapping.get("notes", {})),
        )

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ValidationFinding:
    requirement_id: str
    severity: str
    message: str


ALGORITHM_REGISTRY: dict[str, dict[str, Any]] = {
    "AES-256-GCM": {
        "lifecycle": "approved",
        "allowed_suites": (SuiteName.FIPS_CLASSICAL, SuiteName.CNSA2_READY),
        "kind": "aead",
    },
    "SHA-384": {
        "lifecycle": "approved",
        "allowed_suites": (SuiteName.FIPS_CLASSICAL, SuiteName.CNSA2_READY),
        "kind": "hash",
    },
    "SHA-512": {
        "lifecycle": "approved",
        "allowed_suites": (SuiteName.FIPS_CLASSICAL, SuiteName.CNSA2_READY),
        "kind": "hash",
    },
    "ECDH-P384": {
        "lifecycle": "threshold",
        "allowed_suites": (SuiteName.FIPS_CLASSICAL,),
        "kind": "key_establishment",
    },
    "ECDSA-P384": {
        "lifecycle": "threshold",
        "allowed_suites": (SuiteName.FIPS_CLASSICAL,),
        "kind": "signature",
    },
    "RSA-3072": {
        "lifecycle": "threshold",
        "allowed_suites": (SuiteName.FIPS_CLASSICAL,),
        "kind": "asymmetric",
    },
    "ML-KEM-1024": {
        "lifecycle": "objective",
        "allowed_suites": (SuiteName.CNSA2_READY,),
        "kind": "key_establishment",
    },
    "ML-DSA-87": {
        "lifecycle": "objective",
        "allowed_suites": (SuiteName.CNSA2_READY,),
        "kind": "signature",
    },
    "XCHACHA20-POLY1305": {
        "lifecycle": "research-only",
        "allowed_suites": (SuiteName.RESEARCH_NONAPPROVED,),
        "kind": "aead",
    },
    "CHACHA20-POLY1305": {
        "lifecycle": "research-only",
        "allowed_suites": (SuiteName.RESEARCH_NONAPPROVED,),
        "kind": "aead",
    },
}


TRANSPORT_REGISTRY: dict[str, dict[str, Any]] = {
    "raw": {"family": "custom", "approved_family": False},
    "tls12": {"family": "tls", "approved_family": True},
    "tls13": {"family": "tls", "approved_family": True},
    "ipsec": {"family": "ipsec", "approved_family": True},
    "ssh": {"family": "ssh", "approved_family": True},
}


def _append(findings: list[ValidationFinding], requirement_id: str, severity: str, message: str) -> None:
    findings.append(ValidationFinding(requirement_id=requirement_id, severity=severity, message=message))



def _lookup_suite(config: ProfileConfig, findings: list[ValidationFinding]) -> SuiteName | None:
    try:
        return SuiteName(config.suite)
    except ValueError:
        _append(findings, "REQ-PROFILE-001", Severity.ERROR, f"Unknown suite value {config.suite}")
        return None



def validate_profile_semantics(config: ProfileConfig) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    suite = _lookup_suite(config, findings)
    if suite is None:
        return findings

    if config.transport not in TRANSPORT_REGISTRY:
        _append(findings, "REQ-TRANSPORT-000", Severity.ERROR, f"Unknown transport {config.transport}")
        return findings

    aead = config.aead.upper()
    hsh = config.hash_function.upper()
    nonce_strategy = config.nonce_strategy

    if suite == SuiteName.RESEARCH_NONAPPROVED:
        if config.approved_mode:
            _append(findings, "REQ-PROFILE-010", Severity.ERROR, "Research suite must not run in approved_mode")
        if aead not in {"XCHACHA20-POLY1305", "CHACHA20-POLY1305", "AES-256-GCM"}:
            _append(findings, "REQ-PROFILE-012", Severity.WARNING, "Research suite is using an unusual AEAD selection")
        if not config.allow_research_algorithms and aead in {"XCHACHA20-POLY1305", "CHACHA20-POLY1305"}:
            _append(findings, "REQ-PROFILE-013", Severity.WARNING, "Research suite selected a research-only AEAD while allow_research_algorithms=false")
        return findings

    # Approved-family semantics shared by suite 1 and 2.
    if not config.approved_mode:
        _append(findings, "REQ-PROFILE-020", Severity.ERROR, "Approved-family suites must declare approved_mode=true")
    if aead != "AES-256-GCM":
        _append(findings, "REQ-CRYPTO-001", Severity.ERROR, "Approved-family suites must use AES-256-GCM at the protocol AEAD layer")
    if hsh not in {"SHA-384", "SHA-512"}:
        _append(findings, "REQ-CRYPTO-002", Severity.ERROR, "Approved-family suites must use SHA-384 or SHA-512")
    if config.tag_length_bytes != 16:
        _append(findings, "REQ-CRYPTO-003", Severity.ERROR, "Hot-path approved framing fixes the tag length at 16 bytes")
    if nonce_strategy not in {"module-managed", "module-approved-construct", "tls13-approved"}:
        _append(findings, "REQ-CRYPTO-004", Severity.ERROR, "Approved-family suites must use a module-managed or otherwise approved IV/nonce construction")
    if config.allow_research_algorithms:
        _append(findings, "REQ-CRYPTO-005", Severity.ERROR, "Approved-family suites must not allow research-only algorithms")

    if config.transport == "raw":
        _append(findings, "REQ-TRANSPORT-001", Severity.WARNING, "Raw custom transport is harder to defend; prefer TLS, IPsec, or SSH semantics")
    elif config.transport == "tls12":
        if config.tls_version not in {None, "1.2"}:
            _append(findings, "REQ-TRANSPORT-003", Severity.ERROR, "tls12 transport must declare tls_version=1.2 when provided")
    elif config.transport == "tls13":
        if config.tls_version not in {None, "1.3"}:
            _append(findings, "REQ-TRANSPORT-002", Severity.ERROR, "tls13 transport must declare tls_version=1.3 when provided")

    if suite == SuiteName.FIPS_CLASSICAL:
        if config.key_establishment and config.key_establishment not in {"ECDH-P384", "RSA-3072"}:
            _append(findings, "REQ-CRYPTO-009", Severity.WARNING, "Classical profile typically uses ECDH-P384 or RSA-3072 by policy")
        if config.signature and config.signature not in {"ECDSA-P384", "RSA-3072"}:
            _append(findings, "REQ-CRYPTO-010", Severity.WARNING, "Classical profile typically uses ECDSA-P384 or RSA-3072 by policy")
        return findings

    # CNSA2-ready semantics.
    if config.key_establishment != "ML-KEM-1024":
        _append(findings, "REQ-CNSA2-001", Severity.ERROR, "CNSA2-ready profile requires ML-KEM-1024 for key establishment")
    if config.signature != "ML-DSA-87":
        _append(findings, "REQ-CNSA2-002", Severity.ERROR, "CNSA2-ready profile requires ML-DSA-87 for signatures")
    if config.transport == "tls13":
        if config.tls_version != "1.3":
            _append(findings, "REQ-CNSA2-003", Severity.ERROR, "TLS CNSA2-ready profile must use TLS 1.3")
    elif config.transport not in {"ipsec", "ssh", "tls13"}:
        _append(findings, "REQ-CNSA2-004", Severity.ERROR, "CNSA2-ready profile is only modeled over TLS 1.3, IPsec, or SSH in this reference")
    return findings



def validate_module_binding(config: ProfileConfig) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    suite = _lookup_suite(config, findings)
    if suite is None or suite == SuiteName.RESEARCH_NONAPPROVED:
        if config.validated_module:
            _append(findings, "REQ-PROFILE-011", Severity.INFO, "Validated module present for research suite; it does not make the suite approved")
        return findings

    if not config.validated_module:
        _append(findings, "REQ-CRYPTO-006", Severity.ERROR, "Approved-family suites require a referenced validated cryptographic module")
        return findings

    module = config.validated_module
    if module.standard != "FIPS 140-3":
        _append(findings, "REQ-CRYPTO-007", Severity.WARNING, "Validated module is not marked FIPS 140-3; verify lifecycle acceptability")
    if module.status.lower() != "active":
        _append(findings, "REQ-CRYPTO-008", Severity.WARNING, "Validated module is not marked active")
    return findings



def validate_profile(config: ProfileConfig, require_validated_module: bool = True) -> list[ValidationFinding]:
    findings = validate_profile_semantics(config)
    if require_validated_module:
        findings.extend(validate_module_binding(config))
    else:
        suite = _lookup_suite(config, [])
        if suite is not None and suite != SuiteName.RESEARCH_NONAPPROVED and not config.validated_module:
            _append(findings, "REQ-CRYPTO-006A", Severity.WARNING, "No validated module is attached; this can mimic standards but not claim approved-mode deployment")
    return findings



def has_errors(findings: Iterable[ValidationFinding]) -> bool:
    return any(f.severity == Severity.ERROR for f in findings)
