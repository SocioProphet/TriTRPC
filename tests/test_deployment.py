from pathlib import Path

from tritrpc_requirements_impl.deployment import DeploymentManifest, validate_deployment
from tritrpc_requirements_impl.policy import has_errors


BASE = Path(__file__).resolve().parents[1] / "configs"


def test_standards_inspired_deployment_is_valid() -> None:
    manifest = DeploymentManifest.load_yaml(BASE / "standards_inspired.yaml")
    findings = validate_deployment(manifest)
    assert not has_errors(findings)



def test_approved_like_deployment_is_valid() -> None:
    manifest = DeploymentManifest.load_yaml(BASE / "approved_like.yaml")
    findings = validate_deployment(manifest)
    assert not has_errors(findings)



def test_standards_inspired_no_cert_is_warning_only() -> None:
    manifest = DeploymentManifest.load_yaml(BASE / "standards_inspired_no_cert.yaml")
    findings = validate_deployment(manifest)
    assert not has_errors(findings)
    assert any(f.requirement_id in {"REQ-CRYPTO-006A", "REQ-BOUNDARY-012A"} for f in findings)
