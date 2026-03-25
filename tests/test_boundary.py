from pathlib import Path

from tritrpc_requirements_impl.boundary import BoundaryManifest, validate_boundary
from tritrpc_requirements_impl.policy import has_errors


BASE = Path(__file__).resolve().parents[1] / "configs"


def test_openssl_boundary_is_valid_when_certificate_required() -> None:
    boundary = BoundaryManifest.load_yaml(BASE / "openssl_fips_boundary.yaml")
    findings = validate_boundary(boundary, require_certificate=True)
    assert not has_errors(findings)



def test_relaxed_boundary_warns_without_certificate() -> None:
    boundary = BoundaryManifest.load_yaml(BASE / "relaxed_no_cert_boundary.yaml")
    findings = validate_boundary(boundary, require_certificate=False)
    assert not has_errors(findings)
    assert any(f.requirement_id == "REQ-BOUNDARY-012A" for f in findings)
