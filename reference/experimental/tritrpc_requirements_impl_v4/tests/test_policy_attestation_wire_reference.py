from __future__ import annotations

from pathlib import Path

from tritrpc_requirements_impl.policy_attestation_wire_reference import validate_vector_file



def test_policy_attestation_wire_vectors_validate() -> None:
    repo_root = Path(__file__).resolve().parents[4]
    vectors = repo_root / "docs/vnext/generated/policy_attestation_wire_vectors_v1.json"
    result = validate_vector_file(vectors)

    assert result["count"] == 2
    assert result["validated_vectors"] == [
        "fallback_authorization_attestation",
        "verified_receipt_attestation",
    ]
