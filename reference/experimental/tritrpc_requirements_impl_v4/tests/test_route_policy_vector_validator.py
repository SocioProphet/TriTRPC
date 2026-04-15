from __future__ import annotations

from pathlib import Path

from tritrpc_requirements_impl.route_policy_vector_validator import validate_vector_file


def test_route_policy_vector_packs_validate() -> None:
    repo_root = Path(__file__).resolve().parents[4]
    primary = repo_root / "docs/vnext/generated/route_policy_delta_vectors_v1.json"
    resume = repo_root / "docs/vnext/generated/route_policy_delta_resume_vectors_v1.json"

    primary_result = validate_vector_file(primary)
    resume_result = validate_vector_file(resume)

    assert primary_result["count"] == 4
    assert resume_result["count"] == 2
    assert primary_result["validated_vectors"] == [
        "authorize_fallback",
        "revoke_fallback",
        "pause_route",
        "dictionary_rebind",
    ]
    assert resume_result["validated_vectors"] == [
        "resume_route_after_pause",
        "resume_then_authorize_fallback",
    ]
