from pathlib import Path

import yaml

from tritrpc_requirements_impl.policy import ProfileConfig, has_errors, validate_profile


BASE = Path(__file__).resolve().parents[1] / "configs"


def _profile(name: str) -> ProfileConfig:
    with open(BASE / name, "r", encoding="utf-8") as handle:
        return ProfileConfig.from_mapping(yaml.safe_load(handle))



def test_research_profile_has_no_errors() -> None:
    findings = validate_profile(_profile("research.yaml"))
    assert not has_errors(findings)



def test_fips_profile_has_no_errors() -> None:
    findings = validate_profile(_profile("fips_classical.yaml"))
    assert not has_errors(findings)



def test_cnsa2_profile_has_no_errors() -> None:
    findings = validate_profile(_profile("cnsa2_ready.yaml"))
    assert not has_errors(findings)



def test_masquerade_profile_fails() -> None:
    findings = validate_profile(_profile("bad_masquerade.yaml"))
    assert has_errors(findings)
