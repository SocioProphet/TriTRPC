"""Reference suite gate — a workload runs only on a crypto profile that MEETS OR EXCEEDS its suite.

A WorkUnitPack may declare policy.requiredSuite (v4 §13.4: 0 research / 1 fips-classical / 2
cnsa2-ready). The executing node's resolved crypto profile carries a suite (explicit, or derived
standard->0 / fips->1). This gate refuses to run a workload on a profile whose suite is BELOW the
required one — closing the break where a CNSA-required (suite 2) workload could settle on a merely
FIPS (suite 1) node. Fail-closed, numeric monotone (suite 2 > 1 > 0).

FIPS/boundary: pure comparison, no primitive. The profile's own approved-mode/CNSA correctness is
checked by verify_crypto_profile; this gate only enforces meet-or-exceed. Does not touch the wire.
"""
from __future__ import annotations


class SuiteError(Exception):
    pass


def profile_suite(profile: dict) -> int:
    """Resolve a crypto profile's suite: explicit `suite`, else derived (fips->1, standard->0)."""
    if "suite" in profile:
        return int(profile["suite"])
    return 1 if profile.get("mode") == "fips" else 0


def required_suite(pack: dict) -> int:
    return int((pack.get("policy") or {}).get("requiredSuite", 0))


def require_suite(pack: dict, profile: dict) -> int:
    """Refuse (fail-closed) if the profile's suite is below the pack's requiredSuite. Returns the suite."""
    need = required_suite(pack)
    have = profile_suite(profile)
    if have < need:
        raise SuiteError(
            f"crypto profile suite {have} does not meet the workload's requiredSuite {need} "
            f"(a suite-{need} workload cannot run on a suite-{have} profile)")
    return have
