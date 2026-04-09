from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .jose import jws_verify, jwk_thumbprint, sha256_prefixed


class VerificationError(Exception):
    pass


@dataclass
class Profile:
    allowed_ticket_algs: tuple[str, ...] = ("EdDSA", "ES256")
    allowed_proof_algs: tuple[str, ...] = ("EdDSA", "ES256")
    max_proof_age_seconds: int = 60
    max_future_skew_seconds: int = 30
    max_ticket_ttl_seconds: int = 60
    one_time_default: bool = True


class MemoryReplayCache:
    def __init__(self) -> None:
        self._used: dict[tuple[str, str], int] = {}

    def consume(self, kind: str, jti: str, expiry: int, now: int) -> None:
        self.purge(now)
        key = (kind, jti)
        if key in self._used:
            raise VerificationError(f"{kind} replay detected")
        self._used[key] = expiry

    def purge(self, now: int) -> None:
        stale = [key for key, expiry in self._used.items() if expiry < now]
        for key in stale:
            self._used.pop(key, None)


def _require(condition: bool, msg: str) -> None:
    if not condition:
        raise VerificationError(msg)


def verify_browser_delegation(
    *,
    ticket_jws: str,
    proof_jws: str,
    issuer_public_jwk: dict[str, str],
    proof_public_jwk: dict[str, str],
    now: int,
    request_method: str,
    request_url: str,
    request_path: str,
    expected_audience: str,
    expected_nonce: str,
    expected_sid_ref: str,
    replay_cache: MemoryReplayCache,
    profile: Profile | None = None,
) -> dict[str, Any]:
    profile = profile or Profile()

    ticket_header, ticket = jws_verify(ticket_jws, issuer_public_jwk, set(profile.allowed_ticket_algs))
    proof_header, proof = jws_verify(proof_jws, proof_public_jwk, set(profile.allowed_proof_algs))

    _require(ticket_header.get("typ") == "triticket+jwt", "invalid ticket typ")
    _require(proof_header.get("typ") == "triproof+jwt", "invalid proof typ")
    _require(ticket.get("typ") == "triticket+jwt", "ticket payload typ mismatch")
    _require(proof.get("typ") == "triproof+jwt", "proof payload typ mismatch")

    _require(ticket.get("ver") == "1", "invalid ticket version")
    _require(proof.get("ver") == "1", "invalid proof version")
    _require(ticket.get("aud") == expected_audience, "audience mismatch")
    _require(ticket.get("sid_ref") == expected_sid_ref, "session binding mismatch")

    iat = int(ticket["iat"])
    nbf = int(ticket["nbf"])
    exp = int(ticket["exp"])
    _require(now + profile.max_future_skew_seconds >= nbf, "ticket not yet valid")
    _require(now - profile.max_future_skew_seconds <= exp, "ticket expired")
    _require(exp - iat <= profile.max_ticket_ttl_seconds, "ticket TTL exceeds profile")

    proof_iat = int(proof["iat"])
    _require(proof_iat - now <= profile.max_future_skew_seconds, "proof from the future")
    _require(now - proof_iat <= profile.max_proof_age_seconds, "proof outside freshness window")
    _require(proof.get("nonce") == expected_nonce, "nonce mismatch")
    _require(proof.get("htm") == request_method, "http method mismatch")
    _require(proof.get("htu") == request_url, "http url mismatch")

    expected_jkt = jwk_thumbprint(proof_public_jwk)
    _require(ticket.get("cnf", {}).get("jkt") == expected_jkt, "confirmation key thumbprint mismatch")
    _require(proof_header.get("kid") == expected_jkt, "proof header kid mismatch")

    expected_cap_hash = sha256_prefixed(ticket_jws)
    _require(proof.get("cap_hash") == expected_cap_hash, "capability hash mismatch")

    details = ticket["authorization_details"][0]
    constraints = details.get("constraints", {})
    _require(details.get("type") == "trirpc", "authorization detail type mismatch")
    _require(constraints.get("http_method") == request_method, "http binding method mismatch")
    _require(constraints.get("http_path") == request_path, "http binding path mismatch")

    replay_cache.consume("ticket", ticket["jti"], exp, now)
    replay_cache.consume("proof", proof["jti"], proof_iat + profile.max_proof_age_seconds, now)

    return ticket


def mint_service_capability(
    *,
    browser_ticket_claims: dict[str, Any],
    now: int,
    service_audience: str,
    service_issuer: str,
) -> dict[str, Any]:
    details = browser_ticket_claims["authorization_details"][0]
    constraints = dict(details.get("constraints", {}))
    constraints["http_method"] = None
    constraints["http_path"] = None
    constraints["max_requests"] = 1
    out = {
        "typ": "triticket+jwt",
        "ver": "1",
        "iss": service_issuer,
        "sub_ref": browser_ticket_claims.get("sub_ref"),
        "jti": "svc_" + browser_ticket_claims["jti"],
        "iat": now,
        "nbf": now,
        "exp": min(now + 30, int(browser_ticket_claims["exp"])),
        "aud": service_audience,
        "authorization_details": [
            {
                "type": "trirpc",
                "action": details["action"],
                "resource": details["resource"],
                "constraints": constraints,
            }
        ],
        "upstream_ref": browser_ticket_claims["jti"],
        "policy": browser_ticket_claims.get("policy", {}),
        "evidence": browser_ticket_claims.get("evidence", {}),
    }
    if browser_ticket_claims.get("workspace_id") is not None:
        out["workspace_id"] = browser_ticket_claims.get("workspace_id")
    if browser_ticket_claims.get("tenant_id") is not None:
        out["tenant_id"] = browser_ticket_claims.get("tenant_id")
    if browser_ticket_claims.get("sub_ref") is None:
        out.pop("sub_ref", None)
    return out
