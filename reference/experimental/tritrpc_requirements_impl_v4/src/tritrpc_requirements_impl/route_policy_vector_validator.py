from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

from .codec import Control243, EvidenceGrade, ExecLane, FallbackPolicy, PathProfile, RouteFormat


class RoutePolicyVectorValidationError(ValueError):
    """Raised when a route policy vector violates control-byte or authority-chain rules."""


def _control_from_trits(trits: list[int]) -> Control243:
    if len(trits) != 5:
        raise RoutePolicyVectorValidationError(f"CTRL243 trits must have length 5, got {len(trits)}")
    return Control243(
        profile=PathProfile(trits[0]),
        lane=ExecLane(trits[1]),
        evidence=EvidenceGrade(trits[2]),
        fallback=FallbackPolicy(trits[3]),
        routefmt=RouteFormat(trits[4]),
    )


def _iter_emissions(sequence: list[dict[str, Any]]) -> Iterable[tuple[int, dict[str, Any]]]:
    for idx, item in enumerate(sequence):
        yield idx, item


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RoutePolicyVectorValidationError(message)


def _validate_ctrl243(item: dict[str, Any], vector_id: str, idx: int) -> None:
    trits = item.get("ctrl243_trits")
    byte = item.get("ctrl243_byte")
    _require(isinstance(trits, list), f"{vector_id}[{idx}] missing ctrl243_trits")
    _require(isinstance(byte, int), f"{vector_id}[{idx}] missing ctrl243_byte")
    encoded = _control_from_trits([int(x) for x in trits]).encode()
    _require(
        encoded == byte,
        f"{vector_id}[{idx}] ctrl243_byte={byte} does not match packed trits (expected {encoded})",
    )


def _validate_degradation(item: dict[str, Any], vector_id: str, idx: int) -> None:
    payload = item.get("payload", {})
    _require(item.get("kind243") == 5, f"{vector_id}[{idx}] degradation beacon must use KIND243=5")
    _require(payload.get("evidence") in {"sampled", "exact"}, f"{vector_id}[{idx}] invalid degradation evidence")
    _require("fallback_policy" not in payload, f"{vector_id}[{idx}] degradation payload must not carry fallback_policy")


def _validate_attestation(attestation: dict[str, Any], vector_id: str, idx: int) -> None:
    _require(attestation.get("attestation_type") == "policy_attestation.v1", f"{vector_id}[{idx}] invalid attestation_type")
    for field in ("authority_h", "scope", "decision_class", "issued_at_ms", "evidence_grade"):
        _require(field in attestation, f"{vector_id}[{idx}] attestation missing {field}")


def _validate_route_policy(item: dict[str, Any], vector_id: str, idx: int) -> None:
    payload = item.get("payload", {})
    _require(item.get("kind243") == 5, f"{vector_id}[{idx}] route policy beacon must use KIND243=5")
    _require(payload.get("update_kind") in {"fallback", "pause", "resume", "lane_mask", "route_invalidate", "dictionary_rebind"}, f"{vector_id}[{idx}] invalid update_kind")
    attestation = payload.get("attestation")
    _require(isinstance(attestation, dict), f"{vector_id}[{idx}] route policy delta missing attestation")
    _validate_attestation(attestation, vector_id, idx)


def _validate_commit(item: dict[str, Any], vector_id: str, idx: int) -> None:
    payload = item.get("payload", {})
    _require(item.get("kind243") == 7, f"{vector_id}[{idx}] semantic commit must use KIND243=7")
    if payload.get("evidence_to") == "verified":
        _require(
            any(payload.get(key) for key in ("receipt_ref", "proof_ref", "replay_ref")),
            f"{vector_id}[{idx}] verified commit requires receipt/proof/replay reference",
        )


def _validate_follow_on_behavior(vector: dict[str, Any]) -> None:
    vector_id = str(vector.get("vector_id", "unknown"))
    sequence = vector.get("sequence", [])
    _require(isinstance(sequence, list) and sequence, f"{vector_id} has no sequence")

    for idx, item in _iter_emissions(sequence):
        _validate_ctrl243(item, vector_id, idx)
        delta_type = item.get("delta_type")
        if delta_type == "degradation.cluster.v1":
            _validate_degradation(item, vector_id, idx)
        elif delta_type == "route_policy_delta.v1":
            _validate_route_policy(item, vector_id, idx)
        elif delta_type == "semantic.commit.v1":
            _validate_commit(item, vector_id, idx)

    if vector_id == "authorize_fallback":
        hot = [item for item in sequence if item.get("destination") == "hot_frame"]
        _require(len(hot) >= 2, f"{vector_id} expected baseline and post-policy hot frames")
        _require(hot[-1]["ctrl243_trits"][3] == 1, f"{vector_id} final hot frame must carry fallback=1")

    elif vector_id == "revoke_fallback":
        hot = [item for item in sequence if item.get("destination") == "hot_frame"]
        _require(hot, f"{vector_id} expected a hot frame after revocation")
        _require(hot[-1]["ctrl243_trits"][3] == 0, f"{vector_id} final hot frame must carry fallback=0")

    elif vector_id == "pause_route":
        hot = [item for item in sequence if item.get("destination") == "hot_frame"]
        _require(not hot, f"{vector_id} should not emit a subsequent hot frame in-sequence once pause is authoritative")

    elif vector_id == "dictionary_rebind":
        hot = [item for item in sequence if item.get("destination") == "hot_frame"]
        _require(hot, f"{vector_id} expected a hot frame after rebind")
        _require(hot[-1].get("route_h") == 44, f"{vector_id} final hot frame must use rebound route_h=44")

    elif vector_id == "resume_route_after_pause":
        hot = [item for item in sequence if item.get("destination") == "hot_frame"]
        _require(hot, f"{vector_id} expected a hot frame after resume")
        _require(hot[-1]["ctrl243_byte"] == 1, f"{vector_id} resumed hot frame should return to baseline ctrl byte 1")

    elif vector_id == "resume_then_authorize_fallback":
        hot = [item for item in sequence if item.get("destination") == "hot_frame"]
        _require(len(hot) >= 2, f"{vector_id} expected hot frame after resume and hot frame after fallback authorization")
        _require(hot[0]["ctrl243_byte"] == 1, f"{vector_id} first hot frame after resume should be baseline ctrl byte 1")
        _require(hot[-1]["ctrl243_byte"] == 4, f"{vector_id} final hot frame after fallback authorization should be ctrl byte 4")


def validate_vector_file(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    vectors = data.get("vectors", [])
    _require(isinstance(vectors, list) and vectors, f"{path}: no vectors found")
    validated = []
    for vector in vectors:
        _validate_follow_on_behavior(vector)
        validated.append(str(vector.get("vector_id", "unknown")))
    return {"path": str(path), "validated_vectors": validated, "count": len(validated)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tritrpc-route-policy-vectors")
    parser.add_argument("paths", nargs="+", help="one or more route-policy vector JSON files")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    payload = [validate_vector_file(path) for path in args.paths]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
