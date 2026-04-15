from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .codec import HashHandle, encode_handle243, encode_s243


class PolicyAttestationWireError(ValueError):
    """Raised when a policy attestation wire vector violates the reference-only packed form."""


_SCOPE_MAP = {
    "route": 0,
    "dictionary": 1,
    "epoch": 2,
    "global": 3,
}

_DECISION_MAP = {
    "fallback": 0,
    "pause": 1,
    "resume": 2,
    "lane_mask": 3,
    "rebind": 4,
    "invalidate": 5,
    "receipt": 6,
    "replay_anchor": 7,
}

_EVIDENCE_MAP = {
    "exact": 0,
    "sampled": 1,
    "verified": 2,
}

_OPTIONAL_ORDER = [
    "policy_h",
    "issuer_h",
    "effective_from_epoch",
    "effective_until_epoch",
    "receipt_h",
    "proof_ref",
    "replay_h",
    "signature_ref",
    "reason_h",
]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyAttestationWireError(message)



def _encode_reference(value: Any) -> bytes:
    if isinstance(value, int):
        return encode_handle243(value)
    if isinstance(value, str):
        return encode_handle243(value)
    if isinstance(value, dict) and "hash_hex" in value:
        digest = bytes.fromhex(str(value["hash_hex"]))
        _require(len(digest) == 32, "hash_hex must decode to exactly 32 bytes")
        return encode_handle243(HashHandle(digest))
    raise PolicyAttestationWireError(f"unsupported reference value: {value!r}")



def encode_policy_attestation_mapping(mapping: dict[str, Any]) -> bytes:
    bits = 0
    for idx, field in enumerate(_OPTIONAL_ORDER):
        if mapping.get(field) is not None:
            bits |= 1 << idx

    out = bytearray()
    out += bits.to_bytes(2, "little")
    out += encode_handle243(int(mapping["authority_h"]))
    if mapping.get("policy_h") is not None:
        out += _encode_reference(mapping["policy_h"])
    if mapping.get("issuer_h") is not None:
        out += _encode_reference(mapping["issuer_h"])

    scope = str(mapping["scope"])
    decision_class = str(mapping["decision_class"])
    evidence_grade = str(mapping["evidence_grade"])
    _require(scope in _SCOPE_MAP, f"unknown scope: {scope}")
    _require(decision_class in _DECISION_MAP, f"unknown decision_class: {decision_class}")
    _require(evidence_grade in _EVIDENCE_MAP, f"unknown evidence_grade: {evidence_grade}")
    out.append(_SCOPE_MAP[scope])
    out.append(_DECISION_MAP[decision_class])
    out += encode_s243(int(mapping["issued_at_ms"]))

    if mapping.get("effective_from_epoch") is not None:
        out += encode_s243(int(mapping["effective_from_epoch"]))
    if mapping.get("effective_until_epoch") is not None:
        out += encode_s243(int(mapping["effective_until_epoch"]))
    if mapping.get("receipt_h") is not None:
        out += _encode_reference(mapping["receipt_h"])
    if mapping.get("proof_ref") is not None:
        out += _encode_reference(mapping["proof_ref"])
    if mapping.get("replay_h") is not None:
        out += _encode_reference(mapping["replay_h"])
    if mapping.get("signature_ref") is not None:
        out += _encode_reference(mapping["signature_ref"])

    out.append(_EVIDENCE_MAP[evidence_grade])
    if mapping.get("reason_h") is not None:
        out += _encode_reference(mapping["reason_h"])
    return bytes(out)



def validate_vector_file(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    vectors = data.get("vectors", [])
    _require(isinstance(vectors, list) and vectors, f"{path}: no vectors found")
    validated = []
    for vector in vectors:
        vector_id = str(vector.get("vector_id", "unknown"))
        logical = vector.get("logical")
        packed_hex = vector.get("packed_hex")
        _require(isinstance(logical, dict), f"{vector_id}: logical mapping missing")
        _require(isinstance(packed_hex, str), f"{vector_id}: packed_hex missing")
        encoded = encode_policy_attestation_mapping(logical).hex()
        _require(encoded == packed_hex, f"{vector_id}: packed_hex mismatch")
        validated.append(vector_id)
    return {"path": str(path), "validated_vectors": validated, "count": len(validated)}



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tritrpc-policy-attestation-wire")
    parser.add_argument("paths", nargs="+", help="one or more policy-attestation wire vector JSON files")
    return parser



def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    payload = [validate_vector_file(path) for path in args.paths]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
