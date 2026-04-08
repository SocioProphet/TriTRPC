#!/usr/bin/env python3
"""Pack the full seven-step fixture bundle into a deterministic TriTRPC envelope.

This script uses the repository reference implementation to produce one actual
packed envelope over the canonical JSON fixture bundle. It is a slice-level
composition artifact built on top of the existing TriTRPC reference, not a
claim that the seven-step bundle itself is already a stable normative method in
TritRPC v1.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any


FIXTURE_DIR = Path(__file__).resolve().parent
REPO_ROOT = FIXTURE_DIR.parents[5]
REFERENCE_PATH = REPO_ROOT / "reference" / "tritrpc_v1.py"
FILES = [
    "task-plan.output.example.json",
    "policy-decision.output.example.json",
    "capability-resolve.output.example.json",
    "worker-execute.request.example.json",
    "evidence-append.request.example.json",
    "replay-materialize.request.example.json",
]
SERVICE = "slice.local_hybrid.v0"
METHOD = "RemoteAllowedRedactedFull.REQ"
KEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
NONCE_HEX = "00112233445566778899aabbccddeeff0011223344556677"


def load_reference_module():
    spec = importlib.util.spec_from_file_location("tritrpc_v1", REFERENCE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load reference module from {REFERENCE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_bundle() -> dict[str, Any]:
    return {name: load_json(FIXTURE_DIR / name) for name in FILES}


def build_packed_vector() -> dict[str, Any]:
    ref = load_reference_module()
    bundle = build_bundle()
    payload = canonical_bytes(bundle)
    aad = ref.build_envelope(SERVICE, METHOD, payload, None, None, aead_on=True)
    key = bytes.fromhex(KEY_HEX)
    nonce = bytes.fromhex(NONCE_HEX)
    tag, suite = ref.aead_compute_tag(aad, key, nonce)
    envelope = ref.build_envelope(SERVICE, METHOD, payload, None, tag, aead_on=True)
    return {
        "kind": "packed_vector",
        "fixtureId": "remote_allowed_redacted_full",
        "service": SERVICE,
        "method": METHOD,
        "files": FILES,
        "suite": suite,
        "nonceHex": NONCE_HEX,
        "payloadSha256": hashlib.sha256(payload).hexdigest(),
        "aadSha256": hashlib.sha256(aad).hexdigest(),
        "tagHex": tag.hex(),
        "envelopeSha256": hashlib.sha256(envelope).hexdigest(),
        "envelopeHex": envelope.hex(),
    }


def main() -> int:
    result = build_packed_vector()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
