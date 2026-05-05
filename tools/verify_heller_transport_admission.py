#!/usr/bin/env python3
"""Validate the Heller transport admission manifest against the encoded payload manifest.

This is a repository-local readiness gate. It does not emit canonical TritRPC frames yet.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADMISSION = ROOT / "fixtures" / "descriptors" / "heller" / "v1" / "transport_admission_manifest_v0.1.json"
PAYLOADS = ROOT / "fixtures" / "descriptors" / "heller" / "v1" / "encoded_payload_manifest_v8.json"

REQUIRED_BINDING_KEYS = {
    "binding_id",
    "payload_family",
    "method",
    "payload_codec",
    "message_ref",
    "sample_payload_file",
    "sample_payload_sha256",
    "schema_id_policy",
    "context_id_policy",
}


def fail(msg: str, code: int = 2) -> None:
    print(f"[FAIL] {msg}", file=sys.stderr)
    raise SystemExit(code)


def load_json(path: Path):
    if not path.exists():
        fail(f"missing file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def expected_hash_key(codec: str) -> str:
    if codec == "avro-binary":
        return "avro_sha256"
    if codec == "protobuf-binary":
        return "protobuf_sha256"
    fail(f"unsupported payload codec: {codec}")


def expected_file_key(codec: str) -> str:
    if codec == "avro-binary":
        return "avro_binary_file"
    if codec == "protobuf-binary":
        return "protobuf_binary_file"
    fail(f"unsupported payload codec: {codec}")


def main() -> None:
    admission = load_json(ADMISSION)
    payloads = load_json(PAYLOADS)

    if admission.get("profile") != "tritrpc.heller.transport_admission.v0.1":
        fail("unexpected admission profile")
    if admission.get("service") != "heller.v1.Transport":
        fail("unexpected Heller transport service")

    bindings = admission.get("bindings")
    if not isinstance(bindings, list) or not bindings:
        fail("bindings must be a non-empty array")

    seen = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            fail("binding entries must be objects")
        missing = REQUIRED_BINDING_KEYS - set(binding)
        if missing:
            fail(f"{binding.get('binding_id', '<unknown>')}: missing keys {sorted(missing)}")
        binding_id = binding["binding_id"]
        if binding_id in seen:
            fail(f"duplicate binding_id: {binding_id}")
        seen.add(binding_id)

        family = binding["payload_family"]
        if family not in payloads:
            fail(f"{binding_id}: unknown payload family {family}")
        payload_info = payloads[family]
        codec = binding["payload_codec"]
        hash_key = expected_hash_key(codec)
        file_key = expected_file_key(codec)
        if binding["sample_payload_sha256"] != payload_info.get(hash_key):
            fail(f"{binding_id}: sample payload sha256 mismatch")
        if binding["sample_payload_file"] != payload_info.get(file_key):
            fail(f"{binding_id}: sample payload file mismatch")
        if not binding["method"].count(".") == 1:
            fail(f"{binding_id}: method should use Family.Codec shape")

    print(f"[OK] Heller transport admission manifest validated: {len(bindings)} bindings")


if __name__ == "__main__":
    main()
