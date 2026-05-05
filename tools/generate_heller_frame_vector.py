#!/usr/bin/env python3
"""Generate the first Heller TritRPC frame-vector candidate.

This generator intentionally targets one binding first:
- heller.event_envelope.protobuf.v1

It uses the stable TritRPC v1 envelope field order and the repository fixture
BLAKE2b-MAC-128 tag convention used by existing fixture verification.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_MANIFEST = ROOT / "fixtures" / "descriptors" / "heller" / "v1" / "encoded_payload_manifest_v8.json"
ADMISSION_MANIFEST = ROOT / "fixtures" / "descriptors" / "heller" / "v1" / "transport_admission_manifest_v0.1.json"
OUT_DIR = ROOT / "fixtures" / "heller" / "v1"
VECTOR_OUT = OUT_DIR / "vectors_hex_heller_event_envelope_protobuf_v1.txt"
MANIFEST_OUT = OUT_DIR / "heller_event_envelope_protobuf_v1.frame_manifest.json"

SCHEMA_ID_32 = bytes.fromhex("b2ab814588f99c875d37bb7546d0df4369c28bc5f60ce38a6607dac468034352")
CONTEXT_ID_32 = bytes.fromhex("e6572c0e618f18d572d4c2969db4909659f09eaef32ec66fbb804bad9d89aacd")
ZERO_KEY = bytes(32)


def tritpack243_pack(trits: list[int]) -> bytes:
    out = bytearray()
    i = 0
    while i + 5 <= len(trits):
        value = 0
        for trit in trits[i : i + 5]:
            if trit not in (0, 1, 2):
                raise ValueError(f"invalid trit: {trit}")
            value = value * 3 + trit
        out.append(value)
        i += 5
    tail = len(trits) - i
    if tail:
        out.append(243 + tail - 1)
        value = 0
        for trit in trits[i:]:
            value = value * 3 + trit
        out.append(value)
    return bytes(out)


def tleb3_encode_len(n: int) -> bytes:
    if n < 0:
        raise ValueError("length must be non-negative")
    digits = [0] if n == 0 else []
    while n:
        digits.append(n % 9)
        n //= 9
    trits: list[int] = []
    for index, digit in enumerate(digits):
        cont = 2 if index < len(digits) - 1 else 0
        trits.extend([cont, digit // 3, digit % 3])
    return tritpack243_pack(trits)


def field(value: bytes) -> bytes:
    return tleb3_encode_len(len(value)) + value


def build_frame(service: str, method: str, payload: bytes) -> tuple[bytes, bytes]:
    magic = bytes([0xF3, 0x2A])
    version = tritpack243_pack([1])
    mode = tritpack243_pack([0])
    flags = tritpack243_pack([2, 0, 0])  # AEAD on, compression off, reserved 0
    aad = b"".join(
        field(part)
        for part in (
            magic,
            version,
            mode,
            flags,
            SCHEMA_ID_32,
            CONTEXT_ID_32,
            service.encode("utf-8"),
            method.encode("utf-8"),
            payload,
        )
    )
    tag = hashlib.blake2b(aad, key=ZERO_KEY, digest_size=16).digest()
    return aad + field(tag), tag


def main() -> None:
    payload_manifest = json.loads(PAYLOAD_MANIFEST.read_text(encoding="utf-8"))
    admission_manifest = json.loads(ADMISSION_MANIFEST.read_text(encoding="utf-8"))
    binding = next(
        item for item in admission_manifest["bindings"] if item["binding_id"] == "heller.event_envelope.protobuf.v1"
    )
    payload_info = payload_manifest[binding["payload_family"]]
    payload = base64.b64decode(payload_info["protobuf_base64"])
    payload_sha = hashlib.sha256(payload).hexdigest()
    if payload_sha != binding["sample_payload_sha256"]:
        raise SystemExit("payload hash mismatch")

    frame, tag = build_frame(admission_manifest["service"], binding["method"], payload)
    frame_sha = hashlib.sha256(frame).hexdigest()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    vector = "\n".join(
        [
            "# Heller v1 canonical frame vector candidate",
            "# binding_id: heller.event_envelope.protobuf.v1",
            f"# service: {admission_manifest['service']}",
            f"# method: {binding['method']}",
            f"# payload_sha256: {payload_sha}",
            f"# frame_sha256: {frame_sha}",
            f"heller_event_envelope_protobuf_v1 {frame.hex()}",
            "",
        ]
    )
    VECTOR_OUT.write_text(vector, encoding="utf-8")

    manifest = {
        "fixture_name": "heller_event_envelope_protobuf_v1",
        "binding_id": binding["binding_id"],
        "service": admission_manifest["service"],
        "method": binding["method"],
        "payload_codec": binding["payload_codec"],
        "payload_sha256": payload_sha,
        "frame_size_bytes": len(frame),
        "frame_sha256": frame_sha,
        "tag_hex": tag.hex(),
        "schema_id_hex": SCHEMA_ID_32.hex(),
        "context_id_hex": CONTEXT_ID_32.hex(),
        "aead_tag_algorithm": "BLAKE2b-MAC-128",
        "aead_key": "zero-32-byte-fixture-key",
        "source_payload_manifest": str(PAYLOAD_MANIFEST.relative_to(ROOT)),
        "source_admission_manifest": str(ADMISSION_MANIFEST.relative_to(ROOT)),
    }
    MANIFEST_OUT.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[OK] wrote {VECTOR_OUT.relative_to(ROOT)} and {MANIFEST_OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
