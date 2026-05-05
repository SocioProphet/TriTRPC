#!/usr/bin/env python3
"""Verify the first Heller frame vector candidate.

This verifier keeps the first canonical-frame candidate honest by regenerating it from the
admission and payload manifests, then comparing both the vector line and manifest fields.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "fixtures" / "heller" / "v1" / "vectors_hex_heller_event_envelope_protobuf_v1.txt"
MANIFEST = ROOT / "fixtures" / "heller" / "v1" / "heller_event_envelope_protobuf_v1.frame_manifest.json"
GENERATOR = ROOT / "tools" / "generate_heller_frame_vector.py"
EXPECTED_NAME = "heller_event_envelope_protobuf_v1"


def fail(msg: str, code: int = 2) -> None:
    print(f"[FAIL] {msg}", file=sys.stderr)
    raise SystemExit(code)


def parse_vector() -> tuple[str, str]:
    if not VECTOR.exists():
        fail(f"missing vector file: {VECTOR}")
    rows = [line for line in VECTOR.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
    if len(rows) != 1:
        fail("expected exactly one vector row")
    parts = rows[0].split(" ", 1)
    if len(parts) != 2:
        fail("vector row must have name and hex frame separated by one space")
    return parts[0], parts[1]


def main() -> None:
    if not GENERATOR.exists():
        fail(f"missing generator: {GENERATOR}")
    # Regenerate in-place. This is deterministic and should be idempotent.
    subprocess.run([sys.executable, str(GENERATOR)], cwd=ROOT, check=True)

    name, hex_frame = parse_vector()
    if name != EXPECTED_NAME:
        fail(f"unexpected vector name: {name}")
    if len(hex_frame) % 2:
        fail("frame hex has odd length")
    frame = bytes.fromhex(hex_frame)

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("fixture_name") != EXPECTED_NAME:
        fail("manifest fixture_name mismatch")
    if manifest.get("frame_size_bytes") != len(frame):
        fail("manifest frame_size_bytes mismatch")
    if manifest.get("binding_id") != "heller.event_envelope.protobuf.v1":
        fail("manifest binding_id mismatch")
    if manifest.get("service") != "heller.v1.Transport":
        fail("manifest service mismatch")
    if manifest.get("method") != "EventEnvelope.Protobuf":
        fail("manifest method mismatch")

    print(f"[OK] verified {name}: {len(frame)} bytes")


if __name__ == "__main__":
    main()
