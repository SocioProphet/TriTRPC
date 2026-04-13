#!/usr/bin/env python3
"""Verify the deterministic packed vector against the JSON fixture bundle.

This script re-derives the packed envelope from the JSON fixture files and
compares it to `packed-vector.example.json`.
"""

from __future__ import annotations

import json
from pathlib import Path

from pack_full_fixture_vector import build_packed_vector


FIXTURE_DIR = Path(__file__).resolve().parent
PACKED_VECTOR_PATH = FIXTURE_DIR / "packed-vector.example.json"


def main() -> int:
    expected = build_packed_vector()
    actual = json.loads(PACKED_VECTOR_PATH.read_text(encoding="utf-8"))
    failures: list[str] = []
    for key in [
        "fixtureId",
        "service",
        "method",
        "suite",
        "nonceHex",
        "payloadSha256",
        "aadSha256",
        "tagHex",
        "envelopeSha256",
        "envelopeHex",
    ]:
        if actual.get(key) != expected.get(key):
            failures.append(f"{key}: expected {expected.get(key)!r}, got {actual.get(key)!r}")
    if failures:
        for item in failures:
            print(item)
        print(f"FAILED: {len(failures)} mismatches")
        return 1
    print("PASSED: packed vector matches deterministic re-derivation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
