#!/usr/bin/env python3
"""Verify the deterministic BLAKE2b-MAC packed-vector artifact.

This v2 verifier uses the corrected v2 packer and compares the re-derived
packed envelope to `packed-vector.b2mac.example.json` byte for byte.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any


FIXTURE_DIR = Path(__file__).resolve().parent
PACKER_PATH = FIXTURE_DIR / "pack_full_fixture_vector_b2mac_v2.py"
VECTOR_PATH = FIXTURE_DIR / "packed-vector.b2mac.example.json"


def load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    packer = load_module(PACKER_PATH, "pack_full_fixture_vector_b2mac_v2")
    expected = packer.build_packed_vector()
    actual = load_json(VECTOR_PATH)

    checks = {
        "suite": expected["suite"] == actual["suite"],
        "payloadSha256": expected["payloadSha256"] == actual["payloadSha256"],
        "aadSha256": expected["aadSha256"] == actual["aadSha256"],
        "tagHex": expected["tagHex"] == actual["tagHex"],
        "envelopeSha256": expected["envelopeSha256"] == actual["envelopeSha256"],
        "envelopeHex": expected["envelopeHex"] == actual["envelopeHex"],
    }

    failures = [name for name, ok in checks.items() if not ok]
    for name, ok in checks.items():
        print(f"{name}: {'ok' if ok else 'FAIL'}")
    if failures:
        print(f"FAILED: {len(failures)} checks")
        return 1
    print(f"PASSED: {len(checks)} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
