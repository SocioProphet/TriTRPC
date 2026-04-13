#!/usr/bin/env python3
"""Derive a deterministic prevector bundle from the JSON fixture files.

This is intentionally *not* the normative TriTRPC wire vector. It is a bridge
artifact: a canonical JSON bundle and SHA-256 digest over the full seven-step
fixture inputs, suitable for comparison and later promotion into real packed
fixture vectors.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


FIXTURE_DIR = Path(__file__).resolve().parent
FILES = [
    "task-plan.output.example.json",
    "policy-decision.output.example.json",
    "capability-resolve.output.example.json",
    "worker-execute.request.example.json",
    "evidence-append.request.example.json",
    "replay-materialize.request.example.json",
]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main() -> int:
    bundle = {name: load_json(FIXTURE_DIR / name) for name in FILES}
    payload = canonical_bytes(bundle)
    result = {
        "kind": "prevector",
        "fixtureId": "remote_allowed_redacted_full",
        "files": FILES,
        "bundleSha256": hashlib.sha256(payload).hexdigest(),
        "bundleHex": payload.hex(),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
