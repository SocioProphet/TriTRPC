#!/usr/bin/env python3
"""Validate the remote_allowed_redacted fixture examples.

This validator intentionally uses only the Python standard library so it can run
in a bare checkout. It reads `verification-manifest.json`, loads the referenced
JSON examples in the same directory, and evaluates a very small assertion set.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


FIXTURE_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = FIXTURE_DIR / "verification-manifest.json"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def json_path_get(document: Any, path: str) -> Any:
    if not path.startswith("$."):
        raise ValueError(f"unsupported json path: {path!r}")
    current = document
    for part in path[2:].split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise KeyError(f"path segment {part!r} not found in {path!r}")
    return current


def validate_target(target: dict[str, Any]) -> tuple[bool, str]:
    file_path = FIXTURE_DIR / target["file"]
    document = load_json(file_path)
    expect = target["expect"]
    actual = json_path_get(document, expect["path"])

    if "equals" in expect:
        if actual != expect["equals"]:
            return False, f"{target['name']}: expected {expect['equals']!r}, got {actual!r}"

    if "minItems" in expect:
        if not isinstance(actual, list):
            return False, f"{target['name']}: expected list at {expect['path']}, got {type(actual).__name__}"
        if len(actual) < int(expect["minItems"]):
            return False, f"{target['name']}: expected at least {expect['minItems']} items, got {len(actual)}"

    return True, f"{target['name']}: ok"


def main() -> int:
    manifest = load_json(MANIFEST_PATH)
    failures: list[str] = []
    for target in manifest["targets"]:
        ok, message = validate_target(target)
        print(message)
        if not ok:
            failures.append(message)
    if failures:
        print(f"FAILED: {len(failures)} checks")
        return 1
    print(f"PASSED: {len(manifest['targets'])} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
