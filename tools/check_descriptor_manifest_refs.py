#!/usr/bin/env python3
"""Check descriptor manifests for missing local artifact references.

The checker scans fixture descriptor manifests and validates file-name fields that
look like local schema, sample, or encoded payload artifact references. Strict mode
is the default.

Binary payload refs may be satisfied by a same-record embedded base64 payload when
the manifest also supplies matching size and SHA-256 fields. This lets descriptor
manifests remain self-contained while still catching stale schema/sample/proto refs.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GLOB = "fixtures/**/encoded_payload_manifest*.json"
LOCAL_REF_SUFFIXES = (
    "_schema",
    "schema",
    "sample_json",
    "json_file",
    "avro_binary_file",
    "protobuf_binary_file",
    "binary_file",
    "file",
)
IGNORED_KEYS = (
    "base64",
    "sha256",
    "size_bytes",
    "hash",
    "digest",
)
LOCAL_EXTENSIONS = (
    ".json",
    ".jsonld",
    ".schema.json",
    ".avsc",
    ".proto",
    ".bin",
    ".txt",
    ".nonces",
)


@dataclass(frozen=True)
class MissingRef:
    manifest: Path
    object_path: str
    key: str
    value: str
    expected: Path


@dataclass(frozen=True)
class InvalidEmbeddedPayload:
    manifest: Path
    object_path: str
    key: str
    reason: str


def is_local_file_ref(key: str, value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lowered_key = key.lower()
    if any(token in lowered_key for token in IGNORED_KEYS):
        return False
    if not value or value.startswith(("http://", "https://", "urn:", "sha", "data:")):
        return False
    if any(lowered_key.endswith(suffix) for suffix in LOCAL_REF_SUFFIXES):
        return True
    return value.split("#", 1)[0].endswith(LOCAL_EXTENSIONS)


def iter_refs(node: Any, object_path: str = "$") -> Iterable[tuple[str, Dict[str, Any], str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            next_path = f"{object_path}.{key}"
            if is_local_file_ref(key, value):
                yield object_path, node, key, value
            yield from iter_refs(value, next_path)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from iter_refs(value, f"{object_path}[{index}]")


def expected_path(base: Path, value: str) -> Path:
    file_part = value.split("#", 1)[0]
    return (base / file_part).resolve()


def embedded_prefix(key: str) -> Optional[str]:
    if key.endswith("_binary_file"):
        return key.removesuffix("_binary_file")
    return None


def embedded_payload_is_valid(record: Dict[str, Any], key: str) -> tuple[bool, Optional[str]]:
    prefix = embedded_prefix(key)
    if prefix is None:
        return False, None

    b64_key = f"{prefix}_base64"
    sha_key = f"{prefix}_sha256"
    size_key = f"{prefix}_size_bytes"
    if b64_key not in record:
        return False, None

    try:
        payload = base64.b64decode(record[b64_key], validate=True)
    except Exception as exc:  # noqa: BLE001 - report exact validation failure in CLI output.
        return False, f"{b64_key} is not valid base64: {exc}"

    expected_size = record.get(size_key)
    if expected_size is not None and len(payload) != expected_size:
        return False, f"{size_key}={expected_size} but decoded {len(payload)} bytes"

    expected_sha = record.get(sha_key)
    if expected_sha is not None:
        actual_sha = hashlib.sha256(payload).hexdigest()
        if actual_sha != expected_sha:
            return False, f"{sha_key}={expected_sha} but decoded payload sha256={actual_sha}"

    return True, None


def relative_to_root(path: Path, root: Path) -> Union[Path, str]:
    try:
        return path.relative_to(root)
    except ValueError:
        return str(path)


def check_manifest(path: Path) -> tuple[List[MissingRef], List[InvalidEmbeddedPayload]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[FAIL] {path}: invalid JSON: {exc}") from exc

    missing: List[MissingRef] = []
    invalid_embedded: List[InvalidEmbeddedPayload] = []
    base = path.parent
    for object_path, record, key, value in iter_refs(data):
        expected = expected_path(base, value)
        if expected.exists():
            continue
        embedded_ok, embedded_error = embedded_payload_is_valid(record, key)
        if embedded_ok:
            continue
        if embedded_error is not None:
            invalid_embedded.append(InvalidEmbeddedPayload(path, object_path, key, embedded_error))
            continue
        missing.append(MissingRef(path, object_path, key, value, expected))
    return missing, invalid_embedded


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root")
    parser.add_argument("--glob", default=DEFAULT_GLOB, help="Manifest glob relative to root")
    parser.add_argument("--warn-only", action="store_true", help="Report missing refs without failing")
    parser.add_argument("manifests", nargs="*", type=Path, help="Specific manifest paths to check")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    manifests = args.manifests or sorted(root.glob(args.glob))
    if not manifests:
        print(f"[OK] no descriptor manifests matched {args.glob}")
        return 0

    all_missing: List[MissingRef] = []
    all_invalid: List[InvalidEmbeddedPayload] = []
    for manifest in manifests:
        manifest_path = manifest if manifest.is_absolute() else root / manifest
        missing, invalid = check_manifest(manifest_path.resolve())
        all_missing.extend(missing)
        all_invalid.extend(invalid)

    if not all_missing and not all_invalid:
        print(f"[OK] checked {len(manifests)} descriptor manifest(s); all local refs or embedded payloads are valid")
        return 0

    stream = sys.stderr if not args.warn_only else sys.stdout
    status = "WARN" if args.warn_only else "FAIL"
    print(f"[{status}] descriptor manifest reference validation found issues:", file=stream)
    for ref in all_missing:
        rel_manifest = relative_to_root(ref.manifest, root)
        rel_expected = relative_to_root(ref.expected, root)
        print(f"  - missing {rel_manifest}: {ref.object_path}.{ref.key} -> {ref.value} (expected {rel_expected})", file=stream)
    for invalid in all_invalid:
        rel_manifest = relative_to_root(invalid.manifest, root)
        print(f"  - invalid embedded payload {rel_manifest}: {invalid.object_path}.{invalid.key}: {invalid.reason}", file=stream)

    return 0 if args.warn_only else 2


if __name__ == "__main__":
    raise SystemExit(main())
