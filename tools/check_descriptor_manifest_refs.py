#!/usr/bin/env python3
"""Check descriptor manifests for missing local artifact references.

The checker scans fixture descriptor manifests and validates file-name fields that
look like local schema, sample, or encoded payload artifact references. Strict mode
is the default so a direct invocation exposes fixture debt. CI can pass
`--warn-only` while legacy manifests are being repaired.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Optional, Union

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


def iter_refs(node: Any, object_path: str = "$") -> Iterable[tuple[str, str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            next_path = f"{object_path}.{key}"
            if is_local_file_ref(key, value):
                yield object_path, key, value
            yield from iter_refs(value, next_path)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from iter_refs(value, f"{object_path}[{index}]")


def expected_path(base: Path, value: str) -> Path:
    file_part = value.split("#", 1)[0]
    return (base / file_part).resolve()


def relative_to_root(path: Path, root: Path) -> Union[Path, str]:
    try:
        return path.relative_to(root)
    except ValueError:
        return str(path)


def check_manifest(path: Path) -> List[MissingRef]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[FAIL] {path}: invalid JSON: {exc}") from exc

    missing: List[MissingRef] = []
    base = path.parent
    for object_path, key, value in iter_refs(data):
        expected = expected_path(base, value)
        if not expected.exists():
            missing.append(MissingRef(path, object_path, key, value, expected))
    return missing


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
    for manifest in manifests:
        manifest_path = manifest if manifest.is_absolute() else root / manifest
        all_missing.extend(check_manifest(manifest_path.resolve()))

    if not all_missing:
        print(f"[OK] checked {len(manifests)} descriptor manifest(s); all local refs exist")
        return 0

    stream = sys.stderr if not args.warn_only else sys.stdout
    status = "WARN" if args.warn_only else "FAIL"
    print(f"[{status}] {len(all_missing)} missing descriptor manifest reference(s):", file=stream)
    for ref in all_missing:
        rel_manifest = relative_to_root(ref.manifest, root)
        rel_expected = relative_to_root(ref.expected, root)
        print(f"  - {rel_manifest}: {ref.object_path}.{ref.key} -> {ref.value} (missing {rel_expected})", file=stream)

    return 0 if args.warn_only else 2


if __name__ == "__main__":
    raise SystemExit(main())
