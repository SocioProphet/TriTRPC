#!/usr/bin/env python3
"""Static guardrail for the current TriTRPC runtime parity surface.

This script is intentionally narrow. It does not prove the protocol. It catches
known-bad merge-residue patterns from the PR #27/#44 sequence and records the
current accepted Go/Rust helper API shape so future changes are deliberate.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]

CRITICAL_PATHS = [
    "go/tritrpcv1/envelope.go",
    "go/tritrpcv1/fixtures_test.go",
    "go/tritrpcv1/pathb_dec.go",
    "go/tritrpcv1/tleb3.go",
    "rust/tritrpc_v1/src/lib.rs",
    "rust/tritrpc_v1/tests/fixtures.rs",
    "docs/CAPABILITY_FABRIC_SEMANTIC_SOURCE.md",
]

errors: list[str] = []


def read(path: str) -> str:
    full = ROOT / path
    if not full.exists():
        errors.append(f"missing required file: {path}")
        return ""
    return full.read_text(encoding="utf-8")


def require(path: str, condition: bool, message: str) -> None:
    if not condition:
        errors.append(f"{path}: {message}")


def contains(path: str, needle: str, message: str) -> None:
    body = read(path)
    require(path, needle in body, message)


def not_contains(path: str, needle: str, message: str) -> None:
    body = read(path)
    require(path, needle not in body, message)


def regex(path: str, pattern: str, message: str) -> None:
    body = read(path)
    require(path, re.search(pattern, body, flags=re.DOTALL | re.MULTILINE) is not None, message)


def audit_no_conflict_markers() -> None:
    markers = ("<<<<<<<", "=======", ">>>>>>>")
    for path in CRITICAL_PATHS:
        body = read(path)
        for marker in markers:
  require(path, marker not in body, f"contains unresolved merge marker {marker!r}")


def audit_go_runtime_shape() -> None:
    envelope = "go/tritrpcv1/envelope.go"
    regex(
        envelope,
        r"func\s+BuildEnvelopeWithMode\s*\([^)]*modeBytes\s+\[\]byte\s*\)\s+\[\]byte",
        "Go envelope builder should currently accept packed modeBytes []byte",
    )
    contains(envelope, "golang.org/x/crypto/blake2b", "Go envelope should use BLAKE2b MAC dependency")
    not_contains(envelope, "chacha20poly1305", "Go envelope should not retain stale XChaCha20-Poly1305 import/reference")

    fixtures = "go/tritrpcv1/fixtures_test.go"
    contains(fixtures, "env.Mode", "Go fixture repack should preserve decoded packed mode bytes")
    not_contains(fixtures, "modeTrit :=", "Go fixtures should not reintroduce stale decoded modeTrit merge residue")
    not_contains(
        fixtures,
        "BuildEnvelopeWithMode(env.Service, env.Method, env.Payload, env.Aux, env.Tag, env.AeadOn, env.Compress, modeTrit)",
        "Go fixtures should not call BuildEnvelopeWithMode with decoded modeTrit",
    )

    tleb3 = "go/tritrpcv1/tleb3.go"
    contains(tleb3, "TritUnpack243(buf[off : off+2])", "Go TLEB3 decoder should preserve two-byte tail-marker handling")
    not_contains(tleb3, "pos := offset", "Go TLEB3 decoder should not contain old mixed pos/off merge residue")

    pathb = "go/tritrpcv1/pathb_dec.go"
    contains(pathb, "TritUnpack243(buf[off : off+2])", "Go Path-B decoder should preserve two-byte tail-marker handling")
    not_contains(pathb, "readCount", "Go Path-B decoder should not reintroduce duplicated readCount path")


def audit_rust_runtime_shape() -> None:
    lib = "rust/tritrpc_v1/src/lib.rs"
    regex(
        lib,
        r"pub\s+fn\s+build_with_mode\s*\([^)]*mode_trit\s*:\s*u8",
        "Rust envelope builder should currently accept decoded mode_trit: u8",
    )
    contains(lib, "Blake2bMac", "Rust envelope should use BLAKE2b MAC dependency")
    not_contains(lib, "XChaCha20Poly1305", "Rust envelope should not retain stale XChaCha20-Poly1305 reference")
    not_contains(lib, "mode_bytes", "Rust envelope should not contain stale mode_bytes merge residue")

    fixtures = "rust/tritrpc_v1/tests/fixtures.rs"
    contains(fixtures, "mode_trit", "Rust fixture repack should decode and pass mode_trit explicitly")
    contains(fixtures, "envelope::build_with_mode", "Rust fixtures should continue exercising build_with_mode")
    not_contains(fixtures, "&decoded.mode,\n                mode_trit", "Rust fixtures should not contain mixed packed/decoded mode call residue")


def audit_capability_fabric_pointer() -> None:
    pointer = "docs/CAPABILITY_FABRIC_SEMANTIC_SOURCE.md"
    required_refs = [
        "SocioProphet/socioprophet-standards-knowledge",
        "docs/standards/040-capability-fabric-core.md",
        "docs/standards/041-capability-fabric-realization-profiles.md",
        "docs/standards/042-capability-fabric-delivery-and-receipts.md",
        "docs/standards/043-capability-fabric-controllability-and-proof-strength.md",
        "schemas/jsonschema/capability-fabric/",
    ]
    body = read(pointer)
    for ref in required_refs:
        require(pointer, ref in body, f"missing canonical Capability Fabric reference: {ref}")


def main() -> int:
    audit_no_conflict_markers()
    audit_go_runtime_shape()
    audit_rust_runtime_shape()
    audit_capability_fabric_pointer()

    if errors:
        print("current runtime static audit failed:", file=sys.stderr)
        for err in errors:
  print(f"- {err}", file=sys.stderr)
        return 1

    print("current runtime static audit passed")
    print("- known PR #27/#44 merge-residue patterns absent")
    print("- current Go/Rust helper API shapes are explicit")
    print("- Capability Fabric pointer references are present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
