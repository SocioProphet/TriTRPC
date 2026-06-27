# Repository guide

This repository has two layers:

- a stable TritRPC v1 interoperability surface
- an experimental design track for the next transport architecture

## Top-level layout

- `README.md`: public repo overview
- `docs/`: theory, repository guide, integration checklist, and design documentation
- `spec/`: full spec and draft material
- `reference/`: stable reference implementation plus experimental reference packages
- `fixtures/`: canonical vectors and supporting fixture artifacts
- `rust/`: Rust implementation
- `go/`: Go implementation
- `scripts/`, `tools/`: verification and maintenance utilities

## Stable v1 surface

- `reference/tritrpc.py`: canonical reference generator/parser for the stable surface
- `fixtures/`: interoperability contract
- `rust/tritrpc/`: Rust port
- `go/tritrpc/`: Go port

## Experimental design track

- `docs/design/README.md`: landing page
- `docs/design/WHAT_IS_TRITRPC_VNEXT.md`: overview
- `docs/design/PERFORMANCE_AND_TESTING.md`: performance claims and caveats
- `reference/experimental/tritrpc/`: experimental Python package for cadence, assurance, and comparisons

## Verification expectations

- stable fixtures must remain deterministic
- Rust and Go must maintain byte-for-byte parity on published vectors
- experimental package tests must pass before design-track changes are merged
- `make verify` is the minimum repo-wide gate
