# TriTRPC

TriTRPC is a deterministic, ternary-native RPC repository. It contains the stable TritRPC v1 specification, fixtures, and Rust/Go implementations, plus an experimental design pack for braided semantic cadence, compact authenticated hot-path framing, and standards-inspired hardening.

## Repository status

- **Stable v1**: deterministic fixtures, normative spec material, and cross-language parity.
- **Design track**: experimental transport, cadence, assurance, and benchmarking work that is published in-repo but is not yet the stable normative wire format.

## Quick navigation

- Theory & conceptual model: `docs/THEORY.md`
- Full specification: `spec/README-full-spec.md`
- Stable reference implementation: `reference/tritrpc.py`
- Integration readiness checklist: `docs/integration_readiness_checklist.md`
- Design pack landing page: `docs/design/README.md`
- Design overview: `docs/design/WHAT_IS_TRITRPC_VNEXT.md`
- Performance/testing summary: `docs/design/PERFORMANCE_AND_TESTING.md`
- Fixtures: `fixtures/`
- Rust port: `rust/tritrpc/`
- Go port: `go/tritrpc/`

## What this repository guarantees

1. Canonical encoding for the stable v1 surface.
2. Cross-language parity between Rust and Go on the published fixtures.
3. Strict verification against malformed or non-canonical outputs.
4. Public documentation of the experimental design track so future work is inspectable and testable.

## Stable v1 at a glance

TritRPC v1 is built on these conceptual layers:

- TritPack243 packs 5 trits per byte with a tail marker for 1–4 trailing trits.
- TLEB3 encodes lengths as base-9 digits expressed as tritlets, then packs those trits with TritPack243.
- Envelope framing separates routing metadata, AUX, payload bytes, and the AEAD authentication lane.
- Path-A payloads use Avro binary encoding.
- Path-B payloads are ternary-native and currently remain a toy subset in the published fixtures.
- The stable authenticated v1 lane uses XChaCha20-Poly1305 in the current ports and fixtures.

## Design track

The design track explores:

- compact hot-path control words
- route handles
- braided semantic cadence
- beacon/shared-context strategies
- standards-inspired hardening and approved-like profiles
- transport comparisons against Protobuf and Thrift

Start with:

- `docs/design/README.md`
- `docs/design/WHAT_IS_TRITRPC_VNEXT.md`
- `docs/design/PERFORMANCE_AND_TESTING.md`
- `reference/experimental/tritrpc/`

## Repository layout

- `docs/`: theory, repository guide, and design documentation
- `spec/`: normative spec material and drafts
- `reference/`: stable reference implementation plus experimental reference packages
- `fixtures/`: canonical vectors and related fixture data
- `rust/`, `go/`: language implementations
- `scripts/`, `tools/`: maintenance and verification tooling

## Build and test

### Stable ports

- Rust: `cd rust/tritrpc && cargo test`
- Go: `cd go/tritrpc && go test ./...`

### Experimental design package

- `python3 -m pip install -e reference/experimental/tritrpc`
- `python3 -m pytest -q reference/experimental/tritrpc/tests`

### Whole-repo verification

- `make verify`

## Determinism and fixtures

Fixtures are the interoperability contract for the stable surface. Rust and Go must reproduce the published bytes exactly, and paired nonce files are used to recompute AEAD tags where applicable.

## Security direction

The stable ports remain the current v1 implementation surface.
The design track documents the forward path toward standards-inspired and approved-like cryptographic profiles.
That design-track work is additive; it is not a rollback of the stable interoperability surface.

## Contributing

If encoding or envelope rules change:

1. regenerate the affected fixtures
2. rerun the port tests
3. rerun `make verify`
4. update the relevant design docs if the change affects the design track
