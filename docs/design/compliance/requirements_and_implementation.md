# TriTRPC vNext Requirements and Reference Implementation

Date: 2026-03-11

## Scope

This package turns the earlier TriTRPC vNext protocol work into two concrete deliverables:

1. a requirements baseline for approved, research, and CNSA2-ready deployment profiles; and
2. a reference implementation for the hot-path framing, braided identity compression, and policy gating.

This is a **reference package**, not a validated cryptographic module and not an accreditation package.
The framing, policy gates, and canonical encoders are implemented here; the approved cryptographic boundary is modeled as an external requirement.

## Investigated requirement sets

### External requirements

The external requirements resolved here are:

- FIPS 140-3 / CMVP applicability at the cryptographic-module boundary.
- CMVP reality that implementing an approved algorithm is not the same thing as using a validated module.
- NSA/CNSA reality that NSS/DoD-facing deployments are not assessed against “FIPS-validated” alone.
- Current public PQC standards and CNSA 2.0-ready parameter choices.
- Current GCM guidance relevant to IV handling and tag length.

### Internal design requirements

The internal design requirements resolved here are:

- separate approved and research suites;
- preserve ternary control semantics without dragging full strings over the wire;
- compress phase × focus-topic into one Braid243 byte;
- replace cold-path TLEB3 on hot lengths with S243;
- move route and identity repetition behind Handle243;
- provide true hot-path unary / stream / beacon framing;
- keep an experimental 3-adic refinement lane for approximation-bearing state.

## Requirement summary

The machine-readable matrix lives at `specs/requirements_matrix.json`.

The high-value requirements are:

- `REQ-EXT-001..006`: external compliance / policy gates.
- `REQ-DES-001..007`: protocol and naming changes.
- `REQ-VER-001..002`: conformance and artifact generation.
- `REQ-GAP-001..002`: explicit deferred work.

## What is implemented

### 1) Canonical ternary / hot-path primitives

Implemented in `src/tritrpc_requirements_impl/codec.py`:

- `Control243`
- `TritPack243`
- `TLEB3`
- `S243`
- `Handle243`

The implementation is deterministic and tested.

### 2) Braided identity compression

Implemented in `src/tritrpc_requirements_impl/naming.py`:

- canonical braided identifier parsing / formatting;
- `Braid243` encoding of `(phase ∈ 1..7, topic ∈ 1..23)` into one byte;
- display projection helper;
- placeholder `topic23` registry surface.

### 3) Hot unary / stream / beacon framing

Implemented in `src/tritrpc_requirements_impl/frames.py`:

- `MAGIC[2] | CTRL243[1] | KIND[1] | SUITE[1]`
- unary request/response frame encoding
- stream open/data/close frame encoding
- beacon capability/intent/commit frame encoding
- fixed 16-byte tag handling
- deterministic canonical serializer and parser

Two tag providers are included:

- `NullTagProvider` for fully deterministic fixture work
- `AesGcmDemoTagProvider` for a functional AES-256-GCM reference

The AES-GCM provider is **not** a validated module; it is intentionally labeled as a demo provider only.

### 4) Profile gating / masquerade prevention

Implemented in `src/tritrpc_requirements_impl/policy.py`:

- research/non-approved policy
- FIPS-classical policy
- CNSA2-ready policy
- error/warning findings
- rule that approved-family profiles cannot reuse research-only algorithms

This is the key remediation for the earlier gap where research mode could otherwise be mistaken for approved mode.

### 5) Optional 3-adic refinement helpers

Implemented in `src/tritrpc_requirements_impl/padic.py`:

- residue digit extraction
- append-only refinement delta creation
- delta application
- canonical delta packing

This is explicitly marked experimental.

### 6) Sample configs, registry, vectors, and tests

Included artifacts:

- `configs/research.yaml`
- `configs/fips_classical.yaml`
- `configs/cnsa2_ready.yaml`
- `configs/bad_masquerade.yaml`
- `configs/sample_registry.yaml`
- `generated/sample_vectors.json`
- `generated/*validation.json`
- `tests/*.py`

`pytest` passes on the package.

## What is not implemented

The following remain intentionally outside the sandbox implementation:

### 1) Validated crypto boundary binding

The sandbox package does not bind to BoringCrypto, AWS-LC FIPS, OpenSSL FIPS Provider, BC-FJA, or another selected validated module.
That work must happen inside the target runtime and deployment boundary.

### 2) Transport binding

The package models the framing layer itself, but it does not implement TLS/IPsec/SSH bindings.
The policy gate expects those to be chosen for approved-family deployments.

### 3) Go/Rust upstream patches

This package does not directly patch the upstream TriTRPC repo in the sandbox.
Instead, it provides:

- canonical Python reference code,
- generated vectors,
- config examples,
- an explicit integration map.

### 4) Final topic23 registry

`topic23` is still placeholder-only here.
The implementation is parameterized so the authoritative topic registry can replace the placeholders without changing the wire model.

### 5) PKI / OID policy allocation

The registry-to-DN/SAN/OID mapping is not implemented here.
That should be done once the trust-domain and CA policy are fixed.

## Upstream integration map

The clean upstream sequencing is:

1. add `Control243`, `Kind`, `Suite`, and `S243` to the target runtime;
2. keep cold-path `TLEB3` for compatibility but remove it from hot lengths;
3. add `Handle243` and a beacon-scoped route/identity dictionary;
4. introduce `Braid243` on beacon frames first;
5. separate research mode from approved mode in code, tests, docs, and telemetry;
6. bind approved mode to a selected validated module;
7. regenerate golden vectors in the target language runtime.

## File index

### Code

- `src/tritrpc_requirements_impl/codec.py`
- `src/tritrpc_requirements_impl/naming.py`
- `src/tritrpc_requirements_impl/frames.py`
- `src/tritrpc_requirements_impl/policy.py`
- `src/tritrpc_requirements_impl/registry.py`
- `src/tritrpc_requirements_impl/padic.py`
- `src/tritrpc_requirements_impl/cli.py`

### Specs and machine-readable requirements

- `specs/requirements_and_implementation.md`
- `specs/requirements_matrix.json`

### Validation and vectors

- `generated/sample_vectors.json`
- `generated/research_validation.json`
- `generated/fips_validation.json`
- `generated/cnsa2_validation.json`
- `generated/bad_masquerade_validation.json`

## Quick commands

```bash
cd tritrpc_requirements_impl
PYTHONPATH=src python -m tritrpc_requirements_impl validate configs/fips_classical.yaml
PYTHONPATH=src python -m tritrpc_requirements_impl emit-vectors generated/sample_vectors.json
pytest
```

## Immediate next steps

1. Choose the target approved-module binding per runtime.
2. Write the repo-native Go/Rust port of `Control243`, `S243`, `Handle243`, and `Braid243`.
3. Generate repo-native golden fixtures.
4. Finalize `topic23.v1` and replace the placeholder registry.
5. Add transport-binding profiles for TLS 1.3, IPsec, and SSH.
