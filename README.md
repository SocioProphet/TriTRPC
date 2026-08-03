# TriTRPC (Repository)

Description: TriTRPC is a deterministic, ternary-native RPC protocol repository. It contains the stable TritRPC v1 specification, fixtures, and Rust/Go implementations, plus an experimental TriTRPC vNext design pack for braided semantic cadence, compact authenticated hot-path framing, and standards-inspired hardening.

Topics: ternary, rpc, protocol, deterministic-encoding, fixtures, rust, go, avro, aead, agentic-transport, braided-semantics

This repository contains three layers of work:

1. **Stable TritRPC v1** — deterministic, byte-for-byte reproducible fixtures, normative spec material, and Go/Rust ports.
2. **Experimental TriTRPC vNext / v4** — a public design pack for route handles, compact control words, braided semantic cadence, standards-inspired hardening, and transport comparisons.
3. **Governance, crypto profiles & orchestration contracts** — the schema-first, fail-closed layer built *over* the wire: FIPS/CNSA crypto-suite selection, the Semantic-Obfuscation-Chain transport, qutrit error-correction, and the federated mesh (Work-Unit dispatch → settlement → proof). Every contract ships a JSON Schema, `.valid`/`.invalid` fixtures, a stdlib self-testing reference/validator, and its own CI check.

The repository focus remains deterministic reproducibility and cross-language parity for v1, while publishing the vNext/v4 direction and the governance/orchestration contracts in-repo so the whole design is reviewable, testable, and easy to discuss publicly.

## Repository status

- **v1**: stable interoperability surface for fixtures, reference behavior, and Go/Rust parity.
- **vNext**: experimental design pack and reference package; not yet the normative wire format for the stable ports.

## Quick navigation

- **Theory & conceptual model:** `docs/THEORY.md`
- **Full specification:** `spec/README-full-spec.md`
- **Reference implementation:** `reference/tritrpc_v1.py`
- **Integration readiness checklist:** `docs/integration_readiness_checklist.md`
- **Fixtures (canonical vectors):** `fixtures/`
- **Rust port:** `rust/`
- **Go port:** `go/`

## What this repository guarantees

1. **Canonical encoding:** Trits, lengths, payloads, and envelopes encode to a canonical
   byte sequence.
2. **Cross-language parity:** Rust and Go implementations produce identical bytes for
   the same semantic input.
3. **Strict verification:** Fixtures and tests reject any non-canonical or malformed
   outputs.
4. **Traceable theory:** The theory and spec are included in-repo and linked here for
   easy, long-term reference.

## Theory at a glance (summary)

TritRPC v1 is built on these conceptual layers:

- **Trits (base-3 digits)** are packed into bytes using **TritPack243**, which encodes
  5 trits per byte and uses a tail marker for 1–4 trailing trits.
- **TLEB3** encodes lengths as base-9 digits expressed as tritlets, then packs those
  trits via TritPack243.
- **Envelope framing** separates routing metadata (SERVICE + METHOD), AUX structures,
  payload bytes, and the AEAD authentication lane.
- **Path-A** payloads are encoded with Avro Binary Encoding (used by the reference
  implementation and most fixtures).
- **Path-B** payloads are ternary-native (toy subset fixtures demonstrate this).
- **AEAD integrity** authenticates frames over an AEAD lane. The v1 lane is XChaCha20-Poly1305
  (24-byte nonces); **FIPS is the standard** for approved deployments, so the sealing cipher is a
  gated *choice* via the CryptoProfile suite selector (see *Governance & crypto profiles* below) —
  XChaCha20 is `suite 0`, AES-256-GCM the FIPS/CNSA suites. The wire (TritPack243/TLEB3) is unchanged
  by the cipher choice.

For complete detail, read `docs/THEORY.md` and the full spec.

## Governance, crypto profiles & orchestration

Layered *over* the wire, each of these is a fail-closed contract — a JSON Schema + `.valid`/`.invalid`
fixtures + a stdlib self-testing reference/validator + a dedicated CI check. All are additive: they
never change the v1/v4/vNext wire.

**Crypto & security profiles** (`spec/transport/`, `schemas/jsonschema/`):

- **CryptoProfile** — the AEAD/hash sealing choice, aligned to the v4 **suite selector** (§13.4):
  `0` research · `1` fips-classical · `2` cnsa2-ready · `3` reserved. suite ≥ 1 enforces the
  approved-mode assertions (encode-before-authenticate, canonical-only, nonce/RNG/self-tests); suite 2
  requires AES-256-GCM + SHA-384/512 + ML-KEM-1024 / ML-DSA-87.
- **FederationCryptoProfile** — FIPS hash + signature gate for the Merkle-log P2P layer (BLAKE refused;
  Ed25519 approved under FIPS 186-5).
- **SOC relay-contract / ObfuscationProfile** — the owner-sealed Semantic-Obfuscation-Chain transport
  (complete-to-owner, cloaked-to-observers) + traffic-analysis resistance.
- **Q3 ECC profile** — ternary error correction (RS over GF(3^m) / ternary stabilizer codes).

**Federated mesh — Dual-Orchestration plane B** (`spec/orchestration/`):

The volunteer-compute mesh, contract-first, `admission → dispatch → settle → prove`:

| Stage | Contract / reference |
| --- | --- |
| Who may join | `NodeReputation` + `node_admission` (bounded Trust Equation, fail-closed gates) |
| What runs | `WorkUnitPack` / `WorkUnitResult` + Avro body with a reproducible **SCHEMA-ID** (SHA3-256 of the Avro canonical form) |
| Placement | `NodeRegistration` + `mesh_scheduler` (residency / sandbox / liveness / capacity, redundancy-aware) |
| Settlement | `mesh_coordinator` (strict-majority redundancy, RLC credit) |
| Proof | `proof_envelope` (tee/zk bind + anti-replay) → `attestation_verifier` (decidable checks, abstains on the crypto root) |

FIPS throughout: content addresses are SHA-256, SCHEMA-IDs SHA3-256; no non-FIPS primitive is used.

## Repository layout

A more detailed guide lives in `docs/REPOSITORY_GUIDE.md`. At a glance:

- `docs/`: Theory and repository guide.
- `spec/`: Full specification (normative requirements), incl. `spec/transport/` (crypto/SOC profiles)
  and `spec/orchestration/` (the federated mesh contracts).
- `schemas/jsonschema/`: the fail-closed contract schemas (crypto profiles, mesh Work-Unit family, …).
- `reference/`: Python reference implementations — the v1 codec plus the mesh reference executors
  (`mesh_coordinator`, `node_admission`, `mesh_scheduler`, `proof_envelope`, `attestation_verifier`, …).
- `fixtures/`, `examples/`: Canonical hex fixtures + contract `.valid`/`.invalid` examples.
- `rust/`, `go/`: Language implementations (stable v1).
- `scripts/`, `tools/`: Utility scripts, regeneration tooling, and the `verify_*` contract validators.

## Build and test (ports)

### Build the ports

- Rust: `cd rust/tritrpc_v1 && cargo test`
- Go: `cd go/tritrpcv1 && go test`

### Fixture verification

- Rust: `cargo test -p tritrpc_v1` validates AEAD tags, schema/context IDs, and full-frame
  repack determinism using `.nonces`.
- Go: `cd go/tritrpcv1 && go test` performs the same validations.

### CLI tools

- Rust:
  ```bash
  cargo run -p tritrpc_v1 --bin trpc -- pack \
    --service hyper.v1 \
    --method AddVertex_a.REQ \
    --json payload.json \
    --nonce <hex> \
    --key <hex>
  ```
- Go:
  ```bash
  cd go/tritrpcv1/cmd/trpc
  go build
  ./trpc verify --fixtures ../../fixtures/vectors_hex_unary_rich.txt \
    --nonces ../../fixtures/vectors_hex_unary_rich.txt.nonces
  ```

## Fixtures and determinism

Fixtures are the **interoperability contract** between implementations. The reference
implementation generates canonical frames in `fixtures/*.txt`, and both Rust and Go
implementations must reproduce those bytes exactly. Each fixture line has a paired nonce
file (`*.nonces`) used to recompute AEAD tags.

## Path-B (ternary) vectors (toy subset)

See `fixtures/vectors_hex_pathB.txt` (+ `.nonces`). These use ternary-native encodings
(TLEB3 lengths, balanced-ternary ints) and are AEAD-authenticated like Path-A.

## CI

A GitHub Actions workflow runs `make verify` (format checks + tests + fixture verification)
on push/PR.

## Release workflow

- On tag push (`v*`), builds Rust + Go CLIs, zips them with fixtures, and attaches
  them to the GitHub Release.
- See `.github/workflows/release.yml`.

## Repack check

Repack determinism is verified in the fixture tests by re-encoding envelopes and comparing
full-frame bytes to fixture vectors.

## Pre-commit hook (strict AEAD verification)

To prevent committing drifted fixtures, enable the pre-commit hook that re-computes
**XChaCha20-Poly1305** tags for every `fixtures/*.txt` line using the paired `.nonces`:

```bash
pip install cryptography   # required for local verification
bash scripts/install_hooks.sh
# try a commit; it will refuse if any tag mismatches its AAD+nonce
```

If you need to refresh tags intentionally, run:

```bash
python tools/regenerate_aead_tags.py
```


## vNext preview

The repository now includes an experimental vNext design pack focused on braided semantic cadence, compact authenticated hot-path framing, standards-inspired hardening, and transport comparisons.

Start here:
- `docs/vnext/README.md`
- `docs/vnext/WHAT_IS_TRITRPC_VNEXT.md`
- `docs/vnext/PERFORMANCE_AND_TESTING.md`
- `reference/experimental/tritrpc_requirements_impl_v4/`
