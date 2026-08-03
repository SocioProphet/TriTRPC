# Proof Envelope (tee/zk delegation boundary)

The Mesh Coordinator settles `redundant` proofs itself (majority agreement) but **delegates** the
cryptographic verification of `tee` and `zk` proofs to their verifiers. This spec pins the boundary:
the envelope a `tee`/`zk` result proof must satisfy so the coordinator can **bind** it and **route**
it — the parts a coordinator can and must decide before delegating.

## `ProofEnvelope` (`schemas/jsonschema/proof-envelope.v0.schema.json`)

- `mode` — `tee | zk`.
- `binding` — `{wu_id, result_cid}`: the proof is bound to **exactly one** WU and result.
- `material` — mode-specific: `tee` → `quote` + `measurement` (SHA-256) + `nonce`;
  `zk` → `scheme` (`groth16|plonk|stark`) + `statement` + `proof` (+ optional `publicInputs`).

## Pre-check (`reference/proof_envelope.py:precheck`) — fail-closed

Before delegation the coordinator enforces:
1. `mode == pack.proof_mode`;
2. **anti-replay binding** — `binding.wu_id == pack.wu_id` **and** `binding.result_cid == result.result_cid`;
   a valid proof carrying another result's binding is **refused** (it cannot be replayed against a
   different result);
3. the mode's required material is present (`tee` requires a `nonce` for freshness; `zk` requires a
   known `scheme`).

It then returns a **delegation ticket** — `{mode, verifier, wu_id, result_cid}` — naming the verifier
the coordinator MUST call (`tee-quote-verifier` / `zk-<scheme>-verifier`). It does **not** check the
cryptography; that is the named verifier's job (stated honestly).

## FIPS / boundary

No cryptographic primitive here (structural); `measurement`/`result_cid` are SHA-256 (FIPS 180-4).
The delegated TEE-quote / zk verifier performs the cryptographic check. Does not touch the tritrpc
v4/vNext wire format.
