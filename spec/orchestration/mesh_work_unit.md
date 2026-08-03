# Mesh Work-Unit & Coordinator (Dual-Orchestration plane B)

The Dual-Orchestration model has two planes: **(A)** governed cluster ETL (sp-orchestrator) and
**(B)** a federated volunteer-compute mesh. This spec pins plane B's request/result contracts and the
coordinator's **settlement** step — the part a coordinator can decide deterministically from the
artifacts alone. The `ProjectComputeSetting` cockpit surface (socioprophet) *declares* a project's
mesh + WU governance; this is the runtime that *settles* the units it dispatches.

## Artifacts

- **`WorkUnitPack`** (`schemas/jsonschema/work-unit-pack.v0.schema.json`) — the TriTRPC-enveloped
  descriptor handed to a node. Header: `schema_id` (**SHA3-256** of the Avro canonical schema — the
  SCHEMA-ID), `policy` (`residency` / `isolation` / `slo_ms`), `proof_mode`
  (`redundant | spot_check | tee | zk`), `sandbox` (`docker | lightning | wasm | kata`). Body is
  content-addressed by **SHA-256 CID** (`body_cid`), per the FederationCryptoProfile. `replication`
  is the number of independent nodes the WU is dispatched to.
- **`WorkUnitResult`** (`schemas/jsonschema/work-unit-result.v0.schema.json`) — a node's return:
  `node_ref` (`node://`), `region`, `result_cid` (SHA-256 CID), and a `proof` block whose `mode`
  MUST equal the pack's `proof_mode` and carry that mode's required material.

## Coordinator lifecycle

`registry → schedule → collect → **verify → reduce → settle**`. This reference implements the last
three (`reference/mesh_coordinator.py`); registry/schedule/collect are transport/scheduling and are
out of scope for the contract layer.

### verify (per-result admission — fail-closed)
A result is admissible only if **all** hold; any violation is refused:
1. the node is **trusted AND attested** (no `attestationRef` ⇒ not admitted);
2. the node's `region` satisfies `policy.residency` (`any` waives);
3. `result.wu_id == pack.wu_id`;
4. `proof.mode == pack.proof_mode` and the mode's required material is present
   (`spot_check`: `challenge_index` + `revealed_cid`; `tee`: `quote` + `measurement`;
   `zk`: `statement` + `proof_blob`; `redundant`: none — agreement is decided across replicas).

### reduce / settle (deterministic)
- **redundant** — needs ≥ `replication` admissible results; the accepted CID is the one held by a
  **strict majority** of the admissible set. No majority (a split / suspected sabotage) ⇒ **NOT
  settled**, no credit.
- **spot_check / tee / zk** — `verify` has confirmed the required proof material is present and
  well-formed; the coordinator accepts and records the result CID. Cryptographic proof-checking of a
  TEE quote or a zk proof is **delegated to that mode's verifier** and is out of scope here (stated
  honestly — this is a settler, not a TEE/zk verifier).
- **RLC credit** is assigned ONLY to nodes whose `result_cid` equals the accepted CID; a failed
  settlement pays nothing. (Redundant Labour Credit — the settlement ledger entry.)

The settlement receipt is `{wu_id, settled, method, accepted_result_cid, quorum, rlc_credit, rejected}`
and is a deterministic pure function of `(pack, results, trusted)` — reproducible and auditable.

## FIPS

Agreement / content-addressing is over **SHA-256 CIDs** (FIPS 180-4); SCHEMA-IDs over **SHA3**
(FIPS 202). No non-FIPS primitive is used or required. The coordinator performs **no AEAD**; the
owner-sealing / transport AEAD is the `CryptoProfile` lane's job — **AES-256-GCM** in a FIPS
deployment, never XChaCha20-Poly1305. This module does not touch the tritrpc v4/vNext wire format.

## Governance tie-in

Every settled WU carries an attested node + a residency-checked region + a proof for its declared
mode — the same fail-closed doctrine the `ProjectComputeSetting` validator enforces at declaration
time ("no ungoverned compute"). No attestation, no residency match, or no majority ⇒ no settlement.

## Required assurance suite (v4 §13.4)

A `WorkUnitPack` may declare `policy.requiredSuite` (0 research / 1 fips-classical / 2 cnsa2-ready).
The executing node's resolved crypto profile carries a suite (explicit, or derived `fips→1`/
`standard→0`). `reference/suite_gate.py:require_suite` refuses, fail-closed, to place a workload on a
profile whose suite is **below** the required one — a suite-2 (CNSA) workload cannot settle on a
suite-1 (FIPS) node. This is the cross-consumer meet-or-exceed check that ties the mesh to the
CryptoProfile suite selector; the profile's own correctness is checked by `verify_crypto_profile`.
