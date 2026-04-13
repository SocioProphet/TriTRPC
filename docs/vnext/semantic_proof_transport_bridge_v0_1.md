# Semantic-proof transport bridge v0.1

## Purpose

This note defines the narrow transport-facing bridge between the semantic-proof / replay interoperability work and the active TriTRPC local-hybrid execution slice.

It does **not** make `TriTRPC` the canonical home for the whole semantic-proof pack.
Instead, it records the transport-facing obligations and fixture targets that should exist in the transport repository once the shared standards layer stabilizes.

## Why this belongs here

`TriTRPC` already owns:
- deterministic packing and verification
- fixture discipline
- cross-language transport parity
- the transport-facing local-hybrid slice lifecycle

That makes it the correct home for the transport bridge, but not for the full standards/governance/replay canon.

## Local-hybrid slice alignment

The active local-hybrid slice draft names this seven-step lifecycle:

1. `supervisor.v1.Session/Open`
2. `supervisor.v1.Task/Plan`
3. `policy.v1.Decision/Evaluate`
4. `control.v1.Capability/Resolve`
5. `worker.v1.Capability/Execute`
6. `evidence.v1.Event/Append`
7. `replay.v1.Cairn/Materialize`

The semantic-proof work should align to that lifecycle rather than introducing a second competing method family.

## Transport-facing obligations

### 1. Deterministic request identity
Transport requests that participate in governed replay should expose a stable semantic request hash boundary.

### 2. Evidence append carriage
`evidence.v1.Event/Append` should be the transport-facing insertion point for proof-bearing semantic events.

### 3. Replay materialization carriage
`replay.v1.Cairn/Materialize` should be the transport-facing insertion point for replay/root/proof lookup and response carriage.

### 4. Failure visibility
Transport retries, timeout classes, and envelope failures should remain distinguishable from semantic proof failures.

## What is deliberately excluded

This bridge note does not define:
- the canonical proof schemas
- the canonical vocabulary
- policy/rule lowering
- runtime receipt ownership
- CairnPath materialization semantics

Those belong respectively in:
- `socioprophet-standards-storage`
- future `socioprophet-standards-agents`
- `agentplane`
- `cairnpath-mesh`

## Immediate follow-on once shared schemas settle

1. add deterministic transport fixture vectors for a proof-bearing evidence append call
2. add deterministic transport fixture vectors for a replay/materialize call
3. bind the shared proof identifiers and verifier failure codes into transport-facing examples
4. keep transport and semantic failure classes explicitly separate
