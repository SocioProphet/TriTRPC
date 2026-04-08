# Semantic-proof transport fixture staging

This directory is reserved for transport-facing fixture vectors that bind the semantic-proof core to the active TriTRPC local-hybrid slice.

## Intended first fixture classes

### 1. Proof-bearing evidence append
A deterministic request/response vector for `evidence.v1.Event/Append` carrying:
- a stable semantic request identifier
- one or more proof/stub references
- explicit transport success and failure cases

### 2. Replay/materialize bridge
A deterministic request/response vector for `replay.v1.Cairn/Materialize` carrying:
- replay handle or cairn reference
- proof-bearing result metadata
- explicit transport timeout / retry separation from semantic proof failure

## Constraint

These fixtures should only be added once the shared standards-side proof identifiers and canonical vocabulary stabilize enough to avoid duplicate naming inside `TriTRPC`.
