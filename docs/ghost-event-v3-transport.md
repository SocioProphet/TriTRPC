# GhostEventV3 transport note

## Purpose
This note records the transport implications of the Event-IR → GhostEvent interop specification.

## Scope
GhostEventV3 extends the Ghost event envelope with semantic basis-binding fields:
- `prime_registry_ref`
- `prime_registry_state_hash`
- `event_ir_hash`
- `prime_vector`

## Transport expectations
Implementations carrying GhostEventV3 over TritRPC/TriTRPC SHOULD preserve:
- canonical event hashing semantics
- deterministic payload ordering within fixture vectors
- the malformed vs blocked distinction

## Fixture implications
GhostEventV3 fixture families SHOULD exercise at least:
- valid sparse prime vectors
- duplicate basis index rejection
- unresolved registry rejection
- registry state hash mismatch rejection
- deprecated-topic warning behavior where policy permits

## Relationship to the first Ghost fixture PR
This note is intentionally narrow and builds on the initial Ghost transport scaffold without expanding the entire fixture corpus in one step.
