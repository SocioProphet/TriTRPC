# Scoped Disclosure Slice v0

## Purpose

This slice defines the first transport-facing method pack for governed disclosure rooms.

It does **not** attempt to make TriTRPC the canonical home of social doctrine. The doctrine layer belongs in the shared governance standards repository. This slice instead freezes the method surface that a deterministic transport layer needs in order to carry room creation, disclosure append, relay governance, moderation, reveal, and replay materialization.

## Status

This slice is a **composition-level design pack** for TriTRPC.

It is not yet part of the stable TritRPC v1 normative wire canon. It is a reviewable slice pack that can later be bound to deterministic fixtures and cross-language pack/unpack tests.

## Slice goals

The slice exists to prove that disclosure governance can travel over the same deterministic transport discipline already used for policy, evidence, and replay flows.

Minimum goals:

- typed room-open request and response shapes
- typed disclosure append request and response shapes
- explicit relay authorization and denial flows
- explicit moderation decision flows
- explicit reveal request and reveal decision flows
- first-class evidence append and room materialization

## Method catalog

1. `room.v1.Room/Open`
2. `room.v1.Disclosure/Append`
3. `room.v1.Relay/Authorize`
4. `room.v1.Moderation/Decide`
5. `room.v1.Reveal/Request`
6. `room.v1.Reveal/Decide`
7. `room.v1.Room/Materialize`

See `methods.md` for request/response requirements.

## Cross-repo relationship

- `identity-is-prime-reference` owns root actor and projection semantics.
- `sociosphere` owns local-first room realization and local relay/storage precedence.
- `agentplane` owns tenant-side adjudication and evidence-bearing remote moderation or reveal execution.
- `cairnpath-mesh` owns replay lineage and cairn materialization schemas.
- `socioprophet-standards-storage` owns the canonical governance doctrine.
- `TriTRPC` owns the typed transport-facing slice and its eventual deterministic fixtures.

## Constraints

- no viral default fan-out semantics
- no implicit reveal by transport operator
- no unconstrained public-provider egress by default
- no mutation without evidence-bearing follow-up
- no room materialization without versioned room-contract reference

## Immediate next step

Bind this slice to deterministic fixture vectors once the initial payload schemas stabilize across the standards, identity, and cairn repositories.
