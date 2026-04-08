# Local-Hybrid Slice v0

## Purpose

This slice freezes the first end-to-end control and execution path for a local-first plus tenant-hybrid agent system.

It is intentionally narrow. The goal is to prove deterministic routing, policy gating, evidence emission, and replay semantics before broadening the capability surface.

## Status

This slice is a **composition-level design pack** for TriTRPC. It is not a claim that these methods are already part of the stable TritRPC v1 normative wire canon. Instead, it defines a reviewable method surface and fixture plan that can be encoded over the existing deterministic TriTRPC envelope and verification model.

## Seven-method lifecycle

1. `supervisor.v1.Session/Open`
2. `supervisor.v1.Task/Plan`
3. `policy.v1.Decision/Evaluate`
4. `control.v1.Capability/Resolve`
5. `worker.v1.Capability/Execute`
6. `evidence.v1.Event/Append`
7. `replay.v1.Cairn/Materialize`

## Why this belongs in TriTRPC

TriTRPC already owns the deterministic transport contract, fixture discipline, and verification posture for cross-language interoperability.

This slice therefore belongs here as:

- a method catalog
- a fixture catalog
- a deterministic packing target for future reference implementations

## Cross-repo relationship

- `sociosphere` owns the local supervisor and local-first execution precedence
- `agentplane` owns the tenant-side capability resolution and worker execution path
- `socioprophet-standards-storage` owns the shared payload schemas and benchmark notes
- `TriTRPC` owns the transport-facing method surface and fixtures for this slice

## Slice constraints

- local-first planning and retrieval
- remote execution only after policy approval
- typed capability binding
- typed worker execution
- evidence append as a first-class step
- replay/cairn materialization as a first-class step
- no public-provider egress by default
- no unconstrained side-effecting swarm behavior

## Files in this slice pack

- `methods.md` — method catalog and request/response shapes
- `fixtures/README.md` — deterministic fixture inventory and invariants

## Immediate next step after this pack

Bind these methods to deterministic fixture vectors and reference pack/unpack tests once the shared schemas stabilize.
