# TriTRPC vNext — Local-First Agent Sync and Reputation Binding

Status: Exploratory design binding  
Scope: transport metadata and authenticated control words for local-first mutation, capability, and trust flows

## Purpose

This document defines the TriTRPC-side binding for the platform's local-first desktop, sync, and governance stack.

TriTRPC is not the policy authority and not the desktop capability authority. Its role is to transport the decisions, receipts, mutation envelopes, and recovery semantics between governed components with deterministic, authenticated, replayable behavior.

## Transport responsibilities

TriTRPC SHOULD carry the following vNext surface classes:

- local mutation submission
- sync acknowledgement / refusal
- repair and divergence reports
- capability grant receipt propagation
- session placement decision transport
- remote / mirror trust decision transport
- reputation and concentration telemetry events
- rollback and replay instructions

## Suggested message classes

### 1. Mutation envelope

Represents a locally committed state change awaiting synchronization.

Required fields SHOULD include:

- mutation id
- actor id
- device id
- session id
- object family
- local sequence
- causal reference or dependency vector
- payload reference or payload hash
- evidence reference

### 2. Capability decision envelope

Represents a policy decision about host or runtime capability access.

Required fields SHOULD include:

- decision id
- requested capability class
- subject id
- decision outcome
- time bounds
- policy bundle id
- receipt correlation id

### 3. Placement decision envelope

Represents a governed decision about local, fog, or cloud execution.

Required fields SHOULD include:

- placement decision id
- subject id
- locality class
- trust tier
- fallback eligibility
- policy evidence reference

### 4. Reputation telemetry envelope

Represents a trust or concentration signal that may influence routing or ranking.

Required fields SHOULD include:

- subject id
- integrity score
- utility score
- concentration score
- freshness score
- abuse signal
- decision influence class

## Determinism requirements

For all local-first control traffic, TriTRPC SHOULD preserve:

- canonical encoding of message bodies
- authenticated framing for decision and mutation envelopes
- cross-language parity for all receipt-critical paths
- stable replay semantics for validation and forensic reconstruction

## Failure and repair model

TriTRPC bindings for local-first systems SHOULD model at least:

- accepted-but-not-yet-replicated
- replicated
- refused by policy
- refused by trust gate
- divergence detected
- repair requested
- rollback requested
- replay requested

## Non-goals

This document does not define:

- the underlying CRDT or replicated-record data model
- the package runtime model
- the policy rule language
- the desktop portal implementation

Those belong to the runtime, policy, and contract layers.

## Cross-repository relationship

- `SocioProphet/socioprophet-standards-storage` defines the governing standard posture
- `SocioProphet/policy-fabric` defines capability, placement, and trust policy
- `SocioProphet/prophet-platform` binds these envelopes into runtime services
- `SourceOS-Linux/sourceos-spec` should eventually carry typed contracts for these surfaces

## Immediate implementation backlog

1. Add draft examples for mutation, capability, and placement envelopes
2. Define receipt correlation rules across request / decision / execution / replay paths
3. Decide which fields remain hot-path native vs referenced by payload hash
4. Bind divergence and repair semantics into fixture discipline
