# Context vs Human-Governance Boundary

This note clarifies a repository-boundary rule for the local-hybrid slice.

## Separation rule

The local-hybrid slice depends on both governed context and human-governance state, but those responsibilities remain split across distinct planes and distinct repositories.

### Governed context plane
**Repository:** `slash-topics`

Responsible for:
- topic-pack identity
- pack digests
- locality classes
- provenance references
- cache and fetch facts
- context movement signals

### Human-governance plane
**Repository:** `human-digital-twin`

Responsible for:
- policy bundle identity
- consent state
- approval requirement and outcome
- attestation references
- human trust-membrane semantics

## What this means for `TriTRPC`

`TriTRPC` owns the transport-facing method and fixture surface for the slice.
It may carry frames that reference both planes, but it should not redefine their ownership.

In practice:
- transport fixtures may include context-related frames without making `TriTRPC` the context owner
- transport fixtures may include policy/approval-related frames without making `TriTRPC` the human-governance owner
- transport docs should preserve the fact that these are separate upstream semantic planes joined only through execution, evidence, and replay flows

## Why this note exists

Without this clarification, transport-layer method packs can accidentally compress adjacent semantic layers into one “metadata” bucket. That would make replay, ownership, and future schema governance sloppier than necessary.

## Related slice docs

- `README.md`
- `methods.md`
- `fixtures/README.md`
