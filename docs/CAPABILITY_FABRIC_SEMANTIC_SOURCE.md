# Capability Fabric Semantic Source Pointer

`TriTRPC` is the **transport authority** for deterministic ternary-native RPC framing, fixtures, and wire-level interoperability.

## Scope in this repository

This repository MAY define or evolve:
- transport framing
- canonical byte encoding
- envelope ordering
- AEAD / AAD boundaries
- fixture and verifier behavior
- generic typed-blob carriage and digest/signature/reference mechanics

This repository MUST NOT redefine the canonical semantic core of the Capability Fabric.

## Canonical semantic source of truth

The protocol-independent Capability Fabric semantics live in:

- `SocioProphet/socioprophet-standards-knowledge`
  - `docs/standards/040-capability-fabric-core.md`
  - `docs/standards/041-capability-fabric-realization-profiles.md`
  - `docs/standards/042-capability-fabric-delivery-and-receipts.md`
  - `docs/standards/043-capability-fabric-controllability-and-proof-strength.md`
  - `schemas/jsonschema/capability-fabric/`

## Wire-clean rule

`TriTRPC` MAY carry capability-fabric objects as typed payloads, references, digests, signatures, or attestations.

`TriTRPC` MUST NOT redefine or embed the canonical meaning of:
- `FunctionIdentity`
- `CapabilitySignature`
- `EffectContext`
- `InteractionMode`
- `DeliverySemantics`
- `ReceiptSemantics`
- `ExecutionControllabilityProfile`
- `ProofStrengthProfile`
- `RealizationMetadata`

These semantics MUST be imported or referenced from the canonical standards source rather than re-specified here.

## Intended follow-on work

Future transport-facing work in this repository MAY describe:
- how capability-fabric objects are carried as typed blobs or attachments
- how digest and signature refs bind those objects to wire envelopes
- how fixtures and deterministic verifiers confirm transport-level carriage without changing semantic meaning
