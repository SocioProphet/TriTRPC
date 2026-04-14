# TritRPC policy/evidence AUX profile (draft profile)

This document defines a **draft carriage profile** for policy and evidence references in
TritRPC AUX.

It does **not** redefine the stable TritRPC v1 envelope. Instead, it defines how a policy /
evidence bundle is serialized into the existing AUX byte field.

## Scope

The stable Go/Rust ports currently treat AUX as an **opaque byte slice**, and current
published fixture vectors omit AUX entirely. This profile is therefore the **next-step
integration contract** for carrying policy/evidence references without requiring a stable port
wire-format change.

## Profile identifier

Top-level profile string:

- `tritrpc.policy_evidence_aux.v1`

## Serialization

The AUX bundle is encoded as:

1. A top-level JSON object.
2. Canonicalized to UTF-8 bytes using **RFC 8785 (JCS)**.
3. Inserted directly into the existing TritRPC AUX field as opaque bytes.

Because the existing AEAD AAD definition covers the envelope bytes before the final tag field,
AUX bytes are already authenticated when AEAD is enabled.

## Top-level object

Required fields:

- `profile`: profile identifier string.
- `grant_ref`: URI-like reference to a grant.
- `policy_decision_ref`: URI-like reference to a policy decision.
- `runtime_evidence_refs`: structured evidence references.

Optional fields:

- `attestation_bundle_ref`: URI-like reference to a runtime attestation bundle.
- `policy_hash`: stable policy hash (`sha256:...`) associated with the decision.
- `notes`: array of human-readable notes.

## Runtime evidence refs

`runtime_evidence_refs` MAY contain:

- `event_ir_ref`
- `event_ir_hash`
- `semantic_proof_ref`
- `semantic_proof_hash`
- `hdt_decision_ref`
- `hdt_decision_hash`
- `attestation_bundle_ref`
- `attestation_bundle_hash`

Hash fields are expected to use the `sha256:<64 lowercase hex chars>` form used elsewhere in the
identity/governance stack.

## Signed bytes / receipt-grade hashing

For any receipt-grade or replay-grade use of the AUX JSON object itself:

- parse JSON per RFC 8259,
- canonicalize with JCS,
- hash the UTF-8 canonical bytes using the current repository receipt/content-hash rule.

At the time of writing, the repository copy of the full spec states that receipt/content
hashing for JSON is **JCS + BLAKE3-256**.

## Non-goals

This profile does **not**:

- define semantic policy meaning,
- replace grant / decision / attestation schemas,
- require ports to parse structured AUX today,
- redefine the AEAD lane or frame layout.

## Migration posture

Near-term:

- ports remain AUX-opaque,
- integrations generate and validate the JSON bundle out-of-band,
- fixture/examples establish stable carriage bytes for future port decoding.

Later:

- ports may add structured AUX decoding for this profile,
- fixture vectors may add positive / negative AUX-bearing frames.
