# Heller v1 transport admission v0.1

## Purpose

This note promotes the existing Heller transport seed from descriptor/payload visibility toward transport admission.

It does not claim final canonical TritRPC frame vectors yet. It defines the first stable binding layer needed before canonical vectors can be emitted and verified.

## Existing seed artifacts

The current Heller seed already includes:

- `fixtures/descriptors/heller/v1/heller_wire_v1.proto`
- `fixtures/descriptors/heller/v1/encoded_payload_manifest_v8.json`

The seed manifest includes two payload families:

1. `event_envelope`
   - protobuf message: `socioprophet.heller.v1.HellerEventEnvelope`
   - Avro binary sample: `sample_event_envelope_v1.avro.bin`
   - Protobuf binary sample: `sample_event_envelope_v1.protobuf.bin`

2. `state_snapshot`
   - protobuf message: `socioprophet.heller.v1.HellerStateSnapshot`
   - Avro binary sample: `sample_state_snapshot_v1.avro.bin`
   - Protobuf binary sample: `sample_state_snapshot_v1.protobuf.bin`

## Admission rule

TriTRPC remains the transport authority. Heller semantics are not redefined here.

This repository may define:

- service and method names for Heller carriage
- payload codec labels
- schema/context id derivation policy
- canonical frame-vector generation requirements
- Rust/Go verifier expectations

This repository must not redefine the canonical economics, state-machine, or semantic meaning of Heller objects.

## Initial service and method bindings

The v0.1 admission surface uses one transport service:

- `heller.v1.Transport`

With four method surfaces:

- `EventEnvelope.Avro`
- `EventEnvelope.Protobuf`
- `StateSnapshot.Avro`
- `StateSnapshot.Protobuf`

These are transport-level names. They are not semantic ownership claims.

## Frame-vector readiness gates

A Heller payload family is ready for canonical frame-vector emission when all of the following are true:

1. the descriptor or schema reference is stable
2. the payload hash is recorded in a manifest
3. the service and method binding is recorded
4. the schema id derivation rule is recorded
5. the context id derivation rule is recorded
6. a deterministic nonce strategy is selected for fixture generation
7. Rust and Go verifier expectations are recorded

## Follow-on implementation

The next PR should add a small generator or fixture-emission helper that reads `transport_admission_manifest_v0.1.json`, emits canonical frame vectors for at least one binding, and verifies decode/repack parity in the existing Rust/Go fixture path.
