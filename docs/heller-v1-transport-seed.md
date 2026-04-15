# Heller v1 transport seed for TriTRPC

## Purpose

This patch seeds transport-adjacent artifacts for the Heller contract family without claiming final canonical frame vectors.

## Included artifacts

- `fixtures/descriptors/heller/v1/heller_wire_v1.proto`
- `fixtures/descriptors/heller/v1/heller_wire_v1_descriptor.pb`
- `fixtures/descriptors/heller/v1/encoded_payload_manifest_v8.json`
- `fixtures/descriptors/heller/v1/sample_event_envelope_v1.avro.bin`
- `fixtures/descriptors/heller/v1/sample_state_snapshot_v1.avro.bin`
- `fixtures/descriptors/heller/v1/sample_event_envelope_v1.protobuf.bin`
- `fixtures/descriptors/heller/v1/sample_state_snapshot_v1.protobuf.bin`

## Boundary

These files are descriptor and payload examples. They are not yet canonical TriTRPC frame fixtures.

The remaining work for full transport admission is:

- assign stable schema/context labels and derive IDs where required
- bind the payloads to specific SERVICE/METHOD surfaces
- emit canonical frame vectors plus nonce fixtures
- verify byte parity through the existing Rust/Go conformance flow
