# Heller v1 transport seed for TriTRPC

## Purpose

This patch seeds transport-adjacent artifacts for the Heller contract family without claiming final canonical frame vectors.

## Included artifacts

- `fixtures/descriptors/heller/v1/heller_wire_v1.proto`
- `fixtures/descriptors/heller/v1/heller_wire_v1_descriptor.pb`
- `fixtures/descriptors/heller/v1/heller_event_envelope.avsc`
- `fixtures/descriptors/heller/v1/heller_state_snapshot.avsc`
- `fixtures/descriptors/heller/v1/heller_event_envelope.schema.json`
- `fixtures/descriptors/heller/v1/heller_state_snapshot.schema.json`
- `fixtures/descriptors/heller/v1/sample_event_envelope_v8.json`
- `fixtures/descriptors/heller/v1/sample_state_snapshot_v8.json`
- `fixtures/descriptors/heller/v1/encoded_payload_manifest_v8.json`
- `docs/diagrams/heller_event_envelope_lom.dot`

## Embedded encoded payloads

`encoded_payload_manifest_v8.json` records the Avro and protobuf binary payloads as embedded base64 strings with their expected byte sizes and SHA-256 hashes.

The manifest may still name logical payload files such as `sample_event_envelope_v1.avro.bin`, but those binary payload references are satisfied by the embedded `*_base64`, `*_size_bytes`, and `*_sha256` fields. `tools/check_descriptor_manifest_refs.py` validates those embedded payloads in strict mode.

## Boundary

These files are descriptor and payload examples. They are not yet canonical TriTRPC frame fixtures.

The remaining work for full transport admission is:

- assign stable schema/context labels and derive IDs where required
- bind the payloads to specific SERVICE/METHOD surfaces
- emit canonical frame vectors plus nonce fixtures
- verify byte parity through the existing Rust/Go conformance flow
