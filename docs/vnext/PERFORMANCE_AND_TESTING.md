# TriTRPC vNext: Performance and testing

This document is the public-facing summary of what the vNext work does, where it wins, where it merely ties, and how the claims are tested.

## What TriTRPC vNext is trying to prove

TriTRPC vNext is not claiming a magical universal serialization theorem.

The claim is narrower and stronger:

- TriTRPC is structurally advantaged on authenticated hot-path agentic transport.
- It wins most clearly when route reuse, stream-state reuse, ternary payloads, and compact semantic coordinates dominate.
- It does not claim a universal win on large opaque blobs.

That is the right claim because generic serializers such as Protobuf and Thrift are already strong baselines. The purpose of TriTRPC is to make transport intelligence first-class rather than incidental.

## Measured wire-size results in the current v4 design pack

### Small authenticated hot unary frame

Measured case: handle-routed authenticated unary request with a small JSON payload.

- TriTRPC: 52 bytes
- Protobuf handle schema: 56 bytes
- Protobuf fused schema: 54 bytes
- Thrift compact handle schema: 59 bytes
- Thrift compact fused schema: 55 bytes
- Protobuf inline route: 87 bytes
- Thrift compact inline route: 90 bytes

Interpretation:
TriTRPC wins on the hot frame because route handles and compact hot control are native protocol concepts instead of application-level conventions.

### Small authenticated stream DATA frame

Measured case: stream DATA with a small JSON payload.

- TriTRPC: 35 bytes
- Protobuf handle schema: 41 bytes
- Protobuf fused schema: 37 bytes
- Thrift compact handle schema: 42 bytes
- Thrift compact fused schema: 38 bytes

Interpretation:
The moat is smaller than in ternary payload cases, but still real.

### Ternary payload surface

Measured case: 100 tri-state values in {0,1,2}.

- TriTRPC TritPack243: 20 bytes
- Protobuf packed uint32: 102 bytes
- Thrift compact list<i32>: 104 bytes
- Thrift binary list<i32>: 409 bytes

Interpretation:
When the payload alphabet is genuinely ternary, the win is large and structural.

### Braided semantic coordinate surface

Measured case: one 7×23 braid coordinate.

- TriTRPC Braid243: 1 byte
- Protobuf combined coordinate: 2 bytes
- Protobuf split phase/topic: 4 bytes
- Thrift compact combined coordinate: 4 bytes
- Thrift compact split phase/topic: 5 bytes

Interpretation:
Braided semantic coordinates are a natural fit for a ternary-native hot control plane.

### Large opaque payload counterexample

Measured case: authenticated hot unary frame with a 1024-byte opaque payload.

- TriTRPC: 1052 bytes
- Protobuf handle schema: 1053 bytes
- Protobuf fused schema: 1051 bytes
- Thrift compact handle schema: 1056 bytes
- Thrift compact fused schema: 1052 bytes

Interpretation:
This is the important honesty check. TriTRPC does not claim a universal win on large opaque blobs. On that surface, the fixed-header advantages mostly disappear.

## Braided cadence measurements

Measured cadence primitives:

- STREAM_OPEN baseline: 43 bytes
- STREAM_OPEN with inherited braid/state defaults: 45 bytes
- STREAM_DATA baseline: 35 bytes
- STREAM_DATA with per-frame braid/state override: 37 bytes
- BEACON_INTENT carrying shared context: 26 bytes

Break-even findings:

- Inherited defaults beat per-frame semantic carriage after 2 DATA frames.
- A separate beacon beats per-frame semantic carriage after 13 DATA frames.
- Once multiple streams share the same context, the beacon path becomes strongly attractive.

Interpretation:
The braid is most valuable when attached to cadence boundaries rather than sprayed across every data frame.

## What the tests cover

The experimental v4 package covers:

- trit and length codec behavior
- control-field packing
- deployment and boundary policy validation
- audit-chain behavior
- transport comparison harnesses
- braid and state semantics
- stream inheritance vs override behavior

Generated evidence lives in:

- `docs/vnext/generated/sample_vectors_v4.json`
- `docs/vnext/generated/sample_audit_chain_v4.json`
- `docs/vnext/generated/test_report_v4.txt`
- `docs/vnext/reports/transport_comparison_v4.json`
- `docs/vnext/reports/braid_cadence_comparison_v4.json`

## How to speak about the project publicly

Good claim:
“TriTRPC vNext is optimized for authenticated hot-path agentic transport, especially when route reuse, stream inheritance, ternary payloads, and compact semantic control matter.”

Bad claim:
“TriTRPC always beats Protobuf and Thrift.”

The first claim is supported by the current design pack.
The second one is too broad.

## What remains to be done

- Port Braid243 and State243 into native Go and Rust.
- Add typed BEACON_INTENT semantic deltas.
- Regenerate native golden fixtures.
- Benchmark native per-frame vs inherited vs beaconed semantics.
- Freeze the authoritative topic23 and cycle7 registries.
