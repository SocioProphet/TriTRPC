# TriTRPC competitive surface vs Protobuf and Thrift (v0.3)

## Executive position

TriTRPC should not be sold to ourselves as a universal theorem that "always beats" Protobuf and Thrift under every imaginable schema. That claim is too strong and our own measurements disprove it on at least one surface: for a 1024-byte opaque payload, a manually fused protobuf message is 1051 bytes while the equivalent TriTRPC hot frame is 1052 bytes. The honest position is stronger and more useful: TriTRPC wins by design on the transport surfaces it was invented for.

Those surfaces are:

1. authenticated hot control frames with tiny routing and scheduling scalars,
2. true stream DATA frames after route interning,
3. beaconed/registry-backed agentic meshes where route and identity repetition must be amortized away,
4. ternary or very low-cardinality payload alphabets,
5. semantic coordinates such as 7x23 braid states that map cleanly into a single trit-packed byte.

## What the measurements showed

From the generated comparison artifact:

- Hot unary secure frame, 28-byte JSON payload:
  - TriTRPC: 52 bytes
  - protobuf handle: 56 bytes
  - protobuf fused: 54 bytes
  - thrift compact handle: 59 bytes
  - thrift compact fused: 55 bytes
  - protobuf inline route: 87 bytes
  - thrift compact inline route: 90 bytes

- Stream DATA secure frame, 11-byte JSON payload:
  - TriTRPC: 35 bytes
  - protobuf handle: 41 bytes
  - protobuf fused: 37 bytes
  - thrift compact handle: 42 bytes
  - thrift compact fused: 38 bytes

- 100 tri-state values, payload only:
  - TriTRPC TritPack243: 20 bytes
  - protobuf packed uint32: 102 bytes
  - thrift compact list<i32>: 104 bytes

- One 7x23 braid coordinate:
  - TriTRPC Braid243: 1 byte
  - protobuf combined coordinate: 2 bytes
  - protobuf split phase/topic: 4 bytes

## Why TriTRPC wins when it wins

### 1. Built-in hot-wire control algebra

TriTRPC bakes profile, execution lane, evidence grade, fallback policy, and route format into one canonical Control243 byte. Protobuf and Thrift can emulate this with fused fields, but that fusion is an application convention, not a native transport contract.

### 2. Route and identity interning are transport-level ideas, not afterthoughts

The major advantage is not mystical ternary density by itself. The major advantage is that route and identity handles, beacon references, and braided coordinates are native parts of the transport story. Vanilla protobuf/thrift tend to drag repeated strings around unless the application authors build a separate interning layer.

### 3. Ternary-native payloads are categorical wins

When the payload alphabet itself is ternary, TritPack243 is not shaving a few bytes. It is changing the order of magnitude. Five trits per byte gives a direct advantage over one-byte-per-value varint encodings.

### 4. Stream DATA is where agentic systems live

Agentic meshes produce many small control and data chunks after an initial route/setup event. TriTRPC is explicitly shaped around OPEN/DATA/CLOSE and beacons, so the hot path is optimized around repetition.

## Where Protobuf and Thrift close the gap

1. Large opaque payloads. The payload dominates and fixed header differences largely vanish.
2. Hand-fused competitor schemas. If we allow protobuf/thrift users to manually collapse control metadata into packed scalars and use route handles, the margin becomes small on ordinary byte payloads.
3. Generic serialization tasks. If the problem is "serialize one tiny struct" rather than "run an agentic secure transport frame," protobuf is often the more appropriate baseline.

## Implications for implementation

We should optimize TriTRPC where its design actually compounds.

1. Keep Control243, S243, Handle243, and Braid243 fixed and canonical.
2. Promote beacons and route dictionaries into first-class runtime behavior, not optional extras.
3. Expand Path-B only where the payload alphabet is truly low-cardinality or ternary-native.
4. Do not waste engineering effort trying to beat protobuf on every bulk opaque blob; that is not the moat.
5. Build transport benchmarks around repeated hot frames, stream DATA, and semantic/beacon churn, because that is the regime where TriTRPC is structurally advantaged.

## Recommended claim language

Bad claim:

> TriTRPC always beats Protobuf and Thrift for transport.

Good claim:

> TriTRPC is structurally advantaged over vanilla Protobuf and Thrift on authenticated hot-path agentic transport, especially when route repetition, stream-state reuse, ternary semantics, and braided control coordinates dominate the workload. Competitors can narrow the gap with custom fusion and handle layers, but TriTRPC makes those optimizations first-class rather than incidental.
