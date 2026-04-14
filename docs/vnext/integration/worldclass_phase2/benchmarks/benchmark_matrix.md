# Benchmark matrix

| Scenario | Purpose | Expected TriTRPC edge |
|---|---|---|
| Small authenticated hot frames | compact control path | fewer bytes per control frame |
| Shared-context multi-agent stream | inheritance + typed beacons | fewer repeated semantic bytes |
| Semaphore/barrier coordination | governed scarce resource control | fewer application-level coordination round trips |
| Artifact commit boundary flow | manifest/hash-bound commit plane | more explicit boundary semantics |
| Novelty or contradiction regime shift | async semantic deltas | smaller semantic correction path |
| Large opaque payload transfer | neutral / possible disadvantage | no claim of universal win |

## Measurement dimensions

- mean bytes per control frame
- mean bytes per data frame
- semantic reuse rate
- beacon count
- semaphore events
- barrier events
- artifact commit events
- repair / replay events

## Baselines

- TriTRPC
- gRPC + Protobuf
- Thrift Compact
- Avro RPC
