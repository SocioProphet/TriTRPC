# ExecutionBridgeService contract v0.1

## Goal

Provide a typed bridge from governed work requests into execution-plane realization when a request must resolve into `agentplane` execution.

## Methods

- `ResolveOrderToBundle`
- `AttachRunArtifact`
- `AttachReplayArtifact`

## Rule

Execution bridge methods SHOULD preserve stable references back to `orderId` and relevant `descriptorId` values.

## Constraint

The execution bridge MUST pass only execution-relevant fields, stable identifiers, and evidence references. It MUST NOT tunnel the full knowledge descriptor graph through the execution plane.
