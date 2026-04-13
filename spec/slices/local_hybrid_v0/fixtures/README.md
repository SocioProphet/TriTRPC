# Fixture Catalog

This file defines the initial deterministic fixture inventory for the local-hybrid slice.

These fixtures are intentionally behavioral first. They describe the required invariants so later fixture vectors and reference implementations can be tested against them.

## Fixture 01 — `local_only_denied_remote`

### Scenario
A remote-capable task is planned, but policy denies egress.

### Expected invariants
- `policy.v1.Decision/Evaluate` returns `allow = false`
- no `control.v1.Capability/Resolve` call is issued
- no `worker.v1.Capability/Execute` call is issued
- `evidence.v1.Event/Append` records zero zone crossings
- replay materialization remains valid for the local-only path

## Fixture 02 — `remote_allowed_redacted`

### Scenario
A remote-capable task is planned and policy permits tenant execution only after transformations.

### Expected invariants
- `allow = true`
- `required_transformations` is non-empty
- capability resolution succeeds
- worker execution succeeds
- evidence records exactly two zone crossings: device to tenant and tenant to device
- replay handle is materialized over the post-evidence boundary

## Fixture 03 — `tenant_unreachable_fallback`

### Scenario
Policy allows tenant execution but the tenant execution lane is unavailable.

### Expected invariants
- capability resolution or execution fails with tenant unavailability
- the supervisor degrades to local-only completion or deferred state according to policy
- evidence records the fallback reason explicitly
- no ambiguous partially successful state remains

## Fixture 04 — `evidence_append_failure_quarantine`

### Scenario
Execution succeeds but evidence append fails.

### Expected invariants
- worker execution result exists
- evidence append returns failure
- output is quarantined or withheld from promotable completion
- no replay handle is emitted as if the run were fully committed

## Fixture 05 — `cairn_replay_roundtrip`

### Scenario
A completed execution is materialized into a cairn and replayed.

### Expected invariants
- replay handle resolves successfully
- step lineage remains stable
- input and output digests match the original committed boundary
- no hidden mutable state is required to reproduce the replay boundary

## Future fixture work

The next step is to turn each scenario into deterministic vectors encoded with the existing TriTRPC reference packing and verification discipline.
