# TriTRPC v4.1 semaphore protocol note

This note captures the intended semaphore placement for the experimental v4 governance + telemetry layer.

## Design rule

Use the **slowest cadence that still satisfies correctness, threat model, and reviewability**.

- hot path for routing / admissibility / immediate execution
- stream defaults for stable per-stream semantic posture
- stream overrides for exceptional frame-local changes
- beacon deltas for shared dynamic operating posture
- registry defaults for route policy and retained governance semantics
- boundary / deployment manifests for execution posture and trust boundaries
- event ledger for every transition that must be replayable or auditable

## Hot semaphore layer

These already exist in the wire and should stay compact.

### Control243

- `path_profile`
- `exec_lane`
- `evidence_grade`
- `fallback_policy`
- `route_format`

### State243

- `lifecycle`
- `epistemic`
- `novelty`
- `friction`
- `scope`

## Stream-default semaphore layer

These should ride `STREAM_OPEN.default_braid` / `default_state` and only use
`STREAM_DATA` overrides when necessary.

Recommended use:

- stable semantic braid for a stream
- stable semantic state for a stream
- one-off anomaly override
- one-off scope escalation
- one-off review escalation

## Beacon semaphore layer

These belong in typed beacon deltas.

### BEACON_CAP

Capability envelope:

- `capability_state = full | safe_subset | disabled`
- `venue_mode = local | remote_control | cloud`

### BEACON_INTENT

Live operating posture:

- `admission = open | leased | drain`
- `review_mode = auto | human_required | human_hold`
- `context_health = healthy | compacting | lossy`
- `recovery_mode = retry | hedge | rollback`
- `incident_mode = normal | degraded | contain`

### BEACON_COMMIT

Authoritative or latched state:

- `provenance_state = unpinned | pinned | attested`
- `route_validity = valid | stale | revoked`
- `override_state = none | temporary | latched`
- committed `incident_mode`

## Registry semaphore layer

These should live on routes, not on the hot wire.

- `observability_class`
- `privacy_class`
- `retention_class`
- `evidence_min_grade`
- `allowed_execution_venues`
- `allowed_tool_origins`
- `default_semaphores`
- `latched_semaphores`
- `allowed_overrides`

## Boundary and deployment semaphore layer

These belong in manifests.

- `execution_venues`
- `filesystem_boundary`
- `network_boundary`
- `mcp_locality`
- `allowed_hook_domains`
- `allowed_hook_env_vars`
- `cloud_execution_allowed`
- `data_residency`
- `event_ledger_required`
- `control_snapshot_required`
- `release_attestation_required`

## Ledger transition requirements

Every semaphore transition that changes control-plane behavior should emit a ledger record with:

- `semaphore_family`
- `old_state`
- `new_state`
- `reason_code`
- `trigger_kind`
- `actor`
- `policy_bundle_hash`

## Behavior classes

### Advisory

Inform interpretation or routing, but do not independently block execution.

Examples:
- `novelty`
- `scope`
- `capability_state`

### Gating

Execution cannot proceed without honoring them.

Examples:
- `friction = GATE`
- `review_mode = human_required`
- `admission = drain`
- `route_validity = revoked`

### Latched

Once raised, they require explicit authoritative clearance and should appear in committed state plus the event ledger.

Examples:
- `incident_mode = contain`
- `override_state = latched`
- `provenance_state = attested`
