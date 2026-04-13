# TriTRPC v4.1 governance and telemetry patch plan

This document captures the remaining **existing-file** rewrites for the v4.1 governance + telemetry layer.

## Goals

- keep the hot wire invariant
- extend route-level governance in the registry
- add telemetry and semaphore policy as sibling config objects
- extend runtime/deployment boundary posture
- widen the audit chain into a control-plane event ledger
- add typed beacon semantic deltas for CAP / INTENT / COMMIT lanes

## Existing-file patch slices

### 1. `README.md`

- normalize package identity from `v0.2` to `v0.4`
- change quickstart path from `tritrpc_requirements_impl_v2` to `tritrpc_requirements_impl_v4`
- rename generated artifacts to `*_v4.*`
- document the new governance + telemetry layer

### 2. `src/tritrpc_requirements_impl/codec.py`

- add:
  - `WIRE_CANON_VERSION = "tritrpc.vnext.wire.v4"`
  - `WIRE_INVARIANT = True`
  - `SEMAPHORE_LAYER = "hot"`
- do **not** widen `Control243` or `State243`

### 3. `src/tritrpc_requirements_impl/registry.py`

Extend `RouteDescriptor` with:

- `semantic_topic`
- `default_braid`
- `default_state_policy`
- `observability_class`
- `privacy_class`
- `retention_class`
- `evidence_min_grade`
- `policy_bundle_ref`
- `telemetry_profile_ref`
- `allowed_execution_venues`
- `allowed_tool_origins`
- `default_semaphores`
- `latched_semaphores`
- `allowed_overrides`

### 4. `configs/sample_registry.yaml`

Add route-governance defaults for routes `7` and `19`, including:

- `semantic_topic`
- `observability_class`
- `privacy_class`
- `retention_class`
- `evidence_min_grade`
- `policy_bundle_ref`
- `telemetry_profile_ref`
- `allowed_execution_venues`
- `allowed_tool_origins`
- `default_semaphores`
- `latched_semaphores`
- `allowed_overrides`

### 5. `src/tritrpc_requirements_impl/policy.py`

Add sibling dataclasses:

- `TelemetryProfile`
- `SemaphorePolicy`

Add validator:

- `validate_telemetry_profile()`

### 6. `src/tritrpc_requirements_impl/boundary.py`

Extend `BoundaryManifest` with:

- `execution_venues`
- `filesystem_boundary`
- `network_boundary`
- `mcp_locality`
- `allowed_hook_domains`
- `allowed_hook_env_vars`
- `remote_control_allowed`
- `cloud_execution_allowed`
- `data_residency`
- `tool_boundary_manifest`

Add matching validation rules.

### 7. `src/tritrpc_requirements_impl/deployment.py`

Extend `DeploymentManifest` with:

- `telemetry_profile_path`
- `redaction_profile_path`
- `retention_profile_path`
- `otel_export_profile_path`
- `control_snapshot_required`
- `event_ledger_required`
- `release_attestation_required`
- `materialized_views`

Add deployment validation for non-research and AI systems.

### 8. `src/tritrpc_requirements_impl/audit.py`

Add widened ledger record:

- `EventRecordV2`
- `compute_event_hash_v2()`
- `append_event_record_v2()`
- `verify_event_chain_v2()`

Keep `AuditRecord` for backward compatibility.

### 9. `src/tritrpc_requirements_impl/frames.py`

Add:

- `SemaphoreOp`
- `TypedBeaconDeltaV1`
- `encode_typed_beacon_delta()`
- `decode_typed_beacon_delta()`

Do not alter the hot unary/data frame layout.

### 10. `src/tritrpc_requirements_impl/cli.py`

Add new verbs:

- `validate-telemetry`
- `emit-run-card`
- `emit-policy-posture`

## New files already landed on the feature branch

- `src/tritrpc_requirements_impl/telemetry.py`
- `src/tritrpc_requirements_impl/views.py`
- `configs/telemetry_default.yaml`
- `configs/redaction_strict.yaml`
- `configs/retention_default.yaml`
- `configs/otel_export.yaml`
- `tests/test_views.py`

## Recommended next commit order

1. apply the README / registry / sample registry changes
2. apply `policy.py`, `boundary.py`, and `deployment.py`
3. widen `audit.py` and add typed beacon deltas in `frames.py`
4. extend `cli.py`
5. add validator tests and benchmark outputs
