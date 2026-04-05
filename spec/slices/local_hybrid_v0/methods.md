# Method Catalog

This file defines the method surface for the first local-hybrid slice.

The method IDs below are logical TriTRPC service and method names. The payload schemas should be aligned with the shared contract files in `socioprophet-standards-storage`.

## 1. `supervisor.v1.Session/Open`

### Purpose
Open or resume a locally authoritative session.

### Request shape
- `session_id` — nullable string for resume
- `actor` — human or system actor descriptor
- `surface` — client entry surface metadata
- `device` — device ID and posture snapshot

### Response shape
- `session_id`
- `opened_at`
- `authority` — expected to be `local` for this slice
- `policy_bundle_hash`
- `evidence_journal_head`

## 2. `supervisor.v1.Task/Plan`

### Purpose
Normalize user input into a task graph before any remote dispatch.

### Request shape
- `session_id`
- `input`
- `attachments`

### Response shape
- `task_id`
- `plan.steps`
- `requires_remote_execution`
- `candidate_capability`

## 3. `policy.v1.Decision/Evaluate`

### Purpose
Evaluate whether egress, tool use, or remote execution is allowed.

### Request shape
- `task_id`
- `actor`
- `device`
- `requested_operation`
- `data`

### Response shape
- `allow`
- `reason`
- `approved_destination_zone`
- `required_transformations`
- `max_context_bytes`
- `ttl_seconds`
- `policy_hash`

## 4. `control.v1.Capability/Resolve`

### Purpose
Resolve a logical capability ID into an execution binding.

### Request shape
- `task_id`
- `capability`
- `constraints`

### Response shape
- `resolved`
- `binding.capability_instance_id`
- `binding.execution_lane`
- `binding.worker_endpoint`
- `binding.worker_contract`
- `binding.credential_scope`
- `binding.binding_ttl_seconds`

## 5. `worker.v1.Capability/Execute`

### Purpose
Execute the typed capability payload within the approved execution lane.

### Request shape
- `task_id`
- `capability_instance_id`
- `input`
- `execution_policy`

### Response shape
- `task_id`
- `status`
- `output`
- `provenance.worker_id`
- `provenance.model_id`
- `provenance.toolchain`
- `provenance.input_digest`
- `provenance.output_digest`

## 6. `evidence.v1.Event/Append`

### Purpose
Append a signed or signable execution artifact to the evidence journal.

### Request shape
- `event.event_id`
- `event.parent_event_id`
- `event.task_id`
- `event.session_id`
- `event.actor`
- `event.capability`
- `event.policy_hash`
- `event.execution_lane`
- `event.zone_crossings`
- `event.input_digest`
- `event.output_digest`
- `event.timestamps`

### Response shape
- `appended`
- `journal_offset`
- `evidence_digest`

## 7. `replay.v1.Cairn/Materialize`

### Purpose
Create a replay handle over a completed execution boundary.

### Request shape
- `task_id`
- `journal_offset`
- `materialize_artifacts`

### Response shape
- `cairn_id`
- `replay_handle`
- `artifacts`

## Packing and fixture note

The methods above should eventually be represented as deterministic fixture vectors using the existing TriTRPC packing and verification discipline. This file defines the logical surface; fixture files define the reproducible byte-level contract.
