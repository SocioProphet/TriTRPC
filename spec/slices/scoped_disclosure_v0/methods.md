# Scoped Disclosure Slice v0 — Method Catalog

This document defines the transport-facing methods for governed disclosure rooms.

The request and response fields below are conceptual v0 shapes meant to guide shared schema work. They are not yet declared as stable TritRPC v1 canonical payload contracts.

## 1. `room.v1.Room/Open`

### Request

- `room_contract_ref` — versioned reference to the governing room contract
- `room_id` — deterministic room identifier or proposed identifier
- `membership_snapshot_ref` — reference to the opening membership set
- `projection_policy` — attributable / scoped pseudonymous / masked rules
- `minimum_anonymity_set`
- `retention_policy_ref`

### Response

- `room_id`
- `room_contract_version`
- `room_state_ref`
- `decision` — accepted / rejected
- `reason_code`

## 2. `room.v1.Disclosure/Append`

### Request

- `room_id`
- `event_id`
- `actor_projection_ref`
- `discourse_class`
- `payload_ref` or `payload_inline`
- `attachment_refs[]`
- `requested_relay_mode`
- `client_risk_flags[]`

### Response

- `event_id`
- `accepted_projection_mode`
- `accepted_relay_mode`
- `moderation_state`
- `evidence_append_ref`
- `reason_code`

## 3. `room.v1.Relay/Authorize`

### Request

- `room_id`
- `event_id`
- `requested_relay_mode`
- `target_scope_ref`
- `policy_basis_ref`
- `requester_role`

### Response

- `event_id`
- `relay_decision` — allow / deny / escalate
- `granted_scope_ref`
- `relay_receipt_ref`
- `reason_code`

## 4. `room.v1.Moderation/Decide`

### Request

- `room_id`
- `event_id`
- `moderation_action`
- `policy_basis_ref`
- `evidence_refs[]`
- `requester_role`

### Response

- `event_id`
- `moderation_decision_ref`
- `effective_visibility`
- `effective_relay_mode`
- `appeal_path_ref`
- `reason_code`

## 5. `room.v1.Reveal/Request`

### Request

- `room_id`
- `target_event_id`
- `requester_identity_ref`
- `requester_role`
- `reason_code`
- `policy_basis_ref`
- `requested_reveal_scope`

### Response

- `reveal_request_ref`
- `submission_state` — accepted / rejected / requires_quorum
- `reason_code`

## 6. `room.v1.Reveal/Decide`

### Request

- `reveal_request_ref`
- `deciding_authority_ref` or `quorum_ref`
- `decision`
- `authorized_scope`
- `rationale_ref`

### Response

- `reveal_decision_ref`
- `decision`
- `effective_scope`
- `evidence_append_ref`
- `reason_code`

## 7. `room.v1.Room/Materialize`

### Request

- `room_id`
- `materialization_point` — latest / as_of_event / as_of_time
- `include_withdrawn`
- `include_moderation_history`
- `include_reveal_history`

### Response

- `room_state_ref`
- `cairnline_ref`
- `room_contract_version`
- `membership_snapshot_ref`
- `event_sequence_refs[]`

## Deterministic fixture priorities

The first fixture pass SHOULD prioritize:

1. room open with contract version binding
2. masked confessional append accepted under minimum anonymity set
3. allegation append forced into moderator-only relay
4. reveal request denied without sufficient authority
5. reveal request approved with explicit decision artifact
6. room materialization including moderation and reveal lineage

## Invariants

A conforming implementation of this slice MUST preserve these invariants:

- no disclosure append without room-contract reference
- no reveal decision without reveal request lineage
- no relay widening without explicit relay receipt
- no room materialization that hides contract version
- no mutation of visibility or relay posture without evidence-bearing artifact emission
