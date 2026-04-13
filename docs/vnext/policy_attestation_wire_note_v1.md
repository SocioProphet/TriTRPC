# policy_attestation_wire_note_v1

Status: Reference-only
Scope: packed-wire lowering guidance for `policy_attestation_v1`
Depends-on:

- `policy_attestation_v1`
- `Handle243`
- `S243`
- suite / transport profile selection in the unified v4 master draft

## 1. Purpose

This note narrows the packed-wire interpretation of `policy_attestation_v1` without prematurely freezing the final signature or certificate-chain format.

Its purpose is to keep authority provenance compact and uniform across:

- `route_policy_delta.v1`
- `semantic.commit.v1`

while preserving the current separation between:

- observational telemetry;
- advisory degradation;
- authoritative policy mutation;
- durable commit / receipt evidence.

## 2. Design constraint

`policy_attestation_v1` MUST remain a compact handle-first structure.

It SHOULD lower to handles, compact enums, and `S243` lengths or epochs.
It SHOULD NOT require inline verbose strings or algorithm prose on the hot beacon path.

## 3. Minimal packed fields

Recommended packed order:

1. `authority_h[Handle243]`
2. `policy_h[Handle243]?`
3. `issuer_h[Handle243]?`
4. `scope[1]`
5. `decision_class[1]`
6. `issued_at_ms[S243 or external time-handle]`
7. `effective_from_epoch[S243]?`
8. `effective_until_epoch[S243]?`
9. `receipt_h[Handle243]?`
10. `proof_h[Handle243|hash-escape]?`
11. `replay_h[Handle243]?`
12. `signature_h[Handle243|hash-escape]?`
13. `evidence_grade[1]`
14. `reason_h[Handle243]?`

This order keeps the authority and policy handles first, timing and epoch next, evidence anchors next, and optional human reason indirection last.

## 4. Enum guidance

Suggested compact enums:

### 4.1 scope
- `0 = route`
- `1 = dictionary`
- `2 = epoch`
- `3 = global`

### 4.2 decision_class
- `0 = fallback`
- `1 = pause`
- `2 = resume`
- `3 = lane_mask`
- `4 = rebind`
- `5 = invalidate`
- `6 = receipt`
- `7 = replay_anchor`

### 4.3 evidence_grade
- `0 = exact`
- `1 = sampled`
- `2 = verified`

These assignments are implementation guidance only until promoted.

## 5. Signature handling rule

`signature_ref` SHOULD be carried indirectly.

Preferred order:

1. `Handle243` into a registry object published elsewhere;
2. `Handle243` into an audit-chain node;
3. `245` hash-escape when only a stable hash reference is available.

The attestation object does not itself choose the cryptographic suite.
That remains governed by the unified suite selector and approved/research profile rules.

## 6. Receipt / proof handling rule

`receipt_ref`, `proof_ref`, and `replay_ref` SHOULD follow the same compact indirection model.

A `verified` evidence grade SHOULD normally imply at least one of:

- `receipt_h`
- `proof_h`
- `replay_h`

is present.

## 7. Two canonical examples

### 7.1 Fallback authorization

Compact reading:

- authority handle present;
- policy handle present;
- decision class = fallback;
- effective epoch set;
- proof or signature reference present;
- evidence grade = exact.

### 7.2 Durable receipt promotion

Compact reading:

- authority handle present;
- decision class = receipt or replay_anchor;
- receipt/proof/replay references present;
- evidence grade = verified.

## 8. Non-goals

This note does not define:

- the final binary signature encoding;
- certificate chain transport;
- trust-root distribution;
- external audit-log schema.

Those should be attached later through the suite/profile and audit annexes rather than inflating the beacon path.
