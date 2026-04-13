# policy_attestation_v1

Status: Unified-v4-annex
Owner: TriTRPC policy / authority lane
Applies-to: beacon-carried authoritative updates and durable commit receipts

## 1. Purpose

`policy_attestation_v1` defines the minimum shared provenance and authority object used by typed policy and commit deltas.

It exists to make authority explicit when a route policy is changed, a route is paused or rebound, or a durable receipt or proof promotes evidence posture.

## 2. Design rule

Observational telemetry MAY recommend or summarize.
Only trusted authority output MAY authorize policy mutation.
Only durable receipt or proof material MAY justify verified evidence promotion.

`policy_attestation_v1` is the object that binds those authority claims to a stable handle and proof surface.

## 3. Logical schema

```json
{
  "attestation_type": "policy_attestation.v1",
  "authority_h": 0,
  "policy_h": 0,
  "issuer_h": 0,
  "scope": "route|dictionary|epoch|global",
  "decision_class": "fallback|pause|resume|lane_mask|rebind|invalidate|receipt|replay_anchor",
  "issued_at_ms": 0,
  "effective_from_epoch": 0,
  "effective_until_epoch": 0,
  "receipt_ref": "string|null",
  "proof_ref": "string|null",
  "replay_ref": "string|null",
  "signature_ref": "string|null",
  "evidence_grade": "exact|sampled|verified",
  "reason_code": "string|null"
}
```

## 4. Invariants

- MUST originate from a trusted policy or receipt authority.
- MUST be attached to any delta that authorizes future `CTRL243.fallback` values.
- MUST be attached to any delta that promotes evidence to `verified`.
- MUST NOT be synthesized from browser UI callbacks or local minified telemetry.
- SHOULD reference authority, policy, receipt, and replay objects by handle or hash escape rather than inline prose.

## 5. Lowering guidance

The packed representation SHOULD lower to:

- `authority_h[Handle243]`
- `policy_h[Handle243]?`
- `issuer_h[Handle243]?`
- `scope[1]`
- `decision_class[1]`
- `issued_at_ms[S243 or external time-handle]`
- `effective_from_epoch[S243]?`
- `effective_until_epoch[S243]?`
- `receipt_h[Handle243]?`
- `proof_h[Handle243|hash-escape]?`
- `replay_h[Handle243]?`
- `signature_h[Handle243|hash-escape]?`
- `evidence_grade[1]`
- `reason_h[Handle243]?`

## 6. Shared use sites

`policy_attestation_v1` is intended to be embedded by:

- `route_policy_delta.v1`
- `semantic.commit.v1`

It MAY later be reused by dedicated audit-chain or registry-governance deltas.

## 7. Non-goals

This object does not define the cryptographic algorithm suite, transport binding, or certificate chain format.
Those remain under the unified suite/profile and transport-security sections.
