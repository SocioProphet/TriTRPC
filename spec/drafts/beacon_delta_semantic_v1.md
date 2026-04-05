# TriTRPC typed beacon semantic deltas v1

Status: Unified-v4-annex
Consumes: `atlas_event_v1`
Targets: Beacon-A / Beacon-B / Beacon-C
Depends-on:

- `CTRL243`
- `KIND243`
- `S243`
- `Handle243`
- `Braid243`
- `State243`
- `policy_attestation_v1`

## 1. Scope

This annex defines typed semantic delta objects for beacon-carried shared context.
It replaces opaque beacon semantic bytes with typed deltas while preserving the hot-path rule:
semantic detail MUST ride the slowest cadence that still satisfies correctness and policy.

## 2. Delta families

This annex defines four delta families:

- `semantic.intent.v1` -> Beacon-B
- `semantic.commit.v1` -> Beacon-C
- `degradation.cluster.v1` -> Beacon-A
- `route_policy_delta.v1` -> Beacon-A

## 3. Shared lowering rules

Logical fields in reference fixtures SHOULD lower to compact wire fields:

- `phase + topic` -> `Braid243`
- semantic state -> `State243`
- route / policy / identity references -> `Handle243`
- lengths, counts, epochs -> `S243`
- delta family / delta kind -> 1-byte enum
- scope / evidence / recommendation classes -> 1-byte enum or trit-coded field

Canonical hot beacon frames MUST NOT carry UTF-8 field names or JSON object keys.

## 4. Delta: semantic.intent.v1

### 4.1 Purpose
Carries shared provisional intent that must be visible beyond a single local surface.

### 4.2 Logical schema

```json
{
  "delta_type": "semantic.intent.v1",
  "epoch": 0,
  "scope": "cohort|global",
  "route_h": 0,
  "subject_h": 0,
  "policy_h": 0,
  "intent_kind": "reserve|lease|cancel|backpressure|window|notify_shared",
  "semantic": {
    "phase": "dec|act",
    "topic": "rte|wfl|dlg|pln|inc",
    "state": {
      "lifecycle": "active",
      "epistemic": "derived",
      "novelty": "routine|anomalous",
      "friction": "fluid|review|gate",
      "scope": "cohort|global"
    }
  },
  "ttl_ms": 0,
  "priority": 0,
  "reason_code": "string|null"
}
```

### 4.3 Invariants

- MUST ride `KIND243=6` Beacon-B.
- MUST NOT claim `verified` evidence.
- MUST NOT mutate `fallback`.
- MUST NOT be emitted for `notify_local`.
- SHOULD reference handles instead of strings.

## 5. Delta: semantic.commit.v1

### 5.1 Purpose
Carries durable completion, receipt, provenance, and invalidation semantics.

### 5.2 Logical schema

```json
{
  "delta_type": "semantic.commit.v1",
  "epoch": 0,
  "scope": "cohort|global",
  "route_h": 0,
  "stream_id": 0,
  "commit_kind": "completion|receipt|replay_anchor|invalidate|tombstone",
  "receipt_ref": "string|null",
  "proof_ref": "string|null",
  "replay_ref": "string|null",
  "evidence_to": "exact|sampled|verified",
  "semantic_promotion": {
    "phase": "frz",
    "topic": "prv|asr|inc",
    "state": {
      "lifecycle": "frozen",
      "epistemic": "verified",
      "novelty": "routine|anomalous",
      "friction": "fluid|gate",
      "scope": "cohort|global"
    }
  },
  "attestation": {
    "attestation_type": "policy_attestation.v1",
    "authority_h": 0,
    "policy_h": 0,
    "issuer_h": 0,
    "scope": "route|dictionary|epoch|global",
    "decision_class": "receipt|replay_anchor|invalidate",
    "issued_at_ms": 0,
    "effective_from_epoch": 0,
    "effective_until_epoch": 0,
    "receipt_ref": "string|null",
    "proof_ref": "string|null",
    "replay_ref": "string|null",
    "signature_ref": "string|null",
    "evidence_grade": "exact|sampled|verified",
    "reason_code": "string|null"
  },
  "invalidations": [
    {
      "kind": "route|dictionary|identity|policy",
      "target_h": 0
    }
  ]
}
```

### 5.3 Invariants

- MUST ride `KIND243=7` Beacon-C.
- `evidence_to=verified` requires `receipt_ref` or `proof_ref`.
- SHOULD carry replay-grade references by handle or hash escape, not inline prose.
- SHOULD embed `policy_attestation_v1` when evidence is promoted or an invalidation is authoritative.

## 6. Delta: degradation.cluster.v1

### 6.1 Purpose
Carries cohort-level degradation, contention, and advisory routing pressure.

### 6.2 Logical schema

```json
{
  "delta_type": "degradation.cluster.v1",
  "epoch": 0,
  "scope": "cohort|global",
  "route_h": 0,
  "degradation_kind": "latency|timeout|capacity|challenge|network|backpressure",
  "window_ms": 0,
  "population_n": 0,
  "observed": {
    "p50_ms": 0,
    "p95_ms": 0,
    "error_rate_bp": 0,
    "timeout_rate_bp": 0
  },
  "lane_availability": {
    "classical": "open|degraded|closed|unknown",
    "quantum": "open|degraded|closed|unknown",
    "hybrid": "open|degraded|closed|unknown"
  },
  "recommendation": {
    "kind": "none|watch|consider_fallback|shed_load|pause_route",
    "target": "none|classical-fallback-ok|hedged-ok"
  },
  "evidence": "sampled|exact"
}
```

### 6.3 Invariants

- MUST ride `KIND243=5` Beacon-A.
- SHOULD default to `evidence=sampled`.
- MUST be advisory only.
- MUST NOT directly mutate `fallback`.
- MAY inform later trusted route-policy updates.

## 7. Authority split

The following split is normative for this draft family:

- `degradation.cluster.v1` advises.
- `route_policy_delta.v1` authorizes.
- `semantic.commit.v1` closes with durable receipt or invalidation evidence.

This separation preserves a clean trust boundary between sampled telemetry and authoritative control mutation.
