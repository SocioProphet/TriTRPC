# route_policy_delta_v1

Status: Unified-v4-annex
Owner: TriTRPC route / policy authority lane
Targets: Beacon-A dictionary and route policy refresh
Depends-on:

- `CTRL243`
- `Handle243`
- `S243`
- `policy_attestation_v1`

## 1. Purpose

`route_policy_delta_v1` carries authoritative route-level policy changes that affect future hot-frame defaults or route-handle semantics.

It exists specifically to keep advisory degradation distinct from authoritative control mutation.

## 2. Logical schema

```json
{
  "delta_type": "route_policy_delta.v1",
  "epoch": 0,
  "scope": "cohort|global",
  "route_h": 0,
  "policy_h": 0,
  "update_kind": "fallback|pause|resume|lane_mask|route_invalidate|dictionary_rebind",
  "effective_from_epoch": 0,
  "effective_until_epoch": 0,
  "fallback_policy": {
    "value": "none|classical-fallback-ok|hedged-ok",
    "reason_class": "capacity|timeout|maintenance|manual|experiment",
    "ttl_ms": 0
  },
  "lane_mask": {
    "classical": "allow|deny|inherit",
    "quantum": "allow|deny|inherit",
    "hybrid": "allow|deny|inherit"
  },
  "route_target": {
    "route_h_new": 0,
    "dictionary_epoch": 0
  },
  "attestation": {
    "attestation_type": "policy_attestation.v1",
    "authority_h": 0,
    "policy_h": 0,
    "issuer_h": 0,
    "scope": "route|dictionary|epoch|global",
    "decision_class": "fallback|pause|resume|lane_mask|rebind|invalidate",
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
}
```

## 3. Invariants

- MUST originate from a trusted policy or route authority, not a telemetry normalizer.
- MUST be advisory to future frames, not retroactive mutation of frames already emitted.
- MAY authorize future `CTRL243.fallback` values.
- MUST NOT be emitted for single local timeout or retry observations.
- SHOULD reference routes, policy objects, and authorities by handle.
- SHOULD be carried on Beacon-A because it is dictionary, route, and capability adjacent.
- MUST remain distinct from `degradation.cluster.v1` even when both are emitted in the same epoch.

## 4. Authority split

The intended control chain is:

1. Atlas observes.
2. `degradation.cluster.v1` advises.
3. `route_policy_delta.v1` authorizes.
4. Subsequent hot requests execute with the authorized `CTRL243` posture.
5. `semantic.commit.v1` closes the loop with durable receipt or replay references.

This split prevents sampled telemetry from directly mutating hot control.

## 5. Packed wire shape (proposed)

`update_kind[1] | scope[1] | route_h[Handle243] | policy_h[Handle243] | attestation[...] | eff_from[S243] | eff_until[S243]? | fallback_value[1]? | reason_class[1]? | ttl[S243]? | lane_bits[1]? | route_h_new[Handle243]? | dict_epoch[S243]?`

## 6. Compiler rule

`route_policy_delta.v1` MAY justify future `CTRL243.fallback` changes on new requests.
`route_policy_delta.v1` MUST NOT by itself re-interpret prior frames.

Subsequent hot requests MAY carry:

- `[profile, lane, evidence, fallback, routefmt] = [0,0,0,1,1]` for `classical-fallback-ok`
- `[profile, lane, evidence, fallback, routefmt] = [0,0,0,2,1]` for `hedged-ok`

only after this delta has been emitted by a trusted authority path.
