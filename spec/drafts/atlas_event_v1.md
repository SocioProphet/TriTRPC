# atlas_event_v1

Status: Reference-only
Owner: TriTRPC Atlas / Observability lane
Applies-to: Atlas wire only
Does-not-override: TriTRPC v1 interoperability, Unified v4 hot-frame definitions

## 1. Purpose

`atlas_event_v1` defines the canonical normalized event contract by which lossy runtime telemetry
(browser, gateway, worker, runtime, scheduler, and edge transport observations) is transformed into
stable semantic atoms before any compilation into TriTRPC hot frames, inherited stream semantics,
or beacon payloads.

This contract exists to prevent unstable implementation details from contaminating the trit control wire.

## 2. Non-goals

`atlas_event_v1` does not:

- define new hot-wire fields;
- infer `profile` from client callback names;
- infer `lane` from UI or minified telemetry;
- permit direct mutation of `fallback` from local callback events;
- treat minified symbol names as stable semantics;
- require all Atlas events to produce wire output.

## 3. Trust model

Atlas observations are evidentiary inputs, not wire authority.

The compiler MAY use Atlas observations to:

- choose among already-defined `KIND243` frame families;
- decide whether semantic context belongs on `STREAM_OPEN`, `STREAM_DATA`, a beacon, or Atlas only;
- learn route reuse and route-handle opportunities;
- recommend policy changes to route dictionaries or epochs.

The compiler MUST NOT:

- mint new wire-level control fields;
- infer cryptographic or compliance posture from observational UI telemetry;
- upgrade `evidence=verified` without durable receipt or proof material.

## 4. Canonical schema

```json
{
  "version": "atlas_event_v1",
  "ts_ms": 0,
  "trace_id": "string",
  "req_id": "string",
  "span_id": "string",
  "parent_span_id": "string|null",
  "origin": "browser-ui|edge-proxy|gateway|worker|runtime",
  "source_confidence": "exact|derived|heuristic",
  "event_class": "dispatch_start|dispatch_progress|dispatch_end|completion_ok|completion_receipt|timeout_soft|timeout_hard|retry_scheduled|retry_dispatched|cancel_local|cancel_shared|notify_local|notify_shared|dictionary_publish|dictionary_invalidate|degrade_cluster|fallback_policy_update|error_terminal",
  "route_fingerprint": "string|null",
  "route_handle_hint": 0,
  "transport_hint": "unary|stream|unknown",
  "shared_scope": "local|cohort|global",
  "fanout_count": 0,
  "duration_ms": 0,
  "outcome_hint": "unknown|success|failure|canceled|degraded",
  "degradation_hint": "none|latency|backpressure|timeout|capacity|challenge|network",
  "retry_ordinal": 0,
  "receipt_ref": "string|null",
  "proof_ref": "string|null",
  "tags": {
    "bundle": "string|null",
    "browser": "string|null",
    "network_class": "string|null"
  }
}
```

## 5. Canonical normalization rules

### 5.1 Stable over unstable

The normalizer MUST preserve:

- ordering;
- correlation;
- duration;
- fan-out;
- route repetition;
- timeout / retry / cancel / receipt transitions;
- local vs shared scope.

The normalizer MUST discard as first-class semantics:

- minified symbol names;
- bundle-local function offsets;
- line numbers in shipped bundles;
- incidental callback nesting.

### 5.2 Event-class obligations

- `dispatch_start`: a request or stream has begun.
- `dispatch_progress`: streaming or chunk progression only.
- `dispatch_end`: transport-local completion boundary.
- `completion_ok`: successful logical completion without durable receipt.
- `completion_receipt`: durable receipt or proof anchor exists.
- `timeout_soft`: local timeout observation without definitive terminal outcome.
- `timeout_hard`: terminal timeout outcome.
- `retry_scheduled`: retry planned but not yet emitted.
- `retry_dispatched`: retry emitted onto transport.
- `cancel_local`: cancel visible only to the local actor or surface.
- `cancel_shared`: cancel must be visible to shared peers or streams.
- `notify_local`: local observer or subscriber fan-out only.
- `notify_shared`: notification changes shared coordination state.
- `dictionary_publish`: route, capability, or epoch dictionary publication or refresh.
- `dictionary_invalidate`: route, capability, or identity invalidation or tombstone.
- `degrade_cluster`: cohort-level degradation or contention signal.
- `fallback_policy_update`: policy-authorized route or default change.
- `error_terminal`: terminal error outcome.

## 6. Compiler destinations

Each `atlas_event_v1` event MUST compile to exactly one or more of:

- hot frame emission;
- inherited stream semantic default;
- semantic override tail;
- beacon payload;
- Atlas-only retention.

Atlas-only retention is a first-class valid outcome.

## 7. Rejection rules

Events lacking `trace_id` or `event_class` MUST be rejected.
Events with `completion_receipt` but no `receipt_ref` or `proof_ref` SHOULD be downgraded to `completion_ok`.
Events with `notify_local` MUST NOT emit wire output.
Events with `fallback_policy_update` MUST originate from a policy compiler or equivalent trusted authority, not a UI callback normalizer.
