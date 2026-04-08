# atlas_to_wire_compiler_v1

Status: Reference-only
Consumes: `atlas_event_v1`
Produces: TriTRPC hot frames, inherited semantic defaults, beacon payloads, or Atlas-only retention

## 1. Compiler principle

Compile observational telemetry into the smallest wire surface that still preserves correctness,
routing, replayability, and policy visibility.

Priority order:

1. Atlas only
2. inherited stream defaults
3. beacon payload
4. per-frame semantic override
5. hot-frame field mutation

## 2. Existing wire targets

The compiler targets only existing v4 surfaces:

- `CTRL243 = [profile, lane, evidence, fallback, routefmt]`
- `KIND243` frame families
- `Handle243`
- `STREAM_OPEN` inherited `Braid243 + State243`
- `STREAM_DATA` optional semantic override tail
- Beacon-A / Beacon-B / Beacon-C

## 3. Proposed semantic encoding rule

### 3.1 Braid243 (proposed implementation rule)

Until authoritative freeze of `cycle7` and `topic23`, encode:

`Braid243 = (phase_index - 1) * 23 + (topic_index - 1)`

### 3.2 State243 (proposed implementation rule)

Encode trits in this order:

`[lifecycle, epistemic, novelty, friction, scope]`

Value sets:

- lifecycle: `draft=0, active=1, frozen=2`
- epistemic: `observed=0, derived=1, verified=2`
- novelty: `routine=0, novel=1, anomalous=2`
- friction: `fluid=0, review=1, gate=2`
- scope: `local=0, cohort=1, global=2`

Packing rule:

`State243 = ((((lifecycle * 3) + epistemic) * 3 + novelty) * 3 + friction) * 3 + scope`

## 4. Route-format rules

- `routefmt=0` for inline names only when no stable handle exists.
- `routefmt=1` when a stable route handle exists.
- `routefmt=2` when route material is primarily beacon-referenced for the active epoch.

## 5. Evidence rules

- `evidence=0 exact`: direct local observation or exact route/runtime fact.
- `evidence=1 sampled`: aggregate or probabilistic degradation signal.
- `evidence=2 verified`: durable receipt or proof anchor exists.

The compiler MUST NOT promote to `verified` without `completion_receipt` and durable receipt or proof material.

## 6. Fallback rules

- `fallback=0 none` by default.
- `fallback=1 classical-fallback-ok` only after trusted route or policy authorization.
- `fallback=2 hedged-ok` only after trusted route or policy authorization.

Local timeout or retry observations MUST NOT directly flip `fallback`.

## 7. Event-class compilation table

### 7.1 dispatch_start

- emit `KIND243=0` for unary or `KIND243=2` for stream open;
- prefer `routefmt=1` when `route_handle_hint` is valid;
- assign inherited semantics:
  - default phase/topic: `act/rte`;
  - alternative phase/topic: `act/wfl` if workflow orchestration dominates.

### 7.2 dispatch_progress

- emit `KIND243=3` only for actual streaming;
- inherit stream semantics by default;
- add semantic override only if phase/topic or state changed materially.

### 7.3 dispatch_end

- emit `KIND243=1` for unary response or `KIND243=4` for stream close;
- default semantic transition: `rev/asr`.

### 7.4 completion_ok

- Atlas only unless a higher-layer protocol requires explicit logical completion payload;
- do not promote evidence beyond `exact` automatically.

### 7.5 completion_receipt

- emit Beacon-C;
- semantic promotion: `frz/prv`;
- candidate evidence promotion: `exact -> verified`.

### 7.6 timeout_soft

- Atlas only;
- may contribute to later `degrade_cluster`.

### 7.7 timeout_hard

- emit `KIND243=8` if terminal;
- semantic transition: `rev/inc` or `rev/rsk`.

### 7.8 retry_scheduled

- Atlas only.

### 7.9 retry_dispatched

- emit a new unary request or stream open;
- reuse route handle when available;
- fallback posture only if already authorized by policy.

### 7.10 cancel_local

- Atlas only unless transport close/error is required locally.

### 7.11 cancel_shared

- Beacon-B if cancellation intent must be shared.

### 7.12 notify_local

- Atlas only;
- MUST NOT emit wire output.

### 7.13 notify_shared

- Beacon-B only when shared coordination state changes.

### 7.14 dictionary_publish

- Beacon-A.

### 7.15 dictionary_invalidate

- Beacon-C if durable tombstone or invalidation;
- otherwise Beacon-A.

### 7.16 degrade_cluster

- Beacon-A;
- may influence future route-policy compilation;
- does not mutate `fallback` directly.

### 7.17 fallback_policy_update

- Beacon-A route policy refresh;
- MUST originate from trusted policy compiler input;
- SHOULD lower to `route_policy_delta.v1`.

### 7.18 error_terminal

- emit `KIND243=8`;
- semantic transition: `rev/inc`;
- optional Beacon-C if durable error receipt exists.

## 8. Typed beacon lowering

The compiler SHOULD lower shared context through the typed beacon annex family:

- `semantic.intent.v1`
- `degradation.cluster.v1`
- `route_policy_delta.v1`
- `semantic.commit.v1`

The intended authority chain is:

1. Atlas observes.
2. degradation advises.
3. route policy authorizes.
4. hot frames execute.
5. commit beacons close the loop with durable receipts or invalidations.
