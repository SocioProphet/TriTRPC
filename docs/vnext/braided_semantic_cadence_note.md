# Braided Semantic Tag Pattern Cadence for TriTRPC

## Executive view

The braid fits TriTRPC well if we treat it as a **cadence-aware projection layer** rather than as a replacement for canonical semantics.

The core rule is:

- keep **canonical semantic truth** in stable registry cells and claim/event schemas;
- project that truth onto the wire through **cadence-scoped aliases**;
- rotate only the layers whose entropy and threat model justify rotation.

This gives three direct optimization wins:

1. lower hot-frame byte cost;
2. lower dictionary/cache churn;
3. better novelty/assurance handling without widening the common-case frame.

## Mapping to current TriTRPC work

Existing TriTRPC pieces:

- `Control243` – compact hot control
- `S243` – short-or-extended integer encoding
- `Handle243` – route/identity handles
- `Braid243` – 1-byte 7x23 coordinate candidate
- beacon planes – capability / intent / commit
- registry-backed handles and braided identity manifests

The braid should sit on top of these as a four-cadence system:

### 1) Microbeat

Per-message or very short epoch.

Carries:
- route alias / projection alias
- `Braid243` phase×focus coordinate
- tiny risk or novelty band when immediately action-relevant
- short-lived workload presentation identity

Target: **every hot frame remains O(1) bytes of semantic overhead**.

### 2) Mesobeat

Per burst, task, stream, incident slice, or local operational window.

Carries:
- derived context overlays
- threat / risk / novelty / competence bands
- cohort membership
- temporary routing overlays
- friction policy hints

Target: move medium-volatility semantics off hot frames and onto cached delta beacons.

### 3) Macrobeat

Per policy epoch / ontology epoch / trust-domain epoch.

Carries:
- namespace salts
- handle dictionaries
- semantic registry version
- policy epoch
- trust-zone aliases
- coarse environment labels

Target: stabilize the semantic namespace so local caches survive many microbeats.

### 4) Async beat

Triggered by novelty, policy activation, assurance drop, incident mode, or feed changes.

Carries:
- forced alias rollover
- rollback / freeze signals
- shadow / quarantine routing
- competence downgrade notices
- emergency policy deltas

Target: let the system react like a controller rather than waiting for the next scheduled epoch.

## Why this helps the wire

The braid turns repeated inline metadata into amortized beacon cost.

Let:

- `M_inline` = bytes of semantic metadata if carried inline every frame
- `b_hot` = bytes kept on the hot frame
- `B_i` = size of beat-i beacon/delta in bytes
- `R_i` = number of frames amortizing beat-i

Then average semantic overhead per frame becomes:

`M_avg = b_hot + Σ(B_i / R_i)`

The braid is worth it whenever:

`M_inline > M_avg`

### Worked example

Suppose inline semantic metadata would cost 16 bytes per frame.

With the braid we keep:
- `b_hot = 2` bytes (`Braid243` + one small state/projection byte)
- mesobeat beacon = 256 bytes amortized over 500 frames
- macrobeat beacon = 512 bytes amortized over 5000 frames
- async delta = 128 bytes amortized over 2000 frames

Then:

`M_avg = 2 + 256/500 + 512/5000 + 128/2000`

`M_avg = 2.6784 bytes/frame`

So the braid cuts semantic overhead from 16 bytes/frame to about 2.68 bytes/frame, an ~83% reduction in this scenario.

## Why this helps caches and joins

The main hidden win is **churn isolation**.

Without cadence separation, every semantic change tends to invalidate the same dictionary / resolver / cache surface.

With the braid:

- microbeat changes do **not** invalidate macro semantic dictionaries;
- mesobeat changes update only local operational overlays;
- macrobeat changes are rare and explicit;
- async changes are scoped and auditable.

This means:

- route caches stay hot longer;
- beacon dictionaries have longer half-life;
- replay can resolve wire aliases deterministically by epoch;
- search/join costs fall because most context is looked up by handle rather than carried inline.

## Why `Braid243` is especially attractive

Your proposed 7-phase × 23-topic coordinate has 161 states.

A 5-trit byte supports `3^5 = 243` states.

So one byte can encode the full phase×topic coordinate with 82 spare states.

That gives us:

- exact fit for one hot semantic coordinate byte;
- spare capacity for reserved states such as `mixed`, `unknown`, `governance-only`, `shadow`, or future pack versions;
- no need to spend multiple protobuf/thrift fields for the same semantic coordinate.

## Strongest protocol-level uses

### A. Hot unary / hot stream optimization

Current best use:
- keep `Braid243` on hot frames;
- keep the full semantic cell off-wire;
- resolve via `route_h` / `identity_h` / `context_h`.

This preserves compact hot frames while still letting operators and replay systems reconstruct meaning.

### B. Beaconed semantic overlays

The braid is ideal for capability / intent / commit beacons:

- capability beacon: what semantic families and competencies a node can handle;
- intent beacon: which phase/topic/risk overlays are active now;
- commit beacon: what semantic mutation or projection became authoritative.

This is where mesobeat and macrobeat belong.

### C. Novelty-driven adaptation

The async beat is where SAIL-ON-style novelty response lands operationally.

When novelty is detected:
- we do not widen every frame;
- we emit a scoped async delta;
- we switch the affected projection family or cohort;
- we preserve replay and rollback.

### D. FACT-style friction placement

The braid can carry a **friction-needed** signal without carrying the whole explanation on-wire.

For example:
- hot frame carries `State243` or mesobeat overlay saying `review-required` or `assumption-surfacing-required`;
- operator-facing plane pulls the explanatory bundle from the registry / experience plane.

That gives accountability without bloating transport.

### E. KMASS-style push knowledge

The braid also supports *timely context push*:
- microbeat tells us current task slice;
- mesobeat tells us risk/novelty/competence overlay;
- experience plane selects the right knowledge nugget.

This means the braid is not only defensive aliasing. It is also a low-latency context-selection key.

## A clean field split

Recommended wire split:

- `Control243` = protocol / execution / evidence / fallback / routefmt
- `Kind243` = frame class
- `Braid243` = phase×focus-topic hot coordinate
- `State243` = lifecycle/epistemic/novelty/focus-control compact state
- `route_h` = handle to route tuple
- `context_h` = handle to meso/macro context bundle
- `epoch` = resolver epoch

Recommended registry split:

- `TagSemanticCell` = canonical truth
- `WireTagProjection` = cadence-scoped alias/projection
- `TagMutationPolicy` = when and how projection may rotate
- `TagResolverEpoch` = deterministic replay anchor

## The key design law

A semantic field should be placed in the **slowest cadence whose staleness budget and threat model still permit it**.

That single rule minimizes both byte overhead and cache churn.

In practice:

- if a field changes every message, microbeat;
- if it changes every burst/task, mesobeat;
- if it changes every policy or ontology epoch, macrobeat;
- if it changes only on surprises/incidents, async.

## What not to do

1. Do not confuse the wire alias with the canonical semantic truth.
2. Do not rotate macro semantic handles on micro cadence.
3. Do not push sensitive social/human context into general hot frames.
4. Do not let novelty-triggered async deltas bypass audit/replay.
5. Do not overload `Braid243` with too many orthogonal concepts; use a second byte if needed.

## Where the braid most improves TriTRPC

The biggest concrete wins are:

1. **hot-frame shrinkage** through compact semantic coordinates;
2. **stream efficiency** because DATA frames can keep semantic state stable after OPEN;
3. **beacon amortization** of derived and global context;
4. **dictionary stability** through cadence-bounded mutation;
5. **policy agility** because async deltas can roll aliases and overlays without global resets;
6. **replay/explanation quality** because every projection is epoch-bound and resolvable.

## Bottom line

The braid works here if we make it a **semantic control plane** rather than a decorative naming scheme.

That means:
- canonical truth in registry cells,
- compact hot coordinates on the wire,
- cadence-specific beacons for medium/slow semantics,
- async deltas for novelty and assurance events,
- strict replay/audit resolution by epoch.

Under that design, the braid is not just semantically elegant. It is a transport optimization, a cache-coherence strategy, a novelty controller, and an assurance mechanism at the same time.
