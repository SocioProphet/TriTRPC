# TriTRPC braided cadence implementation v4

## What changed

This revision turns the braided semantic cadence from a design note into executable wire behavior.

1. `topic23.proposed.v1` is now a concrete 23-topic registry with stable numeric slots, mnemonic short codes, families, aliases, and descriptions.
2. `cycle7.proposed.v1` is now a concrete 7-phase registry with human labels and Gray-code machine labels.
3. `Braid243` remains a one-byte mapping from `(phase, topic)` into the live `7 x 23 = 161` coordinate space.
4. `State243` is now a real one-byte semantic state with five trits:
   - lifecycle: `draft | active | frozen`
   - epistemic: `observed | derived | verified`
   - novelty: `routine | novel | anomalous`
   - friction: `fluid | review | gate`
   - scope: `local | cohort | global`
5. `STREAM_OPEN` can now carry default `Braid243 + State243` semantics.
6. `STREAM_DATA` can now omit semantics and inherit them, or override them with an optional 2-byte semantic tail.
7. The CLI now emits codebooks, braid-aware vectors, and a braid-cadence comparison report.

## Why this matters

The transport gain does **not** come from adding more semantic detail to every frame. It comes from moving semantic detail to the slowest cadence that still satisfies correctness and policy.

In this implementation:

- adding a braid+state pair to `STREAM_OPEN` costs **2 bytes once per stream**;
- adding the same braid+state pair to `STREAM_DATA` costs **2 bytes per data frame**;
- putting the context into a separate beacon costs **26 bytes once per shared context epoch**.

That creates clean break-even surfaces:

- inherited stream defaults beat per-frame semantic carriage after **2 data frames**;
- a separate beacon beats per-frame semantic carriage after **13 data frames**;
- a shared beacon becomes even more favorable when multiple streams reuse the same semantic context.

## Measured outputs from the current reference package

Primitive frame sizes:

- `STREAM_OPEN` baseline: 43 bytes
- `STREAM_OPEN` with inherited braid/state defaults: 45 bytes
- `STREAM_DATA` baseline: 35 bytes
- `STREAM_DATA` with per-frame braid/state override: 37 bytes
- `BEACON_INTENT` carrying shared context: 26 bytes

Representative totals:

- one stream, 10 DATA frames:
  - baseline: 393 bytes
  - per-frame semantics: 413 bytes
  - inherited defaults: 395 bytes
  - beaconed context: 419 bytes
- one stream, 1000 DATA frames:
  - baseline: 35043 bytes
  - per-frame semantics: 37043 bytes
  - inherited defaults: 35045 bytes
  - beaconed context: 35069 bytes
- ten streams, 100 DATA frames each:
  - baseline: 35430 bytes
  - per-frame semantics: 37430 bytes
  - inherited defaults: 35450 bytes
  - beaconed context: 35456 bytes

So the braid is cheapest when it rides stream defaults or beacons, and most expensive when carried redundantly at frame rate.

## Design law now enforced by the reference package

Do not send meaning when we can send coordinates.
Do not resend coordinates when we can inherit them.
Do not rotate projections faster than resolver epochs, caches, and policy can absorb.

## Remaining implementation gaps

1. The upstream Go/Rust implementation still needs the same semantic tail behavior for `STREAM_OPEN` and `STREAM_DATA`.
2. `topic23.proposed.v1` is still a proposed codebook. It is no longer a placeholder, but it is not yet authoritative.
3. `BEACON_INTENT` currently treats the semantic payload as opaque bytes; the next step is to define a typed semantic delta schema.
4. Benchmarking is still reference-package-first. The same inheritance and beacon surfaces should be benchmarked in the native runtime.

## Immediate next patch targets

1. Port `State243` to the native runtime.
2. Add stream semantic inheritance in upstream `STREAM_OPEN`/`STREAM_DATA`.
3. Freeze `topic23.v1` with authoritative topic ownership.
4. Add typed beacon semantic deltas rather than opaque payload bytes.
5. Benchmark three regimes natively: per-frame, inherited, and beaconed.
