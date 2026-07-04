# Path-H Semantic Wire Fixtures

Status: draft fixture slice  
Scope: TritRPC Path-H hot-path control frames bound to Semantic SerDes projections

## Purpose

This slice adds executable fixture coverage for the Path-H semantic-wire contract.
It complements the Path-H qutrit / hybrid control annex by binding the hot
control frame to Semantic SerDes objects without placing full semantic payloads
or quantum states on the hot path.

The contract is:

```text
SemanticCell / SHIR assertion
  -> SemanticControlCodebook
  -> WireSemanticProjection
  -> RouteProjectionBundle
  -> Path-H hot frame
  -> receipt / replay / projection-loss report
```

## Hot-path rule

Path-H semantic frames carry only compact handles and ternary coordinates:

- `CTRL243`
- `route_h`
- `projection_id`
- `sem243_ref`
- `state243_ref`
- `schema_h`
- `context_h`
- `bundle_h`
- replay epoch and sequence coordinates

They must not carry:

- full semantic payloads
- sensitive policy objects
- n-ary assertion graphs
- trainable semantic tensors
- quantum states

## Required invariants

The validator in `tools/verify_path_h_semantic_wire.py` enforces these draft
invariants:

1. `CTRL243.profile` must be `2` for Path-H.
2. Path-H semantic control must use quantum or hybrid lane, never classical.
3. Every semantic frame must include `route_h` and `projection_id`.
4. Every semantic frame must include `sem243_ref` and `state243_ref`.
5. Sensitive or full semantic payloads must remain off the hot path.
6. Strict codebook epoch fixtures must not drift from the frame epoch.
7. Lossy semantic lowering must cite a projection-loss report.
8. BSM3 frames must use one of the nine canonical qutrit BSM3 codes.

## Fixtures

Positive fixtures live under:

```text
spec/drafts/path_h_semantic_wire/fixtures/valid/
```

Negative fixtures live under:

```text
spec/drafts/path_h_semantic_wire/fixtures/invalid/
```

Negative fixtures include `expected_error` so they act as regression tests for
specific failure modes, not only generic failure.

## Validation

Run:

```bash
python tools/verify_path_h_semantic_wire.py
```

or through the repository verification surface:

```bash
make path-h-semantic-wire
```

## Boundary with Semantic SerDes

Semantic SerDes owns the source meaning, codebook, projection, route bundle,
receipts, and projection-loss reports. This repository owns the Path-H hot-frame
invariants that make those handles safe to move over TritRPC.
