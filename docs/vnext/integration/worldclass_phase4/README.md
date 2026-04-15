# Worldclass phase 4 native test target slice

This branch starts the first native-test-target-oriented slice on top of the runnable phase-3 reference tooling.

## Scope of slice 1

This slice targets exactly one stable reviewed fixture family:
- `fixture_semantic_beacon_sequence.json`

## Intent

The purpose is not to implement the full runtime semantics yet.
The purpose is to define and emit a compact native-test manifest that a Rust or Go test can consume later.

## Deliverables in this slice

1. a manifest emitter for the semantic beacon fixture family
2. one example native-test manifest output
3. acceptance gates describing when this slice is good enough to stack into real runtime tests
