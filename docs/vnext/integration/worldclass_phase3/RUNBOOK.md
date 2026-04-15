# Phase 3 runbook

This runbook shows the intended reference-tooling flow for the first implementation slice.

## Inputs from phase 2

Use the reviewed phase-2 artifacts as inputs:

- `worldclass_phase2/fixtures/fixture_semantic_beacon_sequence.json`
- `worldclass_phase2/fixtures/fixture_boundary_artifact_commit_sequence.json`
- `worldclass_phase2/benchmarks/harness/input_template.json`
- `worldclass_phase2/benchmarks/harness/tritrpc_capture_template.json`
- `worldclass_phase2/benchmarks/harness/competitor_capture_template.json`

## Example invocations

### Parse semantic beacon refs
```bash
python docs/vnext/integration/worldclass_phase3/tools/parse_typed_beacon_refs.py \
  docs/vnext/integration/worldclass_phase2/fixtures/fixture_semantic_beacon_sequence.json
```

### Parse coordination / barrier refs
```bash
python docs/vnext/integration/worldclass_phase3/tools/parse_coordination_fixture.py \
  docs/vnext/integration/worldclass_phase2/fixtures/fixture_semaphore_barrier_sequence.json
```

### Bridge benchmark captures
```bash
python docs/vnext/integration/worldclass_phase3/tools/benchmark_capture_bridge.py \
  docs/vnext/integration/worldclass_phase2/benchmarks/harness/input_template.json \
  docs/vnext/integration/worldclass_phase2/benchmarks/harness/tritrpc_capture_template.json \
  docs/vnext/integration/worldclass_phase2/benchmarks/harness/competitor_capture_template.json
```

### Run the combined reference slice
```bash
python docs/vnext/integration/worldclass_phase3/tools/run_reference_slice.py \
  docs/vnext/integration/worldclass_phase2/fixtures/fixture_semantic_beacon_sequence.json \
  docs/vnext/integration/worldclass_phase2/fixtures/fixture_boundary_artifact_commit_sequence.json \
  docs/vnext/integration/worldclass_phase2/benchmarks/harness/input_template.json \
  docs/vnext/integration/worldclass_phase2/benchmarks/harness/tritrpc_capture_template.json \
  docs/vnext/integration/worldclass_phase2/benchmarks/harness/competitor_capture_template.json
```

## Expected outputs

- parsed semantic beacon ref summary
- parsed coordination / barrier summary
- bridged benchmark capture structure
- combined reference slice summary

## Scope reminder

This runbook is for reference-tooling execution only. It does not change the hot-path runtime or assert canonical wire behavior beyond the phase-2 reviewed artifact set.
