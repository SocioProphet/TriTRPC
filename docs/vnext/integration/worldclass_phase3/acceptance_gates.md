# Phase 3 acceptance gates

This note defines when the first implementation slice should be considered complete enough to merge into the clean phase-2 branch.

## Required artifacts

- [ ] `parse_typed_beacon_refs.py` exists and matches the reviewed semantic beacon fixture shape
- [ ] `parse_coordination_fixture.py` exists and matches the reviewed semaphore/barrier fixture shape
- [ ] `benchmark_capture_bridge.py` exists and reads the phase-2 harness inputs
- [ ] at least one example output is present for beacon ref parsing
- [ ] at least one example output is present for coordination parsing or benchmark bridging

## Scope control

- [ ] no hot-path runtime wire changes are introduced in this PR
- [ ] no new canonical protocol claims are made beyond the reviewed phase-2 artifacts
- [ ] the implementation slice remains reference-tooling only

## Follow-on trigger

Once this PR is accepted, the next implementation slice can safely target:

1. fixture-driven reference execution over all three reviewed fixture shapes
2. benchmark helper execution over populated captures
3. a minimal native runtime test target bound to one stable fixture family
