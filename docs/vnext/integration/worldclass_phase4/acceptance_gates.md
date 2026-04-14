# Phase 4 acceptance gates

This note defines when the first native-test-target slice should be considered complete enough to merge into the phase-3 branch.

## Required artifacts

- [ ] `emit_native_test_manifest.py` exists and reads the reviewed semantic beacon fixture family
- [ ] at least one example native-test manifest output is present
- [ ] the slice remains limited to one stable fixture family

## Scope control

- [ ] no hot-path runtime behavior is changed in this PR
- [ ] no fixture family other than semantic beacon sequences is targeted here
- [ ] the output is a test-manifest bridge, not yet a native runtime implementation

## Follow-on trigger

Once this PR is accepted, the next slice can target:
1. a minimal Rust or Go test that consumes the emitted manifest shape
2. one stable assertion path over the semantic beacon fixture family
3. extension of the same pattern to a second fixture family only after the first is stable
