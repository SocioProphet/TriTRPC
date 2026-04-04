# Path-H qutrit / hybrid companion package

This package carries the merged Path-H/qutrit-hybrid control workstream as a companion annex and conformance bundle for TriTRPC vNext/v4.

## Contents

- `reference/tritrpc_path_h_reference.py` — Python reference encoder for the draft Path-H hot-path events.
- `generated/path_h_fixtures.json` — canonical draft fixtures.
- `generated/path_h_demo_sequence.json` — example end-to-end event sequence.
- `generated/path_h_fixture_notes.md` — explanatory notes on fixture intent and field choices.
- `parity/go/tritrpc_path_h_go_parity.go` — Go parity harness.
- `parity/rust/` — Rust parity harness.
- `parity/README.md` — how to run the parity checks.

## Relationship to the unified spec

The normative prose lives in `../../../spec/drafts/annex_b_path_h_qutrit_hybrid_profile.md`.

The code and fixtures here are conformance-oriented companion material, not independent normative text.
