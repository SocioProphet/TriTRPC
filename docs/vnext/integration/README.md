# Unified integration

This directory captures the reintegration of the two intentionally separated TriTRPC workstreams:

1. the upstream `docs/vnext/` and draft normative vNext/v4 materials; and
2. the downstream Path-H / qutrit-hybrid control, parity, and unification work.

## Start here

- `unified_spec_integration_crosswalk.md` — exact merge map, source precedence, and placement guidance.
- `branch_pr_merge_runbook.md` — safe merge workflow for integrating branch/PR content into `main` without dropping work.
- `../../spec/drafts/tritrpc_unified_v4_master_spec.md` — working unified master draft.
- `../../spec/drafts/annex_b_path_h_qutrit_hybrid_profile.md` — hybrid/qutrit annex promoted from the parallel workstream.
- `../../reference/experimental/tritrpc_requirements_impl_v4/path_h/` — reference encoder, fixtures, demo sequence, and parity harnesses.

## Intent

The goal is not to preserve two competing branches. The goal is to make the upstream vNext pack and the downstream Path-H/hybrid work one integrated specification family with one conformance story.
