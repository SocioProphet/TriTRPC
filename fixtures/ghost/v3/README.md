# GhostEventV3 fixture examples

This directory contains the first concrete GhostEventV3 fixture examples.

Included cases:
- `happy.valid_sparse_vector.event.json`
- `blocked.duplicate_basis_index.event.json`
- `blocked.registry_state_hash_mismatch.event.json`
- `malformed.bad_prime_vector_type.event.json`

These examples are intentionally narrow and align with `fixtures/ghost/manifest.v0.2.json`.
They provide reviewable transport examples for the Event-IR → GhostEvent V3 bridge without pulling the entire Ghost fixture corpus into this PR.
