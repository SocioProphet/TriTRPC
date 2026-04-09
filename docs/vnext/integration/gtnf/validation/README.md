# GTNF validation summary

## Scope

This directory captures the current validation posture for GTNF.

## Current hardening rules

- release materiality floor is active
- memo carrier size is bounded conservatively
- callback sender authorization is checked before replay logic
- proof-handle integrity is checked before proof and finality
- stale witness state blocks release
- export is stricter than local release

## Current status

The deterministic reference-model pass is green on the current adversarial corpus.

Runtime validation is not complete. The next substrate is a network-capable environment where the locked Cosmos / IBC baseline can be run and scored.
