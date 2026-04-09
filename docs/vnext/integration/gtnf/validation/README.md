# GTNF validation subpack

This directory captures the current validation posture for the governed triparty netting fabric.

## Scope

The current validation surface is deliberately split into two layers:

1. **Deterministic reference-model annealing**
   - adversarial fixture corpus
   - canonical denial/release classes
   - scorecard metrics
   - branch-order hardening
2. **Runtime validation protocol**
   - first executable target
   - relayer candidate order
   - lock / reject criteria
   - required return artifacts

## Current canonical hardening rules

- `epsilon_release = 1.0`
- `MAX_MEMO_BYTES = 2048`
- carrier size / parse before replay / proof
- proof-handle integrity before proof / finality
- stale witness denial before proof / finality
- callback sender authorization before replay / nonce
- export remains stricter than local release

## Canonical negative classes

- `NoReleasableCycle`
- `BlockedProof`
- `BlockedStaleWitness`
- `RejectedMalformedProof`
- `RejectedOversizedMemo`
- `RejectedMalformedCallbackSender`
- `ExportDeniedContradictoryWitnessLocalReleasePreserved`

## Core metrics

- `FRR` — false release rate
- `RRR` — replay rejection rate
- `TRI` — timeout refund integrity
- `CVP` — contradiction veto preservation
- `EDC` — export denial correctness
- `WFR` — stale witness freshness rejection
- `PHR` — malformed proof-handle rejection
- `MBR` — oversized memo boundary rejection
- `CBR` — malformed callback sender rejection
- `XWR` — contradictory export witness rejection
- `CE` — capital efficiency
- `kappa_compress` — gross-flow compression ratio

## Current status

The deterministic v6 reference model and adversarial corpus are treated as the current logic-level truth surface.

Runtime validation is not yet complete. The next substrate is a network-capable environment where the first Hermes / IBC run can be scored with the same metric pack.
