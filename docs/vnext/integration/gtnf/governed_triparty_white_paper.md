# Governed Triparty Netting Fabric

Version 1.0-rc1

## Summary

GTNF is a governed release layer for heterogeneous settlement, authority, proof, and export flows.

It does not replace transport or escrow. It sits above them and controls when evidence becomes admissible, when admitted state becomes releasable, and when local release becomes exportable.

## Main ideas

- Evidence is not permission.
- Permission is not release.
- Local validity is not exportability.
- Replay, contradiction, witness freshness, and proof integrity are first-class boundaries.
- Reversal and replayability are part of the design, not cleanup work after failure.

## Why this matters

Most current stacks have transport, escrow, credentials, or policy in isolation. GTNF is the boundary layer that connects them without collapsing them into one confidence score.

## Current status

This repo capture is a focused subset of the larger GTNF corpus. It is intended to preserve the doctrine, integration posture, validation substrate, and first Cosmos / IBC runtime target inside TriTRPC for discussion and future hardening.
