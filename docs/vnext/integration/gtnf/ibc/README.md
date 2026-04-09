# GTNF Cosmos / IBC runtime subpack

This directory captures the first external adapter target for the governed triparty netting fabric.

## Current lock

- first implementation target: `ibc-go` stable v10 line
- first carrier: IBC Classic + ICS-20 + callbacks + `memo.gtnf`
- first topology: two-chain local Gaia-style topology
- relayer family: Hermes `1.13.x` candidate family

## Why this path first

The current Cosmos / IBC docs already expose the packet lifecycle, ICS-20 acknowledgement semantics, callback surfaces, memo-carried custom packet data path, and local relayer workflow needed to test GTNF as a governed release shell without forking IBC core.

## What is in scope

- source-side GTNF intent registration
- `memo.gtnf` carrier
- ICS-20 send / ack / timeout mapping
- callback-driven policy / proof / contradiction handling
- event assertion harness alignment
- relayer validation log and candidate selection

## What is deferred

- native IBC v2 payload carriage
- Packet Forward Middleware as a required baseline
- ICS-27 as a required baseline
- exact relayer tag lock before validation

## Runtime handoff

The runtime handoff bundle should include:
- locked build spec subset
- version notes
- event schema
- `memo.gtnf` examples
- runtime manifest
- candidate relayer validation script

The first successful executable run should lock or reject one Hermes tag with evidence.
