# GTNF Cosmos / IBC runtime summary

## Current lock

- first implementation target: current ibc-go stable v10 line
- first carrier: IBC Classic + ICS-20 + callbacks + memo.gtnf
- first topology: two-chain local Gaia-style topology
- relayer family: Hermes 1.13.x candidate family

## Why this path first

The current Cosmos / IBC surfaces already expose the packet lifecycle, ICS-20 acknowledgements, callback hooks, memo-carried custom packet data path, and local relayer workflow needed to test GTNF as a governed release shell without forking IBC core.

## In scope

- source-side GTNF intent registration
- memo.gtnf carrier
- ICS-20 send / acknowledgement / timeout mapping
- callback-driven policy, proof, and contradiction handling
- event assertion alignment
- relayer validation log and candidate selection

## Deferred

- native IBC v2 payload carriage
- packet-forward middleware as a required baseline
- ICS-27 as a required baseline
- exact relayer tag lock before runtime validation
