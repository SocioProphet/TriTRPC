# GTNF runtime validation protocol

## Goal

Harden or falsify the current GTNF Cosmos / IBC Classic baseline in a runnable environment.

## Locked baseline

- current ibc-go stable v10 line
- IBC Classic + ICS-20 + callbacks + memo.gtnf
- two-chain local Gaia-style topology
- Hermes 1.13.x candidate family

## Runtime questions

1. Does the locked Classic carrier execute without violating native ICS-20 semantics?
2. Does runtime preserve GTNF release and denial classes across send, acknowledgement, timeout, and contradiction branches?
3. Can one exact Hermes tag be locked with evidence?
4. Does real memo and gas behavior force a tighter carrier bound?
