# GTNF runtime validation protocol

## Goal

Harden or falsify the current GTNF Cosmos / IBC Classic baseline in a runnable environment.

## Locked baseline

- chain-module line: `ibc-go` v10 stable line
- first carrier: IBC Classic + ICS-20 + callbacks + `memo.gtnf`
- demo topology: two-chain local Gaia-style topology
- relayer: Hermes `1.13.x` candidate family

## Questions the runtime pass must answer

1. Does the locked Classic carrier execute without violating native ICS-20 semantics?
2. Does the runtime preserve GTNF release / denial classes across send, ack, timeout, and contradiction branches?
3. Does the relayer candidate family behave consistently enough to lock one exact tag?
4. Does the actual memo/gas envelope force a lower carrier bound than the current constitutional `MAX_MEMO_BYTES`?

## Candidate order

Evaluate Hermes `1.13.x` candidates in descending patch order. A tag may only be locked if the run produces the required artifacts and no undefined denial class appears.

## Minimum execution matrix

- happy-path release
- error acknowledgement
- timeout refund
- replay rejection
- contradiction veto after acknowledgement
- malformed callback sender
- export requested but denied

## Lock criteria

Lock a relayer tag only if:
- the minimum execution matrix completes,
- GTNF event assertions all pass,
- no undefined denial class appears,
- and the return artifacts are complete.

## Reject criteria

Reject a tag if:
- the relay path cannot be established,
- packet lifecycle diverges from the expected Classic baseline,
- GTNF event assertions fail materially,
- or the relayer introduces unclassifiable behavior that cannot be mapped cleanly into the current scorecard.

## Required return artifacts

- filled relayer validation log
- event assertion outputs
- packet / ack / timeout traces
- memo-size and gas observations
- exact relayer tag used
- pass / fail decision with rationale
