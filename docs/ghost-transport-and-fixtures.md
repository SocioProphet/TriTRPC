# Ghost transport and fixture contract

## Purpose
This note defines the minimum transport and fixture expectations for Ghost control-plane artifacts carried over TritRPC/TriTRPC.

## Scope
The Ghost transport surface currently covers:
- semantic Ghost events
- signed Ghost event wrappers
- signed governance attestations
- signed registry update bundles
- correlated control-plane reports

## Method namespace
Recommended method families:
- `semantic.declareCell`
- `semantic.reportLiftedProjection`
- `primeER.reportContradictionFracture`
- `registry.reportUpdateBundle`
- `validation.reportOutcome`

## Fixture classes
Every method SHOULD have fixtures for:
- happy
- warning
- blocked
- malformed

Blocked means well-formed but semantically inadmissible.
Malformed means invalid at transport/schema/canonicalization level.

## Canonical event integrity
If a payload-bearing Ghost event includes `canonical_hash`, implementations MUST verify:

`sha256(canonical_json(event_without_canonical_hash))`

with sorted keys, compact separators, preserved array order, and the top-level `canonical_hash` excluded from hash scope.

## Signed wrappers
Signed wrappers MUST bind:
- schema ref
- subject type
- subject ref
- canonical hash
- signer ref
- key id
- scope ref
- issued-at
- nonce
- signature

## Notes
Fixtures are the interoperability contract. Runtime integrations may evolve, but fixture semantics and canonicalization rules must remain replay-stable.
