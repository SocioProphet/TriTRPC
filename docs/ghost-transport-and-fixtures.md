# Ghost transport and fixture contract

## Purpose
This note defines the minimum transport and fixture expectations for Ghost control-plane artifacts carried over TritRPC/TriTRPC.

## Scope
The Ghost transport surface currently covers:
- semantic Ghost events (method family `semantic.*`)
- primeER contradiction-fracture reports (method family `primeER.*`)
- signed registry update bundles (method family `registry.*`)
- correlated control-plane validation reports (method family `validation.*`)
- signed Ghost event wrappers and governance attestations (cross-cutting)

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

`sha256(jcs_rfc8785(event_without_canonical_hash))`

where `event_without_canonical_hash` is the event with the top-level `canonical_hash` member removed before hashing, and `jcs_rfc8785(...)` means canonicalization according to RFC 8785 (JSON Canonicalization Scheme) over the resulting JSON value encoded as UTF-8. This RFC 8785 requirement is normative for fixtures and replay. Inputs that cannot be represented or canonicalized under RFC 8785, including duplicate object member names, MUST be treated as malformed.

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
