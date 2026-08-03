# Route-handle dictionary negotiation (vNext hot-path gap #3)

A v4 hot frame carries a 1-byte `Handle243` (direct 0..242) in place of a full route URI. That byte is
meaningless without an **agreed dictionary** mapping handle → route. This closes gap #3 of the vNext
"open gaps that still need code" list — additive: it explains the existing `route_handle` byte and
changes no wire.

## `RouteDictionary` (`schemas/jsonschema/route-dictionary.v0.schema.json`)

`entries[{handle 0..242, route}]` plus a `dictionaryId` — **SHA-256 of the canonical (handle-sorted,
compact) entries** — which is the agreement token.

## Negotiation + resolution (`reference/route_dictionary.py`) — fail-closed

- `build_dictionary(map)` — rejects duplicate or out-of-range handles; computes the SHA-256 token.
- `resolve(dict, handle)` — returns the route, or **refuses** if the dictionary's token no longer
  matches its entries (tampered/stale) or the handle is not present (unresolvable route).
- `negotiate(local, remote)` — two peers agree **iff** their tokens match; a mismatch is refused (no
  ambiguous resolution — a peer must never guess a route for a handle it did not agree to).

A hot frame's `route_handle` is thus resolvable only against a negotiated dictionary; an unknown or
disagreed handle fails closed rather than routing somewhere unintended. Advertised via a Beacon-A
(capability) frame.

## FIPS / boundary

The agreement token is SHA-256 (FIPS 180-4). Additive — does not change the TritPack243 / S243 /
Handle243 wire.
