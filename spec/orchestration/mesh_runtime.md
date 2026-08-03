# Mesh runtime message layer (heartbeat + dispatch)

Between the scheduler (picks nodes) and the coordinator (settles results) is the message flow that
keeps the registry live and dispatches units. This pins the **decidable** part; the transport that
moves the bytes (QUIC / libp2p) is delegated.

## Heartbeat (`schemas/jsonschema/heartbeat.v0.schema.json`)

A node's periodic `{node_ref, attestationRef, sentMs, capacity}` message. `apply_heartbeat` refreshes
the node's `NodeRegistration.lastSeenMs` + `capacity` so the scheduler's liveness/capacity filters
stay current — **fail-closed**: only a node already in the trusted registry may heartbeat.
`live_nodes` / `evict_stale` select or drop by `now - lastSeenMs <= ttlMs`. This is what actually
populates the liveness the scheduler reads.

## WorkAssignment (`schemas/jsonschema/work-assignment.v0.schema.json`)

A coordinator's dispatch of one WU to one node: `{wu_id, node_ref, deadlineMs, packRef}` (packRef = the
WU pack's SHA3 SCHEMA-ID). `build_assignment` derives the deadline from `policy.slo_ms`.
`check_assignment` admits a dispatch **only** to a node the scheduler assigned, that is currently live,
before the deadline, for the matching `wu_id` — else refused.

## Composition

The verifier proves the flow end to end: a heartbeat revives a node's liveness → the scheduler then
picks it → the dispatch is admitted. Together with admission (`node_admission`), scheduling
(`mesh_scheduler`), settlement (`mesh_coordinator`), and proof (`proof_envelope`/`attestation_verifier`),
this closes the decidable mesh runtime. FIPS: no primitive (message-flow logic); packRef is SHA3. The
transport is the only remaining runtime and is delegated.
