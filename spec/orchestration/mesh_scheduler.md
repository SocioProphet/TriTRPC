# Mesh Scheduler & Collector (coordinator front-half)

The lifecycle is `registry → schedule → collect → verify → reduce → settle`. The mesh coordinator
(`mesh_work_unit.md`) implements verify/reduce/settle. This spec pins the **front-half** — the
scheduling and collection *policy* a coordinator decides from the registry alone. The actual packet
transport that dispatches a WU and gathers results (QUIC / libp2p) is the wire **below** this and is
out of scope (delegated) — this layer decides *who* and *whether*, not *how the bytes move*.

## Registry (`schemas/jsonschema/node-registration.v0.schema.json`)

A `NodeRegistration` is the admitted trusted-node record (from `node_admission`, #88) plus `capacity`
(`freeSlots`, `sandboxes`) and `liveness` (`lastSeenMs`, `ttlMs`) and the `trustScore` used to rank.

## Schedule (`reference/mesh_scheduler.py`) — fail-closed

`eligible(registry, pack, now)` keeps a node iff it is **live** (`now - lastSeenMs <= ttlMs`), its
`region` satisfies `pack.policy.residency`, it offers `pack.sandbox`, and it has a free slot; the set
is ranked **highest trust first** (ties broken by `node_ref`). `schedule` assigns `pack.replication`
of them — and if **fewer than replication** are eligible it **refuses** (the redundancy the
`proof_mode` needs cannot be met; never silently under-replicate).

## Collect

`collect(assignment, results, deadlineMs)` keeps only results from **assigned** nodes that arrived by
the **SLO deadline**; late or unassigned results are dropped. The kept set is exactly what feeds
`reduce()` — the verifier proves the chain composes: schedule → collect → settle.

## FIPS / boundary

No cryptographic primitive here (scheduling policy). The QUIC/libp2p transport and the heartbeat
source that populates `liveness` are the runtime below. Does not touch the tritrpc v4/vNext wire.
