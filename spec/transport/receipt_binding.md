# TriTRPC Receipt Transport Binding v0.1

## Purpose

This document defines how TriTRPC transport metadata participates in MAIPJ run receipts.

The core rule is simple:

> A governed execution receipt is incomplete if the transport path is invisible.

For hybrid and remote executions, transport contributes to:
- latency,
- retry behavior,
- network energy,
- failure semantics,
- deterministic replayability.

TriTRPC therefore provides the transport-side evidence needed to make a receipt operationally meaningful rather than merely application-shaped.

## Scope

This binding applies when a governed execution crosses a TriTRPC boundary, including:
- local-to-sidecar hops,
- host-to-host calls,
- edge-to-cloud delegation,
- planner-to-runner control messages,
- retrieval or evidence calls routed over TriTRPC.

## Transport goals

TriTRPC should expose enough metadata to answer these questions for any governed run:

1. Which deterministic envelope carried the request?
2. Which transport path was selected?
3. How many retries or fallbacks occurred?
4. What timing split belongs to transport vs application execution?
5. What hash or digest proves envelope identity for replay?

## Required receipt contributions

TriTRPC is not the sole receipt owner, but it is the authoritative source for the following transport-aligned fields.

### Bound into `placement` or adjacent transport metadata
- `transport.protocol = "tritrpc"`
- `transport.envelope_hash`
- `transport.route_id`
- `transport.peer_id`
- `transport.retry_count`
- `transport.timeout_count`
- `transport.failure_class` (if terminal or degraded)
- `transport.request_bytes`
- `transport.response_bytes`
- `transport.latency_ms`

### Contributes to energy accounting
- `energy_j.network`
- optional estimates for part of `energy_j.control` when transport routing overhead is separately modeled

### Contributes to replayability
- `replay.supported`
- deterministic envelope identity / canonical hash
- retry/fallback path notes

## Event contract

TriTRPC SHOULD emit the following normalized events when receipt mode is enabled.

### `rpc.request.sent`
```json
{
  "event_type": "rpc.request.sent",
  "payload": {
    "protocol": "tritrpc",
    "route_id": "route://planner/runner@v1",
    "peer_id": "node://edge-a-01",
    "envelope_hash": "sha256:...",
    "request_bytes": 2048
  }
}
```

### `rpc.response.received`
```json
{
  "event_type": "rpc.response.received",
  "payload": {
    "protocol": "tritrpc",
    "route_id": "route://planner/runner@v1",
    "peer_id": "node://edge-a-01",
    "response_bytes": 8192,
    "latency_ms": 41
  }
}
```

### `rpc.retry`
```json
{
  "event_type": "rpc.retry",
  "payload": {
    "route_id": "route://planner/runner@v1",
    "attempt": 2,
    "reason": "deadline_exceeded"
  }
}
```

### `rpc.fail`
```json
{
  "event_type": "rpc.fail",
  "payload": {
    "route_id": "route://planner/runner@v1",
    "failure_class": "upstream_unreachable"
  }
}
```

## Minimal merge logic into a receipt

When an execution receipt is assembled in `agentplane`, the TriTRPC contribution should be merged as follows:

- sum or select the relevant `latency_ms` contribution for transport timing,
- accumulate `request_bytes` and `response_bytes` for network-estimation context,
- count retries and timeouts,
- retain the final `route_id`, `peer_id`, and deterministic `envelope_hash`,
- map terminal failure to a receipt-visible failure class if execution degraded or aborted.

## Normative statements

1. If a governed run uses TriTRPC across trust or locality boundaries, the run SHOULD include transport metadata in its receipt.
2. If retries occur, retry count MUST be visible either in transport metadata or failure notes.
3. If deterministic serialization is claimed, `envelope_hash` MUST be emitted.
4. If transport contributes materially to latency or energy, those contributions MUST NOT be silently absorbed into generic “other” buckets.
5. A receipt may remain valid without transport metadata only for strictly local, non-TriTRPC execution paths.

## First integration target

The first live-path target is the GAKW hybrid warm-answer path, where TriTRPC carries the remote or hybrid leg needed for planner/runner or evidence interactions.

For that path, the minimal transport evidence is:
- `route_id`
- `peer_id`
- `envelope_hash`
- `retry_count`
- `latency_ms`
- request/response byte counts

## Acceptance gate for v0.1

A TriTRPC-integrated receipt path is acceptable for v0.1 when:
1. at least one real or captured trace includes `rpc.request.sent` and `rpc.response.received`,
2. the receipt shows a deterministic transport identity,
3. retry behavior is visible if it occurred,
4. the receipt builder can consume TriTRPC events without custom per-case hacks.

---

## SOC / Chain Profile (v0.2, additive)

A **Semantic Obfuscation Chain (SOC)** is a governed **multi-hop** RPC: a request is pulled through
a chain of trust-bound relays/enclaves, each performing one transform (schema resolution, opaque
compute, braiding). Its privacy model requires that **no single relay observes the whole path** —
yet §"Normative statements" requires that **the transport path is not invisible**. These reconcile
through **owner-sealing**: the receipt is complete *to the owner* and cloaked *to observers*.

### Chain shape
A SOC is exactly one TriTRPC **trace**. Each hop is a **span**, parent-linked to the previous hop's
span (`parent_span_id`). The ordered spans are the route. Per-hop transport additions:
- `transport.chain_id` — the SOC identity (stable across all hops).
- `transport.chain_position` — 0-based hop index.
- `transport.sealed` — MUST be `true` for a SOC hop: the hop's `transport.*` block is AEAD-sealed
  (the v1 XChaCha20-Poly1305 lane) to the OWNER, not to the relay.
- `transport.sealed_to` — the pseudonymous owner anchor the block is sealed to.

### Owner-sealed visibility rule (NORMATIVE)
1. In a SOC, each hop's `transport.*` metadata MUST be sealed to the owner (`sealed: true`). A relay
   MUST NOT be able to read the transport metadata of a hop it is not a party to.
2. `route_id` and `peer_id` MAY be pseudonymous (Identity-is-Contextual), but MUST be stable within
   the trace so the owner can reassemble the route.
3. The full ordered route MUST be reconstructable by the **owner** (whose cloud-twin holds every
   hop's sealed block) and MUST NOT be reconstructable by any single relay (each relay sees only its
   own span and its parent link).
4. A SOC receipt is **complete** (satisfies "invisible transport is incomplete") iff every hop
   carries a `sealed` transport block AND the owner can assemble the full trace. Governance sees
   everything owner-side; observers see noise.

### `failure_class` extension
SOC introduces adversarial hops, so `transport.failure_class` adds:
- `sabotage` — a relay/enclave returned a well-formed but adversarially-corrupted result (detected
  by proof mismatch); the hop is refused, not actuated.
- `refused_by_policy` — the hop was refused by the local policy gate (trust below `trust_min`, or a
  purpose/consent gate) before execution.
A `sabotage`/`refused_by_policy` hop MUST **fail closed**: the chain aborts at that span, downstream
spans MUST NOT run, and the receipt records the terminal `failure_class`.

### New event: `rpc.hop.sealed`
Emitted once per SOC hop when its transport block is sealed to the owner.
```json
{
  "event_type": "rpc.hop.sealed",
  "payload": {
    "protocol": "tritrpc",
    "chain_id": "soc://alice/fed-hr/001",
    "chain_position": 1,
    "route_id": "route://relay/opaque@v1",
    "peer_id": "node://relay-pseudo-7f",
    "envelope_hash": "sha256:...",
    "sealed": true,
    "sealed_to": "owner://anchor-alice-pseudo"
  }
}
```

### Acceptance gate for the SOC profile
A SOC path is acceptable when:
1. all hop events share one `trace_id`, and spans form a parent-linked chain;
2. every hop transport block is `sealed: true` with a `sealed_to`;
3. `route_id`/`peer_id` are stable within the trace;
4. any `sabotage`/`refused_by_policy` hop terminates the chain (no downstream spans);
5. the owner can assemble the full ordered route from the sealed blocks; no single relay can.

`tools/verify_receipt_soc_profile.py` is the self-testing gate for this profile.
