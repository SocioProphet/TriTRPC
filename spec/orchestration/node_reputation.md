# Node Reputation & Admission (mesh trust gate)

The Mesh Coordinator (`spec/orchestration/mesh_work_unit.md`) refuses any result from a node not in
its `trusted` set. **This spec decides who gets INTO that set.** It is the admission gate for the
federated volunteer mesh — anonymous but transparent: a pseudonymous `node_ref` carries reputation
without identity.

## Reputation (`schemas/jsonschema/node-reputation.v0.schema.json`)

- **Trust** — the Trust Equation dimensions: `credibility`, `reliability`, `intimacy`, and
  `selfOrientation` (the denominator — high self-orientation *lowers* trust). Each in `[0,1]`.
- **Energy spectrum** — `knowledge`, `creativity`, `civility` (each `[0,1]`). `civility` is a hard
  abuse floor at admission.
- **History** — `observations` (settled/verified interactions backing the scores) and a
  `decayHalfLifeDays` for time-decay. Optional anonymized `sentiment`.
- `attestationRef` + `region` travel with the reputation so an admitted node is immediately a
  coordinator-ready trusted-node record.

## Trust score (bounded rendering of `T=(C+R+I)/S`)

```
trust = mean(credibility, reliability, intimacy) * (1 - selfOrientation)   # in [0,1]
```

Monotone: raising any of C/R/I — or lowering self-orientation — never lowers trust. A bounded form is
used so scores compose and threshold cleanly; the ranking is the classic Trust Equation's.

## Admission (`schemas/jsonschema/admission-policy.v0.schema.json`) — fail-closed

`reference/node_admission.py:admit(rep, policy)` admits a node **only if every gate passes**:

1. attestation present (when `requireAttestation`);
2. `observations >= minObservations` (statistical-significance floor — estate default **>= 30**);
3. `selfOrientation <= maxSelfOrientation`;
4. `civility >= minCivility` (abuse guard — a low-civility node is refused **regardless** of trust);
5. `trust >= minTrust`.

Any failure ⇒ `admitted:false` with the failing reasons; only a fully-passing node yields a
`trustedNode` record `{node_ref, attestationRef, region}` — **exactly** the shape
`reference/mesh_coordinator.py` consumes. The verifier proves the loop: an admitted node's record
plugs into the coordinator and its WU result settles.

## FIPS / boundary

No cryptographic primitive is used here (pure scoring). Attestation **verification** is delegated to
the attestation lane; this gate only requires an `attestationRef` be present when the policy demands
it. Does not touch the tritrpc v4/vNext wire format.
