# TriTRPC Unified Specification vNext/v4 (master draft)

Status: draft — unified integration spine (working canonical draft during the merge)

This document is the proposed single-spec integration point for the two workstreams that were intentionally separated and are now being brought back together.

It integrates:

- the upstream `docs/vnext/` design pack and normative drafts;
- the upstream experimental requirements/reference package;
- the local/downstream Path-H, qutrit-control, parity, and explanatory work.

This document is the working canonical spine during the merge. Supporting documents are annexes, evidence packs, generated vectors, white papers, and implementation packages.

---

## 1. Scope

TriTRPC Unified Specification vNext/v4 defines the next-generation TriTRPC protocol family for:

- compact authenticated hot-path transport;
- route handles and stream inheritance;
- ternary-native payload and control surfaces;
- braided semantic cadence for phase/topic/state signaling;
- standards-inspired hardening, auditability, and profile separation;
- hybrid classical/quantum control profiles.

This unified specification does **not** replace stable TriTRPC v1 interoperability. v1 remains the stable baseline. This document defines the unified vNext/v4 family.

---

## 2. Status model

Every requirement or feature in this spec MUST carry one status:

- **Stable-v1** — existing interoperable baseline behavior.
- **Unified-v4-core** — canonical vNext behavior intended for implementation.
- **Unified-v4-annex** — canonical but profile-specific or experimental.
- **Reference-only** — implemented in the experimental package, not yet required in native runtimes.
- **Informative** — explanatory or persuasive only.

---

## 3. Source precedence

When sources overlap, precedence is:

1. `spec/drafts/tritrpc_unified_v4_master_spec.md` and promoted annexes — working normative integration draft.
2. future `spec/unified/` family — normative once promoted.
3. `docs/vnext/` — informative unless explicitly promoted here.
4. `reference/experimental/` — executable reference behavior and conformance evidence.
5. white papers / reports — informative only.

---

## 4. Terminology

### 4.1 Classical trit
A classical base-3 digit with values in `{0,1,2}`.

### 4.2 Qutrit
A physical three-level quantum system. A qutrit is not a serialized trit.

### 4.3 Qutrit wire
The physical quantum channel carrying qutrit or qubit states.

### 4.4 Trit control wire
The classical TriTRPC transport carrying routing, correction, witness, reservation, and coordination traffic.

### 4.5 Atlas wire
The registry / telemetry / coherence-map publication layer.

### 4.6 Canonical encoding
A serialization rule in which the same abstract message always produces the same bytes.

### 4.7 Beacon
A lower-cadence control frame carrying shared context, dictionaries, capability claims, intent, or commit/receipt state.

---

## 5. Architecture overview

TriTRPC Unified v4 has seven major layers:

1. core framing;
2. compact hot-path primitives;
3. stream inheritance;
4. braided semantic coordinates;
5. payload/profile families;
6. crypto/compliance profiles;
7. conformance/evidence.

The protocol design law is:

- do not send meaning when coordinates suffice;
- do not resend coordinates when inheritance suffices;
- do not keep semantics on the hot path when a slower beacon cadence satisfies correctness.

---

## 6. Core hot-path primitives

### 6.1 MAGIC
`MAGIC` is fixed-width and occupies 2 bytes.

### 6.2 CTRL243
Status: **Unified-v4-core**

`CTRL243` is a single fixed one-byte control word carrying exactly 5 trits in canonical TritPack243 order.

`CTRL243 = [profile, lane, evidence, fallback, routefmt]`

Assignments:

- `profile`: `0=Path-A`, `1=Path-B`, `2=Path-H`
- `lane`: `0=classical`, `1=quantum`, `2=hybrid`
- `evidence`: `0=exact`, `1=sampled`, `2=verified`
- `fallback`: `0=none`, `1=classical-fallback-ok`, `2=hedged-ok`
- `routefmt`: `0=inline names`, `1=handle route`, `2=beacon-ref route`

### 6.3 KIND243
Status: **Unified-v4-core**

`KIND243` is a direct 1-byte frame-kind selector.

Defined values:

- `0 = unary-req`
- `1 = unary-rsp`
- `2 = stream-open`
- `3 = stream-data`
- `4 = stream-close`
- `5 = beacon-cap`
- `6 = beacon-intent`
- `7 = beacon-commit`
- `8 = error`

Values `9..242` are reserved. Values `243..255` are invalid in canonical hot frames.

### 6.4 S243
Status: **Unified-v4-core**

Short-or-extended integer coding:

- if `x <= 242`, encode as one byte `x`
- else encode byte `243` followed by canonical TLEB3 of `(x - 243)`

`S243` SHOULD replace hot-path TLEB3 use for lengths, stream IDs, epoch IDs, and handles.

### 6.5 Handle243
Status: **Unified-v4-core**

Session- or beacon-epoch-scoped direct handles:

- `0..242` = direct handle
- `243` = extended handle, followed by `S243(ext_id)`
- `244` = inline UTF-8 escape, followed by `S243(len)` and bytes
- `245` = inline 32-byte hash escape, followed by 32 bytes
- `246` = tombstone/delete
- `247..255` invalid

---

## 7. Frame families

### 7.1 Conservative v1.1-compatible hot frame
Status: **Unified-v4-annex**

`MAGIC[2] | CTRL243[1] | schema_len[S243] | schema[32] | context_len[S243] | context[32] | service_len[S243] | service | method_len[S243] | method | payload_len[S243] | payload | tag[16]`

### 7.2 Aggressive hot unary frame
Status: **Unified-v4-core**

`MAGIC[2] | CTRL243[1] | KIND243[1] | epoch[S243] | route_h[Handle243] | payload_len[S243] | payload | tag[16]`

`route_h` names the tuple `(service, method, schema, context-policy, default profile, reply semantics)`.

### 7.3 StreamHot OPEN
Status: **Unified-v4-core**

`MAGIC[2] | CTRL243[1] | KIND243=2[1] | epoch[S243] | route_h[Handle243] | stream_id[S243] | init_len[S243] | init_payload | tag[16]`

### 7.4 StreamHot DATA
Status: **Unified-v4-core**

`MAGIC[2] | CTRL243[1] | KIND243=3[1] | epoch[S243] | stream_id[S243] | chunk_len[S243] | chunk | tag[16]`

### 7.5 StreamHot CLOSE
Status: **Unified-v4-core**

`MAGIC[2] | CTRL243[1] | KIND243=4[1] | epoch[S243] | stream_id[S243] | close_len[S243] | close_payload | tag[16]`

---

## 8. Braided semantic coordinates

### 8.1 topic23
Status: **Unified-v4-core**, ownership pending final freeze

`topic23` is the 23-slot semantic registry with stable numeric slots, short codes, aliases, families, and descriptions.

### 8.2 cycle7
Status: **Unified-v4-core**, ownership pending final freeze

`cycle7` is the 7-phase registry with human labels and machine labels.

### 8.3 Braid243
Status: **Unified-v4-core**

`Braid243` is a one-byte mapping from `(phase, topic)` into the live `7 x 23 = 161` coordinate space.

### 8.4 State243
Status: **Unified-v4-core**

`State243` is a one-byte semantic state carrying five trits. Current live candidates are:

- lifecycle
- epistemic state
- novelty
- friction
- scope

### 8.5 Semantic inheritance
Status: **Unified-v4-core**

`STREAM_OPEN` MAY carry default `Braid243 + State243` semantics.
`STREAM_DATA` MAY omit semantics and inherit them, or MAY override them with an optional semantic tail.

### 8.6 Design law
Semantic detail SHOULD ride the slowest cadence that satisfies correctness and policy.

---

## 9. Beacons

### 9.1 Beacon-A / capability
Status: **Unified-v4-core**

Carries:

- handle dictionary updates
- route handle publications
- capability claims
- lane availability
- degradation hints

### 9.2 Beacon-B / intent
Status: **Unified-v4-core**

Carries:

- provisional placements
- reservation and lease intent
- quantum window claims
- contention and backpressure

### 9.3 Beacon-C / commit
Status: **Unified-v4-core**

Carries:

- completion receipts
- evidence promotions
- replay-grade references
- invalidations and tombstones

### 9.4 Typed semantic delta schema
Status: **Unified-v4-annex**

The unified spec should replace opaque beacon semantic bytes with a typed semantic delta schema.

---

## 10. Payload/profile families

### 10.1 Path-A
Status: **Stable-v1** then **Unified-v4-core** as inherited

Binary/classical payload profile.

### 10.2 Path-B
Status: **Stable-v1 / Unified-v4-annex** pending scanner hardening

Ternary-native payload profile.

### 10.3 Path-H
Status: **Unified-v4-annex**

Hybrid quantum/classical control profile.

`profile=2` means payload semantics are hybrid quantum-classical.

Lane guidance:

- `lane=0` classical — deterministic classical execution lane
- `lane=1` quantum — direct quantum/QPU-facing lane
- `lane=2` hybrid — iterative mixed loop

Evidence MUST remain independent of lane.

#### 10.3.1 Path-H event vocabulary
The canonical Path-H annex SHOULD include at minimum:

- `PAIR.OPEN`
- `PAIR.HERALD`
- `TELEPORT.BSM3`
- `CORRECTION.APPLY`
- `FRAME.DEFER`
- `MEMORY.HOLD`
- `MEMORY.RELEASE`
- `SWAP.RESULT`
- `WITNESS.REPORT`

#### 10.3.2 Path-H qutrit field guidance
The Path-H annex MAY define a compact qutrit Bell-measurement code (`bsm3_code`) as a canonical ternary-aligned field.

---

## 11. Optional 3-adic refinement lane

Status: **Unified-v4-annex**

Use only for approximation-bearing beacon or receipt data.

Suggested TLV shape:

- `type = PADIC3_DELTA`
- `scale[S243]`
- `delta_len[S243]`
- `delta_digits[ternary or word-packed ternary]`

This lane MUST NOT be used for hashes, AEAD tags, opaque binary blobs, or general strings.

---

## 12. Packing policy

### 12.1 Keep B243 for
- `CTRL243`
- short ternary fields
- handles
- tiny side channels

### 12.2 Consider word packers only for long ternary lanes
Examples:

- `Pack3x20/u32`
- `Pack3x40/u64`

These are throughput/alignment optimizations, not primary density gains.

### 12.3 Do not use ternary/p-adic packing for
- hashes
- AEAD tags
- opaque binary payloads
- general strings

---

## 13. Security and profile separation

### 13.1 Research profile
Status: **Unified-v4-core**

Research/non-approved profile.

### 13.2 FIPS-approved profile
Status: **Unified-v4-core**

Approved-mode profile using validated-module-backed approved algorithms.

### 13.3 CNSA-ready profile
Status: **Unified-v4-core**

High-assurance / transition-ready profile.

### 13.4 Suite selector
Status: **Unified-v4-core**

The unified spec MUST define an explicit suite selector:

- `suite=0 research-nonapproved`
- `suite=1 fips-classical`
- `suite=2 cnsa2-ready`
- `suite=3 reserved`

### 13.5 Approved-mode core requirements
Approved mode requires:

- approved cryptographic module
- approved/allowed algorithms only
- successful self-tests
- no research-only crypto invoked
- canonical encode-before-authenticate/sign behavior

### 13.6 Transport binding preference
Preferred deployment order:

1. TriTRPC over approved transport security (TLS / DTLS / IPsec / SSH as appropriate)
2. TriTRPC handles framing, handles, braid/state semantics, and beacons
3. avoid bespoke public-network raw crypto unless mission constraints force it

---

## 14. Braided identity and registries

### 14.1 Principle
Braided identity exists as structured metadata first and string projection second.

Canonical tuple:

`(base_id, topic_surface, epoch, phase, state, lineage, runtime_envelope)`

### 14.2 Hot-wire rule
The hot wire SHOULD almost never carry the full canonical string.

Use handles such as:

- `route_h`
- `identity_h`
- `cyclepack_h`
- `policy_h`

### 14.3 Braid/state separation
`CTRL243` MUST remain operational/control semantics.
`Braid243` MUST remain naming/semantic coordinates.
They MUST evolve independently.

---

## 15. Conformance and evidence

### 15.1 Fixture classes
The unified spec MUST define fixture classes for:

- core hot unary frames
- stream frames
- braid/state inheritance cases
- beacon-carried semantic contexts
- Path-H hybrid events
- approved/non-approved suite separation

### 15.2 Generated evidence
Generated evidence SHOULD include:

- vectors
- audit chains
- test reports
- transport comparisons
- benchmark manifests

### 15.3 Parity harnesses
Parity harnesses SHOULD exist for all native runtimes.
Path-H parity harnesses SHOULD be retained as part of the annex/conformance package.

### 15.4 Reference implementation package
The experimental requirements/reference package is the current executable evidence source and SHOULD be mapped to spec requirement IDs.

---

## 16. Migration guidance

### 16.1 v1 preservation
Stable v1 fixtures and interoperability remain unchanged.

### 16.2 v4 adoption order
1. adopt `CTRL243`, `KIND243`, `S243`, and `Handle243`
2. adopt aggressive hot unary frames
3. adopt StreamHot inheritance
4. adopt `Braid243` / `State243`
5. adopt suite separation and approved-mode profiles
6. adopt Path-H annex and hybrid events

---

## 17. Immediate patch targets

1. Port `State243` into native runtimes.
2. Add stream semantic inheritance in native `STREAM_OPEN` / `STREAM_DATA`.
3. Freeze `topic23.v1` with authoritative ownership.
4. Define typed beacon semantic deltas.
5. Benchmark three native regimes: per-frame, inherited, beaconed.
6. Promote Path-H fixtures and parity harnesses into the conformance tree.
7. Replace duplicated prose with one canonical benchmark and one canonical security/compliance story.

---

## 18. Annex map

- Annex A — migration from v1
- Annex B — Path-H qutrit/hybrid control profile
- Annex C — hybrid event vocabulary
- Annex D — beacon semantic delta schema
- Annex E — transport comparison notes
- Annex F — white-paper crosswalk
- Annex G — registry governance and ownership
- Annex H — experimental package mapping and requirement IDs

---

## 19. Editorial integration note

This document intentionally makes “ours” and “theirs” the same thing:

- upstream vNext becomes the canonical spine;
- local Path-H, parity, qutrit, and white-paper work become annexes, evidence, and companion material;
- no valid workstream is discarded;
- duplicated ideas are collapsed into one normative home.

