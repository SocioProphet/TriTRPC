# Annex B — Path-H qutrit / hybrid control profile

Status: unified-v4-annex

# TritRPC Path-H / Hybrid Qutrit Control Mini-Spec (Draft)

## 1. Purpose

This draft defines a hybrid control profile for TritRPC, named **Path-H**, for qutrit-aware quantum/classical systems.

It does **not** attempt to serialize quantum states themselves onto the classical wire.
Instead, it defines the **classical control plane** around qutrit entanglement, heralding, teleportation outcomes, software-frame defers, memory reservation, swapping, and witness publication.

## 2. Layer split

Three layers are explicit:

1. **Qutrit wire**: the physical quantum layer (fiber / free-space / memory / detector path).
2. **Trit control wire**: the TritRPC Path-H classical wire.
3. **Atlas / registry wire**: lineage, route identity, pair logs, coherence atlas, policy, and audit metadata.

## 3. Core design rule

Path-H carries:
- pair requests
- herald success/failure
- qutrit Bell-state measurement outcomes
- correction instructions
- deferred software-frame updates
- memory hold / release
- swap outcomes
- witness / fidelity / timing reports

Path-H does **not** carry:
- the quantum state itself
- a classical encoding meant to replace a live quantum channel

## 4. Frame families

### 4.1 Hot control families
- `PAIR.OPEN`
- `PAIR.CANCEL`
- `PAIR.HERALD`
- `TELEPORT.BSM3`
- `CORRECTION.APPLY`
- `FRAME.DEFER`
- `MEMORY.HOLD`
- `MEMORY.RELEASE`
- `SWAP.RESULT`
- `WITNESS.REPORT`
- `ATLAS.PUBLISH`
- `FAULT.RAISE`
- `FAULT.CLEAR`

### 4.2 Frame classes
- unary request
- unary response
- stream open
- stream data
- stream close
- beacon capability
- beacon intent
- beacon commit
- error

## 5. Hot-path envelope

### 5.1 Fixed front matter
- `MAGIC[2]`
- `CTRL243[1]`
- `KIND243[1]`
- `epoch[S243]`
- `route_h[Handle243]`

### 5.2 Payload shell
- `payload_len[S243]`
- `payload[payload_len]`
- `tag[16]`

### 5.3 Control243 trits
Five trits packed into one byte:
- `profile`: `0=Path-A`, `1=Path-B`, `2=Path-H`
- `lane`: `0=classical`, `1=quantum`, `2=hybrid`
- `evidence`: `0=exact`, `1=sampled`, `2=verified`
- `fallback`: `0=none`, `1=classical-ok`, `2=hedged-ok`
- `routefmt`: `0=inline`, `1=handle`, `2=beacon-ref`

Path-H requires:
- `profile=2`
- `lane in {1,2}` for quantum or hybrid operations

## 6. Path-H payload atoms

### 6.1 Common scalar atoms
- `pair_id`: opaque handle or 128-bit ID
- `stream_id`: stream handle
- `mem_id`: memory-slot handle
- `site_id`: registry handle for a site or node
- `route_h`: handle for service + method + schema + context policy
- `basis_id`: small integer identifying measurement basis
- `seq`: monotone sequence number
- `ttl_ms`: time-to-live in milliseconds
- `ts_ns`: nanosecond timestamp in trusted clock domain
- `fidelity_milli`: fidelity scaled by 1000
- `visibility_milli`: visibility scaled by 1000
- `snr_milli`: signal-to-noise scaled by 1000

### 6.2 BSM3 atom
For qutrit teleportation / qutrit swapping outcomes:
- `bsm3_code`: **two trits** representing one of 9 outcomes
- legal values: `00, 01, 02, 10, 11, 12, 20, 21, 22`
- canonical numeric map: `00->0`, `01->1`, `02->2`, `10->3`, `11->4`, `12->5`, `20->6`, `21->7`, `22->8`

This field is the hot-path reason to keep a ternary-native control plane.

### 6.3 Frame-delta atom
Used for deferred correction rather than immediate physical correction:
- `frame_shift_x`: trit or small int
- `frame_shift_z`: trit or small int
- `frame_epoch`: monotone update number
- `frame_scope`: `pair`, `stream`, `memory-slot`, or `route`

For qutrit generalized Pauli-style correction tracking, represent the correction as a pair of base-3 exponents.

## 7. Event schemas

### 7.1 `PAIR.OPEN`
Request entanglement resources.

Fields:
- `seq`
- `src_site`
- `dst_site`
- `pair_kind` (`qubit`, `qutrit`, reserved higher-d)
- `encoding_kind` (`time-bin`, `frequency-bin`, `path`, `memory-backed`, `unknown`)
- `target_fidelity_milli`
- `ttl_ms`
- `need_memory` (bool)
- `need_teleport_ready` (bool)

### 7.2 `PAIR.HERALD`
Detector-confirmed pair creation.

Fields:
- `seq`
- `pair_id`
- `src_site`
- `dst_site`
- `encoding_kind`
- `herald_success` (bool)
- `ts_ns`
- `fidelity_milli`
- `visibility_milli`
- `ttl_ms`

### 7.3 `TELEPORT.BSM3`
Qutrit Bell-state measurement result.

Fields:
- `seq`
- `pair_id`
- `basis_id`
- `bsm3_code` (two trits)
- `ts_ns`
- `mem_id` (optional)
- `defer_ok` (bool)

### 7.4 `CORRECTION.APPLY`
Apply physical correction at receiver.

Fields:
- `seq`
- `pair_id`
- `bsm3_code`
- `correction_code`
- `ts_ns`

### 7.5 `FRAME.DEFER`
Do not physically apply correction; update software frame instead.

Fields:
- `seq`
- `pair_id`
- `frame_shift_x`
- `frame_shift_z`
- `frame_epoch`
- `ts_ns`

### 7.6 `MEMORY.HOLD`
Reserve a quantum memory slot.

Fields:
- `seq`
- `pair_id`
- `mem_id`
- `ttl_ms`
- `ts_ns`

### 7.7 `MEMORY.RELEASE`
Release a memory slot.

Fields:
- `seq`
- `pair_id`
- `mem_id`
- `reason_code`
- `ts_ns`

### 7.8 `SWAP.RESULT`
Publish entanglement-swapping result.

Fields:
- `seq`
- `left_pair_id`
- `right_pair_id`
- `new_pair_id`
- `bsm3_code` (for qutrit-capable swap)
- `fidelity_milli`
- `ts_ns`

### 7.9 `WITNESS.REPORT`
Publish measured quality for a link or path.

Fields:
- `seq`
- `subject_kind` (`link`, `pair`, `path`, `memory`, `swap`)
- `subject_id`
- `delay_ns`
- `fidelity_milli`
- `visibility_milli`
- `snr_milli`
- `clock_quality_code`
- `env_ref`
- `ts_ns`

## 8. Defer semantics

### 8.1 Rule
Whenever the algebra allows, Path-H should prefer `FRAME.DEFER` over immediate `CORRECTION.APPLY`.

### 8.2 Why
This turns “measurement triggers physical action” into “measurement updates classical frame state”, which reduces tight control latency and gate pressure.

### 8.3 Commit boundary
Deferred frame updates must be materialized only at a non-commuting boundary, hardware handoff, or final readout boundary.

## 9. Streaming rules

### 9.1 Stream use
Open a stream once per session / path / experiment family.

### 9.2 `STREAM.OPEN`
Carries:
- `route_h`
- `experiment_id`
- `clock_domain_id`
- `site_set`
- `policy_h`

### 9.3 `STREAM.DATA`
Carries only:
- `stream_id`
- `seq`
- `event_type_h`
- event payload bytes

### 9.4 `STREAM.CLOSE`
Carries:
- `stream_id`
- final status
- summary metrics
- optional receipt hash

## 10. State machine

### 10.1 Pair lifecycle
`OPENED -> HERALDED -> {HELD | MEASURED | SWAPPED | EXPIRED | FAILED}`

### 10.2 Teleport lifecycle
`HERALDED -> BSM3_EMITTED -> {FRAME_DEFERRED | CORRECTION_APPLIED} -> FINALIZED`

### 10.3 Memory lifecycle
`FREE -> HELD -> {RELEASED | EXPIRED | FAULTED}`

## 11. Reliability rules

- All hot events are idempotent.
- `seq` is monotone within `stream_id`.
- repeated identical `(stream_id, seq)` must be safe.
- receiver must reject non-canonical trit encodings.
- receiver must reject invalid `bsm3_code` outside the 9 legal states.

## 12. Simulation-first implementation plan

### Phase 1
- keep current TritRPC `compat-v1` untouched
- implement `Path-H` only in reference code + simulator harness
- use PennyLane `default.qutrit` and/or Qiskit `Statevector(..., dims=(3,3))`
- emulate pair creation, BSM3 outcomes, deferred frame updates, and replay logs

### Phase 2
- add `hot-v1.1` envelope improvements (`CTRL243`, `KIND243`, `S243`, `route_h`)
- generate canonical fixtures for `PAIR.OPEN`, `PAIR.HERALD`, `TELEPORT.BSM3`, `FRAME.DEFER`, `WITNESS.REPORT`

### Phase 3
- integrate with hardware adapters for:
  - photon source / detector controller
  - time service
  - memory controller
  - atlas publisher

## 13. Why Path-H instead of protobuf for the hot path

Path-H is preferable when the control plane needs:
- ternary-native hot symbols
- exact canonical fixture bytes
- replay-stable correction ledgers
- direct qutrit-shaped correction fields
- small deterministic handle-based frames

Protobuf remains acceptable for auxiliary control APIs, dashboards, and bulk analytics, but it is not ideal for the canonical hot correction lane.

## 14. Minimum viable demo

1. Simulate qutrit-pair reservation.
2. Emit `PAIR.HERALD`.
3. Emit `TELEPORT.BSM3` with one of 9 outcomes.
4. Choose `FRAME.DEFER` rather than `CORRECTION.APPLY`.
5. Emit `WITNESS.REPORT`.
6. Verify deterministic replay from fixtures.

