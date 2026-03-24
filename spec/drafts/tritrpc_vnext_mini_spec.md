# TriTRPC vNext mini-spec draft

This draft proposes a hot-path evolution for TriTRPC that preserves the ternary control story while removing most repeated byte overhead from the published fixtures.

## Current v1 facts

Current Go framing does:
- length-prefix magic
- length-prefix packed `ver`
- length-prefix packed `mode`
- length-prefix packed `flags`
- length-prefix 32-byte schema ID
- length-prefix 32-byte context ID
- length-prefix service string
- length-prefix method string
- length-prefix payload
- optional length-prefix AUX
- optional length-prefix AEAD tag

Current lengths use TLEB3 and current trit packing uses TritPack243.

## Proposed hot-path primitives

### Control243

A single fixed one-byte control word carrying exactly 5 trits in canonical TritPack243 order.

`CTRL243 = [profile, lane, evidence, fallback, routefmt]`

Trit order is most-significant first, exactly matching current TritPack243 convention:
`byte = ((((profile * 3) + lane) * 3 + evidence) * 3 + fallback) * 3 + routefmt`

Assignments:

- `profile`: `0=Path-A`, `1=Path-B`, `2=Path-H`
- `lane`: `0=classical`, `1=quantum`, `2=hybrid`
- `evidence`: `0=exact`, `1=sampled`, `2=verified`
- `fallback`: `0=none`, `1=classical-fallback-ok`, `2=hedged-ok`
- `routefmt`: `0=inline names`, `1=handle route`, `2=beacon-ref route`

### KIND243

A direct 1-byte enum, not a trit field.

- `0 = unary-req`
- `1 = unary-rsp`
- `2 = stream-open`
- `3 = stream-data`
- `4 = stream-close`
- `5 = beacon-cap`
- `6 = beacon-intent`
- `7 = beacon-commit`
- `8 = error`

Values `9..242` reserved.
Values `243..255` invalid in canonical hot frames.

### S243

Short-or-extended integer/length/handle coding:

- if `x <= 242`, encode as one byte `x`
- else encode byte `243` followed by canonical TLEB3 of `(x - 243)`

This should replace TLEB3 on the hot path for lengths, handles, stream IDs, and epoch IDs.

### Handle243

Session- or beacon-epoch-scoped direct handles.

- `0..242` = direct handle
- `243` = extended handle, followed by `S243(ext_id)`
- `244` = inline UTF-8 string escape, followed by `S243(len)` then bytes
- `245` = inline 32-byte hash escape, followed by 32 bytes
- `246` = tombstone / delete
- `247..255` invalid

## Frame layouts

### Conservative v1.1 frame

Keep the current semantic fields, but fix hot encoding.

`MAGIC[2] | CTRL243[1] | schema_len[S243] | schema[32] | context_len[S243] | context[32] | service_len[S243] | service[bytes] | method_len[S243] | method[bytes] | payload_len[S243] | payload[bytes] | tag[16]`

Notes:
- `MAGIC` is fixed-width, not length-prefixed.
- `CTRL243` replaces current `ver + mode + flags`.
- `tag` is fixed 16 bytes when AEAD is on.
- AUX remains off hot-path unless negotiated.

### Aggressive hot unary frame

`MAGIC[2] | CTRL243[1] | KIND243[1] | epoch[S243] | route_h[Handle243] | payload_len[S243] | payload[bytes] | tag[16]`

`route_h` names the tuple:
`(service, method, schema, context-policy, default profile, reply semantics)`

### StreamHot OPEN

`MAGIC[2] | CTRL243[1] | KIND243=2[1] | epoch[S243] | route_h[Handle243] | stream_id[S243] | init_len[S243] | init_payload[bytes] | tag[16]`

### StreamHot DATA

`MAGIC[2] | CTRL243[1] | KIND243=3[1] | epoch[S243] | stream_id[S243] | chunk_len[S243] | chunk[bytes] | tag[16]`

### StreamHot CLOSE

`MAGIC[2] | CTRL243[1] | KIND243=4[1] | epoch[S243] | stream_id[S243] | close_len[S243] | close_payload[bytes] | tag[16]`

## Braided A/B/C beacons

### Beacon-A (capability / dictionary / liveness)
Carries:
- handle dictionary updates
- route handle publications
- capability claims
- lane availability
- load / degradation hints

### Beacon-B (reservation / intent)
Carries:
- provisional placements
- quantum window claims
- contention and backpressure
- lease intents

### Beacon-C (commit / receipt)
Carries:
- completion receipts
- evidence grade promotions
- replay-grade references
- tombstones / dictionary invalidations

## Path-H

`profile=2` means payload semantics are hybrid quantum-classical.

Recommended interpretation:
- `lane=0 classical`: deterministic classical execution lane
- `lane=1 quantum`: direct quantum or QPU-facing lane
- `lane=2 hybrid`: iterative mixed loop

`evidence` should remain independent of `lane`.

## Optional 3-adic refinement lane

Use only for approximation-bearing beacon or receipt data.

Suggested TLV:
- `type = PADIC3_DELTA`
- `scale[S243]`
- `delta_len[S243]`
- `delta_digits[ternary or word-packed ternary]`

This is suitable for progressive refinement by congruence class and should not be used for hashes, AEAD tags, raw UTF-8, or ordinary Avro blobs.

## Packing policy

### Keep B243 for
- Control243
- short ternary fields
- handles
- tiny optional side-channels

### Consider word packers only for long ternary lanes
- `Pack3x20/u32`
- `Pack3x40/u64`

Use only when a field is large and profiling shows encode/decode throughput is a bottleneck.
These do not materially improve density over B243 on aligned long runs; they mainly improve machine alignment and throughput.

### Do not use 3-adic lanes for
- hashes
- AEAD tags
- opaque binary payloads
- general strings

## Target lengths from current fixtures

Representative current -> conservative -> aggressive targets:

- `AddVertex_a.REQ`: `148 -> 123 -> 35`
- `AddVertex_a.RSP`: `147 -> 122 -> 34`
- `AddHyperedge_e1_ab.REQ`: `161 -> 136 -> 41`
- `QueryNeighbors_a_k1.REQ`: `153 -> 128 -> 32`
- `RemoveVertex_a.REQ`: `146 -> 122 -> 31`
- `GetSubgraphStream.OPEN`: `159 -> 134 -> 45`
- `GetSubgraphStream.DATA1`: `180 -> 155 -> 65`
- `GetSubgraphStream.DATA2`: `160 -> 135 -> 45`
- `GetSubgraphStream.CLOSE`: `327 -> 302 -> 212`

Averages across the checked fixture sets:

- unary current avg: `155.29`
- unary conservative avg: `130.36`
- unary aggressive avg: `38.07`

- stream current avg: `159.22`
- stream conservative avg: `134.67`
- stream aggressive avg: `44.11`

- Path-B current avg: `163.33`
- Path-B conservative avg: `138.33`
- Path-B aggressive avg: `46.33`

## Break-even rule for beacons

Let:
- `B = beacon bytes per epoch per participant`
- `S = average bytes saved per hot frame`
- `M = hot frames per epoch`

Beaconing pays for itself when:

`M >= ceil(B / S)`

Using the measured fixture-derived unary saving `S ≈ 117.21 bytes/frame`:

- `B = 300` bytes => break-even at `3` messages
- `B = 1024` bytes => break-even at `9` messages

## Open gaps that still need code

1. Replace TLEB3 on hot path with `S243`.
2. Add `Control243` encode/decode.
3. Add route-handle dictionary negotiation.
4. Split stream OPEN/DATA/CLOSE into true hot frames that stop repeating route metadata.
5. Normalize nonce/session derivation for beaconed and streamed operation.
6. Harden Path-B decoding with a proper scanner before giving it larger wire responsibility.
