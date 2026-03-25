# Upstream Patch Plan for TriTRPC

This plan maps the reference implementation to the likely upstream repository surfaces.

## Target patch set

### 1) `go/tritrpcv1/envelope.go`

Change:

- remove separate hot-path length-prefixed `ver`, `mode`, and `flags` fields from the canonical vNext profile;
- add fixed-width `CTRL243[1]`, `KIND[1]`, `SUITE[1]`;
- fix `MAGIC` at 2 bytes;
- fix `tag` at 16 bytes in approved/research hot profiles.

Why:

This is the highest-value immediate byte reduction and the cleanest place to enforce canonical framing.

### 2) `go/tritrpcv1/tleb3.go`

Change:

- keep `TLEB3` as a cold-path primitive;
- add `S243` as the hot-path short-length codec;
- reject non-canonical `S243` / `TLEB3` decodings.

Why:

TLEB3 remains useful as a ternary length primitive, but it is the wrong hot-path codec for short byte lengths.

### 3) Add `control243.go`, `handle243.go`, `braid243.go`

Add:

- `Control243` encoder/decoder
- `Handle243` encoder/decoder
- `Braid243` encoder/decoder

Why:

These are the core vNext hot primitives.

### 4) Add `suite.go`

Add:

- explicit suite enum
- hard gate between `research-nonapproved`, `fips-classical`, and `cnsa2-ready`

Why:

The repo should make it impossible for research mode to be logged or described as approved mode.

### 5) Add `streamhot.go`

Change:

- split `OPEN`, `DATA`, and `CLOSE` into true hot stream frame forms;
- stop repeating full route metadata on `DATA`.

Why:

This is the single biggest stream optimization.

### 6) Add `beacon.go`

Add:

- `BEACON_CAP`, `BEACON_INTENT`, `BEACON_COMMIT`
- route and identity dictionary publication
- compact semantic routing via `Braid243`

Why:

This is the control-plane compression layer that amortizes route/identity overhead.

### 7) `go/tritrpcv1/pathb_dec.go`

Change:

- replace the toy scanner with a production scanner before expanding Path-B’s hot-path role.

Why:

Path-B should not be promoted before the parser is hardened.

### 8) `fixtures/`

Add:

- vNext hot unary fixtures
- vNext stream fixtures
- vNext beacon fixtures
- approved/non-approved profile separation in fixture names and manifests

Why:

Golden vectors are needed for cross-language lockstep.

### 9) `docs/`

Add:

- FIPS/CNSA profile note
- registry-first braided identity note
- migration guide from v1 to vNext

## Runtime binding reminder

The reference package implements the framing and policy gates.
It does **not** satisfy the validated crypto boundary requirement.
The language runtime still needs to bind approved mode to a selected validated module.
