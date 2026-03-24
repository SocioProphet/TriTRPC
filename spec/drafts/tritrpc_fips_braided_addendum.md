# TriTRPC vNext Addendum: FIPS/CNSA Profile and Braided Identity Optimization

Date: 2026-03-11

## 1) Scope

This addendum tightens the previous vNext wire draft for:
- FIPS 140-3 / CMVP compatibility at the cryptographic-module boundary.
- CNSA / NSS readiness and crypto agility.
- Integration of braided naming / namespace coordinates into hot-path optimization.

This document is an engineering addendum, not a legal or accreditation opinion.

## 2) Key reality check

For civilian federal procurement, validated cryptographic modules are a core requirement signal.
For National Security Systems (NSS) and many DoD / military contexts, that is **not sufficient by itself**.

Design consequence:
- We need an **approved-mode profile** for FIPS/CMVP.
- We also need an **NSA/CNSA/NIAP/CSfC-ready deployment story**.
- We should keep a **research / non-approved profile** separate from approved mode.

## 3) Recommended crypto profiles

### 3.1 Research profile (non-approved)
Purpose: experimentation, ternary-native trials, rapid evolution.
- AEAD: XChaCha20-Poly1305 (or other research-only profile)
- PQC experiments allowed
- Not to be advertised as FIPS-approved mode

### 3.2 FIPS-approved profile
Purpose: immediate practical compliance path for commercial/government environments requiring validated modules.
- Symmetric encryption / AEAD: AES-256-GCM
- Hash / digest: SHA-384 or SHA-512
- MAC / KDF family: HMAC/HKDF or KBKDF/KDA from validated module APIs as appropriate
- Key establishment / signatures for interim classical profile:
  - ECDH P-384 / ECDSA P-384, or
  - RSA 3072 where mission constraints require it
- DRBG / entropy: only from the validated module boundary
- Approved-mode only when all invoked functions are approved/allowed for that module

### 3.3 CNSA 2.0-ready profile
Purpose: NSS / long-life / post-quantum transition readiness.
- Symmetric encryption / AEAD: AES-256-GCM
- Hash: SHA-384 or SHA-512
- Key establishment: ML-KEM-1024
- Signatures: ML-DSA-87
- Crypto agility preserved so classical CNSA 1.0 and future CNSA 2.0 can coexist during transition
- If software/firmware signing is in scope, keep room for hash-based signing families where mission guidance requires them

## 4) Transport architecture choice

Strong recommendation:
Treat TriTRPC as an **application framing layer** over approved transport security whenever possible.

Preferred order:
1. TriTRPC over TLS / DTLS / IPsec / SSH profiles that are approved for the target environment.
2. TriTRPC’s own framing handles routing, ternary packing, beacons, handles, and naming coordinates.
3. Avoid a bespoke raw-crypto session protocol on the public network unless mission constraints force it.

Reason:
This sharply reduces accreditation friction and aligns with public-standards guidance.

## 5) Mandatory protocol changes for approved mode

### 5.1 AEAD change
Replace XChaCha20-Poly1305 in approved mode with AES-256-GCM via an already validated module.

### 5.2 Mode separation
Add an explicit crypto-suite selector:
- suite=0 research-nonapproved
- suite=1 fips-classical
- suite=2 cnsa2-ready
- suite=3 reserved

This must not be user-settable without policy gating.

### 5.3 Approved-mode gate
Approved mode requires:
- approved cryptographic module
- approved/allowed algorithms only
- module self-tests complete
- no research-only algorithms invoked
- deterministic, canonical encode-before-authenticate/sign behavior

### 5.4 Nonce/IV policy
Use the validated module’s approved GCM IV construction policy.
Recommended logical interface:
nonce_context || sequence_number
with the actual IV generation delegated to or constrained by the validated module rules.

### 5.5 RNG policy
No external “helpful” RNG shortcuts in approved mode.
All SSP generation, IV/random-field generation, and key generation must come from the validated module boundary or an approved bound module configuration.

### 5.6 Canonicalization
Packing itself is not a FIPS problem.
Ambiguous decoding is.

Therefore:
- one canonical encoding for Control243 / Kind / S243 / Handle243 / Braid243
- reject non-canonical encodings
- authenticate/sign the canonical byte string only

## 6) Braided naming: registry-first, wire-second

### 6.1 Principle
Braided identity should exist as structured metadata first and a string projection second.

Canonical identity tuple:
(base_id, topic_surface, epoch, phase, state, lineage, runtime_envelope)

The hot wire should almost never carry the full canonical string.

### 6.2 Hot-wire optimization
Use negotiated handles:
- route_h = handle to (service, method, schema, context-policy, profile defaults)
- identity_h = handle to canonical braided identity
- cyclepack_h = handle to cycle dictionary version
- policy_h = handle to certificate policy / trust policy / crypto-suite policy

This lets naming improve compression rather than inflate the wire.

### 6.3 New compact coordinate byte: Braid243
A major optimization emerges from the proposed braid:
- 7 phases need only 2 trits (9 states available)
- 23 topic codes need only 3 trits (27 states available)

So phase7 × topic23 = 161 states fits inside **exactly one 5-trit byte**.

Define:

Braid243 (1 byte):
- phase_code: 0..6 used, 7..8 reserved
- topic_code: 0..22 used, 23..26 reserved

This gives:
- 161 used states
- 82 spare states (243 - 161) for escape / mixed / unknown / governance-only / future use

Recommended uses:
- scheduled focus topic in beacons
- curriculum / replay / audit routing hints
- compact policy dispatch key
- telemetry correlation without shipping the whole semantic vector

### 6.4 Keep the full vector off the hot path
The full 23-topic semantic vector belongs in:
- registries
- manifests
- telemetry payloads
- search indexes
- attestation receipts

Only the dominant topic, scheduled focus topic, or compressed braid coordinate should ride hot frames.

## 7) Where braided identity helps FIPS/CNSA work

### 7.1 Certificate policy and DN hygiene
The public guidance for CSfC key management includes requirements around:
- unique distinguished names
- appropriate key usages
- registered certificate policy OIDs

The naming registry can become the allocator for:
- stable subject namespaces
- policy OID arcs
- service identity handles
- lineage / lifecycle policy mapping

### 7.2 What should be stable vs. what should be ephemeral
Stable in PKI / long-life identifiers:
- base accession (org.system.layer.domain.object)
- trust domain
- environment / security domain where required
- certificate policy OID

Ephemeral / rapidly changing:
- epoch
- phase
- focus topic
- replay state
- provisional lineage branches

Therefore:
- stable identity goes into DN / SAN / OID-linked registry entries
- ephemeral braid coordinates go into manifests, beacons, or attested metadata, not long-lived subject names

## 8) Updated hot-frame layout (approved-friendly)

### 8.1 Core bytes
MAGIC[2] | CTRL243[1] | KIND[1] | SUITE[1]

### 8.2 Optional compact semantic bytes
epoch[S243] | route_h[Handle243] | braid[Braid243?] | state243[optional]

### 8.3 Payload and AEAD
payload_len[S243] | payload | tag[16]

Notes:
- `braid` is optional on ordinary RPC frames, expected on beacon frames.
- `state243` can encode lifecycle/epistemic compact state when needed.
- approved-mode signing/authentication always covers the canonical serialized bytes.

## 9) Revised semantic packing ideas

### 9.1 Control243 remains for ternary operational semantics
Recommended:
[profile, lane, evidence, fallback, routefmt]

### 9.2 Braid243 is separate
Do not overload Control243 with naming coordinates.
Keep naming coordinates on their own byte so:
- policy/control stays stable
- braid semantics can evolve independently
- beacons can use braid heavily without perturbing RPC semantics

### 9.3 State243 candidate
Potential packing:
- lifecycle state: 0..5 used, rest reserved
- epistemic status: hypothesis/observed/derived/verified/attested/simulated/etc.
This can be another 5-trit byte if needed, but only when its use is proven by telemetry.

## 10) Optimization priorities after the FIPS shift

Priority 1:
Move approved mode onto validated modules and approved algorithms.

Priority 2:
Stop repeating schema/context/service/method on every frame; use handles and beacons.

Priority 3:
Replace hot-path TLEB3 with S243 short lengths.

Priority 4:
Add Braid243 and registry-backed handle dictionaries.

Priority 5:
Keep research profile and approved profile both available, but with hard policy separation.

Priority 6:
Only then profile whether long-lane ternary packers (u32/u64 grouped trits) are worthwhile for throughput.

## 11) Practical language/library path

A pragmatic path is to bind TriTRPC’s approved mode to an already validated software module rather than homebrewing crypto.
Examples of active CMVP certificates as of 2026-03-11 include:
- BoringCrypto (#4735)
- AWS-LC Cryptographic Module (static) (#4816)
- OpenSSL FIPS Provider (#4985)
- BC-FJA / Bouncy Castle FIPS Java API (#4943)

This does not by itself make the overall solution NSA-approved.
It does reduce the cryptographic-module validation burden.

## 12) Decision rule

If the target is:
- research lab / prototyping -> keep research profile
- federal / civilian procurement -> make FIPS-approved profile first-class
- NSS / DoD / military / long-life classified trajectory -> design for NSA approval path, CNSA agility, NIAP/CSfC compatibility, and stable PKI/policy naming from day one

## 13) Immediate implementation backlog

1. Add `suite` field and approved/non-approved mode gates.
2. Swap approved-mode AEAD to AES-256-GCM through a validated module.
3. Add canonical encode/verify tests.
4. Add `Braid243` and registry-backed identity handles.
5. Define OID / DN allocation policy from the naming registry.
6. Split stable accession from ephemeral braid metadata.
7. Define transport binding profiles:
   - raw-research
   - tls-fips
   - ipsec-cnsa
8. Add conformance tests proving research mode cannot be mistaken for approved mode.
9. Add beacon dictionaries for route_h, identity_h, cyclepack_h, policy_h.
10. Produce new golden fixtures for approved mode and braid-enabled beacons.