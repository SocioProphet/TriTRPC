# TriTRPC Crypto Profile v0 — FIPS is the standard

Across the platform ("From Trits to Trust", the agent threat model, and the SOC owner-sealing
profile) the recurring primitive is **AEAD-sealed canonical bytes**. The v1 lane is
XChaCha20-Poly1305 — fast and safe, but **not FIPS-approved**. A `CryptoProfile` makes the cipher an
explicit, checkable, gateable choice instead of a hardcoded assumption.

- **`mode: fips`** — the AEAD MUST be a FIPS-approved authenticated cipher (AES-GCM / AES-CCM,
  SP 800-38D) and the hash MUST be FIPS-approved (SHA-2 / SHA-3, FIPS 180-4 / 202). XChaCha20 /
  ChaCha20-Poly1305 and BLAKE are **refused** in this mode.
- **`mode: standard`** — the v1 XChaCha20-Poly1305 lane is permitted.

**Non-regression:** the crypto profile selects the *sealing cipher only*. It does **not** change the
TriTRPC wire format — `TritPack243` byte canonical and `TLEB3` lengths are unchanged, so v1 / v4 /
vNext frames still parse. Hashing was already FIPS-clean (`SCHEMA_ID = SHA3(...)`,
`CONTEXT_ID = SHA3(...)`); this closes the AEAD gap. `tools/verify_crypto_profile.py` is the gate.

## v4 suite selector alignment (§13.4 / §13.5 / addendum §5.3–5.6)

The profile now carries the normative **suite selector** — `suite 0` research-nonapproved, `1`
fips-classical, `2` cnsa2-ready, `3` reserved — and gates it fail-closed:

- `mode` remains for back-compat; when `suite` is absent it is **derived** (`standard→0`, `fips→1`),
  so existing profiles keep validating. When present, `suite` must be consistent with `mode`
  (`0↔standard`, `1|2↔fips`); `suite 3` is refused.
- **suite ≥ 1 (approved)** additionally requires an `approvedMode` block asserting the §13.5/§5.3–5.6
  requirements: `encodeBeforeAuth` (authenticate the canonical bytes only), `canonicalOnly` (reject
  non-canonical encodings), a `noncePolicy` (§5.4 IV construction), `rngSource` from the validated
  module (§5.5), and `selfTests` complete (§5.3). A FIPS profile missing these is refused.
- **suite 2 (CNSA 2.0)** is stricter than FIPS-classical: **AES-256-GCM only**, **SHA-384/512 only**,
  and **ML-KEM-1024 / ML-DSA-87** when a KEM/signature is declared. A merely-FIPS profile
  (AES-128 / SHA-256) that claims `suite 2` is **refused** — closing the silent-under-assurance gap
  where a CNSA-required deployment could be handed a weaker FIPS profile.

Still additive: the profile selects the sealing suite; it does not alter the v1/v4/vNext wire.
