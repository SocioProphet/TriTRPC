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
