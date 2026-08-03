# Federation Crypto Profile v0 — FIPS for the Merkle-log layer

The platform docs' P2P federation (signed append-only knowledge logs a la SSB / Hypercore-Dat /
IPFS, Merkle-DAG addressed) secures two surfaces: the **content hash** (Merkle addressing / CIDs)
and the feed **signature**. Those stacks' *defaults* are the FIPS risk, and the risk is the HASH:

- **`mode: fips`** — `contentHash` MUST be FIPS-approved (SHA-2 / SHA-3, FIPS 180-4 / 202); `signature`
  MUST be a FIPS 186-5 algorithm (ECDSA, RSA, or **EdDSA — Ed25519/Ed448, approved in FIPS 186-5**).
  **BLAKE2b (SSB/Hypercore default) and BLAKE3 (IPFS option) are refused.** IPFS CIDs must pin the
  multihash to SHA-256.
- **`mode: standard`** — BLAKE2b/BLAKE3 permitted.

**Correction vs. the naive reading:** it is common to flag "SSB uses Ed25519, so it isn't FIPS" —
but FIPS 186-5 (Feb 2023) approves EdDSA, so Ed25519/Ed448 are fine. The genuine non-FIPS primitive
in these federation stacks is the **BLAKE hash**, not the signature.

**CMVP caveat:** some FIPS-validated modules have not yet added EdDSA to their certificate; a
deployment that must run only CMVP-certified algorithms may further restrict signatures to ECDSA/RSA.
That is a deployment posture on top of 186-5, not a change to the standard.

`tools/verify_federation_crypto_profile.py` is the gate; ties the transport `CryptoProfile`.

## v4 suite selector alignment

The federation profile now carries the v4 suite selector (§13.4), mirroring the transport CryptoProfile:
`mode` stays (back-compat; `suite` derives when absent), suite↔mode consistency is enforced, `suite 3`
is reserved/refused. **suite ≥ 1** requires a FIPS hash + FIPS 186-5 signature **and** the approved-mode
assertions (sign the canonical bytes only, self-tests complete). **suite 2 (CNSA 2.0)** requires
SHA-384/512 and an **ML-DSA-87** signature — an Ed25519/ECDSA feed claiming suite 2 is refused as
under-assured, closing the federation side of the silent-under-assurance gap.
