# Nonce / session derivation (vNext hot-path gap #5)

AES-GCM nonce reuse under a fixed key is catastrophic — it leaks the authentication key. For beaconed
and streamed operation the nonce MUST be unique per `(session, sequence)`. This normalizes the
derivation the frame AEAD lane already uses and adds the reuse guard, closing gap #5.

## Derivation

```
nonce = context_prefix (4 bytes) || sequence (8 bytes, big-endian)   ->  12 bytes (GCM standard)
```

This is exactly the demo frame lane (`"TRPC" || seq`) generalized to a per-session `context_prefix`.
It is the `context-sequence` value of the CryptoProfile approved-mode `noncePolicy` (FIPS SP 800-38D
IV construction).

## Fail-closed guard (`reference/nonce_derivation.py`)

- `derive_nonce(context_prefix, sequence)` — refuses a context that is not exactly 4 bytes, and a
  sequence outside `0 .. 2^64-1` (no wrap).
- `NonceLedger.issue(context_prefix, sequence)` — within a session, sequences MUST be strictly
  monotonic and never reused; a reuse or a non-increasing sequence is **refused**. The same sequence
  value under a *different* session is allowed (the context prefix separates them).

Proven by `tools/verify_nonce_derivation.py`: distinct inputs give distinct nonces; bad context /
overflow / negative sequence refused; reuse and non-monotonic issuance refused; cross-session reuse of
a sequence value allowed.

## FIPS / boundary

No primitive here (derivation + a reuse guard); the AEAD is AES-256-GCM in an approved suite. Additive
— pins how the existing 12-byte frame nonce is formed; the wire is unchanged.
