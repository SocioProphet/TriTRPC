# TriTRPC Obfuscation Profile v0 (optional)

The v1 AEAD lane (XChaCha20-Poly1305) protects payload **confidentiality**. It does not defeat
**traffic analysis** — packet counts, sizes, and timings still leak. The Obfuscation Manifesto's
threat model is exactly traffic analysis, so this OPTIONAL profile declares the checkable
cover-traffic parameters a SOC hop MAY apply. Declaring the profile makes the obfuscation an
auditable, fail-closed configuration rather than an ad-hoc behaviour.

## Parameters (all fail-closed)
- `kFold` (≥ 2) — K-fold anonymity: each real packet is accompanied by K−1 decoys. `K=1` provides
  zero anonymity and is **refused**.
- `decoyEntropyRatio` (0 < r ≤ 1) — how much decoys must differ from the real packet; `0` (identical
  decoys) is refused.
- `braiding.enabled` — if true, `braiding.minParticipants` ≥ 2 (a braid of one is not a braid).
- `jitterMs` (`min`, `max`) — bounded timing jitter, `1 ≤ min ≤ max` (a zero/inverted window is
  refused).
- `paddingBytes` (≥ 0) — fixed padding target to blur size.

## Relationship to the SOC profile
A SOC hop's relay contract MAY reference an obfuscation profile. The obfuscation profile shapes the
**wire behaviour** (cover traffic); the SOC profile's owner-sealed `transport{}` block still records
the **governed receipt** (so the owner audits the real path beneath the cover). Confidentiality
(AEAD) + traffic-analysis resistance (this profile) + governed visibility (owner-sealing) compose.

`tools/verify_obfuscation_profile.py` is the fail-closed gate.
