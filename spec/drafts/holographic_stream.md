# Holographic message stream (experimental draft)

**Status: Reference-only / experimental.** A way to split a message across a stream of N fragments so
each fragment alone encodes a **low-resolution copy of the whole**, while full-resolution content is
**not legible until the full stream is assembled**. Ternary/braided-friendly and a natural companion
to the SOC / Obfuscation profiles (partial capture reads as noise).

## Construction — spread-spectrum holography

1. **Delocalize.** `y = WHT(x)` — the Walsh-Hadamard transform is orthogonal and integer-exact
   (`WHT(WHT(x)) = n·x`) and maximally smears every input byte across every coefficient. The whole is
   now encoded in the whole spectrum — the holographic core.
2. **Distribute.** Fragment *i* owns the strided coefficient set `{i, i+N, i+2N, …}`. Because that set
   samples the entire spectrum, inverse-transforming **one fragment alone** (zero-filling the rest)
   reconstructs a low-resolution copy of the **whole** message (a block-averaged blur).
3. **Threshold.** Add integer keyed masks `mᵢ` that **sum to zero** over the full set. Any strict
   subset leaves a residual mask (noise); only the full set cancels (`Σmᵢ = 0`), so the coherent
   reconstruction is exact **only at full assembly**. Integer masks cancel exactly — full assembly
   recovers the message byte-for-byte, reproducibly, with no floating-point drift.

## Properties (proven by `tools/verify_holographic_stream.py`, measured over several messages)

- **Full assembly is exact** — coherent sum of all fragments == the message, byte for byte (masked and
  maskless).
- **Illegible until full** — every strict subset of masked fragments reconstructs to noise
  (legibility ≈ 0; measured `< 0.15`, actual `0.0`).
- **Low-res whole in each piece** — a single fragment's unmasked preview correlates with the whole
  message well above chance (measured `> 0.2`, actual ≈ `0.36`) yet is not legible (not exact) — a
  blurred whole.

## Scope and honest limits

- This is a **coding/holography** scheme, not encryption. The mask key yields the per-fragment low-res
  preview; **confidentiality is the CryptoProfile AEAD lane's job** — pair the two.
- The zero-sum mask gives a *coherent-gain* "all-or-nothing" for the full-resolution layer, not a
  cryptographic k-of-n threshold. For **any-k-reconstruct / fewer-reveal-nothing**, use **Shamir
  secret sharing / a ramp scheme** instead (which sacrifices the low-res preview). Different knobs.

## Placement in TriTRPC

The message **sequence** is the carrier: each frame carries one fragment in an AUX / Beacon lane, so
the stream's frames *are* the hologram. It composes with the SOC K-fold decoys (decoys can carry mask
chips) and the braided coordinates (the stride is a braid), and its "partial capture = noise" property
is a natural anti-surveillance complement to the Obfuscation Manifesto.
