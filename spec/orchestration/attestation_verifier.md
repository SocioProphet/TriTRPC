# tee/zk Attestation Verifier (decidable checks + honest abstention)

The ProofEnvelope (#90) routes a `tee`/`zk` proof to a named verifier. This spec pins what that
verifier does in software — and, crucially, what it refuses to pretend to do.

## What it decides (fail-closed)

- **tee**: the quote's `report_data` MUST equal `SHA-256(nonce || result_cid)` — the binding that
  ties the quote to **this** result. Wrong/absent ⇒ **reject**. The `measurement` (MRENCLAVE) must be
  in the allow-list; the `nonce` must be fresh (anti-replay).
- **zk**: the `publicInputs` MUST include the `result_cid` and `SHA-256(statement)` — the binding to
  this result/statement; the `scheme` must be supported.

## What it refuses to fake

If every decidable check passes, the verdict is **`refer`**, not `accept`: the hardware/cryptographic
root — the Intel DCAP quote **signature**, the zk **pairing** check — needs collateral / a verifying
key this layer does not have, so it is **delegated** to the named root verifier (`dcap-quote-verifier`
/ `zk-<scheme>-vk-verifier`). A bare `accept` is **never** emitted for tee/zk. The verdict enum is
`{reject, refer}` by construction — abstain, don't rubber-stamp (descend-abstain = gate).

This catches exactly the attacks a coordinator *can* catch deterministically — an unbound quote, a
replayed nonce, the wrong enclave, wrong public inputs — and hands the rest to the root verifier with
an explicit, auditable `referTo`.

## FIPS / boundary

The result-binding is SHA-256 (FIPS 180-4). The delegated quote-signature / zk-pairing check is the
root verifier's job (out of scope). Does not touch the tritrpc v4/vNext wire format.
