# Prophet evidence.v1 lane 1 integration scaffold

Status: integration scaffold only. Do not treat this document as final fixture acceptance.

## Purpose

This document records the first Prophet constitutional service lane proposed for TriTRPC carriage and fixture verification.

Lane: `evidence.v1`

Methods:
- `SubmitEvidence.REQ` / `SubmitEvidence.RES`
- `VerifyEvidence.REQ` / `VerifyEvidence.RES`
- `PromoteEvidence.REQ` / `PromoteEvidence.RES`

## Repository boundary

TriTRPC is the transport authority for deterministic framing, canonical bytes, AEAD/AAD boundaries, fixtures, and cross-language parity.

TriTRPC should not redefine the canonical semantics of evidence, authority, policy, promotion, or provenance. Those meanings should be imported from standards / ontology sources. This follows the existing wire-clean rule already documented for capability-fabric semantics.

## Proposed file placement

```text
spec/salad/prophet/evidence/v1/
  fair_object.avsc
  provenance_record.avsc
  authority_scope.avsc
  policy_context.avsc
  EvidenceSubmitRequest.avsc
  EvidenceSubmitResponse.avsc
  EvidenceVerifyRequest.avsc
  EvidenceVerifyResponse.avsc
  EvidencePromoteRequest.avsc
  EvidencePromoteResponse.avsc

fixtures/
  vectors_hex_prophet_lane1.txt
  vectors_hex_prophet_lane1.txt.nonces
```

## Current blocker

Before wiring generated lane-1 vectors into strict fixture verification, resolve #57.

Current `main` has a mismatch between documentation/spec posture and strict verifier behavior:

- README/spec language says stable v1 fixture verification uses XChaCha20-Poly1305 with explicit per-frame nonces.
- `tools/verify_fixtures_strict.py` currently computes BLAKE2b-MAC tags.

The lane-1 release fixture pack was generated under the documented XChaCha20-Poly1305 posture. Wiring those vectors into the current BLAKE2b verifier path would create a broken integration.

## Related issues

- #50 - add Prophet evidence.v1 lane schemas and fixture vectors
- #54 - extend strict fixture verifier and Rust/Go parity checks
- #55 - add JCS + BLAKE3 receipt vectors
- #57 - resolve AEAD verifier mismatch

## Draft PR policy

A PR carrying this document should remain draft until #57 is resolved and lane-1 vectors can be checked by the same fixture discipline as existing stable v1 vectors.
