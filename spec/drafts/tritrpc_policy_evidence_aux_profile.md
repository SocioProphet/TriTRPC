# Draft: TritRPC policy/evidence AUX profile

Status: draft, repository-local integration profile.

## Normative intent

This draft specifies how policy/evidence references are serialized into the existing TritRPC AUX field without changing the stable TritRPC v1 wire layout.

## Requirements

1. Implementations **MUST** treat the profile payload as a JSON object.
2. Implementations **MUST** canonicalize that object using RFC 8785 (JCS) before hashing, signing, or receipt verification.
3. Implementations **MUST NOT** hash or sign implementation-defined serializer output.
4. The canonical UTF-8 bytes **MUST** be placed in the AUX field as opaque bytes.
5. When AEAD is enabled, the existing AAD definition applies; therefore AUX bytes are authenticated as part of the frame.
6. Hash-typed identifiers inside the profile **SHOULD** use stable `sha256:` identifiers for long-lived semantic/governance references.
7. This profile **MUST NOT** be interpreted as the semantic policy engine; it is a carriage profile only.

## Profile object

Required top-level keys:

- `profile`
- `grant_ref`
- `policy_decision_ref`
- `runtime_evidence_refs`

Optional top-level keys:

- `attestation_bundle_ref`
- `policy_hash`
- `notes`

## Example relationship to runtime contracts

- `grant_ref` points to a grant object.
- `policy_decision_ref` points to a policy decision object.
- `runtime_evidence_refs` points to semantic proof and export-readiness evidence.
- `attestation_bundle_ref` points to a workload/runtime attestation.

## Verification gates

A repository-local shape verifier for published examples **SHOULD** ensure:

- required keys exist,
- known hash fields follow the stable `sha256:` pattern,
- canonical example JSON matches the locally expected canonical string for the example set.

This is a shape/readiness gate and does not replace full cross-language fixture verification.
