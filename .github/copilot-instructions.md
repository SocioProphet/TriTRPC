# Copilot instructions for TriTRPC

TriTRPC is the transport authority for deterministic ternary-native RPC framing, fixtures, canonical byte encoding, envelope ordering, AEAD/AAD boundaries, and transport-level verifier behavior.

Do not redefine Capability Fabric semantic objects in this repository. Canonical semantics live in `SocioProphet/socioprophet-standards-knowledge`.

When working on agent sandbox lifecycle artifacts:

1. Treat this repository as the transport and fixture layer only.
2. Reference the standards objects instead of redefining them.
3. Preserve no-push failure invariants for infrastructure/model/tool failures.
4. Do not modify `.github/workflows/**`, `.github/CODEOWNERS`, or transport verifier scripts without explicit maintainer review.
5. Do not convert rate-limit, MCP, model, tool, attestation, or runner-bootstrap failures into successful writes.
6. Prefer deterministic fixtures, canonical JSON, digest binding, and cross-language verifier behavior.
7. Keep runtime implementation concerns in AgentPlane, Prophet Platform, or workspace-controller repositories rather than in TriTRPC transport docs.

For ordinary code changes, keep `make verify` passing.
