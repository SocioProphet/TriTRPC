# TriTRPC Security Pack v2

This subtree stages the current experimental security hardening pack for TriTRPC.

It contains:
- the browser/BFF/service delegation model,
- the cryptographic profile for browser-visible capability tickets and proofs,
- the transport profile for browser HTTP versus internal QUIC/UDS lanes,
- JSON Schema and CDDL artifacts for tickets, proofs, and internal frames,
- a reference verifier implementation,
- signed example vectors,
- transport/verification tests,
- a reference CI workflow.

This pack is intentionally self-contained so it can be reviewed, evolved, or promoted into repo-root conventions later without forcing an immediate root-level layout decision.

Recommended review order:
1. `security/trirpc-capability-crypto-profile.md`
2. `security/trirpc-transport-profile.md`
3. `security/trirpc-end-to-end-example.md`
4. `security/trirpc-reference-verifier.md`
5. `schemas/`
6. `trirpc_security/`
7. `tests/`
8. `.github/workflows/bootstrap-guardrails.yml`
