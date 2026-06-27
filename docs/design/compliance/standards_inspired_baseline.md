# Standards-Inspired Baseline for TriTRPC v0.2

## Keep

- Explicit cryptographic boundary.
- Approved-family algorithms and transports where practical.
- Strict separation between research and production/standards modes.
- Key-management planning.
- Algorithm-transition planning / crypto agility.
- Supply-chain visibility via SBOM + provenance.
- Canonical serialization + golden vectors.
- Negative tests / tamper tests.
- Hash-chained audit logs.
- Pinned operational environment.
- Fail-closed self-test behavior.
- AI-specific secure-development practices when the system is an AI/agentic system.

## Do not mimic blindly

- Procurement-only bureaucracy.
- Claiming approvals or validations not actually held.
- Freezing the design to a single algorithm family forever.
- Overfitting to one narrow operational environment when portability matters.
- Dragging long trust-plane names onto the hot wire when handles and braid bytes suffice.

## Recommended commercial stance

- Treat `research` as explicitly unsafe for production assurance claims.
- Treat `standards-inspired` as the default commercial hardening target.
- Treat `approved-like` only when an actual active validated module is bound.
- Keep `cnsa2-ready` as a crypto-agility profile, not a procurement label.
