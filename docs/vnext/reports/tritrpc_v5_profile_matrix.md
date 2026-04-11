# TRiTRPC v5 profile matrix

| Profile | Intended use | Status | Crypto / integrity story | Canonicality story | Guarantees | Non-goals |
| --- | --- | --- | --- | --- | --- | --- |
| `compat-v1` | Stable fixture-defined interoperability | Live stable surface | Current repository-authenticated framing as published | Direct frame canonicality under stable v1 rules | canonical fixtures, cross-language parity, strict verification | not optimized hot-path framing |
| `hot-v1.1` | Compact authenticated control transport | Proposed / experimental | bounded authenticated hot frame | wire-canonical relative to fixed profile, registry snapshot, handle dictionary, and epoch | compact control words, route handles, hot-path reuse | not a universal serializer theorem |
| `path-h-research` | Simulator-first hybrid qutrit-aware control sidecar | Proposed / experimental | research profile, not normative for stable ports | same contextual canonicality model as hot-v1.1 | compact hybrid events, qutrit-aware correction semantics | not the physical quantum wire |
| `beaconed-vnext` | Cadence-shaped multi-stream control with inherited semantics | Proposed / experimental | profile-specific authenticated beacon/control framing | canonical relative to epoch, registry snapshot, inherited context | pooled cadence, rotating handles, semantic inheritance | not a formal anonymity proof |
| `fips-v1` | Bounded future compliance profile | Proposal only | must be tied to explicit provider/module/OE claim | canonicality preserved only within that bounded profile | auditable bounded claim surface | no implied broad compliance claim from cipher names alone |
