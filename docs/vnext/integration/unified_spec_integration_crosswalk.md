# TriTRPC Unified Specification Integration Crosswalk

## Purpose

This document merges the two intentionally separated workstreams into one integrated specification plan:

1. the upstream `docs/vnext/` design pack and draft normative materials; and
2. the downstream/local hot-path, Path-H, parity, white-paper, and qutrit-control work.

The goal is not to discard either stream. The goal is to define a single canonical specification stack in which:

- upstream materials become the canonical spine;
- downstream/local materials become merged annexes, profiles, and conformance artifacts;
- duplicated ideas are collapsed into one normative definition;
- all evidence and fixtures point back to one source tree.

---

## Integration rule: source precedence

### Rule 1 — one canonical spec, many layers

The unified spec should be one specification family with one canonical table of contents.
It should not remain split into “vNext docs” vs “local proposals.”

### Rule 2 — normative beats descriptive

When there is overlap:

- `spec/` text is normative.
- `docs/vnext/` is informative unless explicitly promoted.
- `reference/experimental/` is executable reference behavior, not normative prose.
- white papers are informative and persuasive, not authoritative.

### Rule 3 — keep stable v1 separate

`v1` remains the stable interoperability surface.
The unified spec described here is the canonical **vNext/v4** family.

### Rule 4 — preserve both workstreams by folding, not deleting

Where local work adds real detail beyond upstream, it should be promoted into:

- a new annex,
- a new profile,
- a new conformance package, or
- a new explanatory note.

---

## Canonical single-spec target

Recommended canonical title:

**TriTRPC Unified Specification, vNext/v4**

Near-term canonical draft path:

`spec/drafts/tritrpc_unified_v4_master_spec.md`

Promotion target once the unified family is split into stable chapters:

`spec/unified/tritrpc_unified_v4.md`

Recommended split build products:

- `spec/unified/tritrpc_unified_v4.md` — single readable master spec
- `spec/unified/chapters/` — source chapters for maintainability
- `spec/unified/annexes/` — Path-H, qutrit control, test vectors, compliance profiles
- `spec/unified/generated/` — rendered combined outputs

---

## Proposed unified table of contents

### Part I — Scope and architecture
1. Scope, terminology, and conformance language
2. Relationship to stable TriTRPC v1
3. Design goals
4. Architecture overview

### Part II — Core wire and transport
5. Core frame model
6. Control243
7. KIND243
8. S243
9. Handle243
10. Route handles and stream inheritance
11. StreamHot framing
12. Beacon framing and cadence

### Part III — Semantic coordinates
13. topic23 registry
14. cycle7 registry
15. Braid243
16. State243
17. Semantic inheritance rules
18. Beacon-carried semantic deltas

### Part IV — Profiles and payload families
19. Path-A
20. Path-B
21. Path-H (hybrid quantum/classical)
22. Optional 3-adic refinement lane
23. Packing policy for ternary lanes

### Part V — Security and compliance
24. Crypto suite separation
25. Research profile
26. FIPS-approved profile
27. CNSA-ready profile
28. Transport bindings (raw-research / TLS-FIPS / IPsec-CNSA)
29. Nonce, IV, and canonicalization policy
30. Audit chain and receipts

### Part VI — Identity and registries
31. Braided identity principle
32. Registry-first naming
33. Handle dictionaries
34. Projection rules and aliasing
35. Policy and trust handles

### Part VII — Conformance and evidence
36. Fixture classes
37. Generated vectors
38. Native parity requirements
39. Benchmark methodology
40. Assurance evidence and control crosswalks

### Annexes
A. Migration from v1
B. Path-H qutrit control annex
C. Teleportation-control event vocabulary
D. Example beacon semantic delta schema
E. Transport comparison notes
F. White-paper claims vs normative claims
G. Registry governance and ownership
H. Reference implementation package map

---

## Crosswalk: upstream spine vs local work

| Area | Upstream source | Local/downstream source | Unified disposition |
|---|---|---|---|
| vNext landing/index | `docs/vnext/README.md` | none needed | Keep as informative landing page |
| positioning | `docs/vnext/WHAT_IS_TRITRPC_VNEXT.md` | white paper framing | Merge into Part I explanatory language |
| core hot-path wire | `spec/drafts/tritrpc_vnext_mini_spec.md` | local hot-path framing notes | Promote to Part II core normative text |
| security/compliance | `spec/drafts/tritrpc_fips_braided_addendum.md` | local FIPS planning/remedies docs | Promote to Part V normative text |
| braid/state semantics | `docs/vnext/braided_cadence_impl_v4.md` + codebooks | local braided naming theory | Promote to Part III + Part VI |
| transport benchmarks | `docs/vnext/PERFORMANCE_AND_TESTING.md` + reports JSON | local white paper simulations | Keep upstream as canonical evidence summary; local data becomes Annex E/F |
| reference implementation | `reference/experimental/tritrpc_requirements_impl_v4/` | local Python encoder, parity harnesses | Merge under Part VII / Annex H |
| Path-H existence | mini-spec already reserves `profile=2` | local Path-H qutrit mini-spec | Promote local work into Annex B and later into Part IV if stabilized |
| qutrit teleportation control events | not yet upstream in detail | local Path-H fixtures/parity harnesses | Add as Annex B/C and experimental vectors |
| white paper | none upstream as canonical spec | local white paper | Keep purely informative; do not make normative |

---

## What is already integrated upstream

These ideas already exist upstream and should be treated as **canonical foundations**, not re-proposed:

1. **Five-part vNext thesis**
   - compact authenticated transport
   - route handles and stream inheritance
   - ternary-native payload and control surfaces
   - braided semantic cadence
   - standards-inspired hardening and auditability

2. **Core hot-path primitives**
   - `CTRL243`
   - `KIND243`
   - `S243`
   - `Handle243`
   - aggressive hot unary frame
   - StreamHot OPEN / DATA / CLOSE

3. **Braided semantics**
   - `topic23.proposed.v1`
   - `cycle7.proposed.v1`
   - `Braid243`
   - `State243`
   - inherited semantics via `STREAM_OPEN`
   - per-frame semantic override via optional tail

4. **Break-even logic**
   - per-frame semantics are expensive
   - stream defaults win quickly
   - shared beacons win when semantic context is reused

5. **Mode separation for compliance**
   - research / non-approved
   - FIPS-approved
   - CNSA-ready
   - explicit crypto-suite selector

---

## What local work adds and should be merged in

### 1. Path-H should become a formal annex now

Upstream already reserves `profile=2` for Path-H and defines lane semantics:

- classical
- quantum
- hybrid

Local work adds the missing concrete content:

- event vocabulary (`PAIR.OPEN`, `PAIR.HERALD`, `TELEPORT.BSM3`, `FRAME.DEFER`, `WITNESS.REPORT`, etc.)
- qutrit-aware control semantics
- simulator-first fixture set
- Go/Rust parity harnesses

**Disposition:** create **Annex B — Path-H qutrit/hybrid control profile** and mark it experimental but canonical.

### 2. Path-H fixtures should become official generated evidence

The local fixture set and parity harnesses are exactly the type of evidence the upstream reference package is already organized to emit.

**Disposition:** move them under generated evidence / conformance with clear status:

- `generated/path_h_sample_vectors_v1.json`
- `tests/path_h_parity_*`
- `reference/experimental/.../path_h/`

### 3. The white paper should become a companion, not the spec

The white paper is useful for strategy, comparison, investor/executive communication, and conceptual framing.
It should not define wire truth.

**Disposition:** keep as `docs/whitepapers/` or `reports/`, with every normative claim linked back to the unified spec.

### 4. The qutrit/networking language should be normalized

The unified spec needs a clear vocabulary split:

- **qutrit wire** = physical quantum channel
- **trit control wire** = classical TriTRPC control lane
- **atlas wire** = coherence/registry/telemetry publication layer

This is essential to prevent future confusion between serialized trits and physical qutrits.

---

## Single-spec wording changes needed immediately

### Change 1 — stop calling braid/state purely descriptive

`braided_cadence_impl_v4.md` is already executable behavior and should be elevated into the normative semantic sections.

### Change 2 — stop leaving Path-H as a placeholder

The core spec already names Path-H. A unified spec should not keep it as a conceptual stub. It should gain a defined annex with event types, fields, and conformance vectors.

### Change 3 — define typed beacon semantic deltas

Upstream still notes that `BEACON_INTENT` treats semantic payload as opaque bytes. The unified spec should add a typed semantic delta schema.

### Change 4 — make registry ownership explicit

`topic23.proposed.v1` is still proposed, not authoritative. The unified spec should define:

- who owns topic codes,
- how cycle packs are versioned,
- how deprecations happen,
- how aliasing and supersession are recorded.

### Change 5 — unify evidence language

Benchmarks, vectors, audit chains, compliance crosswalks, and parity harnesses should all be described under one conformance/evidence chapter.

---

## Immediate merge plan

### Merge Wave 1 — establish canonical spine
- Create `spec/unified/tritrpc_unified_v4.md`
- Import Part I, II, and III from upstream sources
- Add a source-precedence note at the front

### Merge Wave 2 — fold in security/compliance
- Import FIPS/CNSA addendum content into Part V
- Preserve research/fips/cnsa suite separation
- Keep crypto-suite selector normative

### Merge Wave 3 — fold in local Path-H work
- Add Annex B and Annex C
- Import Path-H event vocabulary and fixtures
- Mark as “experimental canonical annex” until native runtime support lands

### Merge Wave 4 — unify evidence
- Register local parity harnesses and fixture generators under conformance/evidence
- Add a single matrix of vectors → implementations → pass/fail expectations

### Merge Wave 5 — collapse duplicated prose
- Keep one benchmark narrative
- Keep one braid narrative
- Keep one FIPS narrative
- Keep one naming/registry narrative

---

## Proposed status model inside the unified spec

Every feature should carry a status tag:

- **Stable-v1** — existing interoperable baseline
- **Unified-v4-core** — canonical vNext behavior intended for implementation
- **Unified-v4-annex** — canonical but profile-specific or experimental
- **Reference-only** — implemented in the experimental package, not yet normative in native runtimes
- **Informative** — white paper, rationale, comparison prose

This avoids the current ambiguity between “documented,” “measured,” “reference-implemented,” and “normatively required.”

---

## Concrete disposition for major current artifacts

### Keep and elevate
- `spec/drafts/tritrpc_vnext_mini_spec.md`
- `spec/drafts/tritrpc_fips_braided_addendum.md`
- `docs/vnext/braided_cadence_impl_v4.md`
- codebooks for `topic23` and `cycle7`

### Keep as informative
- `docs/vnext/WHAT_IS_TRITRPC_VNEXT.md`
- `docs/vnext/PERFORMANCE_AND_TESTING.md`
- transport comparison reports
- local white paper

### Merge in from local work
- Path-H qutrit mini-spec
- Path-H fixtures
- Go parity harness
- Rust parity harness
- demo sequence

### Convert into normative annexes
- Path-H event vocabulary
- qutrit correction/defer semantics
- teleportation-control lifecycle
- typed beacon semantic delta schema

---

## Recommended final repository shape

```text
spec/
  unified/
    tritrpc_unified_v4.md
    chapters/
      01_scope.md
      02_core_wire.md
      03_semantic_coordinates.md
      04_profiles.md
      05_security.md
      06_identity_and_registries.md
      07_conformance.md
    annexes/
      annex_b_path_h_qutrit.md
      annex_c_hybrid_event_vocabulary.md
      annex_d_beacon_semantic_delta_schema.md
      annex_e_transport_comparison_notes.md
      annex_f_whitepaper_crosswalk.md

docs/
  vnext/
    README.md
    WHAT_IS_TRITRPC_VNEXT.md
    PERFORMANCE_AND_TESTING.md
    braided_cadence_impl_v4.md
    reports/
    generated/
    compliance/

reference/
  experimental/
    tritrpc_requirements_impl_v4/
    path_h/

conformance/
  fixtures/
  parity/
  generated/
```

---

## Integration decision log

1. We are **not** choosing upstream over local or local over upstream.
2. We are choosing a **single canonical spec spine**, and assigning every existing artifact a proper role under it.
3. Upstream vNext becomes the canonical architectural center.
4. Local Path-H/qutrit work becomes the canonical hybrid annex rather than a separate branch.
5. White papers remain persuasive companions, not normative truth.
6. Generated evidence and parity harnesses become first-class conformance material.

---

## Immediate next authoring step

The next document to write should be:

**`spec/unified/tritrpc_unified_v4.md`**

with these first imported sections:

- Scope and status model
- Core hot-path primitives (`CTRL243`, `KIND243`, `S243`, `Handle243`)
- StreamHot framing
- `Braid243` / `State243`
- crypto-suite separation
- Path-H annex placeholder with links to the local fixture set

