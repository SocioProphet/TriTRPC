# Ontology Alignment / Knowledge Induction Drive Inventory

Status: initial inventory from Drive folder  
Date: 2026-05-10  
Source folder: user-provided Google Drive folder `13JXJGt_vN8mmBQCym_XrJ10JIMuUfiHQ`  
Related specs: `spec/drafts/cskg_vnext_profile.md`, issue #67

---

## 1. Purpose

This inventory captures the Drive folder of ontology alignment, knowledge induction, common-sense graph, and grounded-reading papers as a grounding set for SocioProphet work on:

- `cskg.vnext`;
- Ontogenesis schema and memory promotion;
- TriTRPC vNext boundary-admission frames;
- FSMS memory lifecycle;
- Identity-Is-Prime non-linkage controls;
- Holmes/Sherlock common-sense and evidence retrieval;
- Minimal Universe/worldlet grounding.

The folder is not treated as a proof corpus. It is a source inventory and research grounding set. Every paper-derived claim should remain `candidate` until cited, reviewed, and admitted through the claim/evidence pipeline.

---

## 2. Inventory table

| # | File | Year / venue from title | Primary theme | Estate grounding role | Intake status |
|---:|---|---|---|---|---|
| 1 | `2018_NAACL_DeepAlignment - Unsupervised Ontology Matching With Refined Word Vectors.pdf` | 2018 NAACL | unsupervised ontology matching; refined word vectors; stable marriage alignment | lexical/embedding alignment lane for Ontogenesis and CSKG mapping | fetched/initially reviewed |
| 2 | `2018_ECML_Ontology alignment based on word embedding and random forest classification.pdf` | 2018 ECML | word embeddings + classifier-based ontology alignment | supervised/ML alignment baseline | inventory only |
| 3 | `2018_J.BiomedSemantics_Biomedical ontology alignment with representation learning.pdf` | 2018 Journal of Biomedical Semantics | biomedical ontology alignment; representation learning | biomedical/domain-specific alignment stress lane | inventory only |
| 4 | `2018_SIGMOD_Concept Linking Using NNs in Healthcare.pdf` | 2018 SIGMOD | neural concept linking in healthcare | entity/concept linking lane for Holmes/Sherlock; high-stakes domain caution | inventory only |
| 5 | `2018_05_arXiv_Ontology Alignment With Lexical Index And Embeddings.pdf` | 2018 arXiv | lexical index + embeddings for ontology alignment | hybrid lexical/vector alignment baseline | inventory only |
| 6 | `Cerdeira-Ontology Matching-2015.pdf` | 2015 | ontology matching | older baseline / comparison anchor | inventory only |
| 7 | `Grau,Horrocks-ExtractingModulesFromOntologiesLogicBased-ModularOntologies2009.pdf` | 2009 | logic-based ontology module extraction | ontology modularity / boundary extraction for Ontogenesis | inventory only |
| 8 | `paper.pdf` | paper title: *Inducing Implicit Relations from Text using Distantly Supervised Deep Nets* | Socrates; KBP; binary/unary/composite contexts; distant supervision | implicit-relation induction lane; CSKG edge-evidence and memory promotion | fetched/reviewed |
| 9 | `rki-unary-merge.pdf` | draft title: *Inducing Implicit Relations from Text using Distantly Supervised Deep Nets* | Socrates; unary relation extraction; binary+unary merge; saliency | implicit CSKG relation induction and unary/binary complementarity | fetched/reviewed |
| 10 | `rki.pdf` | title: *Deep Relational Knowledge Induction* | PermID KBP; document classification; relation induction; structured-data merger | enterprise/Watson Discovery lineage; boundary-safe KBP pipeline | fetched/reviewed |
| 11 | `RTFM-Generalizing-to-Novel-Environment-via-Reading-2.pdf` | ICLR 2020 | grounded policy learning; reading environment dynamics; txt2pi | Minimal Universe grounding: agent reads rules/dynamics and acts in worldlet | fetched/reviewed |

---

## 3. Extracted notes from reviewed papers

### 3.1 DeepAlignment

DeepAlignment treats ontology matching as representation learning rather than feature engineering. It refines pre-trained word vectors using synonymy and antonymy-style constraints, then computes entity semantic distance and uses stable marriage matching, with an extension for many-to-many alignments.

Key grounding points:

- representation learning can improve ontology alignment when lexical labels are sparse or variable;
- embedding similarity must be disciplined because similarity and association can collapse together;
- many-to-many alignment needs logical/taxonomic constraints to avoid over-linking;
- useful for `cskg.vnext` only if output mappings are treated as candidate edges requiring receipts.

Estate implications:

- `SameAs` and cross-source mapping rows in CSKG need an Identity-Prime gate, not ordinary ingestion;
- embedding-based alignments should be `derived` or `sampled`, not `verified`, until independently checked;
- many-to-many mappings require provenance, confidence, and non-linkability review.

### 3.2 Socrates / implicit relation induction papers

The Socrates papers define a KBP system that uses distant supervision from a partially populated KG and a large corpus. The important system distinction is the use of multiple context types:

- binary context sets: two entities occur in context;
- unary context sets: one entity appears, relation is reduced to a fixed-argument category;
- composite context sets: document title/metadata/header is combined with local mention context, especially for title-oriented documents.

The papers report strong practical value from combining binary and unary extraction. In the Common Crawl / DBpedia-style setting, unary and binary approaches cover different triples, and combined predictions can more than double recall at fixed precision in the reported experiment.

Key grounding points:

- many useful relations are implicit rather than sentence-local;
- context-set construction is a memory operation, not just text parsing;
- extracted triples need confidence, evidence context, and merger policy;
- structured sources and extracted text should merge through precedence/receipt rules, not simple overwrites.

Estate implications:

- `cskg.vnext` should support `EvidenceContextRecord` or `AuxRecord` for binary/unary/composite context evidence;
- FSMS `EpisodeBundle` is the right place to retain extraction traces;
- `SemanticMemoryRelease` requires a `PromotionRule` over confidence, provenance, policy, and identity-risk gates;
- implicit relations should remain `candidate` until admitted.

### 3.3 Deep Relational Knowledge Induction / RKI

The RKI paper focuses on PermID-style attribute prediction and validation using website crawls, entity recognition/linking, document classification for headquarters country, relation extraction for phone/year founded, and structured data merger.

Key grounding points:

- KBP pipelines require text collection, EDL, context extraction, relation inference, and final merger;
- phone numbers, company names, locations, websites, and years are identity/organization-adjacent fields;
- structured-data merger needs precedence and confidence logic;
- entity recognition/linking and phone/location handling are high-risk for privacy and identity linkage.

Estate implications:

- `IdentityPrimeWatcher` is mandatory for person/account/org/contact/location edges;
- `DoNotLearn` and `DoNotLink` must apply to contact/identity-bearing fields by default;
- RKI-style extraction is useful for Sherlock/Holmes, but cannot write directly to semantic memory.

### 3.4 RTFM

RTFM defines a grounded policy-learning setting where an agent must read a document describing environment dynamics, combine it with a goal and observations, and act in a world. The txt2pi model captures three-way interactions among goal, document, and observations.

Key grounding points:

- grounded agents need to read rules/dynamics, not memorize fixed environments;
- documents can act as local world laws;
- policy success depends on connecting goal, world observation, and relevant text;
- curriculum and generalization matter.

Estate implications:

- Minimal Universe/worldlet agents should use CSKG + local rule docs as boundary-admitted dynamics;
- `TriTRPC` beacons can carry context/dynamics manifests and route handles for rules;
- `BoundaryReceipt` should distinguish `observed`, `derived`, `acted`, `self-perceived`, and `admitted` states;
- Holmes/Sherlock should return worldlet dynamics as receipted context, not ungrounded prose.

---

## 4. Grounding map to current work

### 4.1 cskg.vnext

The folder supports the decision already captured in `spec/drafts/cskg_vnext_profile.md`: CSKG graph truth should remain in canonical payload records and manifests; vNext should carry handles, stream defaults, beacons, and boundary receipts.

Direct additions suggested by this inventory:

```text
EvidenceContextRecord {
  edge_id,
  context_type: binary | unary | composite | lexical_alignment | module_extraction,
  source_doc_hash,
  span_or_window_ref?,
  extracted_entities[],
  confidence,
  extractor_ref,
  policy_h,
  receipt_h
}
```

### 4.2 FSMS memory

The papers make clear that retrieval/alignment/KBP is not a single event. It is a memory pipeline:

```text
raw text / graph row
-> context set / candidate alignment
-> episode evidence
-> candidate edge
-> reviewed/admitted edge
-> semantic memory release
```

This should be encoded in FSMS as:

- `WorkingMemoryState` for active query/extraction context;
- `EpisodeBundle` for extraction/alignment traces;
- `SemanticMemoryRelease` for admitted graph/memory artifacts;
- `PromotionRule` for evidence thresholds and policy gates;
- `ForgettingPolicy` for unpromoted or sensitive traces.

### 4.3 Identity-Is-Prime

The ontology-alignment and KBP literature creates linkage risk by design:

- `SameAs`;
- entity resolution;
- company/website/contact extraction;
- location and phone extraction;
- cross-source mappings;
- semantic similarity alignments;
- hidden identity inference via context.

Identity-bearing or quasi-identifier edges must default to quarantine or `DoNotLearn + DoNotLink` until policy/proof gates pass.

### 4.4 Minimal Universe model

RTFM plus CSKG creates a model for worldlet grounding:

```text
local world observations
+ goal
+ rule/dynamics document
+ CSKG/background graph
+ boundary receipts
-> policy action
-> self-perception receipt
```

This is the reading-and-acting version of our minimal universe boundary model.

---

## 5. Work queue

1. Add `EvidenceContextRecord` to `cskg.vnext`.
2. Add fixture examples for binary/unary/composite evidence contexts.
3. Add negative fixture: implicit relation extraction involving a human/contact edge must quarantine.
4. Add `AlignmentCandidateRecord` for DeepAlignment-style ontology mappings.
5. Add `SameAs` / cross-source mapping promotion rule.
6. Add `ModuleBoundaryRecord` for ontology module extraction results.
7. Add RTFM-style `DynamicsManifest` for Minimal Universe/worldlet rules.
8. Add citations/notes from this inventory to Ontogenesis and Holmes planning issues.

---

## 6. Immediate repo alignment

This inventory should ground follow-on work in:

- `spec/drafts/cskg_vnext_profile.md`
- `spec/drafts/annex_x_boundary_admission_profile.md`
- `reference/experimental/tritrpc_requirements_impl_v4/`
- `SocioProphet/ontogenesis`
- `SocioProphet/holmes`
- `SocioProphet/sherlock-search`
- `SocioProphet/guardrail-fabric`

No imported paper should become doctrine until reviewed into an explicit claim/evidence ledger.
