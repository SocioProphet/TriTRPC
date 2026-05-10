# Ontology Alignment / Knowledge Induction — Key Lessons Ledger

Status: v0.1 lesson synthesis  
Date: 2026-05-10  
Source: user-provided Google Drive ontology alignment / KBP / grounded reading folder  
Related: `spec/drafts/cskg_vnext_profile.md`, issues #66 and #67

---

## 1. Why this ledger exists

The inventory alone is insufficient. The value of this folder is the set of design lessons it teaches for SocioProphet: ontology alignment, common-sense graph transport, implicit relation induction, memory promotion, identity insulation, and worldlet grounding.

This ledger extracts the operational lessons from each paper and maps them into implementation consequences for TriTRPC vNext, `cskg.vnext`, FSMS memory, Identity-Is-Prime, Ontogenesis, Holmes, Sherlock, and Guardrail Fabric.

---

## 2. Cross-paper synthesis

### Lesson A — alignment is not one algorithm

The papers collectively reject a single-matcher architecture. Lexical indexes, embeddings, random forests, stable marriage, locality modules, neural translation, binary relation extraction, unary relation extraction, composite contexts, expert feedback, and grounded reading each solve different parts of the problem.

Implementation consequence:

```text
cskg.vnext must represent matcher outputs as typed candidate artifacts,
not as final graph truth.
```

Required object:

```text
AlignmentCandidateRecord {
  source_object,
  target_object,
  relation_type,
  matcher_family,
  score,
  evidence_refs[],
  constraints_checked[],
  decision_state
}
```

### Lesson B — similarity is not equivalence

Several papers make this unavoidable. Embeddings can confuse genuine similarity with association. Healthcare concept linking shows that close surface forms can be wrong and distant lexical forms can be right. Ontology alignment papers show that candidate mappings require structural and logical checks.

Implementation consequence:

```text
SameAs, equivalence, and identity merges must be proof-gated.
```

No embedding score, classifier score, or lexical overlap should directly create a durable merge.

### Lesson C — local context is the control surface

DeepAlignment uses textual descriptions. Socrates uses binary/unary/composite context sets. NCL uses textual and structural context. LexI+module partitioning uses locality modules. RTFM uses documents as local dynamics. The repeated pattern is: do not reason over the entire universe when a scoped context is sufficient.

Implementation consequence:

```text
Every retrieval, matching, extraction, or worldlet action needs a ContextManifest.
```

### Lesson D — evidence has shape, not just score

A confidence score without context is weak evidence. These papers show many evidence shapes: synonym/antonym constraints, lexical-index overlap, locality module coverage, sentence windows, unary context sets, composite TOD contexts, structural ancestor paths, saliency maps, expert feedback, and dynamics documents.

Implementation consequence:

```text
BoundaryReceipt must point to typed evidence records.
```

Required object:

```text
EvidenceContextRecord {
  edge_id?,
  candidate_id?,
  context_type,
  source_doc_hash,
  span_or_window_ref?,
  extracted_entities[],
  relation_or_alignment_hint?,
  confidence,
  extractor_ref,
  policy_h,
  receipt_h
}
```

### Lesson E — memory promotion is the real danger point

KBP systems are built to generate new triples. Ontology alignment systems are built to generate mappings. Concept linkers are built to normalize text to canonical concepts. All three can accidentally convert uncertain outputs into durable world facts.

Implementation consequence:

```text
parser success -> candidate
candidate + evidence -> reviewed claim
reviewed claim + policy -> admitted graph edge
admitted edge + promotion rule -> semantic memory release
```

No direct route from extraction to semantic memory.

### Lesson F — identity linkage is the high-risk case

The same techniques that align ontologies and populate knowledge graphs can also link people, accounts, organizations, locations, phone numbers, diseases, and behavioral traces. This is useful and dangerous.

Implementation consequence:

```text
Identity-bearing and quasi-identifier edges default to DoNotLearn + DoNotLink.
SameAs is a proof obligation.
Entity resolution is a controlled act, not a normal insert.
```

### Lesson G — worldlet intelligence requires reading the rules

RTFM adds the missing embodiment/worldlet lesson: an agent can generalize by reading local dynamics rather than memorizing a fixed environment. This is the bridge to Minimal Universe Model.

Implementation consequence:

```text
worldlet dynamics should be carried as DynamicsManifest + receipted context,
not ungrounded prompt prose.
```

---

## 3. Paper-by-paper lessons

## 3.1 DeepAlignment — unsupervised ontology matching with refined word vectors

Core lesson:

DeepAlignment shows that ontology matching improves when representation learning is task-shaped rather than generic. The paper refines pre-trained embeddings using synonymy and antonymy-style constraints and then uses semantic distance plus stable marriage matching.

What it teaches us:

1. Pre-trained embeddings are not neutral. They encode distributional association, frequency artifacts, and similarity/association collapse.
2. Alignment requires task-specific geometry. Synonym attract and antonym repel constraints reshape the vector space toward the matching task.
3. One-to-one matching is not enough. Many-to-many extension requires taxonomic/subsumption constraints to avoid false association-driven alignments.
4. Unsupervised does not mean ungated. The output is a candidate alignment, not admitted equivalence.

Implementation implication:

DeepAlignment becomes an `AlignmentCandidateRecord` generator. Its outputs should enter `cskg.vnext` with `evidence=derived`, not `verified`, until structural, source, and identity gates pass.

Hard rule:

```text
embedding-near(a,b) != SameAs(a,b)
```

---

## 3.2 ECML word embedding + random forest ontology alignment

Core lesson:

The random-forest approach treats ontology alignment as a supervised classification problem over engineered and learned features. This is the classical ML control lane: embeddings become features, not authority.

What it teaches us:

1. Feature fusion is still useful. Lexical, embedding, and structural features can be combined by an explicit classifier.
2. A classifier can make the decision boundary inspectable in a way pure embedding-nearest-neighbor cannot.
3. Supervised alignment depends heavily on benchmark and training distribution.
4. Classification output still requires provenance and negative testing.

Implementation implication:

This lane should be represented as a `MatcherRunReceipt` with model version, feature set, training corpus, threshold, and calibration metadata.

Hard rule:

```text
classifier-positive(mapping) -> candidate mapping, not committed mapping
```

---

## 3.3 Biomedical ontology alignment with representation learning

Core lesson:

Biomedical alignment needs phrase-level and ontology-aware representation learning, not just word-level similarity. The paper’s phrase retrofitting and outlier detection show that domain alignment needs both positive similarity constraints and negative/descriptive-association controls.

What it teaches us:

1. Domain terms often live at phrase level, not token level.
2. Semantic similarity and descriptive association must be separated.
3. Stable marriage helps enforce coherent pairing, but does not solve all recall/precision tradeoffs.
4. Outlier detection is a useful downstream guard for improbable mappings.

Implementation implication:

`cskg.vnext` should support `AlignmentCandidateRecord` with phrase-level evidence, ontology-specific embedding source, and an optional `OutlierAuditRecord`.

Hard rule:

```text
high biomedical/string/embedding similarity needs domain policy before promotion
```

---

## 3.4 SIGMOD healthcare concept linking — NCL / COM-AID

Core lesson:

Fine-grained concept linking is not string matching. It is closer to translation: given a concept, how likely is it to generate the noisy query? COM-AID uses both textual attention and structural ontology attention.

What it teaches us:

1. Severe word discrepancy is normal: abbreviations, clinician shorthand, synonyms, omissions, and spelling variants.
2. Fine-grained concepts overlap semantically; structural context is required to distinguish them.
3. Candidate generation plus neural re-ranking is more practical than scoring every concept.
4. Expert feedback should be triggered by uncertainty, then incorporated as a controlled training artifact.
5. Healthcare/domain concept linking is a high-stakes admission problem, not a background enrichment feature.

Implementation implication:

Holmes/Sherlock concept linking should produce:

```text
ConceptLinkCandidate {
  query,
  candidate_concept,
  p_query_given_concept,
  textual_attention_ref,
  structural_context_ref,
  uncertainty,
  feedback_required,
  receipt_h
}
```

Hard rule:

```text
uncertain concept link -> review queue, not semantic memory
```

---

## 3.5 Lexical index + neural embeddings + locality modules

Core lesson:

Large ontology matching becomes tractable when the task is broken into overlapping subtasks with measurable coverage. LexI supplies candidate overlap; locality modules supply context; clustering makes subtasks manageable.

What it teaches us:

1. Scale requires decomposition, but decomposition must preserve coverage.
2. Locality modules are not just performance tricks; they are boundary objects with coverage semantics.
3. Splitting can help systems finish large tasks, but can change precision/recall because matchers behave differently on subtasks.
4. Coverage and size ratios should be explicit ledger fields.

Implementation implication:

`cskg.vnext` needs:

```text
ModuleBoundaryRecord {
  source_signature,
  target_signature,
  module_method,
  coverage_estimate,
  size_ratio,
  subtasks[],
  matcher_policy,
  receipt_h
}
```

Hard rule:

```text
subtask decomposition without coverage receipt is not admissible as a grounding claim
```

---

## 3.6 Cerdeira ontology matching literature review

Core lesson:

The ontology matching field has many systems and techniques but fewer durable real-world applications than the volume of prototypes suggests. The practitioner survey calls out exactly the gaps our architecture must solve: complex correspondences, large-scale matching, background knowledge, matcher selection, human validation, explanation, and practical application.

What it teaches us:

1. No single matcher wins universally.
2. Evaluation is structurally underdeveloped relative to system invention.
3. Complex correspondences beyond 1:1 equivalence are a core unsolved need.
4. Explanations and human validation are not UX extras; they are part of the matching system.
5. Practical integration matters more than yet another standalone matcher.

Implementation implication:

SocioProphet should not build “one ontology matcher.” It should build a governed matching fabric with lanes, receipts, explanations, and promotion gates.

Hard rule:

```text
matcher result without explanation/evidence/provenance is not production-grade
```

---

## 3.7 Grau/Horrocks logic-based ontology module extraction

Core lesson:

Module extraction is a formal boundary problem. A useful module must preserve the consequences relevant to a signature. Minimal exact module extraction is undecidable in expressive logics, so practical systems need locality-based sufficient conditions that are safe approximations.

What it teaches us:

1. Importing the whole ontology is often too expensive and cognitively opaque.
2. Naively importing axioms mentioning the target terms can miss required dependencies.
3. Correct module extraction is about preserving observable consequences at an interface signature.
4. Exact minimality is not generally computable; safe approximations matter.
5. Locality-based modules can be small enough for real reuse while preserving needed consequences.

Implementation implication:

Ontogenesis and CSKG grounding should use module boundaries as first-class artifacts.

Required object:

```text
ModuleBoundaryRecord {
  signature,
  source_ontology,
  module_axioms_hash,
  locality_method,
  preserved_query_scope,
  nonminimality_caveat,
  receipt_h
}
```

Hard rule:

```text
ontology reuse without module boundary is uncontrolled import
```

---

## 3.8 Socrates — implicit relations from text using distantly supervised deep nets

Core lesson:

Knowledge base population needs to capture implicit relations, not only explicit sentence-local relations. Socrates introduces binary, unary, and composite context sets and merges their outputs.

What it teaches us:

1. Sentence co-occurrence is too narrow for useful KBP.
2. Unary relations convert a binary relation with a fixed argument into learnable categories.
3. Composite contexts use title/metadata/headers to recover relations that are not locally co-mentioned.
4. Binary, unary, and composite models produce complementary evidence.
5. The merger is a governed decision point.

Implementation implication:

`cskg.vnext` should add `EvidenceContextRecord` with `context_type = binary | unary | composite` and support multiple extraction lanes per candidate edge.

Hard rule:

```text
implicit relation evidence must be preserved as evidence, not hidden behind a naked triple
```

---

## 3.9 RKI / Deep Relational Knowledge Induction

Core lesson:

Enterprise KBP is a pipeline, not a model: crawl, clean, detect/link entities, classify documents, extract relation evidence, merge structured sources, and validate outputs.

What it teaches us:

1. Text collection quality controls downstream truth.
2. EDL is a prerequisite and a high-error boundary, not a footnote.
3. Contact fields, websites, phone numbers, country, and founding year are identity/organization-adjacent and require policy.
4. Structured sources should merge by precedence and confidence, not overwrite.
5. Attribute validation and attribute prediction are distinct tasks.

Implementation implication:

Sherlock/Holmes KBP lanes need `PipelineRunReceipt`, `EDLReceipt`, `StructuredSourceMergeReceipt`, and `AttributeValidationReceipt`.

Hard rule:

```text
structured source merger must be receipted and precedence-governed
```

---

## 3.10 RKI unary merge draft

Core lesson:

Unary relations are not merely a modeling trick. They are the path to recovering partial and implicit evidence at web scale.

What it teaches us:

1. Unary context sets can cover triples that binary context sets miss entirely.
2. Binary and unary extractors are complementary and should be merged, not treated as rivals.
3. Saliency maps are useful evidence diagnostics but not proof.
4. Unary relations should remain relations, not flattened types, because flattening destroys relational inference.
5. Context set construction is itself a memory operation.

Implementation implication:

FSMS should treat context sets as `EpisodeBundle` material. CSKG candidate edges induced from unary evidence need `EvidenceContextRecord` and `ClaimWatcher` classification.

Hard rule:

```text
unary-derived triple -> probabilistic candidate with context evidence, not asserted fact
```

---

## 3.11 RTFM — generalising to novel environment dynamics via reading

Core lesson:

A worldlet agent must read local dynamics and ground them in observations before acting. It cannot rely on memorized static rules.

What it teaches us:

1. Documents can be executable environment law for a bounded worldlet.
2. Generalization comes from reading and grounding, not memorizing fixed dynamics.
3. Goal, document, and observation must be jointly modeled.
4. Attention over rules should track what the agent used to decide.
5. Policy success should be evaluated in held-out dynamics, not just held-out layouts.

Implementation implication:

Minimal Universe needs:

```text
DynamicsManifest {
  rules_doc_hash,
  goal_ref,
  observation_schema,
  action_schema,
  grounding_receipts[],
  policy_receipt_h
}
```

TriTRPC Beacon-A/B/C can carry route handles, dynamics manifests, action intents, and action/self-perception commits.

Hard rule:

```text
agent action without dynamics/goal/observation grounding is not admitted worldlet cognition
```

---

## 4. Required additions to cskg.vnext

Add these records:

```text
AlignmentCandidateRecord
EvidenceContextRecord
ConceptLinkCandidate
ModuleBoundaryRecord
MatcherRunReceipt
OutlierAuditRecord
PipelineRunReceipt
EDLReceipt
StructuredSourceMergeReceipt
AttributeValidationReceipt
DynamicsManifest
FeedbackReviewRecord
```

Add these boundary decisions:

```text
admitted_candidate_edge
admitted_alignment_candidate
quarantine_identity_linkage_candidate
review_required_uncertain_link
semantic_memory_promotion_denied
semantic_memory_promotion_admitted
module_boundary_admitted
worldlet_dynamics_admitted
```

---

## 5. Immediate implementation edits

1. Extend `spec/drafts/cskg_vnext_profile.md` with:
   - `EvidenceContextRecord`
   - `AlignmentCandidateRecord`
   - `ModuleBoundaryRecord`
   - `DynamicsManifest`
2. Add negative fixtures for:
   - embedding-near SameAs human identity link;
   - unary-derived contact relation;
   - concept-link uncertainty;
   - ontology module without coverage receipt;
   - worldlet action without dynamics manifest.
3. Add positive fixtures for:
   - public ConceptNet edge;
   - non-identity WordNet PartOf edge;
   - module extraction with locality receipt;
   - RTFM-style dynamics manifest;
   - Socrates-style binary/unary/composite evidence contexts.

---

## 6. Final doctrine

The folder teaches one doctrine:

```text
Knowledge does not enter the estate as truth.
It enters as candidate structure with evidence shape, context boundary, memory state,
identity risk, and promotion policy.
```

That is the bridge from ontology matching and KBP literature into SocioProphet cybernetics.
