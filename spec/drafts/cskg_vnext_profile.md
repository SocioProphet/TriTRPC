# CSKG vNext Profile for TriTRPC

Status: draft — working profile for review  
Related issues: #66, #67  
Scope: Common Sense Knowledge Graph transport, canonical graph payloads, FSMS memory alignment, Identity-Is-Prime controls, and fail-closed boundary admission.

---

## 1. Purpose

`cskg.vnext` defines a registry-backed graph profile for carrying Common Sense Knowledge Graph (CSKG) operations over TriTRPC vNext.

The core decision is simple:

> TriTRPC vNext is the transport, cadence, handle, beacon, and admission plane. CSKG remains the canonical graph truth carried in payload records, manifests, and receipts.

This profile MUST NOT collapse CSKG graph semantics into hot-path braid bytes. Braid/state coordinates describe the operation posture of a frame or stream; CSKG relations, labels, sources, and sentences remain payload or manifest truth.

---

## 2. Source inputs

This draft is based on:

- `Common Sense Knowledge Graph specification.docx`
- `CSKG_into_TriTRPC_VNext_alignment_blueprint_2026-03-31.docx`
- `fsms_memory_pack.zip`
- `identity_is_prime_reference_v2_patched.zip`
- `spec/drafts/tritrpc_unified_v4_master_spec.md`
- `spec/drafts/tritrpc_vnext_mini_spec.md`
- `docs/vnext/braided_cadence_impl_v4.md`
- issue #66: fail-closed boundary watchers / Minimal Universe worldlets
- issue #67: cskg.vnext with FSMS memory and Identity-Prime controls

---

## 3. Profile defaults

Unless explicitly negotiated otherwise, `cskg.vnext` uses:

```text
profile   = Path-A
lane      = classical
routefmt  = handle
evidence  = sampled | exact | verified by admission stage
fallback  = none unless route policy explicitly permits degraded read-only behavior
```

`Path-B` ternary-native payloads are out of scope for the first profile. CSKG rows are string-heavy and provenance-heavy; forcing them into ternary-native payload encoding before native schemas and fixtures are stable is a category error.

---

## 4. CSKG canonical edge model

CSKG edge import begins from the KGTK-style edge table.

The required default quad is:

```text
(id, node1, relation, node2)
```

All four values MUST be present, non-empty, and single-valued.

The profile supports lifted and secondary columns, including labels, relation dimensions, source, and sentence fields.

### 4.1 EdgeRecord

```text
EdgeRecord {
  id: string,
  node1: string,
  relation: string,
  node2: string,
  node1_labels: string[],
  node2_labels: string[],
  relation_labels: string[],
  relation_dimensions: string[],
  sources: string[],
  sentences: string[]
}
```

### 4.2 AuxRecord

```text
AuxRecord {
  edge_id: string,
  key: string,
  value: bytes | string,
  media_type: string,
  content_hash?: bytes32
}
```

### 4.3 QuerySpec

```text
QuerySpec {
  seed_ids: string[],
  relation_filter: string[],
  dimension_filter: string[],
  source_filter: string[],
  language_scope: string[],
  limit: uint,
  cursor?: bytes | string
}
```

### 4.4 ContextManifest

```text
ContextManifest {
  profile_version: string,
  dataset_version: string,
  vocabulary_versions: map<string,string>,
  policy_epoch: uint,
  ordering_rule: string,
  schema_hash: bytes32,
  vocabulary_hash?: bytes32,
  policy_hash?: bytes32
}
```

---

## 5. Canonicalization

KGTK boundary syntax is an import/export surface, not transport truth.

Canonicalization MUST apply this sequence:

```text
parse KGTK boundary syntax
-> validate required quad
-> trim boundary whitespace
-> unescape multi-value cells
-> split list-valued cells on KGTK list delimiter at the boundary
-> reject empty elements unless the field permits empty arrays
-> deduplicate
-> sort arrays by raw UTF-8 byte order
-> encode deterministically
-> hash over canonical bytes
```

The original pipe-list order MUST NOT be treated as semantic order unless an explicit source-specific field says order is meaningful.

Decode -> encode stability is mandatory for fixtures.

---

## 6. Native service surface

Generic `hyper.v1` methods may remain as migration shims. The native profile SHOULD define typed graph methods.

| Method | Shape | Purpose | Default braid/topic |
|---|---|---|---|
| `PutEdge` | unary | Insert or upsert one canonical edge record | structure × world-model |
| `PutAux` | unary | Attach sparse auxiliary facts by edge id | structure × provenance |
| `GetEdge` | unary | Fetch one canonical edge by id | act × retrieval |
| `DeleteEdge` | unary | Tombstone or delete one edge | act × workflow |
| `ResolveSameAs` | unary | Resolve or inspect identity mappings | decide × identity |
| `ScanEdges` | stream | Filtered deterministic edge scan | act × retrieval |
| `GetSubgraphStream` | stream | Neighborhood/subgraph materialization | act × world-model |
| `BulkPutEdges` | stream | High-throughput ingest with inherited semantics | parse/open; structure/data |

---

## 7. TriTRPC frame mapping

### 7.1 Hot unary PutEdge

```text
MAGIC[2]
CTRL243[1]
KIND243 = unary-req
suite[1]
epoch[S243]
route_h[Handle243]
payload_len[S243]
payload[EdgeRecord]
tag[16]
```

The hot frame carries the route handle and canonical payload. It MUST NOT repeat route strings, schema names, long relation labels, source lists, or sentence text outside the payload.

### 7.2 Stream ingestion

`BulkPutEdges` SHOULD use `STREAM_OPEN` defaults:

```text
STREAM_OPEN:
  route_h = BulkPutEdges
  default_braid = parse × schema
  default_state = active / observed / routine / fluid / cohort
  init_payload = QuerySpec or ContextManifest reference

STREAM_DATA:
  payload = EdgeRecord or compact batch segment
  semantic tail omitted unless overriding stream default

STREAM_CLOSE:
  payload = ingest summary or digest
```

### 7.3 Beacons

`BEACON_CAP` publishes:

- route dictionaries
- schema/context manifests
- vocabulary versions
- profile capabilities
- watcher bundle handles
- policy handles
- degradation hints

`BEACON_INTENT` publishes:

- active ingest/query context
- source filters
- dimension filters
- cursor windows
- policy overlays
- stream defaults
- expected receipt class

`BEACON_COMMIT` publishes:

- BoundaryReceipt
- EdgeRecord admission receipt
- tombstones
- dataset checkpoint digest
- semantic-memory promotion receipt
- alias invalidations

---

## 8. Braid243 and State243 usage

`Braid243` MUST describe operation posture, not graph predicate identity.

`relation` and `relation_dimensions` belong in `EdgeRecord`.

Recommended mappings:

| Operation | Braid coordinate | State guidance |
|---|---|---|
| ingest row / normalize | parse × schema | active / observed / routine / fluid / local |
| materialize canonical edge | structure × world-model | active / verified / routine / fluid / cohort |
| attach provenance/aux | structure × provenance | active / observed / routine / review / cohort |
| resolve SameAs mapping | decide × identity | active / derived / review / gate / cohort |
| unary lookup | act × retrieval | active / observed / routine / fluid / local |
| streaming graph scan | act × retrieval | active / observed / routine / fluid / cohort |
| subgraph checkpoint | freeze × provenance | frozen / verified / routine / gate / global |

---

## 9. FSMS memory alignment

CSKG payloads are memory-bearing. They MUST NOT silently become durable world truth.

### 9.1 Memory objects

`WorkingMemoryState`:

- request/session context
- active query stack
- transient edge refs
- TTL-bounded

`EpisodeBundle`:

- append-only trace of ingest/query/traversal/action/validation
- includes BoundaryReceipt references

`SemanticMemoryRelease`:

- immutable promoted CSKG release or curated graph slice
- requires promotion receipt

`ProceduralMemoryBundle`:

- policy, playbook, operator, watcher, and canonicalization rules used to act

`PromotionRule`:

- describes required evidence, review, privacy, identity, and receipt gates

`ForgettingPolicy`:

- TTL, compaction, purge, archive, legal hold, and tombstone behavior

### 9.2 Promotion rule

```text
WorkingMemoryState or EpisodeBundle
  -> SemanticMemoryRelease
only if:
  SchemaWatcher passes
  CanonicalizationWatcher passes
  VocabularyWatcher passes
  SourceWatcher passes
  PrivacyWatcher passes
  IdentityPrimeWatcher passes when applicable
  MemoryWatcher authorizes semantic write
  ClaimWatcher classifies claim mode
  ReceiptWatcher emits BoundaryReceipt
```

No promotion may occur on parser success alone.

---

## 10. Identity-Is-Prime controls

Identity controls are mandatory.

### 10.1 Default policy

Rows that are identity-bearing or quasi-identifying default to:

```text
DoNotLearn = true
DoNotLink  = true
```

until explicitly reclassified by a policy-backed receipt.

### 10.2 High-risk edge classes

The following require Identity-Prime handling:

- `SameAs`
- account linkage
- person-to-handle linkage
- biometric linkage
- location-history linkage
- source-specific identity merge
- cross-dataset entity resolution
- sentence text that identifies a person or household

### 10.3 SameAs rule

`SameAs` is not an ordinary graph convenience edge. It is a proof obligation.

A SameAs edge must carry or reference:

- provenance
- capability
- evidence basis
- identity policy handle
- proof/review artifact if linking human or account identities
- BoundaryReceipt

Otherwise the edge is quarantined.

---

## 11. Gödelization alignment

Every admitted graph or memory object needs:

```text
QuotedObject              canonical payload or normalized record
CanonicalCode             hash / handle / content address
NumeralReference          stable reference inside another artifact
SubstitutionReceipt       rewrite, mapping, normalization, or merge receipt
ProofReceipt              evidence/proof/check result
AdmissionDecision         boundary decision
SemanticMemoryReceipt     promotion or tombstone record
```

CSKG edges are candidate claims until admitted. Edge existence in a source is not truth. SameAs/entity merge is not label normalization; it is a proof-bearing transformation.

---

## 12. Watcher sequence

`cskg.vnext` uses the boundary watcher sequence from Annex X.

Required order:

1. `SchemaWatcher`
2. `CanonicalizationWatcher`
3. `VocabularyWatcher`
4. `SourceWatcher`
5. `PrivacyWatcher`
6. `IdentityPrimeWatcher`
7. `MemoryWatcher`
8. `LearningWatcher`
9. `ClaimWatcher`
10. `ReceiptWatcher`

If watcher ordering cannot be established, fail closed.

If watcher decisions conflict, the most restrictive decision wins.

If a required watcher times out, deny or quarantine unless the route has an explicitly receipted degraded read-only policy.

---

## 13. Worked examples

### 13.1 Public ConceptNet-style edge

Input row:

```text
node1              /c/en/red_alert
relation           /r/IsA
node2              /c/en/alert
node1;label        red alert
node2;label        alert
relation;label     is a
relation;dimension taxonomic
source             CN
sentence           [[red alert]] is an [[alert]]
```

Canonical payload:

```json
{
  "id": "edge:cn:red_alert:is_a:alert",
  "node1": "/c/en/red_alert",
  "relation": "/r/IsA",
  "node2": "/c/en/alert",
  "node1_labels": ["red alert"],
  "node2_labels": ["alert"],
  "relation_labels": ["is a"],
  "relation_dimensions": ["taxonomic"],
  "sources": ["CN"],
  "sentences": ["[[red alert]] is an [[alert]]"]
}
```

Expected watcher result:

```text
SchemaWatcher: pass
CanonicalizationWatcher: pass
VocabularyWatcher: pass
SourceWatcher: pass
PrivacyWatcher: pass
IdentityPrimeWatcher: pass/not-applicable
MemoryWatcher: allow working/episodic write
LearningWatcher: allow only if profile policy permits public commonsense text
ClaimWatcher: candidate commonsense taxonomic claim
ReceiptWatcher: emit BoundaryReceipt
FinalDecision: admitted_candidate_edge
```

### 13.2 Human SameAs edge

Input row:

```text
node1     person:michael
relation  /r/SameAs
node2     account:github:mdheller
source    local
sentence  Michael is @mdheller.
```

Expected watcher result:

```text
SchemaWatcher: pass
CanonicalizationWatcher: pass
VocabularyWatcher: pass
SourceWatcher: review/local source
PrivacyWatcher: high-risk identity/account linkage
IdentityPrimeWatcher: quarantine pending proof/capability
MemoryWatcher: deny semantic promotion
LearningWatcher: DoNotLearn
ClaimWatcher: identity-linkage candidate, not admitted truth
ReceiptWatcher: emit quarantine receipt
FinalDecision: quarantine_identity_linkage_candidate
```

Forbidden outcomes:

- semantic memory promotion
- vectorization
- public graph export
- training/fine-tuning/eval inclusion
- cross-context merge
- direct hot-path identity label broadcast

---

## 14. Positive and negative fixture targets

Positive fixtures:

- `PutEdge` ConceptNet-style `IsA` edge succeeds.
- `PutEdge` WordNet `PartOf` edge succeeds.
- `PutAux` provenance attachment succeeds.
- `ScanEdges` with valid context handle succeeds.
- `BulkPutEdges` with stream inherited braid/state succeeds.

Negative fixtures:

- missing `id` rejects.
- missing `node1` rejects.
- missing `relation` rejects.
- missing `node2` rejects.
- unknown relation rejects or quarantines.
- malformed KGTK pipe-list rejects.
- stale context handle rejects.
- tombstoned dictionary handle rejects.
- SameAs human linkage quarantines.
- semantic promotion without PromotionRule receipt rejects.
- vectorization/training on unclassified sentence text rejects.
- watcher timeout denies/quarantines.
- receipt write failure blocks admission.

---

## 15. Non-goals

This profile does not:

- replace stable v1;
- force CSKG into Path-B payloads;
- encode relation semantics as braid coordinates;
- treat source rows as truth;
- treat SameAs/entity resolution as ordinary graph insertion;
- permit fail-open memory promotion;
- permit learning from unclassified graph text;
- claim legal, FIPS, CNSA, or evidentiary approval without the relevant external boundary.

---

## 16. Immediate implementation plan

1. Add schema definitions for `EdgeRecord`, `AuxRecord`, `QuerySpec`, and `ContextManifest`.
2. Add canonicalization helpers for KGTK boundary rows.
3. Add `cskg.vnext` route dictionary examples.
4. Add Beacon-A/B/C examples for ingest and query streams.
5. Add BoundaryReceipt examples for public edge admission and SameAs quarantine.
6. Add positive/negative golden vectors.
7. Add decode -> encode stability tests.
8. Cross-link this profile from Annex X.
