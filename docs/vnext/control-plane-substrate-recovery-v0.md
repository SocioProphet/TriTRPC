# TriTRPC Control-Plane Substrate Recovery v0

Status: draft recovery note  
Authority repo: `SocioProphet/TriTRPC`  
Claim level: architecture / integration planning; no normative wire-format change  
Scope: typed control-plane substrate positioning for agent, workspace, memory, and governance traffic

## Purpose

This note recovers the lost TriTRPC thread as a typed control-plane substrate candidate without changing the stable TritRPC v1 surface or promoting vNext into a normative production wire format.

The repository already has two explicit layers:

1. stable TritRPC v1 for deterministic fixtures, reference behavior, and Go/Rust parity;
2. experimental TriTRPC vNext for braided semantic cadence, compact hot-path framing, standards-inspired hardening, transport comparisons, and integration work.

This note does not add a third protocol. It records where the control-plane substrate idea fits so it does not become an unowned concept.

## Correct boundary

TriTRPC control-plane substrate work belongs in vNext/integration until it is explicitly promoted.

Stable v1 remains the deterministic interoperability surface. Nothing in this note changes v1 fixtures, encodings, AEAD behavior, ports, release workflow, or conformance guarantees.

vNext remains experimental unless a future normative promotion PR says otherwise.

## Recovered use case

The recovered use case is typed coordination traffic across:

- workspaces and workrooms;
- agent-plane action proposals, admissions, and receipts;
- memory and topic-pack events;
- governance decisions;
- model-routing or model-governance envelopes;
- cross-repo adoption and estate-ledger events;
- protocol-level receipts and deterministic replay surfaces.

This is a substrate candidate, not a product commitment.

## Candidate control-plane message families

The following message families are candidates for future typed envelopes:

| Family | Description | Likely authority |
| --- | --- | --- |
| `workspace.manifest` | Workspace manifest, lock, materialization, and drift events. | `SocioProphet/sociosphere` |
| `agent.action` | Action proposal, admission, execution, evidence, and replay events. | `SocioProphet/agentplane` |
| `memory.event` | Memory, topic-pack, non-learning, non-linkability, and representation-promotion events. | `SocioProphet/ontogenesis`; `SocioProphet/prophet-platform` |
| `governance.decision` | Policy, guardrail, admission, revocation, and review decisions. | `policy-fabric` / `guardrail-fabric` |
| `model.governance` | Model inference, training, evaluation, drift, routing, and ledger events. | `SocioProphet/model-governance-ledger`; `SocioProphet/model-router` |
| `estate.ledger` | Repo inventory, recovery disposition, adoption, validation, and drift events. | `SocioProphet/workspace-inventory`; `SocioProphet/sociosphere` |
| `receipt.trace` | Runtime, privacy, learning, execution, and protocol receipts. | producing repo, with downstream ledger projection |

A future schema pack may choose different names. These labels are planning handles only.

## Promotion discipline

No candidate control-plane family becomes normative by appearing in this note.

Promotion requires:

1. owning repo and authority surface;
2. envelope schema or IDL;
3. canonicalization rules;
4. deterministic test vectors;
5. at least one reference producer;
6. at least one reference consumer or replay verifier;
7. versioning and compatibility policy;
8. security and privacy review;
9. explicit vNext normative-promotion decision.

## Relationship to SocioProphet product systems

TriTRPC may later carry product-plane or agent-plane traffic, but this note does not require Prophet Platform, AgentPlane, Ontogenesis, Sociosphere, or model-governance systems to adopt TriTRPC immediately.

Those repos remain source authorities for their own domain events. TriTRPC provides a candidate transport/framing/canonicalization substrate, not domain ownership.

## Relationship to workspace-inventory

`SocioProphet/workspace-inventory` should identify TriTRPC as the transport-protocol authority and may later record adoption state for control-plane message families.

The estate ledger should not imply adoption until a consumer repo has explicit compatibility artifacts.

## Non-goals

This note does not:

- alter stable TritRPC v1;
- define a new wire format;
- replace the vNext unified master spec;
- create production commitments;
- define domain schemas for AgentPlane, Sociosphere, Ontogenesis, or Prophet Platform;
- assert performance, security, compliance, or interoperability beyond existing tests and reports.

## Claim boundary

This is a recovery and placement artifact. It preserves the idea that TriTRPC may serve as a typed control-plane substrate while keeping protocol authority, product authority, and domain authority separate.
