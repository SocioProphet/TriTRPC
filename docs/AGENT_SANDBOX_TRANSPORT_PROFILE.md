# Agent Sandbox Transport Profile for TriTRPC (v0.1 draft)

## Status

Draft transport profile. This document is intentionally scoped to TriTRPC carriage, serialization, digest binding, fixture behavior, and verifier behavior.

Canonical lifecycle semantics live in `SocioProphet/socioprophet-standards-knowledge`:

- `docs/standards/044-agent-sandbox-lifecycle.md`
- `schemas/jsonschema/capability-fabric/agent-sandbox-lifecycle.v0.schema.json`

TriTRPC MUST NOT redefine the semantic meaning of `AgentSandboxSpec`, `AgentGenesisManifest`, `AgentFailureBundle`, or `AgentSandboxReceipt`.

## Purpose

This profile defines how agent sandbox lifecycle artifacts are carried over deterministic TriTRPC-style transport surfaces.

It covers:
- typed artifact carriage;
- canonical JSON serialization for examples and fixtures;
- digest and reference binding;
- failure-bundle transport invariants;
- deterministic verification expectations.

It does not define:
- actor trust semantics;
- controllability class semantics;
- proof-strength semantics;
- admission policy meaning;
- runtime placement policy.

Those belong to the Capability Fabric standards source.

## Transport object classes

TriTRPC MAY carry the following lifecycle object classes as typed payloads or typed attachments:

- `application/vnd.socioprophet.agent-sandbox-spec+json;v=0`
- `application/vnd.socioprophet.agent-genesis-manifest+json;v=0`
- `application/vnd.socioprophet.agent-failure-bundle+json;v=0`
- `application/vnd.socioprophet.agent-sandbox-receipt+json;v=0`

A TriTRPC frame carrying one of these objects SHOULD bind:
- object media type;
- canonical payload digest;
- semantic schema reference;
- producer identity or attestation reference;
- parent sandbox or phase reference.

## Canonical JSON profile

For JSON fixtures and transport examples, canonicalization MUST use:
- UTF-8 encoding;
- sorted object keys;
- no insignificant whitespace;
- exact string values for enum-like fields;
- SHA-256 digest over the canonical byte string.

Digest strings use:

```text
sha256:<lowercase-hex-digest>
```

## Typed blob envelope

A transport-facing lifecycle blob SHOULD use this shape:

```json
{
  "schema_version": "tritrpc-agent-sandbox-transport.v0",
  "blob_id": "blob_agent_sandbox_spec_0001",
  "media_type": "application/vnd.socioprophet.agent-sandbox-spec+json;v=0",
  "semantic_schema_ref": "capability-fabric:agent-sandbox-lifecycle.v0#/AgentSandboxSpec",
  "payload_digest": "sha256:...",
  "payload": { "...": "..." },
  "attestation_ref": "github-attestation://..."
}
```

TriTRPC implementations MAY carry `payload` inline for fixtures and small objects, or replace it with a `payload_ref` for large artifacts.

## Failure-bundle no-push invariant

A transport profile MUST preserve the failure-policy invariant from the canonical standard:

- infrastructure/model/tool failures MUST NOT be represented as write-authorized outcomes;
- `allow_partial_push` MUST be false for infrastructure failure bundles;
- `allow_push_after_infra_failure` MUST be false for infrastructure failure bundles;
- failure bundles SHOULD be sealed as artifacts or receipts, not converted into branch mutations.

This is specifically intended to prevent the observed coding-agent failure mode where a model quota error enters a commit/push path during teardown.

## Inception and genesis carriage

An inception phase SHOULD emit an `AgentSandboxSpec` typed blob.

A genesis phase SHOULD emit an `AgentGenesisManifest` typed blob.

The genesis manifest SHOULD reference:
- the exact control-plane revision;
- the target workspace revision;
- tool policy;
- egress policy;
- credential policy;
- failure policy;
- receipt policy.

TriTRPC transport fixtures SHOULD prove that these references and digests are stable under canonical serialization.

## Receipt carriage

Every phase receipt carried by TriTRPC SHOULD include:
- phase;
- outcome;
- payload digest;
- signature or attestation reference;
- parent sandbox identifier.

Receipts MAY be carried as standalone typed blobs or bundled with the corresponding object.

## Verification expectations

A TriTRPC transport verifier SHOULD check:
1. media type is recognized;
2. semantic schema reference points to the standards source;
3. canonical JSON digest matches payload;
4. failure bundles preserve no-push invariants;
5. phase receipt digest references are internally consistent;
6. protected-path or write-policy semantics are referenced, not redefined.

## Repository placement

This repository owns:
- this transport profile;
- example typed lifecycle blobs;
- transport verifier scripts;
- deterministic fixtures proving digest/reference behavior.

The standards repository owns:
- lifecycle object semantics;
- field meaning;
- controllability classes;
- proof-strength constraints;
- receipt obligations.
