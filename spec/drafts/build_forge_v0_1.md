# Build Forge Contract v0.1 — run-lifecycle slice (draft)

Status: Draft / normative seed
Package: `tritrpc.buildforge.v1`

Build Forge is a policy-bound pull-request authoring and proof system — the first
executable vertical slice of the Agentic Commons lane. It exercises the TriTRPC
substrate under real pressure: human-rooted delegation, scoped context mounts,
typed capabilities, provider adapters, proof emission, and replay/cairn closure,
with an explicit separation of **authoring** authority from **merge** authority.

This draft lands the wire contract and the enforceable core of the lifecycle. The
full contract pack (domain model, provider adapter contract, GitHub/GitLab
bindings, offline replay verifier, error taxonomy) is upstream in the Agentic
Forge intake; the beyond-slice items are tracked in the companion issue.

## What is contracted here

| Artifact | Path |
|---|---|
| Proto service + message contract | `fixtures/buildforge/build_forge_tritrpc_v0_1.proto` |
| Run-transition log schema | `schemas/jsonschema/build-forge-run-transition.v0.schema.json` |
| Reference state machine | `reference/build_forge_state_machine.py` |
| Conformance verifier (teeth) | `tools/verify_build_forge_state_machine.py` |
| Accept + reject fixtures | `fixtures/buildforge/*.json` |

The proto declares two services — `BuildForge` (CreateTask, AuthorizeTask,
MountRepoContext, OpenBranchLease, ProposePatchset, PushPatchset,
OpenChangeRequest, RequestReviewers, AttachCheck, EmitProof, CloseCairn) and the
provider-neutral `ForgeProviderAdapter` — plus the `RunState`, `ReviewState`, and
`CheckState` enumerations.

## Hard invariants (enforced by this slice)

1. A run MUST NOT escalate from authoring authority to merge authority unless a
   distinct merge grant exists (**BF-AUTH-006**).
2. Workflow-file mutation MUST be a distinct capability class from ordinary PR
   authoring (**BF-POL-001**).
3. A merge MUST fail closed unless required checks are green / gates pass
   (**BF-POL-005**).
4. Event ordering MUST conform to the state machine below; terminal states are
   absorbing (**BF-INT-004**).

## Normative state machine

Active states, in lifecycle order:
`CREATED → AUTHORIZED → MOUNTED → BRANCHED → PATCHED → PUSHED → PR_OPEN →
CHECKS_PENDING → REVIEW_PENDING → READY_TO_MERGE`.

Terminal (absorbing) states: `MERGED`, `REJECTED`, `ABORTED`, `EXPIRED`, `FAILED`.

Allowed edges:

- the linear chain above, edge by edge;
- `REVIEW_PENDING → REJECTED`;
- `READY_TO_MERGE → MERGED` — **only** with `merge_grant_present` **and**
  `policy_gates_passed` in the transition context;
- any active state → `FAILED` | `ABORTED` | `EXPIRED` (interrupt edges).

Forbidden (a sample, all refused with a machine-readable code):

- any terminal → any state (absorbing);
- `CREATED → MERGED` and every other skip of the chain;
- `READY_TO_MERGE → MERGED` without a distinct merge grant, or with red gates;
- a transition mutating workflow files under an ordinary authoring grant;
- a discontinuous log (edge *i*'s target ≠ edge *i+1*'s source).

## Teeth

`tools/verify_build_forge_state_machine.py` replays every fixture in
`fixtures/buildforge/*.json` and asserts each declared outcome — accept, or reject
with an exact `BF-*` code. Two drift guards assert the JSON Schema `run_state`
enum and the proto `RunState` enum both match the reference state set, so the
three artifacts cannot silently diverge. Wired into `make build-forge` (and the
top-level `make verify`).

Integrity: `build_forge_tritrpc_v0_1.proto` SHA-256 (FIPS 180-4)
`1e3c60f2cf7737c4146e883f9d22916cec7fbddb04ecb1999b72e9301a752472`.

## Beyond this slice

The offline replay verifier over full Cairn chains (signature verification,
artifact-hash matching, provider protection snapshots, `VERIFIED_SUCCESS` /
`TAMPER_DETECTED` verdicts), the provider adapters (`adapter-github`,
`adapter-gitlab`, `adapter-generic-git`), the webhook normalization envelope, and
the reputation-edge basis-proof rules are tracked in the companion issue.

Provenance: distilled from the Agentic Forge intake `build_forge_contract_pack_v0.1`
(2026-07-31 spec-intake corpus). MIT, consistent with this repository.
