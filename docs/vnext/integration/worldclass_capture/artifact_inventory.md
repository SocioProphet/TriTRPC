# Artifact inventory: TriTRPC

This inventory records the TriTRPC-relevant artifacts produced in the local worldclass bundles during the 2026-04-09 chat work.

## Core TriTRPC material identified for this repo

### Unified-v4 integration / narrative material
- unified integration rebase note
- current public repo reconciliation note
- topic25 vs topic26 follow-up note
- typed beacons and semaphores addendum
- full updated spec and apply playbook (for extraction of repo-specific sections)

### Codebook and kind extensions
- topic25/topic26-oriented codebook evolution notes
- KIND243 extension proposals for additional beacon / semaphore / barrier kinds

### Fixtures and sequence artifacts
- semantic beacon sequence fixture
- artifact commit boundary sequence fixture
- semaphore barrier sequence fixture

### Benchmark and harness material
- benchmark matrix
- agentic coordination scenario
- scoring rubric
- harness input and capture templates
- comparison helper

### Patch material
Local bundles organized TriTRPC patch material as:
- `repo_patchsets/TriTRPC/patches/0001-topic25-and-kind243.patch`
- `repo_patchsets/TriTRPC/patches/0002-typed-beacons-fixtures-and-harness.patch`
- `repo_patchsets/TriTRPC/patches/0003-ci-and-benchmark-capture.patch`

## Current public repo alignment

The public repo now exposes a unified-v4 integration direction. Therefore the material above should be interpreted as:

- unified-v4 extension material
- annex-grade typed semantic delta / semaphore / barrier material
- fixture and benchmark harness additions
- follow-on runtime parity work

It should **not** be treated as a detached competing spec line.

## Recommended landing strategy

1. Land integration notes and annex-grade prose first.
2. Land codebook and kind extensions second.
3. Land fixtures and benchmark harness third.
4. Land native runtime parity work after the above are reviewable.

## Preservation note

This inventory exists so the full scope of the TriTRPC-side work is explicitly referenced in GitHub even before every generated local artifact is individually imported into the repository.