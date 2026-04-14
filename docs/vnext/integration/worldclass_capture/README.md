# Worldclass capture: TriTRPC

This branch captures the TriTRPC portion of the worldclass wire/semantic control-fabric work developed in chat on 2026-04-09.

## Purpose

This is a preservation and landing branch. It exists so the work is captured in GitHub in the correct repository with the current public repo direction taken into account.

## Current repo reality

The public repo now exposes a unified-v4 integration direction. That means the correct framing for the chat work is:

- not a detached parallel spec
- not a competing beacon model
- but a unified-v4 extension / annex / landing layer

## Core TriTRPC recommendations captured here

1. Keep Beacon-A/B/C as the native beacon family.
2. Treat typed semantic deltas as the concrete realization of the repo's own stated target.
3. Keep handle-routed inheritance and compact semantic coordinates as the hot-path rule.
4. Add semaphore and barrier coordination semantics as first-class control-plane material.
5. Revisit the topic codebook so temporal semantics and environment/boundary semantics are first-class rather than hidden.

## Source bundles produced in chat

The strongest local bundles generated during the work were:

- `worldclass_outputs_v4.zip`
- `worldclass_outputs_v5.zip`
- `worldclass_outputs_v6.zip`
- `worldclass_outputs_v7.zip`
- `worldclass_outputs_v8.zip`

The TriTRPC-specific patch material was organized under the local paths:

- `repo_patchsets/TriTRPC/patches/0001-topic25-and-kind243.patch`
- `repo_patchsets/TriTRPC/patches/0002-typed-beacons-fixtures-and-harness.patch`
- `repo_patchsets/TriTRPC/patches/0003-ci-and-benchmark-capture.patch`

## Immediate landing order

1. Reconcile any capture material against the current unified-v4 master draft.
2. Land integration notes and annex-grade prose first.
3. Land codebook / kind / fixture deltas next.
4. Only then push into native runtime parity and benchmark captures.

## Important note

This branch preserves the work and the landing plan. It does not claim that all captured ideas are already canonical or merged.