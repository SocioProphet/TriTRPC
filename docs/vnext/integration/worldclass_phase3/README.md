# Worldclass phase 3 implementation slice

This branch starts the first narrow implementation slice on top of the reviewed phase-2 unified-v4 extension material.

## Scope of slice 1

This slice intentionally does **not** attempt a full runtime rewrite.
It focuses on three low-risk implementation-adjacent steps:

1. parse typed beacon refs from the reviewed fixture shapes
2. accept semaphore/barrier fixture files in reference tooling
3. bridge benchmark harness inputs into comparison-ready data structures

## Why this slice is narrow

The phase-2 work established:
- typed beacon and semaphore semantics
- fixture shapes
- codebook drafts
- benchmark scenario and templates

The safest next move is to make those artifacts executable in reference tooling before changing hot-path runtime behavior.
