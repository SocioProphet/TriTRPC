# TRiTRPC v5 benchmark and ablation plan

## Purpose

This document turns the white-paper benchmark into a reproducible next-pass experiment plan. It separates serializer comparison from framed transport comparison and identifies the ablations needed to answer the strongest red-team questions.

## Benchmark families

### A. Five-event hot-path family

- `PAIR.OPEN`
- `PAIR.HERALD`
- `TELEPORT.BSM3`
- `FRAME.DEFER`
- `WITNESS.REPORT`

### B. Route-reuse sweep

Vary:
- route-handle reuse ratio
- inline route vs handle route
- handle lifetime and invalidation frequency

### C. Stream-inheritance sweep

Vary:
- number of `STREAM_DATA` frames per `STREAM_OPEN`
- per-frame semantic override rate
- beacon-carried vs inherited defaults

### D. Payload-shape sweep

Vary:
- opaque byte payload size
- percentage of ternary / low-cardinality fields
- percentage of repeated semantic coordinates

## Required ablations

1. **Control-word ablation**
2. **Route-handle ablation**
3. **Stream-inheritance ablation**
4. **Ternary-payload ablation**
5. **Authentication-placement ablation**

## Fairness rules

- Publish the exact competitor schemas and encoder code.
- Label payload-only comparisons as serializer comparisons.
- Label full-frame comparisons as framed-transport comparisons.
- Treat gRPC numbers as lower bounds unless full HTTP/2 framing, headers, and trailers are modeled.
- Keep Path-H claims narrow: strongest on route-repetitive, low-cardinality control workloads; weak on large opaque blobs.

## Outputs required

- machine-readable CSV of every run
- plots by payload size
- plots by route-reuse rate
- plots by stream length
- plots by ternary-field share
- written interpretation of where the advantage appears and disappears
