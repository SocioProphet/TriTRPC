# Current public repo reconciliation

This note records how the worldclass phase-2 material should be interpreted against the current public `TriTRPC` repository snapshot.

## Public snapshot findings

The public repository exposes a unified integration lane under `docs/vnext/integration/`, with a unified-v4 master draft acting as the working canonical spine while workstreams are reconciled.

The public materials continue to indicate that:

- Beacon-A/B/C remain the native beacon family
- typed semantic deltas are still a target that needs realization
- native Go/Rust parity for newer semantic carriage is unfinished
- authoritative codebooks still need freezing
- benchmark capture still needs native execution evidence

## Reconciliation rule

Interpret the worldclass phase-2 work as:

- unified-v4 extension material
- annex-grade typed semantic delta and semaphore/barrier semantics
- codebook evolution guidance
- fixture and benchmark harness additions

Do not interpret it as a detached competing protocol line.

## Practical consequence

The safest landing order is:

1. integration notes and annex prose
2. codebook and kind extensions
3. fixtures and benchmark harness
4. native runtime parity work
