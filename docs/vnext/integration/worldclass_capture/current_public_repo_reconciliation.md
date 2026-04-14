# Current public repo reconciliation summary

This note records how the worldclass chat work should be interpreted against the current public `TriTRPC` repository snapshot.

## Public snapshot findings

The public repository now exposes a unified integration lane under `docs/vnext/integration/`, with a unified-v4 master draft acting as the working canonical spine while the workstreams are reconciled.

The public materials also continue to state that:

- Beacon-A/B/C remain the native beacon family
- typed semantic deltas are still a target that needs to be realized
- native Go/Rust parity for newer semantic carriage is still unfinished
- authoritative codebooks still need freezing
- benchmark capture still needs native execution evidence

## Reconciliation rule

Interpret the captured worldclass work as:

- unified-v4 extension material
- annex-grade typed semantic delta and semaphore/barrier semantics
- codebook evolution guidance
- benchmark and fixture scaffolding

Do **not** interpret it as a detached competing protocol line.

## Practical consequence

The safest landing order is:

1. integration notes and annex prose
2. codebook and kind extensions
3. fixtures and benchmark harness
4. native runtime parity work

That order minimizes semantic drift against the current public repo direction.