# TRiTRPC v5 repository implementation package

## Goal

Map the white-paper claims to concrete repository work so the paper and the repo evolve together.

## Immediate documentation updates

- Update `README.md` to state the narrowest strongest public claim and link to the white paper, threat table, profile matrix, and claims ledger.
- Replace placeholder `SECURITY.md` with a real policy that distinguishes stable v1 from best-effort vNext and avoids vague compliance claims.
- Update `docs/vnext/README.md` and `docs/vnext/WHAT_IS_TRITRPC_VNEXT.md` so the public theorem is explicit and bounded.

## White-paper and evidence files to add

- `docs/vnext/whitepaper/TRiRPC_WHITE_PAPER_V5.md`
- `docs/vnext/reports/tritrpc_v5_claims_ledger.csv`
- `docs/vnext/reports/tritrpc_v5_protocol_threat_table.md`
- `docs/vnext/reports/tritrpc_v5_profile_matrix.md`
- `docs/vnext/reports/tritrpc_v5_benchmark_and_ablation_plan.md`

## Benchmarks and regenerated evidence

- Publish competitor schemas and encoder code for the five-event benchmark.
- Add ablation outputs showing the effect of compact control words, route handles, stream inheritance, and ternary payload packing.
- Regenerate machine-readable benchmark CSVs and plots.
- Extend cadence testing to native runtime, not only the experimental reference package.

## Native runtime work implied by the paper

- Port `Braid243` and `State243` into native Go and Rust.
- Implement stream semantic inheritance and semantic tail behavior in the native runtime.
- Add typed `BEACON_INTENT` semantic deltas instead of opaque payload bytes.
- Add native golden fixtures for per-frame, inherited, and beaconed semantic regimes.

## Security / assurance follow-through

- Split protocol threat analysis from compliance profile documentation.
- Add separate CI lanes or at minimum separate jobs for stable v1, experimental vNext framing, and future bounded compliance tests.
- Keep any future FIPS/CNSA-style profile clearly tied to module/provider/OE language.

## Hybrid / Path-H next proof point

- Build one simulator-backed end-to-end control walkthrough:
  `PAIR.OPEN -> PAIR.HERALD -> TELEPORT.BSM3 -> FRAME.DEFER/CORRECTION.APPLY -> WITNESS.REPORT`
- Keep it explicitly labeled as a classical sidecar around quantum simulation rather than as the quantum wire itself.

## Freeze points needed

- freeze authoritative route/semantic registries when ready;
- keep `topic23` and `cycle7` explicit about whether they are proposed or authoritative;
- keep stable v1 fixtures fixed while vNext evolves beside them.
