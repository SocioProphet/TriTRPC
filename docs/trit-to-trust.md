# Trits to Trust (design notes)

This document consolidates the “Trit to trust” discussion into the TritRPC core repository so we keep TritRPC as a clean standalone project and avoid commingling via permanent submodules unless we explicitly choose to.

## Source originals

The original working notes are preserved verbatim here:

- `docs/trit-to-trust_sources/From Trits to Trust.rtf`
- `docs/trit-to-trust_sources/From Trits to Trust-.rtf`
- `docs/trit-to-trust_sources/Hypothetical Ternary TritRPC.rtf`
- `docs/trit-to-trust_sources/TritRPC for Avro- A Spec Sketch.rtf`
- `docs/trit-to-trust_sources/ternary tritprc document and spec.rtf`
- `docs/trit-to-trust_sources/Trit to trust.html`

## Next normalization pass (intent)

1) Convert the RTF/HTML into clean Markdown sections (keeping the originals as “sources”).
2) Extract the canonical protocol narrative into `spec/README-full-spec.md` and/or `spec/salad/tritrpc_salad.yml`.
3) Keep this file as the “story + rationale” layer, and keep `spec/` as the normative layer.
