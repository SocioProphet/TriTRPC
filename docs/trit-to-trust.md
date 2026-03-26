# Trits to Trust (design notes)

This document consolidates the “Trit to trust” discussion into the TritRPC core repository so TritRPC stays a clean standalone project and we avoid commingling via permanent dependencies unless we explicitly choose to.

## Source originals (preserved verbatim)

- docs/trit-to-trust_sources/From Trits to Trust.rtf
- docs/trit-to-trust_sources/From Trits to Trust-.rtf
- docs/trit-to-trust_sources/Hypothetical Ternary TritRPC.rtf
- docs/trit-to-trust_sources/TritRPC for Avro- A Spec Sketch.rtf
- docs/trit-to-trust_sources/ternary tritprc document and spec.rtf
- docs/trit-to-trust_sources/Trit to trust.html

## Next normalization pass (intent)

1) Convert the RTF/HTML into clean Markdown sections (keeping these originals as “sources”).
2) Extract canonical protocol narrative into spec/README-full-spec.md and/or spec/salad/tritrpc_salad.yml.
3) Keep this file as the “story + rationale” layer; keep spec/ as the normative layer.
