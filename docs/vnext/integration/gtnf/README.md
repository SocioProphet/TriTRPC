# Governed Triparty Netting Fabric (GTNF) integration pack

This directory captures the GTNF doctrine, integration posture, validation substrate, and first Cosmos / IBC runtime handoff pack inside the TriTRPC vNext integration surface.

## Purpose

GTNF is not presented here as a replacement for TriTRPC. It is captured as a governed release, proof, export, and settlement-control layer that can sit above existing rails and interoperate with the broader TriTRPC vNext design pack.

## Start here

- `governed_triparty_white_paper.md` — current canonical white paper.
- `asi_snet_integration_manual.md` — implementation-facing ASI / SingularityNET integration manual.
- `gtnf_one_page_external_overview_math.md` — short math-forward external overview.
- `validation/` — validation substrate and runtime protocol.
- `ibc/` — first Cosmos / IBC Classic build target and runtime handoff subset.

## Current status

- Doctrine: stabilized enough for private technical circulation.
- ASI / SingularityNET path: documentation-grounded and integration-ready, not yet backed by an observed live payment trace.
- Cosmos / IBC path: version-locked and harness-ready, not yet backed by a live Hermes validation result.

## Positioning

GTNF is stronger than most current ecosystem material at the governed boundary between evidence, admission, release, and export. Existing ecosystems remain stronger as live rails. The operating posture here is therefore:

- agree with the live rails where they already work;
- wrap those rails with stronger proof and policy boundaries;
- extend them where witness, contradiction, reserve, and export control are missing; and
- defer any rewrite of working substrate until validation proves it necessary.
