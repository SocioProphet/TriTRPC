# Governed Triparty Netting Fabric

## What it is

GTNF is a **governed release layer** for heterogeneous settlement, authority, and export flows.

It does not replace transport. It sits above transport.
It does not replace escrow. It governs release.
It does not collapse evidence into permission. It separates them.

## Core claim

The right interoperability primitive is not a bridge, registry, or intent format in isolation.
The right primitive is a **governed triparty clearing cell** that can:
- cancel circulatory gross flow,
- preserve proof and provenance,
- separate evidence from permission,
- and support release, refund, suppression, or export according to policy rather than mere confidence.

## The release law

\[
\lambda_{release}^{(k)} = \eta(H_t,k)\,\rho_t^{(k)}\,p_t^{(k)}\,\lambda_{evid}^{(k)}
\]

Where:
- \(\lambda_{evid}\) = evidentially nettable cycle
- \(p_t\) = policy gate
- \(\rho_t\) = proof / finality / replay gate
- \(\eta(H_t,k)\) = macro-health dampener

This is the whole point: release is not determined by confidence alone.

## Why it matters

Most ecosystems have pieces of this model:
- transport or messaging,
- escrow or settlement,
- credentials or claims,
- some policy surface.

What they usually do **not** have is one coherent boundary between:
- evidence,
- admission,
- release,
- and export.

GTNF provides that boundary.

## What GTNF does better

GTNF makes five things first-class:
1. **Evidence is not permission**
2. **Permission is not release**
3. **Local validity is not exportability**
4. **Contradiction can veto stronger states**
5. **Reversal and replayability are constitutional, not afterthoughts**

## Math-forward validation metrics

Current validation focuses on measurable deltas, not slogans:
- **FRR** — false release rate
- **RRR** — replay rejection rate
- **TRI** — timeout refund integrity
- **CVP** — contradiction veto preservation
- **EDC** — export denial correctness
- **WFR** — stale witness freshness rejection
- **PHR** — malformed proof-handle rejection
- **MBR** — oversized memo boundary rejection
- **CBR** — malformed callback sender rejection
- **XWR** — contradictory export witness rejection
- **CE** — capital efficiency
- **\(\kappa_{compress}\)** — gross-flow compression ratio

## Ecosystem posture

GTNF is designed to integrate with existing ecosystems by:
- **agreeing** with live rails where they already work,
- **wrapping** those rails with stronger proof and policy boundaries,
- **extending** them where witness, contradiction, reserve, and export logic are missing,
- **deferring** any substrate rewrite until validation shows it is necessary.

## Current status

- Doctrine: stabilized enough for private technical circulation
- ASI / SingularityNET path: documentation-grounded and integration-ready
- Cosmos / IBC path: version-locked and harness-ready
- Runtime validation: still pending in a network-capable environment

## Short answer

GTNF is not another bridge.
It is the governed boundary where evidence becomes releasable, and where release becomes exportable only under stricter rules.
