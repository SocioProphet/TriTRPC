# ASI / SingularityNET Integration Manual
## Governed Triparty Netting Fabric

Version 1.1  
Date: 2026-04-05

## Purpose

This manual explains how to integrate the governed triparty netting fabric (GTNF) with the current ASI / SingularityNET ecosystem without demanding a substrate rewrite.

The guiding posture is:
- agree with the live rails where they already work,
- wrap those rails with stronger proof and policy boundaries,
- extend them where witness, contradiction, reserve, and export control are missing,
- defer any substrate rewrite until validation proves it necessary.

## What GTNF reuses unchanged

GTNF reuses the current live monetary and service rails:
- ASI(FET) monetary base
- Multi-Party Escrow (MPE)
- payment channels
- daemon-side service authorization and payment validation
- provider-side delayed claiming

These existing surfaces already provide the money leg and much of the authorization leg needed for a governed release system.

## What GTNF wraps

GTNF wraps the current invocation and claiming flow with:
- explicit evidence commitments
- policy commitments
- release classes
- contradiction/veto handling
- replay and freshness boundaries
- export gating

The intention is to make current rails safer and more legible, not to deny their utility.

## What GTNF extends

GTNF extends the current ecosystem in the following areas:
- witness and solver admission
- contradiction-aware release
- proof lineage and replayability
- reserve-aware release and dampening
- export discipline across scopes
- reversal / unmerge semantics for invalidated stronger states

## What GTNF defers

GTNF intentionally defers:
- a new settlement token,
- mandatory full ASI:Chain dependence,
- fully on-chain proof storage,
- reserve machinery that does not yet have validated runtime backing,
- any platform rewrite whose value is not yet demonstrated by validation.

## Current-rail grounded trace

The current documented path is:
1. fund MPE with ASI(FET),
2. open or fund a payment channel,
3. invoke a paid service through the daemon using signed payment metadata,
4. let the daemon validate channel id, nonce, amount, signature, expiry, and available funds,
5. recover from nonce drift if needed,
6. allow the provider to claim later.

GTNF maps onto this as follows:
- `EscrowBundle` -> MPE funding / channel opening
- `FillBundle` -> signed per-call daemon metadata plus service execution
- `VerificationBundle` -> daemon validation plus proof/policy overlay
- `Release` -> provider claim after GTNF release conditions are satisfied
- `Refund / Denial` -> current rail rollback plus GTNF reason code and proof lineage

## Token posture

GTNF should not introduce a competing settlement token inside the current ASI ecosystem. The monetary base remains ASI(FET). Capability rights, proof artifacts, and governance states are modeled separately from money.

## Why this is useful to the ecosystem

The current ecosystem already has working rails. What it lacks, in one coherent place, is a constitutional boundary between:
- evidence and permission,
- permission and release,
- release and export.

GTNF provides that boundary.

## First-contact summary

If the question is “why should the ecosystem care?”, the answer is simple:

GTNF does not ask SingularityNET to abandon working rails. It gives those rails a stronger release constitution and a cleaner proof/governance model.
