# ASI / SingularityNET Integration Manual

Version 1.1

## Purpose

This document explains how GTNF fits the current ASI / SingularityNET ecosystem without demanding a substrate rewrite.

## Operating posture

- agree with the live rails where they already work
- wrap those rails with stronger proof and policy boundaries
- extend them where witness, contradiction, reserve, and export logic are missing
- defer any platform rewrite until validation proves it necessary

## What GTNF reuses

- ASI(FET) monetary base
- Multi-Party Escrow
- payment channels
- daemon-side per-call authorization and validation
- delayed provider claiming

## What GTNF adds

- stronger release classes
- contradiction-aware denial and reversal
- witness and freshness boundaries
- proof lineage and replay discipline
- scoped export control

## Current status

The ASI / SingularityNET path is documentation-grounded and integration-ready, but it is not yet backed by an observed live payment trace.
