# PlanningService contract v0.1

## Goal

Provide a typed planning surface for governed branch expansion and selection without collapsing planning into execution and without treating hidden prose reasoning as the canonical planning record.

## Methods

- `CreatePlanningScope`
- `ExpandPlanNode`
- `ScorePlanNode`
- `SelectPlanBranch`
- `InduceProgramCandidate`
- `SearchCounterexample`
- `BacktrackPlanNode`
- `ValidateAbstractRule`

## Input discipline

Planning methods MUST operate on stable references to:
- planning scope ids
- belief-state refs
- objective-vector refs
- policy refs
- plan-node refs

## Output discipline

Planning methods SHOULD return:
- stable `scopeRef`
- stable `planNodeRef` values
- stable `objectiveVectorRef` values
- explicit admissibility results
- explicit review requirements when selection remains conditional

## Rule

Planning methods SHOULD preserve stable references back to `scopeId`, `stateRef`, `planNodeId`, and `objectiveId`.

## Constraint

Planning methods MUST NOT directly realize execution-plane effects.

Execution remains downstream of planning and is still governed by the existing `ExecutionBridgeService`.

## Abstract reasoning constraint

For requests where `reasoningClass = ABSTRACT` or `reasoningClass = PROGRAM_INDUCTION`,
the service MUST NOT treat a language-model proposal as sufficient evidence of correctness.

The service SHOULD attach one or more of:
- `programCandidateRef`
- `counterexampleRef`
- causal-check refs
- explicit backtrack refs

before a branch is eligible for final selection.

## Non-goals

This service does not:
- emit `RunArtifact`
- emit execution `ReplayArtifact`
- resolve bundles
- tunnel the full knowledge descriptor graph
- treat hidden chain-of-thought as the audit record
