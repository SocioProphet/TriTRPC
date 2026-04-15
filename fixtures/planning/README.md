# Planning fixtures placeholder

This directory holds deterministic example payloads for governed planning over TriTRPC.

Planned coverage:
- `CreatePlanningScope` request/response
- `ExpandPlanNode` request/response
- `ScorePlanNode` request/response
- `SelectPlanBranch` request/response
- `InduceProgramCandidate` request/response
- `SearchCounterexample` request/response
- `BacktrackPlanNode` request/response
- `ValidateAbstractRule` request/response

These fixtures preserve stable refs to scope, state, objective, and plan-node artifacts.
They do not carry execution artifacts; execution remains in the downstream bridge.
