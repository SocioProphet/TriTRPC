"""Build Forge run-lifecycle state machine (reference).

Enforces the normative RunState transition machine from the Build Forge Contract
Pack v0.1 (`spec/drafts/build_forge_v0_1.md`, §"Normative state machine"), plus the
two hard invariants that give the lifecycle teeth:

  * merge-authority separation  — a run MUST NOT reach MERGED without a distinct
    merge grant AND passing policy gates (invariant 4 / G8, error BF-AUTH-006).
  * workflow-mutation isolation — a transition that mutates workflow files under an
    ordinary authoring grant is refused (invariant 8 / G4, error BF-POL-001).

Terminal states are absorbing. Any illegal edge is an event-order violation
(BF-INT-004). Fail-closed: unknown states raise rather than pass.

Pure stdlib, deterministic. Mirrors the `tritrpc.buildforge.v1` proto RunState enum
in `fixtures/buildforge/build_forge_tritrpc_v0_1.proto`.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Mapping, Optional, Set

# Non-terminal (active) run states, in canonical lifecycle order.
ACTIVE: tuple[str, ...] = (
    "CREATED",
    "AUTHORIZED",
    "MOUNTED",
    "BRANCHED",
    "PATCHED",
    "PUSHED",
    "PR_OPEN",
    "CHECKS_PENDING",
    "REVIEW_PENDING",
    "READY_TO_MERGE",
)

# Absorbing terminal states.
TERMINAL: frozenset[str] = frozenset(
    {"MERGED", "REJECTED", "ABORTED", "EXPIRED", "FAILED"}
)

ALL_STATES: frozenset[str] = frozenset(ACTIVE) | TERMINAL

# Interrupt edges available from every active state.
_INTERRUPT: frozenset[str] = frozenset({"FAILED", "ABORTED", "EXPIRED"})

# Linear / branching happy-path edges (excludes the universal interrupt edges).
_LINEAR: Dict[str, Set[str]] = {
    "CREATED": {"AUTHORIZED"},
    "AUTHORIZED": {"MOUNTED"},
    "MOUNTED": {"BRANCHED"},
    "BRANCHED": {"PATCHED"},
    "PATCHED": {"PUSHED"},
    "PUSHED": {"PR_OPEN"},
    "PR_OPEN": {"CHECKS_PENDING"},
    "CHECKS_PENDING": {"REVIEW_PENDING"},
    "REVIEW_PENDING": {"READY_TO_MERGE", "REJECTED"},
    "READY_TO_MERGE": {"MERGED"},
}


class RunStateError(Exception):
    """A refused transition, carrying a machine-readable Build Forge error code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def allowed_targets(state: str) -> Set[str]:
    """The set of states reachable from ``state`` by a single legal edge."""
    if state not in ALL_STATES:
        raise RunStateError("BF-INT-004", f"unknown state {state!r}")
    if state in TERMINAL:
        return set()
    return set(_LINEAR.get(state, set())) | set(_INTERRUPT)


def assert_transition(
    frm: str, to: str, ctx: Optional[Mapping[str, object]] = None
) -> str:
    """Assert ``frm -> to`` is legal under ``ctx``; return ``to`` or raise.

    ``ctx`` recognised keys:
      merge_grant_present (bool)      — a distinct merge grant is present.
      policy_gates_passed (bool)      — required checks green / gates satisfied.
      workflow_file_mutation (bool)   — this transition mutates workflow files.
      workflow_mutation_capability(bool) — grant carries the workflow-mutation class.
    """
    ctx = ctx or {}
    if frm not in ALL_STATES:
        raise RunStateError("BF-INT-004", f"unknown source state {frm!r}")
    if to not in ALL_STATES:
        raise RunStateError("BF-INT-004", f"unknown target state {to!r}")
    if frm in TERMINAL:
        raise RunStateError(
            "BF-INT-004", f"terminal state {frm} is absorbing; refused edge to {to}"
        )
    if to not in allowed_targets(frm):
        raise RunStateError(
            "BF-INT-004", f"illegal transition {frm} -> {to} (not in allowed set)"
        )
    # Merge-authority separation: MERGED requires a distinct grant AND green gates.
    if to == "MERGED":
        if not ctx.get("merge_grant_present"):
            raise RunStateError(
                "BF-AUTH-006",
                "merge to MERGED requires a distinct merge grant (authoring != merge authority)",
            )
        if not ctx.get("policy_gates_passed"):
            raise RunStateError(
                "BF-POL-005", "merge refused: required checks not green / gates unsatisfied"
            )
    # Workflow-mutation isolation: a distinct capability class from ordinary authoring.
    if ctx.get("workflow_file_mutation") and not ctx.get("workflow_mutation_capability"):
        raise RunStateError(
            "BF-POL-001",
            "workflow file mutation disallowed under ordinary authoring grant",
        )
    return to


def replay(transitions: Iterable[Mapping[str, object]]) -> List[str]:
    """Walk a transition log, asserting each edge and inter-edge continuity.

    Each item: ``{"from": <state>, "to": <state>, "ctx": {...}?}``. The ``to`` of
    edge *i* MUST equal the ``from`` of edge *i+1* (BF-INT-004). Returns the visited
    state sequence, or raises ``RunStateError`` at the first violation.
    """
    seq: List[str] = []
    prev_to: Optional[str] = None
    for i, t in enumerate(transitions):
        frm = str(t["from"])
        to = str(t["to"])
        if prev_to is not None and frm != prev_to:
            raise RunStateError(
                "BF-INT-004",
                f"discontinuous log at edge {i}: expected from={prev_to}, got {frm}",
            )
        ctx = t.get("ctx") or {}
        assert_transition(frm, to, ctx)  # type: ignore[arg-type]
        if not seq:
            seq.append(frm)
        seq.append(to)
        prev_to = to
    return seq
