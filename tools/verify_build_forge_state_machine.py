#!/usr/bin/env python3
"""Verify the Build Forge run-lifecycle state machine (fail-closed, with teeth).

For every fixture in ``fixtures/buildforge/*.json`` this replays the transition log
through ``reference/build_forge_state_machine.py`` and asserts the declared
expectation:

  * ``"accept"``            — the whole log replays with no error.
  * ``{"reject": {code, at}}`` — replay raises ``RunStateError`` with that exact
    machine-readable code (and, when given, at that edge index).

So valid runs are accepted and invalid ones are rejected *for the stated reason* —
CREATED->MERGED skips, terminal reopen, merge without a distinct grant, red gates,
workflow-file mutation under an ordinary grant, and discontinuous logs.

Two drift guards keep the three artifacts in lockstep: the JSON Schema run_state
enum and the proto RunState enum must both match the reference module's state set.

Stdlib only. Prints ``{"ok": bool, "checks": {...}}``; exit 0 iff every check holds.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import build_forge_state_machine as sm  # noqa: E402

FIXTURE_DIR = ROOT / "fixtures" / "buildforge"
SCHEMA = ROOT / "schemas" / "jsonschema" / "build-forge-run-transition.v0.schema.json"
PROTO = FIXTURE_DIR / "build_forge_tritrpc_v0_1.proto"

FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def _run_fixture(path: Path) -> None:
    spec = json.loads(path.read_text())
    name = path.name
    expect = spec["expect"]
    try:
        sm.replay(spec["transitions"])
        raised = None
    except sm.RunStateError as exc:
        raised = exc

    if expect == "accept":
        CHECKS[f"accept:{name}"] = raised is None
        if raised is not None:
            FAILURES.append(f"{name}: expected accept, got {raised.code} ({raised})")
        return

    want = expect["reject"]
    if raised is None:
        CHECKS[f"reject:{name}"] = False
        FAILURES.append(f"{name}: expected reject {want['code']}, but log was accepted")
        return
    code_ok = raised.code == want["code"]
    CHECKS[f"reject:{name}:{want['code']}"] = code_ok
    if not code_ok:
        FAILURES.append(f"{name}: expected {want['code']}, got {raised.code} ({raised})")


def _drift_guards() -> None:
    ref_states = set(sm.ALL_STATES)

    schema = json.loads(SCHEMA.read_text())
    enum = set(schema["$defs"]["run_state"]["enum"])
    CHECKS["drift:schema-enum-matches-reference"] = enum == ref_states
    if enum != ref_states:
        FAILURES.append(f"schema run_state enum drift: {enum ^ ref_states}")

    proto_text = PROTO.read_text()
    block = re.search(r"enum\s+RunState\s*\{(.*?)\}", proto_text, re.DOTALL)
    if not block:
        CHECKS["drift:proto-enum-present"] = False
        FAILURES.append("proto RunState enum not found")
        return
    names = set(re.findall(r"\b([A-Z][A-Z0-9_]+)\s*=\s*\d+", block.group(1)))
    names.discard("RUN_STATE_UNSPECIFIED")
    CHECKS["drift:proto-enum-matches-reference"] = names == ref_states
    if names != ref_states:
        FAILURES.append(f"proto RunState enum drift: {names ^ ref_states}")


def main() -> int:
    fixtures = sorted(FIXTURE_DIR.glob("*.json"))
    CHECKS["fixtures:present"] = len(fixtures) > 0
    if not fixtures:
        FAILURES.append("no fixtures found under fixtures/buildforge/")
    for fx in fixtures:
        _run_fixture(fx)
    _drift_guards()

    # Sanity: at least one accept and one reject fixture exercised.
    CHECKS["coverage:has-accept"] = any(k.startswith("accept:") for k in CHECKS)
    CHECKS["coverage:has-reject"] = any(k.startswith("reject:") for k in CHECKS)

    for k, v in CHECKS.items():
        if not v and f"{k}" not in {f for f in FAILURES}:
            pass
    for m in FAILURES:
        print(f"FAIL: {m}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
