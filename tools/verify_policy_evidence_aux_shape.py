#!/usr/bin/env python3
"""Repository-local readiness verifier for policy/evidence AUX examples.

This is intentionally a SHAPE/CANONICAL-STRING verifier for the published example set.
It does not replace full cross-language frame vectors or full JCS+BLAKE3 compliance tests.
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "fixtures" / "policy_evidence_aux_examples.json"
HASH_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
REQUIRED_TOP = {"profile", "grant_ref", "policy_decision_ref", "runtime_evidence_refs"}
OPTIONAL_TOP = {"attestation_bundle_ref", "policy_hash", "notes"}
ALLOWED_RT = {
    "event_ir_ref",
    "event_ir_hash",
    "semantic_proof_ref",
    "semantic_proof_hash",
    "hdt_decision_ref",
    "hdt_decision_hash",
    "attestation_bundle_ref",
    "attestation_bundle_hash",
}


def fail(msg: str, code: int = 2) -> None:
    print(f"[FAIL] {msg}", file=sys.stderr)
    raise SystemExit(code)


def canonicalize_for_examples(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def check_hash_fields(d: dict, name: str) -> None:
    for k, v in d.items():
        if k.endswith("_hash"):
            if not isinstance(v, str) or not HASH_RE.fullmatch(v):
                fail(f"{name}: invalid hash field {k}={v!r}")


def main() -> None:
    if not EXAMPLES.exists():
        fail(f"missing examples file: {EXAMPLES}")
    data = json.loads(EXAMPLES.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        fail("examples file must be a non-empty JSON array")

    for item in data:
        if not isinstance(item, dict):
            fail("each example must be an object")
        name = item.get("name", "<unnamed>")
        aux = item.get("aux_object")
        cjson = item.get("canonical_aux_json")
        if not isinstance(aux, dict):
            fail(f"{name}: aux_object must be an object")
        if not isinstance(cjson, str) or not cjson:
            fail(f"{name}: canonical_aux_json must be a non-empty string")

        top = set(aux.keys())
        if not REQUIRED_TOP.issubset(top):
            missing = sorted(REQUIRED_TOP - top)
            fail(f"{name}: missing required top-level keys: {missing}")
        extra = top - REQUIRED_TOP - OPTIONAL_TOP
        if extra:
            fail(f"{name}: unexpected top-level keys: {sorted(extra)}")
        if aux.get("profile") != "tritrpc.policy_evidence_aux.v1":
            fail(f"{name}: bad profile {aux.get('profile')!r}")

        rt = aux.get("runtime_evidence_refs")
        if not isinstance(rt, dict):
            fail(f"{name}: runtime_evidence_refs must be an object")
        rt_extra = set(rt.keys()) - ALLOWED_RT
        if rt_extra:
            fail(f"{name}: unexpected runtime_evidence_refs keys: {sorted(rt_extra)}")

        check_hash_fields(aux, name)
        check_hash_fields(rt, name)

        rendered = canonicalize_for_examples(aux)
        if rendered != cjson:
            fail(f"{name}: canonical_aux_json drifted from locally expected canonical string")

    print("[OK] Policy/evidence AUX examples passed shape + canonical-string checks.")


if __name__ == "__main__":
    main()
