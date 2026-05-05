#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "fixtures" / "agent_sandbox_transport"

KNOWN_MEDIA_TYPES = {
    "application/vnd.socioprophet.agent-sandbox-spec+json;v=0",
    "application/vnd.socioprophet.agent-genesis-manifest+json;v=0",
    "application/vnd.socioprophet.agent-failure-bundle+json;v=0",
    "application/vnd.socioprophet.agent-sandbox-receipt+json;v=0",
}


def canonical_digest(payload: object) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def verify_blob(path: pathlib.Path) -> None:
    blob = json.loads(path.read_text(encoding="utf-8"))
    assert blob["schema_version"] == "tritrpc-agent-sandbox-transport.v0", path
    assert blob["media_type"] in KNOWN_MEDIA_TYPES, path
    assert blob["semantic_schema_ref"].startswith("capability-fabric:agent-sandbox-lifecycle.v0#/"), path
    assert "payload" in blob or "payload_ref" in blob, path
    if "payload" in blob:
        got = canonical_digest(blob["payload"])
        assert got == blob["payload_digest"], f"{path}: digest mismatch {got} != {blob['payload_digest']}"
        payload = blob["payload"]
        if blob["media_type"] == "application/vnd.socioprophet.agent-failure-bundle+json;v=0":
            assert payload.get("failure_class") in {"INFRASTRUCTURE", "CONTROL_PLANE", "VALIDATION", "POLICY", "USER_INPUT", "REPOSITORY", "UNKNOWN"}, path
            assert payload.get("allow_partial_push") is False, f"{path}: failure bundle must not allow partial push"
            assert payload.get("allow_push_after_infra_failure") is False, f"{path}: infra failure must not allow push"


def main() -> int:
    fixtures = sorted(FIXTURE_DIR.glob("*.json"))
    if not fixtures:
        raise SystemExit("no agent sandbox transport fixtures found")
    for fixture in fixtures:
        verify_blob(fixture)
    print(f"verified {len(fixtures)} agent sandbox transport fixture(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
