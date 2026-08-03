#!/usr/bin/env python3
"""Verify the reference SOC-hop executor makes the SOC contracts LIVE and fail-closed.

Runs reference/soc_hop.py on the shipped example contract + obfuscation profile and asserts the
produced hop is real and conformant: exactly K-1 decoys, every packet's jitter inside the declared
window, one hidden real packet, and an owner-sealed rpc.hop.sealed receipt that satisfies the
SOC/chain profile. Then asserts fail-closed refusal on an unsealed contract and a no-anonymity
profile, and reproducibility (same inputs -> identical plan). Stdlib, repo convention.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
sys.path.insert(0, str(ROOT / "tools"))
import soc_hop  # noqa: E402

EX = ROOT / "examples" / "transport"


def owner_sealed_ok(event: dict) -> str | None:
    """Per-event owner-sealed conformance (the single-hop analogue of the SOC/chain profile —
    the full-chain contiguity rule doesn't apply to one emitted hop)."""
    if event.get("event_type") != "rpc.hop.sealed":
        return "event_type must be rpc.hop.sealed"
    p = event.get("payload") or {}
    if p.get("protocol") != "tritrpc":
        return "payload.protocol must be tritrpc"
    if p.get("sealed") is not True or not str(p.get("sealed_to") or "").startswith("owner://"):
        return "hop must be owner-sealed (sealed:true + sealed_to owner://)"
    for key, prefix in (("route_id", "route://"), ("peer_id", "node://"), ("chain_id", "soc://")):
        if not str(p.get(key, "")).startswith(prefix):
            return f"payload.{key} must use the {prefix!r} URI shape"
    return None
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def load(name: str):
    return json.loads((EX / name).read_text())


def main() -> int:
    contract = load("soc_relay_contract.example.json")
    profile = load("obfuscation_profile.example.json")

    out = soc_hop.execute_soc_hop(contract, profile, b"real-soc-payload")
    plan, event = out["obfuscation_plan"], out["sealed_event"]

    # 1. K-fold: exactly K-1 decoys + one real packet.
    k = profile["kFold"]
    reals = [p for p in plan["packets"] if p["is_real"]]
    if plan["decoyCount"] != k - 1 or len(plan["packets"]) != k or len(reals) != 1:
        FAILURES.append(f"K-fold wrong: k={k} packets={len(plan['packets'])} decoys={plan['decoyCount']} reals={len(reals)}")
    else:
        CHECKS["kfold:one-real-k-minus-1-decoys"] = True

    # 2. Jitter: every packet's jitter is inside the declared window.
    lo, hi = profile["jitterMs"]["min"], profile["jitterMs"]["max"]
    if all(lo <= p["jitter_ms"] <= hi for p in plan["packets"]):
        CHECKS["jitter:within-window"] = True
    else:
        FAILURES.append("a packet's jitter fell outside the declared jitterMs window")

    # 3. The emitted receipt is an owner-sealed SOC hop event.
    err = owner_sealed_ok(event)
    if err:
        FAILURES.append(f"emitted receipt is not owner-sealed SOC-conformant: {err}")
    else:
        CHECKS["receipt:owner-sealed-soc-conformant"] = True

    # 4. Fail-closed: an unsealed contract and a no-anonymity profile are REFUSED (no hop produced).
    try:
        soc_hop.execute_soc_hop(load("soc_relay_contract.unsealed.invalid.json"), profile, b"x")
        FAILURES.append("an unsealed contract must be refused (no hop produced)")
    except soc_hop.SocHopError:
        CHECKS["fail-closed:unsealed-refused"] = True
    try:
        soc_hop.execute_soc_hop(contract, load("obfuscation_profile.no-anonymity.invalid.json"), b"x")
        FAILURES.append("a no-anonymity (K=1) profile must be refused")
    except soc_hop.SocHopError:
        CHECKS["fail-closed:no-anonymity-refused"] = True

    # 5. Determinism — identical inputs produce an identical plan (auditable/reproducible).
    again = soc_hop.execute_soc_hop(contract, profile, b"real-soc-payload")
    if again == out:
        CHECKS["deterministic:reproducible"] = True
    else:
        FAILURES.append("executor is not deterministic — same inputs produced a different plan")

    for m in FAILURES:
        print(f"FAIL: {m}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
