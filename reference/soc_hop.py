#!/usr/bin/env python3
"""Reference SOC-hop executor — makes the SOC contracts LIVE (Obfuscation-Manifesto follow-through).

Consumes the two contracts shipped alongside it — a `SocRelayContract` (owner-sealed transport
binding) and an optional `ObfuscationProfile` (traffic-analysis resistance) — and deterministically
produces what a real SOC hop emits:

  * the obfuscation PLAN — K-fold decoy set (1 real packet hidden among K-1 decoys), a per-packet
    timing-jitter schedule inside the declared window, a braid plan, and a padded packet size;
  * the owner-sealed `rpc.hop.sealed` transport RECEIPT event (per the SOC/chain profile).

Fail-closed: an unsealed / non-tritrpc / ad-hoc-id contract, or a no-anonymity profile, is REFUSED
before any hop is produced. Deterministic (seeded from contract_id + envelope_hash) so the plan is
reproducible and auditable. This is a reference planner, not a network stack: it does not send
packets — it produces the checkable artifacts a conformant SOC hop must.

FIPS: the deterministic stream uses SHA-256 (FIPS 180-4 approved) and no non-FIPS primitive. This
planner performs NO AEAD itself; the owner-sealing AEAD is carried out by the transport lane, which
in a FIPS deployment MUST be a FIPS-approved AEAD (AES-256-GCM), not XChaCha20-Poly1305. This module
does not touch the tritrpc v4/vNext wire format.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


class SocHopError(Exception):
    pass


def _fail(m: str) -> None:
    raise SocHopError(m)


def _rng_stream(seed_material: str):
    """Deterministic byte stream (SHA-256 CTR) — dependency-free, reproducible across platforms."""
    counter = 0
    while True:
        block = hashlib.sha256(f"{seed_material}:{counter}".encode()).digest()
        for b in block:
            yield b
        counter += 1


def _check_contract(contract: dict) -> dict:
    t = (contract or {}).get("transport")
    if not isinstance(t, dict):
        _fail("contract.transport missing (an owner-sealed transport block is required)")
    if t.get("protocol") != "tritrpc":
        _fail("contract.transport.protocol must be 'tritrpc'")
    if t.get("sealed") is not True or not str(t.get("sealed_to") or "").strip():
        _fail("contract.transport must be owner-sealed (sealed:true + sealed_to)")
    for key, prefix in (("route_id", "route://"), ("peer_id", "node://"),
                        ("chain_id", "soc://"), ("sealed_to", "owner://")):
        if not str(t.get(key, "")).startswith(prefix):
            _fail(f"contract.transport.{key} must use the {prefix!r} URI shape")
    if not isinstance(t.get("chain_position"), int) or t["chain_position"] < 0:
        _fail("contract.transport.chain_position must be a non-negative integer")
    return t


def _check_profile(profile: dict) -> dict:
    k = (profile or {}).get("kFold")
    if not isinstance(k, int) or isinstance(k, bool) or k < 2:
        _fail("obfuscation profile kFold must be an integer >= 2 (K=1 provides zero anonymity)")
    j = profile.get("jitterMs") or {}
    lo, hi = j.get("min"), j.get("max")
    if not (isinstance(lo, int) and isinstance(hi, int) and 1 <= lo <= hi):
        _fail("obfuscation profile jitterMs must satisfy 1 <= min <= max")
    braid = profile.get("braiding") or {}
    if braid.get("enabled") and (not isinstance(braid.get("minParticipants"), int) or braid["minParticipants"] < 2):
        _fail("obfuscation braiding requires minParticipants >= 2 when enabled")
    return profile


def execute_soc_hop(contract: dict, profile: dict, message: bytes) -> dict:
    """Plan one SOC hop. Raises SocHopError (fail-closed) on any invalid input."""
    t = _check_contract(contract)
    _check_profile(profile)

    seed = f"{contract.get('contract_id')}:{t.get('envelope_hash')}"
    stream = _rng_stream(seed)

    k = profile["kFold"]
    lo, hi = profile["jitterMs"]["min"], profile["jitterMs"]["max"]
    pad = int(profile.get("paddingBytes") or 0)
    real_size = max(len(message), pad)

    # Which of the K packets carries the real payload (hidden, deterministic).
    real_index = next(stream) % k
    packets = []
    for i in range(k):
        jitter = lo + (next(stream) % (hi - lo + 1))       # deterministic jitter in [lo, hi]
        # decoys are padded to the same target size so packet size does not distinguish them
        packets.append({
            "index": i,
            "is_real": i == real_index,
            "size_bytes": real_size,
            "jitter_ms": jitter,
        })

    plan = {
        "kFold": k,
        "decoyCount": k - 1,
        "realIndex": real_index,
        "paddedSizeBytes": real_size,
        "packets": packets,
    }
    braid = profile.get("braiding") or {}
    if braid.get("enabled"):
        plan["braid"] = {"participants": braid["minParticipants"]}

    sealed_event = {
        "event_id": "evt_" + hashlib.sha256(seed.encode()).hexdigest()[:12],
        "trace_id": t["chain_id"].replace("soc://", "trace_").replace("/", "_"),
        "span_id": f"span_hop{t['chain_position']}",
        "parent_span_id": f"span_hop{t['chain_position'] - 1}" if t["chain_position"] else "span_send",
        "event_type": "rpc.hop.sealed",
        "producer": "tritrpc",
        "payload": {
            "protocol": "tritrpc",
            "chain_id": t["chain_id"],
            "chain_position": t["chain_position"],
            "route_id": t["route_id"],
            "peer_id": t["peer_id"],
            "envelope_hash": t["envelope_hash"],
            "sealed": True,
            "sealed_to": t["sealed_to"],
        },
    }
    return {"sealed_event": sealed_event, "obfuscation_plan": plan}


if __name__ == "__main__":  # tiny demo on the shipped examples
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    c = json.loads((root / "examples/transport/soc_relay_contract.example.json").read_text())
    p = json.loads((root / "examples/transport/obfuscation_profile.example.json").read_text())
    print(json.dumps(execute_soc_hop(c, p, b"real-soc-payload"), indent=2))
