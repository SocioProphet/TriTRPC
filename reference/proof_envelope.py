#!/usr/bin/env python3
"""Reference proof-envelope pre-check — bind a tee/zk proof to its result and route it (fail-closed).

The Mesh Coordinator delegates the CRYPTOGRAPHIC verification of tee/zk proofs to their verifiers.
Before it can delegate, it must (a) confirm the envelope is well-formed for its mode, and (b) confirm
the proof is BOUND to exactly the result it is settling — a proof carrying binding {wu_id, result_cid}
for another result must be refused, or a node could replay a valid proof against a different result.
This module is that boundary: it validates + binds and returns a delegation ticket naming the verifier
the coordinator MUST call. It does NOT check the cryptography (stated honestly).

FIPS: no primitive here (structural). measurement/result_cid are SHA-256 (FIPS 180-4). The delegated
TEE-quote / zk verifier is responsible for the cryptographic check. Does not touch the v4/vNext wire.
"""
from __future__ import annotations

ZK_SCHEMES = {"groth16", "plonk", "stark"}


class ProofEnvelopeError(Exception):
    pass


def _fail(m: str) -> None:
    raise ProofEnvelopeError(m)


def precheck(envelope: dict, pack: dict, result: dict) -> dict:
    """Validate + bind a proof envelope against the WU pack and the result it settles.
    Returns a delegation ticket {mode, verifier, wu_id, result_cid}. Fail-closed."""
    mode = envelope.get("mode")
    if mode not in ("tee", "zk"):
        _fail(f"proof mode must be tee|zk, got {mode!r}")
    if mode != pack.get("proof_mode"):
        _fail(f"envelope mode {mode!r} != pack.proof_mode {pack.get('proof_mode')!r}")

    binding = envelope.get("binding") or {}
    # Anti-replay: the proof must be bound to THIS wu + THIS result, not any other.
    if binding.get("wu_id") != pack.get("wu_id"):
        _fail("binding.wu_id does not match the pack (proof bound to a different WU — refused)")
    if binding.get("result_cid") != result.get("result_cid"):
        _fail("binding.result_cid does not match the result (replayed proof — refused)")

    m = envelope.get("material") or {}
    if mode == "tee":
        for field in ("quote", "measurement", "nonce"):  # nonce = freshness (anti-replay of the quote itself)
            if not str(m.get(field) or "").strip():
                _fail(f"tee envelope missing required material: {field!r}")
        verifier = "tee-quote-verifier"
    else:
        scheme = m.get("scheme")
        if scheme not in ZK_SCHEMES:
            _fail(f"zk scheme must be one of {sorted(ZK_SCHEMES)}, got {scheme!r}")
        for field in ("statement", "proof"):
            if not str(m.get(field) or "").strip():
                _fail(f"zk envelope missing required material: {field!r}")
        verifier = f"zk-{scheme}-verifier"

    return {"mode": mode, "verifier": verifier,
            "wu_id": binding["wu_id"], "result_cid": binding["result_cid"]}


if __name__ == "__main__":
    import json
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    ex = root / "examples" / "mesh"
    env = json.loads((ex / "proof_envelope.tee.example.json").read_text())
    pack = {"wu_id": env["binding"]["wu_id"], "proof_mode": "tee"}
    result = {"result_cid": env["binding"]["result_cid"]}
    print(json.dumps(precheck(env, pack, result), indent=2))
