#!/usr/bin/env python3
"""Verify the proof-envelope pre-check binds + routes tee/zk proofs fail-closed (delegation boundary).

Runs reference/proof_envelope.py on the shipped tee + zk examples: a well-formed tee envelope routes
to the tee-quote-verifier and a zk envelope to the zk-<scheme>-verifier, each bound to its wu/result.
Then, fail-closed: a REPLAYED proof (binding.result_cid != the result), a mode mismatch, a tee missing
its nonce, and an unknown zk scheme are each refused before any delegation. Stdlib, repo convention.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import proof_envelope as pe  # noqa: E402

EX = ROOT / "examples" / "mesh"
SCHEMA = ROOT / "schemas" / "jsonschema" / "proof-envelope.v0.schema.json"
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def load(name: str):
    return json.loads((EX / name).read_text())


def refused(fn) -> bool:
    try:
        fn()
        return False
    except pe.ProofEnvelopeError:
        return True


def main() -> int:
    # schema drift-guard: strict root, modes + zk schemes match the reference.
    schema = json.loads(SCHEMA.read_text())
    if schema.get("additionalProperties") is not False or set(schema["properties"]["mode"]["enum"]) != {"tee", "zk"} \
       or set(schema["properties"]["material"]["properties"]["scheme"]["enum"]) != pe.ZK_SCHEMES:
        FAILURES.append("schema drifted from reference (mode/zk-scheme enums)")
    else:
        CHECKS["schema:no-drift"] = True

    tee = load("proof_envelope.tee.example.json")
    zk = load("proof_envelope.zk.example.json")
    tee_pack = {"wu_id": "wu-x", "proof_mode": "tee"}
    zk_pack = {"wu_id": "wu-x", "proof_mode": "zk"}
    result = {"result_cid": tee["binding"]["result_cid"]}

    # 1. Valid tee -> routes to tee-quote-verifier, bound to wu/result.
    t = pe.precheck(tee, tee_pack, result)
    if t["verifier"] == "tee-quote-verifier" and t["result_cid"] == result["result_cid"]:
        CHECKS["tee:valid-routes-bound"] = True
    else:
        FAILURES.append(f"valid tee envelope did not route/bind: {t}")

    # 2. Valid zk -> routes to zk-groth16-verifier.
    z = pe.precheck(zk, zk_pack, result)
    if z["verifier"] == "zk-groth16-verifier":
        CHECKS["zk:valid-routes-by-scheme"] = True
    else:
        FAILURES.append(f"valid zk envelope did not route by scheme: {z}")

    # 3. Anti-replay: a proof bound to a different result_cid is refused.
    other = {"result_cid": "sha256:" + "b" * 64}
    CHECKS["fail-closed:replayed-proof-refused"] = refused(lambda: pe.precheck(tee, tee_pack, other))
    if not CHECKS["fail-closed:replayed-proof-refused"]:
        FAILURES.append("a proof bound to a different result must be refused (replay)")

    # 4. Mode mismatch (tee envelope, zk pack).
    CHECKS["fail-closed:mode-mismatch-refused"] = refused(lambda: pe.precheck(tee, zk_pack, result))
    if not CHECKS["fail-closed:mode-mismatch-refused"]:
        FAILURES.append("envelope mode != pack.proof_mode must be refused")

    # 5. tee missing nonce (freshness) refused.
    no_nonce = copy.deepcopy(tee); no_nonce["material"].pop("nonce")
    CHECKS["fail-closed:tee-missing-nonce-refused"] = refused(lambda: pe.precheck(no_nonce, tee_pack, result))
    if not CHECKS["fail-closed:tee-missing-nonce-refused"]:
        FAILURES.append("a tee envelope without a nonce must be refused")

    # 6. Unknown zk scheme refused.
    bad_scheme = copy.deepcopy(zk); bad_scheme["material"]["scheme"] = "snark9000"
    CHECKS["fail-closed:unknown-zk-scheme-refused"] = refused(lambda: pe.precheck(bad_scheme, zk_pack, result))
    if not CHECKS["fail-closed:unknown-zk-scheme-refused"]:
        FAILURES.append("an unknown zk scheme must be refused")

    for m in FAILURES:
        print(f"FAIL: {m}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
