#!/usr/bin/env python3
"""Verify the tee/zk verifier decides bindings fail-closed and ABSTAINS (never fake-passes) the root.

Runs reference/attestation_verifier.py on the shipped tee quote + zk proof and asserts: a well-formed
tee quote (report_data binds nonce|result_cid, measurement allow-listed, fresh nonce) yields REFER —
not accept — routing to the dcap-quote-verifier; a well-formed zk proof (public inputs bind result +
statement, supported scheme) yields REFER to the zk vk verifier. Then, fail-closed: a wrong binding,
an unknown measurement, a replayed nonce, a missing public input, and an unsupported scheme are each
REJECTED. The core invariant: tee/zk NEVER produce a bare 'accept' — the crypto root is always
deferred. Plus determinism + a schema drift-guard. Stdlib.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import attestation_verifier as av  # noqa: E402

EX = ROOT / "examples" / "mesh"
SCHEMA = ROOT / "schemas" / "jsonschema" / "attestation-verdict.v0.schema.json"
FAILURES: list[str] = []
CHECKS: dict[str, bool] = {}


def load(n: str):
    return json.loads((EX / n).read_text())


def main() -> int:
    schema = json.loads(SCHEMA.read_text())
    if schema.get("additionalProperties") is not False or set(schema["properties"]["verdict"]["enum"]) != {"reject", "refer"}:
        FAILURES.append("schema drift: verdict enum must be exactly {reject, refer} (no 'accept')")
    else:
        CHECKS["schema:verdict-has-no-accept"] = True

    tee = load("tee_quote.example.json")
    zk = load("zk_proof.example.json")

    # 1. well-formed tee -> refer (not accept), routed to dcap.
    v = av.verify_tee(tee["quote"], tee["binding"], seen_nonces=set())
    if v["verdict"] == "refer" and v.get("referTo") == "dcap-quote-verifier" and all(v["checks"].values()):
        CHECKS["tee:wellformed-refers-not-accepts"] = True
    else:
        FAILURES.append(f"well-formed tee should refer: {v}")

    # 2. wrong binding -> reject.
    bad = copy.deepcopy(tee); bad["quote"]["report_data"] = "sha256:" + "0" * 64
    CHECKS["fail-closed:tee-unbound-rejected"] = av.verify_tee(bad["quote"], bad["binding"], seen_nonces=set())["verdict"] == "reject"

    # 3. unknown measurement -> reject.
    m = copy.deepcopy(tee); m["quote"]["measurement"] = "sha256:" + "f" * 64
    CHECKS["fail-closed:tee-unknown-enclave-rejected"] = av.verify_tee(m["quote"], m["binding"], seen_nonces=set())["verdict"] == "reject"

    # 4. replayed nonce -> reject.
    seen = {tee["quote"]["nonce"]}
    CHECKS["fail-closed:tee-replayed-nonce-rejected"] = av.verify_tee(tee["quote"], tee["binding"], seen_nonces=seen)["verdict"] == "reject"

    # 5. well-formed zk -> refer.
    z = av.verify_zk(zk["proof"], zk["binding"])
    if z["verdict"] == "refer" and z.get("referTo") == "zk-groth16-vk-verifier":
        CHECKS["zk:wellformed-refers"] = True
    else:
        FAILURES.append(f"well-formed zk should refer: {z}")

    # 6. zk missing result_cid in public inputs -> reject.
    zbad = copy.deepcopy(zk); zbad["proof"]["publicInputs"] = [zbad["proof"]["publicInputs"][1]]
    CHECKS["fail-closed:zk-unbound-rejected"] = av.verify_zk(zbad["proof"], zbad["binding"])["verdict"] == "reject"

    # 7. zk unsupported scheme -> reject.
    zs = copy.deepcopy(zk); zs["proof"]["scheme"] = "snark9000"
    CHECKS["fail-closed:zk-unsupported-scheme-rejected"] = av.verify_zk(zs["proof"], zs["binding"])["verdict"] == "reject"

    # 8. INVARIANT: neither verifier ever returns 'accept'.
    verdicts = {av.verify_tee(tee["quote"], tee["binding"], seen_nonces=set())["verdict"],
                av.verify_zk(zk["proof"], zk["binding"])["verdict"],
                av.verify_tee(bad["quote"], bad["binding"], seen_nonces=set())["verdict"]}
    CHECKS["invariant:never-bare-accept"] = "accept" not in verdicts

    # 9. determinism.
    CHECKS["deterministic:reproducible"] = av.verify_tee(tee["quote"], tee["binding"], seen_nonces=set()) == v

    for k in ("fail-closed:tee-unbound-rejected", "fail-closed:tee-unknown-enclave-rejected",
              "fail-closed:tee-replayed-nonce-rejected", "fail-closed:zk-unbound-rejected",
              "fail-closed:zk-unsupported-scheme-rejected"):
        if not CHECKS.get(k):
            FAILURES.append(f"{k} did not fire")

    for m2 in FAILURES:
        print(f"FAIL: {m2}", file=sys.stderr)
    ok = not FAILURES and all(CHECKS.values())
    print(json.dumps({"ok": ok, "checks": CHECKS}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
