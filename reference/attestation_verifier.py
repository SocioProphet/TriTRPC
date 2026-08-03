"""Reference tee/zk verifier — the decidable checks, then ABSTAIN on the crypto root (fail-closed).

The ProofEnvelope (#90) routes a tee/zk proof here. A software verifier cannot check an Intel DCAP
quote signature or a zk pairing without hardware collateral / a verifying key — but it CAN, and MUST,
decide the parts that don't need them, and it must REFUSE to rubber-stamp what it can't verify:

  tee: the quote's report_data MUST equal SHA-256(nonce || result_cid) — this is the binding that ties
       the quote to THIS result; a wrong/absent binding is a reject. The measurement (MRENCLAVE) must
       be in the allow-list; the nonce must be fresh (not seen before — anti-replay).
  zk:  the public inputs MUST include the result_cid and SHA-256(statement) — the binding that ties
       the proof to THIS result/statement; the scheme must be supported.

If every decidable check passes, the verdict is REFER (not accept): the hardware/crypto root is
delegated to the named root verifier. A bare 'accept' is never emitted for tee/zk — abstain, don't
fake a pass (descend-abstain = gate).

FIPS: the result-binding is SHA-256 (FIPS 180-4). The delegated quote-signature / zk-pairing check is
the root verifier's job. Does not touch the tritrpc v4/vNext wire format.
"""
from __future__ import annotations

import hashlib

TEE_MEASUREMENT_ALLOWLIST = {"sha256:" + "e" * 64}  # known-good MRENCLAVE set (deployment-configured)
ZK_SUPPORTED = {"groth16", "plonk", "stark"}


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def verify_tee(quote: dict, binding: dict, measurement_allow: set | None = None, seen_nonces: set | None = None) -> dict:
    """Decide a TEE quote's binding/measurement/freshness; refer the DCAP signature. Fail-closed."""
    allow = measurement_allow if measurement_allow is not None else TEE_MEASUREMENT_ALLOWLIST
    seen = seen_nonces if seen_nonces is not None else set()
    checks: dict[str, bool] = {}

    nonce = str(quote.get("nonce") or "")
    result_cid = str(binding.get("result_cid") or "")
    expected = _sha256_hex((nonce + "|" + result_cid).encode())
    checks["report_data_binds_result"] = (str(quote.get("report_data") or "") == expected)
    checks["measurement_allowlisted"] = (quote.get("measurement") in allow)
    checks["nonce_fresh"] = bool(nonce) and nonce not in seen

    if not all(checks.values()):
        reason = "; ".join(k for k, v in checks.items() if not v)
        return {"mode": "tee", "verdict": "reject", "checks": checks, "reason": f"failed: {reason}"}
    return {"mode": "tee", "verdict": "refer", "checks": checks,
            "referTo": "dcap-quote-verifier", "reason": "binding/measurement/freshness ok; quote signature delegated"}


def verify_zk(proof: dict, binding: dict, supported: set | None = None) -> dict:
    """Decide a zk proof's public-input binding + scheme; refer the pairing check. Fail-closed."""
    sup = supported if supported is not None else ZK_SUPPORTED
    checks: dict[str, bool] = {}

    scheme = proof.get("scheme")
    public_inputs = proof.get("publicInputs") or []
    stmt_hash = _sha256_hex(str(proof.get("statement") or "").encode())
    checks["scheme_supported"] = scheme in sup
    checks["public_inputs_bind_result"] = str(binding.get("result_cid") or "") in public_inputs
    checks["public_inputs_bind_statement"] = stmt_hash in public_inputs

    if not all(checks.values()):
        reason = "; ".join(k for k, v in checks.items() if not v)
        return {"mode": "zk", "verdict": "reject", "checks": checks, "reason": f"failed: {reason}"}
    return {"mode": "zk", "verdict": "refer", "checks": checks,
            "referTo": f"zk-{scheme}-vk-verifier", "reason": "public-input binding + scheme ok; pairing delegated"}
