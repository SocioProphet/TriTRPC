from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from nacl.signing import SigningKey, VerifyKey


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_prefixed(text: str) -> str:
    return "sha256:" + b64url_encode(hashlib.sha256(text.encode("utf-8")).digest())


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    kty = jwk.get("kty")
    if kty == "OKP":
        subset = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    elif kty == "EC":
        subset = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    else:
        raise ValueError(f"unsupported JWK kty for thumbprint: {kty}")
    return b64url_encode(hashlib.sha256(canonical_json(subset)).digest())


def ed25519_private_jwk_from_seed(seed: bytes) -> dict[str, str]:
    signing_key = SigningKey(seed)
    verify_key = signing_key.verify_key
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "d": b64url_encode(seed),
        "x": b64url_encode(bytes(verify_key)),
    }


def ed25519_public_jwk_from_verify_key(verify_key: VerifyKey) -> dict[str, str]:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url_encode(bytes(verify_key)),
    }


def _sign_ed25519(signing_jwk: dict[str, str], signing_input: bytes) -> bytes:
    signing_key = SigningKey(b64url_decode(signing_jwk["d"]))
    signed = signing_key.sign(signing_input)
    return signed.signature


def _verify_ed25519(public_jwk: dict[str, str], signing_input: bytes, signature: bytes) -> None:
    verify_key = VerifyKey(b64url_decode(public_jwk["x"]))
    verify_key.verify(signing_input, signature)


def _sign_es256(signing_jwk: dict[str, str], signing_input: bytes) -> bytes:
    private_value = int.from_bytes(b64url_decode(signing_jwk["d"]), "big")
    x = int.from_bytes(b64url_decode(signing_jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(signing_jwk["y"]), "big")
    private_numbers = ec.EllipticCurvePrivateNumbers(
        private_value,
        ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()),
    )
    private_key = private_numbers.private_key()
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verify_es256(public_jwk: dict[str, str], signing_input: bytes, signature: bytes) -> None:
    x = int.from_bytes(b64url_decode(public_jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(public_jwk["y"]), "big")
    public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if len(signature) != 64:
        raise ValueError("ES256 compact signature must be 64 bytes")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der = encode_dss_signature(r, s)
    public_key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))


def jws_sign(header: dict[str, Any], payload: dict[str, Any], signing_jwk: dict[str, str]) -> str:
    header_bytes = canonical_json(header)
    payload_bytes = canonical_json(payload)
    encoded_header = b64url_encode(header_bytes)
    encoded_payload = b64url_encode(payload_bytes)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    alg = header.get("alg")
    if alg == "EdDSA":
        sig = _sign_ed25519(signing_jwk, signing_input)
    elif alg == "ES256":
        sig = _sign_es256(signing_jwk, signing_input)
    else:
        raise ValueError(f"unsupported alg: {alg}")
    return f"{encoded_header}.{encoded_payload}.{b64url_encode(sig)}"


def jws_parse(compact: str) -> Tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = compact.split(".")
    if len(parts) != 3:
        raise ValueError("compact JWS must have three segments")
    encoded_header, encoded_payload, encoded_sig = parts
    header = json.loads(b64url_decode(encoded_header))
    payload = json.loads(b64url_decode(encoded_payload))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = b64url_decode(encoded_sig)
    return header, payload, signing_input, signature


def jws_verify(compact: str, public_jwk: dict[str, str], allowed_algs: set[str] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    header, payload, signing_input, signature = jws_parse(compact)
    alg = header.get("alg")
    if allowed_algs is not None and alg not in allowed_algs:
        raise ValueError(f"algorithm not allowed: {alg}")
    if alg == "EdDSA":
        _verify_ed25519(public_jwk, signing_input, signature)
    elif alg == "ES256":
        _verify_es256(public_jwk, signing_input, signature)
    else:
        raise ValueError(f"unsupported alg: {alg}")
    return header, payload
