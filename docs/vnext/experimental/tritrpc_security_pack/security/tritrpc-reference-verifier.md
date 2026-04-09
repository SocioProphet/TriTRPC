# TriRPC Reference Verifier Notes v0.1

## Scope

The reference verifier included in `trirpc_security/verifier.py` is intentionally narrow.
It validates:
- JWS signature and allowlisted `alg`
- explicit `typ`
- audience
- session binding via `sid_ref`
- proof freshness and nonce
- proof binding via `cap_hash`
- confirmation key binding via `cnf.jkt`
- request binding via `http_method` and `http_path`
- one-time replay semantics via an in-memory replay cache

## Non-goals

It does not yet implement:
- distributed replay-cache coordination
- OCSP / X.509 trust chains
- remote JWKS fetching
- COSE verification
- hardware-backed browser key storage

## Operational advice

The in-memory replay cache is for examples and unit tests only.
A production deployment should replace it with a replicated, bounded, expiring store keyed by:
- token/proof kind
- `jti`
- tenant/workspace scope if needed
