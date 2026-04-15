# TriRPC Capability Crypto Profile v0.1

## Purpose

Define a narrow, replay-resistant delegation layer for browser-to-BFF and BFF-to-service calls without exposing generic reusable authority to the browser.

## Threat model

- The browser is not a secret store.
- The DOM may be read or modified by page scripts, XSS, extensions with host permissions, or debugging surfaces.
- Session identity remains server-managed.
- Browser-visible delegation must be:
  - short-lived,
  - audience-bound,
  - action-bound,
  - sender-constrained,
  - optionally one-time.

## Core artifacts

### 1. Session cookie

The browser authenticates with a server-managed session cookie only.

Preferred:
```http
Set-Cookie: __Host-Http-sp_sid=<opaque>; Secure; HttpOnly; SameSite=Lax; Path=/
```

Fallback:
```http
Set-Cookie: __Host-sp_sid=<opaque>; Secure; HttpOnly; SameSite=Lax; Path=/
```

Notes:
- `__Host-Http-` is preferred when browser/client support exists.
- `__Host-` is the conservative interoperable baseline.

### 2. Browser Capability Ticket (`BCT`)

A signed JSON claims object visible to the browser and valid for one bounded browser action.

Mandatory properties:
- explicit `typ`
- explicit `alg`
- narrow `aud`
- `jti`
- `iat`, `nbf`, `exp`
- `authorization_details`
- `cnf.jkt`
- `sid_ref` (reference to session, never the real session identifier)

### 3. Browser proof (`Tri-Proof`)

Per-request proof signed with the private key whose thumbprint appears in `cnf.jkt`.

Mandatory properties:
- explicit `typ`
- explicit `alg`
- `jti`
- `iat`
- `htm`
- `htu`
- `nonce`
- `cap_hash`

### 4. Service Capability Ticket (`SCT`)

A narrower ticket minted by the BFF for the downstream service. Never exposed to the browser.

## Algorithm policy

### Preferred browser proof algorithm
- `EdDSA` over `Ed25519`

### Fallback browser proof algorithm
- `ES256`

### Why
- `Ed25519` is compact, fast, and easier to handle safely.
- `ES256` remains the compatibility path where external libraries or peers are opinionated around P-256 / ES256.

### Key identifiers
- `kid` and `cnf.jkt` use RFC 7638 SHA-256 JWK thumbprints.

## Header rules

### `BCT`
```json
{
  "typ": "triticket+jwt",
  "alg": "EdDSA",
  "kid": "<jwk-thumbprint>"
}
```

### `Tri-Proof`
```json
{
  "typ": "triproof+jwt",
  "alg": "EdDSA",
  "kid": "<jwk-thumbprint>"
}
```

## Prohibited JOSE header features

The verifier MUST reject:
- `jku`
- `x5u`
- `x5c`
- `crit` unless explicitly allowed in the verifier profile
- `none`
- any algorithm outside the configured allowlist

## Thumbprint profile

Use RFC 7638 SHA-256 thumbprints with the minimal canonical public JWK.

For Ed25519 public keys:
```json
{"crv":"Ed25519","kty":"OKP","x":"..."}
```

For ES256 public keys:
```json
{"crv":"P-256","kty":"EC","x":"...","y":"..."}
```

## Lifetime profile

### Browser Capability Ticket
- TTL: 60 seconds
- `max_requests`: 1 by default
- `one_time`: true by default

### Browser proof
- freshness window: 60 seconds
- allowed future clock skew: 30 seconds
- server nonce validity: 120 seconds
- replay-cache retention for proof `jti`: nonce lifetime + 60 seconds

### Browser proof key
- max age: 8 hours
- forced rotation on:
  - authentication event
  - reauthentication / MFA step-up
  - privilege change
  - connector scope elevation
  - explicit logout
  - tab/session restart if desired by deployment

## Verification sequence

The BFF SHOULD verify in this order:

1. Resolve server session from `HttpOnly` cookie.
2. Validate CSRF token.
3. Validate `Origin` and `Sec-Fetch-Site` for unsafe methods.
4. Validate token header:
   - expected `typ`
   - allowed `alg`
   - no remote key references
5. Validate token claims:
   - issuer
   - audience
   - time window
   - `jti`
   - session binding
6. Validate proof signature using enrolled public key identified by `cnf.jkt`.
7. Validate proof freshness and nonce.
8. Validate `htm` and `htu` against the actual request.
9. Validate `cap_hash` against the exact presented BCT.
10. Validate `authorization_details`.
11. Perform object-level authorization on the referenced object IDs.
12. Consume one-time ticket/proof IDs.
13. Mint narrower downstream `SCT` if needed.
14. Emit evidence.

## Failure codes

Recommended stable error codes:
- `401 session_missing_or_invalid`
- `401 csrf_invalid`
- `401 proof_invalid`
- `401 capability_invalid_or_expired`
- `403 authorization_denied`
- `403 object_scope_denied`
- `409 capability_replay_detected`

## Evidence events

Recommended append-only event types:
- `auth.session.created`
- `auth.session.rotated`
- `auth.session.invalidated`
- `capability.issued`
- `capability.used`
- `capability.denied`
- `capability.replayed`
- `proof.invalid`
- `nonce.reissued`
- `connector.scope.elevated`
- `connector.scope.revoked`

## Example BCT

```json
{
  "typ": "triticket+jwt",
  "ver": "1",
  "iss": "https://app.example",
  "sub_ref": "spref_8c7a4f2c6b8d",
  "sid_ref": "sha256:6f0c5e8b7f4a...",
  "jti": "cap_01HTR2Y6W6J0RZ8R2V2T0X6T9A",
  "iat": 1775487000,
  "nbf": 1775487000,
  "exp": 1775487060,
  "aud": "https://app.example/bff/chat/messages",
  "workspace_id": "ws_01H...",
  "authorization_details": [
    {
      "type": "trirpc",
      "action": "chat.send",
      "resource": {
        "conversation_id": "convo_01H..."
      },
      "constraints": {
        "http_method": "POST",
        "http_path": "/bff/chat/messages",
        "max_requests": 1,
        "max_output_tokens": 4096,
        "ttl_seconds": 60,
        "one_time": true
      }
    }
  ],
  "cnf": {
    "jkt": "k1T1M0vM9A8-thumbprint"
  },
  "policy": {
    "hash": "sha256:9d8e...",
    "version": "policy-2026-04-06.1"
  },
  "evidence": {
    "trace_id": "trace_01H...",
    "cairn_ref": "cairn://auth/session/rot_01H..."
  }
}
```

## Example Tri-Proof

```json
{
  "typ": "triproof+jwt",
  "ver": "1",
  "jti": "proof_01HTR2Z7A1M8P4J1X9S7R2D4E6",
  "iat": 1775487005,
  "htm": "POST",
  "htu": "https://app.example/bff/chat/messages",
  "nonce": "srv_nonce_01HTR2Z1",
  "cap_hash": "sha256:8c6a..."
}
```
