# TriRPC Transport Profile v0.1

## Goal

Freeze the wire/encoding profile across browser, BFF, and internal services.

## Browser-facing transport

### Browser -> BFF
- Protocol: HTTPS
- Message envelope: HTTP + JSON
- Capability artifacts: JOSE / JWT serialization
- Proofs: JOSE / JWT serialization
- Session: `HttpOnly` cookie
- CSRF: synchronizer token header
- Content type: `application/json`

### Why
- Browser libraries and platform primitives are mature for JSON + JOSE.
- Simpler debugging and SSR integration.
- Avoids bespoke binary logic in the page.

## Internal service transport

### BFF -> internal services
Preferred:
- Protocol: QUIC for remote service-to-service transport
- Encoding: CBOR payloads
- Signature / proof layer: COSE
- Ticket form: compact COSE / CWT-like representation if desired

Fallback:
- UDS + CBOR + COSE for local node/service boundaries
- HTTPS + JSON + JOSE where legacy interop is required

## Design rule

External/browser transport and internal/service transport are allowed to differ.

- Browser path optimizes interoperability.
- Internal path optimizes compactness, latency, and lower parser ambiguity.

## Proposed internal profile

### Over QUIC
- stream-oriented or datagram-assisted application framing depending endpoint
- CBOR body for requests / responses
- COSE_Sign1 or equivalent proof envelope
- audience form:
  - `trirpc://agent-plane/chat.send`
  - `trirpc://graph/read.node`

### Over UDS
- local trusted channel
- CBOR body
- COSE optional if local trust boundary is already enforced by peer identity and file-system permissions,
  but strongly recommended when evidence/replay semantics matter.

## Identity/delegation layering

1. Browser authenticates to BFF with server-managed session cookie.
2. Browser presents short-lived `BCT` + `Tri-Proof`.
3. BFF verifies and mints narrower `SCT`.
4. Internal service validates `SCT` and object scope.
5. Service emits evidence and returns response.

## Algorithm profile

### Browser
- preferred: Ed25519 / EdDSA
- fallback: ES256

### Internal
- preferred: Ed25519 signatures
- optional: X25519 for session-key agreement when encrypted application subchannels are needed

## Object references

Object IDs in any transport MUST be treated as untrusted selectors.
Every service receiving them MUST enforce object-level authorization.

## Non-goals

- No generic browser bearer tokens.
- No raw connector tokens in browser payloads.
- No raw experiment lattice in browser bootstrap.
- No trust in client-declared roles or tenant identity without server verification.

## Operational notes

- Use deterministic schemas for CBOR/JSON parity.
- Keep JSON Schema and internal CBOR schema semantically aligned.
- Emit the same logical evidence events regardless of the transport form.
