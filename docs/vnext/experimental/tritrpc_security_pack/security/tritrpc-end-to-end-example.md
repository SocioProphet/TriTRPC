# TriRPC End-to-End Delegation Example v0.1

## Goal

Show the concrete transition from browser-visible `BCT` + `Tri-Proof` to a narrower downstream `SCT`
and then into an internal QUIC/UDS-style framed request body.

## Steps

1. Browser authenticates with a server-managed `HttpOnly` cookie.
2. Browser requests a short-lived Browser Capability Ticket (`BCT`) for `chat.send`.
3. Browser signs a `Tri-Proof` over:
   - request method,
   - request URL,
   - server nonce,
   - hash of the presented `BCT`.
4. BFF verifies:
   - session,
   - CSRF,
   - Origin / Fetch Metadata,
   - ticket signature and claims,
   - proof signature and claims,
   - request binding,
   - object scope.
5. BFF mints a narrower Service Capability Ticket (`SCT`) for the internal audience:
   - `trirpc://agent-plane/chat.send`
6. BFF wraps the internal request in a compact frame body and transports it over QUIC or UDS.

## Frame body shape

```json
{
  "trace_id": "trace_01HT...",
  "aud": "trirpc://agent-plane/chat.send",
  "ticket": { "... narrowed SCT claims ..." },
  "request": {
    "action": "chat.send",
    "resource": {
      "conversation_id": "convo_01HXYZ"
    }
  }
}
```

## Expected narrowing

Compared with the `BCT`, the `SCT`:
- removes browser HTTP bindings,
- shortens lifetime,
- retains only the exact internal audience,
- preserves the action and resource scope,
- carries `upstream_ref` back to the originating `BCT`.

## Verification split

- Browser/BFF boundary: JOSE + JSON + `HttpOnly` cookie + CSRF.
- BFF/service boundary: compact framed transport + CBOR logical body.
- Service still performs object-level authorization and policy checks before acting.
