# TriTRPC Path-H parity harnesses

Plain-English glossary:

- **parity harness**: a tiny program that re-encodes known events and proves the bytes match the saved fixtures.
- **fixture**: a known-good saved example.
- **canonical**: the same meaning always turns into the same bytes.

## Files

- `tritrpc_path_h_go_parity.go` — standalone Go parity harness.
- `tritrpc_path_h_rust_parity/` — Cargo project for a Rust parity harness.
- `tritrpc_path_h_fixtures.json` — the five draft Path-H fixtures.
- `tritrpc_path_h_reference.py` — Python reference encoder used to create the fixtures.

## Go

Run:

```bash
go run tritrpc_path_h_go_parity.go tritrpc_path_h_fixtures.json
```

Expected output:

```text
PASS PAIR.OPEN
PASS PAIR.HERALD
PASS TELEPORT.BSM3
PASS FRAME.DEFER
PASS WITNESS.REPORT
```

## Rust

Run from the `tritrpc_path_h_rust_parity/` directory:

```bash
cargo run -- ../tritrpc_path_h_fixtures.json
```

## Important note

The current fixtures use a **deterministic draft tag** based on `HMAC-SHA256(test_key)[:16]` only so fixture bytes stay stable during design. That tag is **not** the final protocol commitment for any production profile.
