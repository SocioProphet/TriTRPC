

### Build the ports
- Rust: `cd rust/tritrpc_v1 && cargo test`
- Go: `cd go/tritrpcv1 && go test`


### Fixture verification
- Rust: `cargo test -p tritrpc_v1` validates AEAD tags using `.nonces` and checks Avro payload bytes for key frames.
- Go: `cd go/tritrpcv1 && go test` performs the same validations.


### CLI tools
- Rust: `cargo run -p tritrpc_v1 --bin trpc -- pack --service hyper.v1 --method AddVertex_a.REQ --json payload.json --nonce <hex> --key <hex>`
- Go: `cd go/tritrpcv1/cmd/trpc && go build && ./trpc verify --fixtures ../../fixtures/vectors_hex_unary_rich.txt --nonces ../../fixtures/vectors_hex_unary_rich.txt.nonces`


## Path-B (ternary) vectors (toy subset)
See `fixtures/vectors_hex_pathB.txt` (+ `.nonces`). These use ternary-native encodings (TLEB3 lengths, balanced-ternary ints) and are AEAD-authenticated like Path-A.

## CI
A GitHub Actions workflow is included in `.github/workflows/ci.yml` to run `cargo test` and `go test` on push/PR.


## Release workflow
- On tag push (`v*`), builds Rust + Go CLIs, zips them with fixtures, and attaches to the GitHub Release.
- See `.github/workflows/release.yml`.

## Repack check
- CI job `repack-check` rebuilds a canonical AddVertex_a frame with Rust and Go CLIs and diffs it against fixtures.


## Pre-commit hook (strict AEAD verification)
To prevent committing drifted fixtures, enable the pre-commit hook that re-computes **XChaCha20-Poly1305** tags for every `fixtures/*.txt` line using the paired `.nonces`:

```bash
pip install cryptography   # required for local verification
bash scripts/install_hooks.sh
# try a commit; it will refuse if any tag mismatches its AAD+nonce
```

If you need to refresh tags intentionally, run:
```bash
python tools/regenerate_aead_tags.py
```
