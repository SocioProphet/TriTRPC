# Upstream Patch Plan v0.2

1. Port `boundary` and `deployment` validators into Go/Rust-side configuration tooling.
2. Port hash-chained audit logging, keeping SHA-384 as default.
3. Add `standards-inspired` and `approved-like` build/runtime flags.
4. Make research mode impossible to select implicitly in production configs.
5. Bind the approved-like profile to the actual chosen module/runtime.
6. Regenerate repo-native vectors and tamper tests.
7. Replace placeholder topic registry with the real topic23 registry once frozen.
