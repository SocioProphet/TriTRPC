#!/usr/bin/env bash
set -euo pipefail

ANCHOR_SHA="1d13590c1b8f7a82f032d29572aaa0f58a6a9ffc"
BASE_URL="https://raw.githubusercontent.com/SocioProphet/TriTRPC/${ANCHOR_SHA}"

FILES=(
  "go/tritrpcv1/fixtures_test.go"
  "go/tritrpcv1/pathb_dec.go"
  "go/tritrpcv1/tleb3.go"
  "rust/tritrpc_v1/src/lib.rs"
  "rust/tritrpc_v1/tests/fixtures.rs"
)

for path in "${FILES[@]}"; do
  mkdir -p "$(dirname "$path")"
  curl -fsSL "${BASE_URL}/${path}" -o "$path"
  echo "restored ${path} from ${ANCHOR_SHA}"
done
