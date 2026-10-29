#!/bin/bash
set -euo pipefail

# Generates the Candid JS/TS declarations (idlFactory, _SERVICE) that the example
# frontends and PocketIC tests import. Each entry is "<did file>:<output dir>".
DECLARATIONS=(
  "examples/certification/certified-counter/src/backend/backend.did:examples/certification/certified-counter/src/declarations"
  "examples/http-certification/assets/src/backend/backend.did:examples/http-certification/assets/src/declarations"
  "examples/http-certification/custom-assets/src/backend/backend.did:examples/http-certification/custom-assets/src/declarations"
  "examples/http-certification/json-api/src/backend/backend.did:examples/http-certification/json-api/src/declarations"
  "examples/http-certification/skip-certification/src/backend/backend.did:examples/http-certification/skip-certification/src/declarations"
  "examples/http-certification/upgrade-to-update-call/src/backend.did:examples/http-certification/upgrade-to-update-call/src/declarations/rust-backend"
  "examples/http-certification/upgrade-to-update-call/src/motoko-backend/backend.did:examples/http-certification/upgrade-to-update-call/src/declarations/motoko-backend"
)

for entry in "${DECLARATIONS[@]}"; do
  did_file="${entry%%:*}"
  out_dir="${entry#*:}"
  pnpm exec icp-bindgen --did-file "$did_file" --out-dir "$out_dir" \
    --actor-disabled --declarations-flat --force
done
