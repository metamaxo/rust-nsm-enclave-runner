#!/usr/bin/env bash
# Runs the attestation verifier against the enclave's public endpoint.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNNER_ROOT="$REPO_ROOT/nsm-enclave-runner"
VERIFIER_ROOT="$REPO_ROOT/attestation-verifier"
OUT_DIR="$RUNNER_ROOT/target/enclave"

export NITRO_ROOT_PEM_PATH="$OUT_DIR/nitro-root.pem"
export NITRO_MEASUREMENTS_PATH="$OUT_DIR/enclave-runner-measurements.json"
export NITRO_EXPECTED_PCRS_PATH="$OUT_DIR/enclave-runner-expected-pcrs.json"

if [[ ! -f "$NITRO_ROOT_PEM_PATH" ]]; then
  echo "Nitro root certificate missing at $NITRO_ROOT_PEM_PATH. Re-run scripts/build_enclave.sh." >&2
  exit 1
fi

cargo run --manifest-path "$VERIFIER_ROOT/Cargo.toml"
