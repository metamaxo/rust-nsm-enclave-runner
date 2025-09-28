#!/usr/bin/env bash
# Terminates any running enclaves and launches a fresh instance from the built EIF.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNNER_ROOT="$REPO_ROOT/nsm-enclave-runner"
OUT_DIR="$RUNNER_ROOT/target/enclave"
EIF_PATH="$OUT_DIR/enclave-runner.eif"
RUN_INFO_PATH="$OUT_DIR/enclave-run.json"
CPU_COUNT=1
MEMORY_MIB=1024

if [[ ! -f "$EIF_PATH" ]]; then
  echo "Enclave EIF not found at $EIF_PATH. Run scripts/build_enclave.sh first." >&2
  exit 1
fi

sudo nitro-cli terminate-enclave --all >/dev/null 2>&1 || true

RUN_OUTPUT=$(sudo nitro-cli run-enclave \
  --eif-path "$EIF_PATH" \
  --cpu-count "$CPU_COUNT" \
  --memory "$MEMORY_MIB")

echo "$RUN_OUTPUT" | jq '.'

echo "$RUN_OUTPUT" > "$RUN_INFO_PATH"

ENCLAVE_ID=$(echo "$RUN_OUTPUT" | jq -r '.EnclaveID')
ENCLAVE_CID=$(echo "$RUN_OUTPUT" | jq -r '.EnclaveCID')

printf '\nEnclave started.\n  EnclaveID: %s\n  EnclaveCID: %s\n' "$ENCLAVE_ID" "$ENCLAVE_CID"
