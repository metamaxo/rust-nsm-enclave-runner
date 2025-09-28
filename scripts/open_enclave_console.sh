#!/usr/bin/env bash
# Attach to the console of the most recently launched enclave.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNNER_ROOT="$REPO_ROOT/nsm-enclave-runner"
RUN_INFO_PATH="$RUNNER_ROOT/target/enclave/enclave-run.json"

if [[ ! -f "$RUN_INFO_PATH" ]]; then
  echo "Run info not found at $RUN_INFO_PATH. Start an enclave first." >&2
  exit 1
fi

ENCLAVE_ID=$(jq -r '.EnclaveID' "$RUN_INFO_PATH")

if [[ -z "$ENCLAVE_ID" || "$ENCLAVE_ID" == "null" ]]; then
  echo "Could not read EnclaveID from $RUN_INFO_PATH" >&2
  exit 1
fi

sudo nitro-cli console --enclave-id "$ENCLAVE_ID"
