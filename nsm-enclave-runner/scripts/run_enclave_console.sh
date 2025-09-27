#!/usr/bin/env bash
# run_enclave_console.sh
# Terminates existing enclaves, runs a new one, and opens the console.

set -euo pipefail

# --- Configuration (Can be overridden via environment variables) ---
EIF_PATH="${EIF_PATH:-enclave-runner.eif}"
CPU_COUNT="${CPU_COUNT:-1}"
MEMORY_MIB="${MEMORY_MIB:-1024}"
DEBUG_MODE="${DEBUG_MODE:-true}"

# --- Internal Variables ---
NITRO="sudo nitro-cli"
# Add `--debug-mode` flag if DEBUG_MODE is "true"
DEBUG_FLAG=""
if [[ "$DEBUG_MODE" == "true" ]]; then
  DEBUG_FLAG="--debug-mode"
fi

# --- Main Script ---

echo "==> Step 1: Terminating all existing enclaves..."
# The "|| true" ensures the script doesn't fail if there are no enclaves to terminate.
$NITRO terminate-enclave --all || true

echo ""
echo "==> Step 2: Running a new enclave from '$EIF_PATH'..."
# Use the working `nitro-cli run-enclave` command you provided.
RUN_OUT=$($NITRO run-enclave \
  --eif-path "$EIF_PATH" \
  --cpu-count "$CPU_COUNT" \
  --memory "$MEMORY_MIB" \
  $DEBUG_FLAG)

# --- Extract the Enclave ID from the output ---
echo "Parsing EnclaveID from run-enclave output..."
# Use jq to robustly parse the JSON output.
ENCLAVE_ID=$(echo "$RUN_OUT" | jq -r '.EnclaveID')

if [[ -z "$ENCLAVE_ID" ]]; then
  echo "Error: Could not find EnclaveID in run-enclave output." >&2
  exit 1
fi

echo "Successfully started enclave with ID: $ENCLAVE_ID"

echo ""
echo "==> Step 3: Opening enclave console..."
echo "Press Ctrl+A followed by C to exit the console."

# Open the console for the newly started enclave.
$NITRO console --enclave-id "$ENCLAVE_ID"
