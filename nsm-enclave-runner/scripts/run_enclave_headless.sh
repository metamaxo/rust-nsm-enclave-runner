#!/usr/bin/env bash
# run_enclave_headless.sh
# Terminates existing enclaves and runs a new one (no console, no debug).

set -euo pipefail

# --- Configuration (override via env vars if you like) ---
EIF_PATH="${EIF_PATH:-enclave-runner.eif}"
CPU_COUNT="${CPU_COUNT:-1}"
MEMORY_MIB="${MEMORY_MIB:-1024}"

# Verifier-compatible env vars / outputs
# NITRO_ROOT_PEM_PATH is NOT created here; your verifier just reads it.
EIF_BASENAME="$(basename "$EIF_PATH")"
EIF_STEM="${EIF_BASENAME%.*}"
NITRO_MEASUREMENTS_PATH="${NITRO_MEASUREMENTS_PATH:-${EIF_STEM}-measurements.json}"
NITRO_EXPECTED_PCRS_PATH="${NITRO_EXPECTED_PCRS_PATH:-${EIF_STEM}-expected-pcrs.json}"

# --- Internal ---
NITRO="sudo nitro-cli"

echo "==> Step 0: Saving EIF measurements to files..."
DESC="$($NITRO describe-eif --eif-path "$EIF_PATH")"
echo "$DESC" | jq . > "$NITRO_MEASUREMENTS_PATH"
echo "$DESC" | jq '{
  pcr0: .Measurements.PCR0,
  pcr1: .Measurements.PCR1,
  pcr2: .Measurements.PCR2,
  hash_algorithm: .Measurements.HashAlgorithm
}' > "$NITRO_EXPECTED_PCRS_PATH"

echo "   Wrote: $NITRO_MEASUREMENTS_PATH   (full describe-eif)"
echo "   Wrote: $NITRO_EXPECTED_PCRS_PATH  (compact PCRs)"

echo ""
echo "==> Step 1: Terminating all existing enclaves..."
$NITRO terminate-enclave --all || true

echo ""
echo "==> Step 2: Running new enclave from '$EIF_PATH' (cpu=$CPU_COUNT, mem=${MEMORY_MIB}MiB) ..."
RUN_OUT=$($NITRO run-enclave \
  --eif-path "$EIF_PATH" \
  --cpu-count "$CPU_COUNT" \
  --memory "$MEMORY_MIB")

echo "==> run-enclave output:"
echo "$RUN_OUT" | jq .

ENCLAVE_ID=$(echo "$RUN_OUT" | jq -r '.EnclaveID')
ENCLAVE_CID=$(echo "$RUN_OUT" | jq -r '.EnclaveCID')

if [[ -z "$ENCLAVE_ID" || "$ENCLAVE_ID" == "null" ]]; then
  echo "Error: Could not parse EnclaveID from run-enclave output." >&2
  exit 1
fi

echo ""
echo "✅ Enclave started."
echo "   EnclaveID: $ENCLAVE_ID"
echo "   EnclaveCID: ${ENCLAVE_CID:-unknown}"

echo ""
echo "==> Current enclaves:"
$NITRO describe-enclaves
