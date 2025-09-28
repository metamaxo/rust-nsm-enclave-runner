#!/usr/bin/env bash
# Builds the enclave runner container image and corresponding EIF artifact.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNNER_ROOT="$REPO_ROOT/nsm-enclave-runner"
OUT_DIR="$RUNNER_ROOT/target/enclave"
DOCKERFILE="$RUNNER_ROOT/Dockerfile.enclave"
IMAGE_TAG="enclave-runner:enclave"
EIF_PATH="$OUT_DIR/enclave-runner.eif"
MEASUREMENTS_PATH="$OUT_DIR/enclave-runner-measurements.json"
PCRS_PATH="$OUT_DIR/enclave-runner-expected-pcrs.json"
BUNDLED_ROOT_CERT="$REPO_ROOT/assets/aws-nitro-root.pem"
ROOT_CERT_DEST="$OUT_DIR/nitro-root.pem"
EXPECTED_ROOT_FINGERPRINT="64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B"

if [[ ! -f "$BUNDLED_ROOT_CERT" ]]; then
  echo "Bundled Nitro root certificate missing at $BUNDLED_ROOT_CERT" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

printf '==> Building enclave image (%s)\n' "$IMAGE_TAG"
docker build -f "$DOCKERFILE" -t "$IMAGE_TAG" "$RUNNER_ROOT"

printf '==> Building EIF (%s)\n' "$EIF_PATH"
sudo nitro-cli build-enclave \
  --docker-uri "$IMAGE_TAG" \
  --output-file "$EIF_PATH"

DESC_JSON="$(sudo nitro-cli describe-eif --eif-path "$EIF_PATH")"
printf '%s\n' "$DESC_JSON" | jq '.' > "$MEASUREMENTS_PATH"
printf '%s\n' "$DESC_JSON" | jq '{
  pcr0: .Measurements.PCR0,
  pcr1: .Measurements.PCR1,
  pcr2: .Measurements.PCR2,
  hash_algorithm: .Measurements.HashAlgorithm
}' > "$PCRS_PATH"

printf '==> Staging bundled Nitro root certificate to %s\n' "$ROOT_CERT_DEST"
cp "$BUNDLED_ROOT_CERT" "$ROOT_CERT_DEST"

fingerprint=$(openssl x509 -noout -fingerprint -sha256 -in "$ROOT_CERT_DEST" | cut -d'=' -f2)
printf '==> Nitro root SHA-256 fingerprint: %s\n' "$fingerprint"

if [[ -n "$EXPECTED_ROOT_FINGERPRINT" && "$fingerprint" != "$EXPECTED_ROOT_FINGERPRINT" ]]; then
  echo "Fingerprint mismatch! Expected $EXPECTED_ROOT_FINGERPRINT" >&2
  exit 1
fi

printf '\nArtifacts written to %s:\n' "$OUT_DIR"
ls -1 "$OUT_DIR"
