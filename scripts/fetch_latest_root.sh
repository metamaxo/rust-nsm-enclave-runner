#!/usr/bin/env bash
# Fetches the Nitro attestation root certificate from the running enclave service.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ASSETS_DIR="$REPO_ROOT/assets"
OUTPUT_PATH="$ASSETS_DIR/aws-nitro-root.pem"

for bin in curl jq python3 base64 openssl; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "\"$bin\" is required but not installed" >&2
    exit 1
  fi
done

mkdir -p "$ASSETS_DIR"

nonce=$(python3 - <<'PY'
import os, base64
print(base64.b64encode(os.urandom(32)).decode())
PY
)

echo "Requesting attestation document from https://127.0.0.1:8443/attestation"
response=$(curl -sS -k -X POST \
  -H 'content-type: application/json' \
  --data "{\"nonce_b64\": \"$nonce\"}" \
  https://127.0.0.1:8443/attestation)

if [[ -z "$response" ]]; then
  echo "Empty response from attestation endpoint" >&2
  exit 1
fi

root_b64=$(printf '%s' "$response" | jq -r '.attestation.cabundle_der_b64 | last // empty')

if [[ -z "$root_b64" ]]; then
  echo "Could not extract root certificate from attestation response" >&2
  exit 1
fi

tmp_cert=$(mktemp)
trap 'rm -f "$tmp_cert"' EXIT

printf '%s' "$root_b64" | base64 -d > "$tmp_cert"

openssl x509 -in "$tmp_cert" -noout >/dev/null 2>&1 || {
  echo "Downloaded data is not a valid X.509 certificate" >&2
  exit 1
}

mv "$tmp_cert" "$OUTPUT_PATH"

fingerprint=$(openssl x509 -in "$OUTPUT_PATH" -noout -fingerprint -sha256 | cut -d'=' -f2)

echo "Saved root certificate to $OUTPUT_PATH"
echo "SHA-256 fingerprint: $fingerprint"
