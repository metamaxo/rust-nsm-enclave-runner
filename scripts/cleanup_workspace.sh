#!/usr/bin/env bash
# Removes extracted project artifacts so you can apply a fresh patch safely.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ITEMS=(
  "README.md"
  "tg-client.tar.gz"
  "attestation-verifier"
  "nsm-enclave-runner"
  "scripts"
)

echo "==> Cleaning workspace at $TARGET_DIR"
for item in "${ITEMS[@]}"; do
  path="$TARGET_DIR/$item"
  if [[ -e "$path" ]]; then
    rm -rf "$path"
    printf 'Removed %s\n' "$item"
  else
    printf 'Skipped %s (not present)\n' "$item"
  fi
done

echo "\nRemaining contents in $TARGET_DIR:"
ls -a "$TARGET_DIR"
