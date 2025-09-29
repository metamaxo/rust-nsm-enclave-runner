#!/usr/bin/env bash
# Stops running enclaves, kills the socat bridge, and removes generated artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

step() {
  printf '\n==> %s\n' "$1"
}

stop_socat() {
  step "Stopping socat bridge if running"
  if pkill -f 'socat.*VSOCK-CONNECT' 2>/dev/null; then
    echo "Killed socat processes"
  else
    echo "No socat bridge detected"
  fi
}

stop_enclaves() {
  step "Terminating running enclaves"
  if nitro-cli terminate-enclave --all >/dev/null 2>&1; then
    echo "Terminated enclaves"
  else
    echo "No enclaves running or nitro-cli unavailable"
  fi
}

remove_generated() {
  step "Removing generated artifacts"
  rm -rf \
    "$REPO_ROOT/nsm-enclave-runner/target/enclave" \
    "$REPO_ROOT/nsm-enclave-runner/target/debug" \
    "$REPO_ROOT/nsm-enclave-runner/target/release" \
    "$REPO_ROOT/attestation-verifier/target" \
    "$REPO_ROOT/logs"
}

stop_socat
stop_enclaves
remove_generated

step "Cleanup complete"
