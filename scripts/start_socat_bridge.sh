#!/usr/bin/env bash
# Forwards host TCP port 8443 to the enclave's VSOCK port 8443 using socat.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNNER_ROOT="$REPO_ROOT/nsm-enclave-runner"
RUN_INFO_PATH="$RUNNER_ROOT/target/enclave/enclave-run.json"
PORT=8443

if [[ ! -f "$RUN_INFO_PATH" ]]; then
  echo "Run info not found at $RUN_INFO_PATH. Start an enclave first." >&2
  exit 1
fi

CID=$(jq -r '.EnclaveCID' "$RUN_INFO_PATH")

if [[ -z "$CID" || "$CID" == "null" ]]; then
  echo "Could not read EnclaveCID from $RUN_INFO_PATH" >&2
  exit 1
fi

sudo socat -d -d -v TCP-LISTEN:${PORT},reuseaddr,fork VSOCK-CONNECT:${CID}:${PORT}
