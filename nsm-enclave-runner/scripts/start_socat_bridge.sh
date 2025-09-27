#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8443}"
CID="${CID:-}"
DAEMON="false"

usage() {
  echo "Usage:"
  echo "  CID=<enclave_cid> [PORT=8443] $0 [--daemon]"
  echo
  echo "Examples:"
  echo "  CID=21 $0              # foreground, port 8443"
  echo "  CID=21 PORT=9443 $0    # foreground, port 9443"
  echo "  CID=21 $0 --daemon     # background with logs + pid"
}

if [[ "${1:-}" == "--help" ]]; then usage; exit 0; fi
if [[ "${1:-}" == "--daemon" ]]; then DAEMON="true"; fi

if [[ -z "$CID" ]]; then
  echo "CID not set. Try: CID=\$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID') $0"
  exit 1
fi

echo "==> stopping systemd vsock-proxy if present"
sudo systemctl stop vsock-proxy 2>/dev/null || true

echo "==> killing any existing vsock-proxy / socat on :$PORT"
sudo pkill -f 'vsock-proxy' || true
sudo pkill -f "socat.*TCP-LISTEN:${PORT}" || true

echo "==> checking if port :$PORT is free"
if sudo ss -lntp | grep -q ":${PORT}\\b"; then
  echo "ERROR: something is already listening on :$PORT"
  sudo ss -lntp | grep ":${PORT}\\b" || true
  exit 2
else
  echo "port $PORT is free"
fi

if [[ "$DAEMON" == "true" ]]; then
  LOG="/var/log/socat-bridge-${PORT}.log"
  PID="/run/socat-bridge-${PORT}.pid"
  echo "==> starting socat bridge in background: host:${PORT} -> cid:${CID}:${PORT}"
  sudo nohup socat TCP-LISTEN:${PORT},fork,reuseaddr VSOCK-CONNECT:${CID}:${PORT} \
    >"$LOG" 2>&1 < /dev/null &
  echo $! | sudo tee "$PID" >/dev/null
  echo "✅ socat bridge running"
  echo "   logs: $LOG"
  echo "   pid : $PID"
else
  echo "==> starting socat bridge (FOREGROUND): host:${PORT} -> cid:${CID}:${PORT}"
  echo "Press Ctrl+C to stop."
  sudo socat -d -d -v TCP-LISTEN:${PORT},reuseaddr,fork VSOCK-CONNECT:${CID}:${PORT}
fi
