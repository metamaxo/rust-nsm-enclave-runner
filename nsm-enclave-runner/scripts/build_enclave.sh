#!/usr/bin/env bash
# build_enclave.sh
# Build the enclave Docker image and produce an EIF with nitro-cli.

set -euo pipefail

# Defaults (override via env or CLI flags)
DOCKERFILE="${DOCKERFILE:-Dockerfile.enclave}"
IMAGE_TAG="${IMAGE_TAG:-enclave-runner:enclave}"
EIF_OUT="${EIF_OUT:-enclave-runner.eif}"

print_usage() {
  cat <<EOF
Usage: $(basename "$0") [-f Dockerfile] [-t image:tag] [-o output.eif]

Options:
  -f  Path to Dockerfile for enclave build (default: ${DOCKERFILE})
  -t  Docker image tag to build (default: ${IMAGE_TAG})
  -o  Output EIF filename (default: ${EIF_OUT})

Env overrides:
  DOCKERFILE, IMAGE_TAG, EIF_OUT
EOF
}

# Parse flags
while getopts ":f:t:o:h" opt; do
  case "$opt" in
  f) DOCKERFILE="$OPTARG" ;;
  t) IMAGE_TAG="$OPTARG" ;;
  o) EIF_OUT="$OPTARG" ;;
  h)
    print_usage
    exit 0
    ;;
  \?)
    echo "Invalid option: -$OPTARG" >&2
    print_usage
    exit 2
    ;;
  esac
done

# Checks
command -v docker >/dev/null 2>&1 || {
  echo "Error: docker not found in PATH"
  exit 1
}
command -v nitro-cli >/dev/null 2>&1 || {
  echo "Error: nitro-cli not found in PATH"
  exit 1
}

if [[ ! -f "$DOCKERFILE" ]]; then
  echo "Error: Dockerfile '$DOCKERFILE' not found."
  exit 1
fi

echo "==> Building Docker image: ${IMAGE_TAG} (Dockerfile: ${DOCKERFILE})"
docker build -f "$DOCKERFILE" -t "$IMAGE_TAG" .

# Use sudo for nitro-cli if not root and sudo is available
NITRO="nitro-cli"
if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    NITRO="sudo nitro-cli"
  else
    echo "Warning: running nitro-cli without sudo (you might need root privileges)."
  fi
fi

echo "==> Building EIF: ${EIF_OUT} from image ${IMAGE_TAG}"
$NITRO build-enclave --docker-uri "$IMAGE_TAG" --output-file "$EIF_OUT"

echo "==> Done."
echo "Image: ${IMAGE_TAG}"
echo "EIF:   ${EIF_OUT}"
