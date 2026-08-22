#!/usr/bin/env bash
set -euo pipefail

# One-command deploy for Osmiridium (coordinator + monitoring).
# Usage:
#   ./scripts/deploy.sh            # build + start stack
#   ./scripts/deploy.sh --pull     # pull prebuilt image from GHCR
#   ./scripts/deploy.sh --status   # show stack status
#   ./scripts/deploy.sh --down     # stop the stack

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

ENV_FILE=".env"
if [ ! -f "$ENV_FILE" ]; then
  cp .env.example "$ENV_FILE"
  echo "[deploy] created $ENV_FILE from .env.example — set OSMOSMPC_API_KEY before exposing publicly."
fi

# shellcheck disable=SC1091
source "$ENV_FILE"

IMAGE="${IMAGE_NAMESPACE:-M-2000-0/Osmiridium}:latest"

case "${1:-}" in
  --status)
    docker compose ps
    exit 0
    ;;
  --down)
    docker compose down
    exit 0
    ;;
  --pull)
    docker login ghcr.io -u "$GHCR_USER" -p "$GHCR_TOKEN"
    docker pull "ghcr.io/$IMAGE"
    sed -i "s|^#IMAGE=|IMAGE=ghcr.io/|" "$ENV_FILE" || true
    IMAGE="ghcr.io/$IMAGE"
    ;;
  *)
    echo "[deploy] building image (local)..."
    ;;
esac

echo "[deploy] starting stack..."
docker compose up -d --remove-orphans

echo "[deploy] waiting for coordinator health..."
for i in $(seq 1 30); do
  if curl -fsS "http://localhost:${API_PORT:-8080}/health" >/dev/null 2>&1; then
    echo "[deploy] coordinator is healthy."
    docker compose ps
    exit 0
  fi
  sleep 2
done

echo "[deploy] coordinator failed to become healthy within 60s." >&2
docker compose ps
docker compose logs coord
exit 1