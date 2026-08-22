#!/usr/bin/env bash
set -euo pipefail

# Restore coordinator state from a backup archive.
# Usage: ./scripts/restore.sh backups/osmiridium-<stamp>.tar.gz

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <backup-archive>" >&2
  exit 1
fi

ARCHIVE="$1"
if [ ! -f "$ARCHIVE" ]; then
  echo "Backup archive not found: $ARCHIVE" >&2
  exit 1
fi

# Stop the stack to avoid conflicting writes.
docker compose -f "$ROOT_DIR/docker-compose.yml" down

rm -rf "$ROOT_DIR/data.bak"
[ -d "$ROOT_DIR/data" ] && mv "$ROOT_DIR/data" "$ROOT_DIR/data.bak"

tar -xzf "$ARCHIVE" -C "$ROOT_DIR"

echo "[restore] data restored from $ARCHIVE"
echo "[restore] previous state kept at data.bak — verify then delete manually."

docker compose -f "$ROOT_DIR/docker-compose.yml" up -d