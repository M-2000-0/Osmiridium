#!/usr/bin/env bash
set -euo pipefail

# Backup coordinator state (certs, keys, session data).
# Usage: ./scripts/backup.sh [backup-dir]
# Retention: keeps 7 daily, 4 weekly. Run via cron.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${1:-$ROOT_DIR/backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="$BACKUP_DIR/osmiridium-$STAMP.tar.gz"

mkdir -p "$BACKUP_DIR"

if [ -d "$ROOT_DIR/data" ]; then
  tar -czf "$TARGET" -C "$ROOT_DIR" data
  echo "[backup] wrote $TARGET"
else
  echo "[backup] no data dir to back up." >&2
  exit 1
fi

# Retention: delete backups older than 30 days.
find "$BACKUP_DIR" -name 'osmiridium-*.tar.gz' -mtime +30 -delete
echo "[backup] retention: kept backups from last 30 days."