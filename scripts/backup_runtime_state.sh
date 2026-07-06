#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

STAMP=$(date +"%Y-%m-%d_%H%M%S")
OUT="${1:-runtime-backup-$STAMP.tar.gz}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/runtime-backup"

copy_if_exists() {
  src="$1"
  dst="$TMPDIR/runtime-backup/$2"
  if [ -e "$src" ]; then
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
  fi
}

copy_if_exists "data/backend/gmjflow.db" "data/backend/gmjflow.db"
copy_if_exists "data/backend/gmjflow.db-wal" "data/backend/gmjflow.db-wal"
copy_if_exists "data/backend/gmjflow.db-shm" "data/backend/gmjflow.db-shm"
copy_if_exists "data/collectors" "data/collectors"
copy_if_exists "docker-compose.collectors.yml" "docker-compose.collectors.yml"
copy_if_exists ".env" ".env"
copy_if_exists "frontend/nginx.conf" "frontend/nginx.conf"

tar -czf "$OUT" -C "$TMPDIR" runtime-backup
echo "$OUT"
