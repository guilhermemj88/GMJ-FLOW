#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

if [ $# -ne 1 ]; then
  echo "usage: scripts/restore.sh data/backups/gmj-flow-YYYYmmddTHHMMSSZ.tar.gz" >&2
  exit 2
fi

backup_file="$1"
if [ ! -f "$backup_file" ]; then
  echo "backup not found: $backup_file" >&2
  exit 2
fi

printf 'Type RESTORE to restore SQLite/config files from %s: ' "$backup_file"
read -r answer
if [ "$answer" != "RESTORE" ]; then
  echo "Restore cancelled."
  exit 0
fi

timestamp=$(date -u +"%Y%m%dT%H%M%SZ")
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

tar -xzf "$backup_file" -C "$tmp_dir"

mkdir -p data/backend data/collectors

if [ -f "$tmp_dir/gmjflow.db" ]; then
  if [ -f data/backend/gmjflow.db ]; then
    cp data/backend/gmjflow.db "data/backend/gmjflow.db.pre-restore-$timestamp"
  fi
  cp "$tmp_dir/gmjflow.db" data/backend/gmjflow.db
fi

if [ -d "$tmp_dir/collectors" ]; then
  if [ -d data/collectors ]; then
    mv data/collectors "data/collectors.pre-restore-$timestamp"
  fi
  mkdir -p data/collectors
  cp -R "$tmp_dir/collectors/." data/collectors/
fi

if [ -f "$tmp_dir/docker-compose.collectors.yml" ]; then
  if [ -f docker-compose.collectors.yml ]; then
    cp docker-compose.collectors.yml "docker-compose.collectors.yml.pre-restore-$timestamp"
  fi
  cp "$tmp_dir/docker-compose.collectors.yml" docker-compose.collectors.yml
fi

if [ -f "$tmp_dir/.env" ]; then
  if [ -f .env ]; then
    cp .env ".env.pre-restore-$timestamp"
  fi
  cp "$tmp_dir/.env" .env
fi

echo "Restore finished. Restart the stack with docker compose --env-file .env up -d."
