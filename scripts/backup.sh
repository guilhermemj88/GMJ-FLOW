#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

timestamp=$(date -u +"%Y%m%dT%H%M%SZ")
backup_dir="data/backups"
work_dir="$backup_dir/gmj-flow-$timestamp"
archive="$backup_dir/gmj-flow-$timestamp.tar.gz"

mkdir -p "$work_dir"

if [ -f data/backend/gmjflow.db ]; then
  # WAL-safe: NUNCA usar `cp` simples do .db (ignora o -wal e produz snapshot
  # inconsistente/corrompido). A API online `.backup` gera um snapshot válido.
  sqlite3 data/backend/gmjflow.db ".backup '$work_dir/gmjflow.db'"
  integrity=$(sqlite3 "$work_dir/gmjflow.db" 'PRAGMA quick_check;' 2>&1 || true)
  if [ "$integrity" != "ok" ]; then
    echo "ERROR: SQLite backup integrity check failed: $integrity" >&2
    exit 1
  fi
fi

if [ -d data/collectors ]; then
  mkdir -p "$work_dir/collectors"
  cp -R data/collectors/. "$work_dir/collectors/"
fi

if [ -f docker-compose.collectors.yml ]; then
  cp docker-compose.collectors.yml "$work_dir/docker-compose.collectors.yml"
fi

if [ -f .env ]; then
  cp .env "$work_dir/.env"
fi

if [ -f clickhouse/init.sql ]; then
  mkdir -p "$work_dir/clickhouse"
  cp clickhouse/init.sql "$work_dir/clickhouse/init.sql"
fi

if [ -f .env ] && docker compose --env-file .env ps --status running clickhouse >/dev/null 2>&1; then
  clickhouse_db=$(grep '^CLICKHOUSE_DATABASE=' .env | tail -n 1 | cut -d= -f2- || true)
  clickhouse_db=${clickhouse_db:-flowdb}
  mkdir -p "$work_dir/clickhouse"
  docker compose --env-file .env exec -T clickhouse clickhouse-client \
    --database "$clickhouse_db" \
    --query "SHOW CREATE TABLE flow_raw" \
    > "$work_dir/clickhouse/flow_raw.schema.sql" 2>/dev/null || true
  docker compose --env-file .env exec -T clickhouse clickhouse-client \
    --database "$clickhouse_db" \
    --query "SELECT * FROM flow_raw FORMAT Native" \
    > "$work_dir/clickhouse/flow_raw.native" 2>/dev/null || true
fi

tar -czf "$archive" -C "$work_dir" .
rm -rf "$work_dir"

# Retenção local: manter apenas os 2 backups .tar.gz mais recentes.
# (histórico maior deve ficar em destino externo, quando disponível).
ls -1t "$backup_dir"/gmj-flow-*.tar.gz 2>/dev/null | tail -n +3 | xargs -r rm -f

echo "Backup created: $archive"
