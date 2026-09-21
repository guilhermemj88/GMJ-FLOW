#!/bin/bash
# GMJ-FLOW backup — hardened after the 2026-09-16 disk-full incident.
#
# Guarantees:
#   1. work_dir is always removed (trap on EXIT/INT/TERM), even on failure
#   2. path-safe rm: refuses to delete anything outside data/backups
#   3. no recursive backup: data/backups / backups never enter the archive
#   4. flow_raw is EXCLUDED by default (INCLUDE_FLOW_RAW=1 to opt in)
#   5. disk preflight aborts BEFORE any heavy dump
#   6. archive is built as .part, validated, then atomically renamed
#   7. concurrent runs are prevented with flock
#   8. no impact on Behavioral/TI runtime (read-only copies + sqlite .backup)
set -Eeuo pipefail
umask 077   # backup artifacts may hold secrets (.env, collectors) — keep private

# ---------------------------------------------------------------------------
# Tunables (overridable via environment)
# ---------------------------------------------------------------------------
INCLUDE_FLOW_RAW="${INCLUDE_FLOW_RAW:-0}"      # 1 = also export flow_raw (huge)
SAFETY_MARGIN_MB="${SAFETY_MARGIN_MB:-1024}"   # extra free space required (MiB)
KEEP_BACKUPS="${KEEP_BACKUPS:-2}"              # local retention: N most recent archives
CLICKHOUSE_DATABASE="${CLICKHOUSE_DATABASE:-flowdb}"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

timestamp=$(date -u +"%Y%m%dT%H%M%SZ")
backup_root="$PROJECT_ROOT/data/backups"
work_dir="$backup_root/gmj-flow-$timestamp"
archive_part="$backup_root/gmj-flow-$timestamp.tar.gz.part"
archive_final="$backup_root/gmj-flow-$timestamp.tar.gz"
manifest_file="$backup_root/gmj-flow-$timestamp.manifest"
lock_file="$backup_root/.backup.lock"

CURRENT_STEP="init"

# ---------------------------------------------------------------------------
# Path safety: only remove a work_dir that resolves strictly under the
# backups root and matches the canonical gmj-flow-<timestamp> pattern.
# ---------------------------------------------------------------------------
safe_remove_workdir() {
  [ -n "$work_dir" ] || return 0
  local resolved root_resolved
  resolved=$(readlink -f "$work_dir" 2>/dev/null || true)
  root_resolved=$(readlink -f "$backup_root" 2>/dev/null || true)

  # Refuse dangerous / empty / non-child paths.
  case "$resolved" in
    ""|"/"|"."|".."|"$HOME"|"$PROJECT_ROOT"|"$root_resolved") return 0 ;;
  esac

  case "$resolved" in
    "$root_resolved"/gmj-flow-*) ;;
    *) return 0 ;;
  esac

  rm -rf -- "$resolved"
}

cleanup() {
  local status=$?
  if [ -n "${work_dir:-}" ] && [ -d "$work_dir" ]; then
    safe_remove_workdir
  fi
  if [ "$status" -ne 0 ]; then
    rm -f -- "$archive_part" 2>/dev/null || true
    echo "BACKUP_FAILED STEP=$CURRENT_STEP EXIT_CODE=$status CLEANUP_DONE=yes" >&2
  else
    log "CLEANUP_DONE"
  fi
  return "$status"
}
# Run a long-running command in the foreground, preserving its exit status while
# translating a signal-killed child (exit >= 128) into the canonical exit code.
# In non-interactive shells bash does not deliver SIGINT traps (platform
# limitation), so the INT trap below covers interactive use (real Ctrl+C) and
# this check covers observable signal-death cases (SIGTERM/SIGHUP/etc.).
run_heavy() {
  set +e
  "$@"
  local rc=$?
  set -e
  if [ "$rc" -ge 128 ] && [ "$rc" -le 192 ]; then
    exit "$rc"
  fi
  return "$rc"
}

trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Concurrency lock
# ---------------------------------------------------------------------------
mkdir -p "$backup_root"
CURRENT_STEP="lock"
exec 9>"$lock_file"
if ! flock -n 9; then
  echo "BACKUP_FAILED STEP=lock EXIT_CODE=1 CLEANUP_DONE=yes reason=another_backup_running" >&2
  exit 1
fi

log "BACKUP_START timestamp=$timestamp include_flow_raw=$INCLUDE_FLOW_RAW"

# ---------------------------------------------------------------------------
# Disk preflight: abort BEFORE any heavy dump.
# ---------------------------------------------------------------------------
CURRENT_STEP="preflight"
free_kb=$(df -P -k "$PROJECT_ROOT" 2>/dev/null | awk 'NR==2 {print $4}')
case "$free_kb" in ''|*[!0-9]*) free_kb=0;; esac
free_bytes=$((free_kb * 1024))

sqlite_bytes=0; collectors_bytes=0; config_bytes=0
[ -f data/backend/gmjflow.db ] && sqlite_bytes=$(stat -c %s data/backend/gmjflow.db 2>/dev/null || echo 0)
if [ -d data/collectors ]; then
  collectors_bytes=$(du -sb data/collectors 2>/dev/null | cut -f1 || echo 0)
  case "$collectors_bytes" in ''|*[!0-9]*) collectors_bytes=0;; esac
fi
for f in docker-compose.collectors.yml .env clickhouse/init.sql; do
  if [ -f "$f" ]; then
    s=$(stat -c %s "$f" 2>/dev/null || echo 0)
    config_bytes=$((config_bytes + s))
  fi
done

# Payload (uncompressed) + archive overhead (~1.5x payload).
payload_bytes=$((sqlite_bytes + collectors_bytes + config_bytes))
estimate_bytes=$(((payload_bytes * 5) / 2))
margin_bytes=$((SAFETY_MARGIN_MB * 1024 * 1024))

flow_raw_estimate_bytes=0
if [ "$INCLUDE_FLOW_RAW" = "1" ]; then
  CURRENT_STEP="preflight_flow_raw"
  ch_bytes=$(docker compose --env-file .env exec -T clickhouse clickhouse-client \
    --database "$CLICKHOUSE_DATABASE" \
    --query "SELECT sum(bytes_on_disk) FROM system.parts WHERE database='$CLICKHOUSE_DATABASE' AND table='flow_raw' AND active" \
    2>/dev/null | tr -d '[:space:]' || true)
  case "$ch_bytes" in ''|*[!0-9]*) ch_bytes=0;; esac
  flow_raw_estimate_bytes=$((ch_bytes * 20))   # Native format expands ~20x vs on-disk
  estimate_bytes=$((estimate_bytes + flow_raw_estimate_bytes))
fi

required_bytes=$((estimate_bytes + margin_bytes))

if [ "$free_bytes" -lt "$required_bytes" ]; then
  echo "BACKUP_FAILED STEP=preflight EXIT_CODE=2 CLEANUP_DONE=yes" >&2
  echo "  free_bytes=$free_bytes required_bytes=$required_bytes payload=$payload_bytes flow_raw_est=$flow_raw_estimate_bytes margin=$margin_bytes" >&2
  exit 2
fi
log "PREFLIGHT_OK free_bytes=$free_bytes required_bytes=$required_bytes"

# ---------------------------------------------------------------------------
# Stage work_dir
# ---------------------------------------------------------------------------
CURRENT_STEP="stage"
mkdir -p "$work_dir"

if [ -f data/backend/gmjflow.db ]; then
  CURRENT_STEP="sqlite"
  # WAL-safe: use the online backup API (never `cp` a live .db with -wal).
  run_heavy sqlite3 data/backend/gmjflow.db ".backup '$work_dir/gmjflow.db'"
  integrity=$(sqlite3 "$work_dir/gmjflow.db" 'PRAGMA quick_check;' 2>&1 || true)
  if [ "$integrity" != "ok" ]; then
    echo "ERROR: SQLite backup integrity check failed: $integrity" >&2
    exit 1
  fi
  log "SQLITE_DONE bytes=$(stat -c %s "$work_dir/gmjflow.db" 2>/dev/null || echo 0)"
fi

if [ -d data/collectors ]; then
  CURRENT_STEP="collectors"
  mkdir -p "$work_dir/collectors"
  cp -R data/collectors/. "$work_dir/collectors/"
fi

for f in docker-compose.collectors.yml .env clickhouse/init.sql; do
  if [ -f "$f" ]; then
    CURRENT_STEP="config"
    mkdir -p "$work_dir/$(dirname "$f")"
    cp "$f" "$work_dir/$f"
  fi
done

# ClickHouse schema reference (cheap metadata; raw data is reconstructable).
if docker compose --env-file .env ps --status running clickhouse >/dev/null 2>&1; then
  CURRENT_STEP="clickhouse_schema"
  mkdir -p "$work_dir/clickhouse"
  docker compose --env-file .env exec -T clickhouse clickhouse-client \
    --database "$CLICKHOUSE_DATABASE" \
    --query "SELECT name, create_table_query FROM system.tables WHERE database='$CLICKHOUSE_DATABASE' ORDER BY name FORMAT TSVRaw" \
    > "$work_dir/clickhouse/schema.tsv" 2>/dev/null || true
  if [ "$INCLUDE_FLOW_RAW" = "1" ]; then
    CURRENT_STEP="clickhouse_flow_raw"
    if ! run_heavy docker compose --env-file .env exec -T clickhouse clickhouse-client \
      --database "$CLICKHOUSE_DATABASE" \
      --query "SELECT * FROM flow_raw FORMAT Native" \
      > "$work_dir/clickhouse/flow_raw.native" 2>/dev/null; then
      echo "ERROR: flow_raw export failed" >&2
      exit 1
    fi
  fi
  log "CLICKHOUSE_DONE include_flow_raw=$INCLUDE_FLOW_RAW"
fi

# ---------------------------------------------------------------------------
# Manifest (kept small; never logs secrets)
# ---------------------------------------------------------------------------
CURRENT_STEP="manifest"
{
  echo "timestamp=$timestamp"
  echo "git_commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "sqlite_included=$([ -f data/backend/gmjflow.db ] && echo yes || echo no)"
  echo "sqlite_bytes=$sqlite_bytes"
  echo "collectors_bytes=$collectors_bytes"
  echo "clickhouse_schema_included=$([ -d "$work_dir/clickhouse" ] && echo yes || echo no)"
  echo "flow_raw_included=$([ "$INCLUDE_FLOW_RAW" = "1" ] && echo yes || echo no)"
  echo "archive=$archive_final"
} > "$work_dir/manifest.txt"

# ---------------------------------------------------------------------------
# Archive: .part -> validate -> atomic rename
# ---------------------------------------------------------------------------
CURRENT_STEP="archive"
run_heavy tar -czf "$archive_part" -C "$work_dir" \
  --exclude='./data/backups' \
  --exclude='./backups' \
  --exclude='./*.tar.gz' \
  --exclude='./*.tar.gz.part' \
  .

chmod 600 "$archive_part"

CURRENT_STEP="archive_validate"
if ! run_heavy tar -tzf "$archive_part" >/dev/null 2>&1; then
  echo "ERROR: archive validation failed" >&2
  exit 1
fi
log "ARCHIVE_VALID bytes=$(stat -c %s "$archive_part" 2>/dev/null || echo 0)"

mv -f -- "$archive_part" "$archive_final"
chmod 600 "$archive_final"
log "BACKUP_SUCCESS archive=$archive_final bytes=$(stat -c %s "$archive_final" 2>/dev/null || echo 0)"

# ---------------------------------------------------------------------------
# Retention: only canonical gmj-flow-*.tar.gz files (never work_dirs/.part).
# ---------------------------------------------------------------------------
CURRENT_STEP="retention"
ls -1t "$backup_root"/gmj-flow-*.tar.gz 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -f

# Copy the manifest alongside the archive for convenient inspection.
cp -f "$work_dir/manifest.txt" "$manifest_file" 2>/dev/null || true

echo "Backup created: $archive_final"
