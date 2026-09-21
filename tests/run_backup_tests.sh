#!/bin/bash
# Backup hardening test harness — runs against the NEW backup.sh in a sandbox.
# Usage: bash run_backup_tests.sh <path-to-new-backup.sh>
set -u
BACKUP_SRC="${1:-scripts/backup.sh}"
BACKUP_SRC=$(readlink -f "$BACKUP_SRC")
TESTROOT=$(mktemp -d /tmp/bh-tests-XXXXXX)
echo "TESTROOT=$TESTROOT"

PASS=0
FAIL=0
ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

# ---- helper: build a minimal sandbox project ----
make_sandbox() {
  local dir="$1"
  mkdir -p "$dir/scripts" "$dir/data/backend" "$dir/data/collectors" "$dir/clickhouse" "$dir/data/backups"
  cp "$BACKUP_SRC" "$dir/scripts/backup.sh"
  # tiny real sqlite db
  sqlite3 "$dir/data/backend/gmjflow.db" "CREATE TABLE t(x INTEGER); INSERT INTO t VALUES(1);" >/dev/null 2>&1
  echo "collector-config" > "$dir/data/collectors/example.yaml"
  echo "GMJFLOW_AUTH_SECRET=testsecret" > "$dir/.env"
  echo "services:" > "$dir/docker-compose.collectors.yml"
  echo "CREATE TABLE flow_raw(x Int64) ENGINE=MergeTree ORDER BY x;" > "$dir/clickhouse/init.sql"
}

# =========================================================================
# T1: bash -n syntax check
# =========================================================================
if bash -n "$BACKUP_SRC" 2>/tmp/bh_n.err; then
  ok "bash -n"
else
  bad "bash -n"; cat /tmp/bh_n.err
fi

# =========================================================================
# T2: success + recursion protection
# =========================================================================
SB="$TESTROOT/success"
make_sandbox "$SB"
# pre-seed a previous archive + marker inside data/backups (recursion fixture)
echo "PREVIOUS" > "$SB/data/backups/OLD_MARKER.txt"
(cd "$SB/data/backups" && tar -czf "gmj-flow-20200101T000000Z.tar.gz" OLD_MARKER.txt && rm -f OLD_MARKER.txt)

set +e
out=$(cd "$SB" && bash scripts/backup.sh 2>&1)
rc=$?
set -e

ARCHIVE=$(ls "$SB"/data/backups/gmj-flow-*.tar.gz 2>/dev/null | grep -v '20200101' | head -1)
WORKDIRS=$(ls -d "$SB"/data/backups/gmj-flow-*/ 2>/dev/null | head -1)
PARTS=$(ls "$SB"/data/backups/*.part 2>/dev/null | head -1)

if [ $rc -eq 0 ] && [ -n "$ARCHIVE" ] && [ -z "$WORKDIRS" ] && [ -z "$PARTS" ]; then
  ok "success: exit=0 archive created work_dir removed .part removed"
else
  bad "success (rc=$rc archive=$ARCHIVE workdir=$WORKDIRS part=$PARTS)"
  echo "$out" | tail -20
fi

if [ -n "$ARCHIVE" ]; then
  if tar -tzf "$ARCHIVE" >/dev/null 2>&1; then ok "success: archive is valid"; else bad "success: archive invalid"; fi
  if tar -tzf "$ARCHIVE" | grep -q 'manifest.txt'; then ok "success: manifest inside archive"; else bad "success: manifest missing"; fi
  if tar -tzf "$ARCHIVE" | grep -q '^\./gmjflow.db$'; then ok "success: sqlite inside"; else bad "success: sqlite missing"; fi
  # recursion: no path may contain 'backups' (data/backups, prior archive, marker)
  if tar -tzf "$ARCHIVE" | grep -qi 'backups'; then
    bad "recursion: archive contains backups path"; tar -tzf "$ARCHIVE" | grep -i backups | head
  else
    ok "recursion: no backups path in archive"
  fi
  # permissions: archive final must be private (600) — contains .env/collectors
  mode=$(stat -c %a "$ARCHIVE" 2>/dev/null)
  if [ "$mode" = "600" ]; then ok "success: archive mode=600"; else bad "success: archive mode=$mode (want 600)"; fi
fi

# =========================================================================
# T3: tar failure -> cleanup, no archive, no .part, exit preserved (7)
# =========================================================================
SB="$TESTROOT/tarfail"
make_sandbox "$SB"
mkdir -p "$SB/bin"
cat > "$SB/bin/tar" <<'EOF'
#!/bin/sh
echo "tar: simulated failure" >&2
exit 7
EOF
chmod +x "$SB/bin/tar"

set +e
(cd "$SB" && PATH="$SB/bin:$PATH" bash scripts/backup.sh >/tmp/bh_tarfail.out 2>&1)
rc=$?
set -e
WORKDIRS=$(ls -d "$SB"/data/backups/gmj-flow-*/ 2>/dev/null | head -1)
ARCHIVES=$(ls "$SB"/data/backups/gmj-flow-*.tar.gz 2>/dev/null | head -1)
PARTS=$(ls "$SB"/data/backups/*.part 2>/dev/null | head -1)
if [ $rc -eq 7 ] && [ -z "$WORKDIRS" ] && [ -z "$ARCHIVES" ] && [ -z "$PARTS" ]; then
  ok "tar failure: exit=7 preserved work_dir removed no archive no .part"
else
  bad "tar failure (rc=$rc workdir=$WORKDIRS archive=$ARCHIVES part=$PARTS)"
fi

# =========================================================================
# T4: disk preflight failure -> abort before dump, exit 2
# =========================================================================
SB="$TESTROOT/preflight"
make_sandbox "$SB"
set +e
(cd "$SB" && SAFETY_MARGIN_MB=999999999 bash scripts/backup.sh >/tmp/bh_pf.out 2>&1)
rc=$?
set -e
WORKDIRS=$(ls -d "$SB"/data/backups/gmj-flow-*/ 2>/dev/null | head -1)
ARCHIVES=$(ls "$SB"/data/backups/gmj-flow-*.tar.gz 2>/dev/null | head -1)
if [ $rc -eq 2 ] && [ -z "$WORKDIRS" ] && [ -z "$ARCHIVES" ]; then
  ok "disk preflight: exit=2 no work_dir no archive"
else
  bad "disk preflight (rc=$rc workdir=$WORKDIRS archive=$ARCHIVES)"
fi

# =========================================================================
# T5: flow_raw default EXCLUDED (fake docker records queries)
# =========================================================================
SB="$TESTROOT/flowraw"
make_sandbox "$SB"
mkdir -p "$SB/bin"
cat > "$SB/bin/docker" <<'EOF'
#!/bin/sh
echo "$@" >> "${FAKE_DOCKER_LOG:-/tmp/fake_docker.log}"
exit 0
EOF
chmod +x "$SB/bin/docker"
# default: INCLUDE_FLOW_RAW unset -> must NOT query flow_raw native
: > "$SB/docker_calls.log"
set +e
(cd "$SB" && FAKE_DOCKER_LOG="$SB/docker_calls.log" PATH="$SB/bin:$PATH" bash scripts/backup.sh >/dev/null 2>&1)
set -e
default_flowraw=$(grep -c 'FROM flow_raw FORMAT Native' "$SB/docker_calls.log" || true)
schema_calls=$(grep -c 'system.tables' "$SB/docker_calls.log" || true)
if [ "$default_flowraw" -eq 0 ] && [ "$schema_calls" -ge 1 ]; then
  ok "flow_raw default: no flow_raw export, schema captured"
else
  bad "flow_raw default (flow_raw_calls=$default_flowraw schema_calls=$schema_calls)"
fi

# opt-in: INCLUDE_FLOW_RAW=1 -> must query flow_raw native
: > "$SB/docker_calls.log"
set +e
(cd "$SB" && FAKE_DOCKER_LOG="$SB/docker_calls.log" PATH="$SB/bin:$PATH" INCLUDE_FLOW_RAW=1 bash scripts/backup.sh >/dev/null 2>&1)
set -e
on_flowraw=$(grep -c 'FROM flow_raw FORMAT Native' "$SB/docker_calls.log" || true)
if [ "$on_flowraw" -ge 1 ]; then ok "flow_raw opt-in: flow_raw export attempted"; else bad "flow_raw opt-in (flow_raw_calls=$on_flowraw)"; fi

# =========================================================================
# T6: interruption (SIGTERM during slow tar) -> cleanup
# =========================================================================
SB="$TESTROOT/interrupt"
make_sandbox "$SB"
mkdir -p "$SB/bin"
cat > "$SB/bin/tar" <<'EOF'
#!/bin/sh
sleep 30
exit 0
EOF
chmod +x "$SB/bin/tar"

# run the script in its own process group so SIGTERM reaches the whole group
setsid bash -c 'cd "$1" && exec env PATH="$1/bin:$PATH" bash scripts/backup.sh' _ "$SB" >/tmp/bh_term.out 2>&1 &
PID=$!
sleep 3
set +e
kill -TERM -- -"$PID" 2>/dev/null
wait "$PID" 2>/dev/null
rc=$?
set -e
WORKDIRS=$(ls -d "$SB"/data/backups/gmj-flow-*/ 2>/dev/null | head -1)
ARCHIVES=$(ls "$SB"/data/backups/gmj-flow-*.tar.gz 2>/dev/null | head -1)
if [ $rc -eq 143 ] && [ -z "$WORKDIRS" ] && [ -z "$ARCHIVES" ]; then
  ok "interruption: SIGTERM exit=143 cleaned work_dir no archive"
else
  bad "interruption SIGTERM (rc=$rc workdir=$WORKDIRS archive=$ARCHIVES)"
fi

# =========================================================================
# T7: interruption (SIGINT via pty, interactive Ctrl+C) -> exit 130 + cleanup
# =========================================================================
SB="$TESTROOT/sigint"
make_sandbox "$SB"
mkdir -p "$SB/bin"
cat > "$SB/bin/tar" <<'EOF'
#!/bin/sh
sleep 30
exit 0
EOF
chmod +x "$SB/bin/tar"

python3 - "$SB" <<'PY'
import os, pty, sys, time
sandbox = sys.argv[1]
os.chdir(sandbox)
env = dict(os.environ)
env["PATH"] = os.path.join(sandbox, "bin") + os.pathsep + os.environ.get("PATH", "")
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("bash", ["bash", "scripts/backup.sh"], env)
time.sleep(2.0)
os.write(fd, b"\x03")  # Ctrl+C to the pty foreground group
time.sleep(1.0)
while True:
    try:
        if not os.read(fd, 65536):
            break
    except OSError:
        break
_, status = os.waitpid(pid, 0)
with open("/tmp/bh_sigint_rc", "w") as f:
    f.write(str(os.waitstatus_to_exitcode(status)))
PY

rc=$(cat /tmp/bh_sigint_rc)
WORKDIRS=$(ls -d "$SB"/data/backups/gmj-flow-*/ 2>/dev/null | head -1)
ARCHIVES=$(ls "$SB"/data/backups/gmj-flow-*.tar.gz 2>/dev/null | head -1)
if [ $rc -eq 130 ] && [ -z "$WORKDIRS" ] && [ -z "$ARCHIVES" ]; then
  ok "interruption: SIGINT exit=130 cleaned work_dir no archive"
else
  bad "interruption SIGINT (rc=$rc workdir=$WORKDIRS archive=$ARCHIVES)"
fi

# =========================================================================
echo "========================================"
echo "RESULT: PASS=$PASS FAIL=$FAIL"
echo "========================================"
[ "$FAIL" -eq 0 ]
