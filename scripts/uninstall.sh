#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

compose_app() {
  if [ -f .env ]; then
    docker compose --env-file .env -f docker-compose.yml "$@"
  else
    docker compose -f docker-compose.yml "$@"
  fi
}

printf '%s\n' "GMJ-FLOW application removal"
printf '%s\n' "- removes only backend and frontend containers"
printf '%s\n' "- preserves ClickHouse, all Docker volumes, .env, PMACCT and ExaBGP"
printf 'Type REMOVE APPLICATION to continue: '
read -r answer
if [ "$answer" != "REMOVE APPLICATION" ]; then
  echo "Application removal cancelled."
  exit 0
fi

printf 'Data policy [PRESERVE/DESTROY APPLICATION DATA] (default PRESERVE): '
read -r data_policy
data_policy=${data_policy:-PRESERVE}
case "$data_policy" in
  PRESERVE)
    ;;
  "DESTROY APPLICATION DATA")
    printf '%s\n' "This deletes only $PROJECT_ROOT/data/backend."
    printf '%s\n' "ClickHouse, PMACCT spool, collector configuration and Docker volumes remain."
    printf 'Type DESTROY APPLICATION DATA permanently: '
    read -r destructive_confirmation
    if [ "$destructive_confirmation" != "DESTROY APPLICATION DATA" ]; then
      echo "Destructive data removal cancelled."
      exit 0
    fi
    ;;
  *)
    echo "Unknown data policy; nothing was changed." >&2
    exit 2
    ;;
esac

if command -v systemctl >/dev/null 2>&1 \
  && systemctl cat gmj-flow.service >/dev/null 2>&1; then
  if systemctl cat gmj-flow.service 2>/dev/null \
    | grep -q 'docker-compose.collectors.yml'; then
    printf '%s\n' \
      "gmj-flow.service also owns PMACCT collectors; application removal was refused." \
      "Split collector autostart before retrying so collectors are never stopped or disabled."
    exit 4
  else
    systemctl disable gmj-flow.service >/dev/null 2>&1 || true
    printf '%s\n' \
      "gmj-flow.service was disabled without stopping it; application containers are removed explicitly below."
  fi
fi

compose_app stop backend frontend
compose_app rm -f backend frontend

if [ "$data_policy" = "DESTROY APPLICATION DATA" ]; then
  backend_data="$PROJECT_ROOT/data/backend"
  case "$backend_data" in
    "$PROJECT_ROOT"/data/backend)
      if [ -d "$backend_data" ]; then
        rm -rf -- "$backend_data"
      fi
      mkdir -p "$backend_data"
      chmod 750 "$backend_data"
      ;;
    *)
      echo "Unsafe backend data path; refusing deletion." >&2
      exit 3
      ;;
  esac
  echo "Backend/frontend removed; application state in data/backend destroyed intentionally."
else
  echo "Backend/frontend removed; data, volumes, collectors, ExaBGP and .env preserved."
fi
