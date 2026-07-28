#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

COMPOSE_FILE="${1:-docker-compose.collectors.yml}"
if [ ! -f "$COMPOSE_FILE" ]; then
  echo "collector compose not found: $COMPOSE_FILE" >&2
  exit 2
fi

SERVICES=$(
  docker compose --env-file .env -f "$COMPOSE_FILE" config --services \
    | awk '/^pmacct-sensor-[0-9]+$/ || /^pmacct-parser-sensor-[0-9]+$/ { print }'
)
if [ -z "$SERVICES" ]; then
  echo "no PMACCT collector services declared in $COMPOSE_FILE" >&2
  exit 2
fi

RUNNING=$(
  docker compose --env-file .env -f "$COMPOSE_FILE" ps \
    --status running --services
)

FAILED=0
for service in $SERVICES; do
  if printf '%s\n' "$RUNNING" | grep -Fx "$service" >/dev/null; then
    echo "collector active: $service"
  else
    echo "collector inactive: $service" >&2
    FAILED=1
  fi
done

exit "$FAILED"
