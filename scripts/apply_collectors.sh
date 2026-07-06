#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

COMPOSE_OVERRIDE="${1:-docker-compose.collectors.yml}"

if [ ! -f "$COMPOSE_OVERRIDE" ]; then
  echo "collector compose override not found: $COMPOSE_OVERRIDE" >&2
  exit 2
fi

docker compose -f "$COMPOSE_OVERRIDE" config >/dev/null

SERVICES=$(
  docker compose -f "$COMPOSE_OVERRIDE" config --services \
    | awk '/^pmacct-sensor-[0-9]+$/ || /^pmacct-parser-sensor-[0-9]+$/ { print }'
)

if [ -z "$SERVICES" ]; then
  echo "no collector services found in $COMPOSE_OVERRIDE" >&2
  exit 2
fi

# Apply only runtime collector services. --no-deps prevents Compose from
# resolving dependencies outside this runtime collector compose.
docker compose -f "$COMPOSE_OVERRIDE" up -d --build --no-deps $SERVICES
