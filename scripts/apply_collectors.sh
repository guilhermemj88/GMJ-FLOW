#!/bin/sh
set -eu

COMPOSE_OVERRIDE="${1:-}"

if [ -z "$COMPOSE_OVERRIDE" ]; then
  echo "usage: scripts/apply_collectors.sh /path/to/docker-compose.collectors.yml" >&2
  exit 2
fi

if [ ! -f "$COMPOSE_OVERRIDE" ]; then
  echo "collector compose override not found: $COMPOSE_OVERRIDE" >&2
  exit 2
fi

if [ ! -f "docker-compose.yml" ]; then
  echo "docker-compose.yml not found. Run from the GMJ-FLOW project root." >&2
  exit 2
fi

docker compose -f docker-compose.yml stop pmacct pmacct-parser >/dev/null 2>&1 || true
docker compose -f docker-compose.yml -f "$COMPOSE_OVERRIDE" up -d --build
