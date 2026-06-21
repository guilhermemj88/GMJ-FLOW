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

if [ ! -f "docker-compose.yml" ]; then
  echo "docker-compose.yml not found. Run from the GMJ-FLOW project root." >&2
  exit 2
fi

if [ ! -f ".env" ]; then
  echo ".env not found. Create it from .env.example before applying collectors." >&2
  exit 2
fi

docker compose --env-file .env -f docker-compose.yml -f "$COMPOSE_OVERRIDE" config >/dev/null
docker compose --env-file .env -f docker-compose.yml -f "$COMPOSE_OVERRIDE" up -d --build --remove-orphans
