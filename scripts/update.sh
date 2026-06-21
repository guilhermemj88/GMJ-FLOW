#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

if [ ! -f .env ]; then
  cp .env.example .env
fi

git pull
docker compose --env-file .env up -d --build backend frontend

if [ -f docker-compose.collectors.yml ]; then
  docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml up -d --build --remove-orphans
fi
