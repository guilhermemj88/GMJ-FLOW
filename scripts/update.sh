#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

if [ ! -f .env ]; then
  cp .env.example .env
fi

git pull

compose_file_args="-f docker-compose.yml"
if [ -f docker-compose.collectors.yml ]; then
  compose_file_args="$compose_file_args -f docker-compose.collectors.yml"
fi

docker compose --env-file .env $compose_file_args up -d --build --remove-orphans
