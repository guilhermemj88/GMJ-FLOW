#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

printf 'Type UNINSTALL to stop GMJ-FLOW containers and disable systemd service: '
read -r answer
if [ "$answer" != "UNINSTALL" ]; then
  echo "Uninstall cancelled."
  exit 0
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now gmj-flow.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/gmj-flow.service
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

printf 'Type DELETE DATA to also remove Docker volumes and ./data: '
read -r delete_data
if [ "$delete_data" = "DELETE DATA" ]; then
  if [ -f .env ]; then
    docker compose --env-file .env down -v --remove-orphans || true
  else
    docker compose down -v --remove-orphans || true
  fi
  rm -rf "$PROJECT_ROOT/data"
  rm -f "$PROJECT_ROOT/docker-compose.collectors.yml"
  echo "GMJ-FLOW containers, volumes, and data removed."
else
  if [ -f .env ]; then
    docker compose --env-file .env down --remove-orphans || true
  else
    docker compose down --remove-orphans || true
  fi
  echo "GMJ-FLOW containers stopped. Data was preserved."
fi
