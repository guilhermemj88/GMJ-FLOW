#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
AI_PROFILE=""
WITH_EXABGP=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) shift; [ "${1:-}" = "ai" ] && AI_PROFILE="--profile ai" ;;
    --with-exabgp) WITH_EXABGP=true ;;
    --project-dir) shift; PROJECT_DIR="${1:-$PROJECT_DIR}" ;;
    -h|--help) echo "Uso: $0 [--profile ai] [--with-exabgp] [--project-dir DIR]"; exit 0 ;;
    *) echo "Argumento invalido: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Execute com sudo/root." >&2
  exit 1
fi

EXABGP_COMPOSE_FILE=""
if [ "$WITH_EXABGP" = true ] || [ -f "$PROJECT_DIR/docker-compose.exabgp.yml" ]; then
  EXABGP_COMPOSE_FILE="-f docker-compose.exabgp.yml"
fi

template="$PROJECT_DIR/deploy/systemd/gmj-flow.service.template"
target="/etc/systemd/system/gmj-flow.service"
if [ ! -f "$template" ]; then
  echo "Template nao encontrado: $template" >&2
  exit 1
fi

sed \
  -e "s|{{PROJECT_DIR}}|$PROJECT_DIR|g" \
  -e "s|{{EXABGP_COMPOSE_FILE}}|$EXABGP_COMPOSE_FILE|g" \
  -e "s|{{AI_PROFILE}}|$AI_PROFILE|g" \
  "$template" > "$target"

systemctl daemon-reload
systemctl enable gmj-flow
systemctl start gmj-flow
systemctl status gmj-flow --no-pager || true
