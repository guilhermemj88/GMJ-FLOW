#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must run as root." >&2
  exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "GMJ-FLOW server install supports Linux only." >&2
  exit 1
fi

install_curl_if_needed() {
  if command -v curl >/dev/null 2>&1; then
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl ca-certificates
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl ca-certificates
  else
    echo "curl is required to install Docker automatically." >&2
    exit 1
  fi
}

install_docker_if_needed() {
  if command -v docker >/dev/null 2>&1; then
    return
  fi
  install_curl_if_needed
  curl -fsSL https://get.docker.com | sh
}

install_compose_if_needed() {
  if docker compose version >/dev/null 2>&1; then
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y docker-compose-plugin
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y docker-compose-plugin
  elif command -v yum >/dev/null 2>&1; then
    yum install -y docker-compose-plugin
  else
    echo "Docker Compose plugin is required. Install it and run install.sh again." >&2
    exit 1
  fi
}

env_value() {
  key="$1"
  default="$2"
  if [ -f .env ] && grep -q "^$key=" .env; then
    grep "^$key=" .env | tail -n 1 | cut -d= -f2-
  else
    printf '%s\n' "$default"
  fi
}

set_env_value() {
  key="$1"
  value="$2"
  tmp=".env.tmp.$$"
  if [ -f .env ] && grep -q "^$key=" .env; then
    awk -v k="$key" -v v="$value" 'BEGIN { FS = OFS = "=" } $1 == k { print k "=" v; next } { print }' .env > "$tmp"
    mv "$tmp" .env
  else
    printf '\n%s=%s\n' "$key" "$value" >> .env
  fi
}

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 64
    printf '\n'
  fi
}

install_docker_if_needed
install_compose_if_needed

if [ ! -f .env ]; then
  cp .env.example .env
fi

if ! grep -q "^GMJFLOW_ENABLE_COLLECTOR_APPLY=" .env; then
  set_env_value GMJFLOW_ENABLE_COLLECTOR_APPLY true
fi

current_secret=$(env_value GMJFLOW_AUTH_SECRET "")
case "$current_secret" in
  ""|"change-me-gmj-flow-auth-secret"|"gmj-flow-dev-secret-change-me")
    set_env_value GMJFLOW_AUTH_SECRET "$(generate_secret)"
    ;;
esac

mkdir -p data data/backend data/collectors data/backups data/logs
chmod 750 data data/backend data/collectors data/logs
chmod 700 data/backups

compose_file_args="-f docker-compose.yml"
if [ -f docker-compose.collectors.yml ]; then
  compose_file_args="$compose_file_args -f docker-compose.collectors.yml"
fi

docker compose --env-file .env $compose_file_args up -d --build --remove-orphans

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  docker_bin=$(command -v docker)
  cat >/etc/systemd/system/gmj-flow.service <<EOF
[Unit]
Description=GMJ-FLOW Docker Compose stack
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$PROJECT_ROOT
ExecStart=$docker_bin compose --env-file .env $compose_file_args up -d
ExecStop=$docker_bin compose --env-file .env $compose_file_args down
RemainAfterExit=yes
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable gmj-flow.service
fi

front_port=$(env_value FRONTEND_PORT 8080)
backend_port=$(env_value BACKEND_PORT 8000)
host_ip=$(hostname -I 2>/dev/null | awk '{ print $1 }')
host_ip=${host_ip:-localhost}

echo
echo "GMJ-FLOW installed."
echo "Frontend: http://$host_ip:$front_port"
echo "Backend:  http://$host_ip:$backend_port"
echo "Initial user: admin/admin"
echo
echo "Next steps:"
echo "1. Log in and change the initial password."
echo "2. Review .env, especially GMJFLOW_ENABLE_COLLECTOR_APPLY."
echo "3. Create sensors and click Aplicar Coletor when ready."
