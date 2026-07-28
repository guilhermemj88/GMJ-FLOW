#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$PROJECT_DIR"

compose_file_args="-f docker-compose.yml"
[ -f docker-compose.collectors.yml ] && compose_file_args="$compose_file_args -f docker-compose.collectors.yml"
[ -f docker-compose.exabgp.yml ] && compose_file_args="$compose_file_args -f docker-compose.exabgp.yml"

echo "== docker ps =="
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true

echo
echo "== restart policy =="
docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' gmj-flow-frontend gmj-flow-backend gmj-flow-clickhouse gmj-flow-ollama 2>/dev/null || true

echo
echo "== systemd =="
systemctl is-enabled gmj-flow 2>/dev/null || true
systemctl is-active gmj-flow 2>/dev/null || true
systemctl is-active exabgp-gmj-flow 2>/dev/null || true

echo
echo "== ExaBGP pipes =="
ls -la /run/exabgp 2>/dev/null || true
docker exec gmj-flow-backend ls -la /run/exabgp 2>/dev/null || true

echo
echo "== Ollama models =="
docker exec gmj-flow-ollama ollama list 2>/dev/null || true

echo
echo "== AI env =="
grep -E '^(AI_MITIGATION_ENABLED|AI_PROVIDER|AI_BASE_URL|AI_MODEL|AI_ALLOW_AUTO|AI_REQUIRE_POLICY_VALIDATION)=' .env 2>/dev/null || true

echo
echo "== API health =="
backend_port=$(grep '^BACKEND_PORT=' .env 2>/dev/null | tail -n 1 | cut -d= -f2-)
backend_port=${backend_port:-8000}
frontend_port=$(grep '^FRONTEND_PORT=' .env 2>/dev/null | tail -n 1 | cut -d= -f2-)
frontend_port=${frontend_port:-8080}
curl -fsS "http://127.0.0.1:$backend_port/health" || true
echo
curl -I -fsS "http://127.0.0.1:$frontend_port/health" || true

echo
echo "== ClickHouse flow_raw =="
docker exec gmj-flow-clickhouse clickhouse-client --query "SELECT count(), max(flow_time) FROM flowdb.flow_raw" 2>/dev/null || true

echo
echo "== compose config =="
docker compose --env-file .env $compose_file_args config >/dev/null && echo "compose ok"
