#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
LOCAL_AS="${LOCAL_AS:-53194}"
PEER_AS="${PEER_AS:-53194}"
LOCAL_ADDRESS="${LOCAL_ADDRESS:-}"
ROUTER_ID="${ROUTER_ID:-}"
PEER_IP="${PEER_IP:-}"
PASSIVE=true
RECREATE_BACKEND=true

while [ "$#" -gt 0 ]; do
  case "$1" in
    --local-as) shift; LOCAL_AS="${1:-$LOCAL_AS}" ;;
    --peer-as) shift; PEER_AS="${1:-$PEER_AS}" ;;
    --local-address) shift; LOCAL_ADDRESS="${1:-$LOCAL_ADDRESS}" ;;
    --router-id) shift; ROUTER_ID="${1:-$ROUTER_ID}" ;;
    --peer-ip) shift; PEER_IP="${1:-$PEER_IP}" ;;
    --passive) shift; PASSIVE="${1:-true}" ;;
    --project-dir) shift; PROJECT_DIR="${1:-$PROJECT_DIR}" ;;
    --no-recreate-backend) RECREATE_BACKEND=false ;;
    -h|--help)
      echo "Uso: $0 --local-as ASN --peer-as ASN --local-address IP --router-id IP --peer-ip IP [--passive true] [--project-dir DIR]"
      exit 0
      ;;
    *) echo "Argumento invalido: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Execute com sudo/root." >&2
  exit 1
fi

[ -n "$LOCAL_ADDRESS" ] || LOCAL_ADDRESS=$(hostname -I 2>/dev/null | awk '{ print $1 }')
[ -n "$ROUTER_ID" ] || ROUTER_ID="$LOCAL_ADDRESS"
[ -n "$PEER_IP" ] || PEER_IP="186.232.160.37"

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y exabgp socat iproute2
fi

mkdir -p /etc/exabgp /run/exabgp
mkfifo /run/exabgp/exabgp.in 2>/dev/null || true
mkfifo /run/exabgp/exabgp.out 2>/dev/null || true
chmod 666 /run/exabgp/exabgp.in /run/exabgp/exabgp.out

PASSIVE_LINE=""
[ "$PASSIVE" = "true" ] && PASSIVE_LINE="    passive;"

template="$PROJECT_DIR/deploy/exabgp/gmj-flow-exabgp.conf.template"
sed \
  -e "s|{{LOCAL_AS}}|$LOCAL_AS|g" \
  -e "s|{{PEER_AS}}|$PEER_AS|g" \
  -e "s|{{LOCAL_ADDRESS}}|$LOCAL_ADDRESS|g" \
  -e "s|{{ROUTER_ID}}|$ROUTER_ID|g" \
  -e "s|{{PEER_IP}}|$PEER_IP|g" \
  -e "s|{{PASSIVE_LINE}}|$PASSIVE_LINE|g" \
  -e "s|{{PIPE_INPUT}}|/run/exabgp/exabgp.in|g" \
  -e "s|{{PIPE_OUTPUT}}|/run/exabgp/exabgp.out|g" \
  "$template" > /etc/exabgp/gmj-flow.conf

cat >/etc/systemd/system/exabgp-gmj-flow.service <<'EOF'
[Unit]
Description=GMJ-FLOW ExaBGP FlowSpec
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
RuntimeDirectory=exabgp
ExecStartPre=/bin/sh -c 'mkfifo /run/exabgp/exabgp.in 2>/dev/null || true; mkfifo /run/exabgp/exabgp.out 2>/dev/null || true; chmod 666 /run/exabgp/exabgp.in /run/exabgp/exabgp.out'
ExecStart=/usr/bin/exabgp /etc/exabgp/gmj-flow.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat >"$PROJECT_DIR/docker-compose.exabgp.yml" <<'EOF'
services:
  backend:
    volumes:
      - /run/exabgp:/run/exabgp
EOF

systemctl daemon-reload
systemctl enable exabgp-gmj-flow
systemctl restart exabgp-gmj-flow

if [ "$RECREATE_BACKEND" = true ]; then
  cd "$PROJECT_DIR"
  docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml -f docker-compose.exabgp.yml up -d --force-recreate backend
fi

systemctl status exabgp-gmj-flow --no-pager || true
ls -la /run/exabgp || true
docker exec gmj-flow-backend ls -la /run/exabgp || true
if [ "$PASSIVE" = "true" ]; then
  ss -lntp | grep ':179' || echo "Aviso: porta TCP/179 ainda nao esta escutando."
fi
