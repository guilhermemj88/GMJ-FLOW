# GMJ-FLOW Install

## Instalação simples

```sh
sudo ./scripts/install.sh
```

## Instalação com IA

```sh
sudo ./scripts/install.sh --with-ai --ollama-model qwen2.5:3b-instruct
```

O instalador habilita `AI_MITIGATION_ENABLED=true`, usa `AI_PROVIDER=ollama`, mantém `AI_ALLOW_AUTO=false` e mantém `AI_REQUIRE_POLICY_VALIDATION=true`.

## Instalação com ExaBGP

```sh
sudo ./scripts/install-exabgp.sh \
  --local-as 53194 \
  --peer-as 53194 \
  --local-address 192.168.1.22 \
  --router-id 192.168.1.22 \
  --peer-ip 186.232.160.37 \
  --passive true
```

Se o ExaBGP roda no host e cria `/run/exabgp/exabgp.in` e `/run/exabgp/exabgp.out`,
use o override opcional versionado para montar os pipes no backend:

```sh
docker compose --env-file .env \
  -f docker-compose.yml \
  -f docker-compose.exabgp-pipe.yml \
  --profile ai up -d --build --force-recreate backend frontend
```

Esse override nao e obrigatorio para instalacoes sem ExaBGP no host.

## IA + ExaBGP + autostart

```sh
sudo ./scripts/install.sh --with-ai --with-exabgp --install-systemd
```

## Wizard Web

Acesse `Sistema > Instalação / Setup` para validar Docker, Compose, restart policy, systemd, Ollama, modelo IA, ExaBGP, pipes, nginx resolver, ClickHouse, SQLite e collectors.

Em `Sistema > IA Local`, o operador pode listar modelos, baixar modelo, testar modelo e habilitar/desabilitar IA. A UI não habilita mitigação automática.

## Status BGP / FlowSpec em backend containerizado

Quando o backend roda em container, `systemctl` e `ss` do host podem ficar indisponíveis. Nesse caso:

- Pipe ExaBGP OK significa que o backend consegue escrever no pipe dentro do container.
- Sessão BGP não verificada não significa DOWN.
- FlowSpec não verificado não significa DOWN.
- Para status completo, configure Router SSH no conector BGP ou um Host Agent.

Router SSH para Huawei VRP executa:

```text
display bgp peer
display bgp flow peer
```

Host Agent opcional:

```sh
sudo python3 scripts/host-agent.py --host 127.0.0.1 --port 18080
GMJFLOW_HOST_AGENT_URL=http://127.0.0.1:18080
```

O agente deve expor `GET /bgp/status?service=<systemd>&peer_ip=<ip>&listen_port=179` retornando JSON com `bgp_state` e `flowspec_state`.

## Autostart

```sh
sudo ./scripts/install-systemd-service.sh --profile ai --with-exabgp
systemctl status gmj-flow
```

Os serviços Docker principais também usam `restart: unless-stopped`.

## Validações

```sh
sudo ./scripts/post-install-check.sh
docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml --profile ai config
curl http://127.0.0.1:8000/health
docker exec gmj-flow-clickhouse clickhouse-client --query "SELECT count(), max(flow_time) FROM flowdb.flow_raw"
```

## Troubleshooting rápido

- `gmj-flow-ollama` não existe: suba com `--with-ai` ou `--profile ai`.
- `ollama list` vazio: use `Sistema > IA Local > Baixar` ou `docker exec gmj-flow-ollama ollama pull qwen2.5:3b-instruct`.
- IA desativada HTTP 409: habilite em `Sistema > IA Local`.
- Pipe ExaBGP down: rode `sudo ./scripts/install-exabgp.sh ...` e valide `/run/exabgp`.
- Backend nao ve `/run/exabgp`: use `-f docker-compose.exabgp-pipe.yml` e recrie `backend frontend`.
- Frontend 502 após recriar backend: confirme `frontend/nginx.conf` com `resolver 127.0.0.11`.
- GMJ-FLOW não sobe após reboot: instale `gmj-flow.service` e confira `systemctl is-enabled gmj-flow`.
- PDF com números crus: exporte Flows novamente; o PDF deve mostrar `Mbps`, `Kpps`, `MB`, `K/M/G`.
