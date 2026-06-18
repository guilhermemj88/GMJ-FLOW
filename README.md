# GMJ-FLOW

MVP para analise simples de NetFlow/IPFIX/sFlow em um ISP pequeno. O projeto usa ClickHouse para armazenamento/agregacao, FastAPI para API e dashboard HTML simples com Bootstrap e Apache ECharts.

## Stack

- Docker Compose
- ClickHouse
- Python FastAPI
- pmacct/nfacctd para coleta real NetFlow v9/IPFIX
- Frontend HTML simples servido por nginx
- Bootstrap e Apache ECharts via CDN

## Subir o ambiente

```bash
cp .env.example .env
docker compose --env-file .env up -d --build
```

Servicos principais:

- Frontend: http://localhost:8080
- Backend: http://localhost:8000
- Healthcheck: http://localhost:8000/health
- ClickHouse HTTP: http://localhost:8123
- Coletor real NetFlow/IPFIX: UDP `9995`

## Modo real com pmacct

O modo real sobe por padrao com os servicos `pmacct` e `pmacct-parser`.

- `pmacct` executa `nfacctd` em foreground e recebe NetFlow v9/IPFIX em `9995/udp`.
- `pmacct-parser` le `/var/spool/pmacct/nfacctd.csv` no volume compartilhado e insere em `flowdb.flow_raw`.
- Sensor padrao: `mikrotik-lab`.
- Exporter padrao: `192.168.0.157`.
- `flow_type`: `netflow-v9`.
- `sample_rate`: `1`.

Comandos uteis:

```bash
docker compose logs -f pmacct
docker compose logs -f pmacct-parser
```

Documentacao completa do laboratorio MikroTik: [docs/pmacct.md](docs/pmacct.md).

## Modo fake

O collector fake continua disponivel no profile `tools` para popular o dashboard sem roteador/exporter real.

Gerar um lote unico:

```bash
docker compose --env-file .env --profile tools run --rm collector python fake_flow_generator.py --once --batch-size 5000
```

Gerar continuamente:

```bash
docker compose --env-file .env --profile tools up collector
```

O gerador fake insere flows em `flowdb.flow_raw` com `src_ip`, `dst_ip`, portas, protocolo, flags TCP, bytes, pacotes, sensor, exporter IP e interfaces de entrada/saida. Esses registros sao marcados com `flow_type = 'fake'`.

## Endpoints

Todos os endpoints aceitam:

- `range_minutes`
- `start`
- `end`
- `sensor`

Endpoints disponiveis:

- `GET /health`
- `GET /api/traffic/bps`
- `GET /api/traffic/pps`
- `GET /api/tops/src-ip`
- `GET /api/tops/dst-ip`
- `GET /api/tops/ports`
- `GET /api/tops/protocols`
- `GET /api/tops/tcp-flags`
- `GET /api/flows/search`

Exemplo:

```bash
curl "http://localhost:8000/api/tops/src-ip?range_minutes=60&sensor=mikrotik-lab"
```

## Modelo inicial

O `clickhouse/init.sql` cria o database `flowdb` e as tabelas:

- `flow_raw`
- `flow_1m`
- `flow_tops_1m`
- `prefix_traffic_1m`
- `anomaly_events`
- `sensors`
- `sensor_interfaces`
- `customer_prefixes`
- `retention_settings`

`flow_raw` guarda IP de origem e destino para investigacao, usa campos `IPv6` para aceitar IPv4/IPv6, possui `flow_type`, `sample_rate` e TTL inicial de 30 dias. As agregacoes de 1 minuto usam `SummingMergeTree` e sao alimentadas por materialized views.

## Fora deste passo

- ExaBGP/blackhole
- Autenticacao
- React ou SPA