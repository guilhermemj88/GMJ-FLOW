# GMJ-FLOW

MVP inicial para analise simples de NetFlow/IPFIX/sFlow em um ISP pequeno. Esta primeira versao usa dados simulados, ClickHouse para armazenamento/agregacao, FastAPI para API e HTML estatico com Bootstrap e Apache ECharts para o dashboard.

## Stack

- Docker Compose
- ClickHouse
- Python FastAPI
- Frontend HTML simples servido por nginx
- Bootstrap e Apache ECharts via CDN

## Subir o ambiente

```bash
cp .env.example .env
docker compose up -d --build
```

Servicos principais:

- Frontend: http://localhost:8080
- Backend: http://localhost:8000
- Healthcheck: http://localhost:8000/health
- ClickHouse HTTP: http://localhost:8123

## Gerar dados fake

Gerar um lote unico:

```bash
docker compose --profile tools run --rm collector python fake_flow_generator.py --once --batch-size 5000
```

Gerar continuamente:

```bash
docker compose --profile tools up collector
```

O gerador insere flows em `flowdb.flow_raw` com `src_ip`, `dst_ip`, portas, protocolo, flags TCP, bytes, pacotes, sensor, exporter IP e interfaces de entrada/saida.

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
curl "http://localhost:8000/api/tops/src-ip?range_minutes=60&sensor=edge-01"
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

`flow_raw` guarda IP de origem e destino para investigacao e possui TTL inicial de 30 dias. As agregacoes de 1 minuto usam `SummingMergeTree` e sao alimentadas por materialized views.

## Fora do MVP

- Coleta real com pmacct
- ExaBGP/blackhole
- Autenticacao
- React ou SPA
