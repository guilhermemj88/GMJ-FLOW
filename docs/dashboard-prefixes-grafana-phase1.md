# Dashboard, prefixos e Grafana — Fase 1

Este documento descreve as três melhorias integradas no editor de dashboards:
persistência do layout, filtros IPv4/IPv6 e exportação JSON para Grafana.

## Causa raiz do drag/drop

O motor já calculava o drop com `widget.id`, revisão e persistência atômica,
mas havia dois caminhos que restauravam o snapshot anterior quando o `PATCH`
falhava:

1. os controladores de movimento/redimensionamento chamavam `onRollback` no
   `catch` de persistência;
2. o host reaplicava o layout persistente anterior ao terminar a interação.

Assim, uma falha ou resposta concorrente fazia o widget voltar visualmente,
mesmo que o drop estivesse correto. O estado final do drop agora é adotado
imediatamente como estado local persistente. Rollback é reservado para
cancelamento (`Escape`, `pointercancel` ou perda de captura). Respostas antigas
são ignoradas por sequência, `interaction_id`, revisão e chave de idempotência.
Em falha, a tela mantém o layout local e oferece nova tentativa.

O refresh periódico consulta apenas dados dos widgets e não recarrega o
dashboard/layout.

## Persistência do layout

O endpoint de layout recebe a grade completa:

```http
PATCH /api/dashboards/42/layout
Idempotency-Key: dashboard-layout:42:7:103:56fa21
Content-Type: application/json
```

```json
{
  "widgets": [
    {"id": 101, "grid": {"x": 0, "y": 0, "w": 6, "h": 8}},
    {"id": 103, "grid": {"x": 6, "y": 12, "w": 6, "h": 6}}
  ],
  "layout_version": 7,
  "base_revision": 7,
  "active_widget_id": 103,
  "interaction_id": "dashboard-layout-42-18",
  "compact_mode": "none"
}
```

O backend grava `dashboard_id`, `widget_id`, `grid_x`, `grid_y`, `grid_w` e
`grid_h` em uma transação. Uma revisão desatualizada é rejeitada e uma
repetição com a mesma chave é idempotente.

## Entidade e migração de prefixos

A migração SQLite é aditiva e executada por `ensure_prefix_schema`:

```text
prefixes(
  id, name, cidr, address_family, enabled, description,
  customer_id, group_id, zone_id, default_split_prefix_length,
  created_at, updated_at
)
```

A tabela `dashboards` recebe:

```text
prefix_filter_json TEXT NOT NULL DEFAULT '{}'
prefix_grouping_json TEXT NOT NULL DEFAULT '{}'
```

CIDRs são validados e canonicalizados com `ipaddress`. Apenas a rede é
armazenada; nunca há materialização de um registro por IP.

No ClickHouse é criada a agregação minuto
`flow_dashboard_prefix_1m`, alimentada por materialized view. Ela consolida
bytes, pacotes e flows por minuto e pelas dimensões mínimas necessárias para
filtro/ranking. `flow_raw` não é duplicada. Intervalos históricos ainda não
cobertos pela view continuam no caminho raw.

## API de prefixos

Endpoints autenticados:

```text
GET    /api/prefixes
POST   /api/prefixes
PUT    /api/prefixes/{id}
DELETE /api/prefixes/{id}
GET    /api/prefixes/{id}/subnets
GET    /api/prefixes/preview
```

Cadastro:

```json
{
  "name": "Cliente A",
  "cidr": "186.232.160.0/20",
  "enabled": true,
  "description": "Bloco de acesso",
  "customer_id": 12,
  "default_split_prefix_length": 24
}
```

Preview:

```http
GET /api/prefixes/preview?cidr=186.232.160.0%2F20&prefix_length=24
```

```json
{
  "cidr": "186.232.160.0/20",
  "address_family": "ipv4",
  "prefix_length": 24,
  "total": 16,
  "start": "186.232.160.0/24",
  "end": "186.232.175.0/24",
  "items": [
    "186.232.160.0/24",
    "186.232.161.0/24"
  ],
  "offset": 0,
  "limit": 100,
  "next_offset": null,
  "direct_lookup": false
}
```

`offset` e `limit` paginam a resposta. Os limites são configurados por
`GMJ_FLOW_PREFIX_PREVIEW_MAX_IPV4` (padrão 65536) e
`GMJ_FLOW_PREFIX_PREVIEW_MAX_IPV6` (padrão 4096). Para uma árvore grande,
`contains_ip` ou `contains_cidr` localiza diretamente o subprefixo sem
enumerar os demais.

## Filtro global

Exemplo salvo no dashboard:

```json
{
  "prefix_filter": {
    "enabled": true,
    "cidr": "186.232.162.0/24",
    "prefix_id": null,
    "start_ip": null,
    "end_ip": null,
    "address_family": "ipv4",
    "match_side": "either",
    "direction": null,
    "temporary": false
  },
  "prefix_grouping": {
    "enabled": true,
    "ipv4_prefix_length": 24,
    "ipv6_prefix_length": 64,
    "side": "destination",
    "top_n": 10,
    "include_empty": false
  }
}
```

O contexto completo entra na assinatura do cache. Portanto, redes diferentes,
comprimentos diferentes e filtro temporário/salvo não compartilham resultados.

O predicado é aplicado dentro da fonte raw e de cada ramo do caminho híbrido:

```sql
WHERE flow_time >= {start:DateTime}
  AND flow_time <= {end:DateTime}
  AND (
    (
      src_ip >= toIPv6({flow_prefix_start:String})
      AND src_ip <= toIPv6({flow_prefix_end:String})
    )
    OR (
      dst_ip >= toIPv6({flow_prefix_start:String})
      AND dst_ip <= toIPv6({flow_prefix_end:String})
    )
  )
```

Como os IPv4 estão armazenados em coluna `IPv6`, os limites de um `/24` são
enviados na forma IPv4-mapped equivalente. CIDRs e ranges usam comparação
nativa com `toIPv6` e parâmetros; não convertem a coluna por linha nem
enumeram endereços.

Agrupamento retorna CIDR real:

```sql
if(
  isIPv4String(toString(dst_ip))
    OR startsWith(toString(dst_ip), '::ffff:'),
  concat(
    toString(IPv4CIDRToRange(toIPv4(mapped_dst_ip), 24).1),
    '/24'
  ),
  concat(toString(IPv6CIDRToRange(dst_ip, 64).1), '/64')
) AS prefix
```

São suportados raw, agregado 1m e híbrido para bits/s, PPS, Top IPs, portas,
protocolos, TCP flags, ASN e séries por prefixo. Sensor, interface, zona,
direção e protocolo continuam no mesmo planejador.

## Widgets por prefixo

O catálogo expõe:

```text
traffic_by_prefix_bps
traffic_by_prefix_pps
top_source_prefixes
top_destination_prefixes
prefix_timeseries
top_ports_by_prefix
top_protocols_by_prefix
prefix_table
prefix_distribution
```

Eles reutilizam os motores tipados de `timeseries` e `top_n`, guardando
`config.widget_alias` para preservar sua semântica no editor e no exportador.

## Grafana Fase 1

Não há plugin nem publicação automática nesta fase.

```http
GET /api/dashboards/42/export/grafana
  ?grafana_version=12
  &datasource_uid=gmj-api
  &datasource_type=yesoreyeram-infinity-datasource
  &include_saved_filters=true
  &make_filters_editable=true
  &include_prefixes=true
  &dashboard_title=Fluxos%20por%20prefixo
  &dashboard_uid=fluxos-prefixo
  &refresh=1m
  &default_from=now-6h
  &default_to=now
```

O alias legado `/api/dashboards/{id}/grafana-export` continua válido.

Trecho do JSON:

```json
{
  "dashboard": {
    "uid": "fluxos-prefixo",
    "title": "Fluxos por prefixo",
    "tags": [
      "GMJ-FLOW",
      "generated-by-gmj-flow",
      "network-observability"
    ],
    "refresh": "1m",
    "time": {"from": "now-6h", "to": "now"},
    "panels": [
      {
        "id": 1,
        "type": "timeseries",
        "gridPos": {"x": 0, "y": 0, "w": 8, "h": 6},
        "targets": [
          {
            "url": "/api/v1/grafana/query/timeseries",
            "url_options": {
              "method": "POST",
              "body_type": "raw",
              "body_content_type": "application/json",
              "data": "{\"metric\":\"traffic_by_prefix_bps\",\"from\":\"$__isoFrom()\",\"to\":\"$__isoTo()\"}"
            }
          }
        ]
      }
    ],
    "gmj_flow": {
      "schema_version": 1,
      "dashboard_id": 42,
      "dashboard_revision": 7,
      "exported_at": "2026-07-30T12:00:00Z",
      "source": "gmj-flow",
      "export_hash": "..."
    }
  },
  "folderUid": "gmj-flow",
  "overwrite": false
}
```

Com filtros editáveis são criadas as variáveis `prefix`, `prefix_group`,
`prefix_length`, `ipv6_prefix_length`, `match_side`, `address_family`,
`sensor`, `interface`, `direction`, `zone` e `top_n`. Os bodies usam os
placeholders e aceitam `all` para os IDs opcionais.

Com filtros fixos, valores salvos são gravados diretamente no body e não são
criadas variáveis desnecessárias.

## Reimportação e segurança

```http
POST /api/dashboards/import/grafana
```

Somente um JSON com metadados `source=gmj-flow`, `schema_version=1` e hash
estrutural íntegro é aceito. Dashboard Grafana arbitrário ou JSON alterado é
rejeitado. A definição reimportável é limitada aos campos tipados de dashboard
e widget.

Campos com formato de credencial (`Authorization`, token, API key, senha,
secret, cookie ou credentials) são removidos recursivamente. O JSON contém
apenas UID/tipo do datasource e nunca contém credenciais de ClickHouse,
SQLite, Router SSH ou Host Agent.

## Desempenho e limites

- A filtragem acontece antes do `GROUP BY`.
- Consultas alinhadas por minuto usam `aggregate_1m`; bordas parciais usam
  `aggregate_hybrid`; ausência de cobertura usa `raw`.
- A agregação por prefixo aumenta armazenamento conforme a cardinalidade de
  pares de endereços/dimensões por minuto. TTL permanece em 30 dias.
- O preview IPv6 não expande árvores grandes; use paginação ou `contains_ip`.
- Comprimentos IPv4 aceitos: 0–32, respeitando o prefixo pai no preview.
- Comprimentos IPv6 aceitos: 0–128, respeitando o prefixo pai no preview.
- A materialized view não retroalimenta períodos anteriores à criação; esses
  períodos usam raw até haver cobertura.
