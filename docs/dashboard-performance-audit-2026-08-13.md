# Auditoria de performance do Dashboard — 2026-08-13

## Resultado

Os ~46 segundos não pertenciam a uma única consulta ClickHouse. O caminho de
Top ASN executava três consultas sequenciais que repetiam o mesmo CTE híbrido
(quatro no fallback) e depois fazia resolução ASN local em padrão N+1. Para
cada IP sem ASN no flow, `lookup_asn_prefix` lia e reinterpretava todo o
catálogo SQLite de prefixos; o ranking podia fazer isso para 200 IPs.

O caminho agregado não havia sido abandonado. `aggregate_hybrid` continuava
usando as bordas incompletas em `flow_raw` e o miolo nas tabelas de um minuto.
O nome do caminho no log cobria também todo o pós-processamento Python/SQLite,
o que fazia uma demora de enriquecimento parecer uma consulta híbrida lenta.

## Caminho HTTP completo

1. O browser chama `POST /api/dashboard-widgets/query`.
2. O alias encaminha para
   `query_configurable_dashboard_widget(dashboard_id, widget_id, ...)`.
3. SQLite carrega dashboard/widget e resolve o contexto de filtros/prefixos.
4. `dashboard_widget_cached_query` usa o cache RAM bounded já existente e sua
   reserva singleflight.
5. `dashboard_widget_execute` seleciona o plano Top-N.
6. `dashboard_widget_top_payload` encaminha `src_asn`/`dst_asn` para
   `top_asn_dimension`.
7. `dashboard_hybrid_source_cte` escolhe `flow_raw` para minutos parciais e
   `flow_dashboard_asn_src_1m` ou `flow_dashboard_asn_dst_1m` para o interior.
8. ClickHouse agrupa, ordena e limita ASN conhecido e IP sem ASN.
9. O backend resolve somente os IPs sem ASN na base local, agrega o resultado,
   enriquece a organização e calcula percentuais.
10. O resultado passa pela normalização do widget, cache e serialização HTTP.

Não há lookup ASN externo síncrono nesse caminho. Ausências apenas são
enfileiradas localmente para o resolvedor existente.

## Antes e depois das consultas Top ASN

Antes, por cache miss:

- query 1: ranking dos ASNs persistidos no flow, `LIMIT Top-N`;
- query 2: ranking de até 200 IPs cujo ASN era zero;
- query 3: total exato de BPS para percentuais;
- query 4 opcional: novo ranking de 200 IPs quando nenhum item era montado.

Cada query reconstruía e lia o mesmo `raw`/`aggregate_hybrid`. Depois há uma
única query: um único `weighted_source`, agrupamento por ASN ou IP, total por
window function e `row_number()` separado para conhecidos/não resolvidos. O
pushdown final é `Top-N + 200`, sem transferir uma lista completa ao backend.

O pós-processamento local agora faz uma leitura em lote do cache de IP, uma
leitura do catálogo de prefixos por família, longest-prefix-match em memória e
uma transação para cache/fila. Metadados de organização também são lidos e
enfileirados em lote.

## Cache e preagregações encontradas

- `MemoryDashboardCache`: cache por processo, TTL 5/15/60/300 s conforme o
  range, LRU, limite de item, orçamento derivado de RAM/cgroup, pressão de
  memória, prewarm opcional e singleflight.
- Tabelas/MVs específicas de um minuto: series, IP origem/destino, porta,
  protocolo, ASN origem/destino, TCP flags, prefixo, SYN e conversações. TTL de
  30 dias e rollout condicionado à cobertura do intervalo.
- `behavior_flow_10s`: MV de detecção comportamental, TTL 24 h. Ela retém alta
  cardinalidade de conversação, não contém nome ASN nem a mesma semântica de
  atualização da configuração de sample-rate. Para Top-N do Dashboard, as MVs
  por dimensão de um minuto são mais estreitas e preservam a semântica atual.
- Caches SQLite existentes: `asn_lookup_cache` e `asn_info`.
- Não há configuração explícita de ClickHouse query cache no repositório. Os
  caches normais de MergeTree/filesystem permanecem sob o ClickHouse/Linux.

Nenhum segundo cache foi criado.

## Concorrência e frontend

O singleflight antigo deixava de aguardar após 35 segundos e iniciava uma nova
computação. Como os widgets observados levavam ~46 s e atualizavam a cada 30 s,
isso permitia sobreposição e amplificação de CPU. O timeout agora gera alerta,
mas continua aguardando o único owner; uma consulta idêntica não é duplicada.

O frontend já carrega widgets visíveis de forma independente com
`Promise.allSettled`, ignora hidden/collapsed e impede uma segunda request do
mesmo widget enquanto há controller ativo. Agora também preserva o último
resultado em falha de refresh e registra TTFB, download, JSON parse, render e
tempo total por widget.

## Telemetria

Cada request de widget emite `dashboard_widget_performance` sem payload, com:

- total, ClickHouse, SQLite/contexto, enriquecimento, agregação, serialização e
  fallback;
- cache hit, quantidade de queries e linhas do resultado;
- query IDs no formato
  `gmjflow-dashboard-<dashboard>-widget-<widget>-<request>-<sequência>`;
- `read_rows`, `read_bytes`, result rows, peak query memory e CPU quando
  disponíveis no summary do driver.

Para obter CPU e memória autoritativas no servidor depois do deploy:

```sql
SELECT
    event_time,
    query_id,
    query_duration_ms,
    read_rows,
    read_bytes,
    result_rows,
    memory_usage,
    ProfileEvents['OSCPUVirtualTimeMicroseconds'] AS cpu_time_us,
    log_comment
FROM system.query_log
WHERE type = 'QueryFinish'
  AND query_id LIKE 'gmjflow-dashboard-8-widget-%'
ORDER BY event_time DESC
LIMIT 100;
```

## Benchmark reproduzível disponível nesta estação

Dataset sintético local: 20.000 prefixos IPv4, 100 IPs, cinco execuções. Foi
medido o estágio que não aparecia no `system.query_log`.

| Resolução ASN local | p50 | p95 | máximo | scans do catálogo/request |
|---|---:|---:|---:|---:|
| legado, um scan por IP | 8,168 s | 8,198 s | 8,198 s | 100 |
| lote, um scan total | 0,132 s | 0,172 s | 0,172 s | 1 |

Speedup p50: 61,7×. A quantidade de queries ClickHouse do Top ASN caiu de
3 (ou 4 no fallback) para 1. A equivalência testada inclui ASN já persistido,
ASN resolvido por prefixo local, soma de BPS e percentual sobre o total exato.

O baseline real fornecido foi 45,982 s e 46,315 s para os widgets 41/42. Não
foi possível produzir o benchmark HTTP/ClickHouse pós-alteração, nem p50/p95
do Dashboard completo, Top IP, Top porta e séries BPS/PPS nesta estação porque
o daemon Docker/ClickHouse não está disponível. Portanto não se atribui uma
redução real de `read_rows`, bytes, CPU ou memória antes do deploy; os query IDs
e campos acima foram adicionados justamente para medir isso sem inferência.

## Origem histórica

`git blame` aponta o scan por IP e as queries/fallback de ASN para `bc5350ea`
e `375f7dd1` (22 de junho de 2026). O refactor `3169e478` (30 de julho de 2026)
passou a repetir o CTE weighted nas consultas separadas, mas não removeu o
caminho agregado. O singleflight com promoção após timeout veio da
infraestrutura adicionada em `7c008fa`. Assim, a causa é a combinação de um
N+1 antigo, consultas sequenciais repetidas e overlap após timeout — não uma
regressão recente que tenha trocado as MVs por `flow_raw`.

## Limites e segurança

Não houve mudança em detecção, mitigação automática, FlowSpec, Threat Policy,
Campaign evaluator, coletores, parser, GreyNoise, Threat Intelligence, schema
persistente ou volumes. O índice temporário de longest-prefix-match existe
somente durante a resolução do lote bounded (máximo 200 no Top ASN); o cache
RAM existente conserva seus limites e TTL.
