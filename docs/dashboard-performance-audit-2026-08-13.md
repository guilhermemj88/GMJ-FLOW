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

O baseline real fornecido foi 45,982 s e 46,315 s para os widgets 41/42. O
daemon Docker/ClickHouse não estava disponível na estação de desenvolvimento;
o benchmark real feito posteriormente no Fibinet está registrado a seguir.

## Auditoria real no Fibinet após `6e2ba21`

Acesso read-only em 13 de agosto de 2026. A árvore estava no merge `8e981d0`,
que contém `6e2ba21 perf: optimize dashboard top ASN processing`, e a imagem
ativa continha o mesmo código. Foram preservadas sem alteração as modificações
locais preexistentes em Threat Intelligence, parser PMACCT e compose.

Estado inicial:

- 31 GiB de RAM, 27 GiB disponíveis e 27 GiB em page cache;
- backend entre 96–129% CPU e 0,95–1,13 GiB RSS/container;
- ClickHouse entre 39–323% CPU e aproximadamente 2,4 GiB;
- um processo Uvicorn com 20 threads;
- uma thread do backend consumia 76–91% CPU continuamente e outra chegava a
  10–27%. Esta é evidência de trabalho Python concorrente/GIL; sem profiler de
  stack instalado não foi atribuído um nome de rotina como fato.

O cache existente estava habilitado com 512 MiB efetivos, uma entrada naquele
instante, 102 hits, 177 misses, hit ratio de 36,56%, nenhuma pressão de memória
e nenhum singleflight ativo. O ClickHouse query cache estava desabilitado;
MarkCache tinha 19,9 MiB, filesystem/uncompressed cache estavam vazios e o
page cache do sistema tinha 27,7 GB.

### Correlação dos widgets

| Widget | Backend | ClickHouse | Enrichment | SQLite/contexto | Leituras CH |
|---|---:|---:|---:|---:|---:|
| 41 Top ASN upload | 5,274 s | 469 ms | 4,150 s | 120 ms | 487.686 linhas / 24,5 MB |
| 44 Top SYN origem | 5,877 s | 227 ms | não medido | 59 ms | 1.366.926 / 110,7 MB |
| 35 Top IP origem | 5,919 s | 310 ms | não medido | 88 ms | 467.699 / 22,6 MB |
| 45 Top SYN destino | 38,321 s | 244 ms | não medido | 3,615 s | 1.360.344 / 110,2 MB |
| 40 Conversações | 38,646 s | 1,671 s | não medido | 3,420 s | 1.774.539 / 132,2 MB |

Para o widget 41, a query principal durou 424 ms, leu 279.523 linhas/23,7 MB,
usou pico de 29,8 MB e 611 ms de CPU segundo `system.query_log`. A outra query
do trace era a prova de cobertura da MV, não um segundo ranking. Isso confirma
uma melhora real de 45,982 s para 5,274 s no caso observado, aproximadamente
8,7×, mas ainda acima da meta de 2 s por causa do enriquecimento local.

O widget 42 teve query principal de 348 ms, 267.209 linhas/22,6 MB, pico de
29,6 MB e 503 ms de CPU. A query principal de conversações durou 1,603 s,
leu 1.223.866 linhas/130 MB, teve pico de 301,8 MB e 4,02 s de CPU paralela.
Nenhuma SELECT individual explica os 38 segundos de backend.

### Segundo N+1 comprovado pelo caminho de código

A medição revelou N+1 adicionais depois da primeira correção:

- Top IP resolvia ASN individualmente para cada item final;
- Top Conversations fazia até dois lookups SQLite por conversa;
- os widgets SYN configuráveis não reutilizavam `dashboard_top_syn`/a MV
  `flow_dashboard_syn_1m`; caíam no caminho genérico raw e enriqueciam até 40
  itens antes do corte final em 10;
- filas ASN já existentes eram atualizadas novamente em cada refresh, criando
  escrita e contenção SQLite desnecessárias.

A correção seguinte no repositório de desenvolvimento passa esses três
enriquecimentos para batch, roteia o contrato exato TCP SYN para a MV já
existente, evita DDL `ensure` repetido no read path e somente enfileira IP/ASN
que ainda não está na fila. Também adiciona `unattributed_ms` à telemetria.

### Bancos e preagregações reais

O SQLite tinha 1,2 GiB, WAL de 59 MiB, 24.371 entradas no cache de IP, 764 em
`asn_info`, 192 prefixos e 16.704 itens na fila. Havia erros reais
`database is locked`. Dos itens da fila, 2.425 `queued`, 585 `pending` e 860
`stale` já tinham pelo menos três tentativas, portanto não eram consumidos pelo
resolver configurado com máximo três, mas continuavam sendo tocados por
upserts do read path anterior.

As MVs de Dashboard estavam presentes e cobertas. Exemplos de volume:

- `flow_raw`: 86,2 milhões de linhas / 2,37 GB;
- `behavior_flow_10s`: 81,6 milhões / 1,88 GB;
- ASN src/dst 1m: 208/226 milhões / 3,23/3,62 GB;
- conversations 1m: 542 milhões / 13,34 GB;
- src/dst IP 1m: 208/226 milhões / 3,09/3,45 GB.

Em dez minutos, consultas somente sobre `flow_raw` somaram 1.120 execuções,
71,6 milhões de linhas, 5,33 GB lidos e 110,4 s de CPU. As duas consultas
observadas de `behavior_flow_10s` somaram 654 mil linhas, 65,4 MB e 2,67 s de
CPU. Isso confirma que ela é rápida para seu uso de detecção, mas não demonstra
equivalência semântica suficiente para substituir as MVs de Dashboard.

### Benchmark HTTP parcial

Uma execução fria seguida de hits imediatos, sequencialmente:

- série BPS: 7,397 s fria; hits 111–192 ms;
- série PPS: 332 ms fria; hits 108–184 ms;
- Top IP origem: 1,186 s fria; hits 123 ms, 489 ms e 3,145 s;
- Top porta: 5,494 s fria; hits 1,477–2,946 s; o quarto request já estava fora
  do TTL de 5 s e recalculou em 2,161 s.

A grande variância até em cache hit demonstra contenção/GIL e custo fora da
query do widget. A sequência foi encerrada quando a VPN/SSH perdeu
conectividade; não foram executados os widgets restantes e não se inferiu
p50/p95 do dashboard completo a partir desse conjunto incompleto.

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

## Validação local e próximo passo

A suíte focada executada em Python 3.12 passou 117 testes, cobrindo Dashboard,
cache, prefixos, batching ASN, o roteamento Top SYN e a regressão do
orquestrador de mitigação automática. `git diff --check` também passou.

O segundo conjunto de correções permanece somente no repositório de
desenvolvimento. Não houve deploy nem hotfix no Fibinet. Ao final da auditoria,
uma nova sondagem TCP de cinco segundos ainda encontrou a porta SSH
indisponível; portanto, a recomendação é fazer deploy controlado somente após
restabelecer a VPN e então repetir os mesmos widgets, coletando p50/p95 e os
campos `auth_ms`, `unattributed_ms` e `query_ids` da telemetria.
