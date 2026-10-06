# Detector de anomalias — desempenho e estabilidade temporal (PERF-A / A.1 / B)

> **Status:** PERF-A e PERF-A.1 **deployados** (2026-10-06); PERF-B implementado, **não deployado**.
> **Fonte de verdade:** medições feitas no servidor real (`root@172.20.10.40`), `flowdb.flow_raw`.
> **Código:** `backend/app/main.py` (`run_detection_template_rules_once`,
> `evaluate_detection_template_rule`, `query_detection_rule_candidates`, `DetectionScanCache`,
> `clickhouse_sample_rate_expr`, `reconcile_detection_template_buckets`, `detection_cursor`).

Este documento registra **por que** o ciclo do detector levava vários minutos, o que foi
medido, o que foi otimizado (com prova de equivalência) e o que ficou desenhado para os
próximos lotes (PERF-B cursor/watermark, PERF-C paralelismo).

---

## 1. Arquitetura atual (medida)

```text
anomaly_detection_loop (intervalo 30 s, apos o termino do ciclo)
  -> run_detection_template_rules_once()          # end_dt = now() UMA vez
       -> para cada uma das 28 regras ativas
            -> evaluate_detection_template_rule()
                 -> detection_rule_zone_prefixes(template)   # pares (zona, prefixo)
                      -> query_detection_rule_candidates()   # 1 query ClickHouse por par
```

Inventário real:

| Item | Valor |
|---|---|
| templates ativos | 2 (`CLIENTES-PUBLICOS-DEFAULT`, `CLIENTES-PUBLICOS-IMPLANTAR`) |
| regras ativas | 14 + 14 = **28** |
| pares (zona, prefixo) | 6 (template 1) + 9 (template 2) = **15 linhas / 14 prefixos distintos** |
| queries por ciclo | 14×6 + 14×9 = **210** |
| queries distintas (SQL+params) | **168** (42 duplicatas exatas = 20%) |
| hashes normalizados distintos | 32 |
| janela avaliada | `window_seconds = 60` em todas as regras |

**Taxonomia do plano (antes):** 210 = 28 regras × pares do seu template. Não há
compartilhamento: regras do mesmo template com filtros idênticos executam o MESMO scan
uma vez por regra.

---

## 2. Profiling (ANTES)

### 2.1 Ciclo real (harness instrumentado, sem gravar anomalias)

| Métrica | Valor |
|---|---|
| queries ClickHouse | **210** |
| tempo ClickHouse somado | **147,0 s** |
| duração do ciclo (wall) | **163,4 s** |
| tempo fora do ClickHouse (Python/SQLite) | 16,3 s (**10%**) |
| query média / p95 / máx | 0,700 s / 0,92 s / **1,058 s** |
| read_rows | **56,6 M** |
| read_bytes | **2 386 MB** |

Conclusão objetiva: **90% do ciclo é ClickHouse**; o gargalo não é Python/SQLite.

### 2.2 `system.query_log` (60 min)

- 1 767 queries do detector, 1 237 s de ClickHouse (**≈20,6 min de CPU-CH por hora**).
- p95 de `result_rows` = **1000** e 233 queries (13%) bateram no `LIMIT 1000` → o
  `ORDER BY metric_value DESC LIMIT 1000` **é significativo** e faz parte da semântica.
- p95 `memory_usage` = 88,7 MB; máx = 122,7 MB.

### 2.3 Causas-raiz encontradas

1. **Plano R×P sem compartilhamento** → 210 scans/ciclo.
2. **`clickhouse_sample_rate_expr` com 476 condições** (`multiIf` de ~39 KB, em TODA query,
   avaliado por linha). Benchmark A/B na mesma query: **0,630 s → 0,142 s (−77,5%)**.
   Das 238 interfaces cadastradas, apenas **5** têm `sample_rate` diferente do default do
   sensor em cada direção — as outras 228 condições eram **redundantes**.
3. **42 scans idênticos repetidos** no mesmo ciclo.
4. **`uniqExact` sobre colunas que já estão no `GROUP BY`** (sempre = 1).
5. **Prefixos duplicados** em `ip_zone_prefixes` (zona 7, `45.163.144.0/22`, ids 11 e 12)
   → 28 queries em vez de 14 naquele prefixo.

### 2.4 Benchmark de alternativas (query isolada)

| Variante | Tempo | Resultado |
|---|---|---|
| CURRENT | 0,708 s | referência |
| sem o `multiIf` (fallback) | 0,157 s | −77,8% (mas muda o multiplicador) |
| FAST (sem `uniq`) | 0,551 s | −22,1% (muda o payload) |
| `uniqCombined` | 0,585 s | −17,3% (aproximado — não aplicado) |
| `uniq` (HLL) | 0,719 s | ≈0% |
| **poda de condições (equivalente)** | **0,142 s** | **−77,5% com resultado idêntico** |
| + uniq trivial = 1 (equivalente) | 0,126 s | −9,2% adicional, idêntico |

`avg_packet_bytes` **não** custa SQL: é derivado (`bytes/packets`) na montagem do item.

### 2.5 Late arrival (received_at × flow_time, 30 min, `VALID_TIME`)

| p50 | p95 | p99 | máx |
|---|---|---|---|
| 26 s | **124 s** | **252 s** | 437 s |

Ingestão ≈ 3 500 rows/s (~210 k rows/min). Máquina: 16 vCPU / 32 GB; ClickHouse ≈5,2 cores,
backend ≈1,4 core, pmacct (ingestão) ≈1,1 core, load 7,3.

---

## 3. PERF-A — o que foi implementado

Todas as três mudanças são **semanticamente equivalentes** (mesmas linhas, mesmas métricas,
mesma severidade, mesma detection key, mesmo target).

1. **Poda de condições redundantes do sample-rate** (`clickhouse_sample_rate_expr`):
   interfaces cujo rate efetivo é igual ao default do sensor não geram condição (o default
   já cobre aquele `if_index` com o MESMO valor). 238 interfaces → **10 condições + 8
   defaults (18)** em vez de 484.
2. **`uniqExact` trivial → `toUInt64(1)`** quando a coluna já faz parte do `GROUP BY`
   (`dst_ip` real na chave, `dst_port`/`src_port` na chave).
3. **`DetectionScanCache`** (novo, teto de 30 000 linhas): dentro de UM ciclo, SQL +
   parâmetros idênticos reaproveitam as mesmas linhas. 210 avaliações → **168 scans reais**
   (42 reusados). O cache morre ao fim do ciclo; nenhuma persistência nova.

### 3.1 Benchmark ANTES × DEPOIS (mesmo harness, ciclos reais)

| Métrica | ANTES | DEPOIS | Ganho |
|---|---|---|---|
| queries por ciclo | 210 | **169** | −19,5% |
| tempo ClickHouse | 147,0 s | **28,0 s** | **−80,9%** |
| duração do ciclo (wall) | 163,4 s | **43,6 s** | **−73,3%** |
| query média | 0,700 s | 0,166 s | −76,3% |
| query máxima | 1,058 s | 0,300 s | −71,6% |
| read_rows | 56,6 M | 36,7 M | −35,3% |
| read_bytes | 2 386 MB | 1 624 MB | −31,9% |
| fora do ClickHouse | 16,3 s | 15,5 s | — |

### 3.2 Prova de equivalência (mesma janela, mesmas regras, mesmos dados)

Janela fixa `20:29:00–20:30:00 UTC` (antiga, sem late arrival), **sem `LIMIT`** (200 000):

- OLD (código da imagem em `/app`) × NEW (código do repo): **106 419 linhas**,
  **conjuntos idênticos, 0 diferenças** (campo a campo, incluindo `packets_s`, `bits_s`,
  `flows`, `unique_*`, `detected_exporter_count`, `key` e `target`).
- Com `LIMIT 1000` a comparação acusa diferença **mesmo rodando o MESMO código duas vezes**
  (136 linhas) — ver §5.3.

Testes de regressão: `tests/test_detection_and_calibration_static`,
`test_anomaly_threshold_policy_static`, `test_traffic_learning_static`,
`test_udp_inbound_distribution_evidence` → **mesmas 6 falhas pré-existentes** antes e depois
(nenhuma regressão nova).

---

## 4. Resultado no ciclo

O intervalo efetivo do detector era `ciclo + 30 s ≈ 193 s` (~3,2 min). Com PERF-A:
`44 + 30 ≈ 74 s` (~1,2 min) no mesmo volume de tráfego — e o tempo de ClickHouse por ciclo
cai de 147 s para 28 s, reduzindo a disputa de CPU com a ingestão.

---

## 5. Achados não implementados (e por quê)

### 5.1 Compartilhar scans que diferem apenas na métrica

28 queries/ciclo poderiam virar 0 se o scan fosse agnóstico de métrica (frame
multi-métrica). **Não aplicado**: 13% das queries batem no `LIMIT 1000` e o top-N é
ordenado por métrica — um frame único mudaria quais grupos são avaliados. Caminho seguro
futuro: `LIMIT N BY metric` ou materializar os grupos e aplicar o top-N em Python.
Status: candidato a PERF-C.

### 5.2 `uniqCombined` / `uniq`

`uniqCombined` dá −19% na query já podada, mas é **aproximado**; `uniq` não ganha. Precisamos
de precisão exata para DDoS/carpet bombing (contagem de alvos) → **mantido `uniqExact`**.
Quando o volume justificar, a decisão deve ser explícita e documentada por regra.

### 5.3 `ORDER BY metric_value DESC LIMIT 1000` era não determinístico em empates

Duas execuções do MESMO código na mesma janela devolveram **136 linhas diferentes**: empates
de `metric_value` escolhiam grupos diferentes a cada execução (risco de *flapping*).
**Resolvido em PERF-A.1** (ver §9).

### 5.4 Prefixo duplicado em `ip_zone_prefixes`

Zona 7 tem `45.163.144.0/22` duas vezes (ids 11 e 12) → 28 queries/ciclo em vez de 14.
Não deduplicamos em código porque, para regras com `domain = subnet`, a chave de dedupe usa
`prefix_id` (`security_anomaly_dedupe_key`) — mudaria o comportamento. **Recomendação:**
inativar a linha duplicada (dado), não o código.

---

## 6. PERF-B — cursor temporal + watermark (desenhado, NÃO implementado)

Problema: se o ciclo demora mais que `window_seconds`, avaliar `now()-60s → now()` deixa
buraco. Projeção:

```text
estado: last_evaluated_until (por template), watermark_delay_seconds (default 240 s)
limite = now() - watermark_delay            # p95=124 s, p99=252 s (medido)
enquanto last_evaluated_until + window <= limite:
    avaliar [last_evaluated_until, last_evaluated_until + window)
    last_evaluated_until += window
    (commit do cursor somente ao final de cada fatia bem-sucedida)
```

- **Nunca** avaliar janela parcial: o cursor só avança após sucesso.
- Atraso de detecção passa a ser `watermark_delay` (240 s cobre o p95=124 s com folga;
  300 s é o valor conservador para o p99=252 s).
- Idempotência: `upsert_security_anomaly` já deduplica por `dedupe_key`, então reavaliar a
  mesma janela não cria anomalia duplicada.
- Requer coluna/tabela nova (`detection_cursor`) → **migration separada**, em commit próprio.

---

## 7. PERF-C — paralelismo controlado (recomendação)

Depois do PERF-A, o ciclo gasta ~28 s de ClickHouse. Se ainda for necessário paralelizar:

- **2 workers** (um por template, ou por grupo `direction`/`protocol`) — recomendado.
- Máximo **4**; nunca 1 query por regra.
- A ingestão tem prioridade: o ClickHouse já usa ~5,2 de 16 cores com pico de 523%. Medir
  antes/depois: `load average`, `docker stats` do backend/clickhouse, p95 do late arrival e
  rows/s de ingestão. Se o p95 do late arrival subir, reduzir workers.

---

## 8. Rollback

- Código: `git revert <commit>` (mudança isolada em `backend/app/main.py`).
- Runtime: o backend é *baked* na imagem — voltar a imagem anterior
  (`docker tag gmj-flow-backend:pre-perf-a-<data> gmj-flow-backend:latest && docker compose up -d --no-deps backend`).
- Nenhum schema, nenhuma migration, nenhum dado alterado por este lote.

---

## 9. PERF-A.1 — ORDER BY determinístico (deployado)

**O que mudou:** `ORDER BY metric_value DESC` virou
`ORDER BY metric_value DESC, <chave do GROUP BY> ASC` (bucket, src_ip, dst_ip, internal_ip,
protocol, [+ src_port/dst_port quando fazem parte da chave]). A métrica continua sendo o
critério **principal**; a chave do grupo entra só como desempate — e como a chave identifica
unicamente cada linha, a ordem é total e o top-N (`LIMIT 1000`) passa a ser reprodutível.

**Commit:** `6845ea8`.

### 9.1 Prova de determinismo (3 execuções, mesma janela fixa, mesmos dados)

Janela `20:29:00–20:30:00 UTC` (fechada, sem late arrival), `LIMIT 1000`, plano completo
(210 avaliações regra×prefixo):

| Execução | linhas | md5 do dump |
|---|---|---|
| run 1 | 37 378 | `b9b16e9212bdaedc72d0539bdbcfe93b` |
| run 2 | 37 378 | `b9b16e9212bdaedc72d0539bdbcfe93b` |
| run 3 | 37 378 | `b9b16e9212bdaedc72d0539bdbcfe93b` |

**3/3 idênticos byte a byte → 0 flapping.** Contraste: sem o tiebreaker, duas execuções do
mesmo código na mesma janela divergiam em 136 linhas.

Além disso, com o `LIMIT` removido (200 000), o conjunto COMPLETO de grupos continua
idêntico ao código antigo (106 419 linhas) — o tiebreaker não muda *quais grupos existem*,
só *qual subconjunto entra no top-N* quando há empate.

---

## 10. Deploy controlado (2026-10-06, apenas backend)

| Item | Valor |
|---|---|
| imagem anterior | `gmj-flow-backend:latest` = `685d527b032d` (tag de rollback `pre-perf-a-20261006`) |
| imagem nova | `gmj-flow-backend:deploy-6845ea8` = `4dd87121…` |
| procedimento | `docker compose build backend` + `docker compose up -d --no-deps backend` (sem `--remove-orphans`) |
| PMACCT | intocado (`Up 2 weeks`) |
| health | `:8080` 200 · `:8081` 200 |

### 10.1 Observação em runtime (Pass A pós-deploy)

| Métrica | ANTES (produção, código antigo) | DEPOIS (runtime) |
|---|---|---|
| tempo ClickHouse do passo de regras | 147,0 s | **~10–24 s** (−85%) |
| wall do passo de regras (28 regras) | 163,4 s | **89,7 s** (−45%) |
| queries do passo | 210 | 168–169 |
| CPU ClickHouse (amostra) | ~523% | **~160%** |
| CPU backend (amostra) | ~142% | ~102% |
| ingestão | ~2 400–3 500 rows/s | **~2 400 rows/s (sem degradação)** |
| anomalias | estável | estável (sem flapping nos logs) |
| erros do detector | 0 | 0 |

**Leitura:** o ganho de ClickHouse aparece integralmente no runtime. O *wall* caiu menos
porque, com as queries 4× mais rápidas, o resto do passo passou a dominar — e esse resto
não é Python puro: é **contenção** (GIL/CPU/SQLite) com os outros 10+ threads do backend
(SNMP, BGP, ASN, threat intel, behavioral, HTTP) e com a fase legada de vetores de ataque,
que roda **sequencialmente depois** do passo de regras no mesmo ciclo.

Medição do ciclo completo pós-deploy: passes iniciados às `13:08:17`, `13:10:12`, `13:12:14`
→ ~115–125 s start-to-start (antes: ~193 s).

### 10.2 Custo do cliente ClickHouse (medido)

Cada `query_clickhouse` abre e fecha um cliente novo: **0,034 s/query** vs **0,005 s/query**
reutilizando o cliente → **0,029 s/query** de overhead (~86% do custo de uma query trivial),
≈4,9 s por passo de 168 queries. Não é o gargalo principal, mas é ganho fácil (PERF-A.2).

### 10.3 Onde o tempo foi parar (medição decisiva)

O MESMO passo, instrumentado por fase, dentro do container:

| Componente | Tempo | Por query |
|---|---|---|
| conexão ClickHouse (`get_client`) | 4,7 s | 28 ms |
| execução da query (`client.query`) | **22,7 s** | 133 ms |
| Python (montagem do SQL + linhas + itens, 31 387 linhas) | 14,7 s | — |
| **wall do passo (processo isolado)** | **42,1 s** | — |
| **wall do passo no processo de produção (uvicorn)** | **~180 s** | — |

Ou seja: quando roda isolado, o passo leva ~42 s; dentro do processo da API leva ~180 s.
A diferença (~140 s) **não é ClickHouse nem Python puro — é contenção**: o backend roda 10+
threads (SNMP, BGP, ASN, threat intel, behavioral, HTTP) e o GIL serializa o trabalho
Python. Como as queries ficaram 4× mais rápidas (147 s → 23 s), a espera passou a dominar.

**Conclusão:** o próximo ganho de wall não vem de otimizar SQL, e sim de **isolar o detector**
(processo/container próprio) — o que também destrava o paralelismo real (PERF-C).

---

## 11. Semântica event-time × ingestion-time (medida no servidor real)

Cadeia: `nfacctd` (`nfacctd_time_new: true`, `aggregate[flows]: … timestamp_start`,
`print_refresh_time: 5`) → CSV → `collector/pmacct/parse_pmacct.py` → ClickHouse `flow_raw`.

| Campo | Semântica real medida |
|---|---|
| `flow_time` | **início do flow** (`timestamp_start` do pmacct); idêntico a `flow_start` em **100%** das linhas |
| `flow_start` | igual a `flow_time` (100%) |
| `flow_end` | **sempre NULL** (0 de 1 984 593 linhas com valor) |
| `duration_ms` | **sempre 0** (não há fim de flow no dado) |
| `received_at` | momento da inserção no ClickHouse (parser), ~refresh de 5 s |

### 11.1 Late arrival (received_at − flow_time, `VALID_TIME`)

| Janela | p50 | p95 | p99 | máx |
|---|---|---|---|---|
| 30 min (pré-deploy) | 26 s | 124 s | 252 s | 437 s |
| 15 min | 25 s | 125 s | 142 s | 176 s |
| 10 min (pós-deploy) | 25 s | 132 s | 333 s | — |

Como `flow_time` é o **início** do flow e o exporter só exporta quando o flow expira
(active/inactive timeout), esse "lag" embute a **duração do flow**: os casos de ~125 s são
flows de ~2 min. Para DDoS (flows curtos) o lag observado é próximo do p50 (~25 s).

### 11.2 Consequências para FAST × RECONCILIAÇÃO

1. **Não usar `received_at` como relógio do FAST.** Ele mistura inícios de flow de épocas
   diferentes; o FAST e a reconciliação precisariam de buckets diferentes, e os mesmos dados
   entrariam em dois buckets → risco de duplicar/errar consolidação.
2. **`flow_time` serve para os dois passes**, com o mesmo bucket alinhado (é o campo que as
   28 regras já usam). `received_at` fica como **métrica de lag de ingestão**.
3. O bucket por `flow_time` fica **incompleto** até os flows daquele intervalo expirarem →
   é exatamente o que o watermark cobre (`p95≈125 s`, `p99≈250 s`).

---

## 12. PERF-B — cursor + watermark + reconciliação (implementado, NÃO deployado)

### 12.1 Granularidade do cursor

**Um cursor por `(template_id, window_seconds)`** — o menor número de cursores que mantém
isolamento entre templates com janelas diferentes (hoje: 2 cursores, ambos de 60 s).
Um cursor global misturaria janelas; um por regra multiplicaria estado sem necessidade.

```sql
CREATE TABLE IF NOT EXISTS detection_cursor (
    template_id INTEGER NOT NULL,
    window_seconds INTEGER NOT NULL,
    last_evaluated_until TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (template_id, window_seconds)
);
```

### 12.2 Regras de avanço (implementadas)

- **Sem gap:** o próximo bucket é sempre `[last_evaluated_until, +window)`; buckets fechados.
- **Só avança após sucesso:** se qualquer regra do bucket falhar, o cursor NÃO avança e o
  bucket é retentado no ciclo seguinte (com log de warning).
- **Restart:** o cursor é persistido, então o processo retoma do ponto exato.
- **Clock skew:** se `now() - watermark` for anterior ao cursor, nada é processado e o cursor
  não anda (proteção contra relógio para trás).
- **Bootstrap:** sem cursor, o primeiro valor é o último bucket fechado antes do watermark
  (não varre histórico).
- **Limite por ciclo:** `GMJFLOW_DETECTION_RECONCILE_MAX_BUCKETS` (default 6) evita uma
  avalanche após uma parada longa; o restante aparece como `buckets_pending`.

### 12.3 Configuração

| Variável | Default | Efeito |
|---|---|---|
| `GMJFLOW_DETECTION_RECONCILE_ENABLED` | `true` | liga/desliga o passo de reconciliação (kill switch) |
| `GMJFLOW_DETECTION_WATERMARK_SECONDS` | `240` | atraso mínimo do bucket fechado (p95≈125 s, p99≈250 s) |
| `GMJFLOW_DETECTION_RECONCILE_MAX_BUCKETS` | `6` | teto de buckets por ciclo |

### 12.4 Idempotência e consolidação (por que não duplica)

A `dedupe_key` das anomalias (`vector|zone_id|target|protocol`) **não inclui bucket nem
tempo** — por isso o FAST e a reconciliação caem no **mesmo** `upsert_security_anomaly`:
o evento é atualizado (`first_seen` mínimo, `last_seen` máximo, métrica = máximo,
`source_details` recalculado), nunca duplicado. Há teste explícito garantindo que a chave
não depende de tempo. Incluir o bucket na chave criaria uma anomalia por bucket — o oposto
do requisito.

### 12.5 Observabilidade (novos campos)

`GET /api/detection/status` e `/api/system/...` passam a expor:
`cycle_duration_seconds`, `queries_last_cycle`, `scan_cache_hits`, `scan_cache_misses`,
`buckets_processed`, `buckets_pending`, `last_evaluated_until`, `watermark_at`,
`detector_lag_seconds`.

### 12.6 Testes (`tests/test_detection_cursor.py`, 11 casos)

bootstrap (1 bucket e cursor persistido) · contiguidade sem gap · falha não avança o cursor ·
retry reprocessa o mesmo bucket · limite por ciclo + `buckets_pending` · restart retoma do
cursor persistido · clock skew não processa/avança · nenhum bucket avaliado duas vezes ·
watermark limita a janela · isolamento por (template, janela) · chave de dedupe estável.

Também validado com dados reais: avaliação de um bucket fechado antigo
(`20:29→20:30Z`) para a regra DNS retornou 212 linhas, `threshold_not_met`, 0 anomalias.

---

## 13. FAST × RECONCILIAÇÃO — avaliação

| | Opção A (watermark único) | Opção B (FAST + reconciliação) |
|---|---|---|
| latência de alerta | `watermark` (240–300 s) + passo | lag do FAST (~25 s) + cadência do ciclo |
| cobertura | completa (p95/p99) | completa pelo passo de reconciliação |
| custo de queries | 1× | **~2×** (um passe rápido + um passe definitivo) |
| complexidade | baixa | média (cursor por template/janela, consolidação) |
| risco | alerta DDoS 4–5 min atrasado | exige idempotência (já garantida) |

**Escolha: Opção B**, com `flow_time` nos dois passes (§11.2) e a `dedupe_key` atual como
consolidador. Motivo: a Opção A atrasa a detecção de DDoS em 4–5 min, o que é inaceitável
para reflexão/amplificação; a Opção B preserva o alerta rápido e garante que nenhum bucket
fique sem avaliação completa.

**Custo assumido:** com o PERF-A, um passe custa ~22 s de ClickHouse; o passo de
reconciliação adiciona ~1 bucket por grupo (≈1 passe) por ciclo → ~+100% de queries.
O kill switch permite desligar; e o PERF-A.2 (reuso de cliente + isolamento da fase legada)
é o caminho para absorver esse custo.

### 13.1 Tamanho de bucket

| Bucket | Prós | Contras |
|---|---|---|
| 10 s | latência mínima | 6× mais buckets/queries; ruído em PPS |
| 15 s | bom para SYN/ACK flood | idem |
| 30 s | equilíbrio | 2× buckets vs 60 s |
| **60 s** | **atual (`window_seconds`), custo mínimo, já validado** | pior latência de bucket |

**Recomendação:** manter **FAST = 60 s** e **RECONCILIAÇÃO = `window_seconds` (60 s)** neste
lote (nada muda no schema de regras); ao criar os vetores inbound/DoS (próximo lote), usar
`window_seconds=30` (ou 15) *por regra* — o cursor já é por `(template, window)` e suporta
janelas diferentes sem mudança estrutural.

### 13.2 Latência esperada (com o desenho atual)

- **FAST:** dado disponível em ~25 s (p50 do lag) → alerta no próximo passe; hoje o ciclo
  completo é ~115–125 s (dominado pela fase legada + contenção) → **latência típica ~1–2 min**.
  Para chegar a 10–30 s é preciso separar a fase legada da fase de templates (PERF-A.2/C) —
  o passo de templates isolado leva ~90 s hoje e poderia rodar a cada 30 s.
- **RECONCILIAÇÃO:** fecha o bucket em `T + 240 s` → evento consolidado até ~`T + 240 s + passo`.

---

## 14. Próximos passos recomendados

1. **PERF-A.2** (barato): reutilizar um cliente ClickHouse por ciclo (≈5 s por passo) e
   **isolar a fase legada** (`active_attack_vectors`) da fase de `detection_template_rules`.
2. **PERF-C.0 — isolar o detector em processo/container próprio** (maior ganho de wall):
   medido que ~140 s do passo de ~180 s são contenção/GIL com as outras threads da API.
   Com o detector isolado, o passo volta aos ~42 s medidos em isolamento e o paralelismo
   por execution group passa a ser real.
3. **Deploy do PERF-B** (decisão do operador): ligar a reconciliação e acompanhar
   `buckets_pending`/`detector_lag_seconds` por 3+ ciclos; se o custo incomodar, desligar por
   `GMJFLOW_DETECTION_RECONCILE_ENABLED=false`.
4. **PERF-C** (paralelismo): 2 workers (um por template), máximo 4; o cursor por
   `(template, window)` já permite paralelizar por execution group sem processar o mesmo
   bucket duas vezes.
5. Limpar o **prefixo duplicado** (zona 7, `45.163.144.0/22`, id 12) — ação de DADO, com
   autorização explícita (não fazer em código, pois muda a `dedupe_key` de regras `subnet`).

---

## 15. Rollback (atualizado)

- **PERF-A + PERF-A.1** (deployados): voltar a imagem anterior
  `docker tag gmj-flow-backend:pre-perf-a-20261006 gmj-flow-backend:latest && docker compose up -d --no-deps backend`
  (imagem `685d527b032d`). Código: `git revert 6845ea8 6f06f24`.
- **PERF-B** (não deployado): `git revert 26cce39`. Se já estiver deployado, também
  `GMJFLOW_DETECTION_RECONCILE_ENABLED=false` desliga o passo sem rollback de imagem; a
  tabela `detection_cursor` pode ficar (inofensiva) ou ser removida.
- Nenhuma migration de dados; nenhum threshold alterado; nenhuma anomalia apagada.

