# Detector de anomalias — desempenho do ciclo (PERF-A)

> **Status:** PERF-A implementado e validado (sem deploy) · **Data:** 2026-10-05
> **Fonte de verdade:** medições feitas no servidor real (`root@172.20.10.40`), `flowdb.flow_raw`.
> **Código:** `backend/app/main.py` (`run_detection_template_rules_once`,
> `evaluate_detection_template_rule`, `query_detection_rule_candidates`,
> `DetectionScanCache`, `clickhouse_sample_rate_expr`).

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

### 5.3 `ORDER BY metric_value DESC LIMIT 1000` é não determinístico em empates

Duas execuções do MESMO código na mesma janela devolveram 136 linhas diferentes: empates de
`metric_value` escolhem grupos diferentes a cada execução. Isso pode causar *flapping* de
anomalias (cria/encerra) entre ciclos. **Recomendação:** adicionar tiebreaker determinístico
(ex.: `ORDER BY metric_value DESC, dst_ip, src_ip, protocol, dst_port`). Fora do escopo deste
lote por alterar levemente qual grupo entra no top-N.

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

