# GMJ-FLOW — Handoff: desempenho do detector de anomalias (PERF-A / A.1 / B / C.0)

> **Data:** 2026-10-06 · **Idioma:** responder sempre em português do Brasil.
> **Objetivo:** permitir que um novo agente continue o trabalho **sem depender do histórico da
> conversa anterior**. Leia este documento inteiro antes de alterar qualquer coisa.
> **Servidor canônico:** `root@172.20.10.40` · **repo:** `/home/guilherme/GMJ-FLOW`.
> O servidor é a fonte de verdade — **não** use clone local para inferir comportamento.

---

## 1. Estado git

| Item | Valor |
|---|---|
| branch | `preserve/fibinet-20260928` |
| HEAD | `e813273` — *docs: record controlled PERF-B activation, budget analysis and PERF-C.1 preparation* |
| `git status` | apenas `?? tests/test_grafana_perf01.py` |

**NÃO tocar em `tests/test_grafana_perf01.py`** (arquivo de outra frente, untracked).

Antes de começar: `git status`, `git branch --show-current`, `git rev-parse --short HEAD`.

---

## 2. Commits importantes (mais antigo → mais novo)

| Commit | Mensagem |
|---|---|
| `6f06f24` | `perf(detection): prune redundant sample-rate conditions and cache scans per cycle` |
| `6845ea8` | `perf(detection): make rule top-N deterministic with a group-key tiebreaker` |
| `2958657` | `docs: record deterministic top-N, event-time semantics and temporal cursor design` |
| `9a66f2e` | `docs: add phase breakdown and GIL contention finding after PERF-A deploy` |
| `e70af02` | `feat(detection): isolate anomaly detector in dedicated worker process` |
| `64f807b` | `fix(detection): immediate worker lease takeover and shared status/error surfacing` |
| `e813273` | `docs: record controlled PERF-B activation, budget analysis and PERF-C.1 preparation` |

(`26cce39` — `feat(detection): persist temporal cursor and reconcile closed buckets with watermark`
— está entre `6845ea8` e `2958657`.)

---

## 3. Arquitetura atual em produção

```
gmj-flow-backend   (uvicorn app.main:app)
  - API HTTP / UI backend / demais workers (SNMP, BGP, ASN, threat intel, behavioral, mídia)
  - detector in-process DESABILITADO

gmj-flow-detector  (python -m app.detection_worker)
  - processo dedicado, MESMO código/imagem do backend
  - ÚNICO owner do detector (lease em SQLite)
  - expõe /health e /status próprios na porta 8090 (healthcheck do container)

gmj-flow-clickhouse  (flowdb.flow_raw — 24/7, ingestão ~2,4–3,7 k rows/s)
```

**O detector isolado está EM PRODUÇÃO** desde 2026-10-06. Imagem:
`gmj-flow-backend:latest` = `deploy-64f807b` (`c6865fb9bb13`); rollback de imagem:
`gmj-flow-backend:pre-perf-a-20261006` (`685d527b032d`).

---

## 4. Flags importantes (produção)

**Backend (`gmj-flow-backend`):**

```env
GMJFLOW_DETECTION_INPROCESS_ENABLED=false
```

**Detector (`gmj-flow-detector`):**

```env
GMJFLOW_DETECTION_WORKER_ENABLED=true
GMJFLOW_DETECTION_LEASE_TTL_SECONDS=60
GMJFLOW_DETECTION_RECONCILE_ENABLED=false     # PERF-B DESLIGADO
GMJFLOW_DETECTION_WATERMARK_SECONDS=240
GMJFLOW_DETECTION_RECONCILE_MAX_BUCKETS=6
GMJFLOW_DETECTION_WORKER_PORT=8090
```

**IMPORTANTE:** o PERF-B existe no código (`reconcile_detection_template_buckets`), mas a
reconciliação está **DESLIGADA** em produção.

---

## 5. PERF-A — o que já foi ganho (deployado)

| Métrica | Antes | Depois |
|---|---|---|
| queries/ciclo | 210 | **168–170** |
| ClickHouse do passo | 147,0 s | **22–29 s** |
| wall do passo | 163,4 s (isolado) | **~42 s isolado** |
| read_rows | 56,6 M | **36,7 M** |
| read_bytes | 2.386 MB | **~1.624 MB** |

Ganhos implementados:

- **poda da expressão de sample-rate** no `clickhouse_sample_rate_expr`: 484 → **18 condições**
  (as demais eram redundantes porque o default do sensor cobre o mesmo `if_index` com o mesmo
  rate) — ~78% do tempo de cada query;
- **cache de scans por ciclo** (`DetectionScanCache`, SQL+params idênticos): **42 scans
  repetidos** reutilizados por ciclo;
- **`uniqExact` trivial removido** (quando a coluna já está no `GROUP BY`, o resultado é
  constante 1);
- **tiebreaker determinístico no `ORDER BY`** (`metric_value DESC, <chave do GROUP BY> ASC`):
  antes, duas execuções do mesmo código na mesma janela divergiam em 136 linhas (flapping);
  depois, 3 execuções → md5 idêntico (`b9b16e92…`).

Equivalência comprovada: janela fixa, sem `LIMIT` → **106 419 linhas idênticas** entre o código
antigo e o novo.

---

## 6. PERF-C.0 — detector isolado da API (deployado)

| Métrica | Antes (dentro da API) | Depois (isolado) |
|---|---|---|
| passo de regras | 90–238 s | **38,8–44,3 s** |
| ciclo completo | ≥193 s | **52–58 s** |
| ClickHouse do passo | 22–29 s | 22–29 s (igual) |
| ingestão | estável | estável (1,9–3,0 k rows/s) |
| resultado funcional | — | **equivalente** |

**Causa comprovada do atraso anterior:** contenção de GIL/CPU com as demais threads do backend.
Medição: `conexão 4,7 s + queries 22,7 s + Python 14,7 s = 42,1 s` isolado vs 90–238 s no
processo da API — ~140 s de espera.

---

## 7. Ownership / lease

- Tabela SQLite: **`detection_worker_lease`** (`id='detector'`, owner `detector@host:pid`,
  `heartbeat_at`, `expires_at`), adquirida com `BEGIN IMMEDIATE`.
- **Heartbeat: 20 s · TTL: 60 s.** Um segundo worker **não executa** enquanto o lease estiver
  ocupado (fica em `lease do detector detido por …; aguardando`).
- O worker adquire o lease **no boot** (takeover imediato após queda do anterior).
- `POST /api/detection/run-now` retorna **409** se outro processo for o owner.
- Tabela **`detection_runtime_state`** guarda o `scheduler_status` (JSON) para a API ler o
  status sem depender da memória do outro processo.

---

## 8. Status / observabilidade

`GET /api/detection/status` fornece:

- `status_source` (`worker` | `inprocess` | `none`), `owner`, `status_age_seconds`,
  `worker_lease`;
- `cycle_duration_seconds`, `queries_last_cycle`, `scan_cache_hits`, `scan_cache_misses`;
- `buckets_processed`, `buckets_pending`, `last_evaluated_until`, `watermark_at`,
  `detector_lag_seconds`;
- além dos campos antigos (`last_run_at`, `last_success_at`, `last_error`, `rules_enabled`,
  `rules_evaluated_last_run`, `anomalies_created_last_run`, `skipped_reasons`).

---

## 9. PERF-B — cursor + watermark (implementado, **REPROVADO** em produção)

Tabela:

```sql
detection_cursor(template_id, window_seconds, last_evaluated_until, updated_at)
```

Cursor por **`(template_id, window_seconds)`** (hoje 2 cursores, ambos com janela 60 s).
Watermark default: **240 s**.

**Teste controlado em produção (2026-10-06), `RECONCILE_ENABLED=true` apenas no detector:**

| ciclo | wall (worker) | queries | buckets | `detector_lag_seconds` | cursor |
|---|---|---|---|---|---|
| 1 | 110,1 s | 362 | 2 | 242 s | 14:32 |
| 2 | 155,1 s | 580 | 4 | 262 s | 14:34 |
| 3 | — (passo 185,4 s) | 786 | 6 (= teto) | 267 s | 14:37 |

**Custo:** FAST ~40 s + 2 grupos de reconciliação × ~40 s ≈ **120 s de trabalho para cada 60 s
de tempo real** → backlog estrutural (cresce ~35 s por ciclo no teto de 6 buckets).
**Ação tomada:** `RECONCILE_ENABLED=false` restaurado; ciclos voltaram a **54,3 / 54,5 s**.

> **Nota ao religar:** o cursor ficou em `2026-10-06T14:37:00Z` (t1 e t2). Ao reativar, limpar
> antes para começar “do agora”: `DELETE FROM detection_cursor;` (a linha é recriada no
> bootstrap do próximo ciclo).

**O que ficou provado (positivo):**

- buckets de reconciliação **alinhados e contíguos** (via `system.query_log`):
  `14:31:00–14:32:00 → 14:32:00–14:33:00 → … → 14:36:00–14:37:00`, ~194–206 queries cada;
- cursor avança 60 s por bucket e sobrevive a restart/recreate;
- **sem duplicação** de anomalias (`security_anomalies` = 68 total / 1 ativo durante o teste).

---

## 10. Watermark / late arrival

Semântica real (medida): `flow_time = flow_start`; `flow_end` **NULL**; `duration_ms` **0**;
`received_at` = momento de inserção no ClickHouse (refresh do pmacct 5 s).

| Lag | Valor |
|---|---|
| p50 | ~25 s |
| p95 | ~125 s |
| p99 | ~250–333 s |

Cobertura medida (35 buckets fechados, 4,9 M linhas):

| Watermark | Cobertura |
|---|---|
| 240 s | **99,485%** |
| 300 s | 99,704% |

**Decisão atual: manter 240 s** (+0,22 p.p. não justifica +60 s de latência; a cauda >300 s
não é coberta por nenhum dos dois).

---

## 11. Dedupe FAST / reconciliation

A `dedupe_key` **não contém bucket nem tempo**:

```
vector | zone_id | target | protocol
```

(para `domain=subnet`, o `target` é o `prefix_id`; para DNS single-flow há variante própria).

FAST e reconciliação caem no mesmo `upsert_security_anomaly` → **atualizam o mesmo evento**
(`first_seen` mínimo, `last_seen` máximo, métrica = máximo). Durante o teste PERF-B:
`security_anomalies` permaneceu **68 total / 1 ativo**, sem duplicação; há teste unitário
garantindo que a chave não depende de tempo. **Não alterar a chave** nesta fase.

---

## 12. PERF-C.1 — 2 workers (NÃO implementado)

**Deliberadamente bloqueado**: o gate (“PERF-B estável por ≥5 ciclos”) não foi atendido.

- unidade de paralelismo correta: **execution groups `(template_id, window_seconds)`** (2 hoje),
  cada um com cursor independente — permite atribuir grupos a workers sem processar o mesmo
  bucket duas vezes;
- **nunca** uma thread por regra, nunca 1 query por regra simultânea;
- começar com **2** e nunca começar com 4;
- antes disso, **baratear a reconciliação** (§13).

---

## 13. Próxima otimização recomendada (antes de paralelizar)

A) **Triagem barata por bucket** — 1 query agregada decide se o bucket merece o passe completo
(buckets sem tráfego relevante passam de ~84–100 scans para ~1 query).

B) **Reconciliação dirigida** — reconciliar apenas escopos/prefixos/targets/protocolos que o
FAST sinalizou (consolida o evento; não recupera detecção perdida).

C) **Shared multi-metric frame** — 1 scan devolvendo `bps`, `pps`, `flows`, `bytes`, `packets`,
`unique_src_ips`, `unique_dst_ips`, `unique_src_ports`, `unique_dst_ports`,
`avg_packet_bytes`, avaliando várias regras em memória.

Depois disso, testar 2 execution workers com medição de ingestão como critério.

---

## 14. Novos vetores — próxima frente funcional

Retomar **Attack Vectors inbound/download**. Presets alvo: DNS Reflection, DNS Query Flood,
NTP Reflection, SSDP Reflection, CLDAP Reflection, Memcached, UDP Flood, TCP SYN Flood,
TCP SYN-ACK Flood, TCP ACK Flood, ICMP Flood.

Suportar:

- **single target**: `GROUP BY dst_ip`;
- **multi-target / carpet bombing**: `GROUP BY prefix/subnet/zone` + `unique_dst_ips` +
  `unique_src_ips`.

Métricas desejadas: `bps`, `pps`, `flows`, `avg_packet_bytes`, `unique_src_ips`,
`unique_dst_ips`, `unique_src_ports`, `unique_dst_ports`.

Triggers booleanos desejados:

```text
bps >= 15M OR pps >= 3k
(bps >= 50M OR pps >= 10k) AND unique_dst_ips >= 8
```

---

## 15. DSL

Existe em `backend/app/services/detection_dsl/` (catálogo/parser/validator/AST/serializer/
compiler). **Ainda NÃO integrada ao detector produtivo**; hoje ela alimenta apenas o Flow Search
por expressão.

Vocabulário canônico: `inbound`, `outbound`, `both`.
Aliases históricos: `receives → inbound`, `transmits → outbound`, `sends → outbound`.
Documentação: `docs/detection-rule-language.md`; catálogo em `GET /api/rule-language/catalog`.

---

## 16. DNS inbound existente

Regras produtivas já existentes (template 1 e 2):

| Regra | direction | protocol | src_port | group_by | warning | critical |
|---|---|---|---|---|---|---|
| `DNS_AMP_INBOUND_HIGH_BITS` | `receives` | UDP | 53 | `dst_ip,src_port,protocol` | 80 Mbps | 100 Mbps |
| `DNS_AMP_INBOUND_HIGH_PPS` | `receives` | UDP | 53 | `dst_ip,src_port,protocol` | 20 kpps | 40 kpps |

Ideia futura (NÃO aplicar agora) para um preset mais sensível: warning ~15 Mbps / critical
~30 Mbps + PPS. **NÃO alterar thresholds neste handoff.**

---

## 17. Outras pendências

- **Prefixo duplicado**: zona 7 / `ip_zone_prefixes` id 12 (`45.163.144.0/22` duplicado) —
  **não alterado**; tratar como correção de **dado** separada (não mexer em código: muda a
  `dedupe_key` das regras `domain=subnet`).
- **Problema operacional de deploy**: recriar o container do backend troca o IP e o nginx
  (V1 `:8080` e V2 `:8081`) pode devolver **502** até `docker exec gmj-flow-frontend nginx -s
  reload` e `docker exec gmj-flow-preview nginx -s reload`. Já documentado; não é do detector.

---

## 18. Guardrails (obrigatórios)

**Nunca usar:**

```bash
docker compose --remove-orphans
git reset --hard
git clean
git add .
```

- Não reiniciar **PMACCT**; não tocar **ExaBGP** sem necessidade.
- O **backend é baked na imagem** (`COPY app ./app`); o bind mount do repo é `/app/runtime`.
  Alteração de código só vale após **build controlado**.
- Deploy exige: **backup** (imagem + `docker-compose.yml`), build, **rollback explícito** e
  validação.
- Preferir `docker compose up -d --no-deps <serviço>`.
- Não usar `git add .` — sempre `git add` explícito.
- Não fazer push sem pedido.

---

## 19. Documentação canônica (ler primeiro)

1. `docs/detection-performance.md` — PERF-A, PERF-A.1, PERF-B (reprovado), PERF-C.0, benchmarks,
   semântica event-time, rollback.
2. `docs/anomalies.md` — motor de detecção, vetores, templates, desempenho e tempo.
3. `docs/detection-rule-language.md` — DSL (catálogo, operadores, Flow Search).
4. `docs/GMJ-FLOW-V1-V2-MIGRATION.md` — backlog canônico V1→V2.

---

## 20. Próximo passo

1. Ler este handoff e os 4 documentos acima.
2. Conferir o estado: `git status`, containers, `/api/detection/status`.
3. Escolher **uma** das frentes:

   **A) Performance** — baratear a reconciliação (triagem por bucket / reconciliação dirigida /
   shared multi-metric frame) e só então avaliar 2 execution workers.

   **B) Funcional** — retomar Attack Vectors inbound/download (presets da §14), ainda sem
   alterar thresholds existentes.

4. **Não alterar código antes de entender o estado atual.** Nesta sessão nada foi deployado
   além do que já está descrito aqui; PERF-B permanece DESLIGADO.

