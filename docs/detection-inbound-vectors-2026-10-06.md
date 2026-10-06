# GMJ-FLOW — Fase 4: vetores inbound/download (base funcional)

> **Data:** 2026-10-06 · **Frente escolhida:** B (novos vetores de ataque inbound/download).
> **Escopo:** criar a base funcional (motor + presets + replay + testes) para os novos vetores
> inbound, **sem ativar nada em produção** e **sem alterar** as 2 regras DNS inbound existentes.
> **Guardrails respeitados:** PERF-B continua `RECONCILE_ENABLED=false`; nenhum paralelismo
> (PERF-C.1 adiado); nenhum ajuste de exporter/timeout; nenhum deploy; nenhum push;
> `tests/test_grafana_perf01.py` intocado; prefixo duplicado da zona 7 apenas observado.

## 0. Estado git desta fase

| Item | Valor |
|---|---|
| branch | `preserve/fibinet-20260928` |
| HEAD anterior | `1b266ba` (handoff de performance) |
| commit do motor | `65fbd3a` — *feat(detection): add boolean trigger engine and cardinality metrics for inbound rules* |
| commit dos presets | `2a77968` — *feat(detection): add inbound/download vector presets and historical replay tooling* |
| commit de docs | este documento (fecha a fase) |
| produção | **intocada** (nenhum build/deploy; detector isolado segue estável em ~52–58 s) |

## 1. Matriz de capacidade (auditada no código real → estado esta fase)

| Capacidade | Antes | Agora (Fase 4) |
|---|---|---|
| `bps` / `pps` / `flows` / `flows_s` | já (1 métrica por regra) | inalterada |
| `unique_dst_ips` / `unique_src_ports` / `unique_dst_ports` | já no frame | inalteradas (agora utilizáveis em trigger composto) |
| `unique_src_ips` | **faltava** (nem no frame, nem no banco) | `uniqExact(src)` por grupo no frame; `toUInt64(1)` quando o src é chave do GROUP BY; persistida em `security_anomalies` |
| `avg_packet_bytes` | **não existia** | derivado `sum(bytes)/sum(packets)` no frame; aceito em EVIDENCE **e TRIGGER** |
| OR / AND / trigger composto | **não** (1 métrica + valor) | `trigger_warning_expr` / `trigger_critical_expr` (DSL TRIGGER, avaliação em Python) |
| `GROUP BY dst_ip` (single target) | já (`group_by=dst_ip`) | usado pelos presets single |
| `GROUP BY prefix/subnet` (multi/carpet) | já (`domain=subnet`) | usado pelos presets multi + `unique_dst_ips` |
| `tcp_flags` no motor | apenas `TCP+SYN` | `TCP+SYNACK`, `TCP+ACK`, `TCP+RST`, `TCP+NULL`, `TCP+ALL`, `TCP+SYN-NO-ACK`, `TCP+ACK-NO-SYN` |
| `src_port` / `dst_port` / listas / exclusão | já | inalterado |
| direção inbound | já (`receives`; alias canônico `inbound`) | inalterado |
| EVIDENCE | não existia por regra | coluna `evidence` + snapshot `evidence_values` (no `source_details` da anomalia) |
| DSL | catálogo/parser/validator/compiler (Fases 1–2) | **reutilizada** no TRIGGER: mesma AST (`parse_expression` + `validate_node`), canonicalização no save; nenhum parser novo |
| Replay histórico | inexistente | `scripts/replay_inbound_vectors.py` (somente leitura, mesmo caminho do detector) |

Gaps fechados: `unique_src_ips`, `avg_packet_bytes`, triggers booleanos, flags TCP exatas,
evidência estruturada e ferramenta de replay.

## 2. Arquitetura aditiva (compatibilidade total com o modelo atual)

- **`backend/app/services/detection_triggers.py`** (novo, stdlib + DSL): canonicaliza
  WARNING/CRITICAL, compila `TriggerEvaluator` (cache por par de expressões) e avalia o
  frame (`bps/pps/flows`, `unique_*`, `avg_packet_bytes`). Erros viram issues estruturadas
  (`code` estável, HTTP 400 `INVALID_TRIGGER_EXPRESSION` no save).
- **`detection_template_rules`**: colunas aditivas `trigger_warning_expr`,
  `trigger_critical_expr`, `evidence` (default `''`; ensure idempotente). Regras legadas sem
  esses campos seguem o caminho antigo (`metric` + `warning_value/critical_value` + `over`).
- **Frame compartilhado**: o scan por (regra × prefixo) já devolvia todas as métricas de uma
  vez; a fase adiciona `unique_src_ips` e o derivado `avg_packet_bytes` — **nenhuma query por
  métrica**. O `DetectionScanCache` por ciclo continua valendo para scans idênticos.
- **`security_anomalies`**: coluna `unique_src_ips` (ensure idempotente) + `source_details`
  com `observed` estendido (unique_*, avg_packet_bytes), `evidence` (valores por campo da
  regra) e `trigger` (expressões canônicas).
- **Segurança**: a expressão do usuário **nunca** vira SQL; o scan devolve o frame e o
  trigger é resolvido em Python (mesmo princípio do Flow Search).
- **Presets** (`backend/app/services/inbound_vectors.py`): catálogo em código; payloads saem
  com `enabled=false`. Ativação só por decisão explícita do operador.

## 3. Presets (11) — MATCH/GROUP BY/TRIGGER/EVIDENCE/WINDOW

| id | família | MATCH (protocolo; portas) | WARNING / CRITICAL (single) | multi-target |
|---|---|---|---|---|
| `dns_reflection` | reflection | UDP; src 53; inbound | `bps >= 15M OR pps >= 3k` / `bps >= 30M OR pps >= 8k` | `(bps >= 50M OR pps >= 10k) AND unique_dst_ips >= 8` / `(bps >= 100M OR pps >= 20k) AND unique_dst_ips >= 16` |
| `dns_query_flood` | query | UDP; dst 53; inbound | `bps >= 15M OR pps >= 5k` / `bps >= 30M OR pps >= 10k` | **não** (resolvers enumeráveis; distribuído coberto pelo UDP flood multi) |
| `ntp_reflection` | reflection | UDP; src 123; inbound | igual ao DNS Reflection | igual |
| `ssdp_reflection` | reflection | UDP; src 1900; inbound | igual | igual |
| `cldap_reflection` | reflection | UDP; src 389; inbound | igual | igual |
| `memcached_amplification` | reflection | UDP; src 11211; inbound | `bps >= 50M OR pps >= 5k` / `bps >= 100M OR pps >= 10k` | `(bps >= 100M OR pps >= 10k) AND unique_dst_ips >= 8` / `(bps >= 300M OR pps >= 20k) AND unique_dst_ips >= 16` |
| `udp_flood` | flood | UDP; inbound | `pps >= 100k OR bps >= 1G` / `pps >= 300k OR bps >= 3G` | `(...) AND unique_dst_ips >= 8 / 16` |
| `tcp_syn_flood` | flood | TCP SYN **sem ACK**; inbound | `pps >= 50k` / `pps >= 150k` | `(...) AND unique_dst_ips >= 8 / 16` |
| `tcp_synack_flood` | flood | TCP SYN+ACK; inbound | `pps >= 50k` / `pps >= 150k` | `(...) AND unique_dst_ips >= 8 / 16` |
| `tcp_ack_flood` | flood | TCP ACK **sem SYN**; inbound | `pps >= 100k` / `pps >= 300k` | `(...) AND unique_dst_ips >= 8 / 16` |
| `icmp_flood` | flood | ICMP; inbound | `pps >= 20k OR bps >= 200M` / `pps >= 50k OR bps >= 500M` | `(...) AND unique_dst_ips >= 8 / 16` |

- **Single** = `domain=internal_ip`, `GROUP BY dst_ip`; **multi** = `domain=subnet`
  (`GROUP BY prefix/subnet`, um escaneamento por prefixo de zona) + `unique_dst_ips`.
- EVIDENCE default: `bps, pps, flows, avg_packet_bytes, unique_src_ips` (+`unique_src_ports`
  para reflection e `unique_dst_ports` para floods).
- WINDOW: 30 s e 60 s por preset (o cursor/execução já suporta janelas diferentes).
- **Portas de reflexão registradas** (sem regra genérica substituta — alertas nomeados):
  19, 53, 123, 137, 389, 1900, 3702, 5353, 11211.
- Thresholds são **presets iniciais, sujeitos a calibração**; as 2 regras DNS inbound
  produtivas (`DNS_AMP_INBOUND_HIGH_BITS`/`PPS`) permanecem **inalteradas**.

## 4. Replay histórico (somente leitura, dados reais)

Método: `scripts/replay_inbound_vectors.py` executa o MESMO caminho do detector
(`query_detection_rule_candidates`) em buckets fechados, em container descartável conectado à
rede do ClickHouse (`SELECT` apenas). Prefixos reais: 15 (templates 1 e 2).

### 4.1 Período recente (2026-10-06T16:59Z, 6 buckets × 15 prefixos × 21 variantes × janelas 30/60)

- 3.625 scans executados (+155 reutilizados pelo cache do harness), ~0,12–0,26 s por scan.
- 1.836 combos com tráfego registrados; **0 matches** de WARNING/CRITICAL.
- Máximos observados (por prefixo/janela): `tcp_ack_flood` multi 7,66 Mbps / 705 pps /
  unique_src_ips 3.448 / unique_dst_ips 1.127; `udp_flood` multi 5,37 Mbps / 663 pps /
  unique_src_ips 4.006; `udp_flood` single 124 kbps / 25 pps; `dns_reflection` single ≤ ~5 kbps.

### 4.2 Janela de anomalia UDP conhecida (2026-10-03 19:45–19:47Z, 45.5.248.0/23)

- 430 combos com tráfego; máximos inbound: 12,86 Mbps / 1.165 pps agregados; **0 matches**.
- Observação: a anomalia legada daquele minuto (`PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS`,
  ~78 kpps) é **outbound** (`transmits`); os presets novos são **inbound** — não são
  substitutos dos vetores existentes.

### 4.3 Retenção e limites do replay

- `flow_raw` disponível a partir de **2026-10-02 03:59:39Z** (retenção ~4 dias); janelas
  anteriores (ex.: 2026-09-24) não retornam linhas.

### 4.4 Prova end-to-end de disparo (dados reais, limiar trivial)

Com `bps >= 0` / `critical bps >= 1000` no mesmo caminho: **53/53** linhas matched,
1 critical (alvo de 4.060,67 bps), `avg_packet_bytes` 176–449 B e `unique_src_ips` 1–5 por
alvo — confirma cálculo e avaliação reais; os limiares default simplesmente têm folga enorme
no tráfego atual.

### 4.5 Função de cardinalidade (uniq × uniqCombined × uniqExact)

Benchmark A/B no frame real (mesmo bucket/prefixo): `uniqExact` 0,0535–0,0788 s ·
`uniqCombined` 0,0652–0,0683 s · `uniq` 0,0576–0,0715 s (grupos pequenos; valores idênticos).
**Decisão: manter `uniqExact`** — contagem exata para carpet bombing/DDoS, sem penalidade
mensurável nos volumes atuais; reavaliar quando a cardinalidade por grupo crescer
(a troca deve ser explícita e documentada por regra).

### 4.6 Falsos positivos

**Nenhum** nos períodos avaliados (calmo e pico UDP recente). Risco de FP baixo com os
defaults; a sensibilidade (TP) ainda não foi exercitada por falta de ataque acima dos
limiares — primeira ativação deve ser em modo observação + calibração.

## 5. Testes

- **50 novos**: `test_detection_triggers.py` (18: canonicalização, OR/AND/NOT, unidades
  k/M/G, aliases, cardinalidades, avg derivado, erros), `test_inbound_vector_presets.py`
  (11: catálogo, defaults do plano, canonicalização, evidence válida, payloads desabilitados),
  `test_detection_inbound_engine.py` (21: SQL/condições, single × multi, SYN/SYN-ACK/ACK,
  evidência, save-path, caminho legado intacto).
- **Regressão**: 286 testes com **exatamente as mesmas 9 falhas pré-existentes** da linha de
  base (6 `test_detection_and_calibration_static` + 3 `test_dns_single_flow_outbound`),
  assinatura comparada antes/depois (incluindo o primeiro ofensor estático
  `toUInt64(1) AS unique_dst_ips`, inalterado).
- `test_detection_dsl_validator.py`: o caso que proibia `avg_packet_bytes` em TRIGGER foi
  atualizado (agora permitido), com justificativa no teste.

## 6. Impacto em performance (medido, nada deployado)

- Custo por scan novo: **0,12–0,26 s** (mesma ordem dos ~0,17 s médios atuais).
- Custo por regra nova: 15 prefixos × ~0,2 s ≈ **~3 s por ciclo** (um scan por prefixo por
  ciclo; a janela só muda o bucket).
- Ativar as 21 variantes de uma vez custaria ≈ **+45–55 s/ciclo** (ciclo atual 52–58 s), ou
  seja, dobrando o ciclo — **não recomendado**. Ativação em ondas de 2–4 regras.
- Otimização futura (não implementada): frame único por família/MATCH compartilhado entre
  regras que diferem apenas no trigger.

## 7. Arquivos e rollback

Novos: `backend/app/services/detection_triggers.py`, `backend/app/services/inbound_vectors.py`,
`scripts/replay_inbound_vectors.py`, `tests/test_detection_triggers.py`,
`tests/test_inbound_vector_presets.py`, `tests/test_detection_inbound_engine.py`,
`docs/detection-inbound-vectors-2026-10-06.md`.
Alterados: `backend/app/main.py`, `backend/app/services/detection_dsl/catalog.py`,
`backend/app/services/detection_dsl/__init__.py`, `tests/test_detection_dsl_validator.py`,
`docs/anomalies.md`, `docs/detection-rule-language.md`.

Rollback de codigo: `git revert <commit do motor> <commit dos presets> <commit de docs>`; deploy realizado em 2026-10-06 (secao 9), sem migration destrutiva; colunas novas sao aditivas com default vazio e ensures idempotentes. Rollback de imagem: `gmj-flow-backend:pre-fase4-20261006` (secao 9.6); `pre-perf-a-20261006` tambem vale em emergencia.

## 8. Recomendação de ativação (PARE antes de ativar)

> Atualizacao Fase 4.1 (2026-10-06): deploy feito com presets desligados e o gate de duplicidade do `DNS_REFLECTION_INBOUND` NAO passou (secoes 9.4-9.5). Antes de ativar a onda 1, aplicar a consolidacao proposta como lote separado.

Nada foi ativado. Quando o operador decidir ativar, sugestão em ondas (24–48 h de observação
por onda, medindo `cycle_duration_seconds`, `queries_last_cycle`, criação de anomalias e a
ingestão):

1. `DNS_REFLECTION_INBOUND` + `DNS_QUERY_FLOOD_INBOUND` + `TCP_SYN_FLOOD_INBOUND`
   (~+9 s/ciclo; maior valor por vetor; replay sem FP e folga grande).
2. `NTP_REFLECTION_INBOUND`, `SSDP_REFLECTION_INBOUND`, `CLDAP_REFLECTION_INBOUND`,
   `ICMP_FLOOD_INBOUND`.
3. `UDP_FLOOD_INBOUND` e `TCP_ACK_FLOOD_INBOUND` (mais ruidosos; ACK mede o tráfego TCP
   estabelecido — calibrar antes com baseline).
4. Variantes `_MULTI` e `MEMCACHED`/`TCP_SYNACK` conforme prioridade de negócio.

Calibração: os defaults são ponto de partida; ajustar após janela real de observação
(ou aprendizado) antes de considerar os limiares definitivos.

## 9. Fase 4.1 — deploy controlado, equivalência das 28 regras e auditoria de deduplicação DNS

Executada em 2026-10-06 com o repositório em `a28fb94`. Objetivo: deployar o motor aditivo com
todos os presets desligados, provar equivalência das 28 regras atuais e auditar a duplicidade
entre o novo preset `DNS_REFLECTION_INBOUND` e as duas regras DNS inbound antigas.

### 9.1 Deploy (todos os presets desligados)

- Build: `docker compose build backend` → imagem `d509d7c7f629` (`gmj-flow-backend:latest`).
- Rollback preservado antes do build: `gmj-flow-backend:pre-fase4-20261006` (= `c6865fb9bb13`,
  deploy-64f807b).
- Recreate sequencial: backend 17:35:47Z, detector 17:36:25Z; health 200 (8080/8081); sem 502.
- Schema aditivo confirmado (idempotente): `detection_template_rules.trigger_warning_expr`,
  `trigger_critical_expr`, `evidence` e `security_anomalies.unique_src_ips`.
- 28 regras com configuração inalterada (só `updated_at` de restart nas regras 1–4);
  `trigger_warning_expr` não-vazio = **0** (nenhum preset ativo).
- `GMJFLOW_DETECTION_RECONCILE_ENABLED=false` inalterado; lease único `detector@e50a75681114:1`.
- Testes: 286 rodados, as mesmas 9 falhas pré-existentes (assinaturas idênticas ao baseline).

### 9.2 Baseline pós-deploy (7 ciclos, sem presets)

- `cycle_duration`: 53,80 / 66,89* / 55,07 / 53,76 / 53,48 / 52,30 / 53,55 s (*outlier isolado,
  janela pré-deploy 52–58 s).
- `queries_executed` 168–173, cache hits 37–42, `rules_evaluated=28`, `last_error=''`;
  ingestão estável (~15,1 M linhas/5 min); 68 anomalias (nenhuma nova).

### 9.3 Equivalência das 28 regras (old × new, janela fixa)

- Método: janela histórica congelada `2026-10-06T14:59:00–15:00:00Z`; old = imagem
  `pre-fase4-20261006` (código baked), new = `latest`; SQLite scratch gravável + ATTACH
  somente leitura no banco de produção; ClickHouse real; itens comparados campo a campo.
- Resultado: **37.149 itens em cada lado, 5 matches em cada lado**, mesmas regras (1, 2, 3, 4 e
  12), com **severidade, métrica (5.888,2) e target (168.232.197.32) idênticos**.
- Piso de ruído: duas execuções da MESMA imagem divergem entre si (1.981–2.518 diffs) em campos
  voláteis (`detected_exporter_ip/sensor_name`, `top_*`, composição de grupos por `any()/argMax`).
  Cruzado old × new ficou em 302–3.068 — **dentro do envelope de ruído** — com **zero divergência
  em campos de decisão** (`matched`, `severity`, `thresholds`, `metric`, `rule_config`, `response`,
  `mitigation_*`) em qualquer das quatro comparações.
- Custo: old 45,8/44,3 s × new 44,9/46,6 s para 210 scans (28 regras × 6–9 prefixos) → paridade.
- Harnesses (commitados): `scripts/equivalence_scan_dump.py` e `scripts/equivalence_scan_compare.py`.

### 9.4 Auditoria de deduplicação (gate §10) — REPROVADO

Simulação com o pipeline real (`evaluate_detection_template_rule` → whitelist → cooldown → upsert),
ClickHouse mockado e scratch descartável; regras A/B reais (ids 13/14) e preset C nas mesmas
condições, mesmo `dst_ip`:

| Caso | A `DNS_AMP_INBOUND_HIGH_BITS` | B `DNS_AMP_INBOUND_HIGH_PPS` | C `DNS_REFLECTION_INBOUND` | Eventos |
|---|---|---|---|---|
| 20 Mbps / 4 kpps | — | — | warning (≥15M) | **1** |
| 50 Mbps / 10 kpps | — | — | critical (≥30M) | **1** |
| 85 Mbps / 25 kpps | warning (>80M) | warning (>20k) | critical (≥30M) | **3** |
| 120 Mbps / 50 kpps | critical (>100M) | critical (>40k) | critical (≥30M) | **3** |

- `security_anomaly_dedupe_key` = `VECTOR|zone_id|target/32|UDP`: as três regras usam o mesmo
  alvo/escopo (`internal_ip_32`, `168.232.197.10/32`) mas vetores diferentes → **chaves distintas**
  → três linhas independentes em `security_anomalies` (`anomaly_source=detection_template_rule`,
  `source_engine=detection_templates`, `source_id` 13/14/901), três cartões na tela de Anomalias.
- Na faixa 15–80 Mbps / 3–20 kpps **não há sobreposição** (só C alerta — o valor do preset); a
  sobreposição existe apenas na faixa extrema (≥80 Mbps ou ≥20 kpps), que hoje já gera 2 eventos
  (A+B) sem o C.
- **Decisão (gate §10): NÃO ativar `DNS_REFLECTION_INBOUND` neste momento.** As regras antigas e
  seus thresholds permanecem intocados; a consolidação (abaixo) vira lote separado.
- Auditoria reproduzível: `scripts/audit_inbound_dedupe.py`.

### 9.5 Opções de consolidação (lote separado — NÃO implementado)

1. **Band-split via DSL (recomendado)**: C cobre apenas a faixa sensível excluindo os limiares
   das regras antigas com `AND NOT (...)` — a DSL booleana já suporta `NOT`
   (ex.: warning `(bps >= 15M OR pps >= 3k) AND NOT (bps > 80M OR pps > 20k)`; critical análogo
   com 30M/8k e 100M/40k). Não toca nas regras antigas; exige replay + testes dedicados.
2. **Evento de família**: consolidar A/B/C em um evento canônico (família DNS inbound) com
   sub-classificações e severidade máxima — mexe no modelo de dedupe/UI; mudança maior.
3. **Aceitar 3 alertas** na faixa extrema (decisão operacional) — documentar o trade-off.

### 9.6 Rollback

1. `docker tag gmj-flow-backend:pre-fase4-20261006 gmj-flow-backend:latest`
2. `docker compose up -d --no-deps backend && docker compose up -d --no-deps detector`
3. Se 502: `docker exec gmj-flow-frontend nginx -s reload` (idem `gmj-flow-preview`).

## 10. Fase 4.2 — band-split do `DNS_REFLECTION_INBOUND` e ativação (2026-10-06)

Executada com o repositório em `65eba5b` → commit `82523c0` (branch `preserve/fibinet-20260928`).

### 10.1 Semântica real dos legados (auditada no código e no banco)

`comparison = "over"` avalia `observed > threshold` (`comparison_matches` em `main.py`), ou seja
**estritamente maior**: `DNS_AMP_INBOUND_HIGH_BITS` warning `bps > 80M` / critical `bps > 100M`;
`DNS_AMP_INBOUND_HIGH_PPS` warning `pps > 20k` / critical `pps > 40k` (ids 13/14 no template 1,
27/28 no template 2). Nenhum threshold legado foi alterado.

### 10.2 Band-split implementado (apenas no preset single)

- WARNING: `(bps >= 15M OR pps >= 3k) AND NOT (bps > 80M OR pps > 20k)`
- CRITICAL: `(bps >= 30M OR pps >= 8k) AND NOT (bps > 80M OR pps > 20k)`

A exclusão usa as condições reais de WARNING dos legados nas **duas** severidades — é a única
forma de garantir zero overlap: em `85 Mbps / 5 kpps` (legado BITS warning) e `50 Mbps / 25 kpps`
(legado PPS warning) o novo vetor deixa de casar; nos limiares exatos (`80M`, `20k`) o legado
não casa (`>` estrito) e o novo cobre o ponto, sem gap. A variante `_MULTI` permanece inalterada.

### 10.3 Provas

- Matriz de fronteiras (11 cenários do plano + exatos 80M/20k/100M/40k) com **zero overlap e
  zero gap** (`tests/test_inbound_vector_presets.py`, `DnsReflectionBandSplitTest`).
- Dedupe audit (`scripts/audit_inbound_dedupe.py`, pipeline real): `20M/4k` e `50M/10k` →
  1 evento (só o novo); `85M/25k` e `120M/50k` → 2 eventos (só os legados A/B; o novo não casa).
- Replay read-only (314 scans, mesmos buckets da seção 4.1): before × after **sem nenhuma
  diferença**; 0 falsos positivos (máximos ~5,7 kbps no período).

### 10.4 Ativação e custo observado

- Regra criada via preset canônico (`POST /api/detection/templates/1/rules`): id **29**
  `DNS_REFLECTION_INBOUND` — enabled, direction `receives`, UDP src_port 53, window 60 s,
  group_by `dst_ip`, response `DETECTION_ONLY`, cooldown 300 s.
- 3 ciclos com 28 regras (desligado): 55,59 / 51,52 / 58,57 s (média 55,2 s).
- Com a regra ativa: 54,79–58,69 s (média **56,28 s** em 9 ciclos concluídos) → Δ ≈ **+1 s**
  (abaixo do previsto +3 s; limite de rollback de 65 s não foi atingido).
- `queries_last_cycle` 168–170 → 174–176 (+6); scan_cache 40–42 hits / 168–176 misses;
  `rules_enabled=29`, `rules_evaluated_last_run=29`; 0 erros; 0 anomalias.
- Ingestão estável: ~2.958 rows/s (2.126.488 linhas em 719 s), sem backlog (`detector_lag=0`).
- CPU: detector ~23% média (pico 72% na janela do restart), ClickHouse ~149% média,
  backend ~99% média.
- Observação: 1 restart gracioso do processo do detector (exit 0, sem OOM) às 20:32:52Z durante
  a janela; ciclos retomados normalmente, 0 erros, regra e contadores preservados.

### 10.5 Rollback

1. Desligar apenas a regra: `PUT /api/detection/templates/1/rules/29` com `enabled=false`
   (ou `DELETE` da regra).
2. Código: `git revert 82523c0`.
3. Imagem: `docker tag gmj-flow-backend:pre-fase42-20261006 gmj-flow-backend:latest && docker compose up -d --no-deps backend detector`.

### 10.6 Próximo vetor (recomendação — nenhuma outra ativação nesta fase)

`DNS_QUERY_FLOOD_INBOUND` (UDP dst 53 inbound; replay sem FP e folga grande) como próximo
candidato, após janela de observação de 24–48 h do vetor atual.
