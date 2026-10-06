# Vetores de Ataque e Anomalias

O modulo de anomalias do GMJ-FLOW adiciona uma camada de analise automatica sobre os flows gravados em `flowdb.flow_raw`. A ideia e separar configuracao de deteccao e eventos detectados:

- **Vetor de ataque**: uma regra configuravel pelo usuario. Define dominio, alvo, direcao, decoder, unidade, threshold, severidade e resposta.
- **Anomalia**: um evento criado pelo worker quando um vetor ativo ultrapassa o threshold em uma janela recente.

## Templates

A tela **Vetores de Ataque** organiza regras em templates. Um template pode ser ativado/desativado, duplicado e usado como base para aprendizado automatico.

O GMJ-FLOW cria o template inicial `THRESHOLD-PADRAO` quando o SQLite ainda nao possui templates. Ele contem thresholds conservadores para trafego recebido em IPs internos. Esses valores sao apenas ponto de partida; o recomendado e rodar o aprendizado automatico por pelo menos 2 dias.

## Campos do vetor

- **Dominio**: escopo da regra. Valores: `any`, `internal_ip`, `external_ip`, `prefix`, `sensor`, `interface`.
- **Alvo**: IP ou CIDR, como `192.168.0.10/32` ou `192.168.0.0/24`. Pode ficar vazio em regras globais.
- **Sensor**: limita a regra a um sensor/exportador cadastrado.
- **Interface**: limita a regra a um `ifIndex` do sensor.
- **Direcao**: `receives`, `sends` ou `both`.
- **Decoder**: classifica o tipo de trafego analisado.
- **Comparacao**: no MVP, apenas `over`.
- **Unidade**: `bits_s`, `packets_s` ou `flows_s`.
- **Severidade**: `info`, `warning` ou `critical`.
- **Resposta**: `alert_only`, `response_ip`, `webhook_future` ou `ignore`.

## Decoders

O backend possui uma funcao testavel de classificacao de flows e tambem empurra filtros equivalentes para o ClickHouse quando possivel.

Decoders suportados:

- `IP`: qualquer protocolo.
- `TCP`, `TCP+ALL`: protocolo 6.
- `TCP+SYN`, `TCP+SYNACK`, `TCP+ACK`, `TCP+RST`, `TCP+NULL`: protocolo TCP com flags correspondentes.
- `UDP`: protocolo 17.
- `ICMP`: protocolos 1 e 58.
- `DNS`: porta 53 UDP/TCP.
- `NTP`: porta 123 UDP.
- `QUIC`, `UDP+QUIC`: UDP 443 ou 8443.
- `HTTP`, `HTTPS`, `MAIL`, `SIP`, `IPSEC`, `NETBIOS`, `MEMCACHED`: portas/protocolos conhecidos.
- `FLOWS`: usa `flow_count` por segundo.
- `OTHER`: trafego que nao bate nos decoders conhecidos.
- `FRAGMENT` e `INVALID`: reservados.

## Aprendizado automatico

Endpoint:

```http
POST /api/attack-vectors/learn
```

Exemplo:

```json
{
  "template_id": 1,
  "days": 2,
  "margin_percent": 20,
  "sensor_id": null,
  "target_cidr": null
}
```

O aprendizado consulta o ClickHouse nos ultimos `N` dias e gera sugestoes por sensor, decoder, direcao e unidade. O calculo usa `p95`, `p99`, maximo e media, ignorando periodos sem trafego e valores muito baixos.

Cada sugestao pendente e unica por:

```text
template_id + sensor_id + interface_if_index + domain_type + target_cidr + direction + decoder + threshold_unit
```

Se o aprendizado encontrar uma sugestao pendente com a mesma chave, ele atualiza `p95`, `p99`, maximo, media, threshold sugerido, margem, confianca e datas em vez de criar outra linha. O threshold sugerido e calculado como:

```text
baseline_max * (1 + margin_percent / 100)
```

As sugestoes ficam pendentes na tela ate o usuario aplicar uma a uma ou aplicar todas. Ao aplicar, a regra gerada inclui sensor, decoder, direcao e unidade no nome, como `mikrotik-LAB02 ICMP receives packets warning`.

## Motor de deteccao

Variaveis de ambiente:

```env
GMJFLOW_ANOMALY_DETECTION_ENABLED=true
GMJFLOW_ANOMALY_INTERVAL_SECONDS=30
GMJFLOW_ANOMALY_LOOKBACK_SECONDS=60
GMJFLOW_ANOMALY_MIN_DURATION_SECONDS=30
GMJFLOW_ANOMALY_CLOSE_AFTER_SECONDS=120
GMJFLOW_ANOMALY_MITIGATION_RETRY_WINDOW_SECONDS=900
```

A cada intervalo, o worker:

1. Carrega vetores ativos em templates ativos.
2. Consulta `flow_raw` na janela recente.
3. Agrega `bits/s`, `packets/s` e `flows/s`.
4. Compara com o threshold.
5. Cria ou atualiza uma anomalia ativa usando chave de deduplicacao.
6. Salva uma amostra de flows relacionados.
7. Encerra eventos ativos que nao aparecem novamente dentro de `GMJFLOW_ANOMALY_CLOSE_AFTER_SECONDS`.
8. Reavalia mitigacao apenas para eventos sem resultado que estejam ativos ou tenham terminado dentro de `GMJFLOW_ANOMALY_MITIGATION_RETRY_WINDOW_SECONDS`.

As metricas sao calculadas na janela avaliada com:

- `bits_s`: `sum(bytes) * 8 / janela_segundos`.
- `packets_s`: `sum(packets) / janela_segundos`.
- `flows_s`: `sum(flow_count) / janela_segundos`.

A deduplicacao usa:

```text
attack_vector_id + target_ip + sensor_id + interface_if_index + decoder + direction
```

### Desempenho do ciclo (PERF-A)

O motor de `detection_template_rules` executa 1 query ClickHouse por par (regra x zona/prefixo),
o que hoje resulta em ~210 queries por ciclo. A otimizacao PERF-A (2026-10-05) reduziu o
ciclo de ~163 s para ~44 s (ClickHouse: 147 s -> 28 s) sem alterar nenhum resultado:

1. poda das condicoes redundantes do `multiIf` de sample-rate (476 -> 18);
2. `uniqExact` trivial (=1 quando a coluna ja esta no `GROUP BY`) virou constante;
3. cache de scans por ciclo (`DetectionScanCache`, SQL + parametros identicos).

Detalhes, medicao completa, prova de equivalencia, cursor/watermark (PERF-B) e paralelismo
(PERF-C) estao em `docs/detection-performance.md`.

### Estabilidade temporal (PERF-A.1 / PERF-B)

- **PERF-A.1 (deployado):** o `ORDER BY metric_value DESC LIMIT 1000` passou a ter tiebreaker
  pela chave do `GROUP BY`. Sem isso, empates escolhiam grupos diferentes a cada execucao
  (136 linhas divergentes em duas execucoes do mesmo codigo). Com o tiebreaker, 3 execucoes
  na mesma janela retornaram resultado identico (md5 igual) — sem flapping.
- **PERF-B (implementado, nao deployado):** cursor persistido por `(template, window_seconds)`
  em `detection_cursor`, avancando somente sobre buckets FECHADOS e somente apos sucesso,
  com watermark (`GMJFLOW_DETECTION_WATERMARK_SECONDS`, default 240 s). O passe rapido
  (janela recente) continua igual; a reconciliacao reavalia os buckets fechados e consolida o
  MESMO evento (a `dedupe_key` nao inclui bucket/tempo). Kill switch:
  `GMJFLOW_DETECTION_RECONCILE_ENABLED=false`.
- **Semantica de tempo:** `flow_time` e o INICIO do flow (`flow_start`); `flow_end` e
  `duration_ms` sao sempre nulos. Por isso o FAST e a reconciliacao usam `flow_time`
  (mesmo bucket) e `received_at` fica apenas como metrica de lag de ingestao.

### Detector isolado da API (PERF-C.0)

O worker de `detection_template_rules` deixou de rodar como thread dentro da API e passou a
rodar em processo/container proprio (`gmj-flow-detector`, mesma imagem, entrypoint
`python -m app.detection_worker`). Motivo medido: o mesmo passo levava ~42 s isolado e
90-238 s dentro da API por contencao de GIL/CPU com as outras threads.

- **Um unico dono:** `GMJFLOW_DETECTION_INPROCESS_ENABLED=false` na API (default no compose)
  + `GMJFLOW_DETECTION_WORKER_ENABLED=true` no worker + lease em SQLite
  (`detection_worker_lease`, heartbeat/expira em 60 s). Um segundo worker no mesmo banco nao
  executa. `POST /api/detection/run-now` responde 409 se outro processo tem o lease.
- **Status:** o worker publica o status em `detection_runtime_state`; `GET /api/detection/status`
  continua funcionando e informa `status_source` (`worker`), `owner` e `status_age_seconds`.
- **Resultado:** ciclo completo caiu para 52-56 s (passo de regras 38,8 s), CPU do ClickHouse
  70-340% (antes 160-523%), ingestao estavel (~2,4 k rows/s), sem SQLite locks.
- **Rollback:** restaurar `docker-compose.yml.bak-pre-perf-c0-20261006`, `docker compose up -d
  --no-deps backend` e `docker stop gmj-flow-detector`.

### PERF-B: ativado em teste e REPROVADO (mantido desligado)

Ativado apenas no worker (`GMJFLOW_DETECTION_RECONCILE_ENABLED=true`) e observado por 4
ciclos: o ciclo cresceu 96,6 → 142,3 → 185,4 s, as queries 362 → 580 → 786, os buckets por
ciclo bateram no teto (2 → 4 → 6) e o `detector_lag_seconds` subiu (242 → 262 → 267 s).
Causa medida: reconciliar um bucket custa ~um passe completo do FAST (~40 s por grupo) e o
orçamento por 60 s de tempo real nao cabe (~120 s de trabalho para 60 s). **Desativado**
(`RECONCILE_ENABLED=false`); ciclos voltaram a ~54 s.

O que ficou provado: buckets de reconciliacao **alinhados e contiguos** (14:31→14:32→…→14:37,
via `system.query_log`), cursor persistido avancando 60 s por bucket, **sem duplicacao** de
anomalias (68 no total, 1 ativo) e cobertura do watermark de **99,485% com 240 s** (vs 99,704%
com 300 s) — recomendacao: manter 240 s.

### Fase 4 — vetores inbound/download (2026-10-06)

O motor de `detection_template_rules` ganhou, de forma **aditiva**, a capacidade de avaliar
vetores inbound/download com triggers booleanos: `trigger_warning_expr`/`trigger_critical_expr`
(expressoes DSL WARNING/CRITICAL canonicalizadas no save e avaliadas em Python sobre o frame
multi-metrica do scan), `unique_src_ips` no frame/coluna, `avg_packet_bytes` derivado
(`sum(bytes)/sum(packets)`, tambem aceito em TRIGGER) e protocolos TCP com flags exatas
(SYN-NO-ACK, SYN+ACK, ACK-NO-SYN, RST, NULL). As 2 regras DNS inbound produtivas
(`DNS_AMP_INBOUND_HIGH_BITS`/`PPS`) **nao foram alteradas** e as 28 regras atuais seguem no
caminho legado (mesma semantica).

Foi adicionado o catalogo de presets `backend/app/services/inbound_vectors.py` (11 vetores:
DNS/NTP/SSDP/CLDAP reflection, DNS query flood, Memcached, UDP/SYN/SYN-ACK/ACK/ICMP floods)
com modos single-target (`GROUP BY dst_ip`) e multi-target/carpet bombing (`domain=subnet` +
`unique_dst_ips >= 8/16`). **Nenhum preset foi ativado**: os payloads saem `enabled=false` e
a ativacao exige decisao explicita do operador.

Replay historico read-only (mesmo caminho do detector, `scripts/replay_inbound_vectors.py`):
3.625 scans reais (~0,12–0,26 s cada) em 15 prefixos, janelas 30/60 s, incluindo a janela de
anomalia UDP de 2026-10-03 19:45Z — **zero matches** nos limiares default (traffico inbound
observado muito abaixo; folga grande) e prova end-to-end de disparo com limiar trivial
(`bps >= 0` → matches; `critical` no alvo acima de 1 kbps). Matriz de capacidade, presets,
thresholds, replay e plano de ativacao: `docs/detection-inbound-vectors-2026-10-06.md`.

## Teste de vetor

Na tela **Vetores de Ataque**, cada linha possui o botao **Testar agora**. O botao executa imediatamente o vetor nos ultimos 60 segundos e abre um modal com:

- valor observado;
- threshold configurado;
- match sim/nao;
- motivo;
- flows encontrados;
- bytes;
- pacotes;
- resumo do filtro ClickHouse;
- amostras de flows.

O endpoint usado pelo botao tambem pode ser chamado diretamente:

```http
POST /api/attack-vectors/{id}/test
```

Corpo opcional:

```json
{
  "lookback_seconds": 60,
  "min_duration_seconds": 0
}
```

Use `min_duration_seconds` como `0` ou `5` quando quiser testar sem aguardar toda a duracao minima configurada em `GMJFLOW_ANOMALY_MIN_DURATION_SECONDS`. Se o threshold ja bateu mas a duracao minima ainda estiver pendente, o campo `reason` retorna `matched=true, aguardando duracao minima`.

## Tela Anomalias

A tela **Anomalias** possui abas:

- **Ativas**: eventos abertos agora.
- **Historico**: eventos encerrados ou reconhecidos.

O menu lateral mostra um badge pulsante quando ha anomalias ativas. Em cada evento e possivel abrir detalhes, reconhecer ou encerrar manualmente.

Os detalhes exibem resumo textual, grafico simples a partir das amostras, flows relacionados e top conversas.

## Limitacoes

- O MVP usa `flow_raw` diretamente; em ambientes grandes, recomenda-se evoluir para agregacoes precomputadas por minuto e decoder.
- `FRAGMENT` esta reservado ate existir campo de fragmentacao no flow.
- A classificacao `OTHER` e conservadora e pode mudar conforme novos decoders forem adicionados.
- O aprendizado depende da qualidade historica do periodo escolhido. Se houve ataque durante a janela, revise as sugestoes antes de aplicar.

## Exemplos praticos

Regra para UDP recebido acima de 5 Gbps em IPs internos:

- Dominio: `internal_ip`
- Direcao: `receives`
- Decoder: `UDP`
- Comparacao: `over`
- Valor: `5000000000`
- Unidade: `bits_s`
- Severidade: `warning`

Regra para SYN flood recebido acima de 1 Mpps:

- Dominio: `internal_ip`
- Direcao: `receives`
- Decoder: `TCP+SYN`
- Comparacao: `over`
- Valor: `1000000`
- Unidade: `packets_s`
- Severidade: `warning`

## Linguagem de regras (DSL)

O vocabulario canonico para descrever regras/consultas de flows (MATCH, TRIGGER, EVIDENCE,
GROUP BY), com aliases, unidades, validacao estruturada e o dicionario exposto em
`GET /api/rule-language/catalog`, esta documentado em
[docs/detection-rule-language.md](detection-rule-language.md).

O pacote `backend/app/services/detection_dsl/` (Fase 1) e a base reutilizavel para o Flow
Search por expressao (Fase 2). Nesta fase o detector atual nao foi alterado e nenhuma regra
foi migrada.
