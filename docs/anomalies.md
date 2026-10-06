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
