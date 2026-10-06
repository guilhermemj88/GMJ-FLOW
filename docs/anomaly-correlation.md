# Correlação canônica de anomalias — reincidência por sujeito real

Documento de referência da fase **"reincidência por sujeito real"** (core de
correlação). A UI e o webhook/n8n **ainda não foram alterados**: eles apenas
consumirão `anomaly.correlation` em fase seguinte.

## 1. Conceitos

| Conceito | Definição |
|---|---|
| **Ocorrência** | Ciclo de vida contínuo de detecção. Uma mesma row de `security_anomalies` ou `anomaly_events` pode conter várias ocorrências ao longo do tempo. |
| **Continuação** | Novo match da mesma ocorrência (`last_seen` avança). Não incrementa reincidência. |
| **Reincidência** | A ocorrência anterior encerrou (`ended_at`) ou houve gap maior que `GMJFLOW_OCCURRENCE_GAP_SECONDS` (padrão: `GMJFLOW_ANOMALY_CLOSE_AFTER_SECONDS` ou 300 s). Conta como nova ocorrência do dia. |
| **Correlação (V1)** | Mesmo vetor/regra + mesmo sujeito + mesmo dia operacional. Regras diferentes NÃO se correlacionam nesta fase. |

O histórico canônico fica na tabela `anomaly_occurrences`
(`backend/app/services/anomaly_correlation.py`), com backfill idempotente do
histórico existente (1 ocorrência por row antiga; a divisão por gaps passa a
valer para os ciclos novos).

## 2. Sujeito canônico (`correlation_subject`)

- `subject_type`: `ip` | `prefix` | `cgnat_subscriber` | `cgnat_private_ip` | `cgnat_public_ip`
- `subject_key`: identidade estável (IP, prefixo, subscriber_id ou IP privado resolvido)
- `subject_confidence`: `high` | `medium` | `low`
- `subject_context`: papel (`role`), direção, IP/porta/protocolo e bloco `cgnat` quando aplicável

Regras de derivação:

1. anomalias de **prefixo/subnet** (`domain=subnet`) → `prefix` (key = CIDR)
2. anomalias com direção **receives/inbound** (ou `target_role=dst_ip`) → sujeito é o **destino** (alvo/cliente)
3. anomalias com direção **transmits/sends** (ou `target_role=src_ip`) → sujeito é a **origem** (cliente)
4. anomalias sem direção → prioriza a origem, com fallback para o destino

**CGNAT** (reutiliza o resolver canônico `resolve_cgnat_subscriber`, mesmo
`public_ip + porta + protocolo + timestamp`):

- IP sujeito dentro de pool CGNAT ativo (`cgnat_pools.active=1`) e resolução
  inequívoca → `cgnat_subscriber` (key = `subscriber_id`) ou `cgnat_private_ip`
  (key = IP privado); confiança vem da confiança do mapeamento.
- Resolução ambígua ou ausente → **fallback** para o IP público
  (`cgnat_public_ip`) com confiança `low`; `subject_context.cgnat.reason`
  registra o motivo (`no_mapping`, `no_public_port`, `ambiguous_mapping`, ...).
- IP fora de pool → sujeito `ip` com confiança `high`.
- O `subject_context` mantém o IP público, a porta e o protocolo usados, para
  nunca ocultar que houve fallback.

**Data/hora da resolução:** a resolução usa o **início da ocorrência**
(`first_seen`), pois o mapeamento CGNAT é dinâmico no tempo (valid_from/valid_until).

## 3. Dia operacional

O "hoje" da correlação é o dia local em **America/Sao_Paulo**
(`ANOMALY_TIME_ZONE_NAME`, já canônico no sistema). Nunca usa data UTC
diretamente: `2026-10-07T02:30Z` é dia operacional `2026-10-06` (23:30 BRT).

## 4. Payload de API (backward-compatible)

Os endpoints abaixo passaram a incluir `correlation` **sem remover nem
renomear** nenhum campo existente:

- `GET /api/security/anomalies/active` e `GET /api/security/anomalies/history` → `items[].correlation`
- `GET /api/anomalies/active` e `GET /api/anomalies/history` → `items[].correlation` (eventos e grupos consolidados de `security_anomalies`)
- `GET /api/anomalies/{id}` → `event.correlation`/`anomaly.correlation` (eventos, anomalias de segurança e detalhe consolidado)

Estrutura:

```json
"correlation": {
  "subject_type": "cgnat_subscriber",
  "subject_key": "SUB-777",
  "subject_confidence": "high",
  "subject_context": {
    "role": "dst", "direction": "receives", "ip": "45.168.203.83",
    "port": 18432, "protocol": "udp",
    "cgnat": {"in_pool": true, "resolved": true, "private_ip": "100.97.0.17", "public_ip": "45.168.203.83", "public_port": 18432, "mapping_confidence": 1.0}
  },
  "is_recurrence": true,
  "occurrence_number_today": 4,
  "occurrences_today": 4,
  "previous_occurrences_today": 3,
  "last_previous_occurrence_at": "2026-10-06T13:05:00Z",
  "previous_occurrences": [
    {"occurrence_id": 12, "anomaly_id": 88, "anomaly_table": "anomaly_events",
     "first_seen": "2026-10-06T13:05:00Z", "last_seen": "2026-10-06T13:07:00Z",
     "ended_at": "2026-10-06T13:12:00Z", "severity": "critical",
     "metric": "packets_s", "metric_value": 9000.0}
  ],
  "previous_occurrences_truncated": false,
  "operational_day": "2026-10-06",
  "timezone": "America/Sao_Paulo",
  "schema_version": 1
}
```

Regras do summary:

- `is_recurrence = previous_occurrences_today > 0`
- `occurrence_number_today`/`occurrences_today` incluem a ocorrência atual
- a ocorrência atual **nunca** aparece em `previous_occurrences`
- `previous_occurrences` é limitado (padrão 3); `previous_occurrences_truncated`
  indica que existem mais
- `last_previous_occurrence_at` é o **início** da ocorrência anterior mais recente

## 5. Registro das ocorrências (caminho quente)

O registro acontece nos três upserts de anomalia (detection templates →
`security_anomalies`/`anomaly_events`, engine DNS outbound e attack vectors
legados → `anomaly_events`), no encerramento automático por inatividade
(`close_stale_anomaly_events`) e nos endpoints de **ack/close** (incluindo
fechamento em lote de grupos consolidados). O registro é **fail-safe**
(`record_occurrence_safe`): qualquer falha é logada e jamais derruba o ciclo de
detecção.

`ack`/`close` **não** criam ocorrência: apenas fecham a atual (`ended_at`). O
próximo match depois de um encerramento real (ou de um gap relevante) abre a
ocorrência seguinte — mesmo que a mesma row seja reutilizada.

## 6. Performance

- Índices: `idx_anomaly_occurrences_lookup (vector_key, subject_key, operational_day, first_seen)`
  e `idx_anomaly_occurrences_row (anomaly_table, anomaly_id, first_seen)`.
- Gravação: 1 SELECT + 1 INSERT/UPDATE por anomalia com match (volume baixo).
- Leitura: 2 consultas indexadas por item; a lista de eventos calcula em lote
  por grupo quando consolida.
- Medições reais (cópia do DB de produção, 2026-10-06, 5.253 ocorrências):
  backfill completo em **2,2 s**; `resolve_anomaly_correlation` **0,57 ms/item**;
  attach de uma página de 200 itens em **71 ms** (0,36 ms/item) — sem full scan.

## 7. Limitações conhecidas

- **Retroativo**: o backfill cria 1 ocorrência por row histórica; divisões por
  gap só passam a existir para os ciclos após o deploy.
- **V1 correlaciona mesma regra apenas**; atividade entre regras diferentes
  (`related_events`/`same_subject_activity`) fica para fase futura.
- **Rows paralelas do mesmo vetor/sujeito** (ex.: prefixos sobrepostos da
  zona 7, onde o mesmo ataque gera duas rows com prefix_id 13 e 19) contam como
  ocorrências individuais. Efeito colateral do problema de prefixo duplicado já
  conhecido; ao corrigi-lo, as contagens deixam de dobrar. Uma fase futura pode
  agrupar por janela de início para contar "momentos de reincidência".
- Sujeito de regras agregadas (ex.: `PREFIX_INTERNAL_IP_*`) é o prefixo; sem
  porta não há resolução CGNAT (fallback explícito).
- O webhook/mídia ainda usa o payload antigo; a fase seguinte deve apenas
  **consumir** `anomaly.correlation` (sem recalcular).
