# Gestao de banco de dados

A tela **Banco de Dados** fica disponivel para usuarios admin.

## Status

`GET /api/database/status` retorna:

- saude do ClickHouse e SQLite;
- total de flows em `flow_raw`;
- flow mais antigo e mais recente;
- tamanho de `flow_raw`;
- tamanho total do banco ClickHouse;
- tamanho do SQLite;
- uso de disco do servidor;
- politica de retencao;
- ultima limpeza executada.

`GET /api/database/tables` lista tabelas ClickHouse, linhas e tamanho comprimido informado por `system.parts`.

## Retencao configuravel

A politica fica em SQLite na tabela `system_settings`.

As chaves efetivas usam horas e permitem valores inferiores a um dia:

- `database_retention_enabled`;
- `flow_raw_retention_hours` (default `168`);
- `flow_1m_retention_hours` (default `720`);
- `flow_tops_1m_retention_hours` (default `360`);
- `snmp_retention_hours` (default `2160`);
- `anomaly_retention_hours` (default `2160`);
- `database_last_cleanup_at`;
- `database_cleanup_hour`.

As chaves antigas `*_retention_days` continuam armazenadas. No primeiro startup da versão nova, cada chave em horas ausente é criada a partir dos dias persistidos. Depois disso, horas têm precedência.

`POST /api/database/retention` aceita a estrutura `value/unit` e também os campos legados em dias:

```json
{
  "enabled": true,
  "flow_raw": {"enabled": true, "value": 12, "unit": "hours"},
  "flow_1m": {"enabled": true, "value": 30, "unit": "days"},
  "flow_tops_1m": {"enabled": true, "value": 15, "unit": "days"},
  "snmp": {"enabled": true, "value": 90, "unit": "days"},
  "anomalies": {"enabled": true, "value": 90, "unit": "days"},
  "cleanup_hour_utc": 3
}
```

Ao salvar a politica, o backend tambem tenta atualizar o TTL do ClickHouse:

```sql
ALTER TABLE flowdb.flow_raw MODIFY TTL toDateTime(flow_time) + INTERVAL N HOUR DELETE
```

Se a retencao for desativada, o backend remove o TTL de `flow_raw`:

```sql
ALTER TABLE flow_raw REMOVE TTL
```

## TTL x DELETE

TTL e a politica permanente da tabela. O ClickHouse remove dados vencidos durante merges de partes, entao o espaco fisico pode nao cair imediatamente.

DELETE manual cria uma mutation:

```sql
ALTER TABLE flow_raw DELETE WHERE flow_time < now() - INTERVAL N DAY
```

Essa mutation tambem pode demorar para se materializar fisicamente. Use para limpeza pontual ou correcao de politica.

## Disk Guard

O Disk Guard é independente da retenção normal. Ele não altera os valores configurados pelo operador. O espaço é medido em `system.disks` do ClickHouse; o filesystem do backend é apenas fallback quando essa consulta não está disponível.

Configurações persistidas e defaults:

- `disk_guard_enabled = 1`;
- `disk_guard_warning_free_gb = 15`;
- `disk_guard_cleanup_free_gb = 10`;
- `disk_guard_emergency_free_gb = 7`;
- `disk_guard_absolute_floor_gb = 5`;
- `disk_guard_target_free_gb = 15`;
- `disk_guard_check_seconds = 60`.

Estados: `NORMAL`, `WARNING`, `CRITICAL`, `EMERGENCY` e `ABSOLUTE_DANGER`. A exclusão começa em `CRITICAL`. Cada lote avança 1, 3 ou 6 horas a partir do registro mais antigo e o espaço é medido novamente. A limpeza para ao alcançar `target_free_gb` e nunca executa `OPTIMIZE FINAL`.

Endpoints administrativos:

- `GET /api/system/disk-guard` retorna configuração, medição e última operação;
- `PUT /api/system/disk-guard` valida e persiste os limites.

As operações do Disk Guard e a limpeza normal usam o mesmo lock global de manutenção. Os logs estruturados são `DISK_GUARD_STATE`, `DISK_GUARD_CLEANUP_START`, `DISK_GUARD_CLEANUP_BATCH`, `DISK_GUARD_CLEANUP_FINISH` e `DISK_GUARD_CLEANUP_ERROR`.

O Disk Guard não remove arquivos do spool pmacct. A rotação do parser só remove um arquivo histórico expirado quando existe checkpoint válido com ingestão concluída, `offset >= file_size` e `lag_bytes == 0`. CSV ativo, backlog e arquivos sem checkpoint são protegidos.

## Limpeza manual

`POST /api/database/cleanup` exige:

```json
{
  "older_than_days": 90,
  "optimize": false,
  "confirm": "LIMPAR"
}
```

Se `confirm` for diferente de `LIMPAR`, a API bloqueia a acao.

O retorno inclui:

- quantidade aproximada antes;
- periodo apagado;
- comando executado;
- status;
- observacao sobre merges do ClickHouse quando `optimize=false`.

## OPTIMIZE

`POST /api/database/optimize` exige:

```json
{
  "confirm": "OTIMIZAR"
}
```

Executa:

```sql
OPTIMIZE TABLE flow_raw FINAL
```

Use com cuidado em tabelas grandes. Pode consumir CPU, I/O e espaco temporario. `OPTIMIZE FINAL` é bloqueado no estado `ABSOLUTE_DANGER` e não é executado automaticamente durante pressão de disco.

## Cuidados

- Faca backup antes de limpar janelas grandes.
- Valide o flow mais recente depois da limpeza.
- Evite `OPTIMIZE FINAL` em horario de pico.
- Em ambientes com pouco disco, prefira ajustar TTL e deixar o ClickHouse executar merges gradualmente.
