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

## Retencao

A politica fica em SQLite na tabela `system_settings`.

Chaves principais:

- `database_retention_enabled`;
- `flow_retention_days`;
- `snmp_retention_days`;
- `database_last_cleanup_at`;
- `database_cleanup_hour`.

Ao salvar a politica, o backend tambem tenta atualizar o TTL do ClickHouse:

```sql
ALTER TABLE flow_raw MODIFY TTL toDateTime(flow_time) + INTERVAL N DAY DELETE
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

Use com cuidado em tabelas grandes. Pode consumir CPU, I/O e espaco temporario.

## Cuidados

- Faca backup antes de limpar janelas grandes.
- Valide o flow mais recente depois da limpeza.
- Evite `OPTIMIZE FINAL` em horario de pico.
- Em ambientes com pouco disco, prefira ajustar TTL e deixar o ClickHouse executar merges gradualmente.
