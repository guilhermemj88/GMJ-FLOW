# Periodos de consulta

O Dashboard e o Flow Search aceitam dois modos de periodo.

## Ranges padrao

Quando apenas `range_minutes` e enviado, o backend consulta:

```text
flow_time >= now() - INTERVAL range_minutes MINUTE
```

A interface oferece os ranges de 5 minutos ate 6 meses. O limite padrao do backend e `259200` minutos, equivalente a 6 meses, e pode ser ajustado com:

```env
GMJFLOW_MAX_RANGE_MINUTES=259200
```

## Periodo personalizado

Quando `start_time` e `end_time` sao enviados, o backend usa:

```text
flow_time >= start_time AND flow_time <= end_time
```

Formatos aceitos:

```text
2026-06-20T10:00:00
2026-06-20T10:00:00Z
```

Se `end_time` estiver no futuro, o backend limita o fim ao horario atual. Se `start_time` for maior ou igual a `end_time`, a API retorna HTTP 400 com mensagem em portugues.

Os parametros antigos `start` e `end` continuam aceitos por compatibilidade, mas `start_time` e `end_time` sao os nomes preferidos.
