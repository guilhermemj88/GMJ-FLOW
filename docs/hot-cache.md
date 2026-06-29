# Hot cache para flows recentes

## Objetivo

Acelerar consultas recentes sem transformar cache em fonte de verdade. A tabela persistente `flow_raw` continua sendo o dado canonico.

## Recomendacao

Nao usar `ENGINE = Memory` para armazenar raw flow em producao. Com centenas de milhoes de linhas, dados comprimidos em disco podem ocupar varias vezes mais quando descomprimidos em memoria, e restart/crash perderia o cache.

Uma opcao segura e opcional:

```sql
CREATE TABLE flow_raw_hot
AS flow_raw
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(flow_time)
ORDER BY (flow_time, exporter_ip, src_ip, dst_ip, proto, dst_port, input_if, output_if)
TTL flow_time + INTERVAL 60 MINUTE DELETE;
```

`flow_raw_hot` deve receber somente uma copia curta dos flows recentes, por exemplo via materialized view ou escrita dupla no coletor. O backend pode usa-la apenas quando a janela pedida estiver dentro do TTL, como dashboards e investigacao dos ultimos minutos. Pesquisas historicas continuam em `flow_raw`.

## Alternativas antes de cache raw

- Projections em `flow_raw` para agrupamentos comuns.
- Materialized views agregadas para top talkers e series de dashboard.
- Skip indexes/bloom filter para `src_ip`, `dst_ip`, `dst_port`, `proto`, `input_if`, `output_if`.
- Revisao de `ORDER BY` caso as consultas recentes estejam filtrando sempre por tempo, sensor/interface e IP/porta.

## Guardrails

- `flow_raw` segue sendo persistente e autoritativo.
- `flow_raw_hot` precisa ter TTL curto, 30 a 60 minutos.
- Falha/restart nao pode causar perda do dado canonico.
- O backend deve cair para `flow_raw` quando a janela exceder o TTL ou quando `flow_raw_hot` nao existir.
