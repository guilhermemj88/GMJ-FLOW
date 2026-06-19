# Collectors por sensor

No MVP do GMJ-FLOW, cada sensor ativo deve usar uma porta UDP exclusiva.

O motivo e uma limitacao do CSV gerado pelo `pmacct`: o parser atual nao recebe o `exporter_ip` real no registro CSV. Para evitar misturar exportadores diferentes na mesma porta, o GMJ-FLOW gera um collector e um parser por sensor ativo:

- um `nfacctd` escutando a `listener_port` do sensor;
- um arquivo CSV proprio em `/var/spool/pmacct/sensor-<id>-<porta>.csv`;
- um parser com `PMACCT_EXPORTER_IP` e `PMACCT_SENSOR` fixos para aquele sensor.

## Aplicar configuracao

Na tela **Flow Sensor Configuration**, mantenha cada sensor ativo com:

- `Exporter IP` valido;
- `Listener Port` entre `1024` e `65535`;
- uma porta exclusiva entre sensores ativos.

Depois clique em **Aplicar Coletor**. O backend gera:

- `/app/data/collectors/sensor-<id>/nfacctd.conf`;
- `/app/data/collectors/docker-compose.collectors.yml`.

Se o script configurado em `GMJFLOW_APPLY_COLLECTORS_SCRIPT` existir, o backend executa esse script fixo para aplicar o override com Docker Compose. O script incluido em `scripts/apply_collectors.sh` executa:

```sh
docker compose -f docker-compose.yml -f <docker-compose.collectors.yml> up -d --build
```

Ele tambem tenta parar os servicos legados `pmacct` e `pmacct-parser`, evitando conflito quando um sensor gerado usa a porta `9995`.

## Variaveis

```env
GMJFLOW_COLLECTORS_DIR=/app/data/collectors
GMJFLOW_APPLY_COLLECTORS_SCRIPT=
```

Em execucao local a partir da raiz do projeto, o backend encontra `scripts/apply_collectors.sh` automaticamente. Em ambientes Docker, configure `GMJFLOW_APPLY_COLLECTORS_SCRIPT` apenas quando o backend tiver acesso ao script, ao Docker Compose e ao projeto GMJ-FLOW. Se o script nao estiver disponivel para o backend, a API ainda gera os arquivos e retorna essa informacao no resultado.

## Validacao operacional

Exemplo com dois sensores:

- Sensor 1: `exporter_ip=192.168.0.157`, `listener_port=9995`;
- Sensor 2: `exporter_ip=192.168.0.171`, `listener_port=9996`.

Configure os MikroTik para enviar NetFlow para as respectivas portas e valide no ClickHouse:

```sql
SELECT
  toString(exporter_ip),
  sensor,
  count(),
  sum(bytes),
  sum(packets)
FROM flow_raw
WHERE flow_time >= now() - INTERVAL 10 MINUTE
GROUP BY exporter_ip, sensor
ORDER BY count() DESC
```

Resultado esperado:

```text
::ffff:192.168.0.157  mikrotik-lab
::ffff:192.168.0.171  mikrotik-LAB02
```

## Plano futuro

Quando o parser passar a receber o `exporter_ip` real diretamente do collector, sera possivel aceitar multiplos exportadores na mesma porta. Ate la, a regra operacional do MVP e uma porta UDP por sensor ativo.
