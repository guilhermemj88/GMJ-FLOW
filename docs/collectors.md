# Collectors por sensor

No MVP do GMJ-FLOW, cada sensor ativo e com **Flow Collector** habilitado usa uma porta UDP exclusiva.

O motivo e uma limitacao do CSV gerado pelo `pmacct`: o parser atual nao recebe o `exporter_ip` real no registro CSV. Para evitar misturar exportadores diferentes na mesma porta, o GMJ-FLOW gera um collector e um parser por sensor:

- um `nfacctd` escutando a `listener_port` do sensor;
- um arquivo CSV proprio em `/var/spool/pmacct/sensor-<id>-<porta>.csv`;
- um `allow.lst` proprio contendo o `exporter_ip` cadastrado no sensor;
- um parser com `PMACCT_EXPORTER_IP` e `PMACCT_SENSOR` fixos.

## Arquivos gerados

Ao clicar em **Aplicar Coletor**, o backend gera:

- `data/collectors/sensor-<id>/nfacctd.conf`;
- `data/collectors/sensor-<id>/allow.lst`;
- `docker-compose.collectors.yml`.

Dentro dos containers de collector, `data/collectors` e montado como `/app/data/collectors`. Por isso cada `nfacctd.conf` aponta para:

```text
nfacctd_allow_file: /app/data/collectors/sensor-<id>/allow.lst
```

O `allow.lst` contem apenas o exporter do sensor:

```text
192.0.2.10
```

Collectors dinamicos nao usam o allow list global `/etc/pmacct/allow.lst`.

## Modo manual

Com `GMJFLOW_ENABLE_COLLECTOR_APPLY=false`, a API apenas gera os arquivos. Aplique manualmente na raiz do projeto:

```sh
docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml config
docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml up -d --build --remove-orphans
```

## Modo automatico

Para fazer o botao **Aplicar Coletor** subir os containers:

```env
GMJFLOW_ENABLE_COLLECTOR_APPLY=true
GMJFLOW_RUNTIME_DIR=/app/runtime
GMJFLOW_COLLECTORS_DIR=/app/runtime/data/collectors
GMJFLOW_COLLECTOR_APPLY_SCRIPT=/app/runtime/scripts/apply_collectors.sh
```

O `docker-compose.yml` monta:

```yaml
- ./:/app/runtime
- /var/run/docker.sock:/var/run/docker.sock
```

O backend executa somente o script fixo definido em `GMJFLOW_COLLECTOR_APPLY_SCRIPT`. Ele nao aceita comando enviado pelo usuario.

O script `scripts/apply_collectors.sh`:

1. entra na raiz do projeto;
2. valida `docker-compose.collectors.yml`;
3. executa `docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml config`;
4. executa `docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml up -d --build --remove-orphans`.

O retorno de `POST /api/collectors/apply` inclui `stdout`, `stderr` e `returncode`.

## Seguranca do Docker socket

Montar `/var/run/docker.sock` da ao backend poder para criar, parar e alterar containers no host. Na pratica, isso equivale a acesso administrativo ao Docker do servidor.

Use modo automatico apenas quando:

- o servidor for dedicado ou confiavel;
- somente admins acessarem o GMJ-FLOW;
- `.env` e backups estiverem protegidos;
- o backend nao estiver exposto diretamente a redes nao confiaveis.

## Validacao operacional

Exemplo com dois sensores:

- Sensor 1: `exporter_ip=192.0.2.10`, `listener_port=9995`;
- Sensor 2: `exporter_ip=192.0.2.11`, `listener_port=9996`.

Valide no ClickHouse:

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

## Plano futuro

Quando o parser receber o `exporter_ip` real diretamente do collector, sera possivel aceitar multiplos exportadores na mesma porta. Ate la, a regra operacional do MVP e uma porta UDP por sensor ativo.
