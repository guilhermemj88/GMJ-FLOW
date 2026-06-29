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

O compose base ainda preserva os servicos antigos `pmacct` e `pmacct-parser`, mas eles ficam no profile `single-collector`. Ao usar `docker-compose.yml` junto com `docker-compose.collectors.yml`, o padrao e subir somente os servicos sensorizados, por exemplo `pmacct-sensor-1` e `pmacct-parser-sensor-1`.

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

Para conferir que apenas o collector sensorizado esta publicando a porta UDP do sensor:

```sh
docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml ps
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

## ASN no IPFIX/NetFlow

O collector pmacct foi configurado para tentar agregar `src_as` e `dst_as`:

```text
aggregate[flows]: src_host, dst_host, src_port, dst_port, proto, tcpflags, in_iface, out_iface, src_as, dst_as, timestamp_start
```

Quando o exportador envia ASN, o parser grava:

- `src_asn`
- `dst_asn`
- `src_as_name`
- `dst_as_name`

No Huawei NE8000, isso depende da exportacao IPFIX incluir origem AS, por exemplo:

```text
ip netstream export version ipfix origin-as bgp-nexthop
ipv6 netstream export version ipfix origin-as bgp-nexthop
```

Se o pmacct da distribuicao nao suportar `src_as`/`dst_as`, remova esses campos do `aggregate` e use a base ASN local pelo GMJ-FLOW.

## Duplicidade de collectors

O GMJ-FLOW contabiliza apenas flows recebidos pelo collector local configurado para o sensor. Se o roteador exportar para outros collectors, isso nao duplica os dados dentro do GMJ-FLOW. Evite apontar o mesmo exportador para duas portas/sensores GMJ-FLOW com o mesmo trafego, pois isso criaria duplicidade local.

Nao rode o profile `single-collector` junto com collectors sensorizados usando a mesma porta UDP. Isso faria o servico legado `pmacct` disputar `9995/udp` com `pmacct-sensor-1`.

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
