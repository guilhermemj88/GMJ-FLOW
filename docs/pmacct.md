# Coleta real com pmacct/nfacctd

Este modo recebe NetFlow v9/IPFIX do MikroTik via `nfacctd`, grava a saida do pmacct em CSV e usa um parser Python para inserir registros normalizados em `flowdb.flow_raw`.

## Topologia do laboratorio

- MikroTik/exporter: `192.168.0.157`
- Host GMJ-FLOW: `192.168.0.10`
- Porta NetFlow: UDP `9995`
- Rede cliente atras do MikroTik: `192.168.240.0/24`
- Sensor gravado no ClickHouse: `mikrotik-lab`
- Exporter gravado no ClickHouse: `192.168.0.157`
- Tipo gravado em `flow_raw.flow_type`: `netflow-v9`
- `sample_rate` padrao: `1`

## Configuracao do MikroTik

No RouterOS, habilite Traffic Flow e adicione o host GMJ-FLOW como destino:

```routeros
/ip traffic-flow set enabled=yes interfaces=all
/ip traffic-flow target add src-address=192.168.0.157 dst-address=192.168.0.10 port=9995 version=9
```

## Validacao com Wireshark

No PC/host GMJ-FLOW, filtre os pacotes recebidos:

```text
udp.port == 9995
```

Se o Wireshark mostra UDP `9995` chegando de `192.168.0.157`, o caminho de rede ate o host esta correto. A partir dai, valide containers, porta publicada e logs do pmacct/parser.

## Como subir o coletor real

Copie o arquivo de ambiente e suba o stack com o compose de collectors. O modo padrao atual usa collector por sensor; para o sensor 1, sobem `pmacct-sensor-1` e `pmacct-parser-sensor-1`.

```bash
cp .env.example .env
docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml up -d --build
```

Servicos relevantes:

```bash
docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml ps
docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml logs -f pmacct-sensor-1
docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml logs -f pmacct-parser-sensor-1
```

A porta publicada pelo Compose e:

```text
9995:9995/udp
```

O arquivo de saida do pmacct fica em volume Docker compartilhado, montado nos containers em:

```text
/var/spool/pmacct/sensor-1-9995.csv
```

Os servicos legados `pmacct` e `pmacct-parser` existem apenas para uso manual no profile `single-collector`. Nao use esse profile junto com `pmacct-sensor-1` na mesma porta UDP.

## Formato de saida do pmacct

A configuracao usa o plugin `print` em CSV para compatibilidade com pacotes Debian/Ubuntu que podem nao ter JSON habilitado.

Campos esperados, na ordem de fallback do parser quando nao houver header CSV:

```text
src_host,dst_host,src_port,dst_port,proto,tcpflags,in_iface,out_iface,src_as,dst_as,timestamp,packets,bytes,flows
```

O parser tambem aceita header CSV emitido pelo pmacct e tenta reconhecer aliases comuns para esses campos, incluindo `src_asn`/`dst_asn`.

## Consultas no ClickHouse

Verificar se dados reais entraram:

```bash
docker compose exec clickhouse clickhouse-client --database flowdb --query "SELECT count() FROM flow_raw WHERE sensor = 'mikrotik-lab'"
```

Ver ultimos registros reais:

```bash
docker compose exec clickhouse clickhouse-client --database flowdb --query "SELECT flow_time, sensor, flow_type, toString(src_ip) AS src_ip, toString(dst_ip) AS dst_ip, src_port, dst_port, proto, tcp_flags, bytes, packets FROM flow_raw WHERE sensor = 'mikrotik-lab' ORDER BY flow_time DESC LIMIT 10 FORMAT PrettyCompact"
```

Ver trafego agregado por minuto:

```bash
docker compose exec clickhouse clickhouse-client --database flowdb --query "SELECT minute, sensor, sum(bytes) AS bytes, sum(packets) AS packets, sum(flows) AS flows FROM flow_1m WHERE sensor = 'mikrotik-lab' GROUP BY minute, sensor ORDER BY minute DESC LIMIT 10 FORMAT PrettyCompact"
```

## Ajustes uteis

Variaveis em `.env`:

```dotenv
NETFLOW_PORT=9995
PMACCT_SENSOR=mikrotik-lab
PMACCT_EXPORTER_IP=192.168.0.157
PMACCT_SAMPLE_RATE=1
PMACCT_PARSER_BATCH_SIZE=1000
PMACCT_PARSER_FLUSH_SECONDS=5
```

O allowlist inicial do `nfacctd` aceita somente `192.168.0.157` em `collector/pmacct/allow.lst`.

## Observacoes

- Este coletor nao implementa ExaBGP/blackhole.
- Este coletor nao implementa autenticacao.
- O schema inicial usa `IPv6` em `flow_raw` para aceitar IPv4 e IPv6 no mesmo campo; IPv4 e armazenado normalmente e exibido via `toString()`.
- Se voce ja tinha um volume ClickHouse criado antes desta alteracao de schema, recrie o volume em laboratorio ou aplique ALTERs equivalentes antes de inserir dados reais.
