# Dashboard e Flow Search

## Filtros

O Dashboard usa os filtros `Periodo`, `Sensor` e `Interface`. Com todos os sensores selecionados, os graficos de Bits/s e Packets/s exibem series por sensor. Com um sensor especifico, os graficos exibem series por interface monitorada. Com sensor e interface, os graficos e tops consideram apenas flows em que `input_if` ou `output_if` correspondem ao `if_index` escolhido.

O Flow Search aceita filtros independentes:

- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `proto`
- `sensor_id`
- `interface_id` ou `if_index`
- `range_minutes` ou `start_time`/`end_time`
- `limit`
- `order_by`/`order_dir`
- `decoder`

O parametro legado `ip` continua funcionando no backend e consulta `src_ip = ip OR dst_ip = ip`. Enderecos IPv4 sao convertidos para IPv4-mapped IPv6, como `::ffff:192.168.0.171`, para comparar com as colunas IPv6 do ClickHouse.

## Busca por expressao (DSL)

Alem dos filtros por coluna, o Flow Search aceita `expression=<DSL>` (apenas a secao MATCH):

```http
GET /api/flows/search?range_minutes=60&expression=proto%20==%20udp%20and%20src_port%20==%2053
```

`expression` e filtros legados podem ser combinados; a combinacao e **AND**. Sem `expression`, o comportamento antigo permanece igual. Para validar/preview sem executar query use `GET /api/flows/expression/validate?expression=...`, que devolve `valid`, `canonical_expression`, AST resumida, campos e erros estruturados.

Limites de protecao: 2000 caracteres por expressao, 40 condicoes, profundidade 12, 64 itens por lista `IN`/`NOT IN` e 200 caracteres de regex. `direction == inbound/outbound` filtra pelo IP interno no destino/origem usando as redes internas: primeiro `GMJFLOW_FLOW_INTERNAL_CIDRS` (override), senao os prefixos ativos das zonas (`ip_zones`/`ip_zone_prefixes`), senao o default RFC1918 + loopback + link-local + CGNAT + ULA.

A semantica completa (campos, operadores, exemplos e comparacao legacy x expressao) esta em `docs/detection-rule-language.md`.

A aba **Flows** tem duas sub-abas:

- **Registros de Flow**: tabela de registros com ordenacao no backend e exportacao CSV por `format=csv`.
- **TOP Flow**: agregacoes por IP origem, IP destino, conversa, portas, protocolo, TCP flags, interfaces e ASN.

Os valores de Bits/s, Packets/s, Bytes e Pacotes sao corrigidos pelo sample-rate efetivo: override da interface quando existir, depois default IN/OUT do sensor, depois `flow_raw.sample_rate` e, por fim, `1`. `Flows` permanece bruto.

## Upload e download

Nos graficos, Download aparece positivo e Upload aparece negativo. O valor negativo e apenas visual: tooltips, tabelas e readouts exibem valores absolutos.

Regra MVP:

- `input_if` representa Download.
- `output_if` representa Upload.

Quando a direcao da interface estiver configurada como Upstream, Downstream, Both ou Unset, essa informacao fica disponivel para evoluir a classificacao de direcao. A primeira versao mantem a regra simples por `input_if`/`output_if`.

## Cores e legendas

Sensores recebem cores deterministicas geradas a partir do identificador/nome. Interfaces usam a cor salva no SQLite. A legenda do ECharts permite ocultar ou exibir series clicando no item da legenda.

## ASN

Os widgets `Maiores ASNs de Upload` e `Maiores ASNs de Download` usam:

- `GET /api/tops/asn-src`
- `GET /api/tops/asn-dst`

O MVP nao faz chamadas externas por flow. Enquanto nao houver base ASN local, os endpoints retornam `ASN indisponivel` com o trafego agregado do filtro atual. O caminho recomendado e integrar uma base local, como MaxMind GeoLite2 ASN ou uma tabela/cache local de prefixos IP para ASN/organizacao.

O backend agora tenta esta ordem:

1. `src_asn`/`dst_asn` vindo do flow/IPFIX.
2. Base local `asn_prefixes` por prefixo IP.
3. Resolucao sob demanda via botao **Resolver ASNs**, que enfileira IPs sem ASN e processa a fila usando base/cache local.

Endpoints administrativos:

```text
GET  /api/asn/status
POST /api/asn/import
POST /api/asn/queue-from-flows
POST /api/asn/resolve
```

Veja tambem `docs/asn-resolution.md`.
