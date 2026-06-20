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

O parametro legado `ip` continua funcionando no backend e consulta `src_ip = ip OR dst_ip = ip`. Enderecos IPv4 sao convertidos para IPv4-mapped IPv6, como `::ffff:192.168.0.171`, para comparar com as colunas IPv6 do ClickHouse.

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
