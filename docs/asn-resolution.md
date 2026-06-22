# Resolucao ASN local/cache

O GMJ-FLOW usa ASN vindo do flow quando `src_asn`/`dst_asn` chegam preenchidos pelo exporter. Quando o IPFIX/NetFlow vem com ASN `0`, o backend tenta resolver o IP usando base local e cache, sem consulta externa durante o carregamento do Dashboard.

## Tabelas SQLite

- `asn_prefixes`: prefixos locais com `asn`, `as_name`, `country`, `source` e timestamps.
- `asn_info`: metadados por ASN.
- `asn_lookup_cache`: cache por IP resolvido, com TTL.
- `asn_resolution_queue`: fila de IPs pendentes ou stale.

## Prioridade

1. ASN informado no flow/IPFIX.
2. Cache valido em `asn_lookup_cache`.
3. Longest prefix match em `asn_prefixes`.
4. Enfileirar em `asn_resolution_queue`.
5. Retornar `ASN indisponivel` temporariamente.

IPv4-mapped IPv6, como `::ffff:179.189.80.17`, e normalizado para IPv4 antes do lookup.

## Endpoints

```text
GET  /api/asn/status
POST /api/asn/import
POST /api/asn/queue-from-flows
POST /api/asn/resolve
```

O botao **Resolver ASNs** chama `queue-from-flows` com os filtros atuais e depois `resolve`. O Dashboard e o TOP Flow usam apenas cache/base local durante requests normais.

## Job diario

O backend inicia um job em background para processar a fila:

```env
GMJFLOW_ASN_RESOLVER_ENABLED=true
GMJFLOW_ASN_RESOLVER_INTERVAL_SECONDS=86400
GMJFLOW_ASN_RESOLVER_MAX_IPS_PER_RUN=5000
GMJFLOW_ASN_CACHE_TTL_SECONDS=604800
```

A interface modular `resolve_ips_to_asn(ips)` esta pronta para plugar um provider externo no job. Consultas externas nao devem ser feitas dentro do Dashboard.

## TOPs e pais

Os widgets **Maiores ASNs de Upload/Download** e o **TOP Flow** para ASN exibem `Pais`. Quando nao houver pais na base/cache, a UI mostra `N/D`.

## Huawei NE8000

Para Huawei com:

```text
ip netstream sampler fix-packets 1000 inbound
ip netstream sampler fix-packets 1000 outbound
```

configure `sample_rate_default_in=1000` e `sample_rate_default_out=1000` no sensor, mantenha as interfaces herdando do sensor e use a calibracao SNMP para validar.
