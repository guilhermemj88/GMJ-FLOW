# GeoIP Offline (Threat Intelligence Map V2.2)

O Security Situation Map usa geolocalização **100% local/offline** para IPs
públicos. Nenhuma API externa (MaxMind web, ipinfo, ip-api, RDAP, GreyNoise,
Team Cymru) é chamada durante o render.

## Arquivo necessário

| Item | Valor |
|---|---|
| Arquivo | `GeoLite2-City.mmdb` |
| Formato | MaxMind DB (`.mmdb`), base City |
| Biblioteca | `geoip2` (já listada em `backend/requirements.txt`) |
| Variável | `GMJFLOW_GEOIP_MMDB_PATH` |

## Onde colocar

O container `backend` monta `./data/backend` em `/app/data`. O caminho padrão é:

```
/app/data/GeoLite2-City.mmdb   →  ./data/backend/GeoLite2-City.mmdb (host)
```

Ou configure um caminho próprio via `.env`:

```
GMJFLOW_GEOIP_MMDB_PATH=/app/data/GeoLite2-City.mmdb
```

O arquivo **não** deve ser commitado no Git.

## Como disponibilizar

O GeoLite2 da MaxMind atualmente exige conta e aceitação de licença
(https://www.maxmind.com). Não há URL pública não autenticada confiável — por
isso este projeto **não** baixa o arquivo automaticamente.

1. Crie uma conta MaxMind e aceite a licença do GeoLite2.
2. Baixe `GeoLite2-City.mmdb` (edição City).
3. Copie para `data/backend/GeoLite2-City.mmdb` (ou o path configurado).
4. Reinicie o backend: `docker compose up -d --build backend`.

> Nunca coloque a license key da MaxMind em arquivos versionados.

## Fallback chain (sem o arquivo)

Sem o MMDB, o mapa continua funcionando com:

1. MaxMind City (se o arquivo existir) → `MAXMIND_CITY`
2. ASN local → país → `ASN_COUNTRY`
3. centroid do país → `COUNTRY_CENTROID`
4. não resolvido → `NONE` (contabilizado como `unlocated_public`)

A degradação é graciosa: a ausência do arquivo não quebra o mapa nem os demais
serviços.
