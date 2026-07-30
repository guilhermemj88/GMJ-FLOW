# Integração GMJ-FLOW com Grafana

Esta integração foi dividida em fases para manter o dashboard nativo como
fonte de verdade e evitar que credenciais do Grafana sejam armazenadas em
widgets ou arquivos exportados.

O guia integrado de layout, prefixos IPv4/IPv6, variáveis de exportação e
reimportação segura está em
[Dashboard, prefixos e Grafana — Fase 1](dashboard-prefixes-grafana-phase1.md).

## Escopo implementado

- **Fase 1 — API read-only:** rota de teste do datasource, catálogo, health,
  anomalias, mitigações, status BGP e consultas canônicas de série temporal,
  ranking e tabela em `/api/v1/grafana`.
- **Fase 2 — exportação:** conversão determinística de dashboards GMJ-FLOW
  para JSON de dashboard do Grafana, direcionado ao datasource Infinity.
- **Fase 3 — publicação:** não habilitada. As rotas de publicação não fazem
  chamadas externas e retornam `phase_3_not_enabled`.

A integração Grafana não duplica `flow_raw` nem altera o pipeline de
ingestão. O recurso integrado de prefixos adiciona somente a agregação
derivada minuto `flow_dashboard_prefix_1m` e inclui o contexto de prefixo nas
chaves do cache.

## Autenticação e segurança

A API pública usa um token exclusivo para a integração. Ela não aceita o
token administrativo nem o cookie da interface web.

Variáveis suportadas:

```text
GMJ_FLOW_GRAFANA_TOKEN=<segredo-longo-e-aleatorio>
GMJ_FLOW_GRAFANA_PREVIOUS_TOKEN=<opcional-durante-rotacao>
GMJ_FLOW_GRAFANA_SCOPES=grafana:data:read,grafana:dashboard:export
GMJ_FLOW_GRAFANA_RATE_LIMIT_PER_MINUTE=120
GMJ_FLOW_GRAFANA_MAX_WINDOW_SECONDS=604800
GMJ_FLOW_DATA_STALE_AFTER_SECONDS=90
```

Scopes:

- `grafana:data:read`: health, catálogo e consultas.
- `grafana:dashboard:export`: exportação pela API pública.
- `grafana:dashboard:publish`: reservado à Fase 3 e desabilitado por padrão.

O token é comparado em tempo constante, não é escrito nos logs e pode ser
rotacionado com `GMJ_FLOW_GRAFANA_PREVIOUS_TOKEN`. Cada resposta inclui um
`X-Correlation-ID`, e a auditoria registra somente o hash curto de identidade
do token, ação, métrica e resultado.

CORS fica desabilitado por padrão tanto na aplicação quanto no Compose. Se uma
origem diferente realmente precisar chamar a API do navegador, configure
`API_CORS_ORIGINS` com uma lista explícita de origens separadas por vírgula. Não
use `*`. Para Grafana, prefira o parser backend do Infinity: assim a consulta
sai do servidor do Grafana, não do navegador e não depende de CORS aberto.

## Contrato da API read-only

### Save & Test, health e catálogo

```bash
curl -H "Authorization: Bearer <GMJ_FLOW_GRAFANA_TOKEN>" \
  https://gmj-flow.exemplo/api/v1/grafana

curl -H "Authorization: Bearer <GMJ_FLOW_GRAFANA_TOKEN>" \
  https://gmj-flow.exemplo/api/v1/grafana/health

curl -H "Authorization: Bearer <GMJ_FLOW_GRAFANA_TOKEN>" \
  https://gmj-flow.exemplo/api/v1/grafana/catalog
```

O catálogo informa métricas, dimensões, cálculos e limites vigentes. Métricas
disponíveis:

- `traffic_bps`
- `traffic_pps`
- `top_upload_destinations`
- `top_download_origins`
- `top_source_ips`
- `top_destination_ips`
- `top_ports`
- `top_protocols`
- `top_tcp_flags`

Os rankings têm as seguintes dimensões e unidades:

| Métrica | Dimensão | Unidade principal |
| --- | --- | --- |
| `top_upload_destinations` | ASN de destino | `bps` |
| `top_download_origins` | ASN de origem | `bps` |
| `top_source_ips` | IP de origem | `bps` |
| `top_destination_ips` | IP de destino | `bps` |
| `top_ports` | protocolo + porta de destino | `bps` |
| `top_protocols` | protocolo | `bps` |
| `top_tcp_flags` | combinação de TCP flags | `pps` |

Datasets read-only para consultas JSONPath:

- `anomalies_active`: `/api/v1/grafana/anomalies/active`
- `anomalies_history`: `/api/v1/grafana/anomalies/history`
- `mitigations`: `/api/v1/grafana/mitigations`
- `mitigations_active`: `/api/v1/grafana/mitigations/active`
- `bgp_status`: `/api/v1/grafana/bgp/status`

O histórico aceita `from`, `to`, `limit` (100 por padrão e 1.000 no máximo),
`offset`, `status`, `severity` e `search`. As respostas mantêm timestamps em
UTC e usam objetos JSON simples; `$.items[*]` pode ser usado diretamente nos
painéis. Essas rotas aceitam apenas `GET` e não executam, aprovam, rejeitam ou
retiram mitigações.

### Anomalias e CGNAT

Cada item de anomalia inclui:

```text
cgnat_applicable, cgnat_resolved, cgnat_private_ip, cgnat_public_ip,
cgnat_public_port, cgnat_port_range, cgnat_pool, cgnat_device,
cgnat_vendor, cgnat_mapping_source, cgnat_confidence
```

`cgnat_private_ip` é o mesmo valor exibido como
**Cliente CGNAT/private_ip** no detalhe da anomalia. A API reutiliza o
enriquecimento do detalhe e não mantém um algoritmo de resolução paralelo.
Quando CGNAT não se aplica, `cgnat_applicable` e `cgnat_resolved` são `false`
e os demais campos CGNAT são `null`. Quando a resolução é necessária, mas não
encontra um cliente inequívoco, `cgnat_applicable` é `true`,
`cgnat_resolved` é `false` e os dados do mapeamento permanecem `null`.

`cgnat_mapping_source` contém somente o tipo seguro da fonte, como `a10` ou
`mikrotik_netmap`. Nome de arquivo, conteúdo importado, lote, candidatos
internos e regras completas não fazem parte do contrato Grafana.

### Mitigações

`GET /api/v1/grafana/mitigations/active` retorna anúncios operacionais nos
estados equivalentes a `sent`, `advertised`, `active`, `applied` e o estado
legado `announced`. Registros expirados pelo timestamp também são excluídos,
mesmo antes da próxima rotina de manutenção.

Nunca são considerados ativos estados como `expired`, `withdrawn`, `failed`,
`blocked`, `rejected`, `dry_run` ou `simulation_only`. A resposta informa o
conector, regra, fluxo, prefixo, início, expiração, TTL restante e os mesmos
campos CGNAT seguros das anomalias.

`GET /api/v1/grafana/mitigations` aceita:

```text
active_only, anomaly_id, status, connector_id, from, to, limit, offset
```

`limit` usa 100 por padrão e aceita no máximo 1.000. `from` e `to` são
ISO-8601 e filtram o instante operacional da mitigação. A resposta inclui
`count`, `total`, `limit` e `offset`.

As rotas Grafana nunca retornam comandos `announce`/`withdraw`, senha,
credencial BGP ou Bearer Token. Também não possuem métodos para anunciar,
retirar, aprovar, rejeitar ou modificar mitigações.

## Configuração do Grafana JSON API

1. Crie um datasource do tipo **JSON API**.
2. Configure a URL como `https://gmj-flow.exemplo/api/v1/grafana`.
3. Adicione o header seguro
   `Authorization: Bearer <GMJ_FLOW_GRAFANA_TOKEN>`.
4. Execute **Save & Test**. A rota-base autenticada deve responder
   `status: ok`.
5. Nos painéis, consulte um dos caminhos read-only listados no catálogo e use
   `$.items[*]` como raiz dos dados.

O datasource deve usar um token cujo conjunto de scopes inclua
`grafana:data:read`. Não é necessário nem suportado um plugin Grafana próprio
para esses endpoints.

### Série temporal

```bash
curl -X POST \
  -H "Authorization: Bearer <GMJ_FLOW_GRAFANA_TOKEN>" \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: grafana-panel-a" \
  https://gmj-flow.exemplo/api/v1/grafana/query/timeseries \
  -d '{
    "metric": "traffic_bps",
    "from": "2026-07-28T10:00:00Z",
    "to": "2026-07-28T10:10:00Z",
    "interval_ms": 60000,
    "max_data_points": 1000,
    "filters": {
      "sensor_ids": [],
      "interfaces": [],
      "protocols": [],
      "direction": "both"
    },
    "group_by": ["direction"],
    "calculation": "rate",
    "include_partial_bucket": false,
    "timezone": "UTC",
    "format": "json"
  }'
```

Os pontos têm timestamps Unix em milissegundos, são ordenados e deduplicados.
Download e upload permanecem positivos no contrato; a inversão de upload no
modo `split_zero` é exclusivamente visual.

Por padrão, o bucket ainda aberto não é retornado. A taxa usa a duração real
do intervalo selecionado (1 s, 5 s, 10 s, 30 s, 1 min, 5 min etc.). Para
diagnóstico, `include_partial_bucket: true` inclui o bucket vigente com
`partial: true` e `bucket_duration_seconds` igual ao tempo efetivamente
transcorrido. `null` continua `null`; zero é uma amostra válida.

`meta.quality` informa `data_status` (`current`, `delayed` ou `no_data`),
`last_complete_sample_at`, atraso, limite configurado, aviso de ingestão e
timezone UTC. Erro de consulta permanece um erro HTTP e não é convertido em
zero ou em “sem dados”.

### Ranking

```bash
curl -X POST \
  -H "Authorization: Bearer <GMJ_FLOW_GRAFANA_TOKEN>" \
  -H "Content-Type: application/json" \
  https://gmj-flow.exemplo/api/v1/grafana/query/ranking \
  -d '{
    "metric": "top_ports",
    "from": "2026-07-28T10:00:00Z",
    "to": "2026-07-28T10:10:00Z",
    "direction": "both",
    "sensor": 2,
    "interface": 17,
    "protocol": "udp",
    "top_n": 10,
    "calculation": "rate",
    "timezone": "UTC",
    "format": "json"
  }'
```

Os filtros podem ser enviados diretamente como no exemplo ou no formato
anterior:

```json
{
  "filters": {
    "direction": "both",
    "sensor_ids": [2],
    "interfaces": [17],
    "protocols": ["udp"]
  }
}
```

Não misture os dois formatos com valores diferentes. `direction` aceita
`both`, `upload` e `download`; `top_n` aceita de 1 a 100. O contrato aceita
um sensor, uma interface e um protocolo por consulta e aplica esses filtros
antes da agregação. `from` e `to` são obrigatórios, em ISO-8601, e o intervalo
selecionado no Grafana é preservado.

Os cálculos aceitos em rankings são `last`, `last_not_null`, `mean`, `max`,
`min`, `total` e `rate`. Rankings de tráfego mantêm `bps` como valor
principal. `top_tcp_flags` mantém `pps` como valor principal e também retorna
o total de `packets`.

Resposta canônica:

```json
{
  "kind": "ranking",
  "metric": "top_ports",
  "unit": "bps",
  "items": [
    {
      "rank": 1,
      "key": "udp/443",
      "label": "udp/443",
      "value": 1200000000,
      "bps": 1200000000,
      "pps": 820000,
      "percentage": 45.2,
      "percent": 45.2,
      "asn": null,
      "asn_name": "",
      "country_code": "",
      "country_name": "",
      "protocol": "UDP",
      "port": 443,
      "display_name": "udp/443",
      "tcp_flags": null,
      "packets": 492000000,
      "metadata": {}
    }
  ],
  "total": 2650000000,
  "timestamp": "2026-07-28T10:10:00Z",
  "calculation": "rate",
  "meta": {
    "source": "aggregate_first",
    "timezone": "UTC",
    "correlation_id": "grafana-panel-top-ports"
  }
}
```

`percentage` é o campo canônico; `percent` permanece como alias para não
quebrar painéis existentes. Para o plugin Grafana JSON API, use
`$.items[*]` como raiz e mapeie `label` para o texto e `value` para o valor.
Campos numéricos permanecem números, sem formatação localizada.
Os dois campos percentuais são recalculados como
`value / soma dos values retornados * 100`; totais anteriores ao `LIMIT` ou
expressos em outra unidade não entram nesse cálculo.

#### ASN, portas e TCP flags

`top_upload_destinations` agrupa o upload por ASN de destino.
`top_download_origins` agrupa o download por ASN de origem. Ambos reutilizam
o enriquecimento ASN do dashboard nativo e retornam `asn`, `asn_name`,
`country_code` e `country_name`:

```json
{
  "rank": 1,
  "key": "AS263009",
  "label": "AS263009 — Nome da rede (BR)",
  "value": 7900000000,
  "bps": 7900000000,
  "pps": 3500000,
  "percentage": 49.49,
  "asn": 263009,
  "asn_name": "Nome da rede",
  "country_code": "BR",
  "country_name": "Brazil"
}
```

No primeiro contrato de `top_ports`, `port` é sempre a porta de destino e a
chave de agrupamento é protocolo + porta. Exemplos de `display_name`:
`udp/443`, `tcp/57300` e `udp/53`.

`top_tcp_flags` considera somente fluxos cujo protocolo IP é TCP e normaliza
ausência de flags como `NONE`. Combinações seguem a
ordem `FIN,SYN,RST,PSH,ACK,URG,ECE,CWR`; por exemplo `SYN,ACK`,
`FIN,ACK`, `PSH,ACK` e `SYN,PSH,ACK`. Cada item retorna `tcp_flags`, `pps`,
`packets` e `percentage`.

Use `format: "table"` para obter `columns` e `rows`. O endpoint
`POST /api/v1/grafana/query/table` também aceita qualquer métrica de ranking,
os mesmos filtros, `top_n` e `calculation`, e retorna colunas estáveis para
JSONPath: `rank`, `label`, `value` e `percent`.

O período máximo e o rate limit são configuráveis pelas variáveis acima. As
consultas reutilizam os agregados e o motor Top N do dashboard, aplicam
`LIMIT` no ClickHouse e não carregam registros de fluxo linha a linha.

Erros usam a forma:

```json
{
  "detail": {
    "error": "metric_not_allowed",
    "message": "Métrica não permitida.",
    "correlation_id": "grafana-panel-a"
  }
}
```

## Configuração do Infinity

1. Instale o plugin Infinity no Grafana pelo processo administrativo adotado
   no ambiente.
2. Crie um datasource com parser **Backend**.
3. Configure a **Base URL** do GMJ-FLOW e inclua essa origem em **Allowed
   hosts** no datasource.
4. Use `Authorization: Bearer <token>` no armazenamento seguro do datasource.
5. Importe o JSON gerado pelo GMJ-FLOW e selecione o datasource quando
   solicitado.

Exemplo de datasource:

```text
Base URL: https://gmj-flow.exemplo
Allowed hosts: https://gmj-flow.exemplo
Authentication header: Authorization = Bearer <token>
Parser: Backend
```

O export usa:

```text
/api/v1/grafana/query/timeseries
/api/v1/grafana/query/ranking
```

As URLs são relativas à Base URL do datasource. O export também usa as macros
de tempo do Infinity, que são interpoladas no backend:

```text
${__timeFrom:date:iso}
${__timeTo:date:iso}
${__interval_ms}
${__maxDataPoints}
```

O JSON exportado não contém `Authorization`, cookies, tokens ou headers
secretos. A versão atual do Infinity recomenda parser backend (JSONata ou JQ)
para alertas, dashboards compartilhados e cache, e recomenda suas macros
`__timeFrom`/`__timeTo` para requisições de backend. Consulte a
[documentação de configuração](https://grafana.com/docs/plugins/yesoreyeram-infinity-datasource/latest/configure/),
[macros](https://grafana.com/docs/plugins/yesoreyeram-infinity-datasource/latest/query/macros/)
e [query editor](https://grafana.com/docs/plugins/yesoreyeram-infinity-datasource/latest/query/).
O Infinity mais recente requer Grafana 11.6 ou superior; para Grafana 10 ou
11.0–11.5, valide uma versão anterior compatível do plugin antes da importação.

## Exportação de dashboard

Na interface do GMJ-FLOW, abra **Gerenciar dashboard → Grafana**. É possível:

- escolher Grafana 10, 11 ou 12;
- informar datasource UID e folder UID;
- incluir ou omitir widgets ocultos;
- testar a estrutura localmente;
- copiar ou baixar o JSON.

Endpoint autenticado pela sessão do usuário:

```text
GET /api/dashboards/{dashboard_id}/grafana-export
```

Endpoint autenticado pelo token da integração:

```text
GET /api/v1/grafana/dashboards/{dashboard_id}/export
```

O exportador preserva posição e tamanho (`gridPos`), título, descrição,
unidade, decimais, cores, overrides, cálculo de legenda e orientação visual.
Ele converte visualizações para `timeseries`, `barchart`, `piechart`,
`bargauge`, `stat` ou `table`. Recursos sem equivalência exata geram avisos em
`meta.warnings`, no formato:

```json
{
  "widget_id": 17,
  "field": "appearance.custom_gradient",
  "message": "Gradiente personalizado não possui equivalente exato no Grafana."
}
```

O mesmo dashboard e as mesmas opções produzem o mesmo `meta.export_hash`.
Campos voláteis e credenciais não participam do documento.

## Painéis e variáveis

Para séries, use o endpoint de timeseries e selecione `$.rows` quando o painel
esperar dados tabulares: `timestamp` é epoch em milissegundos, `series` é texto
e `value` é número ou `null`. Para rankings, `$.items` alimenta barras,
pie/donut e tabelas; `value` e `percentage` são numéricos (`percent` é o alias
legado), e os campos planos incluem ASN, organização, país, protocolo, porta
e TCP flags conforme a métrica.

As macros `${__timeFrom:date:iso}`, `${__timeTo:date:iso}`,
`${__interval_ms}` e `${__maxDataPoints}` devem vir do Grafana. Variáveis de
sensor, interface ou protocolo podem preencher `sensor`, `interface` e
`protocol`, ou os arrays correspondentes em `filters`; o contrato aceita no
máximo um valor de cada por consulta.

## Troubleshooting

- **401:** confirme que o header é `Authorization: Bearer ...`, que o token
  foi configurado no container backend e que não há espaços extras.
- **403:** inclua `grafana:data:read` para consultas ou
  `grafana:dashboard:export` para exportação.
- **URL not allowed:** adicione exatamente a origem da Base URL em Allowed
  hosts e use o parser Backend.
- **Sem dados:** consulte health e catalog, confira o período em UTC e leia
  `meta.quality`. `no_data` indica ausência de amostras; `delayed` indica que
  a última completa ultrapassou `GMJ_FLOW_DATA_STALE_AFTER_SECONDS`.
- **Último ponto ausente:** é o comportamento esperado enquanto o bucket está
  aberto. Use `include_partial_bucket: true` apenas para diagnóstico.

## Compose e PMACCT

Os collectors rodam pelo arquivo separado `docker-compose.collectors.yml`.
Ao reconstruir backend/frontend, não use `--remove-orphans`, pois os containers
PMACCT são intencionais embora não apareçam no compose base. Não remova
volumes durante uma atualização. Depois do deploy da aplicação, valide sem
mutação:

```sh
sh scripts/check_pmacct_collectors.sh
```

## Plano detalhado da Fase 3

A publicação direta só deve ser ativada depois de uma revisão de segurança e
de operação. O plano recomendado é:

1. Criar uma entidade de conexão Grafana administrada fora do JSON do
   dashboard, com URL permitida por allowlist, segredo criptografado e acesso
   restrito a administradores.
2. Implementar um cliente HTTP dedicado com timeout curto, TLS obrigatório,
   limite de tamanho, bloqueio de redirects e proteção SSRF por resolução de
   host e faixas IP.
3. Implementar `dry-run` puramente local: gerar o documento, validar schema,
   calcular diff determinístico e listar avisos, sem chamada externa.
4. Implementar um `dry-run` remoto opcional somente contra endpoint de
   validação permitido, sem mutação, caso a versão do Grafana ofereça esse
   recurso.
5. Publicar via `POST /api/dashboards/db` apenas após confirmação explícita,
   com `overwrite=false` como padrão e controle de versão/UID.
6. Persistir somente metadados seguros: UID remoto, hash exportado, status,
   versão e timestamps. Nunca persistir o token em logs ou snapshots.
7. Implementar consulta de status e detecção de drift comparando o hash local
   ao dashboard remoto normalizado.
8. Adicionar idempotency key, retry apenas para falhas transitórias,
   correlation ID ponta a ponta, auditoria de ator e rollback por versão.
9. Cobrir com testes usando servidor HTTP falso local; os testes jamais devem
   apontar para uma instância Grafana real.
10. Manter a feature flag de publicação desligada por padrão e documentar um
    runbook separado de habilitação e rotação de segredo.

Até essa fase ser concluída, `/publish` retorna HTTP 501 e `/status` informa
`phase_3_not_enabled`; nenhum desses endpoints faz chamadas de rede.
