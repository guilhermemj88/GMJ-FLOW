# Integração GMJ-FLOW com Grafana

Esta integração foi dividida em fases para manter o dashboard nativo como
fonte de verdade e evitar que credenciais do Grafana sejam armazenadas em
widgets ou arquivos exportados.

## Escopo implementado

- **Fase 1 — API read-only:** catálogo, health e consultas canônicas de série
  temporal, ranking e tabela em `/api/v1/grafana`.
- **Fase 2 — exportação:** conversão determinística de dashboards GMJ-FLOW
  para JSON de dashboard do Grafana, direcionado ao datasource Infinity.
- **Fase 3 — publicação:** não habilitada. As rotas de publicação não fazem
  chamadas externas e retornam `phase_3_not_enabled`.

Nenhuma dessas fases altera o schema do ClickHouse, o pipeline de ingestão ou
o cache interno.

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
```

Scopes:

- `grafana:data:read`: health, catálogo e consultas.
- `grafana:dashboard:export`: exportação pela API pública.
- `grafana:dashboard:publish`: reservado à Fase 3 e desabilitado por padrão.

O token é comparado em tempo constante, não é escrito nos logs e pode ser
rotacionado com `GMJ_FLOW_GRAFANA_PREVIOUS_TOKEN`. Cada resposta inclui um
`X-Correlation-ID`, e a auditoria registra somente o hash curto de identidade
do token, ação, métrica e resultado.

CORS fica desabilitado por padrão. Se uma origem diferente realmente precisar
chamar a API do navegador, configure `API_CORS_ORIGINS` com uma lista explícita
de origens. Não use `*`. Para Grafana, prefira o parser backend do Infinity:
assim a consulta sai do servidor do Grafana, não do navegador.

## Contrato da API read-only

### Health e catálogo

```bash
curl -H "Authorization: Bearer <GMJ_FLOW_GRAFANA_TOKEN>" \
  https://gmj-flow.exemplo/api/v1/grafana/health

curl -H "Authorization: Bearer <GMJ_FLOW_GRAFANA_TOKEN>" \
  https://gmj-flow.exemplo/api/v1/grafana/catalog
```

O catálogo informa métricas, dimensões, cálculos e limites vigentes. Métricas
iniciais:

- `traffic_bps`
- `traffic_pps`
- `top_download_origins`
- `top_upload_destinations`
- `top_protocols`

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
    "timezone": "UTC",
    "format": "json"
  }'
```

Os pontos têm timestamps Unix em milissegundos, são ordenados e deduplicados.
Download e upload permanecem positivos no contrato; a inversão de upload no
modo `split_zero` é exclusivamente visual.

### Ranking

```bash
curl -X POST \
  -H "Authorization: Bearer <GMJ_FLOW_GRAFANA_TOKEN>" \
  -H "Content-Type: application/json" \
  https://gmj-flow.exemplo/api/v1/grafana/query/ranking \
  -d '{
    "metric": "top_download_origins",
    "from": "2026-07-28T10:00:00Z",
    "to": "2026-07-28T10:10:00Z",
    "top_n": 10,
    "filters": {"direction": "both"},
    "calculation": "last_not_null",
    "timezone": "UTC",
    "format": "json"
  }'
```

A resposta canônica contém `rank`, `key`, `label`, `value`, `percent` e
`metadata`. Use `format: "table"` para obter `columns` e `rows`. O endpoint
`/query/table` também aceita qualquer métrica do catálogo e retorna o formato
tabular estável.

O contrato aceita no máximo um sensor, uma interface e um protocolo por
consulta, um único `group_by`, até 5.000 pontos e até 100 itens de ranking. O
período máximo e o rate limit são configuráveis pelas variáveis acima.

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
