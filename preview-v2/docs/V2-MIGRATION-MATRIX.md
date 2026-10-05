# GMJ-FLOW — Matriz de Migração para o Preview V2

> **Documento persistente de verdade da migração V2.**
> Toda sessão futura deve ler este arquivo antes de implementar qualquer tela e
> atualizar a linha correspondente na matriz ao terminar um bloco.
>
> Base: auditoria global concluída em **2026-09-25** (frontend de produção,
> backend real via OpenAPI, Preview V2 local e os dois `nginx.conf`).
> Esta tarefa **não implementa tela nenhuma** — apenas formaliza a auditoria.

---

## 1. Fontes de verdade

| Papel | Fonte | O que manda |
| --- | --- | --- |
| Funcional | **Backend real** (`/openapi.json`, 357 paths) | Contratos, verbos, comportamento |
| Funcional existente | **Frontend de produção** `:8080` | O que o operador já usa hoje |
| Visual | **Preview V2** `:8081` | Linguagem visual e estrutura novas |
| Exploração visual | **Magic Patterns** | Ferramenta de design, **nunca** fonte funcional |

### Princípios do Preview V2

- **read-only** (escrita bloqueada no nginx, sem exceções novas por conveniência);
- **sem mocks** — todo dado vem do backend real;
- **sem endpoints inventados** — só o que existe no backend;
- **mesmo backend real** de produção;
- **produção isolada** — nenhum artefato do V2 pode alterar `:8080`.

---

## 2. Estado confirmado da auditoria

| Métrica | Valor |
| --- | --- |
| Views reais em produção | **21** (20 no menu + `placeholder`) |
| COMPLETE no V2 | **3** — Dashboard, Threat Intelligence, Anomalias |
| PARTIAL no V2 | **5** — Flows, Sensores, Peak Hunter, Mitigação, BGP / Conectores |
| MISSING no V2 | **12** — Mapa Global, Interfaces, Clientes/Prefixos, Vetores de Ataque, Alertas, Banco de Dados, Codecs, IA, Sistema, Configurações/CGNAT, Usuários e Acessos, Minha Conta |
| NOT_APPLICABLE | **1** — `view-placeholder` |
| Containers de modal/drawer | **20** |
| Funções de abertura | **34** |
| Modais/drawers importantes para paridade | **~15** |
| Referências de endpoint no frontend antigo | **247** |
| Paths distintos do backend alcançados | **220** |
| Destes, somente leitura | **98** |
| Destes, com verbo mutável | **122** |
| Endpoints usados pelo V2 | **46 paths** (51 referências, todas GET) |
| Paths totais do backend | **357** (213 GET, 153 POST, 27 PUT, 27 DELETE, 8 PATCH) |

---

## 3. Política read-only vigente

Comportamento atual do nginx do preview (`:8081`):

| Verbo | Situação |
| --- | --- |
| `GET` / `HEAD` / `OPTIONS` | Permitidos |
| `POST` / `PUT` / `PATCH` / `DELETE` | **Bloqueados por padrão (405)** |

POSTs liberados como exceção exata (semântica de leitura):

- `POST /api/auth/login`
- `POST /api/v1/auth/login`
- `POST /api/dashboard-widgets/query`
- `POST /api/dashboard-widgets/preview`
- `POST /api/dashboards/{id}/widgets/{id}/query`

Namespace totalmente bloqueado:

- `/api/v1/grafana/*` → **404**

### Classificação das ações mutáveis

- **A — pode aparecer desabilitada com explicação:** `ack`, `close`, `feedback`
  (Peak Hunter), `mark-benign/confirmed/investigating`, `analyze-ai/reanalyze-ai`,
  `providers/{p}/test|sync`, `dry-run` (BGP/FlowSpec), `test` (profile/vetor/
  interface/SNMP), `collectors/apply`, `dashboard-cache` (DELETE),
  `imports/{id}/parse` e `errors.csv`.
- **B — deve permanecer escondida:** usuários (reset-password, revoke-sessions,
  enable/disable, CRUD), `auth/change-password`, CGNAT (approve/activate/
  deactivate/reject e CRUD de pools), IA (providers/prompts/routes/settings,
  models pull/cancel), codecs CRUD, ip-zones CRUD, sensores/interfaces CRUD,
  `network-assets` PUT, attack-vectors/templates CRUD + `apply-all`,
  `asn/resolve|queue-from-flows`, RTBH candidatos, dashboards/widgets
  (POST/PATCH/DELETE de layout).
- **C — requer decisão futura:** `bgp/connectors` CRUD e `recover-sessions`,
  `bgp/announcements/{id}/approve|reject|withdraw`,
  `anomalies/{id}/mitigation/apply|reject|evaluate`, `threat-engine/run`,
  `prefixes` (POST), aplicação real de RTBH.

---

## 4. Dependências entre módulos

```
Anomalia → Mitigação → Announcement → BGP / Conector → RTBH
Anomalia → Threat Intelligence

Flows → Sensores → Interfaces → Peak Hunter
Peak Hunter → Detection Rule → Attack Vector → Response Profile → Playbook

Dashboard → Clientes / Prefixos → Mapa Global

Alertas → Anomalias
        → BGP Announcements
        → Mitigação Executions
        → Collectors Health

Cross-links globais: IP · ASN · Interface · Evento

Requisitos registrados no bloco 8.1 (dependência funcional):
UDP flood (dst/port) → Flows → Sensor/Exporter → ingress interface → interface resolvida
(exporter/sensor, ifIndex) → interface conhecida  ← um único resolver, reutilizado
```

Consequência prática: **migrar juntos** o que compartilha drawer/fetch/artefato
(Anomalia+Mitigação+BGP; Flows+Sensores+Interfaces; Peak Hunter+Vetores de
Ataque; Dashboard+Clientes/Prefixos+Mapa Global).

O requisito de resolução de interface reforça esse agrupamento: o mesmo resolver
`(exporter/sensor, ifIndex) → interface` deve ser compartilhado por Flows,
Sensores, Interfaces, Anomalias, Alertas, drawers de investigação e Peak Hunter
— nunca uma tradução diferente por tela.

---

## 5. Componentes do V2

### Já existentes (reutilizar sempre)

`Badge` · `Panel` · `Table` · `useApi`/`api` · `Loading` · `ErrorBox` · `Drawer`
· `Section` · `KvGrid` · `KPI` · `Sparkline` · `TrafficChart` · `Select` ·
`Tabs` / `SubTabs`

Criados no BLOCO 1 (já disponíveis para os próximos blocos):
`ReadOnlyAction` · `EntityLink` · `Timeline` · `EmptyState` · `Pagination` ·
`KeyValues` · `EvidenceLevel` · `StatusDot` · `stateTone`

### A padronizar / criar futuramente

`FilterBar` · `TimeRangePicker` · `JsonViewer`/`EvidenceBlock` · `CopyValue` ·
`GeoMap` · wrappers de gráfico · `StatusBadge` unificado

Requisito de componente (BLOCO 3, ver 8.1): **resolver de interface
reutilizável** `(exporter/sensor, ifIndex) → interface conhecida`, usado por
Flows, Sensores, Interfaces, Anomalias, Alertas, drawers de investigação e
Peak Hunter quando aplicável.

### Diretriz

- **Não** criar uma abstração genérica excessiva de `InvestigationDrawer`.
- Compartilhar **primitivas e estrutura**; preservar a **semântica específica**
  de cada domínio (anomalia ≠ evento de segurança ≠ mitigação).

---

## 6. Dívidas e decisões pendentes

1. **Permissões por papel ainda não aplicadas no V2.** Antes de expor CGNAT,
   Usuários e IA/configuração, o V2 deve respeitar as permissões reais
   (`dashboard.view`, `sensors.view`, `anomalies.view`, `mitigations.view`,
   `bgp.view`, `settings.view`, `cgnat.view`, `users.view`).
2. **Canonicalização futura:** `/api/anomalies/*` **versus**
   `/api/security/anomalies/*` — decidir antes de migrar Alertas/Anomalias para
   não duplicar fetch.
3. **Grafana continua bloqueado** (`/api/v1/grafana/*` → 404), o que trava
   widgets configuráveis e o export do Dashboard.
4. **POSTs que funcionam como consulta** precisam de análise individual de
   efeito colateral antes de virarem exceção no nginx.
5. **`/health` do preview retorna 401** (em `:8080` retorna
   `{"status":"ok","clickhouse":"ok"}`) — alinhar para monitoração.
6. **Polling precisa respeitar visibilidade da aba** (Dashboard, TI e Ops
   summary fazem refresh periódico em produção).
7. **Estado persistente/localStorage ainda não padronizado** (tema, grupos do
   menu, layout do dashboard em produção; no V2 só existe a chave do token).

---

## 7. Checkpoints das telas já migradas

### DASHBOARD V2

- **Status:** COMPLETE
- Gaps residuais documentados: dashboards configuráveis e widgets, Mapa Global
  geoespacial, export Grafana, drilldowns, seletor de período e controles de
  prefixo.

### THREAT INTELLIGENCE V2

- **Status:** COMPLETE
- Gaps residuais documentados: ações de investigação (mark-benign/confirmed,
  analyze-ai, test/sync de provider) e detalhamento de campanhas/decisões.

### ANOMALIAS V2

- **Status:** COMPLETE
- Chrome validado
- ErrorBoundary funcionando
- console sem erros
- read-only validado
- Gaps residuais documentados: ações (ack/close/aplicar-rejeitar mitigação),
  feedback e detalhe legado.

---

### BLOCO 1 — Mitigação + BGP / Conectores (VALIDADO, COMPLETE)

- **Status:** `COMPLETE`. Código V2 entregue, buildado, publicado em `:8081` e
  **validado em Chrome autenticado** (sessão reaproveitada do navegador, sem
  tocar em credenciais).
- **Validação funcional autenticada (2026-09-25):** Dashboard (13 rankings,
  4 KPIs), Threat Intelligence (6 abas + drawer "Evento de segurança"),
  Anomalias (Ativas 11 / Histórico 25 / Consolidadas 3 / Resumo com 14 rankings
  + drawer), Mitigação (Agora com 8 KPIs, 6 chips de automação e 4 painéis;
  Execuções com 400 linhas, busca e filtro de status; drawer de execução com as
  7 seções, 7 níveis de evidência e timeline) e BGP/Conectores (Overview com 11
  chips separados — listener, FIFO, mount, FSM, FlowSpec, pipe, reader,
  host-agent; Conectores com drawer de 10 seções; Announcements com 22 linhas e
  drawer de 9 seções).
- **Cadeia real validada nos dois sentidos:** anomalia **#3569** → execução
  **#443** → announcement **#19** → conector **#4 (BGP-GM-BORDA)**, e a volta
  conector #4 → announcement #19 (9 seções, **8 eventos reais** de
  `bgp_announcement_events`) → execução #443; announcement `advertised` (#23) →
  execução #458 também validado.
- **Semântica comprovada na tela:** `peer_established_announce_requested` é
  exibido como confirmação registrada (sem "confirmado no roteador"), e **RIB
  remoto** e **dataplane** aparecem como **"não verificado"**; RTBH é rotulado
  `RECOMMEND_ONLY`/`DRY_RUN` e os candidatos (`REVIEW_REQUIRED`) nunca aparecem
  como mitigação aplicada.
- **Console:** `ERRORS = []` (sem `console.error`, sem exceções) em todas as
  passagens.
- **Erros encontrados e corrigidos nesta validação (somente frontend V2):**
  (1) `mitigation.jsx` lia `focus.item`, mas a navegação entrega `{ kind, id }`
  — o cross-link announcement → execução não abria; agora resolve por id,
  aguarda a lista e, se o id não estiver na amostra, preenche o filtro em vez de
  inventar registro; (2) `bgp.jsx` mantinha os drawers de conector e announcement
  montados ao mesmo tempo — agora são mutuamente exclusivos; (3) o link de
  execução no drawer do announcement dependia de baixar a lista pesada de
  execuções (que oscila em 504) — agora usa o vínculo provado pelo backend
  (`source = automatic_orchestrator` + `source_id`).
- **Magic Patterns (Inpiration):**
  https://www.magicpatterns.com/inspiration/7a3f6bd4-0391-4771-84c4-73dd815edebc
  com as variantes A (Incident Pipeline), B (Dense NOC Console) e C (Split
  Operations). Composição escolhida: **híbrida C+B+A** — arquitetura em páginas
  separadas (C), densidade e readiness por camada (B), pipeline de evidência e
  timeline (A).
- **Endpoints usados (todos GET):** `/api/mitigation/executions`,
  `/api/mitigation/automation/health`, `/api/bgp/summary`,
  `/api/bgp/connectors`, `/api/bgp/connectors/{id}/status`,
  `/api/bgp/announcements`, `/api/bgp/announcements/{id}` (inclui `events`),
  `/api/bgp/response-profiles`, `/api/bgp/port-policies`,
  `/api/bgp/protected-prefixes`, `/api/system/exabgp/status`,
  `/api/rtbh/overview`, `/api/rtbh/providers`, `/api/rtbh/candidates`.
- **Estados reais persistidos** (produção): execuções `blocked` 425 · `active` 6
  · `withdrawn` 13; announcements `advertised` 6 · `expired` 13, com
  `confirmation_level` `peer_established_announce_requested` / `withdrawn`;
  3 conectores `established` (BGP, FlowSpec e pipe `ok`); 17 response profiles;
  42 protected prefixes; 10 port policies; RTBH `REVIEW_REQUIRED` 18 ·
  `DRY_RUN` 1 · política `MANUAL_APPROVAL` · `validation_only=1`.
- **Semântica preservada:** a UI separa solicitado → policy → comando entregue →
  peer established → RIB remoto → dataplane, e marca explicitamente como
  **não verificado** o que não tem endpoint (RIB remoto e efeito no dataplane).
  RTBH nunca aparece como mitigação aplicada (`RECOMMEND_ONLY / DRY-RUN`).
- **Primitivas novas:** `ReadOnlyAction`, `EntityLink`, `Timeline`, `EmptyState`,
  `Pagination`, `KeyValues`, `EvidenceLevel`, `StatusDot`, `stateTone`.
- **Validação read-only (`:8081`):** GETs atravessam o proxy (401 sem token);
  `POST/PUT/DELETE` de `recover-sessions`, `withdraw`, `approve`,
  `check-router`, conector e `/api/mitigation/analyze` retornam **405**;
  `/api/v1/grafana/*` retorna **404**; `POST /api/auth/login` segue como
  exceção (422 sem corpo, alcançando o backend).
- **Estado de produção antes/depois:** `:8080` 200 → 200; :8081 200 → 200; containers inalterados
  (12 do stack `gmj-flow` + preview); ExaBGP PID **2217892** e host-agent PID
  **2217893** idênticos. O único PID que mudou foi o `cat` do wrapper do FIFO
  (`2380273` → `2387704`), recomposição normal do reader após o withdraw real de
  17:09:09 feito **pelo orquestrador de produção** (não pela auditoria).
- **Gaps residuais reais do bloco:** (1) RBAC ainda não aplicado no V2 (dívida
  global — módulos sensíveis continuam acessíveis a qualquer sessão válida);
  (2) `/api/mitigation/executions?limit=400` e
  `/api/dashboard/directional-analytics` apresentaram **504 intermitente**
  (capacidade do backend): a UI trata com `ErrorBox`, sem exceção JS, e o
  cross-link do announcement não depende mais dessa lista pesada;
  (3) tabelas de execuções (400) e announcements (500) usam o teto do backend
  sem paginação (RTBH tem paginação real); (4) readiness do conector usa o
  snapshot persistido — `check-router` é POST e segue bloqueado; (5) `host-agent`
  aparece como evidência do snapshot quando existe, não como consulta ao vivo;
  (6) o announcement #19 já estava `expired/withdrawn` durante a validação, então
  a semântica de `peer_established_announce_requested` foi comprovada num
  anúncio `advertised` (#23).

### BLOCO 1.5 — Alertas (VALIDADO, COMPLETE)

- **Status:** `COMPLETE`. Implementado em `src/alerts.jsx`, buildado, publicado em
  `:8081` e validado em Chrome autenticado.
- **Auditoria focada (produção):** a tela `view-alerts` do `:8080` é uma central
  agregadora com **4 feeds independentes** carregados em paralelo
  (`Promise.all`), cada um com `catch` próprio: `/api/anomalies/active?limit=1000`
  (todas as ativas), `/api/bgp/announcements?limit=500` filtrado por
  `pending_approval · failed · failed_withdraw · peer_down`,
  `/api/mitigation/executions?limit=500` filtrado por `failed · blocked` e
  `/api/collectors/health` filtrado por `atrasado · sem_flow_recente`
  (`/api/collectors/health` só produz `ok · atrasado · sem_flow_recente`).
  Filtros de produção: status (ativos+reconhecidos / somente reconhecidos /
  todos), severidade, fonte e sensor/fonte; ação única **Investigar**
  (anomalia → drawer; BGP → BGP/Conectores; mitigação → Mitigação;
  coletor → Sensores). `/api/anomalies/{id}` é usado pelo drawer de investigação,
  não pelo carregamento da fila.
- **Implementação V2 (paridade + linguagem V2):** KPIs **Críticos · Warnings ·
  Ativos · Reconhecidos · Anomalias ativas · Mitigações com problema ·
  Announcements com atenção · Coletores unhealthy** (cada um com a semântica
  explícita), faixa de **4 chips de feed** com estado e freshness por fonte,
  **fila operacional única** com Severidade · Fonte · Alerta/entidade · Resumo ·
  Sensor/fonte · Status · **Correlação** · Última/Primeira ocorrência · Eventos ·
  Investigar, filtros (status, severidade, fonte, sensor/fonte e busca textual
  sobre a amostra carregada — sem mascarar dados), bloco de **semântica**
  (alerta ativo ≠ tráfego acontecendo; anomalia ≠ ataque confirmado; mitigação
  solicitada ≠ aplicada; policy ≠ announcement confirmado; peer established ≠
  RIB; RIB ≠ dataplane; collector unhealthy ≠ sensor offline) e **ações
  bloqueadas** como `ReadOnlyAction`.
- **Correlação:** apenas por vínculo comprovado — `execution.anomaly_id`,
  `announcement.source = automatic_orchestrator` + `source_id` e
  `announcement.anomaly_id`; sem vínculo, a coluna diz
  "sem vínculo comprovado".
- **Cross-links validados:** Alertas → **Anomalia** (drawer `Anomalia #3614`),
  Alertas → **Mitigação** (drawer `Execução #463`), Alertas → **BGP** via
  correlação (drawer `Announcement #25`) e retorno à fila.
- **Resiliência validada:** com o feed de execuções respondendo **504
  intermitente**, a fila continuou com as demais fontes, o chip da fonte afetada
  marcou indisponível e o erro **não foi convertido em zero**.
- **Sem Magic Patterns:** decisão **NO** — a linguagem V2 já existente
  (KPIs + FilterBar + tabela densa + `EntityLink`/`Badge`/`StatusDot` +
  `ReadOnlyAction`) cobre a tela; créditos não foram gastos por obrigação.
- **Interface/ifIndex:** nenhuma das 4 fontes de Alertas expõe interface de flow
  hoje; quando o resolver único do BLOCO 3 existir, campos de interface vindos de
  flow entram por ele (sem tradução local).
- **Read-only:** revalidado — GETs atravessam (401 sem sessão), escritas
  (`recover-sessions`, `withdraw`, `approve`, `check-router`, `PUT`/`DELETE` de
  conector, `mitigation/analyze`) → **405**, `/api/v1/grafana/*` → **404**.
  Nenhuma exceção nova no nginx.
- **Console:** `ERRORS = []` (sem `console.error`, sem exceções).

## 8. Blocos aprovados (numeração preservada)

| Bloco | Telas |
| --- | --- |
| **JÁ CONCLUÍDO** | Dashboard · Threat Intelligence · Anomalias |
| **BLOCO 1** | Mitigação · BGP / Conectores |
| **BLOCO 1.5** | Alertas |
| **BLOCO 2** | Peak Hunter · Vetores de Ataque |
| **BLOCO 3** | Flows · Sensores · Interfaces |
| **BLOCO 5** | Mapa Global · Clientes / Prefixos |
| **BLOCO 6** | Banco de Dados · Codecs · Sistema |
| **BLOCO 6B** | IA |
| **BLOCO 7** | Configurações / CGNAT · Usuários e Acessos · Minha Conta |

### 8.1 Requisitos funcionais registrados por bloco (NÃO implementados)

> Registrado em 2026-09-25 a partir da revisão operacional. **Nada aqui está
> implementado**: são requisitos a auditar no backend e a entregar nos blocos
> indicados. Status dos blocos e `NEXT` permanecem inalterados.

#### BLOCO 2 — Peak Hunter · Vetores de Ataque

> **STATUS 2026-09-26: R1/R2/R3 FECHADOS (Estratégia C).** Decisão aprovada:
> **não** adicionar cardinalidade ao HAVING, **não** criar vetor novo, **não**
> duplicar `anomaly_event`. A cardinalidade passou a ser **classificação/evidência**
> (`source_details.distribution_evidence`), nunca gate. Backend alterado em
> `backend/app/main.py` (backup `main.py.bak.udp-distribution-evidence.20260926120100`),
> 11 testes novos em `tests/test_udp_inbound_distribution_evidence.py` (11/11 OK),
> suíte completa com **conjunto de falhas idêntico** com e sem o patch (2134 testes —
> zero regressão), imagem reconstruída e **somente** o serviço `backend` recriado.

**R1. Detector de UDP FLOOD por destino / porta — RESOLVIDO POR CLASSIFICAÇÃO ESTRUTURAL**

Simulação histórica read-only (4 dias, janela real de 60s, sample-rate real):
**0 grupos inbound cruzaram os 100k pps**; o mais próximo foi **96.750 pps / ~994 Mbps
por 11 janelas** de uma **única origem**. **2 de 2** anomalias inbound históricas tinham
`unique_src_ips = 1` e **71,4%** dos grupos ≥50k pps eram single-source — por isso um
gate de cardinalidade criaria falso negativo sem cobertura substituta.

- Auditar no backend atual se existe detector equivalente a **UDP flood por
  destino/porta**, com conceito semelhante a `direction = receives`,
  `protocol = UDP` e agrupamento por **destino (/32 ou prefixo protegido) +
  destination_port + protocol**.
- O detector deve ser auditado quanto à capacidade de operar por **/32**,
  **prefixo**, **protected prefix** e **zona de clientes** — **não assumir
  suporte sem verificar no backend**.
- Deve considerar **condições compostas**, por exemplo: `packets_per_second`
  corrigido pelo sample-rate **E** cardinalidade de IPs de origem distintos.
- **Não registrar thresholds fixos como requisito.** Números vistos em
  ferramentas externas são apenas referência conceitual; thresholds reais do
  GMJ-FLOW devem vir do detector existente, de baseline, de configuração ou de
  definição futura baseada em dados reais.
- Evidências desejadas (**somente quando os dados realmente existirem**): PPS ·
  bitrate · packets · bytes · unique source IPs · top source IPs · top source
  ASNs · top conversations · destination port · ingress interfaces · duração ·
  série temporal · packet-size distribution (só se suportado pelos dados reais).

**R2. "Por que disparou?" — trigger e distribuição SEPARADOS (fechado)**

- `POR QUE DISPAROU?` = somente `detection.trigger_condition` (+ `conditions_passed`
  quando a cardinalidade realmente participa do HAVING, caso do vetor de upload
  many-clients). Nos vetores **inbound** a seção tem **apenas PPS**.
- `FORMA DO TRÁFEGO` = `source_details.distribution_evidence`
  (`unique_src_ips_observed`, `attack_shape`, `semantic_threshold = 3`,
  `threshold_role = classification_only`, `used_for_trigger`, `sampling`).
- Anomalias antigas: sem os campos → a UI mostra **"threshold não registrado"**;
  nenhum retropreenchimento.

- Detectores compostos devem expor **cada condição que contribuiu** para o
  trigger, com **condição · threshold · valor observado · relação com o disparo**
  (ex.: `PPS — threshold X — observado Y`, `Unique source IPs — threshold X —
  observado Y`).
- **Não** transformar isso em texto genérico: o operador precisa entender
  imediatamente por que a anomalia foi aberta.

**R3. Semântica obrigatória do detector (fechado)**

- Tráfego UDP alto **sozinho não implica** DDoS distribuído.
- **Cardinalidade de origens é evidência separada** do volume.
- Um **único source muito volumoso** é cenário diferente de **centenas/milhares
  de sources convergindo** para o mesmo destino — o detector deve preservar essa
  distinção.

#### DÍVIDA NOVA (registrada 2026-09-26) — AUDITAR THRESHOLD/BASELINE UDP INBOUND

Tráfego real sustentado de **96.750 pps (~994 Mbps) por 11 janelas consecutivas**
(`45.168.202.6:61810`, sensor `NE8000-F1A-IMPLANTAR` ifIndex 90, 2026-09-25 01:37→01:47 UTC)
ficou **abaixo do threshold de 100k pps** e não gerou anomalia. **Não reduzir o threshold
agora** — auditar threshold/baseline dos vetores UDP inbound com dados históricos.

#### BLOCO 3 — Flows · Sensores · Interfaces

**R4. Resolver ifIndex → interface real (exporter/sensor + ifIndex)**

- Problema atual: na tabela de Flows o operador vê `Interface entrada: 284` /
  `Interface saída: 289`. Esses valores são ifIndex/exporter interface
  identifiers — úteis tecnicamente, mas **não devem ser a informação principal**
  quando o GMJ-FLOW conhece a interface correspondente.
- **Regra de resolução:** usar **a identidade do exporter/sensor JUNTO com o
  ifIndex** — conceitualmente `(exporter/sensor, ifIndex) → interface conhecida`.
  **NUNCA** resolver apenas pelo número global de ifIndex: `Sensor A / ifIndex
  284` pode ser uma interface diferente de `Sensor B / ifIndex 284`.

**R5. Apresentação e fallback seguro**

- Quando houver resolução, mostrar como informação principal o **nome da
  interface** (ex.: `Eth-Trunk1`) e manter o ifIndex como informação técnica
  secundária — em tabela densa, `Eth-Trunk1 · 284`; havendo descrição útil,
  `Eth-Trunk1` + `TRANSITO-SEABORN` + `ifIndex 284`.
- **Fallback:** se a interface **não puder ser resolvida**, mostrar o **ifIndex
  cru** (`ifIndex 284`). **Não inventar nome** e **não esconder o valor cru**.
- Aplicar a mesma lógica a **input_ifindex/ingress** e
  **output_ifindex/egress**, mantendo o sentido **relativo ao exporter** que
  gerou o flow. **Não** interpretar automaticamente "entrada = Internet" e
  "saída = cliente" (ou o inverso): quem define isso é a topologia/rota.

**R6. Resolver reutilizável (componente único)**

- O mesmo resolver deve ser reutilizado em **Flows · Anomalias · Alertas ·
  drawers de investigação · Peak Hunter (quando aplicável)** e em qualquer tela
  que mostre interface oriunda de flow.
- Evitar traduções diferentes por tela (mesmo problema resolvido uma única vez).

**R7. Paridade funcional da tela Flows (GAP confirmado visualmente)**

- **Estado atual do V2:** a tela Flows entrega apenas Top flows/conversações
  (bits/s, packets/s, bytes, flows, participação %, último registro) e **perdeu a
  capacidade de investigação/pesquisa** que existe no `:8080`. Isso é **gap de
  paridade**: Flows **não pode ser marcado `COMPLETE`** enquanto existir somente
  Top Conversations.
- **A produção tem dois modos** que precisam continuar existindo: **REGISTROS DE
  FLOW** (busca detalhada com filtros reais) e **TOP FLOW** (agregações/rankings).
  Preservar a distinção — **não misturar os dois conceitos numa única tabela**;
  o V2 pode usar tabs ou outra composição validada visualmente.
- **Busca de Registros de Flow — auditar os endpoints reais e reproduzir apenas
  os filtros que o backend suporta** (não inventar): SRC IP/CIDR, DST IP/CIDR,
  SRC porta, DST porta, protocolo, número de protocolo, decoder, sensor,
  interface, período e limite, com Buscar e Limpar. Confirmar especialmente
  **IP exato, CIDR, origem, destino, portas, ranges de portas, protocolo, número
  de protocolo, sensor/exporter, interface, período e limite**. A pesquisa deve
  consultar os registros reais: **não** implementar filtragem client-side sobre
  amostra limitada quando o backend já oferece busca server-side.
- **Colunas da tabela de resultados (produção):** horário · sensor · exporter ·
  IP origem · porta origem · IP destino · porta destino · protocolo · TCP flags ·
  interface entrada · interface saída · bytes · pacotes · flows · taxa.
- **CSV / PDF:** auditar como a exportação funciona hoje (método HTTP e efeito
  colateral antes de liberar). Exportações puramente de leitura podem ser
  consideradas, mas **sem abrir exceção nova no nginx automaticamente** — o gap
  fica registrado mesmo que a exportação continue indisponível no início.
- **Taxa:** a produção já apresenta registros como
  `"Taxa indisponível: flow_raw não possui duração"`. Portanto: **não calcular
  taxa artificialmente**, **não inferir duração inexistente** e mostrar
  explicitamente a indisponibilidade; usar bits/s ou packets/s apenas quando
  derivados de dados válidos.
- **Interface nos registros de flow:** aplicar **R4/R5/R6** (nome como informação
  principal, `ifIndex` como evidência, fallback seguro) e manter o sentido
  relativo ao **exporter** — nunca assumir "entrada = Internet / saída = cliente".
- **Cross-links futuros com investigação:** registrar a dependência
  `Anomalia → flows relacionados → pesquisa em Flows`,
  `Peak Hunter → flow/conversação → pesquisa em Flows`,
  `Alertas → entidade → flow quando aplicável` e `Flows → Sensor → Interface`,
  permitindo abrir Flows **com filtros já preenchidos** (ex.: anomalia
  `179.189.82.245 UDP dst-port 27901` → "Abrir em Flows" com src/dst conforme a
  evidência real, protocolo UDP, porta 27901 e a janela temporal
  correspondente). **Não implementar essa navegação agora.**
- **UX V2 (estudar no BLOCO 3):** `[ Registros de Flow ] [ Top Flow ]` —
  em Registros: FilterBar densa, filtros avançados recolhíveis, tabela
  operacional, paginação/limite, links de IP, interface resolvida e drawer de
  flow quando fizer sentido; em Top Flow: conversations, source IP, destination
  IP, portas, protocolos, interfaces e demais rankings **realmente existentes**.
  A função principal de Flows também é **investigação** — não transformar a tela
  apenas em um dashboard de rankings.

#### Dependência entre os requisitos

```
UDP flood → flows → sensor/exporter → ingress interface → interface resolvida
```

O detector do BLOCO 2 só consegue evidência de interface de qualidade se o
resolver do BLOCO 3 existir — o que reforça o agrupamento já definido
(Peak Hunter/Vetores e Flows/Sensores/Interfaces).

---

## 9. Matriz mestre de migração

Colunas: Tela · Status · Paridade · Endpoints leitura · Endpoints mutáveis ·
Drawers · Dependências · Magic · Backend suficiente · Complexidade · Risco ·
Bloco · Gaps · Última validação.

| Tela | Status | Paridade | Leitura | Mutáveis | Drawers | Dependências | Magic | Backend | Compl. | Risco | Bloco | Gaps | Última validação |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Dashboard | COMPLETE | ~60% | 14 | 4 | 4 | Clientes/Prefixos, Sensores | OPTIONAL | Sim (Grafana bloqueado) | HIGH | MEDIUM | JÁ CONCLUÍDO | Dashboards configuráveis, geo map, export Grafana, drilldowns, time range | Auditoria 2026-09-25 (estática + build publicado :8081) |
| Threat Intelligence | COMPLETE | ~70% | 13 | 6 | 3 | Anomalias, Eventos, Alertas | — | Sim | HIGH | HIGH | JÁ CONCLUÍDO | Ações de investigação, campanhas/decisões detalhadas | Auditoria 2026-09-25 (estática + build publicado :8081) |
| Anomalias | COMPLETE | ~75% | 10 | 7 | 2 | Mitigação, BGP, TI, Flows | — | Sim | HIGH | HIGH | JÁ CONCLUÍDO | Ações ack/close/mitigação, feedback, detalhe legado | Chrome + ErrorBoundary (read-only validado) |
| Flows | PARTIAL | ~20% | 5 | 0 | 2 | Sensores, Interfaces | YES | Sim | HIGH | MEDIUM | BLOCO 3 | **R7 (ver 8.1): paridade de busca de Registros de Flow + separação Registros/Top Flow + filtros server-side + CSV/PDF a auditar + taxa sem duração; não marcar COMPLETE com apenas Top Conversations** · **R4/R5/R6: interface resolvida por exporter+ifIndex com ifIndex secundário** | Auditoria 2026-09-25 + gap de paridade confirmado no Chrome (2026-09-25) |
| Sensores | PARTIAL | ~25% | 5 | 2 | 3 | Interfaces | OPTIONAL | Sim | MEDIUM | MEDIUM | BLOCO 3 | Edição, SNMP, sample-rate, traffic learning · **R6 (ver 8.1): fornecer a identidade exporter/sensor usada pelo resolver** | Auditoria 2026-09-25 |
| Interfaces | MISSING | 0% | 3 | 3 | 3 | Sensores, Flows | YES | Sim | HIGH | MEDIUM | BLOCO 3 | Tela + drawer Overview/Traffic · **R4/R5/R6 (ver 8.1): fonte da resolução `(exporter/sensor, ifIndex)` e do fallback seguro** | Auditoria 2026-09-25 |
| Peak Hunter | **PARTIAL** (validação Chrome OK; depende de evento novo) | ~55% | 11 | 6 | 1 | Sensores, Interfaces, Vetores | YES | Sim | HIGH | MEDIUM | BLOCO 2 | Validado em Chrome autenticado (2026-09-26): 4 abas, loading, empty states legítimos (0 picos/0 análises), automação com job real, 4 sensores + 114 interfaces (GET 3,0 s / 6,7 s), sem erro JS · **GAP R2**: `POR QUE DISPAROU?`/`FORMA DO TRÁFEGO` só terão conteúdo quando existir anomalia UDP legacy criada APÓS o deploy (hoje: 0 anomalias com `distribution_evidence`) · latência longa de `options/*` | Chrome autenticado 2026-09-26 (`windowErrors = []`) — pendente evento pós-deploy |
| Vetores de Ataque | **PARTIAL** (validação Chrome OK; depende de evento novo) | ~60% | 8 | 9 | 1 | Peak Hunter, Detection, Clientes/Prefixos | YES | Sim | HIGH | MEDIUM | BLOCO 2 | Validado em Chrome autenticado (2026-09-26): 16 vetores, 14 regras do template #1, 6 presets, templates, whitelist, scheduler e drawer do vetor #8 com direção/HAVING textual (`cardinalidade NAO participa`)/mitigação configurada/ações bloqueadas · **GAP R2** compartilhado com o Peak Hunter (aguarda evento UDP legacy pós-deploy) | Chrome autenticado 2026-09-26 (`windowErrors = []`) |
| Alertas | COMPLETE | 0% (auditoria) | 5 | 0 | 0 (reuso de cross-links) | Anomalias, BGP, Mitigação, TI | NO | Sim | LOW | LOW | BLOCO 1.5 | Fila única agregando 4 fontes com KPIs, filtros, correlação por vínculo real e cross-links; gaps: feed BGP vazio quando não há announcement em atenção e coletores sem item unhealthy; `status=active` esconde mitigação `blocked` (mesma semântica da produção) | Chrome autenticado 2026-09-25 (`ERRORS = []`, read-only 405/404 revalidado) |
| Mitigação | COMPLETE | ~25% (auditoria) | 13 | 5 | 2 | BGP/Conectores, Anomalias, RTBH, IA | YES | Sim | HIGH | HIGH | BLOCO 1 | Gaps residuais: RBAC no V2; 504 intermitente do backend em endpoints pesados; sem paginação em execuções | Chrome autenticado 2026-09-25 (abas, filtros, drawers, cross-links, `ERRORS = []`) |
| BGP / Conectores | COMPLETE | ~20% (auditoria) | 3 | 15 | 2 | Mitigação, Anomalias | YES | Sim | HIGH | HIGH | BLOCO 1 | Gaps residuais: readiness vem do snapshot (check-router é POST bloqueado); host-agent só como evidência; sem paginação em announcements | Chrome autenticado 2026-09-25 (overview/readiness, conectores, announcements, drawers, cross-links, `ERRORS = []`) |
| Mapa Global | MISSING | 0% | 4 | 0 | 2 (reuso) | Sensores, Clientes/Prefixos, Dashboard | YES | Sim | HIGH | HIGH | BLOCO 5 | Leaflet + ranking geográfico | Auditoria 2026-09-25 |
| Clientes / Prefixos | MISSING | 0% | 12 | 5 | 1 | Dashboard, Detection, BGP | OPTIONAL | Sim | MEDIUM | MEDIUM | BLOCO 5 | Zonas, assets/services, whitelist | Auditoria 2026-09-25 |
| Banco de Dados | MISSING | 0% | 4 | 1 | 0 | Sistema | NO | Sim | LOW | LOW | BLOCO 6 | Tabelas, operações ClickHouse, disk-guard | Auditoria 2026-09-25 |
| Codecs | MISSING | 0% | 2 | 4 | 2 | Flows, Sensores | OPTIONAL | Sim | MEDIUM | MEDIUM | BLOCO 6 | Editor e tester de codec | Auditoria 2026-09-25 |
| IA | MISSING | 0% | 11 | 13 | 7 painéis | Sistema, Anomalias, TI | YES | Sim | HIGH | HIGH | BLOCO 6B | Providers/models/prompts/rotas/histórico | Auditoria 2026-09-25 |
| Sistema | MISSING | 0% | 5 | 1 | 0 | Todos | NO | Sim | LOW | LOW | BLOCO 6 | Recursos, containers, setup, cache | Auditoria 2026-09-25 |
| Configurações / CGNAT | MISSING | 0% | 6 | 7 | 0 | BGP, Prefixos | OPTIONAL | Sim | MEDIUM | HIGH | BLOCO 7 | Pools, importações e ciclo de vida | Auditoria 2026-09-25 |
| Usuários e Acessos | MISSING | 0% | 3 | 9 | 2 | Auth/Roles (global) | NO | Sim | MEDIUM | HIGH | BLOCO 7 | CRUD, sessões, auditoria de usuários | Auditoria 2026-09-25 |
| Minha Conta | MISSING | 0% | 2 | 2 | 0 | Auth | NO | Sim | LOW | MEDIUM | BLOCO 7 | Sessões, troca de senha | Auditoria 2026-09-25 |
| placeholder | NOT_APPLICABLE | — | — | — | — | — | — | — | — | — | — | View genérica para módulos não implementados | Auditoria 2026-09-25 |

> Notas metodológicas (para não gerar número divergente no futuro):
> - **Leitura/Mutáveis** são os endpoints referenciados pelo frontend de
>   produção no módulo da tela (análise estática de loaders/handlers); “Mutáveis”
>   conta endpoints que **têm** verbo de escrita no backend, mesmo quando o V2
>   usa apenas GET.
> - **Paridade** é estimativa técnica de cobertura funcional, não ranking visual.
> - **Drawers** conta containers relevantes; a maioria é global (fora das
>   sections) e é aberta por JS.

---

## 10. NEXT

> **ESTADO CONSOLIDADO (2026-09-27)**
> `BLOCO 3 = CLOSED` · `Flows = COMPLETE` · `Interfaces = COMPLETE` · `Sensores = COMPLETE` ·
> `R4/R5/R6/R7 = COMPLETE` · `BLOCO 2 = PARTIAL` (pendente: evidência real de anomalia UDP
> legacy criada após o deploy do enriquecimento `distribution_evidence`).
> **TECH DEBT: `PERF-01 /api/flows/top`** — ~7 s na medição atual (já visto ~28,7 s);
> exige comparação antigo×novo com prova de equivalência
> (dimensions, bytes, packets, flows, bits_s, packets_s, duration, percent_total,
> sample-rate aplicado, ordenação/top N). **Não é condição para fechar o BLOCO 3.**
> **NEXT FUNCIONAL = BLOCO 5** (Mapa Global + Clientes/Prefixos) — **não iniciado**.

```
NEXT = BLOCO 3
FLOWS + SENSORES + INTERFACES
Status: BLOCO 2 **implementado e validado em Chrome autenticado**, mas mantido
**PARTIAL** por um único gap de evidência (não de código): as seções
`POR QUE DISPAROU?` e `FORMA DO TRÁFEGO` do drawer de Anomalias já existem e
mostram o estado honesto `threshold não registrado` / `forma não registrada`
para as anomalias anteriores ao deploy — a validação com dado real (cardinalidade
no trigger em `UDP_UPLOAD_MANY_CLIENTS_SAME_DST_PORT` e `single-source` no
inbound) depende de uma **nova** anomalia UDP legacy criada após 2026-09-26 12:10.
Hoje: **0 anomalias** com `distribution_evidence`; as 4 anomalias-alvo
(#193, #195, #3575, #3125) têm `source_details_json` apenas com as 3 chaves
legadas. BLOCO 3 permanece **não iniciado** por decisão desta tarefa.
```

> **BLOCO 2 fechado em 2026-09-26**: backend enriquecido (Estratégia C — trigger PPS-only
> + `distribution_evidence` classification-only, sem gate e sem vetor novo), 11 testes
> dedicados verdes e suíte completa sem regressão (conjunto de falhas idêntico),
> Magic Patterns com 3 variantes, Peak Hunter e Vetores de Ataque publicados em `:8081`
> com a barreira read-only revalidada (POST/PUT/DELETE → 405). Pendência: **validação
> funcional em Chrome autenticado** (sessão CDP indisponível nesta janela).

**Objetivo funcional do BLOCO 1 (referência, já implementado):**

```
Anomalia → Policy Decision → Mitigation Execution → Announcement → Connector → BGP State
```

**Escopo do BLOCO 1.5 (Alertas)** — não iniciar sem nova autorização:

- Alertas agrega `/api/anomalies/active`, `/api/bgp/announcements`,
  `/api/mitigation/executions` e `/api/collectors/health`.
- Nenhuma ação mutável; a tela deve manter os mesmos níveis de evidência.

---

## 11. Histórico do documento

| Data | Alteração |
| --- | --- |
| 2026-09-25 | Criado a partir da auditoria global (21 views, 20 drawers, 247 referências de endpoint). Nenhuma tela implementada. |
| 2026-09-25 | BLOCO 1 (Mitigação + BGP/Conectores): auditoria funcional com payload real, Inspiration no Magic Patterns, implementação read-only, build e publicação em `:8081`, validação da política read-only e do estado de `:8080`. Validação funcional em Chrome **pendente de credencial** (base real tem 1 usuário: `admin`). |
| 2026-09-25 | BLOCO 1 **fechado**: validação funcional autenticada em Chrome (Dashboard, TI, Anomalias, Mitigação e BGP/Conectores), cadeia real 3569 → 443 → 19 → conector 4 nos dois sentidos, `ERRORS = []`, read-only revalidado (405/404) e produção inalterada (ExaBGP 2217892, host-agent 2217893). 3 defeitos de frontend corrigidos (foco do cross-link, drawers sobrepostos, link por `source_id`). Mitigação e BGP/Conectores → `COMPLETE`; NEXT = BLOCO 1.5 — ALERTAS. |
| 2026-09-25 | Planejamento: registrados em **8.1** os requisitos **R1–R3 (BLOCO 2: detector UDP flood por destino/porta, condições compostas e "por que disparou")** e **R4–R6 (BLOCO 3: resolver `(exporter/sensor, ifIndex) → interface`, apresentação com fallback seguro e resolver reutilizável)**, incluindo a dependência `UDP flood → flows → sensor/exporter → ingress interface`. Apenas documentação — nenhum código, build ou deploy. Status dos blocos e `NEXT` inalterados. |
| 2026-09-25 | Planejamento: registrado o requisito **R7 (BLOCO 3 — paridade funcional da tela Flows)**: busca de Registros de Flow com filtros server-side, separação Registros/Top Flow, CSV/PDF a auditar, taxa sem duração explícita e cross-links futuros com investigação; Flows **não pode** ser marcado `COMPLETE` só com Top Conversations. Apenas documentação. |
| 2026-09-25 | BLOCO 1.5 **fechado**: tela **Alertas** implementada (`src/alerts.jsx`), publicada em `:8081` (`index-C8r88ava.js`) e validada em Chrome autenticado — 4 feeds independentes (anomalias 7 · BGP 25 · mitigações 463 · coletores 4), 8 KPIs, fila única com 446 linhas em `status=Todos`, filtros e cross-links reais (Anomalia #3614, Execução #463, Announcement #25), `ERRORS = []`, read-only revalidado (405/404) e produção inalterada (ExaBGP 2217892, host-agent 2217893). Alertas → `COMPLETE`; `NEXT = BLOCO 2 — PEAK HUNTER + VETORES DE ATAQUE`. |
| 2026-09-26 | **BLOCO 2 fechado (Estratégia C)**. (1) Auditoria read-only do detector UDP inbound com simulação histórica de 4 dias (janela real de 60s, sample-rate real): 0 grupos ≥100k pps, pico de 96.750 pps (~994 Mbps) por 11 janelas de origem única; 2/2 anomalias inbound históricas com `unique_src_ips = 1`; 71,4% dos grupos ≥50k pps single-source — decisão: **não** usar cardinalidade como gate. (2) Backend `backend/app/main.py` alterado para persistir `detection.trigger_condition` (PPS-only nos vetores inbound) + `distribution_evidence` (`attack_shape` reutilizando `attack_shape_from_samples`, `semantic_threshold = 3`, `threshold_role = classification_only`, `used_for_trigger`, `sampling`); refactor `attack_shape_from_counts`; sem migration, sem endpoint novo, sem vetor novo, sem alteração de query/HAVING/severidade/mitigação. (3) 11 testes novos (11/11 OK) e suíte completa (2134 testes) com conjunto de falhas **idêntico** com e sem o patch. (4) Imagem do backend reconstruída e **apenas** o serviço `backend` recriado; ExaBGP 2217892 e host-agent 2217893 inalterados; demais containers intactos. (5) Magic Patterns: 3 variantes (A Peak Investigation Workbench, B Detection Engineering Console, C Split Investigation + Engineering) → https://www.magicpatterns.com/inspiration/b152df24-8b94-4c66-acc3-7e8dc80b6c32 . (6) Frontend V2: `src/peak.jsx` (novo), `src/vectors.jsx` (novo) e duas seções semânticas no drawer de Anomalias ("Por que disparou?" e "Forma do tráfego"), publicados em `:8081` (`index-Dg6GnPz9.js`), read-only revalidado (405/404). Dívida registrada: **auditar threshold/baseline dos vetores UDP inbound**. `NEXT = BLOCO 3`. |
| 2026-09-26 | **Validação funcional autenticada do BLOCO 2 (Chrome/Edge via CDP 127.0.0.1:9222)**. Regressão 6/6 OK sem `ErrorBox` (Dashboard, TI, Anomalias, Alertas, Mitigação, BGP/Conectores). Peak Hunter: 4 abas OK (empty states legítimos; automação com o job real `Default NE8000 dataset collector`; `/options/sensors` 4 itens em 3,0 s e `/options/interfaces` 114 itens em 6,7 s). Vetores: 16 vetores, 14 regras do template #1, 6 presets, whitelist e drawer do vetor #8 com direção, HAVING textual (`cardinalidade NAO participa`), mitigação configurada e ações bloqueadas. Drawer de Anomalias: seções novas renderizam com o estado honesto `threshold não registrado` / `forma do tráfego não registrada` (anomalia antiga) e as seções 6/7/8 (TI, mitigação/BGP, timeline) seguem intactas — `mitigation_basis`/`reason`/perfil/anúncio/conector inalterados na apresentação. Console: `windowErrors = []`, nenhum `console.error` de aplicação, nenhum pageerror; apenas 1 log de recurso 401. Read-only revalidado (POST/PUT/DELETE → 405; grafana → 404). **GAP R2 registrado**: nenhuma anomalia UDP legacy pós-deploy existe ainda (0 com `distribution_evidence`), então a validação de cardinalidade-como-trigger (#3575/#3125) e de single-source inbound (#193) com dado real fica pendente — **não é bug de montagem de tabela**. Peak Hunter e Vetores mantidos **PARTIAL**; BLOCO 3 **não iniciado**. Produção inalterada: `:8080` 200, `:8081` 200, ExaBGP 2217892, host-agent 2217893. |
| 2026-09-26 | **BLOCO 3 — FASE 1 (backend) implementada, testada, medida e publicada.** `backend/app/main.py` (backup `main.py.bak.block3-interfaces.20260926170409`): (1) `GET /api/sensors?include_interfaces=false` (modo leve; default preserva `sensor.interfaces`, que tem consumidor real em `:8080`); (2) cache de 45 s por sensor em `sensor_sample_rate_config_cached` — elimina o fan-out O(N²) de `enrich_interface_metrics` (476 releituras de inventário) e é invalidado em `update_sensor`; (3) `GET /api/sensors/{id}/interfaces` com `monitor=all\|enabled`, `q`, `limit`, `offset` (default preservado); (4) **novo** `GET /api/interfaces` paginado server-side (`sensor_id`, `sensor_name`, `exporter_ip`, `monitor`, `q`, `sample_rate_override`, `enrich`, `limit`, `offset`) com `source: inventory`, `identity_key = [exporter_ip, if_index]`; (5) resolver em lote `interface_name_map_for_exporters` + `enrich_flow_rows_with_interfaces` — aditivo em `/api/flows/search` (`input_if_name/alias/descr`, `input_interface_key/source`, idem output) **preservando `input_if`/`output_if` crus**. Testes: `tests/test_block3_interfaces.py` **9/9 OK**; regressão comparada (com × sem patch) com **conjunto de falhas idêntico** → zero regressão. Bench in-process (cópia read-only do banco real): `/api/sensors` fan-out **424 ms → 104 ms**, modo leve **0 ms**, `/api/interfaces?limit=100` **5 ms** (238 no inventário), resolver em lote **5 ms**, sample-rate 20 leituras **114 ms → 5,6 ms**, `179.189.80.0 ifIndex 141 output = 761` preservado, overrides 138/140/225/258 = 908/1009/947/961, colisão `138` provada (`LINk_AMT_REAL` × `LINK_IP_FALCONNET`). Backend reconstruído e **somente** o serviço `backend` recriado; ExaBGP 2217892 e host-agent 2217893 inalterados. **FASE 2 (telas Flows/Interfaces/Sensores), validação Chrome e fechamento da matriz ficam pendentes** (sessão CDP caiu durante a rodada; benchmark HTTP "depois" não realizado). |
| 2026-09-26 | **BLOCO 3 — FASE 2 (parcial): Interfaces e Sensores validados; Flows pendente.** Implementados `src/interface-ref.jsx` (primitive reutilizável, chave `(exporter_ip, ifIndex)`, inventory > observed, fallback `ifIndex N`), `src/flows.jsx` (tabs Registros/Top Flow, busca server-side com todos os filtros, tabela densa, CSV/PDF por GET, handoff Top→Registros), `src/interfaces.jsx` (Dense Inventory paginado por `/api/interfaces`) e `src/sensors.jsx` (master/detail leve com `include_interfaces=false`), ligados em `main.jsx` (+ item de nav Interfaces) e publicados em `:8081` (`index-Bf2cuO25.js`, CSS `index-_i9-m-G3.css`). **Benchmark HTTP (depois):** `/api/sensors` **9.610 ms / 164 KB** × `?include_interfaces=false` **63 ms / 4 KB**; `/api/interfaces?limit=100` **68 ms** (238 no total); `/api/flows/search` **1.398 ms**; `/api/flows/top` **7.221 ms** (não otimizado — gap registrado; a meta de comparação antigo×novo não foi executada). **Exports:** CSV 200 `text/csv` 14 KB e PDF 200 `application/pdf` 9 KB — ambos por GET. **Caso obrigatório provado:** ifIndex 138 em `179.189.80.0` = **LINk_AMT_REAL** (override 908/708) × em `45.163.144.1` = **LINK_IP_FALCONNET** (1000/1000) — `diferentes = true`; monitor `enabled=54` / `all=238`; sensor 3 = 192 cadastradas. **Chrome:** regressão 8/8 sem erro; **Interfaces** (100 linhas, aviso de colisão de ifIndex, filtro por exporter → 6 linhas) e **Sensores** (4 no master, modo leve, detalhe com cadastradas/monitoradas e 6 interfaces) renderizando corretamente; **Flows não renderizou no teste automatizado** (0 linhas, sem as tabs, **sem erro de render e com console vazio**) → permanece **PARTIAL** e exige diagnóstico na próxima rodada. `console = []` e `windowErrors = []`. Backend não foi recriado nesta fase (nenhuma alteração de backend foi feita). |
| 2026-09-27 | **BLOCO 3 FECHADO — Flows / Sensores / Interfaces COMPLETE (R4–R7 entregues).** Investigação do "Flows não renderiza": **não havia bug de código**. Prova direta via CDP: ao clicar em Flows o componente **monta** (`h1 = Flows`, tabs `["Registros de Flow","Top Flow"]`), a busca **dispara** (`/api/flows/search?...&limit=200` → 200 em **2.139 ms / 255 KB**), o `loading` **sai** e a tabela densa renderiza (**200 linhas**, `Taxa indisponível` presente, interface resolvida). A falha anterior era do **instrumento de medição** (espera de 4 s para uma resposta de 2,1 s/255 KB e verificação de texto antes do paint). **Nenhuma alteração de código foi necessária** — nenhum arquivo/linha foi corrigido. Validação Chrome final: Registros **200 linhas**, filtro server-side por DST port **200→158**, `InterfaceRef` resolvida e fallback cru preservado, exports **CSV 200 `text/csv` 14 KB** e **PDF 200 `application/pdf` 18 KB** (GET), Top Flow **10 linhas** com `Investigar`, handoff **OK** (marcou "Handoff do Top Flow", voltou para Registros com o filtro `dst_ip` comprovado pela linha). Regressão **10/10** (Dashboard, TI, Anomalias, Alertas, Mitigação, BGP, Peak Hunter, Vetores, Interfaces, Sensores) sem erro e sem tela vazia. Interfaces: `179.189.80.0|138 = LINk_AMT_REAL` × `45.163.144.1|138 = LINK_IP_FALCONNET`; monitor `enabled=54` / `all=238`; sensor 3 `=192`. Sensores: **4** no master, modo leve. `console = []` e `windowErrors = []`. Read-only revalidado: `POST /api/attack-vectors`, `PUT/DELETE /api/sensors/1`, `POST /api/sensors/1/snmp/poll` → **405**; Grafana → **404**; `GET /api/interfaces` → 401 (exige auth). Produção: `:8080` 200, `:8081` 200, containers intactos, **ExaBGP 2217892**, **host-agent 2217893**. **PERFORMANCE DEBT registrado (tarefa separada):** `/api/flows/top` ~7 s na medição atual (já visto ~28,7 s) — a otimização exige comparação antigo×novo com prova de equivalência e **não** condiciona este fechamento. `NEXT = BLOCO 5` (não iniciado). |
> **PERF-01 /api/flows/top = RESOLVED (2026-09-27).** Otimização publicada com prova de
> equivalência. Patch mínimo em `backend/app/main.py`, função interna `final_top_query`
> (usada por `top_flows` nas linhas 50008/50143): o CTE `totals` + `CROSS JOIN totals` foi
> substituído por **window aggregation** (`if(sum(bytes) OVER () > 0, bytes / sum(bytes) OVER () * 100, 0)`
> para `percent_total`). **Nada mais foi alterado** — em especial `clickhouse_sample_rate_expr`
> (matemática intacta), `bytes`, `packets`, `flows`, `bits_s`, `packets_s`, `duration_seconds`,
> ordenação e Top N. As outras duas ocorrências de `CROSS JOIN totals` no arquivo pertencem a
> `top_conversations_payload` e `dashboard_top_syn` (Dashboard) e **não foram tocadas**.
> **Prova OLD × NEW:** 16 casos (2 janelas absolutas fixas × src_ip, dst_ip, conversation, proto,
> dst_port + sensor conhecido, filtro de protocolo, filtro de porta) → **16/16 PASS**
> (mesmas linhas, mesma ordem, **zero** diferenças em bytes/packets/flows, `max_rel_diff ≤ 1e-9`),
> executados no mesmo ClickHouse (`--database flowdb`), melhores tempos de 2 execuções por variante:
> **OLD 1,29–8,44 s → NEW 1,05–4,66 s**, speedup **1,14×–1,95×** (mediana ≈ **1,66×**).
> **Sample-rate preservado:** o `multiIf` de configuração real permanece por linha e o caso
> obrigatório `179.189.80.0 / ifIndex 141 / output → 761` continua presente na expressão gerada.
> Deploy: `docker compose build backend` + `up -d --no-deps backend` (sem `--remove-orphans`);
> backup `main.py.bak.perf01-flows-top.20260927213444`; health 200; `:8080` 200; `:8081` 200;
> containers intactos; **ExaBGP 2217892** e **host-agent 2217893**. Regressão focada comparada
> (com × sem patch): conjunto de falhas **idêntico** (só o tempo difere) → sem regressão.
> **Pendência de registro:** medição HTTP autenticada do endpoint após o deploy (a evidência de
> equivalência/ganho é a da própria query que o endpoint executa, confirmada em `final_top_query`).
> `BLOCO 3`/`Flows`/`Interfaces`/`Sensores`/`R4–R7` **permanecem inalterados (COMPLETE/CLOSED)**;
> `BLOCO 2` permanece **PARTIAL**; **NEXT = BLOCO 5** (não iniciado).
> **BLOCO 5 — FASE 1 (AUDITORIA) — 2026-09-28.** Nada implementado. Achados com
> evidência de código/endpoint/dado real:
> • **Mapa Global ≠ topologia.** A tela `view-global-map` do `:8080` é **geográfica**
>   (Leaflet: `L.map(`, `tileLayer`) e **operacional**: filtros de período, fluxos/anomalias,
>   sensores/interfaces, **"Grupo de Prefixos / Cliente"**, direção (Saindo/Entrando/Envolvendo/
>   Bidirecional/Download/Upload), protocolo, métrica (bits/s, packets/s, flows), **Cidade/País**,
>   IP/CIDR e Top 10/20. Fonte: **`/api/geo/flows`** (group_by=`city|country|asn|ip`,
>   filtros `sensor_id/interface_id/if_index/direction/protocol/decoder/asn_src|dst/src|dst_ip|cidr/
>   portas/zone_id/zone_direction/prefix_*` + multi-seleção `sensor_ids/interface_ids/protocols/services`),
>   **`/api/geo/anomalies`**, `/api/geo/status` e rankings `/api/tops/*` + `/api/asn/*`.
>   No payload, cada item é uma **rota geográfica** (`src`/`dst` = `city:Porto Alegre, BR:BR:-30.0273,-51.2353`,
>   rótulos, IPs, cidade/região/país/lat/lon) — **nó = cidade (ou país/ASN/IP) e link = fluxo origem→destino
>   agregado na janela**; não são equipamentos, sensores nem interfaces.
> • **PERFORMANCE CRÍTICA (bloqueia portar o mapa como está):** `/api/geo/flows?group_by=city` **39,4 s**;
>   `country` 12,0 s; **`asn` e `ip` → 504 em 60 s**; `zone_id=7` → **504**; `/api/tops/asn-src|dst` **~16,5 s**;
>   `geo/status` 3,4 s; **`/api/ip-zones/{id}/flow-coverage` → 504 em 60 s**; `prefix_enabled=true&prefix_id=5` → **400**.
>   Rápidos: `geo/anomalies` 0,5 s (0 itens), `ip-zones` 0,83 s (6), `ip-zones/{id}/prefixes` 0,26 s (9),
>   `cgnat/pools` 0,15 s (6), `cgnat/mappings` 0,17 s, `cgnat/config` 0,16 s, `asn/status` 0,61 s,
>   `network-assets` 4,1 s (10).
> • **Dois modelos de prefixo:** (a) **vivo/operacional** = `ip_zones` (6: JETFIBRA, FIBINET, FTI,
>   ACM TELECOM, GM-TELECOM, IMPLANTAR) + `ip_zone_prefixes` (18; 13 `client` + 5 `public_cgnat`;
>   16 IPv4 + 2 IPv6) — é o que alimenta detecção (`detection_template_id`), mitigação
>   (`connector_id`), CGNAT (`subscriber_addressing_mode`) e o filtro de prefixo do mapa;
>   (b) **`prefixes`** (com `customer_id`, `group_id`, `zone_id`, `address_family`) → **0 linhas**
>   e `/api/prefixes` devolve `items: []` ⇒ a tela de Clientes/Prefixos **nunca foi usada** em produção.
> • **"Cliente" = zona.** Não existe entidade `customer`; o cliente é a `ip_zones.name`
>   (opcionalmente com conector BGP e modo de endereçamento CGNAT). Prefixo pode existir sem cliente
>   (CIDR avulso em `network_assets`) e o mesmo cliente pode ter N prefixos (IMPLANTAR: 10).
> • **ASN/geo:** `asn_prefixes` (1000; 985 v4 + 15 v6; fonte `cymru-lacnic`) sustenta `group_by=asn`,
>   `/api/tops/asn-*` e `/api/asn/*`. **CGNAT:** `cgnat_pools` 6 + `cgnat_port_mappings` **14.334**
>   (public_ip ↔ private_ip por faixa de portas, protoclo, device A10/Mikrotik; `subscriber_*` nulos)
>   — confirma a regra "IP público CGNAT ≠ assinante". **Protegidos:** `bgp_protected_prefixes` 42
>   (`block_rtbh/block_flowspec/protection_level`). **Baseline:** `prefix_behavior_baselines`
>   com **19.260.096 linhas**.
> • **Preview V2:** **Mapa Global, Clientes e Prefixos = AUSENTES** (não há módulo; prefixo/zona
>   aparecem só como contexto em Anomalias, Mitigação e no mapa do Threat Intelligence).
> • Baseline de produção inalterado: branch `sync/windows-network-context-20260902`, HEAD `379227e`,
>   `:8080` 200, `:8081` 200, health 200, 13 containers, **ExaBGP 2217892**, **host-agent 2217893**.
> `BLOCO 3`/`PERF-01`/`BLOCO 2` **não foram alterados**. Nenhum status marcado COMPLETE nesta rodada.
> **PERF/GAP-01 (GEO + COBERTURA DE ZONAS) — 2026-09-28 — OPEN (sem patch publicado).**
> Causas comprovadas por código + SQL real capturada + EXPLAIN + medição em **janela absoluta fixa**
> (`2026-09-25 12:00→13:00 UTC`):
> • **`city`, `country`, `asn` e `ip` geram a MESMA SQL** (3.196 bytes, `limit=500`): o `group_by` é
>   aplicado **em Python**, no ClickHouse a agregação é sempre por `(src_ip, dst_ip, src_asn, dst_asn, top_protocol)`.
>   Logo, a diferença 39 s (city) × 12 s (country) × 504 (asn/ip) **não é trabalho diferente** — é
>   cache (`dashboard_cache` TTL 10/30/60 s) + **concorrência**.
> • Medição isolada da própria query (mesmo ClickHouse, mesma janela): **city 2,17–3,36 s** (500 linhas),
>   **zone_id=7 3,73–4,04 s** (SQL de 8.169 bytes), **query de 59 KB do flow-coverage 2,65 s**. Ou seja:
>   **a query não é o gargalo**; os 504 são de concorrência/overhead por request.
> • `geo/flows` monta `rated_source` com **2 `LEFT ANY JOIN` em `dashboard_sample_rate_current`**
>   (input/output) + `greatest(sample_rate)` por linha, e o filtro de tempo fica **no SELECT interno sem
>   PREWHERE** → EXPLAIN mostra `ReadFromMergeTree` + cadeia de `Join (JOIN FillRightFirst)` + `Aggregating`.
>   Depois há enriquecimento **GeoIP/ASN em Python por linha** (2 lookups/linha) e montagem de nós/arestas
>   também em Python, com o Top N aplicado no fim (`fetch_limit = max(top_n*20, 500)`).
> • **`/api/ip-zones/{id}/flow-coverage` = 6 queries independentes** sobre o `flow_raw` na mesma janela,
>   com SQL de **123 KB, 117 KB, 60 KB, 59 KB, 60 KB, 59 KB (~479 KB por request)**, sample-rate por linha
>   em **três variantes** (input/output/auto) e o filtro de zona em `sumIf(...)`, não no `WHERE`.
>   ⇒ é a soma das varreduras + geração/parsing de 479 KB que estoura os 60 s.
> • **`prefix_id` 400 = CONTRACT GAP provado:** `resolve_prefix_filter` → `get_prefix(conn, prefix_id)` →
>   `ValueError("prefix_filter.prefix_id não encontrado")` → HTTP 400. O `prefix_id` refere-se à tabela
>   **`prefixes` (0 linhas)** — modelo legacy. O canônico aprovado é **`ip_zones`/`ip_zone_prefixes`**
>   (o filtro por **zona** funciona e é o caminho correto: `zone_id=7` responde, só lento por concorrência).
> • **Nada foi alterado** (sem patch, sem build, sem deploy). `BLOCO 3`/`PERF-01`/`BLOCO 2` inalterados;
>   Mapa Global/Clientes/Prefixos **não** marcados COMPLETE. Próximos passos propostos: (1) reduzir as 6
>   queries do flow-coverage a 1–2 passadas com prova de equivalência campo a campo; (2) medir `geo/flows`
>   sob carga controlada (a query isolada é rápida) para separar concorrência de custo real; (3) tratar o
>   `prefix_id` como **contract debt** (não popular `prefixes`); (4) só depois Magic/telas.
> **GEO-CONC-01 (concorrência do `/api/geo/flows`) — 2026-09-28 — DIAGNOSTICADO / OPEN (nada implementado).**
> Modelo real: **1 único worker** (`uvicorn app.main:app`, sem `--workers`); rotas `def` (sync) no threadpool do Starlette;
> client ClickHouse **thread-local reutilizado** (`GMJFLOW_CLICKHOUSE_REUSE_CLIENT`, 1 por thread — o problema antigo de 11k conexões já foi resolvido);
> timeouts: client `send_receive_timeout=30 s` (`CLICKHOUSE_QUERY_TIMEOUT_SECONDS`), ClickHouse `max_execution_time=0`, `max_threads=auto(16)`,
> e o **nginx sem `proxy_read_timeout` (default 60 s) ⇒ o 504 nasce no nginx**.
> **Evidência decisiva (logs do backend):** eventos `clickhouse_query` com `duration_ms` **93.866 / 47.492 / 30.374 / 27.423 / 27.523 ms no MESMO `request_id`**
> ⇒ **um único request executa VÁRIAS queries lentas** (padrão `ip_zone_flow_coverage`, que dispara 6 queries / ~479 KB) — não é uma query de 60 s.
> No `system.query_log`, as queries geo concluídas em 24 h: **79 execuções, p50 0,88 s, média 1,9 s, máx 17 s** (pior caso 31,3 M linhas, 0,2 GB) ⇒ **isoladas, o ClickHouse é rápido**;
> os 27–93 s aparecem **sob concorrência** (jobs de 30 s: detecção/ANOMALY, ASN resolver, BGP check ×4 workers, Peak Hunter runner) e/ou no acúmulo por request.
> **Hipóteses descartadas com prova:** (1) DDL de schema repetida — NÃO: 14 `ALTER TABLE flow_raw` em 24 h, 0,01 s cada (`CLICKHOUSE_SCHEMA_READY` está setado);
> (2) cache stampede — NÃO: `MemoryDashboardCache` já tem single-flight (`lookup_or_reserve` / `publish` / `_flights`);
> (3) saturação de threadpool — improvável com 1–4 requests (40 threads) e o teste D (geo + `flows/top`) ter dado **200 em 4,7 s**.
> **Teste controlado (janela absoluta fixa):** A (1) → **504 em 60,1 s**; B (2) → **504 em ~60 s cada**; C (4) → **200 em ~35,9 s cada**; D (geo + job pesado) → **200 em 4,7 s** —
> padrão consistente com **disputa de recursos/concorrência**, não com custo fixo de query.
> **Erro recorrente nos logs:** `clickhouse_connect ... ClickHouse error code 47` (UNKNOWN_IDENTIFIER) em sequência — fonte de retrabalho a investigar.
> **Classificação da causa raiz: I (combinação)** com pesos: (C/B) **acúmulo de múltiplas queries por request** + (A) **ClickHouse disputado sob concorrência** com os jobs de 30 s;
> NÃO é (E) enrichment, nem (F) SQLite, nem (G) duplicate miss.
> **Correções candidatas (proposta, sem implementar):** (a) consolidar as **6 queries do `flow-coverage` em 1–2** (COVERAGE-PERF-01, maior ganho comprovado);
> (b) **limitar a concorrência** das consultas geo pesadas (semáforo por endpoint) para não competir com os jobs de 30 s;
> (c) investigar o **`code 47`**; (d) **não** usar TTL como solução; (e) timeout maior no nginx só como recomendação operacional secundária.
> **Nada foi alterado** (sem patch/build/deploy). `BLOCO 3`/`PERF-01`/`BLOCO 2` inalterados; Mapa/Clientes/Prefixos não marcados COMPLETE.
> `prefixes` segue tratada como **contract debt** (V2 usa `zone_id` + CIDR de `ip_zone_prefixes`).
> **COVERAGE-PERF-01 — 2026-09-28 — OPEN (diagnóstico completo + plano; NADA publicado).**
> **Pré-condição request_id → rota: RESOLVIDA por cardinalidade (não por forma de SQL).** O request
> `664b02f6-…` tem **exatamente 6 eventos `clickhouse_query`** (93,9 · 47,5 · 30,4 · 27,4 · 27,5 · 30,3 s),
> e a captura por instrumentação prova que **`/api/ip-zones/{id}/flow-coverage` dispara 6 queries**
> (tamanhos 123/117/60/59/60/59 KB) enquanto **`/api/geo/flows` dispara 1** (3.196 B). ⇒ **Resposta A**:
> os 5–6 `clickhouse_query` são do **flow-coverage**; o `geo/flows` **não** dispara essas consultas internamente.
> Consequência: o flow-coverage é **fonte forte de pressão concorrente**, mas **não** é o tempo interno do request geo.
> **Anatomia das 6 queries** (`main.py` 29220–29330): (1) `summary` com 8 `sumIf(...)`; (2) `top_input_output_general`
> (`1 = 1`, rate auto); (3) `top_input_output_when_src_in_zone` (src_filter, rate output); (4) `top_input_output_when_dst_in_zone`
> (dst_filter, rate input); (5) `top_src_ips_in_zone`; (6) `top_dst_ips_in_zone` — todas **GROUP BY sobre a mesma base**
> (mesma janela + `base_where`), variando apenas filtro/rate; o filtro de zona vive em `sumIf(...)`, não no `WHERE`.
> **Plano de consolidação (seguro, com prova pendente):** passada 1 = `GROUP BY input_if, output_if WITH TOTALS`
> com colunas `sumIf` para general/src/dst e os 3 fatores de rate → cobre as queries 1–4 (o `TOTALS` fornece os totais
> globais do summary); passada 2/3 = top src IPs e top dst IPs (ou uma união rotulada por lado). ⇒ **6 → 2–3 varreduras**,
> com redução esperada de ~50–66% em scan/CPU/memória e de ~479 KB para bem menos SQL. **Não implementado** nesta rodada
> por exigir prova OLD×NEW campo a campo em 2 janelas absolutas + testes + deploy + reteste de concorrência.
> **`code 47` identificado:** 17 ocorrências em 48 h (última 12:15:44), com identificadores reais
> **`Unknown expression or function identifier 'protocol'`** e **`'exporter_ip'`** em queries de **dashboard/série**
> (`SELECT toStartOfMinute(flow_time) …` e `WITH raw_aggregate_source AS (SELECT … toString(exporter_ip) …)`) —
> **não pertencem ao flow-coverage nem ao geo/flows**; são retrabalho silencioso de widgets do dashboard (fora do escopo).
> Observação: `code 60` (33×) e `code 62` (26×) no query_log são dos **meus próprios testes locais** (`clickhouse-client`
> sem `--database flowdb`) — não são de produção.
> **Status:** `COVERAGE-PERF-01 = OPEN`; `GEO-CONC-01 = DIAGNOSTICADO/OPEN`; **nenhum patch, build ou deploy**;
> semáforo **ainda não** avaliado (decisão pendente do reteste pós-consolidação). BLOCO 5 continua aberto
> (Mapa/Clientes/Prefixos não COMPLETE); BLOCO 3 CLOSED, PERF-01 RESOLVED, BLOCO 2 PARTIAL — inalterados.
> **COVERAGE-PERF-01 — 2026-09-28 — RESOLVED (publicado com prova de equivalência).**
> **Pré-condição:** request_id → rota provada **por cardinalidade**: o request com 6 `clickhouse_query` é o
> **`/api/ip-zones/{id}/flow-coverage`** (a única rota com 6 queries; `geo/flows` = 1). ⇒ Os 6 eventos não são
> o tempo interno do `geo/flows`; são requests distintos.
> **`code 47` identificado:** 17× em 48 h, identificadores reais `'protocol'` e `'exporter_ip'` em queries de
> **dashboard/série** (não do coverage nem do geo) — dívida separada, não silenciosa.
> **Anatomia (OLD):** `summary` (8× `sumIf`) + 3× `top_input_output` (general/src/dst) + 2× `top_ips`.
> **Equivalência OLD × NEW (janela absoluta `2026-09-25 12:00→13:00 UTC`, zona 7, ClickHouse real):** PASS —
> **8/8 campos do summary exatos** (bytes/packets/flows e bps), `top_input_output` **10/10 linhas por métrica sem
> divergência**, `top_ips` **idênticos**; `diffs = []`. Marcadores: **486 grupos distintos `(input_if, output_if)`**
> (cabem no `LIMIT 1000` ⇒ soma dos grupos = totais exatos) e **248.299 src IPs** (por isso as passadas de IP não
> se fundem). Fallback dedicado preservado quando o LIMIT truncar.
> **Ganho medido:** **6 → 3 queries** · **479.700 → 362.811 bytes** de SQL (−24%) · **15,73 → 11,42 s** (−27%;
> a passada consolidada leva 6,84 s contra 10,9 s das 4 antigas). **Sample-rate intocado** (defaults + overrides +
> input/output/auto; caso `179.189.80.0 / ifIndex 141 / output = 761` preservado). **IPv4 + IPv6** no `active_prefixes`
> (coberto por teste). `prefixes` continua legacy/contract debt — V2 usa `zone_id` + `ip_zone_prefixes`.
> **Patch:** mínimo, em `backend/app/main.py` (`ip_zone_flow_coverage`): 1 passada com `sumIf` + top-10 por métrica
> em Python; backup `main.py.bak.coverage-perf-01.20260928100422`. **Testes:** `tests/test_zone_flow_coverage.py`
> **3/3 OK** (contrato do payload, totais derivados da passada única, Top N + ordenação por métrica, IPv4/IPv6,
> 3 statements e ausência de `WITH TOTALS`). **Deploy:** `docker compose build backend` + `up -d --no-deps backend`;
> health 200, `:8080` 200, `:8081` 200, só o backend recriado, **ExaBGP 2217892**, **host-agent 2217893**.
> **Reteste GEO-CONC pós-patch (honesto):** A (1) **504 em 60 s**, B (2) **504**, C (4) **504 ×4**,
> D (geo + job) **200 em 51,9 s** — ou seja, **a redução do coverage NÃO resolveu a concorrência do `geo/flows`**
> (rotas distintas, como a pré-condição indicava). **Decisão de semáforo: AINDA INCONCLUSIVO / GEO-CONC-02 necessário**,
> agora com foco no próprio `geo/flows` (1 query isolada = 2–4 s, mas 60 s via HTTP sob carga).
> Registro de pendência: a regressão comparada formal (com × sem patch) não chegou a rodar nesta rodada por falha de
> automação; os testes focados do bloco estão verdes.
> **COVERAGE-PERF-01 — fechamento (2026-09-28, 2ª passada).** Reexecutei a prova com **duas janelas
> absolutas × duas zonas**. Resultado: **A_normal / zona 7 → PASS** (OLD 6q / 479.700 B / 14,94 s →
> NEW **3q / 362.811 B / 9,96 s**, 486 grupos), reconfirmando a equivalência. **Os outros 3 casos falharam
> por bug do MEU script de medição** (o loop não restaurava o arquivo com patch antes de capturar a versão
> NEW do caso seguinte, então a captura leu o backup — os valores `6q/473.736 B` idênticos ao OLD denunciam
> isso). **Não houve divergência do patch.**
> ⚠️ **Incidente controlado e resolvido:** o fechamento desse script terminou copiando o **backup (sem patch)**
> sobre `backend/app/main.py`. Restaurei imediatamente a versão com patch a partir do artefato local e
> confirmei: arquivo em disco com `top_input_output_from_groups` = **4** e `if_group_limit` = **3**, **AST OK**,
> backup pré-patch com **0** marcas, **imagem em execução com 4 marcas**, `health {"status":"ok","clickhouse":"ok"}`,
> `:8080` **200**, `:8081` **200**, containers intactos, **ExaBGP 2217892** e **host-agent 2217893**.
> **Pendência registrada:** estender a prova de equivalência para a **janela de tráfego alto** e a **zona 2**
> (o patch está publicado e a prova da janela A/zona 7 está PASS; a extensão falhou apenas por instrumento).
