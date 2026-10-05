# GMJ-FLOW — Migração V1 → V2 (documento vivo)

> **Status:** vivo · **Criado:** 2026-10-05 · **Última atualização:** 2026-10-05
> **Branch de referência:** `preserve/fibinet-20260928` @ `997b7dc`
> **Fonte de verdade deste documento:** auditoria funcional read-only executada no **servidor real** em 2026-10-04/05.

Este é o documento **canônico** para qualquer IA/agente responder:

1. o que já existe na V2;
2. o que falta migrar da V1;
3. o que é apenas bloqueio do Preview read-only;
4. o que é problema de performance (não de paridade);
5. quais fluxogramas/documentos consultar antes de cada mudança.

---

## 1. Fontes de verdade

| Ambiente | URL | Artefato real no servidor | Observação |
|---|---|---|---|
| **V1 (produção)** | http://172.20.10.40:8080/ | `/home/guilherme/GMJ-FLOW/frontend/index.html` | página única (`index.html` ~1,8 MB, JS inline) |
| **V2 (preview)** | http://172.20.10.40:8081/ | `/home/guilherme/GMJ-FLOW-preview/dist` | build Vite (`index-DZRB5VDm.js`, `index-_i9-m-G3.css`), nginx **read-only** |
| Backend | (mesmo para as duas) | `gmj-flow-backend:8000` | V1 e V2 fazem proxy para o mesmo backend |

### 1.1 Source canônico da V2 (versionado)

- **Source:** `preview-v2/` **neste repositório** (antes vivia solto em `C:\projetos\GMJ-FLOW-MagicPreview`, sem Git).
- **Build:** `cd preview-v2 && npm ci && npm run build` (Vite). Gera `preview-v2/dist/`, que **não é versionado** (`.gitignore`).
- **Runtime atual:** `/home/guilherme/GMJ-FLOW-preview/dist` — bind mount do nginx `gmj-flow-preview` em `http://172.20.10.40:8081/` (preview **somente leitura**).
- **Publicação atual:** cópia **manual** do artefato `dist` para o diretório de runtime (não há CI). **Sempre gerar backup do `dist` atual antes de publicar** — o serviço aponta para o backend real.
- **Referência técnica detalhada:** `preview-v2/docs/V2-MIGRATION-MATRIX.md`.

**Divisão de papéis (evitar fontes concorrentes):**

| Documento | Papel |
|---|---|
| `docs/GMJ-FLOW-V1-V2-MIGRATION.md` (este) | **backlog/status canônico** da migração V1 → V2 |
| `preview-v2/docs/V2-MIGRATION-MATRIX.md` | **documentação técnica/detalhada da V2** (telas, endpoints, decisões) |

**Base validada:** o build do source versionado reproduz o bundle publicado `assets/index-Cy72qZUb.js` (md5 `9b34b2d4773c097469e8110909fe3468`), o mesmo que o `:8081` serve.

**Método:** leitura do código-fonte real no servidor (V1 `index.html`, bundle da V2, `GMJ-FLOW-preview/nginx.conf`, `backend/app/main.py`), `GET`s autenticados reais nas duas portas e `docker inspect`/`git` somente leitura. **Nenhuma escrita**, nenhum deploy, nenhum restart, nenhum toque em banco/PMACCT.

> **Sessões Edge/CDP do operador** (`127.0.0.1:9222`/`9223`) são loopback da máquina do operador e **não são acessíveis** do servidor. A auditoria foi feita sobre o artefato realmente servido no IP real; não se usou `127.0.0.1:8081`.

---

## 2. Estrutura de documentação existente (levantamento)

### 2.1 Onde fica a documentação

- **`docs/`** — documentação canônica do produto (24 arquivos `.md`).
- **`README.md` (raiz)** — funciona como **índice de fato** (aponta para `docs/*.md`).
- **`PROJECT_PLAN.md` (raiz)** — atualmente **vazio (0 bytes)**.
- Não existe `docs/README.md` nem `docs/INDEX.md`.

### 2.2 Onde ficam os fluxogramas

**Não existem fluxogramas formais no repositório**: nenhum `*.mmd`, `*.puml`, `*.drawio`, `*.mermaid`, e nenhum `mermaid`/`flowchart`/`graph TD` nos `.md`. O que existe são **descrições de fluxo em prosa** nos documentos abaixo:

| Documento | Fluxo descrito |
|---|---|
| [docs/collectors.md](collectors.md) | ciclo coletor → parser → ClickHouse / apply por sensor |
| [docs/pmacct.md](pmacct.md) | coleta real NetFlow/IPFIX com pmacct/nfacctd |
| [docs/security-events.md](security-events.md) | pipeline de eventos de segurança (detecção → persistência → investigação) |
| [docs/anomalies.md](anomalies.md) | vetores de ataque, regras, anomalias |
| [docs/dashboard-prefixes-grafana-phase1.md](dashboard-prefixes-grafana-phase1.md) | fluxo de dashboards, prefixos e integração Grafana |
| [docs/auth-access.md](auth-access.md) | autenticação, usuários e RBAC |
| [docs/grafana-integration.md](grafana-integration.md) | export/import Grafana |
| [docs/database-management.md](database-management.md) | retenção, otimização e limpeza |

> **Recomendação registrada (não executada nesta etapa):** quando esta migração introduzir/alterar fluxo, criar os diagramas em `docs/fluxos/` (mermaid) e referenciá-los aqui. Até então, os documentos acima são a referência de fluxo.

### 2.3 Canônicos por área (usar antes de qualquer mudança)

| Área / tela | Documento canônico |
|---|---|
| Dashboard / Flow Search | [docs/dashboard.md](dashboard.md), [docs/dashboard-performance.md](dashboard-performance.md), [docs/dashboard-performance-audit-2026-08-13.md](dashboard-performance-audit-2026-08-13.md) |
| Dashboards custom / Grafana | [docs/dashboard-prefixes-grafana-phase1.md](dashboard-prefixes-grafana-phase1.md), [docs/grafana-integration.md](grafana-integration.md) |
| Flows / períodos | [docs/time-ranges.md](time-ranges.md), [docs/hot-cache.md](hot-cache.md) |
| Sensores / Interfaces / coleta | [docs/collectors.md](collectors.md), [docs/pmacct.md](pmacct.md), [docs/snmp-calibration.md](snmp-calibration.md) |
| Anomalias / Vetores / linguagem de regras (DSL) | [docs/anomalies.md](anomalies.md), [docs/detection-rule-language.md](detection-rule-language.md) |
| Threat Intelligence / mapa | [docs/threat-intelligence.md](threat-intelligence.md), [docs/geoip-offline.md](geoip-offline.md) |
| Eventos de segurança / investigação | [docs/security-events.md](security-events.md), [docs/security-event-investigation.md](security-event-investigation.md) |
| Mitigação / BGP / RTBH | [docs/mitigation-playbook.md](mitigation-playbook.md), [docs/ai-mitigation.md](ai-mitigation.md) |
| ASN | [docs/asn-resolution.md](asn-resolution.md) |
| Banco / retenção | [docs/database-management.md](database-management.md) |
| Usuários / acesso | [docs/auth-access.md](auth-access.md) |
| Instalação / operação | [docs/install.md](install.md) |

---

## 3. Inventário atual da V2 (21 telas)

Extraído do bundle servido em `:8081`:

- **Visão geral:** Dashboard, Flows, Sensores, Interfaces, Mapa Global, Clientes / Zonas
- **Segurança:** Anomalias, Peak Hunter, Threat Intelligence, Alertas, Mitigação, BGP / Conectores, Vetores de Ataque
- **Rede / Classificação:** Codecs, Prefixos, CGNAT
- **Integrações:** Mídia
- **Plataforma:** Banco, Sistema
- **Administração:** Usuários e Acessos *(novo no P0-A — listagem somente leitura, 2026-10-05)*

A V1 tem 21 itens de navegação; **não existem na V2: IA e Minha Conta**. Usuários e Acessos entrou na V2 no **P0-A** (somente listagem read-only; detalhe/permissões e escrita pendentes).

---

## 4. Matriz resumida V1 → V2

Classificação: **A** redesign · **B** reorganizado · **C** gap real · **D** dado/API · **E** V2-only · **F** bloqueado só pelo preview read-only.

| Tela | Recurso V1 | Existe na V2? | Onde na V2 | Cl. | Evidência | Impacto |
|---|---|---|---|---|---|---|
| Dashboard | Widgets/visuais | Sim | `dashboard` | A | `GET /api/dashboard/{series,top-conversations,top-syn}` 200 | — |
| Dashboard | **Editor de dashboards** (CRUD/layout/widget-catalog/import-export Grafana) | Não | — | **C** | bundle sem `/api/dashboards` e `/api/dashboard-widgets`; V1 usa `/api/dashboards/*`, `/api/dashboard-widgets/query|preview`, `/widget-catalog`, `/import/grafana` | Alto |
| Flows | Busca/Top | Sim | `flows` | A | `GET /api/flows/search|top` 200 | — |
| Flows | ASN (`/api/asn/*`), whois IP (`/api/ip/whois`), export CSV | Não | — | **C** | 0 referências no bundle V2 | Médio |
| Sensores | Lista/detalhe | Sim | `sensors` | A | `GET /api/sensors` 200 (4) | — |
| Sensores | CRUD/SNMP/interfaces/calibração/aplicar coletor | Não há nem botão | — | **C** | bundle sem `Novo sensor/Salvar sensor/Aplicar coletor`; V1 tem `newSensorButton`, `saveSensorButton`, `deleteSensorButton`, `applyCollectorsButton`, `openSnmpButton` | Alto |
| Interfaces | Lista/detalhe | Sim | `interfaces` | A | `GET /api/interfaces` 200 | — |
| Interfaces | Add/Edit/Del/descoberta/calibração | Não há botão | — | **C** | V1 tem `addInterfaceButton`, `manageInterfacesButton`, `calibrateSampleRateButton`, `saveInterfaceButton` | Alto |
| Mapa Global | Geo flows | Sim | `gmaps` | A/D | `GET /api/geo/flows`: 1ª carga fria 57,9 s → **504** (timeout 60 s do nginx do preview); cache quente 0,07 s | Médio (perf) |
| Clientes/Zonas | Zonas/prefixos/ativação/flow-coverage | Sim | `zones` | A/B | `GET /api/ip-zones` 200 (6), `/1/prefixes` 200; `activate`/`flow-coverage` não referenciados | Médio |
| Prefixos | (na V1 fica dentro de Zonas) | Sim | `prefixes` | **B/E** | rota própria; consome `/api/detection/templates|whitelist` | Baixo |
| Anomalias | Histórico/ativos/stats/top | Sim | `anomalies` | A | 200 | — |
| Anomalias | Ack/Close/Aplicar mitigação | Sim (desabilitado) | `anomalies` | **F** | `reason:"ack/close/mitigate continuam bloqueados no preview"` | — |
| Anomalias | PDF e Análise IA da anomalia | Não | — | **C** | bundle sem `/api/anomalies/{id}/pdf` e `/ai-analysis` | Médio |
| Peak Hunter | Histórico/eventos/options/export-dataset | Sim | `peak` | A | 200; `/export-dataset` presente | — |
| Peak Hunter | Feedback e Run-now | Sim (desabilitado) | `peak` | **F** | `PATCH .../feedback e escrita`, `POST .../run-now grava execucao` | — |
| Threat Intelligence | IOCs/providers/map/lookup | Sim | `threat` | A/E | 200 (`iocs` 100, `providers` 5, `map` 26) | — |
| Threat Intelligence | Mapa geo de anomalias (`/api/geo/anomalies`) | Não | — | **C/B** | 0 refs (V2 usa `security-map`) | Baixo |
| Alertas | Eventos de segurança + summary | Sim | `alerts` | A/D | `/api/security/events` 200 (17,3 s) | Baixo (perf) |
| Mitigação | Executions/automation health | Sim | `mitigation` | A | `/api/mitigation/executions` 200 mas **53 MB** (24 s) | Médio (perf) |
| Mitigação | Aplicar mitigação | Sim (desabilitado) | `mitigation` | **F** | `POST /api/anomalies/{id}/mitigation/apply — bloqueado` | — |
| BGP/Conectores | Summary/connectors/announcements/policies/profiles | Sim | `bgp` | A | 200 (`connectors` 3, `announcements` 74) | — |
| BGP/Conectores | Approve/Reject/Withdraw/check-router/recover/editar | Sim (desabilitado) | `bgp` | **F** | 6 `reason:"POST /api/bgp/..."` + `PUT .../connectors/{id}` | — |
| BGP/Conectores | Relatório PDF | Não | — | **C** | 0 refs a `/api/bgp/report.pdf` | Médio |
| Vetores de Ataque | Lista/templates/sugestões | Sim | `vectors` | A | 200 (`attack-vectors` 16, `templates` 1) | — |
| Vetores de Ataque | apply/apply-all/duplicate/test/rules/learn | Sim (desabilitado) | `vectors` | **F** | `POST /apply e /apply-all alteram vetores reais.`, `POST /duplicate`, `POST /test`, `PUT /api/attack-vectors/{id}` | — |
| Codecs | Lista/options | Sim | `codecs` | A | 200 (22) | — |
| Codecs | Create/test/duplicate | Sim (desabilitado) | `codecs` | **F** | labels `Novo codec`/`Testar codec` + `ReadOnlyAction` | — |
| CGNAT | Pools/mappings/config/imports | Sim | `cgnat` | A | 200 (`pools` 6, `mappings` 1000) | — |
| CGNAT | Importar/parse NETMAP, `errors.csv` | Sim (desabilitado) | `cgnat` | **F/C** | `Importar` como `ReadOnlyAction`; `errors.csv` não referenciado | Médio |
| Mídia | Destinos (GET) | Sim | `media` | A/E | `/api/media` 200 (3) | — |
| Mídia | Nova/Testar entrega/Rotacionar segredo | Sim (desabilitado) | `media` | **F** | labels `Testar entrega`, `Rotacionar segredo` + `ReadOnlyAction` | — |
| Banco | Status/tabelas | Sim | `database` | A | 200 (22 tabelas) | — |
| Banco | Otimizar/TTL/limpeza | Sim (desabilitado) | `database` | **F** | labels `Otimizar`/`Aplicar TTL`/`Limpeza manual` | — |
| Sistema | Resources/disk-guard/cache/exabgp | Sim | `system` | A | 200 | — |
| Sistema | Containers | Sim | `system` | **D** | `GET /api/system/containers` → `items=0` **também na V1** (endpoint sem dados; não é gap da V2) | Baixo |
| **IA** | Providers/rotas/prompts/playground/modelos/settings/audit | **Não** | — | **C** | sem rota `ai`; **0 refs** a `/api/ai/*` no bundle; V1 usa ~20 endpoints `/api/ai/*` | **Alto** |
| **Usuários/Acessos** | **Listagem** (usuários + perfis/permissões, filtros, paginação) | **Sim (P0-A)** | `users` | **A** | rota `users` na sidebar (grupo *Administração*); consome `GET /api/v1/users|roles|permissions`; validado no :8081 em 2026-10-05 | Médio |
| **Usuários/Acessos** | Detalhe/matriz de permissões/escrita (criar, editar, reset, revoke, excluir, perfis, auditoria) | **Não** | — | **C** | V2 tem apenas ações como `ReadOnlyAction`; faltam P0-B (detalhe+matriz) e P0-D (escrita) | **Alto** |
| **Minha Conta** | Trocar senha/sessões/revogar | **Não** | — | **C** | 0 refs a `/api/auth/change-password`, `/api/auth/logout`, `/api/v1/auth/sessions|revoke-sessions` | **Alto** |
| Configurações | Templates/whitelist de detecção | Sim (leitura) | `prefixes`/`vectors` | **A/F** | consome `/api/detection/templates|whitelist|status`; `POST /api/detection/whitelist` = ReadOnlyAction | Médio |
| Configurações | run-now / apply collectors / config efetiva | Não | — | **C/F** | 0 refs a `/api/detection/run-now`, `/api/collectors/apply`, `/api/config/effective` | Médio |
| Qualquer tela | Login | Sim | gate de auth | A | `/api/auth/login`, `/api/auth/me` | — |
| Qualquer tela | Banner de preview | — | todas | **E** | `preview-env-banner` "Bloqueado no PREVIEW V2 (somente leitura)" | — |

---

## 5. Itens F — NÃO são gaps funcionais

Existem na V2 e estão bloqueados **apenas** porque `:8081` é Preview read-only (`GMJ-FLOW-preview/nginx.conf`: escrita responde `405`; só `login` e consultas de widget são exceções). **Ao servir a V2 sem o proxy read-only, eles voltam a funcionar** — os endpoints existem e respondem no backend.

- Anomalias: **ack / close / mitigate**
- Mitigação: **apply**
- BGP: **approve / reject / withdraw / check-router / recover-sessions / editar conector**
- Vetores: **apply / apply-all / duplicate / test / editar regras**
- Codecs: **create / test / duplicate**
- Peak Hunter: **feedback / run-now**
- Mídia: **testar entrega / rotacionar segredo**
- Banco: **optimize / aplicar TTL / cleanup**
- CGNAT: **import**
- Genérico: qualquer `POST`/`PUT`/`PATCH`/`DELETE` (reason `"POST de escrita — bloqueado no preview"`)

---

## 6. V2-only (recursos novos comprovados)

- **Prefixos** como tela própria (na V1 vive dentro de Clientes/Zonas).
- **RTBH** como área própria dentro de Mitigação (`/api/rtbh/overview|candidates|providers`).
- **Framework read-only** (`ReadOnlyAction`/`ReadOnlyBanner`, políticas A/B/C) + banner de ambiente.
- **Peak Hunter `export-dataset`** exposto como ação.
- **Threat Intelligence `security-map`** (`/api/threat-intelligence/security-map`).

---

## 7. PERFORMANCE ≠ PARIDADE

Itens abaixo **não** são gaps V1→V2; são características/limites de dados e infraestrutura, com sintomas comprovados:

| Endpoint | Sintoma comprovado | Efeito na tela | Encaminhamento |
|---|---|---|---|
| `/api/dashboard/directional-analytics` | 1ª chamada ~30,3 s | Dashboard carrega lento | cache/consulta |
| `/api/geo/flows` | 1ª chamada fria 57,9 s → **504** (timeout 60 s do nginx do preview); cache quente 0,07 s | Mapa Global pode falhar na 1ª carga | cache/prewarm |
| `/api/mitigation/executions` | 200 com **~53 MB** em 24 s | Mitigação pesada no browser | paginação/limite |
| `/api/system/containers` | `items=0` **na V1 e na V2** | Lista vazia (não é gap) | verificar acesso ao docker socket |

---

## 8. Observação importante sobre usuários (endpoint)

O path correto é **`/api/v1/users`**.
**Não é** `/api/users` — este retorna `404 Not Found` **tanto na V1 quanto na V2**.

Endpoints de acesso relacionados (V1): `/api/v1/users/{id}`, `/api/v1/users/{id}/reset-password`, `/api/v1/users/{id}/revoke-sessions`, `/api/v1/auth/me`, `/api/v1/auth/change-password`, `/api/v1/auth/sessions`, `/api/v1/auth/revoke-sessions`, `/api/v1/audit/users/{id}`.

---

## 9. Backlog canônico

### P0 — bloqueiam a substituição da V1

| ID | Item | Descrição resumida |
|---|---|---|
| MIG-001 | **IA** | Migrar a área de IA (providers, rotas, prompts, playground, modelos, settings central, audit). |
| MIG-002 | **Usuários e Acessos** | Migrar CRUD de usuários, papéis/permissões, reset de senha, revogação de sessões e auditoria por usuário. |
| MIG-003 | **Minha Conta** | Migrar troca de senha, sessões ativas e revogação. |
| MIG-004 | **Editor de Dashboards** | Migrar CRUD de dashboards, layout, catálogo de widgets e import/export Grafana. |

### P1 — necessários para operação plena

| ID | Item | Descrição resumida |
|---|---|---|
| MIG-010 | **Sensores: CRUD/SNMP/interfaces/calibração/aplicar coletor** | Migrar a gestão de sensores e o "Aplicar Coletor". |
| MIG-011 | **Interfaces: add/edit/delete/discovery/calibração** | Migrar a gestão de interfaces. |
| MIG-012 | **ASN / WHOIS** | Migrar enriquecimento ASN (`/api/asn/*`) e consulta de IP (`/api/ip/whois`). |
| MIG-013 | **Exportações PDF/CSV** | Migrar PDF de anomalias, PDF de BGP, PDF/teste de vetores e `errors.csv` de CGNAT. |
| MIG-014 | **Anomalias: análise IA + PDF** | Migrar `/api/anomalies/{id}/ai-analysis*` e `/api/anomalies/{id}/pdf`. |

### P2 — complementos e performance

| ID | Item | Descrição resumida |
|---|---|---|
| MIG-020 | **Configurações operacionais** | Migrar `run-now`, `collectors/apply`, `config/effective` e afins. |
| MIG-021 | **Performance/endpoints lentos** | Cache/paginação para `directional-analytics`, `geo/flows`, `mitigation/executions`; investigar `system/containers`. |
| MIG-022 | **CGNAT `errors.csv` e complementos menores** | Migrar export de erros e itens residuais (ex.: `/api/geo/anomalies`). |

---

## 10. Status por item

**Status permitidos:** `TODO` · `AUDITANDO` · `EM_IMPLEMENTACAO` · `VALIDANDO` · `CONCLUIDO` · `BLOQUEADO`.
Campos: **ID · prioridade · status · descrição · endpoints · arquivos envolvidos · testes necessários · commit · data · observações**.

### P0

| ID | Pri | Status | Descrição | Endpoints | Arquivos | Testes necessários | Commit | Data | Obs. |
|---|---|---|---|---|---|---|---|---|---|
| MIG-001 | P0 | TODO | Área de IA na V2 | `/api/ai/overview`, `/api/ai/providers*`, `/api/ai/routes*`, `/api/ai/prompts*`, `/api/ai/playground`, `/api/ai/settings/central`, `/api/ai/audit`, `/api/ai/history`, `/api/ai/models` | V2 (`src/*`), `backend/app/services/ai_integration.py`, `backend/app/main.py` | GETs reais + fluxo provider/rota/prompt; UI read-only | — | 2026-10-05 | Auditado no servidor real em 2026-10-04. Escrever só quando a V2 tiver backend de escrita. |
| MIG-002 | P0 | EM_IMPLEMENTACAO | Usuários e Acessos (**P0-A entregue**: estrutura/nav + listagem read-only) | Entregues: `GET /api/v1/users` (offset/limit/search/status/role), `GET /api/v1/roles`, `GET /api/v1/permissions`. Pendentes (P0-B/P0-D): `/api/v1/users/{id}`, `/reset-password`, `/revoke-sessions`, `/enable|/disable`, `DELETE`, `/api/v1/roles[/{id}]`, `/api/v1/audit[/users/{id}]` | V2: `src/users.jsx` (novo), `src/shared.jsx` (`hasPermission`), `src/main.jsx` (nav/gate `users.view`/rota/header); backend sem alteração (`auth_access.py`, `main.py`) | P0-A ✔ GETs reais no :8081, filtros, paginação, gate `users.view`, 8 colunas, ReadOnlyAction sem escrita; pendentes: matriz de permissões (P0-B) e escrita (P0-D) | `docs: update MIG-002 with P0-A delivery` | 2026-10-05 | **P0-A validado no servidor real em 2026-10-05**: nav com gate, tabela com as 8 colunas, 1 usuário real (`admin`/Administrador), 8 `ReadOnlyAction`, 0 erros de console/HTTP, nenhuma escrita. **Path correto: `/api/v1/users`** (não `/api/users`). |
| MIG-003 | P0 | TODO | Minha Conta | `/api/v1/auth/me`, `/api/v1/auth/change-password`, `/api/v1/auth/sessions`, `/api/v1/auth/revoke-sessions` | V2, `backend/app/services/auth_access.py` | troca de senha + sessões | — | 2026-10-05 | — |
| MIG-004 | P0 | TODO | Editor de Dashboards | `/api/dashboards*`, `/api/dashboard-widgets/query|preview`, `/api/dashboards/widget-catalog`, `/api/dashboards/import/grafana`, `/api/dashboards/{id}/export/grafana`, `/api/dashboards/{id}/layout`, `/api/dashboards/migrate-legacy-layout` | V2, `frontend/*dashboard*`, `docs/dashboard-prefixes-grafana-phase1.md` | CRUD + import/export + layout | — | 2026-10-05 | Consultar `docs/dashboard-performance*.md` e `docs/grafana-integration.md`. |

### P1

| ID | Pri | Status | Descrição | Endpoints | Arquivos | Testes necessários | Commit | Data | Obs. |
|---|---|---|---|---|---|---|---|---|---|
| MIG-010 | P1 | TODO | Sensores: CRUD/SNMP/interfaces/calibração/apply | `/api/sensors*`, `/api/collectors/apply`, `/api/collectors/health` | V2, `backend/app/main.py`, `docs/snmp-calibration.md`, `docs/collectors.md` | CRUD + SNMP + apply | — | 2026-10-05 | Escrever dependem do backend de escrita. |
| MIG-011 | P1 | TODO | Interfaces: gestão/descoberta/calibração | `/api/sensors/{id}/interfaces*`, `/api/interfaces*` | V2, `backend/app/main.py`, `docs/snmp-calibration.md` | add/edit/del/discovery/calibração | — | 2026-10-05 | — |
| MIG-012 | P1 | TODO | ASN / WHOIS | `/api/asn/status|info|details|resolve|queue-from-flows`, `/api/ip/whois` | V2, `backend/app/services/asn_local_cache.py`, `docs/asn-resolution.md` | consultas + cache | — | 2026-10-05 | — |
| MIG-013 | P1 | TODO | Exportações PDF/CSV | `/api/anomalies/{id}/pdf`, `/api/bgp/report.pdf`, `/api/attack-vectors/{id}/test/pdf`, `/api/cgnat/imports/{id}/errors.csv` | V2, `backend/app/main.py` | download/erro | — | 2026-10-05 | São GETs: não são bloqueados pelo proxy. |
| MIG-014 | P1 | TODO | Anomalias: análise IA + PDF | `/api/anomalies/{id}/ai-analysis`, `/ai-analysis/draft`, `/api/anomalies/{id}/pdf` | V2, `backend/app/services/security_event_ai.py` | análise + download | — | 2026-10-05 | — |

### P2

| ID | Pri | Status | Descrição | Endpoints | Arquivos | Testes necessários | Commit | Data | Obs. |
|---|---|---|---|---|---|---|---|---|---|
| MIG-020 | P2 | TODO | Configurações operacionais | `/api/detection/run-now`, `/api/collectors/apply`, `/api/config/effective` | V2, `backend/app/main.py` | smoke + permissão | — | 2026-10-05 | Escritas → F no preview. |
| MIG-021 | P2 | AUDITANDO | Performance de endpoints lentos | `/api/dashboard/directional-analytics`, `/api/geo/flows`, `/api/mitigation/executions`, `/api/system/containers` | `backend/app/main.py`, `backend/app/services/dashboard_*`, `docs/dashboard-performance*.md` | tempo/tamanho de resposta | — | 2026-10-05 | Sintomas medidos; ver seção 7. |
| MIG-022 | P2 | TODO | CGNAT `errors.csv` e complementos | `/api/cgnat/imports/{id}/errors.csv`, `/api/geo/anomalies` | V2, `backend/app/services/cgnat_mapping.py` | export + mapa | — | 2026-10-05 | — |
| MIG-030 | P2 | EM_IMPLEMENTACAO | **DSL de flows** — Fases 1 e 2: catálogo/dicionário canônico + Flow Search por expressão | `GET /api/rule-language/catalog`, `GET /api/flows/search?expression=`, `GET /api/flows/expression/validate` | `backend/app/services/detection_dsl/*` (inclui `compiler.py`), `backend/app/main.py`, `preview-v2/src/flows.jsx`, `docs/detection-rule-language.md` | 133 testes de DSL + comparação legacy×expressão com dados reais | `d1fd345` (Fase 1) + commits da Fase 2 | 2026-10-05 | Fase 3 = builder visual / Vetores. Detector atual **não** alterado; sem migration; sem AST persistida. |

### Itens F (não são migração; não entram no backlog)

| Recurso | Tela | Onde na V2 | Situação |
|---|---|---|---|
| ack / close / mitigate | Anomalias | `anomalies` | Existe; bloqueado pelo proxy read-only |
| apply | Mitigação | `mitigation` | Existe; bloqueado pelo proxy read-only |
| approve / reject / withdraw / check-router / recover / edit | BGP | `bgp` | Existe; bloqueado pelo proxy read-only |
| apply / apply-all / duplicate / test / edit | Vetores | `vectors` | Existe; bloqueado pelo proxy read-only |
| create / test / duplicate | Codecs | `codecs` | Existe; bloqueado pelo proxy read-only |
| feedback / run-now | Peak Hunter | `peak` | Existe; bloqueado pelo proxy read-only |
| testar entrega / rotacionar segredo | Mídia | `media` | Existe; bloqueado pelo proxy read-only |
| optimize / TTL / cleanup | Banco | `database` | Existe; bloqueado pelo proxy read-only |
| import | CGNAT | `cgnat` | Existe; bloqueado pelo proxy read-only |
| create / edit / enable / disable / reset / revoke / delete / roles | Usuários e Acessos | `users` | Existe como `ReadOnlyAction` desde o P0-A; bloqueado pelo proxy read-only |

---

## 11. Fluxogramas/documentos a consultar antes de cada mudança

**Regra obrigatória para qualquer IA/agente** — antes de implementar um item deste backlog:

1. ler este backlog (item + status + arquivos);
2. ler o **documento/fluxograma relacionado** (seção 2.3);
3. auditar a **V1** (o que existe e como se comporta);
4. auditar a **V2** (rota/componente/endpoint já usado);
5. auditar o **backend/endpoints** (existe? devolve dados? permissão?);
6. **evitar duplicação de lógica** (reaproveitar serviços do backend, não recriar regra no front).

Se a implementação **alterar arquitetura/fluxo**:

- **atualizar o fluxograma/documento correspondente no mesmo trabalho** (ou criar em `docs/fluxos/` quando ainda não existir).

---

## 12. Regra de atualização deste documento

Ao concluir qualquer lote V1→V2, a IA **deve obrigatoriamente** atualizar este documento:

- mudar o `Status` do item (`TODO` → `AUDITANDO` → `EM_IMPLEMENTACAO` → `VALIDANDO` → `CONCLUIDO`);
- preencher `commit` e `data`;
- registrar nas observações o que mudou e o que foi validado;
- atualizar a matriz (seção 4) e as listas F/V2-only/performance quando aplicável.

Preferência: **no mesmo commit** do lote; no mínimo, em commit documental **imediatamente associado**.

---

## 13. Critério objetivo para aposentar a V1

A V1 só pode ser desativada quando **todos** os critérios abaixo forem verdadeiros:

1. **100% dos itens P0** em `CONCLUIDO` (MIG-001..MIG-004), validados no servidor real.
2. **100% dos itens P1** em `CONCLUIDO` **ou** formalmente aceitos como não-bloqueadores (com justificativa registrada aqui).
3. **V2 servida sem o proxy read-only** na URL final (para que os itens F funcionem de fato) — evidência: escrita aprovada retornando 2xx em teste controlado.
4. **Checklist funcional por tela** (seção 4) revisado, sem item C em aberto.
5. **Sem 5xx/timeout sistemático** nas telas migradas (itens de performance da seção 7 resolvidos ou aceitos).
6. **Suíte de testes** relevante verde (backend + testes estáticos de frontend).
7. **Operação paralela** de pelo menos **7 dias** sem uso da V1 (métrica/log) e sem incidente atribuído à V2.
8. **Rollback documentado**: V1 reativável em < 5 min (imagem/arquivo preservados).
9. **Documentação atualizada**: este documento + fluxogramas + `README.md` apontando para a V2 como front canônico.

---

## 14. Veredito atual (2026-10-05)

**A V2 ainda NÃO pode substituir a V1.**

**Bloqueadores reais (P0):** IA · Usuários e Acessos · Minha Conta · Editor de Dashboards.

**Sequência P1 recomendada:** Sensores (CRUD/SNMP/apply) → Interfaces → Exportações PDF/CSV → Anomalias (IA + PDF) → ASN/WHOIS.

**Não bloqueiam:** todos os itens **F** (existem na V2; só dependem de a V2 ser servida sem o proxy read-only) e os itens de **performance** da seção 7 (não são gaps de paridade).

---

### Changelog

| Data | Alteração |
|---|---|
| 2026-10-05 | Criação do documento com a auditoria funcional V1→V2, backlog canônico P0/P1/P2, itens F, V2-only, performance, fluxogramas e critério de aposentadoria da V1. |
| 2026-10-05 | **P0-A entregue**: tela “Usuários e Acessos” na V2 (rota `users`, nav com gate `users.view`, listagem read-only de `GET /api/v1/users|roles|permissions`, filtros, paginação, 8 colunas e ações como `ReadOnlyAction`). MIG-002 → `EM_IMPLEMENTACAO`. |
| 2026-10-05 | **Versionamento do source da V2 (Opção A)**: criado `preview-v2/` no repo canônico (src, `index.html`, `package.json`/lock, `vite.config.js`, `deploy/`, `docs/V2-MIGRATION-MATRIX.md`, `README.md`, `.gitignore`). O build do source versionado reproduz o bundle publicado `assets/index-Cy72qZUb.js` (md5 `9b34b2d4…`). Nenhuma publicação/deploy. |
| 2026-10-05 | **DSL de flows — Fase 1**: evoluído o catálogo/dicionário canônico (`backend/app/services/detection_dsl/catalog.py`) com operadores canônicos (`==`), aliases (`proto`, `receives/transmits/sends`), campos prioritários e métricas/evidence; adicionado `parse_expression`/`validate_expression` (base do Flow Search) e o endpoint read-only `GET /api/rule-language/catalog`; criado `docs/detection-rule-language.md`. Detector atual **não** alterado, sem migration, sem AST persistida. MIG-030. |
| 2026-10-05 | **DSL de flows — Fase 2 (Flow Search por expressão)**: compilador `AST → WHERE` com parâmetros vinculados (`detection_dsl/compiler.py`), `expression=` aditivo em `GET /api/flows/search` (combina com filtros legados via AND) e `GET /api/flows/expression/validate`; limites de custo (2000 chars, 40 condições, profundidade 12, 64 itens `IN`, 200 de regex); `direction` usa os prefixos ativos de `ip_zones` (override `GMJFLOW_FLOW_INTERNAL_CIDRS`); V2 ganhou modo **Filtros | Expressão** + **Dicionário** em `preview-v2/src/flows.jsx`. Comparação legacy × expressão idêntica no mesmo snapshot; detector de ataques **não** alterado. MIG-030. |
