# Blackhole / RTBH por Transit Provider (RECOMMEND_ONLY)

Evolução do GMJ-FLOW para que o Threat Intelligence transforme incidentes
volumétricos (ex.: UDP carpet bombing com origem spoofada) em **candidatos de
mitigação RTBH**, resolvendo a COMMUNITY BGP específica de cada trânsito.

## Estado desta versão (limite de segurança)

- **RECOMMEND_ONLY / DRY RUN.** Nenhum anúncio BGP é realizado.
- Ciclo máximo de candidato: `PROPOSED` → `REVIEW_REQUIRED` → `DRY_RUN`.
  `EXECUTING`, `ACTIVE`, `WITHDRAW_PENDING`, `WITHDRAWN` existem no schema
  por completude, mas **nenhum caminho de código alcança esses estados**.
- Nenhuma escrita em pipe ExaBGP, nenhuma alteração em roteador, nenhum
  anúncio/retirada de FlowSpec ou RTBH.
- Kill switch real: `RTBH_EXECUTION_ENABLED` (padrão `false`).
  `effectiveExecution = persistent_enabled (policy mode=AUTO) AND
  RTBH_EXECUTION_ENABLED`. A IA e a API normal não conseguem contornar.

## Modelo conceitual

```text
Threat Intelligence (vetor/campanha)
        │  action=RTBH + provider + target_prefix (NUNCA recebe/cria community)
        ▼
Mitigation Engine (app/services/transit_rtbh.py)
        │  resolve provider + TransitRtbhPolicy
        ▼
standard communities / large communities / prefix policy /
approval requirement / execution mode
        ▼
RtbhDryRunExecutor → DRY RUN (monta a ação, não chama o executor real)
```

## Entidades persistidas (SQLite, migrations incrementais)

`backend/migrations/20260829_transit_rtbh.sql` (referência canônica; o startup
aplica o mesmo DDL idempotente via `ensure_transit_rtbh_schema`).

- **transit_providers**: nome, `sensor_id` opcional, `input_if`, `enabled`.
- **transit_rtbh_policies**: `standard_communities_json`,
  `large_communities_json`, `communities_sensitive`, `address_family`,
  `mode` (`OFF | RECOMMEND_ONLY | MANUAL_APPROVAL | AUTO`),
  `min_prefix_length`/`max_prefix_length`, `min_confidence`,
  `min_attack_bps`, `min_duration_seconds`, `cooldown_seconds`,
  `allow_auto`, `require_manual_approval`.
- **rtbh_mitigation_candidates**: incident_id, threat_assessment_id,
  classification, action_type (`RTBH | MANUAL_LARGE_PREFIX_RTBH`),
  target_prefix, provider_id, input_if, confidence, taxas observadas e
  estimadas, baseline, share por provider, suitability, collateral_risk,
  reason, evidence, status, `no_safe_selective_rtbh_candidate`,
  `large_prefix_manual_only`, `dry_run_json`.
- **rtbh_candidate_audit**: trilha de auditoria (actor, action, incident,
  candidate, provider, prefixo, policy, referência de communities, estados
  antigo/novo, motivo). Communities sensíveis **não** são duplicadas em
  plaintext — a referência segura é o `policy_id`.

## Prefixos protegidos (3 níveis, compatível)

`bgp_protected_prefixes` ganhou colunas incrementais sem remover a proteção
existente:

- `block_auto_rtbh` (default 0)
- `require_manual_rtbh` (default 1)
- `block_all_rtbh` (default 0)
- `service_name` (default '') — identifica o serviço legítimo no host
- `protocol` (default '') — `tcp`/`udp`/`icmp` do serviço
- `port` (nullable) — porta do serviço
- `protection_level` (default `NORMAL`) — `NORMAL`/`IMPORTANT`/`CRITICAL`

O booleano legado `block_rtbh` é preservado e continua governando o caminho
BGP legado. Na geração de candidatos RTBH: `block_all_rtbh` → candidato
pulado com auditoria; `require_manual_rtbh` → status forçado para
`REVIEW_REQUIRED`. O formulário da UI aceita os novos campos de serviço.

Um /32 que hospede serviço protegido **nunca** vira candidato de RTBH
seletivo — o host é pulado com auditoria
`candidate_skipped_protected_service/protected_service_collateral`. Quando
não há vítima seletiva segura e a alternativa é o prefixo pai inteiro, o
candidato MANUAL_LARGE_PREFIX_RTBH carrega em `evidence` os serviços
afetados (`protected_services_affected`, `affected_service_names`,
`affected_host_count`) e o motivo lista os nomes.


## Lógica de carpet bombing

Incidentes com UDP volumétrico + muitas origens + provável spoofing + portas
aleatórias + fanout alto + muitos destinos são classificados como
`UDP_VOLUMETRIC_CARPET_BOMBING`.

Suitability avaliada por candidato:

| dimensão | resultado típico (spoofing) |
|---|---|
| source_blocking_suitability | VERY_LOW |
| asn_blocking_suitability | VERY_LOW |
| port_flowspec_suitability | LOW (sem porta dominante) |
| protocol_flowspec_suitability | LOW/MEDIUM (colateral) |
| rtbh_suitability | HIGH (vítima seletiva /32) |
| scrubbing_suitability | VERY_HIGH (excede capacidade local) |
| source/asn_attribution_confidence | LOW (ASN infere de IP spoofado) |
| blocklist_value | LOW |

**Nunca blackhole automático do /22.** A distribuição por /32 (attack bps,
pps, baseline, duração, share por provider) é calculada no ClickHouse. A
concentração de cada /32 é medida contra o **volume total do prefixo**
(`total_bps`), nunca contra um subset TOP-N — validado no incidente real de
45.163.144.0/22, onde o /32 mais atacado tinha apenas 0,74% do total
(ataque uniforme). Com concentração suficiente, são criados candidatos
seletivos por /32; caso contrário
`no_safe_selective_rtbh_candidate = true` e são oferecidas apenas as ações
`MANUAL_LARGE_PREFIX_RTBH` (com `collateral_risk = CRITICAL` e o texto
explícito: *"Esta ação tornará todo o prefixo indisponível através deste
trânsito."*) e/ou `UPSTREAM_SCRUBBING` (quando o ataque excede a capacidade
local).

## Multi-trânsito

A distribuição de ingress (`input_if`) do incidente identifica quais
providers transportam o ataque; cada provider gera seus próprios candidatos
(um candidate por provider por vítima). Ex.: RTBH 45.163.145.74/32 via
CIRION, via SEABORN e via SEMPRE. Bloquear em um provider não resolve os
demais.

## Auditoria de amostragem e magnitude (validado em 2026-08-29/30)

- O parser pmacct grava contagens **cruas** no ClickHouse
  (`RAW_BYTES_ALREADY_SCALED=false` etc.); `flow_raw.sample_rate` fica `1`.
- O multiplicador `GMJFLOW_RTBH_ESTIMATE_MULTIPLIER` (default 1000, NE8000
  amostra 1:1000) é aplicado **uma única vez** na geração de candidatos
  (`generate_rtbh_candidates_from_rows`); nada mais escala.
- **Cross-check SNMP × NetFlow inconclusivo**: não há amostras SNMP do
  sensor `NE8000-F1A-IMPLANTAR` durante a janela do incidente (o polling
  SNMP desse sensor iniciou às ~00:55 UTC, após o fim da janela). Os
  valores estimados (×1000) são portanto **limites superiores NÃO
  validados** (o pico observado de ~593 Mbps estima ~593 Gbps).
- Consequência: o gate de magnitude da política (`min_attack_bps`) usa o
  valor **observado** (físico) por provider, nunca o estimado
  (`evidence.gate_bps_basis = "observed"`). A recomendação de scrubbing
  continua usando o limite superior estimado (conservador, apenas
  recomendação).
- `baseline_available=false` no incidente: nenhuma razão baseline foi
  inventada; candidatos não dependem de baseline.

## Ordenação por persistência (adotada, apenas ordenação)

`candidate_rank_key` combina volume estimado, persistência (duração
## Dry run

```text
RTBH DRY RUN
Provider: CIRION
Target: 45.163.145.74/32
Standard communities: [Configured]     <- mascaradas se sensitive
Large communities: [Configured]
Policy: MANUAL_APPROVAL
Would announce: YES/NO
Actually announced: NO
Reason: ...
```

O dry-run monta a ação que seria enviada ao BGP mas nunca chama o executor
real.

## APIs

- `GET /api/rtbh/overview` — kill switch + contadores.
- `GET|POST /api/rtbh/providers`, `PUT|DELETE /api/rtbh/providers/{id}`.
- `PUT /api/rtbh/providers/{id}/policy` — valida communities
  (`ASN:VALOR` / `ASN:A:B`; entradas inválidas são rejeitadas).
- `GET /api/rtbh/candidates`, `GET /api/rtbh/candidates/{id}`.
- `POST /api/rtbh/candidates/{id}/review|reject|dry-run` — **não existe
  endpoint de execução**.
- `GET /api/rtbh/incidents/{incident_id}/candidates` — seção
  MITIGATION CANDIDATES do relatório (sem valores de community sensíveis).
- `GET /api/rtbh/audit` — trilha de auditoria.

Permissões: leitura `bgp.view`/`mitigations.view`; escrita `bgp.manage`
(mapeadas em `permission_for_legacy_admin_route`). Communities só são
retornadas com `bgp.manage`; caso contrário aparecem como "Configured".

## UI

Mitigação → painel **Blackhole / RTBH (Transit Providers)**:

- Transit Providers (nome, ifIndex, status, modo, communities configuradas)
- Políticas (modo, constraints IPv4/IPv6 de prefixo, confiança mínima,
  volume mínimo, duração mínima, cooldown, communities com validação)
- Candidates (target, provider, tipo, share, taxas observada/estimada,
  confiança, colateral, disponibilidade RTBH, status) com ações
  **Review / Reject / Dry Run**. Não há botão "Execute".

## BCP38 / uRPF (registro correto)

- uRPF/BCP38 local impede spoofing **originado** por clientes da própria rede.
- Spoofing recebido da Internet depende de source validation nas redes
  upstream/origem.
- Isso **não** é usado como mitigação deste evento inbound.

## Pontos que ainda faltam para habilitar RTBH real

1. Executor real (ExaBGP/GoBGP/FRR) com `announce route ... community` +
   withdraw, atrás do kill switch `RTBH_EXECUTION_ENABLED=true` e de policy
   `mode=AUTO` com aprovação humana.
2. Contractos de comunidade com cada trânsito cadastrados pelo operador
   (nunca hardcoded).
3. Resolução de next-hop/null0 e validação no roteador (Huawei VRP) para a
   rota blackhole.
4. Transições `APPROVED → EXECUTING → ACTIVE → WITHDRAW_PENDING →
   WITHDRAWN` + TTL/cooldown por provider.
5. Confirmação operacional da presença da rota na RIB do trânsito.
