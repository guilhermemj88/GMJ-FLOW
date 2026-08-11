# Threat Intelligence e Behavioral Threat Engine

## Arquitetura integrada

O pipeline mantém os papéis já existentes no GMJ-FLOW:

1. `pmacct/nfacctd` recebe NetFlow/IPFIX e grava `flow_raw` no ClickHouse.
2. A materialized view `mv_flow_raw_to_behavior_10s` gera dimensões agregadas de 10 segundos em `behavior_flow_10s`, com TTL de 24 horas.
3. O `BehavioralThreatRuntime` lê um intervalo e um número máximo de grupos configuráveis. Detectores determinísticos produzem `AttackVector`; o correlacionador produz `CampaignVector`.
4. O `ThreatIntelManager` consulta os providers de forma isolada. Falha, timeout, erro de autenticação ou rate limit de um provider não interrompe os demais nem o detector.
5. A política combina evidência comportamental, desvio de baseline, coordenação, reincidência, inteligência externa e classificação Groq sobre JSON agregado.
6. Somente uma decisão `ALLOW_AUTO` atravessa a ponte para o ciclo FlowSpec existente. O código reaproveita perfil, conector, validações, allowlists, idempotência, cooldown, auditoria, entrega ExaBGP, TTL e retirada já existentes.

Nenhum flow bruto é enviado ao Groq. Cereal2, GreyNoise e Feodo nunca autorizam bloqueio isoladamente.

## Persistência

O ClickHouse permanece como data plane e recebe apenas o agregado de curta retenção `behavior_flow_10s`. O SQLite permanece como control plane e armazena:

- estado e auditoria de providers;
- indicadores normalizados e ranges bogon com índices binários;
- observações externas do Cereal2;
- contextos de rede/exporter;
- Attack Vectors, Campaign Vectors e histórico interno;
- decisões da política e trilha completa do Threat Engine.

Registros externos preservam somente campos operacionais normalizados. Respostas completas e credenciais não são persistidas.

## Rollout seguro

A detecção inicia em modo shadow. `GMJFLOW_THREAT_POLICY_AUTO_ENABLED=false` é o padrão e impede qualquer mitigação automática. Recomenda-se:

1. habilitar e observar providers e detectores;
2. calibrar thresholds e baselines com tráfego real;
3. opcionalmente habilitar `GMJFLOW_THREAT_AI_SHADOW_ENABLED` para validar a classificação agregada;
4. configurar exatamente um perfil FlowSpec automático com conector fixo, ou informar `GMJFLOW_THREAT_RESPONSE_PROFILE_ID`;
5. revisar allowlists, peers, exporters, IPs de gestão e ranges protegidos;
6. habilitar a política automática somente após os testes de dry-run.

Rollback imediato: definir `GMJFLOW_THREAT_POLICY_AUTO_ENABLED=false`. A coleta, a detecção e a tela continuam disponíveis sem criar FlowSpec. Também é possível desabilitar o scheduler de Threat Intelligence ou a detecção comportamental separadamente.

## Guardrails

- TTL obrigatório, limitado a 3600 segundos.
- Falha/timeout/JSON inválido do Groq resulta em `NO_AUTO`.
- A proposta é determinística e usa o menor escopo suportado pela evidência.
- Carpet bombing agrega prefixos e não cria milhares de `/32`.
- Filtro de porta UDP só é incluído com concentração mínima de 70%.
- Segurança é revalidada após resolver o perfil e imediatamente antes do handoff ao criador FlowSpec.
- Perfil ausente ou múltiplos perfis compatíveis resultam em `not_applied`.

## Riscos de performance

- A tabela de 10 segundos é limitada por TTL e a consulta possui lookback e limite de linhas.
- Agrupamentos de prefixos têm teto configurável para conter cardinalidade.
- Chamadas Groq por rodada têm limite configurável e ficam desativadas no shadow padrão.
- GreyNoise usa paginação/scroll e persiste cada página antes de buscar a próxima.
- Cereal2 usa cursor, Feodo é normalizado em lote e Team Cymru usa ranges indexados em vez de varredura de strings.

## Fontes oficiais

- GreyNoise GNQL API: <https://docs.greynoise.io/docs/using-the-greynoise-api>
- Cereal2: <https://cereal2.botnet.cl/>
- Team Cymru Bogon Reference: <https://www.team-cymru.com/bogon-reference-http>
- Feodo Tracker blocklists: <https://feodotracker.abuse.ch/blocklist/>
