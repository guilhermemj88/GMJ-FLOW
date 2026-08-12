# Eventos de segurança comportamentais

O GMJ-FLOW usa uma sequência deliberadamente separada:

1. o detector local mede fatos do tráfego;
2. `security_events` consolida o evento e suas recorrências;
3. Threat Intelligence enriquece reputação e contexto histórico;
4. a IA interpreta a evidência quando o operador solicita;
5. o Policy Engine, em shadow mode por padrão, é o único componente que pode autorizar uma mitigação futura.

Threat Intelligence não cria eventos. A IA não executa mitigação. `GMJFLOW_THREAT_POLICY_AUTO_ENABLED=false` continua sendo o padrão obrigatório para implantação e atualização.

## Modelo canônico e compatibilidade

`security_events` é a visão canônica usada para investigação. `behavioral_attack_vectors`, `threat_campaigns`, `gmj_threat_history` e `threat_engine_audit` continuam preservadas. Cada execução grava as tabelas legadas e faz UPSERT no evento canônico.

A chave estável combina detector, tipo, origem, alvo, direção e protocolo. Uma recorrência atualiza `last_seen`, incrementa `recurrence_count` e preserva os maiores valores de score, confiança e métricas. Evidências, contexto e Threat Intelligence são atualizados com a observação mais recente. A migration aditiva está em `backend/migrations/20260812_security_events.sql`; o startup executa a mesma criação idempotente e faz um backfill único dos vetores legados.

`threat_campaigns.campaign_key` usa identidade semântica (família, classificação, prefixo alvo e família de protocolo), sem timestamp da janela. Janelas consecutivas equivalentes reutilizam o mesmo `campaign_id`, preservam `first_seen`, avançam `last_seen`, incrementam `recurrence_count` e mantêm os máximos. Registros antigos recebem a chave progressivamente e conservam seu identificador original.

Eventos expiram após três dias por padrão. O job não remove estados `confirmed`, `investigating`, `mitigated` ou `manually_pinned`.

## Papéis e direção

O Network Context Engine combina IP Zones, `prefix_type`, contextos de sensor/interface e mapeamentos CGNAT ativos.

- `CUSTOMER`: prefixo de assinante cadastrado;
- `CGNAT_PUBLIC`: pool público compartilhado de CGNAT;
- `INFRASTRUCTURE`: servidor, cache, BRAS ou infraestrutura do provedor;
- `MANAGEMENT`: plano de gerência;
- `TRANSIT`: rede/interface de trânsito;
- `PEERING`: rede/interface de peering;
- `EXTERNAL`: endereço válido fora das redes conhecidas;
- `UNKNOWN`: informação ausente ou topologia insuficiente.

As direções são `INTERNAL`, `INBOUND`, `OUTBOUND`, `EXTERNAL` e `UNKNOWN`. Dois endpoints fora das redes cadastradas nunca usam `INTERNAL` como fallback.

Cadastre pools CGNAT como prefixos `public_cgnat` em uma IP Zone. Mapeamentos CGNAT ativos também classificam seus IPs públicos como `CGNAT_PUBLIC`. Esse papel não ignora tráfego e não subtrai pontos por si só: ele apenas informa ao detector e à IA que diversidade de fontes, portas e fluxos pode representar muitos assinantes.

## Detector, severity e verdict

Os tipos de scan e `SSH_BRUTE_FORCE` pertencem a `SCAN_FAMILY`. SYN/UDP floods, reflection e carpet bombing pertencem a `FLOOD_FAMILY`. Os demais usam `OTHER_FAMILY`.

`severity` é a prioridade operacional (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). O verdict do detector comunica o grau de evidência: `INFO`, `SUSPICIOUS`, `WARNING`, `LIKELY_ATTACK` ou `CONFIRMED_ATTACK`. O verdict da IA é independente e pode ser `BENIGN`, `SUSPICIOUS`, `LIKELY_ATTACK` ou `CONFIRMED_ATTACK`.

O score é decomponível em `score_components`, por exemplo volume, diversidade, concentração, persistência, baseline, Threat Intelligence e contexto de rede. Cardinalidade ou baseline isolados não bastam para classificar floods.

## Threat Intelligence

A investigação mostra `matched_source_count / lookup_count`, truncamento, provider, indicador, classificação e tags. Um histórico GreyNoise de Telnet para uma origem de um evento UDP significa reputação suspeita com baixa relevância direta; não significa “GreyNoise confirmou UDP Flood”. Matches coerentes com o vetor, como scanner local mais reputação de scanner, recebem relevância maior, sempre limitada.

## Análise por IA

Use **ANALISAR COM IA** no drawer do evento. O backend envia o evento completo, papéis de rede, métricas, distribuições, baseline, recorrência, score, evidências, campanha, eventos relacionados e Threat Intelligence. O retorno estruturado é persistido em `ai_analysis_json` com data, provider, modelo e versão. Abrir o drawer reutiliza o resultado; **REANALISAR** força uma nova chamada manual.

O cache só é reutilizado com `ai_analysis_status=valid`. Nova recorrência material (tempo, score/confiança, volume/cardinalidade, evidência, TI, campanha ou contexto) muda o estado para `stale`; a resposta anterior permanece no evento e também é copiada para `threat_engine_audit` antes da próxima análise.

A IA recomenda ações e informa `mitigation_recommended`, mas registra sempre `mitigation_executed=false`. A recomendação não contorna o Policy Engine.

`mitigation_status` acompanha somente o ciclo autorizado pelo Policy Engine: `not_executed`, `shadow`, `requested`, `executed`, `failed` ou `expired`. As transições operacionais de FlowSpec atualizam também `decision_source` e `updated_at`; essa sincronização não altera gates nem habilita automação.

## APIs de investigação

- `GET /security/events`
- `GET /security/events/{id}`
- `GET /security/events/{id}/evidence`
- `GET /security/events/{id}/threat-intel`
- `GET /security/events/{id}/related`
- `POST /security/events/{id}/analyze-ai`
- `POST /security/events/{id}/reanalyze-ai`
- `POST /security/events/{id}/mark-benign`
- `POST /security/events/{id}/mark-confirmed`
- `POST /security/events/{id}/investigating`
- `GET /security/campaigns/{id}`

Essas rotas exigem as mesmas permissões `anomalies.view`/`anomalies.manage` das APIs antigas.

## Candidate Engine V2

`GMJFLOW_BEHAVIOR_CANDIDATE_ENGINE_V2=false` mantém o pipeline V1 como fonte de produção. Quando habilitado, quatro consultas ClickHouse (`scan_candidates`, `syn_flood_candidates`, `udp_flood_candidates` e `carpet_candidates`) pré-agregam candidatos e gravam uma comparação V1/V2 em `threat_engine_audit`. Nesta fase, o resultado V2 é somente shadow e não dirige policy nem mitigação.

As queries V2 recebem o mesmo objeto `DetectorThresholds` efetivo do V1. Isso inclui cardinalidades de scan, pisos de pacotes/pps/bit/s de SYN e UDP e pisos/máximo por host de carpet bombing; alterações `GMJFLOW_*` portanto chegam aos dois caminhos.

## Variáveis

| Variável | Padrão | Uso |
|---|---:|---|
| `GMJFLOW_AUTO_MITIGATION_ENABLED` | `false` | worker legado de mitigação automática; manter falso |
| `GMJFLOW_SECURITY_EVENT_RETENTION_DAYS` | `3` | retenção de eventos não protegidos |
| `GMJFLOW_BEHAVIOR_CANDIDATE_ENGINE_V2` | `false` | comparação shadow de candidatos ClickHouse |
| `GMJFLOW_SCAN_VERTICAL_PORTS` | `20` | portas mínimas do scan vertical em V1/V2 |
| `GMJFLOW_SCAN_HORIZONTAL_HOSTS` | `20` | hosts mínimos do scan horizontal em V1/V2 |
| `GMJFLOW_SCAN_LOW_SLOW_UNIQUE` | `10` | cardinalidade mínima low-slow em V1/V2 |
| `GMJFLOW_UDP_FLOOD_MIN_PACKETS` | `3000` | piso de pacotes UDP |
| `GMJFLOW_UDP_FLOOD_MIN_PPS` | `100` | piso obrigatório de pps UDP |
| `GMJFLOW_UDP_FLOOD_MIN_BPS` | `1000000` | sinal complementar de volume UDP |
| `GMJFLOW_SYN_FLOOD_MIN_PACKETS` | `3000` | piso de SYN sem ACK |
| `GMJFLOW_SYN_FLOOD_MIN_PPS` | `100` | piso de pps SYN |
| `GMJFLOW_SYN_FLOOD_MIN_BPS` | `1000000` | sinal complementar de volume SYN |
| `GMJFLOW_CARPET_MIN_HOSTS` | `8` | cardinalidade mínima de alvos |
| `GMJFLOW_CARPET_MIN_PACKETS` | `3000` | piso absoluto que baseline não substitui |
| `GMJFLOW_CARPET_MIN_PPS` | `200` | taxa agregada mínima |
| `GMJFLOW_CARPET_MIN_BPS` | `1000000` | sinal complementar de volume |
| `GMJFLOW_CARPET_MAX_HOST_PPS` | `100` | máximo por host para padrão distribuído |
| `GMJFLOW_SSH_BRUTE_FORCE_MIN_ATTEMPTS` | `30` | tentativas mínimas TCP/22 |
| `GMJFLOW_SSH_BRUTE_FORCE_MIN_SECONDS` | `30` | persistência mínima |
| `GMJFLOW_CAMPAIGN_DDOS_MIN_SOURCES` | `20` | fontes mínimas para campanha DDoS |
| `GMJFLOW_CAMPAIGN_DDOS_MIN_PPS` | `200` | volume mínimo da campanha |
| `GMJFLOW_CAMPAIGN_DDOS_MIN_BPS` | `1000000` | largura de banda mínima da campanha |
| `GMJFLOW_THREAT_POLICY_MIN_CONFIDENCE` | `0.80` | confiança mínima para política futura |
| `GMJFLOW_THREAT_POLICY_REQUIRE_RELEVANT_INTEL` | `false` | exige TI contextualmente relevante quando opt-in |
| `GMJFLOW_THREAT_POLICY_AUTO_ENABLED` | `false` | autorização automática global; manter falso |

## Validação em produção

Antes de promover qualquer decisão automática, compare V1/V2 por sensor e interface, calibre baselines por prefixo, valide a cobertura dos pools CGNAT e confira falso positivo/negativo para QUIC, DNS, jogos e CDNs. Confirme também a granularidade do sampler, a fidelidade de flags TCP e a resolução ASN. A política automática deve permanecer desativada até a aprovação manual dessas métricas.
