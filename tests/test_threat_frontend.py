from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ThreatFrontendStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        cls.script = (ROOT / "frontend" / "threat-intelligence.js").read_text(encoding="utf-8")
        cls.style = (ROOT / "frontend" / "threat-intelligence.css").read_text(encoding="utf-8")

    def test_navigation_view_and_permission_are_wired(self) -> None:
        self.assertIn('data-nav-view="threat-intelligence"', self.html)
        self.assertIn('id="view-threat-intelligence"', self.html)
        self.assertIn("'threat-intelligence': 'anomalies.view'", self.html)
        self.assertIn("window.loadThreatIntelligenceWorkspace?.()", self.html)

    def test_current_map_component_is_reused(self) -> None:
        self.assertIn("new root.GeoFlowMap", self.script)
        self.assertIn("id=\"threatGlobalMap\"", self.html)

    def test_threat_map_uses_aggregated_points_without_gmj_routes(self) -> None:
        self.assertIn("visualization: 'points'", self.script)
        self.assertIn("nodes: mapNodes", self.script)
        self.assertNotIn("GMJ_CENTER", self.script)
        self.assertNotIn("dst_label: 'GMJ-FLOW'", self.script)
        self.assertNotIn("mapEdges", self.script)

    def test_point_popup_contains_required_aggregates(self) -> None:
        for label in (
            "País / localização",
            "Quantidade de IPs",
            "Top organizações",
            "Top tags",
            "Providers envolvidos",
            "Classificação predominante",
        ):
            self.assertIn(label, self.script)

    def test_provider_secrets_are_not_rendered(self) -> None:
        self.assertNotIn("GREYNOISE_API_KEY", self.script)
        self.assertNotIn("api_key", self.script.lower())
        self.assertIn("credential_configured", self.script)

    def test_text_badges_exist_in_addition_to_colors(self) -> None:
        for label in ("GMJ-FLOW", "External Threat Intel", "Manual", "Allowlist/Exception"):
            self.assertIn(label, self.html)
        self.assertIn("threat-source-badge", self.style)

    def test_provider_states_and_intel_evidence_lanes_are_explicit(self) -> None:
        for status in ("ACTIVE", "WAITING_SYNC"):
            self.assertIn(status, self.script)
        for label in ("Detecção local", "Intel da origem", "Correlação alvo/campanha"):
            self.assertIn(label, self.script)
        self.assertIn("threat-status-active", self.style)
        self.assertIn("threat-status-waiting-sync", self.style)
        self.assertIn("source_intel", self.script)
        self.assertIn("target_campaign_intel", self.script)

    def test_security_events_are_clickable_and_ai_is_manual(self) -> None:
        self.assertIn('id="securityEventDrawer"', self.html)
        self.assertIn("/security/events?limit=200", self.script)
        self.assertIn('data-security-event-id', self.script)
        self.assertIn('ANALISAR COM IA', self.script)
        self.assertIn('REANALISAR', self.script)
        self.assertIn('mitigation_recommended', self.script)
        self.assertIn('.security-event-drawer', self.style)

    def test_security_event_investigation_sections_and_bounded_endpoints_are_wired(self) -> None:
        for label in (
            "Resumo", "Tráfego", "Origens", "Top Sources", "Top Destination Ports",
            "Top Source Ports", "Threat Intelligence", "Evidências", "Análise IA",
        ):
            self.assertIn(label, self.script)
        for endpoint in ("/traffic?padding_seconds=600", "/sources?sort=packets&limit=100", "/evidence?sample_limit=100", "/ai-analysis"):
            self.assertIn(endpoint, self.script)
        for sort in ("packets", "bytes", "pps"):
            self.assertIn(f"'{sort}'", self.script)
        self.assertIn("securityEventTrafficChart", self.script)
        self.assertIn("security-event-traffic-chart", self.style)

    def test_threat_intelligence_uses_persisted_event_snapshot(self) -> None:
        for field in ("last_seen", "organization", "country", "actor", "tags", "cves", "metadata"):
            self.assertIn(field, self.script)
        self.assertIn("abrir o drawer não faz lookup individual", self.script)
        self.assertIn("Evento sem enrichment externo associado", self.script)

    def test_ai_disabled_stale_and_advisory_states_are_visible(self) -> None:
        self.assertIn("Security AI desabilitada por configuração", self.script)
        self.assertIn("Análise potencialmente desatualizada", self.script)
        self.assertIn("Advisory only", self.script)
        self.assertIn("Nenhuma mitigação automática foi executada", self.script)

    def test_campaign_investigation_is_independent_from_canonical_events(self) -> None:
        for label in (
            "Investigação da campanha", "RESUMO DA CAMPANHA", "AVALIAÇÃO CONTEXTUAL DETERMINÍSTICA",
            "TARGET / TRAFFIC", "TOP SOURCES", "ASN DISTRIBUTION", "EVENTOS CORRELACIONADOS",
            "Nenhum Security Event canônico correlacionado a esta campanha.",
        ):
            self.assertIn(label, self.script)
        for field in (
            "campaign.campaign_id", "campaign.classification", "campaign.coordination_score",
            "campaign.unique_sources", "campaign.unique_source_asns", "campaign.packets_per_second",
            "campaign.bits_per_second", "campaign.first_seen", "campaign.last_seen",
        ):
            self.assertIn(field, self.script)
        self.assertIn("payload.correlated_events", self.script)
        self.assertIn("payload.top_sources", self.script)
        self.assertIn("payload.asn_distribution", self.script)
        self.assertNotIn("Nenhum evento canônico vinculado.", self.script)

    def test_campaign_ai_and_persisted_enrichment_are_wired(self) -> None:
        self.assertIn("/api/security/campaigns/${encodeURIComponent(campaignId)}/ai-analysis", self.script)
        self.assertIn('data-campaign-action="analyze"', self.script)
        self.assertIn('data-campaign-action="reanalyze"', self.script)
        self.assertIn("Enrichment persistido na campaign", self.script)
        self.assertIn("Campanha sem enrichment externo associado", self.script)
        self.assertIn("abrir o drawer não faz lookup individual", self.script)

    def test_campaign_ai_provider_failure_is_reloaded_and_displayed(self) -> None:
        self.assertIn("Última tentativa:", self.script)
        self.assertIn("await openSecurityCampaign(campaignId);", self.script)
        self.assertIn("error?.payload?.detail?.message", self.script)
        self.assertIn("securityEventDrawerStatus').textContent = providerMessage", self.script)

    def test_campaign_metric_context_and_asn_snapshot_are_explicit(self) -> None:
        for label in (
            "Peak detection PPS", "Investigation packets", "Investigation bytes",
            "Metric provenance / time window", "Duração da campanha", "Duração técnica",
            "ASN DISTRIBUTION — TOP SOURCES SNAPSHOT", "Total campaign ASNs",
            "ASNs represented in snapshot", "Sources represented in snapshot",
            "Contexto de detecção / CGNAT", "O score comportamental reflete critérios locais de correlação",
        ):
            self.assertIn(label, self.script)
        self.assertIn("function humanDuration(value)", self.script)
        self.assertIn("const hours = Math.floor(seconds / 3600)", self.script)
        self.assertIn("protocol_label", self.script)
        self.assertIn("item.country", self.script)
        self.assertNotIn("/api/asn/", self.script)

    def test_opening_campaign_performs_only_gets_and_ai_is_manual(self) -> None:
        start = self.script.index("async function openSecurityCampaign(")
        end = self.script.index("function renderLegacySecurityAnomalyDetail", start)
        open_campaign = self.script[start:end]
        self.assertNotIn("method: 'POST'", open_campaign)
        self.assertIn("apiRequest(base)", open_campaign)
        self.assertIn("apiRequest(`${base}/ai-analysis`)", open_campaign)
        self.assertIn("Promise.allSettled", open_campaign)
        self.assertIn("if (campaignResult.status === 'rejected')", open_campaign)
        self.assertIn("renderSecurityCampaignInvestigation(payload, aiState)", open_campaign)

    def test_campaign_context_state_confidence_fp_and_role_are_visible(self) -> None:
        for label in (
            "Estado operacional", "Confiança de ataque", "Risco de falso positivo",
            "Role do alvo", "Análise por IA sugerida", "Score comportamental",
        ):
            self.assertIn(label, self.script)
        for field in ("evaluation.state", "evaluation.attack_confidence", "evaluation.false_positive_risk", "context.target_role"):
            self.assertIn(field, self.script)

    def test_workspace_panels_are_isolated_with_partial_status(self) -> None:
        start = self.script.index("async function loadWorkspace()")
        end = self.script.index("async function providerAction", start)
        workspace = self.script[start:end]
        self.assertIn("Promise.allSettled", workspace)
        self.assertNotIn("Promise.all([", workspace)
        self.assertIn("Atualização parcial", workspace)
        self.assertIn("renderVectors", workspace)
        for panel_id in (
            "threatProvidersStatus", "threatMapStatus", "threatVectorsStatus",
            "threatCampaignsStatus", "threatDecisionsStatus",
        ):
            self.assertIn(f'id="{panel_id}"', self.html)
            self.assertIn(panel_id, self.script)

    def test_attack_vector_polling_is_bounded_canonical_and_non_concurrent(self) -> None:
        self.assertIn("let securityEventsRequestPromise = null", self.script)
        self.assertIn("if (securityEventsRequestPromise) return securityEventsRequestPromise", self.script)
        self.assertIn("Math.max(5, Math.min(15", self.script)
        self.assertIn("securityEventsPollingSeconds = 10", self.script)
        start = self.script.index("async function fetchSecurityEvents()")
        end = self.script.index("async function loadWorkspace()", start)
        polling = self.script[start:end]
        self.assertIn("apiRequest('/api/security/events?limit=200'", polling)
        self.assertNotIn("/api/threat-engine/attack-vectors", polling)
        self.assertNotIn("threat-intelligence/providers", polling)
        self.assertNotIn("policy-decisions", polling)
        self.assertNotIn("campaigns?", polling)

    def test_polling_uses_etag_and_runs_only_for_active_visible_tab(self) -> None:
        self.assertIn("'If-None-Match'", self.script)
        self.assertIn("__notModified", self.script)
        self.assertIn("__unchanged", self.script)
        self.assertIn("__etag", self.script)
        self.assertIn("function startSecurityEventsPolling", self.script)
        self.assertIn("function stopSecurityEventsPolling", self.script)
        self.assertIn("document.visibilityState !== 'visible'", self.script)
        self.assertIn("root.startThreatIntelligencePolling = startSecurityEventsPolling", self.script)
        self.assertIn("root.stopThreatIntelligencePolling = stopSecurityEventsPolling", self.script)
        self.assertIn("window.startThreatIntelligencePolling?.()", self.html)
        self.assertIn("window.stopThreatIntelligencePolling?.()", self.html)
        self.assertNotIn("configureSecurityEventsPolling();", self.script)

    def test_event_ids_are_not_localized_in_data_attributes(self) -> None:
        self.assertIn('data-security-event-id="${item.id}"', self.script)
        self.assertIn('data-event-id="${event.id}"', self.script)
        self.assertIn('data-anomaly-id="${anomalyId}"', self.script)
        self.assertIn('data-anomaly-id="${mitigationId}"', self.script)
        # IDs técnicos nunca podem passar por number() (localização pt-BR
        # transformaria 109771 em "109.771" e quebraria URLs/actions).
        self.assertNotIn('number(event.id)', self.script)
        self.assertNotIn('number(item.id)', self.script)
        self.assertNotIn('number(anomalyId)', self.script)
        self.assertNotIn('number(mitigationId)', self.script)
        self.assertNotIn('data-security-event-id="${number(', self.script)
        self.assertNotIn('data-event-id="${number(', self.script)
        self.assertNotIn('data-anomaly-id="${number(', self.script)
        self.assertNotIn('/api/security/events/${number(', self.script)
        self.assertIn("apiRequest('/api/security/events?limit=200'", self.script)
        self.assertNotIn("apiRequest('/security/events?limit=200'", self.script)

    def test_security_overview_summary_and_shadow_score_are_wired(self) -> None:
        self.assertIn('id="securityOverviewPanel"', self.html)
        self.assertIn('id="secOverviewAnalyzed"', self.html)
        self.assertIn('id="secOverviewEligible"', self.html)
        self.assertIn('Threat Score em SHADOW', self.html)
        self.assertIn("apiRequest('/api/security/summary?window=60')", self.script)
        self.assertIn('function renderSecuritySummary', self.script)
        self.assertIn('function renderThreatScore', self.script)
        self.assertIn('threat_score', self.script)
        self.assertIn('shadow_decision', self.script)
        self.assertIn('eligible_for_mitigation', self.script)

    def test_low_rate_and_targetless_scanners_remain_visible(self) -> None:
        start = self.script.index("function renderVectors(")
        end = self.script.index("function renderCampaigns(", start)
        renderer = self.script[start:end]
        self.assertIn("items.map", renderer)
        self.assertNotIn("items.filter", renderer)
        self.assertIn("recurrence_count", renderer)
        self.assertIn("rateNumber(item.packets_per_second)", renderer)
        self.assertIn("Math.abs(parsed) < 1 ? 3 : 1", self.script)
        self.assertIn("scannerTargetLabel(item)", renderer)
        self.assertIn("múltiplos destinos", self.script)
        self.assertIn("unique_dst_ports", self.script)
        for badge in ("Scanner conhecido", "Malicious", "GreyNoise", "Botnet", "Exploit", "SSH brute force"):
            self.assertIn(badge, self.script)

    def test_canonical_events_are_also_loaded_in_anomalies(self) -> None:
        self.assertIn("apiRequest('/api/security/events?limit=200'", self.html)
        self.assertIn('canonical_security_event: true', self.html)
        self.assertIn('data-security-action="open"', self.html)

    def test_legacy_anomalies_reuse_the_investigation_drawer(self) -> None:
        self.assertEqual(self.html.count('id="securityEventDrawer"'), 1)
        self.assertIn('data-legacy-security-anomaly-id', self.html)
        self.assertIn('gmjLegacySecurityAnomalyCache', self.html)
        self.assertIn('openLegacySecurityAnomaly', self.script)
        self.assertIn('Legacy anomaly', self.script)
        for action in ('mitigate', 'ack', 'close'):
            self.assertIn(f'data-legacy-security-action="{action}"', self.script)

    def test_investigation_drawer_is_never_empty_and_has_lineage_and_deeplink(self) -> None:
        # Fallback de CASO B: sem Security Event persistido, ainda renderiza algo.
        self.assertIn('function renderInvestigationUnavailable', self.script)
        self.assertIn('Esta é uma detecção comportamental informativa', self.script)
        self.assertIn('não possui Anomaly/Security Event correlacionado', self.script)
        # Nucleo renderiza imediatamente e enriquecimento e independente.
        start = self.script.index('async function openSecurityEventInvestigation(')
        end = self.script.index('function campaignPersistence', start)
        opener = self.script[start:end]
        self.assertIn('renderSecurityEventInvestigation(event, [], { items: [] }, { items: [] }, {})', opener)
        self.assertIn('Promise.allSettled', opener)
        self.assertNotIn('Promise.all([', opener)
        self.assertIn('renderInvestigationUnavailable(eventId, error)', opener)
        # Rastreabilidade (lineage) e deep-link para Threat Intelligence.
        self.assertIn('function renderSecurityEventLineage', self.script)
        self.assertIn('Rastreabilidade', self.script)
        self.assertIn('Regra responsável', self.script)
        self.assertIn('ABRIR NO THREAT INTELLIGENCE', self.script)
        self.assertIn('data-security-action="open-in-threat-intel"', self.script)
        self.assertIn("showView('threat-intelligence')", self.script)
        # Evidencia deterministica generica (observado vs threshold) e campos E2.2.
        self.assertIn('Resultado', self.script)
        self.assertIn('unique_destination_hosts', self.script)
        self.assertIn('Robust z-score', self.script)
        self.assertIn('Maturity', self.script)
        self.assertIn('Classification', self.script)


if __name__ == "__main__":
    unittest.main()

