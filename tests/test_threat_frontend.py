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

    def test_canonical_events_are_also_loaded_in_anomalies(self) -> None:
        self.assertIn("apiRequest('/security/events?limit=200'", self.html)
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


if __name__ == "__main__":
    unittest.main()
