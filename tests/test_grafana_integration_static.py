from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
DOCS = (ROOT / "docs" / "grafana-integration.md").read_text(encoding="utf-8")
SCHEMAS = (
    ROOT / "backend" / "app" / "services" / "grafana_schemas.py"
).read_text(encoding="utf-8")
GRAFANA_API = (
    ROOT / "backend" / "app" / "services" / "grafana_api.py"
).read_text(encoding="utf-8")


class GrafanaIntegrationStaticTest(unittest.TestCase):
    def test_public_api_has_versioned_read_only_contract_and_openapi_models(self):
        for route in (
            "/api/v1/grafana",
            "/api/v1/grafana/health",
            "/api/v1/grafana/catalog",
            "/api/v1/grafana/anomalies/active",
            "/api/v1/grafana/anomalies/history",
            "/api/v1/grafana/mitigations",
            "/api/v1/grafana/mitigations/active",
            "/api/v1/grafana/bgp/status",
            "/api/v1/grafana/query/timeseries",
            "/api/v1/grafana/query/ranking",
            "/api/v1/grafana/query/table",
            "/api/v1/grafana/dashboards/{dashboard_id}/export",
        ):
            self.assertIn(route, MAIN)
        self.assertIn('tags=["Grafana Integration"]', MAIN)
        for model in (
            "GrafanaTimeseriesQuery",
            "GrafanaRankingQuery",
            "GrafanaTableQuery",
            "GrafanaHealthResponse",
        ):
            self.assertIn("class %s(" % model, SCHEMAS)

    def test_json_api_resources_are_get_only_and_use_read_scope(self):
        for route in (
            "/api/v1/grafana",
            "/api/v1/grafana/anomalies/active",
            "/api/v1/grafana/anomalies/history",
            "/api/v1/grafana/mitigations",
            "/api/v1/grafana/mitigations/active",
            "/api/v1/grafana/bgp/status",
        ):
            self.assertIn(f'@app.get("{route}"', MAIN)
            self.assertNotIn(f'@app.post("{route}"', MAIN)
        self.assertGreaterEqual(MAIN.count('"grafana:data:read"'), 8)

    def test_complete_top_n_catalog_reuses_dashboard_query_engine(self):
        for metric in (
            "top_upload_destinations",
            "top_download_origins",
            "top_source_ips",
            "top_destination_ips",
            "top_ports",
            "top_protocols",
            "top_tcp_flags",
        ):
            self.assertIn(f'"{metric}"', GRAFANA_API)
            self.assertIn(f"`{metric}`", DOCS)
        self.assertIn('"top_ports": {', GRAFANA_API)
        self.assertIn('"dimension": "dst_port"', GRAFANA_API)
        self.assertIn('"top_tcp_flags": {', GRAFANA_API)
        self.assertIn('"metric": "pps"', GRAFANA_API)
        self.assertIn("GRAFANA_RANKING_QUERY_PLANS", MAIN)
        self.assertIn("dashboard_widget_top_payload(", MAIN)
        self.assertIn("dashboard_widget_enrich_ranking_identity(", MAIN)

    def test_ranking_contract_is_flat_jsonpath_safe_and_read_only(self):
        for field in (
            '"bps":',
            '"pps":',
            '"percentage":',
            '"asn_name":',
            '"country_code":',
            '"country_name":',
            '"display_name":',
            '"tcp_flags":',
        ):
            self.assertIn(field, GRAFANA_API)
        ranking_endpoint = MAIN[
            MAIN.index("def grafana_ranking_endpoint"):
            MAIN.index("def grafana_table_endpoint")
        ]
        self.assertNotIn("announce", ranking_endpoint.lower())
        self.assertNotIn("withdraw", ranking_endpoint.lower())

    def test_cgnat_uses_shared_anomaly_detail_resolution(self):
        self.assertIn("fetch_anomaly_mitigation_context(", MAIN)
        self.assertIn("enrich_anomaly_event_with_cgnat(", MAIN)
        self.assertIn("grafana_announcement_cgnat_event(", MAIN)
        for unsafe_field in (
            '"announce_command":',
            '"withdraw_command":',
            '"router_password":',
        ):
            self.assertNotIn(unsafe_field, MAIN[MAIN.index("def grafana_mitigation_records"):MAIN.index("def grafana_bgp_status_records")])

    def test_security_defaults_are_narrow_and_token_is_dedicated(self):
        self.assertIn('cors_origins = os.getenv("API_CORS_ORIGINS", "")', MAIN)
        self.assertNotIn('allow_headers=["*"]', MAIN)
        self.assertIn("authenticate_grafana_api(", MAIN)
        self.assertIn('"grafana:data:read"', MAIN)
        self.assertIn('"grafana:dashboard:export"', MAIN)

    def test_phase_three_is_explicitly_disabled(self):
        self.assertIn("phase_3_not_enabled", MAIN)
        self.assertIn("status_code=501", MAIN)
        self.assertIn("Publicação direta", FRONTEND)
        self.assertIn("Plano detalhado da Fase 3", DOCS)
        self.assertIn("feature flag", DOCS)

    def test_export_ui_exposes_safe_actions(self):
        for token in (
            "grafanaExportModal",
            "testGrafanaExportButton",
            "copyGrafanaExportButton",
            "downloadGrafanaExportButton",
            "credentials_included",
            "/grafana-export",
        ):
            self.assertIn(token, FRONTEND)


if __name__ == "__main__":
    unittest.main()
