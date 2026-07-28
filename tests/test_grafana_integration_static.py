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


class GrafanaIntegrationStaticTest(unittest.TestCase):
    def test_public_api_has_versioned_read_only_contract_and_openapi_models(self):
        for route in (
            "/api/v1/grafana/health",
            "/api/v1/grafana/catalog",
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
