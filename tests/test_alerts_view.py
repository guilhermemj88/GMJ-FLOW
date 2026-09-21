from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AlertsViewStaticTest(unittest.TestCase):
    """Guards Fase 6 Alerts view (anomalias como núcleo, fontes complementares degradáveis)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

    def test_nav_and_permission(self) -> None:
        self.assertIn('data-nav-view="alerts" data-required-permission="anomalies.view"', self.html)
        self.assertIn("alerts: 'anomalies.view'", self.html)
        self.assertIn('id="alertsNavButton"', self.html)

    def test_view_section_and_table(self) -> None:
        self.assertIn('id="view-alerts"', self.html)
        self.assertIn('id="alertsTable"', self.html)
        self.assertIn('id="alertsStatusFilter"', self.html)
        self.assertIn('id="alertsSeverityFilter"', self.html)
        self.assertIn('id="alertsSourceFilter"', self.html)
        self.assertIn('id="alertsSensorFilter"', self.html)
        self.assertIn('id="alertsRefreshButton"', self.html)

    def test_show_view_routes_to_alerts(self) -> None:
        self.assertIn("else if (view === 'alerts') {", self.html)
        self.assertIn("loadAlertsView().catch(error => setText('alertsViewStatus'", self.html)

    def test_render_and_row_builders_exist(self) -> None:
        for fn in (
            "function loadAlertsView()",
            "function renderAlertsTable()",
            "function renderAlertsSensorFilter()",
            "function alertsAnomalyRows(items)",
            "function alertsBgpRows(items)",
            "function alertsMitigationRows(items)",
            "function alertsCollectorRows(items)",
            "function alertsStatusBadge(status)",
            "function alertsTime(value)",
        ):
            self.assertIn(fn, self.html)

    def test_anomalies_are_the_core_source(self) -> None:
        self.assertIn("apiRequest('/api/anomalies/active?limit=1000')", self.html)
        # reusa a correlação/consolidação já existente do backend (sem nova dedup)
        self.assertIn("anomalyActionId(event)", self.html)
        self.assertNotIn("function securityConsolidationKey", self.html)

    def test_complementary_sources_are_permission_gated(self) -> None:
        self.assertIn("apiRequest('/api/bgp/announcements?limit=500')", self.html)
        self.assertIn("apiRequest('/api/mitigation/executions?limit=500')", self.html)
        self.assertIn("apiRequest('/api/collectors/health')", self.html)
        # degradação graciosa: fontes opcionais só entram se a permissão existir
        self.assertIn("hasPermission('bgp.view')", self.html)
        self.assertIn("hasPermission('mitigations.view')", self.html)
        self.assertIn("hasPermission('collectors.view')", self.html)

    def test_no_n_plus_1_all_sources_batched(self) -> None:
        self.assertIn("Promise.all(tasks)", self.html)
        self.assertIn("alertsRows = results.flat();", self.html)

    def test_no_per_row_requests_in_render(self) -> None:
        start = self.html.index("function renderAlertsTable()")
        end = self.html.index("function renderAlertsSensorFilter()")
        block = self.html[start:end]
        self.assertNotIn("apiRequest(", block)
        self.assertNotIn("fetchJSON(", block)

    def test_columns_are_real(self) -> None:
        for col in (
            "Severidade", "Status", "Alerta/Anomalia", "Alvo/Entidade",
            "Sensor/Fonte", "Primeira ocorrência", "Última ocorrência", "Eventos", "Ação",
        ):
            self.assertIn(col, self.html)

    def test_status_and_severity_badges(self) -> None:
        self.assertIn("severityBadgeClass(row.severity)", self.html)
        self.assertIn("alertsStatusBadge(row.status)", self.html)
        # active/acknowledged claramente identificáveis; historical mutado
        self.assertIn("if (value === 'active') return 'status-active';", self.html)
        self.assertIn("if (value === 'acknowledged') return 'status-acknowledged';", self.html)
        self.assertIn("return 'status-ended';", self.html)
        self.assertIn("html[data-theme] .badge-soft.status-acknowledged {", self.html)

    def test_no_mock_data(self) -> None:
        start = self.html.index("let alertsRows = [];")
        end = self.html.index("function bindAlertsView()")
        block = self.html[start:end]
        self.assertNotIn("mock", block.lower())

    def test_css_uses_theme_tokens(self) -> None:
        marker = "/* ---- Alerts view (Fase 6) ---- */"
        start = self.html.index(marker)
        end = self.html.index("</style>", start)
        block = self.html[start:end]
        self.assertIn("var(--warning)", block)
        self.assertNotIn("#", block)


if __name__ == "__main__":
    unittest.main()
