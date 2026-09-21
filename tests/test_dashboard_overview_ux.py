from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DashboardOverviewUxStaticTest(unittest.TestCase):
    """Guards Phase 3 Overview (real data only, configurable dashboard preserved)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        cls.sparkline_path = ROOT / "frontend" / "dashboard-sparkline.js"
        cls.sparkline = cls.sparkline_path.read_text(encoding="utf-8")

    def test_sparkline_primitive_exists_without_dependencies(self) -> None:
        self.assertTrue(self.sparkline_path.is_file())
        self.assertIn("renderSparkline", self.sparkline)
        self.assertIn("<svg", self.sparkline)
        # no external chart library
        self.assertNotIn("echarts", self.sparkline.lower())
        self.assertNotIn("import ", self.sparkline)
        self.assertNotIn("require(", self.sparkline)
        self.assertIn("dashboard-sparkline.js", self.html)
        self.assertIn("./frontend/dashboard-sparkline.js:/usr/share/nginx/html/dashboard-sparkline.js:ro", self.compose)

    def test_rx_tx_colors_use_theme_tokens(self) -> None:
        self.assertIn("semanticColor('--chart-rx'", self.html)
        self.assertIn("semanticColor('--chart-tx'", self.html)
        self.assertIn("const aggregateDirectionColor = items.length <= 2", self.html)

    def test_kpi_strip_is_present_and_real(self) -> None:
        self.assertIn('id="dashboardKpiStrip"', self.html)
        self.assertIn('id="kpiTrafficValue"', self.html)
        self.assertIn('id="kpiPacketsValue"', self.html)
        # fed by real series payloads (no hardcoded values)
        self.assertIn("function renderKpiStrip(name, items, apiMetric)", self.html)
        self.assertIn("overviewSeriesDirectionPoints(items)", self.html)

    def test_alert_strip_uses_real_anomaly_summary(self) -> None:
        self.assertIn('id="dashboardAlertStrip"', self.html)
        self.assertIn("function renderAlertStrip(payload)", self.html)
        # reads real summary fields, hides when none
        self.assertIn("active_critical", self.html)
        self.assertIn("active_warning", self.html)
        self.assertIn("strip.hidden = true", self.html)

    def test_top_interfaces_uses_real_snmp_interfaces(self) -> None:
        # Fase 4: Top Interfaces agora vem de SNMP por sensor (dados reais), nao do series flow.
        self.assertIn('id="topInterfacesTable"', self.html)
        self.assertIn("function loadAllInterfaces(force = false)", self.html)
        self.assertIn("/api/sensors/${sensor.id}/interfaces", self.html)
        self.assertIn("Promise.all(sensors.map(", self.html)
        self.assertIn("['topInterfaces', loadAllInterfaces()]", self.html)
        self.assertIn("snmp_in_bps", self.html)
        self.assertIn("snmp_out_bps", self.html)

    def test_top_interfaces_shows_only_real_columns(self) -> None:
        # no fabricated utilization/capacity/status columns cross-sensor (Sensor added in Fase 4)
        self.assertIn("<th>#</th><th>Interface</th><th>Sensor</th><th>RX</th><th>TX</th><th>Total</th><th>Share</th>", self.html)
        self.assertIn(".share-bar", self.html)
        self.assertIn(".top-interfaces .rank", self.html)

    def test_configurable_dashboard_preserved(self) -> None:
        for marker in (
            'id="dashboardSelector"',
            'id="addDashboardWidgetButton"',
            'id="editDashboardButton"',
            'id="resetDashboardButton"',
            'id="configurableDashboardGrid"',
            'function refreshConfigurableDashboard()',
        ):
            self.assertIn(marker, self.html)


if __name__ == "__main__":
    unittest.main()
