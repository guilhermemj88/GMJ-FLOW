from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
BACKEND = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")


def js_block(start_marker: str, end_marker: str) -> str:
    start = FRONTEND.index(start_marker)
    end = FRONTEND.index(end_marker, start)
    return FRONTEND[start:end]


def refresh_block() -> str:
    return js_block("async function refresh()", "function selectedDashboardRefreshMs()")


def load_all_interfaces_block() -> str:
    return js_block("async function loadAllInterfaces(", "function interfaceRowStatus(")


class OverviewWidgetsShareContextTest(unittest.TestCase):
    """Todos os widgets do Overview usam o contexto global unificado."""

    def test_refresh_uses_top_query_for_flow_widgets(self) -> None:
        block_text = refresh_block()
        for endpoint in (
            "'/api/tops/src-ip', topQuery",
            "'/api/tops/dst-ip', topQuery",
            "'/api/tops/ports', topQuery",
            "'/api/tops/protocols', topQuery",
            "'/api/tops/tcp-flags', topQuery",
            "'/api/tops/asn-src', topQuery",
            "'/api/tops/asn-dst', topQuery",
            "'/api/dashboard/directional-analytics', topQuery",
            "'/api/dashboard/top-conversations', `${topQuery}&limit=",
            "'/api/dashboard/top-syn', `${topQuery}&mode=",
        ):
            self.assertIn(endpoint, block_text)

    def test_series_use_dashboard_series_params(self) -> None:
        block_text = refresh_block()
        self.assertIn("const bpsSeriesQuery = dashboardSeriesParams('bits_s');", block_text)
        self.assertIn("const ppsSeriesQuery = dashboardSeriesParams('packets_s');", block_text)

    def test_top_interfaces_respect_sensor_scope(self) -> None:
        block_text = load_all_interfaces_block()
        self.assertIn("const scopeSensors = selectedDashboardSensors().map(Number);", block_text)
        self.assertIn("sensors = sensors.filter(sensor => allowed.has(Number(sensor.id)));", block_text)

    def test_top_interfaces_respect_interface_scope(self) -> None:
        block_text = load_all_interfaces_block()
        self.assertIn("const scopeInterfaces = selectedDashboardInterfaces().map(Number);", block_text)
        self.assertIn("merged = merged.filter(item => selected.has(Number(item.id)));", block_text)

    def test_no_sensor_scope_means_all_sensors(self) -> None:
        block_text = load_all_interfaces_block()
        self.assertIn("if (scopeSensors.length) {", block_text)
        self.assertIn("let sensors = (Array.isArray(dashboardSensorCache)", block_text)


class MultiSelectSemanticsTest(unittest.TestCase):
    """Multiselect dentro da mesma dimensao e OR; dimensoes independentes e AND."""

    def test_two_sensors_use_csv(self) -> None:
        block_text = js_block("function dashboardParams(", "function dashboardSeriesParams(")
        self.assertIn("query.set('sensor_ids', sensors.join(','));", block_text)
        self.assertIn("if (includeSensorId && sensors.length > 1) {", block_text)

    def test_sensor_plus_interface_are_anded(self) -> None:
        block_text = js_block("function dashboardParams(", "function dashboardSeriesParams(")
        self.assertIn("query.set('interface_ids', interfaces.join(','));", block_text)

    def test_protocol_plus_sensor_are_anded(self) -> None:
        block_text = js_block("function appendDashboardFilterQuery(", "function appendDashboardPrefixQuery(")
        self.assertIn("query.set('protocols', values.protocols.join(','));", block_text)

    def test_service_plus_sensor_are_anded(self) -> None:
        block_text = js_block("function appendDashboardFilterQuery(", "function appendDashboardPrefixQuery(")
        self.assertIn("query.set('services', values.services.join(','));", block_text)

    def test_prefix_plus_sensor_are_anded(self) -> None:
        block_text = js_block("function appendDashboardPrefixQuery(", "function dashboardFiltersToGlobalFilters(")
        self.assertIn("query.set('prefix_enabled', String(enabled));", block_text)

    def test_changing_sensor_drops_orphan_interfaces(self) -> None:
        block_text = js_block("function setDashboardFilterValues(", "function toggleDashboardFilterValue(")
        self.assertIn("dashboardFilterState.interfaces = dashboardFilterState.interfaces.filter", block_text)
        self.assertIn("loadDashboardInterfaces()", block_text)

    def test_no_sensor_scope_means_all_for_flows(self) -> None:
        block_text = js_block("function dashboardParams(", "function dashboardSeriesParams(")
        self.assertIn("const sensors = selectedDashboardSensors();", block_text)
        self.assertIn("else if (includeSensorId && sensorId) {", block_text)


class BackendPropagationTest(unittest.TestCase):
    """Os endpoints que faltavam agora recebem o contexto global."""

    def test_geo_accepts_multi_scope(self) -> None:
        block_text = BACKEND
        self.assertIn("def geo_flows(", block_text)
        start = block_text.index("def geo_flows(")
        end = block_text.index("\n):", start)
        signature = block_text[start:end]
        for token in ("sensor_ids: str | None = None,", "interface_ids: str | None = None,", "protocols: str | None = None,", "services: str | None = None,"):
            self.assertIn(token, signature)
        self.assertIn("sensor_ids=sensor_ids,\n        interface_ids=interface_ids,\n        protocols=protocols,\n        services=services,", block_text)

    def test_anomalies_accepts_sensor_ids(self) -> None:
        block_text = BACKEND
        self.assertIn("sensor_ids: str | None = None,", block_text)
        self.assertIn('where.append("sensor IN (%s)" % ", ".join(["?"] * len(sensor_names)))', block_text)
        self.assertIn('"sensor_ids": sorted(sensor_names),', block_text)

    def test_no_extra_requests_on_panel_toggle(self) -> None:
        block_text = js_block("function initDashboardFiltersPanel()", "function selectedDashboardSensors()")
        self.assertNotIn("apiRequest(", block_text)
        self.assertNotIn("fetchJSON(", block_text)


if __name__ == "__main__":
    unittest.main()
