from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "frontend" / "index.html"
HTML = HTML_PATH.read_text(encoding="utf-8")
STYLE_ONLY = HTML[:HTML.rindex("</style>")]


def css_block(selector: str) -> str:
    start = HTML.index(selector)
    return HTML[start:HTML.index("}", start)]


class Phase7InterfaceDrawerTest(unittest.TestCase):
    """Fase 7: o drawer fechado não deve permanecer visível/focável."""

    def test_drawer_is_hidden_while_closed(self) -> None:
        block = css_block(".interface-drawer {")
        self.assertIn("visibility: hidden", block)
        open_rule = css_block(".interface-drawer.open {")
        self.assertIn("visibility: visible", open_rule)

    def test_drawer_rows_are_keyboard_activatable(self) -> None:
        start = HTML.index("function bindInterfaceDrawerEvents()")
        end = HTML.index("document.addEventListener('click'", start)
        block = HTML[start:end]
        self.assertIn("event.key === 'Enter'", block)
        self.assertIn("openInterfaceDrawer(row.dataset.interfaceSensor", block)

    def test_drawer_keeps_keyboard_focus_inside(self) -> None:
        start = HTML.index("function interfaceDrawerFocusableElements()")
        end = HTML.index("function bindInterfaceDrawerEvents()", start)
        self.assertIn("querySelectorAll(", HTML[start:end])
        start = HTML.index("function bindInterfaceDrawerEvents()")
        end = HTML.index("document.addEventListener('click'", start)
        block = HTML[start:end]
        self.assertIn("event.key === 'Tab' && interfaceDrawerState.open", block)
        self.assertIn("first.focus()", block)
        self.assertIn("last.focus()", block)

    def test_drawer_traffic_chart_is_disposed(self) -> None:
        self.assertIn("function disposeInterfaceDrawerTrafficChart()", HTML)
        self.assertIn("interfaceDrawerTrafficChart.dispose()", HTML)
        close_start = HTML.index("function closeInterfaceDrawer()")
        close_end = HTML.index("if (interfaceDrawerState.lastFocus)", close_start)
        self.assertIn("disposeInterfaceDrawerTrafficChart();", HTML[close_start:close_end])
        render_start = HTML.index("function renderInterfaceDrawer()")
        render_end = HTML.index("function interfaceDrawerFocusableElements()", render_start)
        self.assertIn("disposeInterfaceDrawerTrafficChart();", HTML[render_start:render_end])
        self.assertIn("if (interfaceDrawerTrafficChart === chart) chart.resize();", HTML)


class Phase7OverviewTest(unittest.TestCase):
    """Fase 7: densidade do KPI strip e breakpoints consistentes."""

    def test_kpi_strip_uses_compact_tracks(self) -> None:
        block = css_block(".dashboard-kpi-strip {")
        self.assertIn("repeat(auto-fit, minmax(240px, 360px))", block)
        self.assertIn("justify-content: start", block)

    def test_new_breakpoints_follow_app_convention(self) -> None:
        self.assertIn("@media (max-width: 991.98px) {\n      .dashboard-secondary-grid", HTML)
        self.assertIn("@media (max-width: 991.98px) {\n      .alerts-filter-grid", HTML)
        self.assertIn("@media (max-width: 575.98px) {\n      .alerts-filter-grid { grid-template-columns: 1fr; }", HTML)
        self.assertNotIn("@media (max-width: 992px)", HTML)

    def test_alerts_status_reflects_active_filters(self) -> None:
        self.assertIn("function updateAlertsStatus(visibleCount)", HTML)
        self.assertIn("updateAlertsStatus(rows.length);", HTML)
        self.assertIn("alertsLoadedAt = new Date().toLocaleTimeString('pt-BR');", HTML)


class Phase7SidebarResponsiveTest(unittest.TestCase):
    """Fase 7: a sidebar não pode virar uma lista completa expandida em ≤991.98px."""

    def test_compact_sidebar_layout_below_desktop(self) -> None:
        start = HTML.index("@media (max-width: 991.98px) {\n      .app-shell")
        block = HTML[start:HTML.index("@media (max-width: 767.98px)", start)]
        self.assertIn(".side-nav {\n        display: grid;", block)
        self.assertIn("repeat(auto-fit, minmax(190px, 1fr))", block)
        self.assertIn("max-height: 46vh", block)

    def test_small_viewport_grid_is_compact(self) -> None:
        start = HTML.index("@media (max-width: 767.98px)")
        block = HTML[start:HTML.index("@media (max-width", start + 10)]
        self.assertIn("repeat(auto-fit, minmax(150px, 1fr))", block)
        self.assertIn("max-height: 40vh", block)


class Phase7OverviewCompositionTest(unittest.TestCase):
    """Fase 7: padrao/operacional = chrome operacional; custom = grade configuravel (+ AlertStrip)."""

    def test_alert_strip_is_not_part_of_the_operational_chrome(self) -> None:
        self.assertEqual(1, HTML.count('id="dashboardAlertStrip"'))
        start = HTML.index('<section class="dashboard-alert-chrome" id="dashboardAlertSection">')
        block = HTML[start:HTML.index("</section>", start)]
        self.assertIn('id="dashboardAlertStrip"', block)
        self.assertNotIn('id="dashboardKpiStrip"', block)

    def test_alert_strip_is_the_first_overview_block(self) -> None:
        # aparece no topo tambem em dashboard customizado, antes da grade de widgets
        self.assertLess(HTML.index('id="dashboardAlertSection"'), HTML.index('id="dashboardPrefixControls"'))
        self.assertLess(HTML.index('id="dashboardAlertSection"'), HTML.index('id="configurableDashboardGrid"'))

    def test_custom_dashboard_keeps_widget_grid_and_alert_strip(self) -> None:
        start = HTML.index("#view-dashboard.dashboard-engine-active:not(.dashboard-operational) > section")
        block = HTML[start:HTML.index("}", start)]
        self.assertIn("#configurableDashboardGrid", block)
        self.assertIn("#dashboardAlertSection", block)

    def test_operational_dashboard_shows_only_operational_blocks(self) -> None:
        start = HTML.index("#view-dashboard.dashboard-engine-active.dashboard-operational > section")
        block = HTML[start:HTML.index("}", start)]
        for section in (
            "#dashboardAlertSection",
            "#dashboardOverviewChrome",
            "#dashboardAggregateSection",
            "#dashboardTopInterfacesSection",
            "#dashboardSecondaryAnalyticsSection",
        ):
            self.assertIn(section, block)
        self.assertNotIn("#configurableDashboardGrid", block)

    def test_composition_uses_dashboard_is_default_metadata(self) -> None:
        self.assertIn("function applyOverviewComposition(operational)", HTML)
        self.assertIn("applyOverviewComposition(Boolean(dashboard.is_default));", HTML)
        self.assertIn("function resetOverviewComposition()", HTML)
        # sem heuristica por texto/titulo do dashboard
        self.assertNotIn("dashboard.name === ", HTML)
        self.assertNotIn(".name.toLowerCase().includes(", HTML)

    def test_operational_overview_uses_the_legacy_refresh_loop(self) -> None:
        # o chrome operacional precisa de dados: refresh legado e auto-refresh seguem ativos
        self.assertEqual(2, HTML.count("configurableDashboardActive && !dashboardOverviewOperational"))
        self.assertIn("dashboardOverviewOperational ? refresh() : refreshConfigurableDashboard()", HTML)
        self.assertIn("if (dashboardOverviewOperational) refresh().finally(scheduleDashboardRefresh)", HTML)

    def test_alert_strip_shares_the_ops_summary_source(self) -> None:
        start = HTML.index("function renderOpsSummary(summary)")
        block = HTML[start:HTML.index("function requestOpsSummary()", start)]
        self.assertIn("renderAnomalyBadge(anomalySummary);", block)
        self.assertIn("renderAlertStrip(anomalySummary);", block)

    def test_alert_strip_has_a_single_source(self) -> None:
        # `/api/dashboard/anomalies-summary` pode voltar vazio: nao pode oscilar com o ops summary
        start = HTML.index("if (name === 'anomaliesSummary')")
        block = HTML[start:HTML.index("if (name === 'asnSrc'", start)]
        self.assertIn("renderDashboardAnomalies(payload);", block)
        self.assertNotIn("renderAlertStrip(payload);", block)

    def test_interface_sweep_shares_the_in_flight_load(self) -> None:
        start = HTML.index("async function loadAllInterfaces(force = false)")
        block = HTML[start:HTML.index("function interfaceRowStatus", start)]
        self.assertIn("allInterfacesLoadPromise", block)
        self.assertIn("return allInterfacesLoadPromise;", block)
        self.assertIn("allInterfacesCacheAt", block)
        self.assertIn("Promise.all(sensors.map(", block)

    def test_aggregate_throughput_section_is_addressable(self) -> None:
        self.assertIn('<section class="row g-3" id="dashboardAggregateSection">', HTML)

    def test_flows_summary_uses_global_formatters(self) -> None:
        # `compactNumber` e privado do componente GeoFlowMap: chamar daqui quebrava o resumo
        start = HTML.index("function renderSecondaryFlowsSummary(protocolItems)")
        block = HTML[start:HTML.index("let alertsRows", start)]
        self.assertNotIn("compactNumber(", block)
        self.assertIn("window.GMJDashboardFormatters", block)
        self.assertIn("formatters.formatCount(totalFlows", block)
        self.assertIn("formatPps(totalPps)", block)


class Phase7RegressionGuardsTest(unittest.TestCase):
    """Fase 7: identidade de campos CGNAT e line endings do index.html."""

    def test_cgnat_pool_fields_have_distinct_ids(self) -> None:
        self.assertEqual(1, HTML.count('id="cgnatPoolName"'))
        self.assertEqual(1, HTML.count('id="cgnatImportPoolName"'))
        self.assertIn('<label for="cgnatImportPoolName">Pool</label>', HTML)
        self.assertIn("pool_name: selectValue('cgnatImportPoolName').trim() || null,", HTML)
        # o formulário de pools continua usando o id original
        self.assertIn("name: selectValue('cgnatPoolName').trim(),", HTML)

    def test_no_html_id_is_declared_twice_in_markup(self) -> None:
        markup = re.sub(r"<script\b.*?</script>", "", STYLE_ONLY, flags=re.DOTALL | re.IGNORECASE)
        ids = re.findall(r'\sid="([^"]+)"', markup)
        duplicates = sorted({value for value in ids if ids.count(value) > 1})
        self.assertEqual([], duplicates)

    def test_index_html_keeps_crlf_line_endings(self) -> None:
        data = HTML_PATH.read_bytes()
        self.assertGreater(data.count(b"\r\n"), 0)
        self.assertEqual(data.count(b"\n"), data.count(b"\r\n"))


if __name__ == "__main__":
    unittest.main()
