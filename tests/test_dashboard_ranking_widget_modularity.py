from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
BACKEND = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")

RANKING_WIDGETS = (
    "top-interfaces",
    "top-protocols",
    "top-asn-external-download",
    "top-asn-external-upload",
    "top-ip-download",
    "top-ip-upload",
)

DEFAULT_GRID_ORDER = (
    "traffic-by-service",
    "top-interfaces",
    "top-protocols",
    "top-conversations",
    "top-asn-external-download",
    "top-asn-external-upload",
    "top-ip-download",
    "top-ip-upload",
    "syn-src",
    "syn-dst",
    "global-summary",
)

ACTIONS = (
    "widget-narrower",
    "widget-wider",
    "widget-shorter",
    "widget-taller",
    "widget-expand",
    "widget-up",
    "widget-down",
    "widget-hide",
)


def grid_block() -> str:
    start = FRONTEND.index('<section id="dashboardWidgetGrid"')
    end = FRONTEND.index("</section>", start)
    return FRONTEND[start:end]


def js_block(start_marker: str, end_marker: str) -> str:
    start = FRONTEND.index(start_marker)
    end = FRONTEND.index(end_marker, start)
    return FRONTEND[start:end]


class RankingWidgetsAreGridWidgetsTest(unittest.TestCase):
    """Os rankings sao widgets reais do mesmo grid de BITS/S e PACKETS/S."""

    def test_rankings_live_inside_the_widget_grid(self) -> None:
        block = grid_block()
        for widget_id in RANKING_WIDGETS:
            self.assertIn(f'data-widget-id="{widget_id}"', block, widget_id)

    def test_traffic_by_service_is_a_widget_too(self) -> None:
        block = grid_block()
        self.assertIn('data-widget-id="traffic-by-service"', block)
        self.assertIn('data-ranking-widget="top-interfaces"', block)

    def test_widgets_use_the_shared_widget_classes(self) -> None:
        block = grid_block()
        for widget_id in RANKING_WIDGETS:
            index = block.index(f'data-widget-id="{widget_id}"')
            opening = block[block.rindex("<div", 0, index):index]
            self.assertIn("dashboard-widget", opening, widget_id)
            self.assertIn("col-12", opening, widget_id)

    def test_every_new_widget_has_the_full_action_bar(self) -> None:
        block = grid_block()
        for widget_id in RANKING_WIDGETS + ("traffic-by-service",):
            start = block.index(f'data-widget-id="{widget_id}"')
            window = block[start:start + 4200]
            for action in ACTIONS:
                self.assertIn(action, window, f"{widget_id}/{action}")

    def test_bits_and_packets_keep_their_widget_contract(self) -> None:
        aggregate = FRONTEND[FRONTEND.index('id="dashboardAggregateSection"'):FRONTEND.index('id="dashboardWidgetGrid"')]
        for widget_id in ("bps-chart", "pps-chart"):
            self.assertIn(f'data-widget-id="{widget_id}"', aggregate)
        for action in ACTIONS:
            self.assertIn(action, aggregate, action)
        # o refresh operacional continua condicionado a visibilidade
        self.assertIn("isDashboardWidgetVisible('bps-chart')", FRONTEND)
        self.assertIn("isDashboardWidgetVisible('pps-chart')", FRONTEND)


class DefaultLayoutTest(unittest.TestCase):
    """Layout default desejado, sem sobrescrever dashboards custom."""

    def test_default_order_constant_matches_expected_layout(self) -> None:
        block = js_block("const DEFAULT_DASHBOARD_GRID_ORDER = [", "];")
        for widget_id in DEFAULT_GRID_ORDER:
            self.assertIn(f"'{widget_id}'", block)
        self.assertEqual(FRONTEND.count("const DEFAULT_DASHBOARD_GRID_ORDER = ["), 1)

    def test_dom_order_matches_the_default_order(self) -> None:
        block = grid_block()
        ids = re.findall(r'data-widget-id="([^"]+)"', block)
        self.assertEqual(tuple(ids), DEFAULT_GRID_ORDER)

    def test_grid_sits_right_after_the_aggregate_strip(self) -> None:
        aggregate = FRONTEND.index('id="dashboardAggregateSection"')
        grid = FRONTEND.index('id="dashboardWidgetGrid"')
        secondary = FRONTEND.index('id="dashboardSecondaryAnalyticsSection"')
        legacy = FRONTEND.index('data-dashboard-legacy-fallback="top-rankings"')
        self.assertLess(aggregate, grid)
        self.assertLess(grid, secondary)
        self.assertLess(secondary, legacy)

    def test_traffic_by_service_keeps_protocol_chart(self) -> None:
        self.assertIn('id="protocolChart"', FRONTEND)
        self.assertIn("protocol-chart", FRONTEND)
        self.assertIn('.dashboard-widget[data-widget-id="traffic-by-service"] .protocol-chart {', FRONTEND)

    def test_default_sizes_cover_the_new_widgets(self) -> None:
        block = js_block("function defaultWidgetSize(widget)", "function saveDashboardLayout()")
        for widget_id in DEFAULT_GRID_ORDER:
            self.assertIn(f"'{widget_id}'", block, widget_id)

    def test_custom_dashboards_keep_their_own_grid(self) -> None:
        # nenhuma alteracao na infra de dashboards configuraveis
        self.assertIn("configurableDashboardGrid", FRONTEND)
        self.assertIn("function renderConfigurableDashboard()", FRONTEND)
        self.assertNotIn("dashboardWidgetGrid .configurable", FRONTEND)
        self.assertNotIn("configurableDashboardGrid", grid_block())


class MoveResizeHideRestoreTest(unittest.TestCase):
    """Mover, redimensionar, ocultar e restaurar sem novas chamadas HTTP."""

    def test_widget_click_handler_supports_all_actions(self) -> None:
        block = js_block("document.getElementById('view-dashboard').addEventListener('click'", "charts.srcIp.on('click'")
        for action in ACTIONS:
            self.assertIn(action, block, action)
        self.assertNotIn("fetchJSON(", block)
        self.assertNotIn("apiRequest(", block)

    def test_hide_updates_bar_and_resizes_without_fetch(self) -> None:
        block = js_block("if (button.classList.contains('widget-hide')) {", "} else if (button.classList.contains('widget-narrower')) {")
        self.assertIn("widget.classList.add('hidden-widget');", block)
        self.assertIn("renderDashboardHiddenWidgetsBar();", block)
        self.assertIn("resizeDashboardCharts();", block)
        self.assertNotIn("fetch", block)

    def test_restore_bar_and_function_exist(self) -> None:
        self.assertIn('id="dashboardHiddenWidgetsBar"', FRONTEND)
        self.assertIn('id="dashboardHiddenWidgetsList"', FRONTEND)
        self.assertIn("function renderDashboardHiddenWidgetsBar()", FRONTEND)
        self.assertIn("function restoreDashboardWidget(widgetId)", FRONTEND)
        self.assertIn("data-widget-restore=", FRONTEND)

    def test_restore_removes_hidden_and_persists_without_fetch(self) -> None:
        block = js_block("function restoreDashboardWidget(widgetId)", "function isDashboardWidgetVisible(")
        self.assertIn("widget.classList.remove('hidden-widget');", block)
        self.assertIn("saveDashboardLayout();", block)
        self.assertIn("renderDashboardHiddenWidgetsBar();", block)
        self.assertIn("resizeDashboardCharts();", block)
        self.assertNotIn("fetch", block)
        self.assertNotIn("apiRequest", block)

    def test_restore_is_wired_on_click(self) -> None:
        block = js_block("document.addEventListener('click', event => {", "document.getElementById('dashboardSeriesLimit')")
        self.assertIn("event.target.closest('[data-widget-restore]')", block)
        self.assertIn("restoreDashboardWidget(restoreButton.dataset.widgetRestore);", block)

    def test_hidden_bar_only_visible_while_editing(self) -> None:
        self.assertIn(".dashboard-editing .dashboard-hidden-widgets-bar:not([hidden]) {", FRONTEND)
        self.assertIn("display: flex;", FRONTEND)

    def test_ranking_chart_follows_widget_resize(self) -> None:
        self.assertIn('.ranking-widget[data-widget-height="medium"] .ranking-chart {', FRONTEND)
        self.assertIn('.ranking-widget[data-widget-height="high"] .ranking-chart {', FRONTEND)
        self.assertIn("resizeRankingCharts();", js_block("function resizeDashboardCharts()", "function shiftWidgetSize("))


class PersistenceTest(unittest.TestCase):
    """Persistencia de ordem, tamanho, visibilidade e viewMode."""

    def test_layout_stores_order_sizes_hidden_and_view_modes(self) -> None:
        block = js_block("function saveDashboardLayout()", "function applyDashboardLayout()")
        self.assertIn("order: dashboardGridWidgets().map(widget => widget.dataset.widgetId),", block)
        self.assertIn("sizes,", block)
        self.assertIn("rankings: { ...rankingViewModes }", block)
        self.assertIn("hidden: widgets.filter(widget => widget.classList.contains('hidden-widget'))", block)

    def test_layout_restores_order_sizes_hidden_and_view_modes(self) -> None:
        block = js_block("function applyDashboardLayout()", "function toggleDashboardEdit()")
        self.assertIn("(layout.order || []).forEach(id => {", block)
        self.assertIn("layout.sizes?.[id]", block)
        self.assertIn("(layout.hidden || []).includes(widget.dataset.widgetId)", block)
        self.assertIn("layout.config?.rankings", block)
        self.assertIn("renderDashboardHiddenWidgetsBar();", block)

    def test_reset_restores_default_order(self) -> None:
        block = js_block("function resetDashboardLayout()", "function isDashboardWidgetVisible(")
        self.assertIn("DEFAULT_DASHBOARD_GRID_ORDER.forEach(id => {", block)
        self.assertIn("rankingViewModes = {};", block)

    def test_grid_widgets_helper_reads_the_shared_grid(self) -> None:
        block = js_block("function dashboardGridWidgets()", "function defaultWidgetSize(")
        self.assertIn("querySelectorAll('#dashboardWidgetGrid .dashboard-widget')", block)

    def test_view_mode_stays_individual_per_widget(self) -> None:
        block = js_block("function setRankingViewMode(widgetId, mode, options = {})", "function applyRankingViewMode(")
        self.assertIn("rankingViewModes[widgetId] = normalized;", block)
        self.assertNotIn("RANKING_WIDGET_IDS.forEach", block)


class NoExtraRequestsTest(unittest.TestCase):
    """Mover/redimensionar/restaurar nao disparam API."""

    def test_move_resize_helpers_do_not_call_api(self) -> None:
        for marker, end in (
            ("function shiftWidgetSize(widget, kind, delta)", "async function loadIngestionStatus()"),
            ("function renderDashboardHiddenWidgetsBar()", "function restoreDashboardWidget("),
            ("function restoreDashboardWidget(widgetId)", "function isDashboardWidgetVisible("),
        ):
            block = js_block(marker, end)
            self.assertNotIn("fetchJSON(", block, marker)
            self.assertNotIn("apiRequest(", block, marker)

    def test_backend_unchanged_for_this_feature(self) -> None:
        for token in ("ranking_view_mode", "widget_view_mode", "view_mode"):
            self.assertNotIn(token, BACKEND)
        self.assertIn('@app.get("/api/dashboard/directional-analytics")', BACKEND)

    def test_refresh_keeps_the_same_endpoints(self) -> None:
        block = js_block("const entries = [", "const progressiveEntries")
        for endpoint in ("/api/tops/src-ip", "/api/dashboard/directional-analytics", "/api/tops/protocols"):
            self.assertIn(endpoint, block)
        self.assertNotIn("/api/dashboard/ranking", block)


class UniqueIdsTest(unittest.TestCase):
    """IDs unicos: nenhum id de markup ou widget duplicado."""

    def test_widget_ids_are_unique(self) -> None:
        # apenas atributos declarados em tags <div ...> do markup
        ids = re.findall(r'<div[^>]*data-widget-id="([^"]+)"', FRONTEND)
        self.assertEqual(len(ids), len(set(ids)), "data-widget-id duplicado")
        self.assertGreaterEqual(len(ids), len(DEFAULT_GRID_ORDER) + 2)

    def test_ranking_widget_markers_are_unique_per_widget(self) -> None:
        for widget_id in RANKING_WIDGETS:
            self.assertEqual(FRONTEND.count(f'data-ranking-widget="{widget_id}"'), 1, widget_id)

    def test_widget_internal_ids_are_unique(self) -> None:
        # ids funcionais usados pelos renders nao podem colidir
        for element_id in (
            "protocolSectionTitle",
            "protocolSectionMeta",
            "protocolChart",
            "topInterfacesMeta",
            "topInterfacesTable",
            "secondaryProtocolsMeta",
            "secondaryProtocolsTable",
            "externalAsnDownloadMeta",
            "externalAsnDownloadTable",
            "externalAsnUploadMeta",
            "externalAsnUploadTable",
            "localIpDownloadMeta",
            "localIpDownloadTable",
            "localIpUploadMeta",
            "localIpUploadTable",
            "dashboardHiddenWidgetsBar",
            "dashboardHiddenWidgetsList",
        ):
            self.assertEqual(
                len(re.findall(r'\sid="%s"' % element_id, FRONTEND)),
                1,
                element_id,
            )

    def test_ranking_toggles_and_targets_match_widgets(self) -> None:
        self.assertEqual(FRONTEND.count('class="btn-group btn-group-sm ranking-view-toggle"'), 6)
        for widget_id in RANKING_WIDGETS:
            start = FRONTEND.index(f'data-ranking-widget="{widget_id}"')
            window = FRONTEND[start:start + 9000]
            self.assertIn("data-ranking-chart", window, widget_id)
            self.assertIn("data-ranking-table", window, widget_id)


if __name__ == "__main__":
    unittest.main()
