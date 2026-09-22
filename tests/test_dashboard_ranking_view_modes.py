from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

RANKING_WIDGETS = (
    "top-interfaces",
    "top-protocols",
    "top-asn-external-download",
    "top-asn-external-upload",
    "top-ip-download",
    "top-ip-upload",
)

RANKING_VIEW_MODES = ("table", "chart", "both")


def widget_window(widget_id: str, size: int = 9000) -> str:
    """Trecho do HTML a partir do widget de ranking (janela suficiente p/ o card)."""
    index = FRONTEND.index(f'data-ranking-widget="{widget_id}"')
    return FRONTEND[index:index + size]


def js_block(start_marker: str, end_marker: str) -> str:
    start = FRONTEND.index(start_marker)
    end = FRONTEND.index(end_marker, start)
    return FRONTEND[start:end]


class RankingWidgetToggleTest(unittest.TestCase):
    """1-3: cada widget de ranking oferece Tabela | Grafico | Ambos."""

    def test_every_ranking_widget_is_marked(self) -> None:
        for widget_id in RANKING_WIDGETS:
            self.assertIn(f'data-ranking-widget="{widget_id}"', FRONTEND)

    def test_each_widget_has_the_three_modes(self) -> None:
        for widget_id in RANKING_WIDGETS:
            block = widget_window(widget_id, 9000)
            for mode in RANKING_VIEW_MODES:
                self.assertIn(f'data-ranking-view="{mode}"', block, widget_id)

    def test_each_widget_has_chart_and_table_targets(self) -> None:
        for widget_id in RANKING_WIDGETS:
            block = widget_window(widget_id, 9000)
            self.assertIn("data-ranking-chart", block, widget_id)
            self.assertIn("data-ranking-table", block, widget_id)

    def test_toggle_uses_existing_button_group_style(self) -> None:
        # integra a toolbar existente (mesmo padrao do toggle de direcao)
        self.assertEqual(FRONTEND.count('class="btn-group btn-group-sm ranking-view-toggle"'), 6)
        self.assertIn(".ranking-view-toggle .btn {", FRONTEND)

    def test_chart_mode_hides_table_and_vice_versa(self) -> None:
        block = js_block("function applyRankingViewMode(widgetId)", "function disposeRankingChart(")
        self.assertIn("const showChart = mode === 'chart' || mode === 'both';", block)
        self.assertIn("const showTable = mode === 'table' || mode === 'both';", block)
        self.assertIn("tableWrap.hidden = !showTable;", block)
        self.assertIn("chartContainer.hidden = !showChart;", block)

    def test_both_mode_uses_compact_chart_height(self) -> None:
        self.assertIn('.ranking-widget[data-ranking-mode="both"] .ranking-chart {', FRONTEND)
        self.assertIn('.ranking-widget[data-ranking-mode="chart"] .ranking-chart {', FRONTEND)


class RankingWidgetPersistenceTest(unittest.TestCase):
    """4-5: persistencia individual por widget no layout do dashboard."""

    def test_view_mode_is_persisted_with_layout(self) -> None:
        block = js_block("function saveDashboardLayout()", "function applyDashboardLayout()")
        self.assertIn("rankings: { ...rankingViewModes }", block)

    def test_view_mode_is_restored_from_layout(self) -> None:
        block = js_block("function applyDashboardLayout()", "function toggleDashboardEdit()")
        self.assertIn("layout.config?.rankings", block)
        self.assertIn("RANKING_WIDGET_IDS.forEach(id => applyRankingViewMode(id));", block)

    def test_reset_returns_to_default_mode(self) -> None:
        block = js_block("function resetDashboardLayout()", "function isDashboardWidgetVisible(")
        self.assertIn("rankingViewModes = {};", block)
        self.assertIn("RANKING_WIDGET_IDS.forEach(id => applyRankingViewMode(id));", block)

    def test_set_mode_touches_only_the_target_widget(self) -> None:
        block = js_block("function setRankingViewMode(widgetId, mode, options = {})", "function applyRankingViewMode(widgetId)")
        self.assertIn("rankingViewModes[widgetId] = normalized;", block)
        self.assertIn("applyRankingViewMode(widgetId);", block)
        self.assertNotIn("RANKING_WIDGET_IDS.forEach", block)

    def test_legacy_layouts_without_view_mode_default_to_table(self) -> None:
        self.assertIn("const DEFAULT_RANKING_VIEW_MODE = 'table';", FRONTEND)
        block = js_block("function rankingViewMode(widgetId)", "function setRankingViewMode(")
        self.assertIn("RANKING_VIEW_MODES.includes(mode) ? mode : DEFAULT_RANKING_VIEW_MODE", block)

    def test_custom_dashboards_are_not_touched(self) -> None:
        # nenhuma alteracao na infra de dashboards configuraveis
        self.assertNotIn("configurable-dashboard-widget[data-ranking-widget", FRONTEND)
        block = js_block("function saveDashboardLayout()", "function applyDashboardLayout()")
        self.assertNotIn("configurable", block)


class RankingWidgetDataTest(unittest.TestCase):
    """6, 10-11: tabela e grafico usam o MESMO payload; IP/IPv6 completo no tooltip."""

    def test_table_and_chart_share_the_same_rows(self) -> None:
        for marker, widget_id in (
            ("function renderTopInterfaces(interfaces)", "top-interfaces"),
            ("function renderSecondaryProtocols(items)", "top-protocols"),
            ("function renderDirectionalAsnTable(tableId, metaId, items, emptyLabel)", "RANKING_TABLE_WIDGETS[tableId]"),
            ("function renderDirectionalIpTable(tableId, metaId, items, emptyLabel)", "RANKING_TABLE_WIDGETS[tableId]"),
        ):
            block = js_block(marker, "\n    function ")
            self.assertIn("updateRankingWidget(", block, marker)

    def test_no_extra_request_when_switching_view(self) -> None:
        toggle_block = js_block(
            "const button = event.target.closest('.ranking-view-toggle button[data-ranking-view]');",
            "document.getElementById('dashboardSeriesLimit')",
        )
        self.assertIn("setRankingViewMode(", toggle_block)
        self.assertNotIn("fetch", toggle_block)
        self.assertNotIn("apiRequest", toggle_block)

    def test_render_helpers_do_not_call_api(self) -> None:
        for marker in (
            "function renderRankingChartFor(widgetId, attempt = 0)",
            "function rankingBarOption(rows, options = {})",
            "function updateRankingWidget(widgetId, payload)",
        ):
            block = js_block(marker, "\n    function ")
            self.assertNotIn("fetchJSON(", block, marker)
            self.assertNotIn("apiRequest(", block, marker)

    def test_long_labels_are_truncated_but_tooltip_keeps_full_value(self) -> None:
        self.assertIn("function truncateRankingLabel(value, maximum = 22)", FRONTEND)
        option_block = js_block("function rankingBarOption(rows, options = {})", "function renderRankingChartFor(")
        # eixo usa o label truncado
        self.assertIn("formatter: value => truncateRankingLabel(value)", option_block)
        # tooltip usa o label completo + valor formatado + share
        self.assertIn("const head = item.secondary", option_block)
        self.assertIn("formatter(item.value)", option_block)
        self.assertIn("share.toFixed(1)", option_block)

    def test_ipv6_value_is_not_truncated_internally(self) -> None:
        block = js_block("function renderDirectionalIpTable(", "\n    function ")
        self.assertIn("rows: rows.map(item => ({ label: item.ip || '—', value: Number(item.bps) || 0 })),", block)
        self.assertIn("escapeHtml(item.ip || '—')", block)

    def test_metric_stays_configurable_bits_and_packets(self) -> None:
        option_block = js_block("function rankingBarOption(rows, options = {})", "function renderRankingChartFor(")
        self.assertIn("const metric = options.metric || 'bits_s';", option_block)
        self.assertIn("metricFormatter(metricFromApi(metric))", option_block)


class RankingWidgetResizeTest(unittest.TestCase):
    """9: resize acompanha o container sem nova API."""

    def test_ranking_charts_follow_dashboard_resize(self) -> None:
        block = js_block("function resizeDashboardCharts()", "function shiftWidgetSize(")
        self.assertIn("resizeRankingCharts();", block)

    def test_window_resize_also_resizes_ranking_charts(self) -> None:
        block = js_block("window.addEventListener('resize', () => {", "document.addEventListener('visibilitychange'")
        self.assertIn("resizeRankingCharts();", block)

    def test_chart_waits_for_visible_container(self) -> None:
        block = js_block("function renderRankingChartFor(widgetId, attempt = 0)", "\n    function ")
        self.assertIn("container.clientWidth", block)
        self.assertIn("container.clientHeight", block)


class TopAsnOriginRemovalTest(unittest.TestCase):
    """14: o card antigo e redundante saiu do overview default."""

    def test_card_is_gone_from_default_overview(self) -> None:
        self.assertNotIn('id="secondaryAsnTable"', FRONTEND)
        self.assertNotIn("Top ASN de origem", FRONTEND)
        self.assertNotIn("renderSecondaryAsnSrc", FRONTEND)

    def test_shared_data_source_is_still_present(self) -> None:
        self.assertIn('id="asnSrcTable"', FRONTEND)
        self.assertIn('id="externalAsnUploadTable"', FRONTEND)

    def test_backend_and_api_untouched(self) -> None:
        backend = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        self.assertIn('@app.post("/api/dashboards/{dashboard_id}/widgets/{widget_id}/query")', backend)
        self.assertIn("def directional_analytics_payload(", backend)


class RankingComponentReuseTest(unittest.TestCase):
    """12-13, 15: componente unico reutilizado pelos rankings."""

    def test_single_component_serves_all_rankings(self) -> None:
        self.assertEqual(FRONTEND.count("function rankingBarOption(rows, options = {})"), 1)
        self.assertEqual(FRONTEND.count("function updateRankingWidget(widgetId, payload)"), 1)
        self.assertEqual(FRONTEND.count("function renderRankingChartFor(widgetId, attempt = 0)"), 1)

    def test_every_ranking_render_publishes_rows(self) -> None:
        self.assertGreaterEqual(FRONTEND.count("updateRankingWidget("), 9)  # 1 def + 8 chamadas

    def test_protocol_colors_reuse_protocol_palette(self) -> None:
        block = js_block("function renderSecondaryProtocols(items)", "\n    function ")
        self.assertIn("color: row => protocolPalette[row.label] || palette[0]", block)

    def test_ranking_ids_map_is_consistent(self) -> None:
        block = js_block("const RANKING_TABLE_WIDGETS = {", "};")
        for table_id in (
            "topInterfacesTable",
            "secondaryProtocolsTable",
            "externalAsnDownloadTable",
            "externalAsnUploadTable",
            "localIpDownloadTable",
            "localIpUploadTable",
        ):
            self.assertIn(table_id, block)
        for widget_id in RANKING_WIDGETS:
            self.assertIn(f"'{widget_id}'", block)

    def test_script_has_no_syntax_placeholder_issues(self) -> None:
        # os blocos novos nao deixam marcadores de template pendentes
        for marker in ("rankingBarOption", "applyRankingViewMode", "renderRankingChartFor"):
            self.assertNotIn(f"{marker}(...) ", FRONTEND)
        self.assertEqual(FRONTEND.count("RANKING_VIEW_MODES = ['table', 'chart', 'both']"), 1)


if __name__ == "__main__":
    unittest.main()
