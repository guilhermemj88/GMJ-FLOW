import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FORMATTERS = (ROOT / "frontend" / "dashboard-formatters.js").read_text(
    encoding="utf-8"
)
RESIZE = (ROOT / "frontend" / "dashboard-resize.js").read_text(
    encoding="utf-8"
)
CHARTS = (ROOT / "frontend" / "dashboard-charts.js").read_text(
    encoding="utf-8"
)
TIME_RANGE = (ROOT / "frontend" / "dashboard-time-range.js").read_text(
    encoding="utf-8"
)
VISUALIZATIONS = (
    ROOT / "frontend" / "dashboard-visualizations.js"
).read_text(encoding="utf-8")
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
BACKEND = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
HARNESS = ROOT / "tests" / "dashboard_frontend_harness.html"
EDGE_CANDIDATES = (
    pathlib.Path(
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    ),
    pathlib.Path(
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    ),
)


class DashboardFormatterContractTest(unittest.TestCase):
    def test_required_formatter_functions_are_exported(self):
        required = (
            "formatBitsPerSecond",
            "formatPacketsPerSecond",
            "formatBytes",
            "formatCount",
            "formatPercentage",
            "formatLatency",
            "formatDuration",
            "formatMetricValue",
            "formatAxisValue",
            "formatTooltipValue",
            "formatTableValue",
            "selectMetricScale",
        )
        exports = FORMATTERS[FORMATTERS.find("return Object.freeze") :]
        for name in required:
            self.assertIn("function %s(" % name, FORMATTERS)
            self.assertIn(name, exports)
        self.assertIn("const LOCALE = 'pt-BR'", FORMATTERS)
        self.assertNotIn("toFixed(", FORMATTERS)

    def test_configurable_widgets_use_one_metric_scale_everywhere(self):
        for token in (
            '<script src="dashboard-formatters.js"></script>',
            "configurableSeriesMaximum",
            "configurableItemsMaximum",
            "selectMetricScale(",
            "formatAxisValue(",
            "formatTooltipValue(",
            "formatTableValue(",
            "formatPercentage(",
            "legend:",
            "axisLabel:",
        ):
            self.assertIn(token, FRONTEND)

    def test_backend_keeps_numeric_values_and_adds_metadata(self):
        self.assertIn("def dashboard_widget_metric_metadata(", BACKEND)
        self.assertIn('"value_kind": value_kind', BACKEND)
        self.assertIn('"unit": unit', BACKEND)
        self.assertIn("**dashboard_widget_metric_metadata(", BACKEND)


class DashboardResizeContractTest(unittest.TestCase):
    def test_required_resize_functions_are_exported(self):
        required = (
            "pixelWidthToGridColumns",
            "pixelHeightToGridRows",
            "gridColumnsToPixelWidth",
            "gridRowsToPixelHeight",
            "snapWidgetSize",
        )
        exports = RESIZE[RESIZE.find("return Object.freeze") :]
        for name in required:
            self.assertIn("function %s(" % name, RESIZE)
            self.assertIn(name, exports)
        self.assertIn("layoutEngine.resizeItemAndPush(", RESIZE)
        self.assertIn("layoutEngine.calculateResizePreview", RESIZE)
        self.assertIn("layoutEngine.commitLayoutInteraction", RESIZE)
        self.assertIn("createDashboardMoveController", RESIZE)

    def test_pointer_keyboard_permissions_and_single_commit_contract(self):
        for token in (
            "'pointerdown'",
            "'pointermove'",
            "'pointerup'",
            "'pointercancel'",
            "'ArrowLeft'",
            "'ArrowRight'",
            "'ArrowUp'",
            "'ArrowDown'",
            "'Escape'",
            "'Enter'",
            "setPointerCapture",
            "releasePointerCapture",
            "'lostpointercapture'",
            "DEFAULT_DRAG_THRESHOLD",
            "Math.hypot(deltaX, deltaY) < threshold",
            "requestAnimationFrame",
            "session.persisting",
            "await options.onPersist?.(",
            "await options.onRollback?.(",
        ):
            self.assertIn(token, RESIZE)
        self.assertNotIn("onPersist?.", RESIZE[RESIZE.find("function onPointerMove") :])
        self.assertIn("3px solid", FRONTEND)
        self.assertIn("is-drop-valid", FRONTEND)

    def test_dom_has_handles_edit_mode_and_containment(self):
        for token in (
            "let dashboardEditMode = false",
            "Finalizar edição",
            'data-resize-handle="e"',
            'data-resize-handle="s"',
            'data-resize-handle="se"',
            'role="separator"',
            'aria-label="Redimensionar',
            "widget-resize-badge",
            ".is-resizing",
            "e-resize",
            "s-resize",
            "se-resize",
            "touch-action: none",
            "overflow: auto",
            "position: sticky",
            'draggable="false"',
        ):
            self.assertIn(token, FRONTEND)
        self.assertNotIn("grid.addEventListener('dragstart'", FRONTEND)
        self.assertNotIn("'text/widget-id'", FRONTEND)

    def test_resize_persists_desktop_grid_and_preserves_height_fields(self):
        for token in (
            "installConfigurableWidgetResize",
            "getResponsiveColumns: configurableResponsiveColumns",
            "configurableResponsiveColumns",
            "updateConfigurableDashboardGridPositions",
            "scheduleConfigurableChartResize",
            "commitConfigurableLayout",
            "/layout",
            "Idempotency-Key",
            "observer.observe(body.closest('.configurable-dashboard-widget') || body)",
        ):
            self.assertIn(token, FRONTEND)

    def test_container_responsive_chart_table_contract(self):
        for token in (
            "DEFAULT_WIDGET_BREAKPOINTS",
            "normalizeWidgetBreakpoints",
            "getWidgetResponsiveLayout",
            "applyWidgetResponsiveLayout",
            "getResponsiveLegendLayout",
            "getResponsivePieGeometry",
            "function debounce(",
        ):
            self.assertIn(token, CHARTS)
        for token in (
            'data-widget-tab-panel="layout"',
            "widgetConfigStackedBreakpoint",
            "widgetConfigWideBreakpoint",
            'data-responsive-layout="stacked"',
            "configurable-ranking-table",
            "ranking-col-value",
            "ranking-col-percent",
            "table-layout: fixed",
            "overflow-x: hidden",
            "updateConfigurableChartResponsiveness",
            "configurableWidgetChartResponsiveContexts",
            "textBorderWidth",
            "opacity: 1",
        ):
            self.assertIn(token, FRONTEND)
        observer_block = FRONTEND[
            FRONTEND.find("function observeConfigurableWidgetSize("):
            FRONTEND.find("function configurableAppearanceFromForm(")
        ]
        self.assertIn("ResizeObserver", observer_block)
        self.assertIn("GMJDashboardCharts.debounce", observer_block)
        self.assertNotIn("patchConfigurableWidget(", observer_block)
        self.assertNotIn("@media (max-width: 820px)", FRONTEND)

    def test_ranking_quality_identity_and_layout_race_contracts(self):
        for token in (
            "groupRankingItems",
            "chart_table",
            "configurable-ranking-combined",
            "chart_table_ratio",
            "slice_limit",
            "openAsnDetails",
            "/api/asn/info?asns=",
            "/api/asn/details?asn=",
            "/api/ip/whois?ip=",
            "configurableQualityStatus",
            "last_complete_sample_at",
            "configurableLayoutCommitQueue",
            "performConfigurableLayoutCommit",
            "stale_response_ignored",
            "configurableWidgetAutoHeightTimers.clear()",
        ):
            self.assertIn(token, FRONTEND)
        self.assertIn(
            "button, a, input, select, textarea, table, .widget-content, .scroll-container",
            RESIZE,
        )


class DashboardChartContractTest(unittest.TestCase):
    def test_safe_refresh_density_and_appearance_contract(self):
        for token in (
            "DEFAULT_APPEARANCE",
            "normalizeAppearance",
            "consolidateDirectionSeries",
            "getChartDensityMode",
            "replaceChartOption",
            "notMerge: true",
            "replaceMerge: ['series', 'xAxis', 'yAxis']",
            "chart.off?.()",
        ):
            self.assertIn(token, CHARTS)
        for token in (
            '<script src="dashboard-charts.js"></script>',
            "GMJDashboardCharts.replaceChartOption",
            "minimum_slice_label_percent",
            "labelLayout: { hideOverlap: true }",
            "containLabel: true",
            "hideOverlap: true",
        ):
            self.assertIn(token, FRONTEND)

    def test_global_time_range_controls_axis_requests_and_cache(self):
        for token in (
            "buildRangeContext",
            "contextSignature",
            "formatUtcTimestamp",
            "widgetCacheKey",
            "createRequestGate",
        ):
            self.assertIn(token, TIME_RANGE)
        self.assertIn("timeZone: 'UTC'", TIME_RANGE)
        for token in (
            '<script src="dashboard-time-range.js"></script>',
            "activateConfigurableDashboardContext",
            "configurableRangeRequestGate.isCurrent",
            "maximum_data_points",
            "min: effectiveRange.start || undefined",
            "max: effectiveRange.end || undefined",
            "configurableTimestampLabel(pointTimestamp)",
            "dashboard_debug_period",
            "useUTC: true",
        ):
            self.assertIn(token, FRONTEND)
        configurable_block = FRONTEND[
            FRONTEND.find("function configurableDashboardContext("):
            FRONTEND.find("function clearConfigurableWidgetRuntime(")
        ]
        self.assertNotIn(".slice(-", configurable_block)

    def test_visualization_data_contract_and_split_zero(self):
        for token in (
            "dataQuerySignature",
            "normalizeRankingPayload",
            "rankingDataset",
            "calculatePoints",
            "normalizedFieldConfig",
            "buildTrafficModel",
            "last_not_null",
            "split_zero",
            "original_points",
            "legend_value",
        ):
            self.assertIn(token, VISUALIZATIONS)
        for token in (
            '<script src="dashboard-visualizations.js"></script>',
            "GMJDashboardVisualizations.visualizationKind",
            "GMJDashboardVisualizations.buildTrafficModel",
            "dashboardWidgetInspectorModal",
            "configurableDeferredWidgetPayloads",
        ):
            self.assertIn(token, FRONTEND)


class DashboardBrowserHarnessTest(unittest.TestCase):
    def test_real_browser_formatter_and_pointer_flow(self):
        edge = next((path for path in EDGE_CANDIDATES if path.exists()), None)
        if edge is None:
            self.skipTest("Microsoft Edge não está disponível")
        with tempfile.TemporaryDirectory(prefix="gmj-dashboard-edge-") as profile:
            completed = subprocess.run(
                [
                    str(edge),
                    "--headless=new",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--no-first-run",
                    "--force-time-zone=America/Sao_Paulo",
                    "--allow-file-access-from-files",
                    "--virtual-time-budget=3000",
                    "--user-data-dir=%s" % profile,
                    "--dump-dom",
                    HARNESS.resolve().as_uri(),
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr[-4000:],
        )
        self.assertIn(
            'data-status="passed"',
            completed.stdout,
            completed.stdout[-4000:],
        )
        self.assertIn("DASHBOARD_FRONTEND_TESTS_OK", completed.stdout)


if __name__ == "__main__":
    unittest.main()
