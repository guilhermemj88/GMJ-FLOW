import pathlib
import json
import re
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


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
PREFIX_CONTROLS = (
    ROOT / "frontend" / "dashboard-prefix-controls.js"
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
            "'mouseup'",
            "'blur'",
            "'visibilitychange'",
            "addTemporaryGestureListeners",
            "DEFAULT_DRAG_THRESHOLD",
            "Math.hypot(deltaX, deltaY) < threshold",
            "requestAnimationFrame",
            "current.persisting",
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
            "configurable-dashboard-widget-drag-surface",
            "data-widget-drag-handle",
        ):
            self.assertIn(token, FRONTEND)
        self.assertNotIn("grid.addEventListener('dragstart'", FRONTEND)
        self.assertNotIn("'text/widget-id'", FRONTEND)
        self.assertNotIn("configurable-widget-drag-handle", FRONTEND)
        self.assertNotIn("configurable-widget-left", FRONTEND)
        self.assertIsNone(
            re.search(r"<button[^>]+data-widget-drag-handle", FRONTEND)
        )

    def test_core_top_rankings_use_editable_widget_controls(self):
        legacy_section_start = FRONTEND.index(
            'data-dashboard-legacy-fallback="top-rankings"'
        )
        legacy_section_end = FRONTEND.index(
            '<section class="row g-3 mt-1">',
            legacy_section_start,
        )
        legacy_section = FRONTEND[legacy_section_start:legacy_section_end]
        for widget_key in ("top-src-ip", "top-dst-ip", "top-ports"):
            self.assertIn(
                'dashboard-widget legacy-dashboard-widget" '
                f'data-widget-id="{widget_key}"',
                legacy_section,
            )
            widget_start = legacy_section.index(
                f'data-widget-id="{widget_key}"'
            )
            next_widget = legacy_section.find(
                'class="col-12 col-xl-4 dashboard-widget',
                widget_start + 1,
            )
            widget_source = legacy_section[
                widget_start:next_widget if next_widget >= 0 else None
            ]
            self.assertIn('class="widget-actions"', widget_source)
            for action in (
                "widget-narrower",
                "widget-wider",
                "widget-shorter",
                "widget-taller",
                "widget-expand",
                "widget-up",
                "widget-down",
                "widget-hide",
            ):
                self.assertIn(action, widget_source)

        renderer = FRONTEND[
            FRONTEND.index("function renderConfigurableDashboard()"):
            FRONTEND.index("function syncConfigurableDashboardSelector(")
        ]
        for token in (
            'class="configurable-dashboard-widget',
            'data-widget-id="${widget.id}"',
            'data-widget-key="${escapeHtml(widget.widget_key || \'\')}"',
            'data-widget-editable="${Boolean(configurableDashboard.permissions?.can_edit)}"',
            "configurable-dashboard-widget-drag-surface",
            "configurable-widget-edit",
            "configurable-widget-wider",
            "configurable-widget-hide",
            "configurable-widget-delete",
            'data-resize-handle="e"',
            'data-resize-handle="s"',
            'data-resize-handle="se"',
        ):
            self.assertIn(token, renderer)
        self.assertIn(
            "#view-dashboard.dashboard-engine-active > section:not(#configurableDashboardGrid):not(#dashboardPrefixControls)",
            FRONTEND,
        )
        self.assertIn("function setLegacyTopRankingsFallbackVisible(visible)", FRONTEND)
        self.assertIn("setLegacyTopRankingsFallbackVisible(false)", FRONTEND)
        self.assertIn("setLegacyTopRankingsFallbackVisible(true)", FRONTEND)
        self.assertIn(".dashboard-editing .widget-actions", FRONTEND)
        self.assertIn(
            "#view-dashboard.dashboard-engine-active:not(.dashboard-editing)",
            FRONTEND,
        )

    def test_core_top_rankings_keep_configurable_appearance_and_refresh_paths(self):
        for token in (
            'id="widgetConfigTitle"',
            'id="widgetConfigVisualization"',
            'id="widgetConfigPaletteMode"',
            'id="widgetConfigBarColor"',
            "refresh_interval_seconds",
            "scheduleConfigurableWidgetRefresh(widget)",
            "queryConfigurableWidget(widget, { force: true })",
            "configurableRankingIdentity(item)",
            "configurable-drilldown",
        ):
            self.assertIn(token, FRONTEND)
        migration_block = BACKEND[
            BACKEND.index('legacy_to_widget = {'):
            BACKEND.index('width_map = {', BACKEND.index('legacy_to_widget = {'))
        ]
        for mapping in (
            '"top-src-ip": "top-src-ip"',
            '"top-dst-ip": "top-dst-ip"',
            '"top-ports": "top-ports"',
        ):
            self.assertIn(mapping, migration_block)

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
            "getWidgetContentMetrics",
            "--widget-scale",
            "--widget-font-size",
            "--widget-label-size",
            "--widget-gap",
            "--widget-row-height",
            "data-chart-scroll",
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

    def test_asn_dimension_orientation_round_trip_contract(self):
        for token in (
            'id="widgetConfigDimension"',
            'id="widgetConfigFlowOrientation"',
            "config.dimension = document.getElementById('widgetConfigDimension').value",
            "config.flow_orientation =",
            "item.config?.flow_orientation || 'canonical'",
            "widgetConfigFlowOrientation: baseType === 'top_n'",
        ):
            self.assertIn(token, FRONTEND)

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
            "button, a, input, select, textarea, table, [data-resize-handle]",
            RESIZE,
        )
        for protected_target in (
            ".widget-actions",
            ".configurable-dashboard-widget-body",
            ".configurable-dashboard-widget-chart",
            ".gmj-dashboard-chart-tooltip",
        ):
            self.assertIn(protected_target, FRONTEND)

    def test_distinct_colors_external_tooltip_and_bounded_legend(self):
        for token in (
            "DISTINCT_SERIES_PALETTE",
            "assignSeriesColors",
            "stableSeriesHash",
            "seriesContrastRatio",
            "positionFloatingTooltip",
            "externalTooltipOptions",
            "appendToBody: true",
            "confine: false",
            "sortTooltipRows",
            "maxRows: 1",
        ):
            self.assertIn(token, CHARTS)
        for token in (
            "configurableWidgetSeriesColorRegistries",
            "configurableSeriesColorAssignments",
            "gmj-dashboard-chart-tooltip",
            "GMJDashboardCharts.externalTooltipOptions()",
            "GMJDashboardCharts.sortTooltipRows(",
            "type: 'scroll'",
            "renderConfigurableLegendMore",
            "Ver mais (${items.length})",
        ):
            self.assertIn(token, FRONTEND)

    def test_prefix_controls_are_collapsible_persistent_and_responsive(self):
        for token in (
            '<script src="dashboard-prefix-controls.js"></script>',
            "dashboardPrefixControlsHeader",
            "dashboardPrefixControlsBody",
            "dashboardPrefixStateBadge",
            "dashboardPrefixClearCompact",
            "collapseDashboardPrefixFilter",
            "is-collapsed",
            "grid-template-columns: minmax(0, 1fr)",
            "expandForError()",
        ):
            self.assertIn(token, FRONTEND)
        for token in (
            "gmjflow.dashboard-prefix-controls.collapsed.v1",
            "storageKey",
            "readCollapsed",
            "writeCollapsed",
            "prefixSummaryState",
            "createController",
            "fallback = true",
        ):
            self.assertIn(token, PREFIX_CONTROLS)

        controller_source = FRONTEND[
            FRONTEND.index("function ensureConfigurablePrefixControlsController()"):
            FRONTEND.index("function renderConfigurablePrefixCatalog()")
        ]
        self.assertIn("const prefixControlsApi = window.GMJDashboardPrefixControls;", controller_source)
        self.assertIn("typeof prefixControlsApi.createController !== 'function'", controller_source)
        self.assertIn("dashboard-prefix-controls.js não foi carregado.", controller_source)

        load_source = FRONTEND[
            FRONTEND.index("async function loadConfigurableDashboard("):
            FRONTEND.index("async function initializeConfigurableDashboards()")
        ]
        self.assertLess(
            load_source.index("renderConfigurableDashboard();"),
            load_source.index("setLegacyTopRankingsFallbackVisible(false);")
        )
        for token in (
            "configurableDashboardActive = false;",
            "setLegacyTopRankingsFallbackVisible(true);",
            "classList.remove('dashboard-engine-active')",
            "Falha ao renderizar dashboard configurável; usando layout legado.",
        ):
            self.assertIn(token, load_source)

        bootstrap_source = FRONTEND[
            FRONTEND.index("mountDetectionTemplateSection();"):
            FRONTEND.index("window.addEventListener('beforeunload'")
        ]
        self.assertIn("try {\n      installConfigurableDashboardEvents();", bootstrap_source)
        self.assertIn("Falha ao instalar controles configuráveis do dashboard.", bootstrap_source)
        self.assertLess(
            bootstrap_source.index("installConfigurableDashboardEvents();"),
            bootstrap_source.index("initAuth().then(")
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
        self.assertIn("timeZone: 'America/Sao_Paulo'", TIME_RANGE)
        self.assertNotIn("timeZone: 'UTC'", TIME_RANGE)
        for token in (
            '<script src="dashboard-time-range.js"></script>',
            "activateConfigurableDashboardContext",
            "configurableRangeRequestGate.isCurrent",
            "maximum_data_points",
            "min: effectiveRange.start || undefined",
            "max: effectiveRange.end || undefined",
            "configurableTimestampLabel(pointTimestamp)",
            "dashboard_debug_period",
            "useUTC: false",
            "formatter: value => configurableTimestampLabel(value)",
            "Sem dados · BRT",
            "Dados atrasados",
            "Última completa",
            "America/Sao_Paulo (BRT)",
        ):
            self.assertIn(token, FRONTEND)
        self.assertNotIn("Sem dados · UTC", FRONTEND)
        self.assertNotIn("${lastLabel} UTC", FRONTEND)
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

    def test_real_browser_renders_core_top_widget_actions_in_edit_mode(self):
        edge = next((path for path in EDGE_CANDIDATES if path.exists()), None)
        if edge is None:
            self.skipTest("Microsoft Edge nÃ£o estÃ¡ disponÃ­vel")

        widgets = [
            {
                "id": index,
                "dashboard_id": 1,
                "widget_key": widget_key,
                "type": "top_n",
                "title": title,
                "description": "",
                "category": "traffic",
                "config": {
                    "dimension": dimension,
                    "metric": "bps",
                    "direction": direction,
                    "limit": 10,
                    "visualization": visualization,
                    "appearance": {"palette_mode": "default"},
                },
                "filters": [],
                "visualization": {
                    "type": visualization,
                    "show_legend": True,
                },
                "grid": {"x": (index - 1) * 4, "y": 0, "w": 4, "h": 6},
                "collapsed": False,
                "hidden": False,
                "height_mode": "fixed",
                "refresh_interval_seconds": 30,
                "use_global_filters": True,
                "use_global_time_range": True,
                "inheritance": {},
                "custom_time_range": {},
            }
            for index, (widget_key, title, dimension, direction, visualization) in enumerate(
                (
                    ("top-src-ip", "Top IP origem", "src_ip", "source", "horizontal_bar"),
                    ("top-dst-ip", "Top IP destino", "dst_ip", "destination", "horizontal_bar"),
                    ("top-ports", "Top portas", "dst_port", "both", "bar"),
                ),
                start=1,
            )
        ]
        dashboard = {
            "id": 1,
            "name": "Meu Dashboard",
            "owner_user_id": 1,
            "is_default": True,
            "is_shared": False,
            "is_system": False,
            "legacy_layout_migrated": True,
            "core_top_widgets_migrated": True,
            "layout_mode": "custom",
            "compact_mode": "none",
            "time_range": {"mode": "relative", "minutes": 10},
            "refresh_interval_seconds": 30,
            "layout_version": 3,
            "revision": 3,
            "permissions": {"can_view": True, "can_edit": True, "can_delete": True},
            "widgets": widgets,
        }
        served_html = FRONTEND.replace(
            "<title>GMJ-FLOW</title>",
            "<script>localStorage.setItem('gmjFlowAuthToken','dashboard-test');</script><title>GMJ-FLOW</title>",
        ).replace(
            "</body>",
            """
            <script>
              setTimeout(() => document.getElementById('editDashboardButton')?.click(), 1200);
              setTimeout(() => document.getElementById('dashboardPrefixToggle')?.click(), 1800);
              setTimeout(() => {
                (configurableDashboard?.widgets || []).forEach(widget => configurableVisibleWidgets.add(widget.id));
                refreshConfigurableDashboard();
              }, 2200);
              setTimeout(() => {
                const editButtons = Array.from(document.querySelectorAll('.configurable-widget-edit'));
                const prefixBody = document.getElementById('dashboardPrefixControlsBody');
                const prefixToggle = document.getElementById('dashboardPrefixToggle');
                document.body.dataset.configurableEditButtonsVisible = String(
                  editButtons.length === 3
                  && editButtons.every(button => getComputedStyle(button).display !== 'none' && !button.disabled)
                );
                document.body.dataset.dashboardPrefixExpanded = String(
                  prefixToggle?.getAttribute('aria-expanded') === 'true'
                  && prefixBody
                  && !prefixBody.hidden
                );
              }, 3500);
            </script>
            </body>
            """,
        )
        authenticated_html = FRONTEND.replace(
            "<title>GMJ-FLOW</title>",
            "<script>localStorage.setItem('gmjFlowAuthToken','dashboard-test');</script><title>GMJ-FLOW</title>",
        )
        renderer_failure_html = authenticated_html.replace(
            "function renderConfigurableDashboard() {",
            "function renderConfigurableDashboard() { throw new Error('renderer failure test');",
        ).replace(
            "</body>",
            """
            <script>
              setTimeout(() => {
                const view = document.getElementById('view-dashboard');
                const fallback = document.querySelector('[data-dashboard-legacy-fallback="top-rankings"]');
                document.body.dataset.rendererFailureHandled = String(
                  configurableDashboardActive === false
                  && !view.classList.contains('dashboard-engine-active')
                  && fallback
                  && !fallback.hidden
                  && fallback.getAttribute('aria-hidden') === 'false'
                );
                document.body.dataset.rendererFailureAuthReady = String(currentAuthUser?.id === 1);
              }, 3500);
            </script>
            </body>
            """,
        )
        missing_module_html = authenticated_html.replace(
            "</body>",
            """
            <script>
              setTimeout(() => {
                const view = document.getElementById('view-dashboard');
                const fallback = document.querySelector('[data-dashboard-legacy-fallback="top-rankings"]');
                document.body.dataset.missingModuleBootstrapContinued = String(
                  currentAuthUser?.id === 1
                  && !document.getElementById('appShell').classList.contains('auth-hidden')
                  && configurableDashboardActive === false
                  && !view.classList.contains('dashboard-engine-active')
                  && fallback
                  && !fallback.hidden
                );
              }, 3500);
            </script>
            </body>
            """,
        )
        widget_queries = []
        prefix_asset_requests = []
        missing_module_auth_requests = []

        class Handler(BaseHTTPRequestHandler):
            def send_json(self, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                if path == "/api/auth/me":
                    if "missing_module=1" in (self.headers.get("Referer") or ""):
                        missing_module_auth_requests.append(path)
                    return self.send_json({
                        "user": {
                            "id": 1,
                            "username": "dashboard-test",
                            "role": "admin",
                            "must_change_password": False,
                        }
                    })
                if path == "/api/dashboards":
                    return self.send_json({
                        "items": [{"id": 1, "name": "Meu Dashboard", "is_system": False}],
                        "default_dashboard_id": 1,
                    })
                if path == "/api/dashboards/1":
                    return self.send_json(dashboard)
                if path == "/api/dashboards/widget-catalog":
                    return self.send_json({"presets": [], "types": [], "dimensions": [], "metrics": []})
                if path in {"/", "/index.html"}:
                    if "renderer_failure=1" in parsed.query:
                        selected_html = renderer_failure_html
                    elif "missing_module=1" in parsed.query:
                        selected_html = missing_module_html
                    else:
                        selected_html = served_html
                    body = selected_html.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if path == "/dashboard-prefix-controls.js":
                    referer = self.headers.get("Referer") or ""
                    if "missing_module=1" in referer:
                        self.send_error(404)
                        return
                asset = ROOT / "frontend" / path.lstrip("/")
                if asset.is_file():
                    if path == "/dashboard-prefix-controls.js":
                        prefix_asset_requests.append((path, 200))
                    body = asset.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/javascript; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                return self.send_json({"items": []})

            def do_POST(self):
                path = urlparse(self.path).path
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                if path == "/api/dashboard-widgets/query":
                    widget_queries.append(path)
                    return self.send_json({
                        "kind": "ranking",
                        "metric": "bps",
                        "items": [],
                        "quality": {},
                    })
                return self.send_json({})

            def log_message(self, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        def run_edge_page(query, profile_prefix):
            with tempfile.TemporaryDirectory(prefix=profile_prefix) as profile:
                return subprocess.run(
                    [
                        str(edge),
                        "--headless=new",
                        "--disable-gpu",
                        "--disable-extensions",
                        "--no-first-run",
                        "--force-time-zone=America/Sao_Paulo",
                        "--virtual-time-budget=6000",
                        "--user-data-dir=%s" % profile,
                        "--dump-dom",
                        "http://127.0.0.1:%s/%s#dashboard"
                        % (server.server_port, query),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=40,
                )

        try:
            completed = run_edge_page("", "gmj-dashboard-widgets-edge-")
            renderer_failure_completed = run_edge_page(
                "?renderer_failure=1",
                "gmj-dashboard-renderer-failure-edge-",
            )
            missing_module_completed = run_edge_page(
                "?missing_module=1",
                "gmj-dashboard-missing-module-edge-",
            )
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)

        self.assertEqual(completed.returncode, 0, completed.stderr[-4000:])
        self.assertIn('id="view-dashboard" class="app-view active dashboard-engine-active dashboard-editing"', completed.stdout)
        fallback_start = completed.stdout.index(
            'data-dashboard-legacy-fallback="top-rankings"'
        )
        fallback_open_end = completed.stdout.index(">", fallback_start)
        fallback_opening = completed.stdout[fallback_start:fallback_open_end]
        self.assertIn('hidden=""', fallback_opening)
        self.assertIn('aria-hidden="true"', fallback_opening)
        grid_start = completed.stdout.index('<section id="configurableDashboardGrid"')
        grid_end = completed.stdout.index('</section>', grid_start)
        rendered_grid = completed.stdout[grid_start:grid_end]
        for widget_key in ("top-src-ip", "top-dst-ip", "top-ports"):
            self.assertEqual(rendered_grid.count(f'data-widget-key="{widget_key}"'), 1)
        self.assertEqual(rendered_grid.count("configurable-widget-edit"), 3)
        self.assertEqual(rendered_grid.count("configurable-widget-hide"), 3)
        self.assertEqual(rendered_grid.count("configurable-widget-delete"), 3)
        self.assertIn('data-configurable-edit-buttons-visible="true"', completed.stdout)
        self.assertIn('data-dashboard-prefix-expanded="true"', completed.stdout)
        self.assertIn(
            ("/dashboard-prefix-controls.js", 200),
            prefix_asset_requests,
        )
        self.assertGreaterEqual(len(widget_queries), 3)

        self.assertEqual(
            renderer_failure_completed.returncode,
            0,
            renderer_failure_completed.stderr[-4000:],
        )
        self.assertIn(
            'data-renderer-failure-handled="true"',
            renderer_failure_completed.stdout,
        )
        self.assertIn(
            'data-renderer-failure-auth-ready="true"',
            renderer_failure_completed.stdout,
        )
        self.assertNotIn(
            'id="view-dashboard" class="app-view active dashboard-engine-active',
            renderer_failure_completed.stdout,
        )

        self.assertEqual(
            missing_module_completed.returncode,
            0,
            missing_module_completed.stderr[-4000:],
        )
        self.assertIn(
            'data-missing-module-bootstrap-continued="true"',
            missing_module_completed.stdout,
        )
        self.assertGreaterEqual(len(missing_module_auth_requests), 1)
        self.assertNotIn(
            'id="view-dashboard" class="app-view active dashboard-engine-active',
            missing_module_completed.stdout,
        )


if __name__ == "__main__":
    unittest.main()
