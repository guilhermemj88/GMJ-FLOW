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
        self.assertIn("layoutEngine.repairDashboardLayout(", RESIZE)

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
            "session.persisting",
            "await options.onPersist?.(",
            "await options.onRollback?.(",
        ):
            self.assertIn(token, RESIZE)
        self.assertNotIn("onPersist?.", RESIZE[RESIZE.find("function onPointerMove") :])

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
        ):
            self.assertIn(token, FRONTEND)

    def test_resize_persists_desktop_grid_and_preserves_height_fields(self):
        for token in (
            "installConfigurableWidgetResize",
            "getResponsiveColumns: configurableResponsiveColumns",
            "configurableResponsiveColumns",
            "updateConfigurableDashboardGridPositions",
            "scheduleConfigurableChartResize",
            "expanded_grid_h: widget.expanded_grid_h",
            "collapsed_grid_h: widget.collapsed_grid_h",
            "height_mode: widget.height_mode",
            "body.closest('.configurable-dashboard-widget')?.classList.contains('is-resizing')",
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
