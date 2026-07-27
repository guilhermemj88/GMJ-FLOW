from __future__ import annotations

import copy
import sqlite3
import unittest
from pathlib import Path

from backend.app.services.dashboard_widgets import (
    DASHBOARD_EXPORT_VERSION,
    DASHBOARD_SCHEMA_VERSION,
    DASHBOARD_WIDGET_METRICS,
    GENERAL_WIDGETS,
    SYSTEM_TEMPLATES,
    build_widget_query_plan,
    create_dashboard,
    duplicate_dashboard,
    ensure_dashboard_schema,
    ensure_user_default_dashboard,
    get_dashboard,
    normalize_grid,
    resolve_grid_collision,
    validate_filters,
    validate_inheritance,
    validate_widget_definition,
    widget_catalog,
    widget_data_signature,
)


ROOT = Path(__file__).resolve().parents[1]
MAIN_SOURCE = (ROOT / "backend" / "app" / "main.py").read_text(
    encoding="utf-8",
    errors="ignore",
)
FRONTEND_SOURCE = (ROOT / "frontend" / "index.html").read_text(
    encoding="utf-8",
    errors="ignore",
)


def memory_database() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL
        )
        """
    )
    conn.executemany(
        "INSERT INTO users (id, username) VALUES (?, ?)",
        [(1, "admin"), (2, "operator")],
    )
    return conn


class DashboardWidgetSchemaTest(unittest.TestCase):
    def setUp(self):
        self.conn = memory_database()
        ensure_dashboard_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_schema_and_system_templates_are_idempotent(self):
        template_count = self.conn.execute(
            "SELECT COUNT(*) FROM dashboards WHERE is_system = 1"
        ).fetchone()[0]
        widget_count = self.conn.execute(
            "SELECT COUNT(*) FROM dashboard_widgets"
        ).fetchone()[0]
        self.assertEqual(template_count, len(SYSTEM_TEMPLATES))
        self.assertGreaterEqual(widget_count, len(GENERAL_WIDGETS))

        ensure_dashboard_schema(self.conn)
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM dashboards WHERE is_system = 1"
            ).fetchone()[0],
            template_count,
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM dashboard_widgets"
            ).fetchone()[0],
            widget_count,
        )

    def test_existing_user_gets_one_server_side_default(self):
        first = ensure_user_default_dashboard(self.conn, 2)
        second = ensure_user_default_dashboard(self.conn, 2)
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(first["is_default"])
        self.assertEqual(first["name"], "Meu Dashboard")
        self.assertEqual(len(first["widgets"]), len(GENERAL_WIDGETS))
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM dashboards WHERE owner_user_id = 2"
            ).fetchone()[0],
            1,
        )

    def test_create_duplicate_and_load_dashboard(self):
        source = create_dashboard(
            self.conn,
            {
                "name": "Operação",
                "description": "Teste",
                "is_default": True,
                "is_shared": False,
                "global_filters": [],
                "time_range": {"mode": "relative", "minutes": 30},
                "refresh_interval_seconds": 30,
            },
            2,
            widgets=[copy.deepcopy(GENERAL_WIDGETS[0])],
        )
        duplicate = duplicate_dashboard(self.conn, source, 2)
        loaded = get_dashboard(self.conn, duplicate["id"])
        self.assertIsNotNone(loaded)
        self.assertEqual(len(loaded["widgets"]), 1)
        self.assertFalse(loaded["is_default"])
        self.assertFalse(loaded["is_shared"])
        self.assertNotEqual(source["id"], duplicate["id"])


class DashboardWidgetValidationTest(unittest.TestCase):
    def test_catalog_is_declarative_and_complete(self):
        catalog = widget_catalog()
        self.assertEqual(catalog["schema_version"], DASHBOARD_SCHEMA_VERSION)
        self.assertEqual(
            {item["id"] for item in catalog["types"]},
            {"top_n", "timeseries", "kpi", "status_list", "recent_events"},
        )
        for required in (
            "src_ip",
            "dst_ip",
            "src_asn",
            "dst_asn",
            "conversation",
            "zone",
            "subscriber",
        ):
            self.assertIn(required, catalog["dimensions"])
        self.assertIn("percentage", catalog["metrics"])
        self.assertIn("bits_per_second", catalog["metrics"])
        self.assertIn("input_interface", catalog["dimensions"])
        self.assertIn("ingress", catalog["directions"])
        self.assertIn("not_in", catalog["filter_operators"])
        self.assertIn("between", catalog["filter_operators"])
        self.assertIn("clickhouse", catalog["status_sources"])
        self.assertIn(
            "mitigated-destinations",
            {preset["id"] for preset in catalog["presets"]},
        )
        self.assertGreaterEqual(len(catalog["presets"]), 15)

    def test_rejects_sql_and_unknown_filter_surface(self):
        widget = copy.deepcopy(GENERAL_WIDGETS[2])
        widget["config"]["sql"] = "SELECT * FROM flow_raw"
        with self.assertRaisesRegex(ValueError, "SQL livre"):
            validate_widget_definition(widget)
        with self.assertRaisesRegex(ValueError, "campo de filtro"):
            validate_filters(
                [{"field": "arbitrary_column", "operator": "eq", "value": 1}]
            )
        with self.assertRaisesRegex(ValueError, "operador"):
            validate_filters(
                [{"field": "protocol", "operator": "sql", "value": "tcp"}]
            )

    def test_typed_filters_and_safe_limits(self):
        filters = validate_filters(
            [
                {"field": "src_port", "operator": "in", "value": ["53", 443]},
                {
                    "field": "src_prefix",
                    "operator": "eq",
                    "value": "192.0.2.7/24",
                },
                {"field": "ip_version", "operator": "eq", "value": "6"},
                {
                    "field": "addressing_mode",
                    "operator": "eq",
                    "value": "cgnat",
                },
            ]
        )
        self.assertEqual(filters[0]["value"], [53, 443])
        self.assertEqual(filters[1]["value"], "192.0.2.0/24")
        self.assertEqual(filters[2]["value"], 6)
        aliased = validate_widget_definition(
            {
                **copy.deepcopy(GENERAL_WIDGETS[2]),
                "visualization": {"type": "vertical_bar"},
                "config": {
                    "dimension": "input_interface",
                    "metric": "bits_per_second",
                    "direction": "ingress",
                    "limit": 10,
                    "visualization": "vertical_bar",
                },
            }
        )
        self.assertEqual(aliased["config"]["dimension"], "input_if")
        self.assertEqual(aliased["config"]["metric"], "bps")
        self.assertEqual(aliased["config"]["direction"], "download")
        self.assertEqual(aliased["visualization"]["type"], "bar")
        with self.assertRaisesRegex(ValueError, "limit"):
            validate_widget_definition(
                {
                    **copy.deepcopy(GENERAL_WIDGETS[2]),
                    "config": {
                        **GENERAL_WIDGETS[2]["config"],
                        "limit": 101,
                    },
                }
            )

    def test_grid_is_normalized_and_collision_free(self):
        self.assertEqual(
            normalize_grid({"x": 11, "y": -2, "w": 9, "h": 99}),
            {"x": 3, "y": 0, "w": 9, "h": 12},
        )
        moved = resolve_grid_collision(
            {"x": 0, "y": 0, "w": 6, "h": 4},
            [{"x": 0, "y": 0, "w": 6, "h": 4}],
        )
        self.assertGreaterEqual(moved["y"], 4)

    def test_individual_context_inheritance_is_typed(self):
        inheritance = validate_inheritance(
            {
                "range": "custom",
                "sensor": {"mode": "custom", "value": "4"},
                "interface": "inherit",
                "zone": {"mode": "custom", "value": 9},
                "direction": "inherit",
            }
        )
        self.assertEqual(inheritance["sensor"]["value"], 4)
        self.assertEqual(inheritance["zone"]["value"], 9)
        self.assertIsNone(inheritance["interface"]["value"])
        with self.assertRaisesRegex(ValueError, "sensor"):
            validate_inheritance(
                {"sensor": {"mode": "custom", "value": "SELECT"}}
            )

    def test_query_plan_never_accepts_user_expression(self):
        top_plan = build_widget_query_plan(copy.deepcopy(GENERAL_WIDGETS[2]))
        series_plan = build_widget_query_plan(copy.deepcopy(GENERAL_WIDGETS[0]))
        self.assertEqual(top_plan["aggregate"], "src_ip")
        self.assertEqual(top_plan["dimension_expression"], "toString(src_ip)")
        self.assertEqual(series_plan["kind"], "timeseries")
        self.assertNotIn("sql", top_plan)

    def test_data_cache_signature_ignores_presentation_only(self):
        base = copy.deepcopy(GENERAL_WIDGETS[2])
        restyled = copy.deepcopy(base)
        restyled["visualization"] = {
            "type": "donut",
            "palette": ["#fff"],
            "show_legend": False,
        }
        context = {
            "time_range": {"minutes": 10},
            "global_filters": [],
            "sensor_id": 3,
        }
        self.assertEqual(
            widget_data_signature(base, context),
            widget_data_signature(restyled, context),
        )
        filtered = copy.deepcopy(base)
        filtered["filters"] = [
            {"field": "protocol", "operator": "eq", "value": "udp"}
        ]
        self.assertNotEqual(
            widget_data_signature(base, context),
            widget_data_signature(filtered, context),
        )
        explicit_range = {
            **context,
            "start": "2026-07-27T10:00:00Z",
            "end": "2026-07-27T10:10:00Z",
        }
        shifted_range = {
            **explicit_range,
            "start": "2026-07-27T11:00:00Z",
            "end": "2026-07-27T11:10:00Z",
        }
        self.assertNotEqual(
            widget_data_signature(base, explicit_range),
            widget_data_signature(base, shifted_range),
        )

    def test_observability_snapshot_is_stable(self):
        before = DASHBOARD_WIDGET_METRICS.snapshot()["queries_total"]
        DASHBOARD_WIDGET_METRICS.record(
            duration_seconds=0.02,
            source="aggregate",
            preview=True,
        )
        snapshot = DASHBOARD_WIDGET_METRICS.snapshot()
        self.assertEqual(snapshot["queries_total"], before + 1)
        self.assertGreaterEqual(snapshot["aggregate_queries_total"], 1)
        self.assertGreaterEqual(snapshot["preview_queries_total"], 1)


class DashboardWidgetContractTest(unittest.TestCase):
    def test_rest_contract_is_present(self):
        for route in (
            '"/api/dashboards"',
            '"/api/dashboards/{dashboard_id}"',
            '"/api/dashboards/{dashboard_id}/duplicate"',
            '"/api/dashboards/{dashboard_id}/set-default"',
            '"/api/dashboards/{dashboard_id}/export"',
            '"/api/dashboards/import"',
            '"/api/dashboards/{dashboard_id}/widgets"',
            '"/api/dashboards/{dashboard_id}/widgets/{widget_id}"',
            '"/api/dashboard-widgets/query"',
            '"/api/dashboard-widgets/preview"',
        ):
            self.assertIn(route, MAIN_SOURCE)
        self.assertIn("dashboard_can_view", MAIN_SOURCE)
        self.assertIn("dashboard_can_edit", MAIN_SOURCE)
        self.assertIn("widget_data_signature", MAIN_SOURCE)
        self.assertIn("DASHBOARD_WIDGET_METRICS.snapshot()", MAIN_SOURCE)
        self.assertIn('widget.get("hidden") or widget.get("collapsed")', MAIN_SOURCE)

    def test_frontend_uses_real_widget_engine_and_progressive_loading(self):
        for token in (
            'id="dashboardSelector"',
            'id="configurableDashboardGrid"',
            'id="dashboardWidgetModal"',
            "initializeConfigurableDashboards",
            "IntersectionObserver",
            "configurableWidgetControllers",
            "Promise.allSettled",
            "/api/dashboard-widgets/query",
            "/api/dashboard-widgets/preview",
            "data-widget-tab=\"filters\"",
            'id="widgetConfigCustomRangeMinutes"',
            'id="widgetConfigSensorMode"',
            'id="widgetConfigDirectionMode"',
            "configurable-widget-fullscreen",
            "configurable-widget-duplicate",
        ):
            self.assertIn(token, FRONTEND_SOURCE)
        self.assertIn("if (!force && !configurableVisibleWidgets.has(widget.id)) return null", FRONTEND_SOURCE)
        self.assertIn("hidden: !widget.hidden", FRONTEND_SOURCE)
        self.assertIn("writeConfigurableWidgetCache", FRONTEND_SOURCE)

    def test_legacy_dashboard_remains_as_failure_fallback(self):
        for legacy_id in (
            'id="bpsChart"',
            'id="ppsChart"',
            'id="srcIpChart"',
            'id="topConversationsTable"',
        ):
            self.assertIn(legacy_id, FRONTEND_SOURCE)
        self.assertIn("dashboard-engine-active", FRONTEND_SOURCE)
        self.assertIn("usando layout legado", FRONTEND_SOURCE)

    def test_versioned_export_constants_exist(self):
        self.assertEqual(DASHBOARD_EXPORT_VERSION, 1)
        self.assertEqual(DASHBOARD_SCHEMA_VERSION, 1)


if __name__ == "__main__":
    unittest.main()
