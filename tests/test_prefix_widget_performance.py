from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from backend.app.services.dashboard_widgets import (
    build_widget_query_plan,
    validate_widget_definition,
    widget_data_signature,
)
from backend.app.services.prefixes import normalize_prefix_grouping
from tests.test_collector_apply_static import backend_main


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
MAIN = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
EXPORTER = (
    ROOT / "backend" / "app" / "services" / "grafana_exporter.py"
).read_text(encoding="utf-8")
START = datetime(2026, 7, 30, 10, 0, tzinfo=timezone.utc)
END = datetime(2026, 7, 30, 11, 0, tzinfo=timezone.utc)


def clickhouse_result(columns, rows):
    return SimpleNamespace(column_names=list(columns), result_rows=list(rows))


def prefix_plan(metric="bps"):
    return {
        "kind": "timeseries",
        "widget_alias": (
            "traffic_by_prefix_pps"
            if metric == "pps"
            else "traffic_by_prefix_bps"
        ),
        "metric": metric,
        "direction": "both",
        "group_by": "dst_prefix",
        "aggregation": "sum",
        "calculation": "last_not_null",
        "legend_calculation": "last_not_null",
        "resolution_seconds": 60,
        "maximum_data_points": 300,
        "prefix_mode": "top_n",
        "top_n": 10,
        "include_partial_bucket": False,
        "filters": [],
    }


def prefix_context(
    *,
    cidr=None,
    grouping_length=24,
    mode="top_n",
    top_n=10,
    maximum_data_points=300,
):
    return {
        "range_minutes": 60,
        "start": START,
        "end": END,
        "sensor_id": None,
        "interface_id": None,
        "if_index": None,
        "zone_id": None,
        "zone_direction": "both",
        "series_limit": top_n,
        "global_filters": [],
        "maximum_data_points": maximum_data_points,
        "maximum_data_points_explicit": True,
        "prefix_filter": (
            {
                "enabled": True,
                "cidr": cidr,
                "address_family": "ipv6" if ":" in cidr else "ipv4",
                "match_side": "destination",
            }
            if cidr
            else None
        ),
        "prefix_grouping": {
            "enabled": True,
            "ipv4_prefix_length": grouping_length,
            "ipv6_prefix_length": grouping_length,
            "side": "destination",
            "mode": mode,
            "top_n": top_n,
            "include_empty": False,
        },
    }


class PrefixTopNQueryTest(unittest.TestCase):
    def execute(
        self,
        *,
        metric="bps",
        aggregate=False,
        start=START,
        total_found=6454,
        top_n=10,
    ):
        queries = []
        keys = ["192.0.%s.0/24" % index for index in range(top_n)]

        def query_clickhouse(sql, params=None):
            params = dict(params or {})
            queries.append((sql, params))
            if "ranked_prefixes AS" in sql:
                return clickhouse_result(
                    ["group_key", "ranking_value", "total_series_found"],
                    [
                        (key, 1000 - index, total_found)
                        for index, key in enumerate(keys)
                    ],
                )
            return clickhouse_result(
                ["ts", "group_key", "total_value"],
                [(start, key, 100 + index) for index, key in enumerate(keys)],
            )

        context = prefix_context(top_n=top_n)
        context["start"] = start

        def normalize_rows(rows, **_kwargs):
            return [
                {
                    **row,
                    "value": row.get("value", row.get("total_value")),
                    "partial": False,
                }
                for row in rows
            ]

        with mock.patch.object(
            backend_main,
            "dashboard_aggregate_range_covered",
            return_value=aggregate,
        ), mock.patch.object(
            backend_main,
            "resolve_dashboard_if_index",
            return_value=None,
        ), mock.patch.object(
            backend_main,
            "query_clickhouse",
            side_effect=query_clickhouse,
        ), mock.patch.object(
            backend_main,
            "normalize_rate_bucket_rows",
            side_effect=normalize_rows,
        ), mock.patch.object(
            backend_main,
            "series_data_quality",
            return_value={},
        ):
            payload = backend_main.dashboard_widget_series_payload(
                prefix_plan(metric),
                context,
            )
        return queries, payload

    def test_top_n_is_selected_before_timeseries(self):
        queries, payload = self.execute()
        self.assertEqual(len(queries), 2)
        ranking_sql, ranking_params = queries[0]
        series_sql, series_params = queries[1]
        self.assertIn("ranked_prefixes AS", ranking_sql)
        self.assertIn("ORDER BY ranking_value DESC, group_key ASC", ranking_sql)
        self.assertIn("LIMIT {prefix_series_limit:UInt32}", ranking_sql)
        self.assertEqual(ranking_params["prefix_series_limit"], 10)
        self.assertIn(
            "group_key IN {prefix_series_keys:Array(String)}",
            series_sql,
        )
        self.assertEqual(len(series_params["prefix_series_keys"]), 10)
        self.assertEqual(payload["series_count"], 10)
        self.assertEqual(payload["total_series_found"], 6454)
        self.assertTrue(payload["limited"])
        self.assertIn("6", payload["limit_message"])

    def test_never_returns_thousands_of_series(self):
        _queries, payload = self.execute(total_found=6454, top_n=50)
        self.assertLessEqual(len(payload["series"]), 50)
        self.assertNotEqual(len(payload["series"]), 6454)

    def test_bps_and_pps_use_the_same_safe_two_stage_strategy(self):
        for metric in ("bps", "pps"):
            with self.subTest(metric=metric):
                queries, payload = self.execute(metric=metric)
                self.assertEqual(len(queries), 2)
                self.assertEqual(payload["metric"], metric)
                self.assertLessEqual(payload["points_count"], 12000)

    def test_raw_aggregate_and_hybrid_keep_top_n_first(self):
        cases = (
            (False, START, "raw"),
            (True, START, "aggregate_1m"),
            (True, START.replace(second=15), "aggregate_hybrid"),
        )
        for aggregate, start, expected in cases:
            with self.subTest(path=expected):
                queries, payload = self.execute(
                    aggregate=aggregate,
                    start=start,
                )
                self.assertEqual(payload["source"], expected)
                self.assertIn("ranked_prefixes AS", queries[0][0])
                if aggregate:
                    self.assertIn(
                        backend_main.DASHBOARD_AGGREGATE_TABLES["prefix"],
                        queries[0][0],
                    )
                if expected == "aggregate_hybrid":
                    self.assertIn("UNION ALL", queries[0][0])


class PrefixSafetyLimitTest(unittest.TestCase):
    def test_ipv4_block_capacities(self):
        for cidr, expected in (
            ("186.232.160.0/20", 16),
            ("186.232.160.0/22", 4),
        ):
            with self.subTest(cidr=cidr):
                limits = backend_main.dashboard_prefix_series_limits(
                    prefix_plan(),
                    prefix_context(
                        cidr=cidr,
                        grouping_length=24,
                        mode="block",
                    ),
                    {"cidr": cidr},
                    normalize_prefix_grouping(
                        {
                            "enabled": True,
                            "ipv4_prefix_length": 24,
                            "ipv6_prefix_length": 64,
                            "mode": "block",
                        }
                    ),
                )
                self.assertEqual(limits["series_limit"], expected)

    def test_ipv6_huge_expansion_is_rejected_before_query(self):
        with self.assertRaises(backend_main.HTTPException) as caught:
            backend_main.dashboard_prefix_block_series_capacity(
                {"cidr": "2001:db8::/48"},
                normalize_prefix_grouping(
                    {
                        "enabled": True,
                        "ipv6_prefix_length": 64,
                        "mode": "block",
                    }
                ),
            )
        self.assertEqual(caught.exception.status_code, 422)
        self.assertIn("limite seguro", str(caught.exception.detail))

    def test_top_n_and_data_point_limits_are_absolute(self):
        grouping = normalize_prefix_grouping(
            {
                "enabled": True,
                "top_n": 50,
                "ipv4_prefix_length": 24,
            }
        )
        limits = backend_main.dashboard_prefix_series_limits(
            prefix_plan(),
            {
                **prefix_context(top_n=50, maximum_data_points=5000),
                "maximum_data_points_explicit": True,
            },
            None,
            grouping,
        )
        self.assertEqual(limits["series_limit"], 50)
        self.assertLessEqual(limits["points_per_series"], 1000)
        self.assertLessEqual(
            limits["series_limit"] * limits["points_per_series"],
            backend_main.PREFIX_WIDGET_MAX_TOTAL_POINTS,
        )
        self.assertLessEqual(
            limits["estimated_payload_bytes"],
            backend_main.PREFIX_WIDGET_TARGET_PAYLOAD_BYTES,
        )
        with self.assertRaises(ValueError):
            normalize_prefix_grouping({"enabled": True, "top_n": 51})

    def test_block_mode_requires_a_network(self):
        with self.assertRaises(backend_main.HTTPException) as caught:
            backend_main.dashboard_prefix_block_series_capacity(
                None,
                normalize_prefix_grouping({"enabled": True, "mode": "block"}),
            )
        self.assertEqual(caught.exception.status_code, 422)
        self.assertIn("CIDR ou range", str(caught.exception.detail))


class PrefixCacheTest(unittest.TestCase):
    def widget(self):
        return validate_widget_definition(
            {
                "id": 77,
                "dashboard_id": 9,
                "title": "Tráfego por Prefixo",
                "type": "traffic_by_prefix_bps",
                "category": "traffic",
                "config": {},
                "visualization": {},
                "grid": {"x": 0, "y": 0, "w": 6, "h": 6},
            }
        )

    def test_signatures_are_separated_by_cidr_range_and_top_n(self):
        widget = self.widget()
        base = prefix_context(cidr="192.0.2.0/24")
        contexts = [
            base,
            prefix_context(cidr="198.51.100.0/24"),
            {
                **prefix_context(),
                "prefix_filter": {
                    "enabled": True,
                    "start_ip": "192.0.2.10",
                    "end_ip": "192.0.2.20",
                    "address_family": "ipv4",
                    "match_side": "either",
                },
            },
            prefix_context(cidr="192.0.2.0/24", top_n=20),
        ]
        signatures = {
            widget_data_signature(widget, context)
            for context in contexts
        }
        self.assertEqual(len(signatures), len(contexts))

    def test_oversized_prefix_payload_returns_422_and_is_not_cached(self):
        widget = self.widget()
        huge = {
            "kind": "timeseries",
            "metric": "bps",
            "source": "raw",
            "series": [],
            "padding": "x" * (8 * 1024 * 1024 + 1),
        }
        with mock.patch.object(
            backend_main,
            "dashboard_cache_get",
            return_value=None,
        ), mock.patch.object(
            backend_main,
            "dashboard_aggregate_range_covered",
            return_value=False,
        ), mock.patch.object(
            backend_main,
            "dashboard_widget_execute",
            return_value=huge,
        ), mock.patch.object(
            backend_main,
            "dashboard_cache_set",
        ) as cache_set, mock.patch.object(
            backend_main.DASHBOARD_CACHE,
            "fail_flight",
        ):
            with self.assertRaises(backend_main.HTTPException) as caught:
                backend_main.dashboard_widget_cached_query(
                    widget,
                    prefix_context(),
                )
        self.assertEqual(caught.exception.status_code, 422)
        cache_set.assert_not_called()

    def test_cache_key_contains_dashboard_widget_metric_path_and_strategy(self):
        widget = self.widget()
        keys = []

        def cache_get(key, _ttl):
            keys.append(key)
            return {"kind": "timeseries", "series": []}

        with mock.patch.object(
            backend_main,
            "dashboard_cache_get",
            side_effect=cache_get,
        ):
            backend_main.dashboard_widget_cached_query(
                widget,
                {
                    **prefix_context(),
                    "dashboard_id": 9,
                    "widget_id": 77,
                    "query_path": "aggregate_hybrid",
                },
            )
        key = keys[0]
        for expected in (
            "dashboard_id",
            "widget_id",
            "metric",
            "top_n",
            "query_path",
            "aggregate_hybrid",
            "prefix_top_n_first_v2",
        ):
            self.assertIn(expected, key)


class PrefixFrontendContractTest(unittest.TestCase):
    def test_prefix_widget_query_uses_its_configured_top_n(self):
        query_context = HTML[
            HTML.find("function configurableWidgetQueryContext("):
            HTML.find("function activateConfigurableDashboardContext(")
        ]
        for contract in (
            "const configuredPrefixTopN = Number(widget?.config?.top_n);",
            "Math.trunc(configuredPrefixTopN)",
            "top_n: seriesLimit",
            "series_limit: seriesLimit",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, query_context)

    def test_controls_are_visible_and_complete(self):
        self.assertIn(
            ":not(#configurableDashboardGrid):not(#dashboardPrefixControls)",
            HTML,
        )
        for control in (
            "dashboardPrefixFilterType",
            "dashboardPrefixFamily",
            "dashboardPrefixSaved",
            "dashboardPrefixSubnet",
            "dashboardPrefixCidr",
            "dashboardPrefixStart",
            "dashboardPrefixEnd",
            "dashboardPrefixMatchSide",
            "dashboardPrefixGroupingEnabled",
            "dashboardPrefixIpv4Length",
            "dashboardPrefixIpv6Length",
            "dashboardPrefixGroupSide",
            "dashboardPrefixGroupMode",
            "dashboardPrefixMaxDataPoints",
            "dashboardPrefixTemporaryScope",
        ):
            with self.subTest(control=control):
                self.assertIn('id="%s"' % control, HTML)

    def test_lazy_loading_cancellation_and_stale_guards(self):
        for contract in (
            "IntersectionObserver",
            "if (configurableVisibleWidgets.has(id)) return;",
            "if (configurableWidgetControllers.has(widget.id)) return null;",
            "configurableWidgetControllers.get(id)?.abort();",
            "configurableRangeRequestGate.isCurrent(activeRangeToken)",
            "Number(configurableDashboard?.id || 0) !== dashboardId",
            "configurableWidgetBlockedQueries.add(widget.id)",
            "error.status === 422",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, HTML)

    def test_render_cache_legend_and_table_guards(self):
        for contract in (
            "CONFIGURABLE_WIDGET_MAX_SERIES = 50",
            "CONFIGURABLE_WIDGET_MAX_TOTAL_POINTS = 12000",
            "CONFIGURABLE_WIDGET_MAX_CACHE_BYTES = 8 * 1024 * 1024",
            "responseSeries.length > CONFIGURABLE_WIDGET_MAX_SERIES",
            ".slice(0, CONFIGURABLE_WIDGET_MAX_SERIES)",
            "configurableLegendLabel",
            "payload.limit_message",
            "configurablePrefixSeriesTable",
            "configurable-prefix-table-page",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, HTML)

    def test_temporary_global_filter_survives_dashboard_navigation(self):
        for contract in (
            "CONFIGURABLE_PREFIX_SESSION_KEY",
            "sessionStorage.setItem",
            "restoreConfigurableTemporaryPrefix();",
            "configurableTemporaryPrefixScope === 'dashboard'",
            "persistConfigurableTemporaryPrefix();",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, HTML)

    def test_geo_map_receives_the_same_global_prefix_filter(self):
        for contract in (
            "prefix_enabled",
            "prefix_id",
            "prefix_cidr",
            "prefix_start",
            "prefix_end",
            "prefix_address_family",
            "prefix_match_side",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, HTML)
                self.assertIn(contract, MAIN)


class PrefixGrafanaContractTest(unittest.TestCase):
    def test_editable_export_contains_complete_prefix_variables(self):
        for variable in (
            "prefix",
            "prefix_id",
            "prefix_start",
            "prefix_end",
            "address_family",
            "match_side",
            "ipv4_prefix_length",
            "ipv6_prefix_length",
        ):
            with self.subTest(variable=variable):
                self.assertIn('"%s"' % variable, EXPORTER)
        self.assertNotIn('"${token}"', EXPORTER)
        self.assertNotIn('"${credential}"', EXPORTER)

    def test_alias_defaults_and_query_plan_are_safe(self):
        for alias, metric in (
            ("traffic_by_prefix_bps", "bps"),
            ("traffic_by_prefix_pps", "pps"),
            ("prefix_timeseries", "bps"),
        ):
            with self.subTest(alias=alias):
                widget = validate_widget_definition(
                    {
                        "title": alias,
                        "type": alias,
                        "category": "traffic",
                        "config": {},
                        "visualization": {},
                        "grid": {"x": 0, "y": 0, "w": 6, "h": 6},
                    }
                )
                plan = build_widget_query_plan(widget)
                self.assertEqual(plan["widget_alias"], alias)
                self.assertEqual(plan["metric"], metric)
                self.assertEqual(plan["top_n"], 10)
                self.assertEqual(plan["maximum_data_points"], 300)
                self.assertEqual(plan["prefix_mode"], "top_n")


if __name__ == "__main__":
    unittest.main()
