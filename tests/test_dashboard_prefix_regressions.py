from __future__ import annotations

import re
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

from backend.app.services.dashboard_aggregates import DASHBOARD_AGGREGATE_TABLES
from backend.app.services.dashboard_widgets import validate_widget_definition
from backend.app.services.prefixes import (
    effective_prefix_filter,
    effective_prefix_grouping,
)
from tests.test_collector_apply_static import backend_main


START = datetime(2026, 7, 29, 10, 0, tzinfo=timezone.utc)
END = datetime(2026, 7, 29, 11, 0, tzinfo=timezone.utc)
OMITTED = object()


def empty_clickhouse_result():
    return SimpleNamespace(column_names=[], result_rows=[])


def assert_no_nested_weighted_aggregate(test_case, sql):
    compact = re.sub(r"\s+", " ", sql)
    test_case.assertNotRegex(compact.lower(), r"\bsum\s*\(\s*sum\s*\(")
    test_case.assertNotRegex(
        compact,
        r"sum\s*\(\s*toFloat64\((bytes|packets)\).*?\)\s+AS\s+\1\b",
    )
    test_case.assertNotIn(
        "sum(toFloat64(packets) * dashboard_auto_sample_rate) AS packets",
        compact,
    )


class ConversationRegressionTest(unittest.TestCase):
    def capture(
        self,
        *,
        aggregate=False,
        start=START,
        include_partial_bucket=OMITTED,
        prefix_filter=OMITTED,
        direction="both",
    ):
        queries = []

        def query_clickhouse(query, params=None):
            queries.append((query, dict(params or {})))
            return empty_clickhouse_result()

        kwargs = {
            "range_minutes": 60,
            "sensor_id": None,
            "interface_id": None,
            "if_index": None,
            "direction": direction,
            "proto": None,
            "limit": 10,
            "start": start,
            "end": END,
        }
        if include_partial_bucket is not OMITTED:
            kwargs["include_partial_bucket"] = include_partial_bucket
        if prefix_filter is not OMITTED:
            kwargs["prefix_filter"] = prefix_filter

        with mock.patch.object(
            backend_main,
            "dashboard_aggregate_range_covered",
            return_value=aggregate,
        ), mock.patch.object(
            backend_main,
            "dashboard_cache_get",
            return_value=None,
        ), mock.patch.object(
            backend_main,
            "dashboard_cache_set",
            side_effect=lambda _key, payload: payload,
        ), mock.patch.object(
            backend_main,
            "resolve_dashboard_if_index",
            return_value=None,
        ), mock.patch.object(
            backend_main,
            "query_clickhouse",
            side_effect=query_clickhouse,
        ):
            payload = backend_main.top_conversations_payload(**kwargs)
        return queries[-1], payload

    def test_old_payload_has_safe_default_and_source_destination_contract(self):
        (sql, _params), payload = self.capture()
        self.assertEqual(
            set(payload),
            {"start", "end", "sort_by", "items"},
        )
        self.assertIn("toString(src_ip) AS src_ip", sql)
        self.assertIn("toString(dst_ip) AS dst_ip", sql)
        self.assertIn(
            "GROUP BY src_ip, dst_ip, src_port, dst_port, proto",
            sql,
        )
        self.assertIn("weighted_packets_value", sql)
        assert_no_nested_weighted_aggregate(self, sql)

    def test_partial_bucket_true_false_are_explicit_and_do_not_change_sql(self):
        (false_sql, _), false_payload = self.capture(
            include_partial_bucket=False
        )
        (true_sql, _), true_payload = self.capture(
            include_partial_bucket=True
        )
        self.assertEqual(set(false_payload), set(true_payload))
        self.assertEqual(false_sql, true_sql)

    def test_raw_aggregate_1m_and_hybrid_plans(self):
        (raw_sql, _), _raw = self.capture(aggregate=False)
        (aggregate_sql, _), _aggregate = self.capture(aggregate=True)
        (hybrid_sql, _), _hybrid = self.capture(
            aggregate=True,
            start=START.replace(second=15),
        )
        self.assertNotIn(DASHBOARD_AGGREGATE_TABLES["conversations"], raw_sql)
        self.assertIn(
            DASHBOARD_AGGREGATE_TABLES["conversations"],
            aggregate_sql,
        )
        self.assertIn("UNION ALL", hybrid_sql)
        for sql in (raw_sql, aggregate_sql, hybrid_sql):
            assert_no_nested_weighted_aggregate(self, sql)

    def test_disabled_prefix_is_identical_to_absent_for_legacy_widget(self):
        (absent_sql, absent_params), _absent = self.capture()
        (disabled_sql, disabled_params), _disabled = self.capture(
            prefix_filter={
                "enabled": False,
                "cidr": "192.0.2.0/24",
                "match_side": "source",
            }
        )
        self.assertEqual(absent_sql, disabled_sql)
        self.assertEqual(absent_params, disabled_params)

    def test_upload_and_download_filters_do_not_raise_name_error(self):
        for direction, expected in (
            ("upload", "output_if > 0"),
            ("download", "input_if > 0"),
        ):
            with self.subTest(direction=direction):
                (sql, _params), payload = self.capture(direction=direction)
                self.assertIn(expected, sql)
                self.assertEqual(payload["items"], [])

    def test_top_syn_no_longer_has_a_free_partial_bucket_variable(self):
        queries = []

        def query_clickhouse(query, params=None):
            queries.append(query)
            return empty_clickhouse_result()

        with mock.patch.object(
            backend_main,
            "dashboard_aggregate_range_covered",
            return_value=False,
        ), mock.patch.object(
            backend_main,
            "dashboard_cache_get",
            return_value=None,
        ), mock.patch.object(
            backend_main,
            "dashboard_cache_set",
            side_effect=lambda _key, payload: payload,
        ), mock.patch.object(
            backend_main,
            "resolve_dashboard_if_index",
            return_value=None,
        ), mock.patch.object(
            backend_main,
            "query_clickhouse",
            side_effect=query_clickhouse,
        ):
            payload = backend_main.dashboard_top_syn(
                range_minutes=60,
                start=START,
                end=END,
                start_time=None,
                end_time=None,
                sensor_id=None,
                interface_id=None,
                if_index=None,
                direction="both",
                mode="src",
                limit=10,
                zone_id=None,
                zone_direction="both",
            )
        self.assertEqual(payload["items"], [])
        assert_no_nested_weighted_aggregate(self, queries[-1])

    def test_configurable_conversation_widget_propagates_partial_bucket(self):
        context = {
            "range_minutes": 60,
            "start": START,
            "end": END,
            "sensor_id": None,
            "interface_id": None,
            "if_index": None,
            "zone_id": None,
            "zone_direction": "both",
            "global_filters": [],
            "prefix_filter": {"enabled": False},
        }
        base_plan = {
            "dimension": "conversation",
            "metric": "bps",
            "filters": [],
            "limit": 10,
            "direction": "both",
            "calculation": "current",
        }
        for configured, expected in (
            (OMITTED, False),
            (False, False),
            (True, True),
        ):
            plan = dict(base_plan)
            if configured is not OMITTED:
                plan["include_partial_bucket"] = configured
            with self.subTest(configured=configured), mock.patch.object(
                backend_main,
                "top_conversations_payload",
                return_value={
                    "start": START.isoformat(),
                    "end": END.isoformat(),
                    "sort_by": "bits_s",
                    "items": [],
                },
            ) as top_conversations:
                payload = backend_main.dashboard_widget_top_payload(
                    plan,
                    context,
                )
            self.assertEqual(payload["items"], [])
            args = top_conversations.call_args[0]
            self.assertIs(args[14], expected)
            self.assertEqual(args[15], {"enabled": False})


class PrefixSqlRegressionTest(unittest.TestCase):
    def capture_series(
        self,
        *,
        metric="bps",
        group_by="dst_prefix",
        aggregate=False,
        start=START,
        prefix_filter=OMITTED,
        prefix_grouping=OMITTED,
    ):
        queries = []

        def query_clickhouse(query, params=None):
            queries.append((query, dict(params or {})))
            return empty_clickhouse_result()

        context = {
            "range_minutes": 60,
            "start": start,
            "end": END,
            "sensor_id": None,
            "interface_id": None,
            "if_index": None,
            "zone_id": None,
            "zone_direction": "both",
            "series_limit": 10,
            "global_filters": [],
            "maximum_data_points": 1000,
        }
        if prefix_filter is not OMITTED:
            context["prefix_filter"] = prefix_filter
        if prefix_grouping is not OMITTED:
            context["prefix_grouping"] = prefix_grouping

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
        ):
            payload = backend_main.dashboard_widget_series_payload(
                {
                    "metric": metric,
                    "direction": "both",
                    "group_by": group_by,
                    "aggregation": "sum",
                    "calculation": "last_not_null",
                    "legend_calculation": "last_not_null",
                    "resolution_seconds": 60,
                    "include_partial_bucket": False,
                    "filters": [],
                },
                context,
            )
        return queries[-1], payload

    def test_timeseries_uses_only_selected_aliases_and_stable_order(self):
        for metric in ("bps", "pps"):
            for group_by, family_sql, grouping in (
                (
                    "src_prefix",
                    "IPv4CIDRToRange",
                    {
                        "enabled": True,
                        "ipv4_prefix_length": 24,
                        "ipv6_prefix_length": 64,
                    },
                ),
                (
                    "dst_prefix",
                    "IPv6CIDRToRange",
                    {
                        "enabled": True,
                        "ipv4_prefix_length": 24,
                        "ipv6_prefix_length": 64,
                    },
                ),
            ):
                with self.subTest(metric=metric, group_by=group_by):
                    (sql, _params), payload = self.capture_series(
                        metric=metric,
                        group_by=group_by,
                        prefix_grouping=grouping,
                    )
                    self.assertIn(family_sql, sql)
                    self.assertIn("AS total_value", sql)
                    self.assertIn(
                        "ORDER BY ts ASC, group_key ASC",
                        sql,
                    )
                    self.assertNotRegex(
                        sql,
                        r"ORDER BY\s+ts(?:\s+ASC)?,\s*value\b",
                    )
                    self.assertEqual(payload["source"], "raw")
                    assert_no_nested_weighted_aggregate(self, sql)

    def test_prefix_series_raw_aggregate_and_hybrid(self):
        cases = (
            (False, START, "raw"),
            (True, START, "aggregate_1m"),
            (True, START.replace(second=15), "aggregate_hybrid"),
        )
        for aggregate, start, expected_source in cases:
            with self.subTest(source=expected_source):
                (sql, _params), payload = self.capture_series(
                    aggregate=aggregate,
                    start=start,
                    prefix_filter={
                        "enabled": True,
                        "cidr": "2001:db8::/48",
                        "address_family": "ipv6",
                        "match_side": "destination",
                    },
                    prefix_grouping={
                        "enabled": True,
                        "ipv4_prefix_length": 24,
                        "ipv6_prefix_length": 64,
                    },
                )
                self.assertEqual(payload["source"], expected_source)
                if aggregate:
                    self.assertIn(
                        DASHBOARD_AGGREGATE_TABLES["prefix"],
                        sql,
                    )
                if expected_source == "aggregate_hybrid":
                    self.assertIn("UNION ALL", sql)

    def test_prefix_widget_activates_disabled_grouping_internally(self):
        (sql, _params), payload = self.capture_series(
            prefix_grouping={
                "enabled": False,
                "ipv4_prefix_length": 24,
                "ipv6_prefix_length": 64,
            },
        )
        self.assertIn("IPv4CIDRToRange", sql)
        self.assertIn("IPv6CIDRToRange", sql)
        self.assertEqual(payload["group_by"], "dst_prefix")

    def test_disabled_prefix_context_does_not_change_legacy_series_sql(self):
        for metric in ("bps", "pps"):
            with self.subTest(metric=metric):
                (absent_sql, absent_params), _ = self.capture_series(
                    metric=metric,
                    group_by="total",
                )
                (disabled_sql, disabled_params), _ = self.capture_series(
                    metric=metric,
                    group_by="total",
                    prefix_filter={
                        "enabled": False,
                        "cidr": "192.0.2.0/24",
                        "match_side": "source",
                    },
                    prefix_grouping={
                        "enabled": False,
                        "ipv4_prefix_length": 30,
                        "ipv6_prefix_length": 96,
                    },
                )
                self.assertEqual(absent_sql, disabled_sql)
                self.assertEqual(absent_params, disabled_params)

    def test_effective_normalization_drops_disabled_context(self):
        self.assertIsNone(
            effective_prefix_filter(
                {"enabled": False, "cidr": "192.0.2.0/24"}
            )
        )
        self.assertIsNone(
            effective_prefix_grouping(
                {
                    "enabled": False,
                    "ipv4_prefix_length": 30,
                    "ipv6_prefix_length": 96,
                }
            )
        )
        self.assertIsNone(
            effective_prefix_filter(
                {"enabled": False, "cidr": "not-a-prefix"}
            )
        )
        self.assertIsNone(
            effective_prefix_grouping(
                {
                    "enabled": False,
                    "ipv4_prefix_length": "invalid",
                }
            )
        )
        self.assertIsNotNone(
            effective_prefix_grouping({"enabled": True})
        )

    def test_every_prefix_widget_alias_executes_without_http_500(self):
        widget_types = (
            "traffic_by_prefix_bps",
            "traffic_by_prefix_pps",
            "top_source_prefixes",
            "top_destination_prefixes",
            "prefix_timeseries",
            "top_ports_by_prefix",
            "top_protocols_by_prefix",
            "prefix_table",
            "prefix_distribution",
        )
        for widget_type in widget_types:
            queries = []

            def query_clickhouse(query, params=None):
                queries.append(query)
                return empty_clickhouse_result()

            widget = validate_widget_definition(
                {
                    "title": widget_type,
                    "type": widget_type,
                    "category": "traffic",
                    "config": {"resolution_seconds": 60},
                    "visualization": {},
                    "grid": {"x": 0, "y": 0, "w": 6, "h": 6},
                }
            )
            context = {
                "range_minutes": 60,
                "start": START,
                "end": END,
                "sensor_id": None,
                "interface_id": None,
                "if_index": None,
                "zone_id": None,
                "zone_direction": "both",
                "series_limit": 10,
                "global_filters": [],
                "maximum_data_points": 1000,
                "prefix_filter": {
                    "enabled": True,
                    "cidr": "192.0.2.0/24",
                    "address_family": "ipv4",
                    "match_side": "either",
                },
                "prefix_grouping": {
                    "enabled": True,
                    "ipv4_prefix_length": 24,
                    "ipv6_prefix_length": 64,
                },
            }
            with self.subTest(widget_type=widget_type), mock.patch.object(
                backend_main,
                "dashboard_aggregate_range_covered",
                return_value=False,
            ), mock.patch.object(
                backend_main,
                "dashboard_cache_get",
                return_value=None,
            ), mock.patch.object(
                backend_main,
                "dashboard_cache_set",
                side_effect=lambda _key, payload: payload,
            ), mock.patch.object(
                backend_main,
                "resolve_dashboard_if_index",
                return_value=None,
            ), mock.patch.object(
                backend_main,
                "dashboard_interface_metadata",
                return_value={},
            ), mock.patch.object(
                backend_main,
                "query_clickhouse",
                side_effect=query_clickhouse,
            ):
                payload = backend_main.dashboard_widget_execute(
                    widget,
                    context,
                )
            self.assertTrue(queries)
            self.assertIn(payload["kind"], {"ranking", "timeseries"})
            self.assertNotIn("ORDER BY ts, value", queries[-1])
            assert_no_nested_weighted_aggregate(self, queries[-1])


class AggregateAliasRegressionTest(unittest.TestCase):
    def test_all_legacy_ranking_dimensions_aggregate_weighted_fields_once(self):
        for dimension in (
            "src_ip",
            "dst_ip",
            "dst_port",
            "proto",
            "tcp_flags",
            "src_prefix",
            "dst_prefix",
        ):
            queries = []

            def query_clickhouse(query, params=None):
                queries.append(query)
                return empty_clickhouse_result()

            with mock.patch.object(
                backend_main,
                "dashboard_aggregate_range_covered",
                return_value=True,
            ), mock.patch.object(
                backend_main,
                "dashboard_cache_get",
                return_value=None,
            ), mock.patch.object(
                backend_main,
                "dashboard_cache_set",
                side_effect=lambda _key, payload: payload,
            ), mock.patch.object(
                backend_main,
                "resolve_dashboard_if_index",
                return_value=None,
            ), mock.patch.object(
                backend_main,
                "dashboard_interface_metadata",
                return_value={},
            ), mock.patch.object(
                backend_main,
                "query_clickhouse",
                side_effect=query_clickhouse,
            ):
                backend_main.top_dimension(
                    dimension,
                    60,
                    None,
                    None,
                    10,
                    start=START,
                    end=END,
                    metric="pps" if dimension == "tcp_flags" else "bps",
                    prefix_grouping={
                        "enabled": dimension.endswith("_prefix"),
                        "ipv4_prefix_length": 24,
                        "ipv6_prefix_length": 64,
                    },
                )
            sql = queries[-1]
            self.assertIn("aggregation_base AS", sql)
            self.assertIn("AS value", sql)
            self.assertIn("ORDER BY value DESC", sql)
            assert_no_nested_weighted_aggregate(self, sql)

    def test_source_and_destination_asn_queries_use_weighted_ctes(self):
        for dimension in ("src", "dst"):
            for aggregate in (False, True):
                queries = []

                def query_clickhouse(query, params=None):
                    queries.append(query)
                    return empty_clickhouse_result()

                with self.subTest(
                    dimension=dimension,
                    aggregate=aggregate,
                ), mock.patch.object(
                    backend_main,
                    "ensure_clickhouse_schema",
                    return_value=None,
                ), mock.patch.object(
                    backend_main,
                    "dashboard_aggregate_range_covered",
                    return_value=aggregate,
                ), mock.patch.object(
                    backend_main,
                    "dashboard_cache_get",
                    return_value=None,
                ), mock.patch.object(
                    backend_main,
                    "dashboard_cache_set",
                    side_effect=lambda _key, payload: payload,
                ), mock.patch.object(
                    backend_main,
                    "resolve_dashboard_if_index",
                    return_value=None,
                ), mock.patch.object(
                    backend_main,
                    "query_clickhouse",
                    side_effect=query_clickhouse,
                ):
                    payload = backend_main.top_asn_dimension(
                        dimension,
                        60,
                        None,
                        None,
                        10,
                        start=START,
                        end=END,
                        traffic_direction=(
                            "download"
                            if dimension == "src"
                            else "upload"
                        ),
                    )
                self.assertTrue(queries)
                self.assertEqual(
                    payload["query_source"],
                    "aggregate_1m" if aggregate else "raw",
                )
                self.assertIn("weighted_source AS", queries[0])
                for sql in queries:
                    assert_no_nested_weighted_aggregate(self, sql)


if __name__ == "__main__":
    unittest.main()
