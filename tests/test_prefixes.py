from __future__ import annotations

import os
import sqlite3
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

from backend.app.services.dashboard_aggregates import (
    DASHBOARD_AGGREGATE_TABLES,
    dashboard_aggregate_schema_statements,
)
from backend.app.services.dashboard_widgets import (
    create_dashboard,
    ensure_dashboard_schema,
    get_dashboard,
    normalize_dashboard_payload,
    validate_widget_definition,
    widget_catalog,
    widget_data_signature,
)
from backend.app.services.prefixes import (
    create_prefix,
    ensure_prefix_schema,
    get_prefix,
    normalize_prefix_filter,
    normalize_prefix_grouping,
    preview_subnets,
    resolve_prefix_filter,
    update_prefix,
)
from tests.test_collector_apply_static import backend_main


START = datetime(2026, 7, 29, 10, 0, tzinfo=timezone.utc)
END = datetime(2026, 7, 29, 11, 0, tzinfo=timezone.utc)


def empty_clickhouse_result():
    return SimpleNamespace(column_names=[], result_rows=[])


class PrefixPreviewTest(unittest.TestCase):
    def test_ipv4_subdivision_counts_and_boundaries(self):
        twenty = preview_subnets("186.232.160.0/20", 24)
        self.assertEqual(twenty["total"], 16)
        self.assertEqual(twenty["start"], "186.232.160.0/24")
        self.assertEqual(twenty["end"], "186.232.175.0/24")
        self.assertEqual(len(twenty["items"]), 16)

        twenty_two = preview_subnets("186.232.160.0/22", 24)
        self.assertEqual(twenty_two["total"], 4)
        self.assertEqual(twenty_two["items"][-1], "186.232.163.0/24")

        same = preview_subnets("186.232.160.0/24", 24)
        self.assertEqual(same["items"], ["186.232.160.0/24"])

    def test_ipv6_pagination_direct_lookup_and_safe_limit(self):
        page = preview_subnets(
            "2001:db8:1200::/48",
            56,
            offset=10,
            limit=3,
        )
        self.assertEqual(page["total"], 256)
        self.assertEqual(len(page["items"]), 3)
        self.assertEqual(page["next_offset"], 13)
        self.assertTrue(all(item.endswith("/56") for item in page["items"]))

        old = os.environ.get("GMJ_FLOW_PREFIX_PREVIEW_MAX_IPV6")
        os.environ["GMJ_FLOW_PREFIX_PREVIEW_MAX_IPV6"] = "16"
        try:
            with self.assertRaisesRegex(ValueError, "expansão excessiva"):
                preview_subnets("2001:db8::/48", 64)
            direct = preview_subnets(
                "2001:db8::/48",
                64,
                contains_ip="2001:db8:0:12::1",
            )
            self.assertTrue(direct["direct_lookup"])
            self.assertEqual(direct["items"], ["2001:db8:0:12::/64"])
            direct_cidr = preview_subnets(
                "2001:db8::/48",
                64,
                contains_cidr="2001:db8:0:20::/64",
            )
            self.assertEqual(direct_cidr["lookup"], "cidr")
            self.assertEqual(
                direct_cidr["items"],
                ["2001:db8:0:20::/64"],
            )
        finally:
            if old is None:
                os.environ.pop("GMJ_FLOW_PREFIX_PREVIEW_MAX_IPV6", None)
            else:
                os.environ["GMJ_FLOW_PREFIX_PREVIEW_MAX_IPV6"] = old

    def test_invalid_network_and_lengths_are_readable(self):
        with self.assertRaisesRegex(ValueError, "CIDR"):
            preview_subnets("not-an-ip", 24)
        with self.assertRaisesRegex(ValueError, "prefix_length"):
            preview_subnets("192.0.2.0/24", 20)
        with self.assertRaisesRegex(ValueError, "prefix_length"):
            preview_subnets("2001:db8::/48", 129)


class PrefixPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)"
        )
        self.conn.execute("INSERT INTO users(id, username) VALUES (1, 'admin')")
        ensure_dashboard_schema(self.conn)
        ensure_prefix_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_crud_resolution_and_dashboard_storage(self):
        prefix = create_prefix(
            self.conn,
            {
                "name": "Cliente A",
                "cidr": "186.232.160.1/20",
                "default_split_prefix_length": 24,
            },
        )
        self.assertEqual(prefix["cidr"], "186.232.160.0/20")
        self.assertEqual(prefix["address_family"], "ipv4")
        updated = update_prefix(
            self.conn,
            prefix["id"],
            {"description": "Borda principal"},
        )
        self.assertEqual(updated["description"], "Borda principal")
        self.assertEqual(get_prefix(self.conn, prefix["id"])["name"], "Cliente A")

        resolved = resolve_prefix_filter(
            self.conn,
            {
                "enabled": True,
                "prefix_id": prefix["id"],
                "match_side": "either",
            },
        )
        self.assertEqual(resolved["cidr"], "186.232.160.0/20")

        dashboard = create_dashboard(
            self.conn,
            {
                "name": "Prefixos",
                "prefix_filter": {
                    "enabled": True,
                    "prefix_id": prefix["id"],
                    "address_family": "ipv4",
                    "match_side": "source",
                },
                "prefix_grouping": {
                    "enabled": True,
                    "ipv4_prefix_length": 24,
                    "ipv6_prefix_length": 64,
                    "side": "source",
                    "top_n": 20,
                },
                "refresh_interval_seconds": 30,
            },
            1,
        )
        reloaded = get_dashboard(self.conn, dashboard["id"])
        self.assertEqual(reloaded["prefix_filter"]["prefix_id"], prefix["id"])
        self.assertEqual(
            reloaded["prefix_grouping"]["ipv4_prefix_length"],
            24,
        )

    def test_filter_and_grouping_validation(self):
        source = normalize_prefix_filter(
            {
                "cidr": "192.0.2.9/24",
                "match_side": "source",
                "address_family": "ipv4",
            }
        )
        self.assertEqual(source["cidr"], "192.0.2.0/24")
        ranged = normalize_prefix_filter(
            {
                "start_ip": "2001:db8::1",
                "end_ip": "2001:db8::ffff",
                "address_family": "ipv6",
                "match_side": "both",
            }
        )
        self.assertTrue(ranged["enabled"])
        with self.assertRaisesRegex(ValueError, "start_ip"):
            normalize_prefix_filter(
                {"start_ip": "192.0.2.20", "end_ip": "192.0.2.10"}
            )
        grouping = normalize_prefix_grouping(
            {
                "enabled": True,
                "ipv4_prefix_length": 26,
                "ipv6_prefix_length": 56,
                "side": "destination",
                "top_n": 50,
            }
        )
        self.assertEqual(grouping["ipv6_prefix_length"], 56)

    def test_prefix_context_separates_widget_cache(self):
        widget = validate_widget_definition(
            {
                "title": "Portas",
                "type": "top_ports_by_prefix",
                "category": "traffic",
                "config": {},
                "visualization": {"type": "table"},
                "grid": {"x": 0, "y": 0, "w": 6, "h": 6},
                "refresh_interval_seconds": 30,
            }
        )
        base = {
            "range_minutes": 60,
            "time_range": {"minutes": 60},
            "prefix_grouping": normalize_prefix_grouping({}),
        }
        one = widget_data_signature(
            widget,
            {
                **base,
                "prefix_filter": normalize_prefix_filter(
                    {"cidr": "192.0.2.0/24"}
                ),
            },
        )
        two = widget_data_signature(
            widget,
            {
                **base,
                "prefix_filter": normalize_prefix_filter(
                    {"cidr": "192.0.3.0/24"}
                ),
            },
        )
        self.assertNotEqual(one, two)

    def test_all_prefix_widget_types_are_catalogued_and_semantically_stable(self):
        expected = {
            "traffic_by_prefix_bps",
            "traffic_by_prefix_pps",
            "top_source_prefixes",
            "top_destination_prefixes",
            "prefix_timeseries",
            "top_ports_by_prefix",
            "top_protocols_by_prefix",
            "prefix_table",
            "prefix_distribution",
        }
        catalog = widget_catalog()
        self.assertTrue(
            expected.issubset({item["id"] for item in catalog["types"]})
        )
        self.assertTrue(
            expected.issubset(
                {item["type"] for item in catalog["presets"]}
            )
        )
        for widget_type in expected:
            widget = validate_widget_definition(
                {
                    "title": widget_type,
                    "type": widget_type,
                    "category": "traffic",
                    "config": {},
                    "visualization": {},
                    "grid": {"x": 0, "y": 0, "w": 6, "h": 6},
                }
            )
            self.assertIn(widget["type"], {"top_n", "timeseries"})
            self.assertEqual(
                widget["config"]["widget_alias"],
                widget_type,
            )


class PrefixClickHousePlannerTest(unittest.TestCase):
    def capture_ranking(
        self,
        match_side: str,
        aggregate: bool,
        *,
        dimension: str = "dst_port",
        metric: str = "bps",
    ):
        queries = []

        def query_clickhouse(query, params=None):
            queries.append((query, dict(params or {})))
            return empty_clickhouse_result()

        patches = (
            mock.patch.object(
                backend_main,
                "dashboard_aggregate_range_covered",
                return_value=aggregate,
            ),
            mock.patch.object(
                backend_main,
                "dashboard_cache_get",
                return_value=None,
            ),
            mock.patch.object(
                backend_main,
                "dashboard_cache_set",
                side_effect=lambda _key, payload: payload,
            ),
            mock.patch.object(
                backend_main,
                "resolve_dashboard_if_index",
                return_value=None,
            ),
            mock.patch.object(
                backend_main,
                "dashboard_interface_metadata",
                return_value={},
            ),
            mock.patch.object(
                backend_main,
                "query_clickhouse",
                side_effect=query_clickhouse,
            ),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            payload = backend_main.top_dimension(
                dimension,
                60,
                None,
                None,
                10,
                start=START,
                end=END,
                metric=metric,
                prefix_filter={
                    "enabled": True,
                    "cidr": "192.0.2.0/24",
                    "address_family": "ipv4",
                    "match_side": match_side,
                },
            )
        return queries[-1], payload

    def capture_series(
        self,
        metric: str,
        *,
        aggregate: bool,
        start: datetime = START,
    ):
        queries = []

        def query_clickhouse(query, params=None):
            queries.append((query, dict(params or {})))
            return empty_clickhouse_result()

        with mock.patch.object(
            backend_main,
            "dashboard_aggregate_range_covered",
            return_value=aggregate,
        ), mock.patch.object(
            backend_main,
            "resolve_dashboard_if_index",
            return_value=12,
        ), mock.patch.object(
            backend_main,
            "query_clickhouse",
            side_effect=query_clickhouse,
        ):
            payload = backend_main.dashboard_widget_series_payload(
                {
                    "metric": metric,
                    "direction": "both",
                    "group_by": "dst_prefix",
                    "aggregation": "sum",
                    "calculation": "last_not_null",
                    "legend_calculation": "last_not_null",
                    "resolution_seconds": 60,
                    "include_partial_bucket": False,
                    "filters": [],
                },
                {
                    "range_minutes": 60,
                    "start": start,
                    "end": END,
                    "sensor_id": None,
                    "interface_id": None,
                    "if_index": 12,
                    "zone_id": None,
                    "zone_direction": "both",
                    "series_limit": 10,
                    "global_filters": [],
                    "maximum_data_points": 1000,
                    "prefix_filter": {
                        "enabled": True,
                        "cidr": "2001:db8:1200::/48",
                        "address_family": "ipv6",
                        "match_side": "destination",
                    },
                    "prefix_grouping": {
                        "enabled": True,
                        "ipv4_prefix_length": 24,
                        "ipv6_prefix_length": 56,
                        "side": "destination",
                    },
                },
            )
        return queries[-1], payload

    def test_source_destination_either_both_and_raw(self):
        for side, connective in (
            ("source", None),
            ("destination", None),
            ("either", " OR "),
            ("both", " AND "),
        ):
            (sql, params), payload = self.capture_ranking(side, False)
            self.assertIn("FROM flow_raw", sql)
            self.assertIn("toIPv6({top_prefix_start:String})", sql)
            # flow_raw stores IPv4 as IPv4-mapped IPv6, so native comparisons
            # receive the equivalent mapped start/end boundaries.
            self.assertEqual(
                params["top_prefix_start"],
                "::ffff:192.0.2.0",
            )
            self.assertEqual(params["top_prefix_end"], "::ffff:192.0.2.255")
            if side == "source":
                self.assertIn("src_ip >= toIPv6(", sql)
            elif side == "destination":
                self.assertIn("dst_ip >= toIPv6(", sql)
            else:
                self.assertIn(connective, sql)
            self.assertEqual(payload["query_source"], "raw")

    def test_aggregate_1m_and_hybrid_use_prefix_table(self):
        (aligned_sql, _), aligned = self.capture_ranking("either", True)
        self.assertIn(DASHBOARD_AGGREGATE_TABLES["prefix"], aligned_sql)
        self.assertEqual(aligned["query_source"], "aggregate_1m")

        non_aligned_start = START.replace(second=15)
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
            payload = backend_main.top_dimension(
                "proto",
                60,
                None,
                None,
                10,
                start=non_aligned_start,
                end=END,
                prefix_filter={"cidr": "2001:db8::/48"},
            )
        self.assertIn("UNION ALL", queries[-1])
        self.assertEqual(payload["query_source"], "aggregate_hybrid")

    def test_bits_pps_and_all_top_dimensions_receive_early_prefix_filter(self):
        for metric in ("bps", "pps"):
            for dimension in (
                "src_ip",
                "dst_ip",
                "dst_port",
                "proto",
                "tcp_flags",
            ):
                with self.subTest(metric=metric, dimension=dimension):
                    (sql, params), payload = self.capture_ranking(
                        "either",
                        False,
                        dimension=dimension,
                        metric=metric,
                    )
                    self.assertIn("FROM flow_raw", sql)
                    self.assertIn("toIPv6({top_prefix_start:String})", sql)
                    self.assertEqual(
                        params["top_prefix_start"],
                        "::ffff:192.0.2.0",
                    )
                    self.assertEqual(payload["query_source"], "raw")
                    if dimension == "tcp_flags":
                        self.assertIn("proto = 6", sql)

        for metric in ("bps", "pps"):
            with self.subTest(series_metric=metric):
                (sql, params), payload = self.capture_series(
                    metric,
                    aggregate=False,
                )
                self.assertIn("FROM flow_raw", sql)
                self.assertIn("dst_ip >= toIPv6({flow_prefix_start:String})", sql)
                self.assertIn("IPv6CIDRToRange(dst_ip, 56)", sql)
                self.assertEqual(
                    params["flow_prefix_start"],
                    "2001:db8:1200::",
                )
                self.assertEqual(payload["source"], "raw")

    def test_prefix_series_uses_1m_and_hybrid_sources(self):
        (aggregate_sql, _params), aggregate = self.capture_series(
            "bps",
            aggregate=True,
        )
        self.assertIn(DASHBOARD_AGGREGATE_TABLES["prefix"], aggregate_sql)
        self.assertEqual(aggregate["source"], "aggregate_1m")

        (hybrid_sql, _params), hybrid = self.capture_series(
            "pps",
            aggregate=True,
            start=START.replace(second=15),
        )
        self.assertIn("UNION ALL", hybrid_sql)
        self.assertIn(DASHBOARD_AGGREGATE_TABLES["prefix"], hybrid_sql)
        self.assertEqual(hybrid["source"], "aggregate_hybrid")

    def test_prefix_filter_reaches_source_and_destination_asn_rankings(self):
        for dimension in ("src", "dst"):
            queries = []

            def query_clickhouse(query, params=None):
                queries.append((query, dict(params or {})))
                return empty_clickhouse_result()

            with mock.patch.object(
                backend_main,
                "ensure_clickhouse_schema",
                return_value=None,
            ), mock.patch.object(
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
                return_value=9,
            ), mock.patch.object(
                backend_main,
                "dashboard_interface_metadata",
                return_value={},
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
                    if_index=9,
                    traffic_direction=(
                        "download" if dimension == "src" else "upload"
                    ),
                    prefix_filter={
                        "enabled": True,
                        "cidr": "2001:db8::/48",
                        "address_family": "ipv6",
                        "match_side": "either",
                    },
                    protocol="tcp",
                )
            sql, params = queries[0]
            self.assertIn(DASHBOARD_AGGREGATE_TABLES["prefix"], sql)
            self.assertIn("toIPv6({asn_prefix_start:String})", sql)
            self.assertIn("proto = {asn_protocol:UInt8}", sql)
            self.assertEqual(params["asn_protocol"], 6)
            self.assertEqual(params["if_index"], 9)
            self.assertEqual(payload["query_source"], "aggregate_1m")

    def test_range_and_real_cidr_group_expression(self):
        params = {}
        condition = backend_main.clickhouse_prefix_filter_condition(
            {
                "enabled": True,
                "start_ip": "192.0.2.10",
                "end_ip": "192.0.2.20",
                "address_family": "ipv4",
                "match_side": "both",
                "direction": "download",
            },
            params,
            "range",
        )
        self.assertIn("toIPv6({range_start:String})", condition)
        self.assertIn(" AND ", condition)
        self.assertIn("input_if > 0", condition)
        expression = backend_main.dashboard_prefix_group_expression(
            "src_ip",
            {
                "ipv4_prefix_length": 24,
                "ipv6_prefix_length": 64,
            },
        )
        self.assertIn("IPv4CIDRToRange", expression)
        self.assertIn("IPv6CIDRToRange", expression)
        self.assertIn("'/24'", expression)
        self.assertIn("'/64'", expression)

    def test_prefix_aggregate_schema_is_minute_granular(self):
        sql = "\n".join(dashboard_aggregate_schema_statements())
        self.assertIn("flow_dashboard_prefix_1m", sql)
        for field in (
            "src_ip IPv6",
            "dst_ip IPv6",
            "src_port UInt16",
            "dst_port UInt16",
            "tcp_flags UInt16",
            "src_asn UInt32",
            "dst_asn UInt32",
        ):
            self.assertIn(field, sql)
        self.assertIn("toStartOfMinute(flow_time)", sql)


if __name__ == "__main__":
    unittest.main()
