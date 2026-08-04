from __future__ import annotations

import re
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

from tests.test_collector_apply_static import backend_main


START = datetime(2026, 7, 29, 10, 0, tzinfo=timezone.utc)
END = datetime(2026, 7, 29, 11, 0, tzinfo=timezone.utc)
EXPORTER_FILTER = "toString(exporter_ip) = {exporter_ip:String}"
SENSORS = {
    1: "192.0.2.10",
    2: "2001:db8::20",
}


def empty_clickhouse_result():
    return SimpleNamespace(column_names=[], result_rows=[])


class DashboardSensorFilterSqlTest(unittest.TestCase):
    def sensor_exporter_ip(self, sensor_id):
        if sensor_id not in SENSORS:
            raise backend_main.HTTPException(
                status_code=404,
                detail="Sensor nao encontrado",
            )
        return SENSORS[sensor_id]

    def assert_no_external_exporter_filter(self, query):
        external_where_clauses = re.findall(
            r"FROM rated_source(?:\s+AS\s+\w+)?\s+WHERE\s+"
            r"(.*?)(?:GROUP BY|ORDER BY|LIMIT|\n\s*\))",
            query,
            flags=re.DOTALL,
        )
        self.assertTrue(
            external_where_clauses,
            "A consulta de teste deve selecionar de rated_source.",
        )
        for where_clause in external_where_clauses:
            self.assertNotIn(EXPORTER_FILTER, where_clause)

    def common_patches(self, queries, *, aggregate_covered=False):
        def query_clickhouse(query, params=None):
            queries.append((query, dict(params or {})))
            return empty_clickhouse_result()

        return (
            mock.patch.object(
                backend_main,
                "sensor_exporter_ip",
                side_effect=self.sensor_exporter_ip,
            ),
            mock.patch.object(
                backend_main,
                "resolve_dashboard_if_index",
                return_value=None,
            ),
            mock.patch.object(
                backend_main,
                "dashboard_aggregate_range_covered",
                return_value=aggregate_covered,
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
                "dashboard_interface_metadata",
                return_value={},
            ),
            mock.patch.object(
                backend_main,
                "interface_label_map",
                return_value={},
            ),
            mock.patch.object(
                backend_main,
                "ensure_clickhouse_schema",
                return_value=None,
            ),
            mock.patch.object(
                backend_main,
                "query_clickhouse",
                side_effect=query_clickhouse,
            ),
        )

    def run_series(self, sensor_id, metric, *, aggregate_covered=False):
        queries = []
        patches = self.common_patches(
            queries,
            aggregate_covered=aggregate_covered,
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8]:
            backend_main.dashboard_series_payload(
                range_minutes=60,
                sensor_id=sensor_id,
                interface_id=None,
                if_index=None,
                direction="both",
                group_by="total",
                metric=metric,
                start=START,
                end=END,
                start_time=None,
                end_time=None,
                limit=10,
                maximum_data_points=1000,
            )
        return queries

    def run_ranking(
        self,
        sensor_id,
        dimension,
        *,
        aggregate_covered=False,
        metric="bps",
    ):
        queries = []
        patches = self.common_patches(
            queries,
            aggregate_covered=aggregate_covered,
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8]:
            backend_main.top_dimension(
                dimension=dimension,
                range_minutes=60,
                sensor=None,
                sensor_id=sensor_id,
                limit=10,
                start=START,
                end=END,
                metric=metric,
            )
        return queries

    def run_asn_ranking(
        self,
        dimension,
        *,
        aggregate_covered=False,
        flow_orientation="canonical",
    ):
        queries = []
        patches = self.common_patches(
            queries,
            aggregate_covered=aggregate_covered,
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8]:
            backend_main.top_asn_dimension(
                dimension=dimension,
                range_minutes=60,
                sensor=None,
                sensor_id=None,
                limit=10,
                start=START,
                end=END,
                traffic_direction=(
                    "download" if dimension == "src" else "upload"
                ),
                flow_orientation=flow_orientation,
            )
        return queries

    def assert_sensor_filter(self, query, params, sensor_id, occurrences):
        if sensor_id is None:
            self.assertNotIn(EXPORTER_FILTER, query)
            self.assertNotIn("exporter_ip", params)
            return
        self.assertEqual(query.count(EXPORTER_FILTER), occurrences)
        self.assertEqual(
            params["exporter_ip"],
            backend_main.clickhouse_ip_string_param(
                SENSORS[sensor_id],
                "exporter_ip",
            ),
        )
        self.assert_no_external_exporter_filter(query)

    def test_series_bps_and_pps_filter_each_physical_source_only(self):
        for metric in ("bits_s", "packets_s"):
            for sensor_id in (None, 1, 2):
                with self.subTest(metric=metric, sensor_id=sensor_id):
                    queries = self.run_series(sensor_id, metric)
                    self.assertEqual(len(queries), 1)
                    query, params = queries[0]
                    self.assert_sensor_filter(
                        query,
                        params,
                        sensor_id,
                        occurrences=1,
                    )
                    self.assertIn("FROM flow_raw", query)

    def test_rankings_cover_ips_ports_protocols_and_tcp_flags(self):
        for dimension in (
            "src_ip",
            "dst_ip",
            "dst_port",
            "proto",
            "tcp_flags",
        ):
            for sensor_id in (None, 1, 2):
                with self.subTest(
                    dimension=dimension,
                    sensor_id=sensor_id,
                ):
                    queries = self.run_ranking(sensor_id, dimension)
                    self.assertEqual(len(queries), 1)
                    query, params = queries[0]
                    self.assert_sensor_filter(
                        query,
                        params,
                        sensor_id,
                        occurrences=1,
                    )

    def test_each_ranking_dimension_has_its_own_select_and_group_by(self):
        expectations = {
            "src_ip": ("toString(src_ip) AS ip", "GROUP BY ip"),
            "dst_ip": ("toString(dst_ip) AS ip", "GROUP BY ip"),
            "dst_port": ("dst_port AS port", "GROUP BY port, proto"),
            "proto": ("SELECT\n            proto,", "GROUP BY proto"),
            "tcp_flags": ("SELECT\n            tcp_flags,", "GROUP BY tcp_flags"),
        }
        queries = {}
        for dimension, (select_sql, group_sql) in expectations.items():
            metric = "pps" if dimension == "tcp_flags" else "bps"
            query, _params = self.run_ranking(
                None,
                dimension,
                metric=metric,
            )[0]
            queries[dimension] = query
            self.assertIn(select_sql, query)
            self.assertIn(group_sql, query)
        self.assertEqual(len(set(queries.values())), len(expectations))
        self.assertIn("AND proto = 6", queries["tcp_flags"])
        self.assertIn("packets_s AS value", queries["tcp_flags"])
        self.assertIn("ORDER BY value DESC", queries["tcp_flags"])

    def test_hybrid_query_filters_raw_and_minute_aggregate_not_outer_cte(self):
        series_query, series_params = self.run_series(
            1,
            "bits_s",
            aggregate_covered=True,
        )[0]
        self.assert_sensor_filter(
            series_query,
            series_params,
            1,
            occurrences=2,
        )
        self.assertIn("FROM flow_raw", series_query)
        self.assertIn(
            "FROM flow_dashboard_series_1m",
            series_query,
        )

        ranking_query, ranking_params = self.run_ranking(
            2,
            "dst_port",
            aggregate_covered=True,
        )[0]
        self.assert_sensor_filter(
            ranking_query,
            ranking_params,
            2,
            occurrences=2,
        )
        self.assertIn("FROM flow_dashboard_dst_port_1m", ranking_query)
        self.assertIn("GROUP BY port, proto", ranking_query)

    def test_all_ranking_dimensions_keep_their_dimension_in_hybrid_sql(self):
        aggregate_tables = {
            "src_ip": "flow_dashboard_src_ip_1m",
            "dst_ip": "flow_dashboard_dst_ip_1m",
            "dst_port": "flow_dashboard_dst_port_1m",
            "proto": "flow_dashboard_protocol_1m",
            "tcp_flags": "flow_dashboard_tcp_flags_tcp_1m",
        }
        for dimension, aggregate_table in aggregate_tables.items():
            with self.subTest(dimension=dimension):
                query, _params = self.run_ranking(
                    None,
                    dimension,
                    aggregate_covered=True,
                    metric="pps" if dimension == "tcp_flags" else "bps",
                )[0]
                self.assertIn("FROM flow_raw", query)
                self.assertIn("FROM %s" % aggregate_table, query)
                if dimension == "tcp_flags":
                    self.assertIn("tcp_flags, proto", query)
                    self.assertIn("proto = 6", query)

    def test_asn_rankings_keep_source_and_destination_in_raw_and_hybrid_sql(self):
        expectations = {
            "src": (
                "toUInt32(src_asn) AS asn",
                "FROM flow_dashboard_asn_src_1m",
                "input_if > 0",
            ),
            "dst": (
                "toUInt32(dst_asn) AS asn",
                "FROM flow_dashboard_asn_dst_1m",
                "output_if > 0",
            ),
        }
        for dimension, (select_sql, aggregate_sql, direction_sql) in (
            expectations.items()
        ):
            with self.subTest(dimension=dimension, source="raw"):
                raw_query, _params = self.run_asn_ranking(dimension)[0]
                self.assertIn(select_sql, raw_query)
                self.assertIn("GROUP BY asn", raw_query)
                self.assertIn(direction_sql, raw_query)
                self.assertNotIn(aggregate_sql, raw_query)
            with self.subTest(dimension=dimension, source="hybrid"):
                hybrid_query, _params = self.run_asn_ranking(
                    dimension,
                    aggregate_covered=True,
                )[0]
                self.assertIn(select_sql, hybrid_query)
                self.assertIn("FROM flow_raw", hybrid_query)
                self.assertIn(aggregate_sql, hybrid_query)
                self.assertIn(direction_sql, hybrid_query)

        reversed_query, _params = self.run_asn_ranking(
            "dst",
            aggregate_covered=True,
            flow_orientation="reversed",
        )[0]
        self.assertIn("toUInt32(src_asn) AS asn", reversed_query)
        self.assertIn("FROM flow_dashboard_asn_src_1m", reversed_query)
        self.assertIn("input_if > 0", reversed_query)

    def test_zone_direction_respects_selected_asn_dimension_and_orientation(self):
        cases = (
            ("dst", "upload", "canonical", "transmits", "dst_asn"),
            ("src", "upload", "canonical", "transmits", "src_asn"),
            ("src", "download", "canonical", "receives", "src_asn"),
            ("dst", "download", "canonical", "receives", "dst_asn"),
            ("src", "upload", "reversed", "receives", "dst_asn"),
            ("dst", "download", "reversed", "transmits", "src_asn"),
        )
        for dimension, direction, orientation, zone_edge, asn_column in cases:
            with self.subTest(
                dimension=dimension,
                direction=direction,
                orientation=orientation,
            ):
                queries = []
                patches = self.common_patches(queries)
                zone_directions = []

                def zone_filter(_zone_id, zone_direction, _params, _prefix):
                    zone_directions.append(zone_direction)
                    return "zone_%s" % zone_direction

                with patches[0], patches[1], patches[2], patches[3], \
                        patches[4], patches[5], patches[6], patches[7], \
                        patches[8], mock.patch.object(
                            backend_main,
                            "build_zone_flow_filter",
                            side_effect=zone_filter,
                        ):
                    backend_main.top_asn_dimension(
                        dimension=dimension,
                        range_minutes=60,
                        sensor=None,
                        sensor_id=None,
                        limit=10,
                        start=START,
                        end=END,
                        zone_id=9,
                        zone_direction="both",
                        traffic_direction=direction,
                        flow_orientation=orientation,
                    )
                self.assertEqual(zone_directions, [zone_edge])
                self.assertIn("zone_%s" % zone_edge, queries[0][0])
                self.assertIn(
                    "toUInt32(%s) AS asn" % asn_column,
                    queries[0][0],
                )

    def test_generic_configurable_series_uses_rated_filter(self):
        queries = []
        patches = self.common_patches(queries)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8]:
            backend_main.dashboard_widget_series_payload(
                {
                    "metric": "bps",
                    "direction": "both",
                    "group_by": "total",
                    "aggregation": "sum",
                    "calculation": "last_not_null",
                    "legend_calculation": "last_not_null",
                    "resolution_seconds": 60,
                    "include_partial_bucket": False,
                    "filters": [],
                },
                {
                    "range_minutes": 60,
                    "start": START,
                    "end": END,
                    "sensor_id": 1,
                    "interface_id": None,
                    "if_index": None,
                    "zone_id": None,
                    "zone_direction": "both",
                    "series_limit": 10,
                    "global_filters": [],
                    "maximum_data_points": 1000,
                },
            )
        self.assertEqual(len(queries), 1)
        query, params = queries[0]
        self.assert_sensor_filter(
            query,
            params,
            1,
            occurrences=1,
        )

    def test_missing_sensor_fails_before_clickhouse_query(self):
        queries = []
        patches = self.common_patches(queries)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8]:
            with self.assertRaises(backend_main.HTTPException) as caught:
                backend_main.dashboard_series_payload(
                    range_minutes=60,
                    sensor_id=999,
                    interface_id=None,
                    if_index=None,
                    direction="both",
                    group_by="total",
                    metric="bits_s",
                    start=START,
                    end=END,
                    start_time=None,
                    end_time=None,
                    limit=10,
                )
        self.assertEqual(caught.exception.status_code, 404)
        self.assertEqual(queries, [])

    def test_shared_filter_builder_keeps_source_and_outer_contracts(self):
        with mock.patch.object(
            backend_main,
            "sensor_exporter_ip",
            side_effect=self.sensor_exporter_ip,
        ), mock.patch.object(
            backend_main,
            "resolve_dashboard_if_index",
            return_value=None,
        ):
            context = backend_main.flow_query_context(
                range_minutes=60,
                start=START,
                end=END,
                sensor_id=1,
            )
        self.assertIn(EXPORTER_FILTER, context["source_where"])
        self.assertNotIn(EXPORTER_FILTER, context["rated_where"])
        self.assertEqual(context["where"], context["source_where"])
        self.assertEqual(
            backend_main.dashboard_rated_source_where(
                EXPORTER_FILTER
            ),
            "1",
        )


class GrafanaRankingExecutionPlanTest(unittest.TestCase):
    def request_data(
        self,
        metric,
        *,
        direction="both",
        protocols=None,
    ):
        return {
            "metric": metric,
            "start": START,
            "end": END,
            "top_n": 10,
            "calculation": "rate",
            "filters": {
                "direction": direction,
                "sensor_ids": [4],
                "interfaces": [11],
                "protocols": list(protocols or []),
            },
        }

    def test_rankings_executed_sequentially_do_not_contaminate_next_metric(self):
        expected = [
            ("top_source_ips", "src_ip", "both", "bps"),
            ("top_destination_ips", "dst_ip", "both", "bps"),
            ("top_ports", "dst_port", "both", "bps"),
            ("top_protocols", "protocol", "both", "bps"),
            ("top_tcp_flags", "tcp_flags", "both", "pps"),
            ("top_upload_destinations", "dst_asn", "upload", "bps"),
            ("top_download_origins", "src_asn", "download", "bps"),
        ]
        captured = []

        def capture(plan, context):
            captured.append((dict(plan), dict(context)))
            return {"items": [], "source": "test"}

        with mock.patch.object(
            backend_main,
            "dashboard_widget_top_payload",
            side_effect=capture,
        ):
            for metric, _dimension, _direction, _value_metric in expected:
                backend_main.execute_grafana_ranking(
                    self.request_data(metric)
                )

        self.assertEqual(
            [
                (
                    metric,
                    plan["dimension"],
                    plan["direction"],
                    plan["metric"],
                )
                for (metric, _dimension, _direction, _value_metric),
                (plan, _context) in zip(expected, captured)
            ],
            expected,
        )
        self.assertEqual(
            [plan["dimension"] for plan, _context in captured],
            [
                "src_ip",
                "dst_ip",
                "dst_port",
                "protocol",
                "tcp_flags",
                "dst_asn",
                "src_asn",
            ],
        )

    def test_direction_sensor_interface_protocol_and_window_reach_planner(self):
        captured = {}

        def capture(plan, context):
            captured["plan"] = plan
            captured["context"] = context
            return {"items": [], "source": "test"}

        with mock.patch.object(
            backend_main,
            "dashboard_widget_top_payload",
            side_effect=capture,
        ):
            backend_main.execute_grafana_ranking(
                self.request_data(
                    "top_ports",
                    direction="upload",
                    protocols=["udp"],
                )
            )

        plan = captured["plan"]
        context = captured["context"]
        self.assertEqual(plan["dimension"], "dst_port")
        self.assertEqual(plan["direction"], "upload")
        self.assertEqual(
            plan["filters"],
            [{"field": "protocol", "operator": "eq", "value": "udp"}],
        )
        self.assertEqual(context["sensor_id"], 4)
        self.assertEqual(context["if_index"], 11)
        self.assertEqual(context["start"], START)
        self.assertEqual(context["end"], END)

    def test_tcp_flags_is_tcp_only_and_conflicting_udp_filter_is_empty(self):
        result = backend_main.execute_grafana_ranking(
            self.request_data(
                "top_tcp_flags",
                protocols=["udp"],
            )
        )
        self.assertEqual(result["dimension"], "tcp_flags")
        self.assertEqual(result["items"], [])
        self.assertEqual(result["total"], 0)

        captured = {}

        def capture(plan, context):
            captured["plan"] = plan
            return {"items": [], "source": "test"}

        with mock.patch.object(
            backend_main,
            "dashboard_widget_top_payload",
            side_effect=capture,
        ):
            backend_main.execute_grafana_ranking(
                self.request_data(
                    "top_tcp_flags",
                    direction="download",
                )
            )
        self.assertEqual(
            captured["plan"]["filters"],
            [{"field": "protocol", "operator": "eq", "value": "tcp"}],
        )

    def test_fixed_upload_download_metrics_do_not_override_conflicting_filter(self):
        upload_result = backend_main.execute_grafana_ranking(
            self.request_data(
                "top_upload_destinations",
                direction="download",
            )
        )
        download_result = backend_main.execute_grafana_ranking(
            self.request_data(
                "top_download_origins",
                direction="upload",
            )
        )
        self.assertEqual(upload_result["items"], [])
        self.assertEqual(download_result["items"], [])
        self.assertEqual(upload_result["dimension"], "dst_asn")
        self.assertEqual(download_result["dimension"], "src_asn")


if __name__ == "__main__":
    unittest.main()
