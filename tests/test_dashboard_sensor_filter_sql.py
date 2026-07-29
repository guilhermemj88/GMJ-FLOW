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

    def run_ranking(self, sensor_id, dimension, *, aggregate_covered=False):
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


if __name__ == "__main__":
    unittest.main()
