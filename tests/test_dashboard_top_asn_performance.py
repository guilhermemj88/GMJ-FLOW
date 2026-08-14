from __future__ import annotations

import sqlite3
import threading
import time
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

from backend.app.services.asn_local_cache import resolve_asn_ips_from_local_db
from backend.app.services.dashboard_cache import MemoryDashboardCache
from backend.app.services.dashboard_performance import DashboardPerformanceTrace
from tests.test_collector_apply_static import backend_main
from tests.test_dashboard_performance import config, memory


START = datetime(2026, 8, 13, 10, 0, tzinfo=timezone.utc)
END = datetime(2026, 8, 13, 11, 0, tzinfo=timezone.utc)


def clickhouse_result(columns, rows, summary=None):
    return SimpleNamespace(
        column_names=list(columns),
        result_rows=list(rows),
        summary=dict(summary or {}),
    )


class DashboardAsnBatchResolutionTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        backend_main.ensure_asn_db(self.conn)
        now = backend_main.utc_now_iso()
        self.conn.executemany(
            """
            INSERT INTO asn_prefixes (
                prefix, ip_version, asn, as_name, country, source,
                first_seen_at, updated_at
            ) VALUES (?, 4, ?, ?, 'BR', 'test', ?, ?)
            """,
            [
                ("11.0.0.0/8", 64500, "broad", now, now),
                ("11.10.20.0/24", 64501, "specific", now, now),
                ("12.0.0.0/8", 64502, "other", now, now),
            ],
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_batch_reads_prefix_catalog_once_and_keeps_longest_match(self):
        prefix_reads = []

        def trace(sql):
            if "FROM asn_prefixes" in sql:
                prefix_reads.append(sql)

        self.conn.set_trace_callback(trace)
        resolved = resolve_asn_ips_from_local_db(
            self.conn,
            ["11.10.20.7", "11.22.1.1", "12.4.3.2", "192.0.2.1"],
        )
        self.assertEqual(resolved["11.10.20.7"]["asn"], 64501)
        self.assertEqual(resolved["11.22.1.1"]["asn"], 64500)
        self.assertEqual(resolved["12.4.3.2"]["asn"], 64502)
        self.assertNotIn("192.0.2.1", resolved)
        self.assertEqual(len(prefix_reads), 1)

    def test_existing_resolution_queue_entries_are_not_touched_by_refresh(self):
        backend_main.queue_asn_resolution(self.conn, "8.8.8.8")
        backend_main.queue_asn_info_resolution(self.conn, 64666)
        self.conn.execute(
            "UPDATE asn_resolution_queue SET last_seen_at='old', updated_at='old'"
        )
        self.conn.commit()

        @contextmanager
        def connection():
            yield self.conn

        with mock.patch.object(
            backend_main,
            "ensure_sensor_db",
            return_value=None,
        ), mock.patch.object(
            backend_main,
            "sqlite_connection",
            connection,
        ):
            resolved = backend_main.resolve_asns_for_ips(["8.8.8.8"])
            information = backend_main.lookup_asn_information_batch([64666])

        rows = self.conn.execute(
            "SELECT ip,last_seen_at,updated_at FROM asn_resolution_queue ORDER BY ip"
        ).fetchall()
        self.assertEqual(resolved["8.8.8.8"]["asn"], 0)
        self.assertEqual(information, {})
        self.assertEqual(
            [(row["ip"], row["last_seen_at"], row["updated_at"]) for row in rows],
            [("8.8.8.8", "old", "old"), ("AS64666", "old", "old")],
        )


class DashboardTopAsnQueryTest(unittest.TestCase):
    def test_known_and_locally_resolved_asn_use_one_clickhouse_query(self):
        queries = []
        result = clickhouse_result(
            [
                "asn",
                "ip",
                "as_name",
                "bps",
                "packets",
                "flows",
                "total_bps",
                "group_rank",
                "value",
            ],
            [
                (64500, "", "flow-name", 100.0, 10, 2, 200.0, 1, 100.0),
                (0, "11.10.20.7", "", 50.0, 5, 1, 200.0, 1, 50.0),
            ],
        )

        def query(sql, params=None):
            queries.append((sql, dict(params or {})))
            return result

        with mock.patch.object(
            backend_main, "ensure_clickhouse_schema", return_value=None
        ), mock.patch.object(
            backend_main, "dashboard_aggregate_range_covered", return_value=False
        ), mock.patch.object(
            backend_main, "dashboard_cache_get", return_value=None
        ), mock.patch.object(
            backend_main,
            "dashboard_cache_set",
            side_effect=lambda _key, payload: payload,
        ), mock.patch.object(
            backend_main, "resolve_dashboard_if_index", return_value=None
        ), mock.patch.object(
            backend_main, "query_clickhouse", side_effect=query
        ), mock.patch.object(
            backend_main,
            "resolve_asns_for_ips",
            return_value={
                "11.10.20.7": {
                    "ip": "11.10.20.7",
                    "asn": 64500,
                    "as_name": "local-name",
                    "country": "BR",
                    "source": "test",
                }
            },
        ), mock.patch.object(
            backend_main,
            "lookup_asn_information_batch",
            return_value={
                64500: {
                    "asn": 64500,
                    "as_name": "canonical-name",
                    "org_name": "Canonical Org",
                    "country": "BR",
                }
            },
        ):
            payload = backend_main.top_asn_dimension(
                "src",
                60,
                None,
                None,
                10,
                start=START,
                end=END,
                traffic_direction="download",
            )

        self.assertEqual(len(queries), 1)
        sql, params = queries[0]
        self.assertIn("row_number() OVER", sql)
        self.assertIn("sum(weighted_bytes_total) OVER ()", sql)
        self.assertEqual(params["unresolved_limit"], 200)
        self.assertEqual(params["combined_limit"], 210)
        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["asn_number"], 64500)
        self.assertEqual(payload["items"][0]["bps"], 150.0)
        self.assertEqual(payload["items"][0]["percent"], 75.0)


class DashboardRankingEnrichmentBatchTest(unittest.TestCase):
    def test_final_ip_ranking_uses_one_ip_and_one_asn_batch(self):
        items = [
            {"key": "11.0.0.1", "value": 10.0},
            {"key": "12.0.0.1", "value": 5.0},
        ]
        resolved = {
            "11.0.0.1": {
                "ip": "11.0.0.1",
                "asn": 64501,
                "as_name": "flow-one",
                "country": "BR",
                "source": "cache",
            },
            "12.0.0.1": {
                "ip": "12.0.0.1",
                "asn": 64502,
                "as_name": "flow-two",
                "country": "US",
                "source": "cache",
            },
        }
        information = {
            64501: {
                "asn": 64501,
                "as_name": "one",
                "org_name": "Org One",
                "country": "BR",
            },
            64502: {
                "asn": 64502,
                "as_name": "two",
                "org_name": "Org Two",
                "country": "US",
            },
        }
        with mock.patch.object(
            backend_main,
            "resolve_asns_for_ips",
            return_value=resolved,
        ) as resolve_batch, mock.patch.object(
            backend_main,
            "lookup_asn_information_batch",
            return_value=information,
        ) as info_batch, mock.patch.object(
            backend_main,
            "resolve_asn_for_ip",
            side_effect=AssertionError("per-IP resolution must not run"),
        ), mock.patch.object(
            backend_main,
            "lookup_asn_info",
            side_effect=AssertionError("per-ASN lookup must not run"),
        ):
            enriched = backend_main.dashboard_widget_enrich_ranking_identities(
                items,
                "src_ip",
            )
        resolve_batch.assert_called_once()
        info_batch.assert_called_once()
        self.assertEqual(enriched[0]["metadata"]["asn"], 64501)
        self.assertEqual(enriched[0]["metadata"]["org_name"], "Org One")
        self.assertEqual(enriched[1]["metadata"]["asn"], 64502)

    def test_flow_asn_avoids_re_resolving_the_ip(self):
        items = [
            {
                "key": "11.0.0.1",
                "ip": "11.0.0.1",
                "asn_number": 64501,
                "as_name": "flow-name",
                "country": "BR",
                "value": 10.0,
            }
        ]
        with mock.patch.object(
            backend_main,
            "resolve_asns_for_ips",
        ) as resolve_batch, mock.patch.object(
            backend_main,
            "lookup_asn_information_batch",
            return_value={},
        ):
            enriched = backend_main.dashboard_widget_enrich_ranking_identities(
                items,
                "src_ip",
            )
        resolve_batch.assert_called_once_with([], max_ips=1)
        self.assertEqual(enriched[0]["metadata"]["asn"], 64501)
        self.assertEqual(enriched[0]["metadata"]["as_name"], "flow-name")

    def test_conversation_rows_batch_asn_information(self):
        result = clickhouse_result(
            [
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "proto",
                "src_asn",
                "dst_asn",
                "src_as_name",
                "dst_as_name",
                "bytes",
                "packets",
                "flows",
                "first_seen",
                "last_seen",
                "key",
                "bits_s",
                "packets_s",
                "percent_total",
                "duration_seconds",
            ],
            [
                (
                    "11.0.0.1",
                    "12.0.0.1",
                    12345,
                    443,
                    6,
                    64501,
                    64502,
                    "",
                    "",
                    1000,
                    10,
                    1,
                    START,
                    END,
                    "conversation",
                    100.0,
                    1.0,
                    100.0,
                    60,
                )
            ],
        )
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
            return_value=result,
        ), mock.patch.object(
            backend_main,
            "lookup_asn_information_batch",
            return_value={
                64501: {"as_name": "source"},
                64502: {"as_name": "destination"},
            },
        ) as info_batch, mock.patch.object(
            backend_main,
            "lookup_asn_info",
            side_effect=AssertionError("per-ASN lookup must not run"),
        ):
            payload = backend_main.top_conversations_payload(
                60,
                None,
                None,
                None,
                "both",
                None,
                10,
                "bits_s",
                START,
                END,
            )
        info_batch.assert_called_once()
        self.assertEqual(payload["items"][0]["src_as_name"], "source")
        self.assertEqual(payload["items"][0]["dst_as_name"], "destination")

    def test_configurable_syn_ranking_reuses_existing_syn_path(self):
        plan = {
            "kind": "top_n",
            "dimension": "src_ip",
            "metric": "pps",
            "filters": [
                {"field": "protocol", "operator": "eq", "value": "tcp"},
                {"field": "tcp_flags", "operator": "eq", "value": "SYN"},
            ],
            "direction": "both",
            "limit": 10,
            "calculation": "current",
        }
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
            "prefix_grouping": {},
        }
        with mock.patch.object(
            backend_main,
            "dashboard_top_syn",
            return_value={
                "start": START.isoformat(),
                "end": END.isoformat(),
                "query_source": "aggregate_hybrid",
                "items": [],
            },
        ) as top_syn, mock.patch.object(
            backend_main,
            "top_flows",
            side_effect=AssertionError("raw generic path must not run"),
        ):
            payload = backend_main.dashboard_widget_top_payload(plan, context)
        top_syn.assert_called_once()
        self.assertEqual(payload["source"], "aggregate_hybrid")


class DashboardSingleflightRegressionTest(unittest.TestCase):
    def test_timeout_does_not_start_a_duplicate_query(self):
        cache = MemoryDashboardCache(
            config(singleflight_timeout_seconds=1),
            memory_provider=lambda: memory(),
        )
        barrier = threading.Barrier(2)
        counter = {"value": 0}
        results = []

        def worker():
            barrier.wait()
            payload, owner = cache.lookup_or_reserve("slow-widget")
            if owner:
                counter["value"] += 1
                time.sleep(1.1)
                payload = {"items": [42]}
                cache.publish("slow-widget", payload, 5)
            results.append(payload)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)
        self.assertEqual(counter["value"], 1)
        self.assertEqual(results, [{"items": [42]}, {"items": [42]}])


class DashboardPerformanceTelemetryTest(unittest.TestCase):
    def test_dashboard_clickhouse_query_id_names_dashboard_and_widget(self):
        trace = DashboardPerformanceTrace(
            8,
            41,
            "top_n",
            "bps",
            "request-123",
        )
        request_token = backend_main.HTTP_REQUEST_ID.set("request-123")
        sequence_token = backend_main.CLICKHOUSE_QUERY_SEQUENCE.set(0)
        trace_token = backend_main.DASHBOARD_PERF_TRACE.set(trace)
        try:
            request_id, query_id = backend_main.clickhouse_request_query_id()
        finally:
            backend_main.DASHBOARD_PERF_TRACE.reset(trace_token)
            backend_main.CLICKHOUSE_QUERY_SEQUENCE.reset(sequence_token)
            backend_main.HTTP_REQUEST_ID.reset(request_token)
        self.assertEqual(request_id, "request-123")
        self.assertEqual(
            query_id,
            "gmjflow-dashboard-8-widget-41-request-123-1",
        )

    def test_trace_reports_query_ids_and_clickhouse_summary_without_payload(self):
        trace = DashboardPerformanceTrace(1, 2, "top_n", "bps", "request-1")
        trace.add_stage("auth", 0.01)
        trace.record_query(
            query_id="query-1",
            duration_seconds=0.25,
            result=SimpleNamespace(
                summary={
                    "read_rows": "1200",
                    "read_bytes": "4096",
                    "memory_usage": "2048",
                    "cpu_time_us": "3000",
                    "result_rows": "10",
                },
                result_rows=[],
            ),
        )
        payload = trace.log_payload(
            cache_hit=False,
            query_path="aggregate_hybrid",
            result_rows=10,
            response_bytes=900,
        )
        self.assertEqual(payload["query_ids"], ["query-1"])
        self.assertEqual(payload["query_stats"][0]["duration_ms"], 250.0)
        self.assertEqual(payload["read_rows"], 1200)
        self.assertEqual(payload["read_bytes"], 4096)
        self.assertEqual(payload["peak_query_memory_bytes"], 2048)
        self.assertEqual(payload["cpu_time_us"], 3000)
        self.assertEqual(payload["auth_ms"], 10.0)
        self.assertGreaterEqual(payload["unattributed_ms"], 0)
        self.assertNotIn("response", payload)
        self.assertNotIn("prompt", payload)


if __name__ == "__main__":
    unittest.main()
