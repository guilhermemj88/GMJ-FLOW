from __future__ import annotations

import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.app.services.dashboard_aggregates import (
    DASHBOARD_AGGREGATE_TABLES,
    aggregate_boundaries,
    dashboard_aggregate_schema_statements,
    dashboard_effective_sample_rate_expr,
    effective_sample_rate_from_rows,
    sample_rate_config_rows,
)
from backend.app.services.dashboard_cache import (
    GIB,
    MIB,
    DashboardCacheConfig,
    MemoryDashboardCache,
    MemorySnapshot,
    automatic_total_budget,
    effective_budget,
)


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def memory(available_gb=16, total_gb=32, container_limit_gb=None, container_usage_gb=0):
    return MemorySnapshot(
        host_total_bytes=int(total_gb * GIB),
        host_available_bytes=int(available_gb * GIB),
        container_limit_bytes=None if container_limit_gb is None else int(container_limit_gb * GIB),
        container_usage_bytes=None if container_limit_gb is None else int(container_usage_gb * GIB),
    )


def config(mode="custom", max_mb=16, **overrides):
    values = {
        "mode": mode,
        "custom_max_bytes": max_mb * MIB if max_mb is not None else None,
        "max_entries": 100,
        "min_available_bytes": 512 * MIB,
        "max_available_percent": 10,
        "max_item_bytes": 8 * MIB,
        "workers": 1,
        "monitor_interval_seconds": 15,
        "singleflight_timeout_seconds": 2,
        "prewarm": False,
    }
    values.update(overrides)
    return DashboardCacheConfig(**values)


class DashboardCacheAdaptiveTest(unittest.TestCase):
    def test_disabled_does_not_store_but_singleflight_still_shares(self):
        cache = MemoryDashboardCache(
            config(mode="disabled", max_mb=None),
            memory_provider=lambda: memory(),
        )
        counter = {"value": 0}
        barrier = threading.Barrier(5)
        results = []

        def worker():
            barrier.wait()

            def compute():
                counter["value"] += 1
                time.sleep(0.04)
                return {"items": [1, 2, 3]}

            results.append(cache.get_or_compute("same", 5, compute))

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)
        self.assertEqual(counter["value"], 1)
        self.assertEqual(results, [{"items": [1, 2, 3]}] * 5)
        self.assertEqual(cache.status()["entries"], 0)
        self.assertGreaterEqual(cache.status()["singleflight_shared_requests"], 4)

    def test_auto_disables_with_little_memory_and_uses_requested_bands(self):
        self.assertEqual(automatic_total_budget(int(1.99 * GIB)), 0)
        self.assertEqual(automatic_total_budget(3 * GIB), 64 * MIB)
        self.assertEqual(automatic_total_budget(6 * GIB), 128 * MIB)
        self.assertEqual(automatic_total_budget(12 * GIB), 256 * MIB)
        self.assertEqual(automatic_total_budget(20 * GIB), 512 * MIB)
        auto = config(
            mode="auto",
            max_mb=None,
            min_available_bytes=1536 * MIB,
            max_available_percent=5,
        )
        self.assertEqual(effective_budget(auto, memory(available_gb=1))[1], 0)

    def test_custom_and_container_limits_are_safe(self):
        custom = config(max_mb=512, max_available_percent=10, min_available_bytes=128 * MIB)
        self.assertEqual(effective_budget(custom, memory(available_gb=16))[1], 512 * MIB)
        configured, effective = effective_budget(
            custom,
            memory(available_gb=8, container_limit_gb=2, container_usage_gb=1.75),
        )
        self.assertEqual(configured, 512 * MIB)
        self.assertEqual(effective, int(256 * MIB * 0.10))

    def test_worker_budget_is_divided_per_process(self):
        auto = config(
            mode="auto",
            max_mb=None,
            workers=4,
            min_available_bytes=512 * MIB,
            max_available_percent=10,
        )
        configured, effective = effective_budget(auto, memory(available_gb=20))
        self.assertEqual(configured, 128 * MIB)
        self.assertEqual(effective, 128 * MIB)
        cache = MemoryDashboardCache(auto, memory_provider=lambda: memory(available_gb=20))
        status = cache.status()
        self.assertEqual(
            status["estimated_total_worker_budget"],
            status["effective_max_bytes"] * 4,
        )

    def test_lru_evicts_old_entry_and_ttl_returns_equal_value(self):
        clock = FakeClock()
        cache = MemoryDashboardCache(
            config(max_mb=1, max_entries=2),
            memory_provider=lambda: memory(),
            clock=clock,
        )
        original = {"items": [{"value": 10}]}
        self.assertTrue(cache.set("a", original, 5))
        self.assertTrue(cache.set("b", {"value": "b"}, 5))
        self.assertEqual(cache.get("a"), original)
        self.assertTrue(cache.set("c", {"value": "c"}, 5))
        self.assertIsNone(cache.get("b"))
        self.assertEqual(cache.get("a"), original)
        clock.advance(6)
        self.assertIsNone(cache.get("a"))

    def test_item_limit_skips_storage_without_losing_result(self):
        cache = MemoryDashboardCache(
            config(max_mb=8, max_item_bytes=32),
            memory_provider=lambda: memory(),
        )
        result = cache.get_or_compute("large", 30, lambda: {"blob": "x" * 100_000})
        self.assertEqual(len(result["blob"]), 100_000)
        self.assertEqual(cache.status()["entries"], 0)
        self.assertEqual(cache.status()["skipped_large_items"], 1)

    def test_memory_pressure_shrinks_then_recovers_insertions(self):
        snapshots = [memory(available_gb=16), memory(available_gb=0.25), memory(available_gb=16)]
        cache = MemoryDashboardCache(
            config(max_mb=8),
            memory_provider=lambda: snapshots[0],
        )
        cache.set("a", {"blob": "a" * 1000}, 60)
        cache.set("b", {"blob": "b" * 1000}, 60)
        self.assertTrue(cache.evaluate_memory_pressure(snapshots[1]))
        self.assertTrue(cache.status()["insertions_suspended"])
        self.assertFalse(cache.set("blocked", {"value": 1}, 60))
        self.assertFalse(cache.evaluate_memory_pressure(snapshots[2]))
        self.assertFalse(cache.status()["insertions_suspended"])
        self.assertTrue(cache.set("recovered", {"value": 1}, 60))

    def test_clear_removes_only_derived_values(self):
        persistent = {"sensor": "edge-1"}
        cache = MemoryDashboardCache(config(), memory_provider=lambda: memory())
        cache.set("derived", {"items": [1]}, 60)
        self.assertEqual(cache.clear(), 1)
        self.assertEqual(persistent, {"sensor": "edge-1"})
        self.assertEqual(cache.status()["entries"], 0)

    def test_different_keys_never_share_results(self):
        cache = MemoryDashboardCache(config(), memory_provider=lambda: memory())
        self.assertEqual(cache.get_or_compute("sensor=1", 10, lambda: {"sensor": 1}), {"sensor": 1})
        self.assertEqual(cache.get_or_compute("sensor=2", 10, lambda: {"sensor": 2}), {"sensor": 2})

    def test_empty_cache_computes_dashboard_payload_normally(self):
        cache = MemoryDashboardCache(config(), memory_provider=lambda: memory())
        payload = {"items": [{"bps": 123.0}], "filters": {"sensor_id": 7}}
        self.assertEqual(cache.get_or_compute("empty", 5, lambda: payload), payload)

    def test_memory_behavior_uses_injected_snapshot_not_machine_ram(self):
        snapshot = memory(available_gb=3, total_gb=6)
        cache = MemoryDashboardCache(
            config(mode="auto", max_mb=None, max_available_percent=10),
            memory_provider=lambda: snapshot,
        )
        self.assertEqual(cache.status()["available_memory"], snapshot.available_bytes)
        self.assertEqual(cache.effective_max_bytes, 64 * MIB)

    def test_status_never_exposes_cached_payload(self):
        secret_marker = "not-for-metrics"
        cache = MemoryDashboardCache(config(), memory_provider=lambda: memory())
        cache.set("key", {"secret": secret_marker}, 60)
        status = cache.status()
        self.assertNotIn(secret_marker, repr(status))
        self.assertNotIn("key", repr(status))

    def test_admin_clear_endpoint_only_calls_derived_cache(self):
        source = (Path(__file__).parents[1] / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        start = source.index("def clear_dashboard_cache")
        end = source.index('@app.get("/api/system/resources")', start)
        endpoint_source = source[start:end]
        self.assertIn("DASHBOARD_CACHE.clear()", endpoint_source)
        for forbidden in ("sqlite_connection", "query_clickhouse", "command_clickhouse", "DELETE FROM"):
            self.assertNotIn(forbidden, endpoint_source)


class DashboardAggregateRegressionTest(unittest.TestCase):
    def test_schema_contains_all_specific_non_destructive_aggregates(self):
        statements = "\n".join(dashboard_aggregate_schema_statements())
        for table in DASHBOARD_AGGREGATE_TABLES.values():
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {table}", statements)
            self.assertIn(f"CREATE MATERIALIZED VIEW IF NOT EXISTS mv_{table}", statements)
        upper = statements.upper()
        for forbidden in ("DROP TABLE", "TRUNCATE", "OPTIMIZE FINAL", "DELETE FROM FLOW_RAW"):
            self.assertNotIn(forbidden, upper)

    def test_tcp_flags_minute_aggregate_is_versioned_and_tcp_only(self):
        statements = "\n".join(dashboard_aggregate_schema_statements())
        self.assertEqual(
            DASHBOARD_AGGREGATE_TABLES["tcp_flags"],
            "flow_dashboard_tcp_flags_tcp_1m",
        )
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS flow_dashboard_tcp_flags_tcp_1m",
            statements,
        )
        self.assertIn("tcp_flags UInt16", statements)
        self.assertIn("proto UInt8", statements)
        self.assertIn("WHERE proto = 6", statements)

    def test_sample_rate_join_expression_has_no_giant_multiif(self):
        expression = dashboard_effective_sample_rate_expr("auto")
        self.assertNotIn("multiIf", expression)
        self.assertIn("sr_input", expression)
        self.assertIn("sr_output", expression)
        self.assertIn("sample_rate", expression)
        source = (Path(__file__).parents[1] / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        start = source.index("def dashboard_series_payload")
        end = source.index("def search_flows_payload")
        dashboard_source = source[start:end]
        self.assertNotIn("clickhouse_sample_rate_expr(", dashboard_source)
        self.assertIn("dashboard_raw_rated_source_cte", dashboard_source)

    def test_old_and_new_sample_rate_resolution_are_equivalent(self):
        rows = {
            (0, 1): 100,
            (0, 2): 200,
            (10, 1): 150,
            (10, 2): 250,
        }
        cases = [
            (1, 10, 0, "input", 150),
            (1, 0, 10, "output", 250),
            (1, 99, 0, "input", 100),
            (1, 0, 99, "output", 200),
            (512, 0, 0, "auto", 512),
            (1, 10, 10, "auto", 150),
        ]
        for sample_rate, input_if, output_if, direction, expected in cases:
            with self.subTest(direction=direction, input_if=input_if, output_if=output_if):
                self.assertEqual(
                    effective_sample_rate_from_rows(
                        sample_rate,
                        input_if,
                        output_if,
                        direction,
                        rows,
                    ),
                    expected,
                )

    def test_sample_rate_exporter_key_matches_clickhouse_ipv6_text(self):
        rows = sample_rate_config_rows(
            [
                {
                    "exporter_ip": "192.0.2.10",
                    "default_in": 100,
                    "default_out": 200,
                    "interfaces": {},
                }
            ]
        )
        self.assertEqual({row[0] for row in rows}, {"::ffff:192.0.2.10"})

    def test_specific_minute_aggregate_preserves_values_top_n_and_percent(self):
        flows = [
            {"minute": "12:00", "src_ip": "192.0.2.1", "bytes": 10, "packets": 2, "flows": 1, "rate": 100},
            {"minute": "12:00", "src_ip": "192.0.2.1", "bytes": 5, "packets": 1, "flows": 2, "rate": 100},
            {"minute": "12:01", "src_ip": "192.0.2.1", "bytes": 20, "packets": 4, "flows": 1, "rate": 50},
            {"minute": "12:00", "src_ip": "198.51.100.2", "bytes": 7, "packets": 3, "flows": 1, "rate": 200},
        ]

        def final_totals(rows):
            totals = {}
            for row in rows:
                item = totals.setdefault(row["src_ip"], {"bytes": 0, "packets": 0, "flows": 0})
                item["bytes"] += row["bytes"] * row["rate"]
                item["packets"] += row["packets"] * row["rate"]
                item["flows"] += row["flows"]
            return totals

        minute_rows = {}
        for flow in flows:
            key = (flow["minute"], flow["src_ip"], flow["rate"])
            item = minute_rows.setdefault(
                key,
                {
                    "minute": flow["minute"],
                    "src_ip": flow["src_ip"],
                    "rate": flow["rate"],
                    "bytes": 0,
                    "packets": 0,
                    "flows": 0,
                },
            )
            for field in ("bytes", "packets", "flows"):
                item[field] += flow[field]

        raw_totals = final_totals(flows)
        aggregate_totals = final_totals(minute_rows.values())
        self.assertEqual(aggregate_totals, raw_totals)
        raw_top = sorted(raw_totals, key=lambda key: raw_totals[key]["bytes"], reverse=True)
        aggregate_top = sorted(aggregate_totals, key=lambda key: aggregate_totals[key]["bytes"], reverse=True)
        self.assertEqual(aggregate_top, raw_top)
        total_bytes = sum(item["bytes"] for item in raw_totals.values())
        self.assertEqual(
            [
                round(aggregate_totals[key]["bytes"] * 100 / total_bytes, 6)
                for key in aggregate_top
            ],
            [round(raw_totals[key]["bytes"] * 100 / total_bytes, 6) for key in raw_top],
        )

    def test_hybrid_boundaries_keep_partial_minutes_on_raw_path(self):
        start = datetime(2026, 7, 27, 12, 3, 25, tzinfo=timezone.utc)
        end = datetime(2026, 7, 27, 12, 13, 25, tzinfo=timezone.utc)
        interior_start, interior_end = aggregate_boundaries(start, end)
        self.assertEqual(interior_start.minute, 4)
        self.assertEqual(interior_end.minute, 13)

    def test_frontend_guards_hidden_and_lazy_panels_and_renders_progressively(self):
        html = (Path(__file__).parents[1] / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn("isDashboardWidgetVisible('bps-chart')", html)
        self.assertIn("isDashboardWidgetVisible('pps-chart')", html)
        self.assertIn("flowRecordsPanel", html)
        self.assertIn("activeView !== 'flows'", html)
        self.assertIn("flowSearchAbortController?.abort()", html)
        self.assertIn("dashboardRefreshInFlight) abortDashboardRequest()", html)
        self.assertIn("renderDashboardSettledEntry(name, payload", html)
        self.assertIn("Promise.allSettled", html)

    def test_observability_wraps_auth_and_links_clickhouse_queries(self):
        source = (Path(__file__).parents[1] / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        self.assertLess(source.index("async def auth_middleware"), source.index("async def http_observability_middleware"))
        for field in ("method", "path", "status", "duration_ms", "response_bytes", "request_id"):
            self.assertIn(f'"{field}"', source)
        self.assertIn('"query_id": query_id', source)
        self.assertIn('"log_comment": f"gmj-flow request_id={request_id}"', source)

    def test_sensor_endpoint_does_not_call_clickhouse(self):
        source = (Path(__file__).parents[1] / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        start = source.index("def list_dashboard_sensors")
        end = source.index('@app.post("/api/sensors"', start)
        endpoint_source = source[start:end]
        self.assertNotIn("query_clickhouse", endpoint_source)
        self.assertNotIn("GROUP BY", endpoint_source.upper())
        self.assertIn("sensor_runtime_status", endpoint_source)

    def test_prewarm_has_no_fact_table_query(self):
        source = (Path(__file__).parents[1] / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        start = source.index("def start_dashboard_cache_prewarm")
        end = source.index("def peak_hunter_runner_enabled", start)
        prewarm_source = source[start:end]
        self.assertNotIn("flow_raw", prewarm_source)
        self.assertNotIn("query_clickhouse", prewarm_source)


if __name__ == "__main__":
    unittest.main()
