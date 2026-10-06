import ast
from dataclasses import replace
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.api import traffic_statistics as api
from app.services.traffic_statistics import (
    Scope,
    StatisticsService,
    StatisticsStore,
    window_seconds,
)
from app.services.traffic_statistics_math import (
    CONFIG,
    baseline,
    benford_test,
    entropy_counts,
    ks_test,
    overall,
)


class MathematicsTests(unittest.TestCase):
    def test_single(self):
        result = entropy_counts({"x": 12})
        self.assertEqual((result["entropy_bits"], result["entropy_normalized"]), (0, 0))

    def test_uniform(self):
        result = entropy_counts(dict.fromkeys("abcd", 10))
        self.assertEqual(result["entropy_bits"], 2)
        self.assertEqual(result["entropy_normalized"], 1)

    def test_concentration(self):
        self.assertLess(
            entropy_counts({"a": 90, "b": 10})["entropy_bits"],
            entropy_counts({"a": 50, "b": 50})["entropy_bits"],
        )

    def test_empty_and_null(self):
        for counts in ({}, {None: 50}, {"a": 0}):
            result = entropy_counts(counts)
            self.assertIsNone(result["entropy_bits"])
            self.assertEqual(result["distribution_classification"], "NO_DATA")
        self.assertEqual(
            entropy_counts({None: 100, "a": 10}), entropy_counts({"a": 10})
        )

    def test_packet_vs_record_weight(self):
        packet = entropy_counts({"a": 90, "b": 10})
        records = entropy_counts({"a": 1, "b": 1})
        self.assertAlmostEqual(
            packet["entropy_bits"], -0.9 * math.log2(0.9) - 0.1 * math.log2(0.1)
        )
        self.assertEqual(records["entropy_bits"], 1)

    def test_baseline_median_mad(self):
        value = baseline(
            0.7, [0.1, 0.2, 0.3, 0.4, 0.5], replace(CONFIG, baseline_min_windows=3)
        )
        self.assertEqual(value["baseline_median"], 0.3)
        self.assertAlmostEqual(value["baseline_mad"], 0.1)
        self.assertAlmostEqual(value["robust_z"], 0.4 / (1.4826 * 0.1))

    def test_baseline_zero_mad(self):
        stable = baseline(0.5, [0.5] * 20)
        changed = baseline(0.9, [0.5] * 20)
        self.assertEqual(stable["robust_z"], 0)
        self.assertIsNone(changed["robust_z"])
        self.assertEqual(changed["anomaly_classification"], "STRONG")
        self.assertAlmostEqual(changed["regularized_z"], 40)

    def test_baseline_outlier(self):
        result = baseline(0.5, [0.4, 0.5, 0.6] * 10 + [1e9])
        self.assertEqual(result["baseline_median"], 0.5)
        self.assertAlmostEqual(result["baseline_mad"], 0.1)
        self.assertEqual(result["anomaly_classification"], "NORMAL")

    def test_no_baseline_and_no_current(self):
        self.assertEqual(baseline(0.5, [])["anomaly_classification"], "NO_BASELINE")
        self.assertEqual(
            baseline(None, [0.5] * 20)["anomaly_classification"], "NO_DATA"
        )

    def test_ks_same(self):
        result = ks_test(list(range(100)), list(range(100)))
        self.assertEqual(result["statistic"], 0)
        self.assertEqual(result["classification"], "NORMAL")

    def test_ks_different(self):
        result = ks_test(list(range(100)), list(range(1000, 1100)))
        self.assertEqual(result["statistic"], 1)
        self.assertEqual(result["classification"], "STRONG_SHIFT")

    def test_ks_small_and_nan(self):
        result = ks_test([1, float("nan")], [2] * 100)
        self.assertEqual(result["classification"], "INSUFFICIENT_SAMPLES")
        json.dumps(result, allow_nan=False)

    def test_benford_compatible(self):
        values = [10 ** (i / 1000) for i in range(5000)]
        result = benford_test(values)
        self.assertTrue(result["applicable"])
        self.assertLess(result["mad"], 0.001)
        self.assertEqual(result["classification"], "NORMAL_CONFORMITY")

    def test_benford_divergent(self):
        result = benford_test([9 * 10 ** (i % 5) for i in range(5000)])
        self.assertEqual(result["classification"], "STRONG_DIVERGENCE")
        self.assertGreater(result["mad"], 0.1)

    def test_benford_small(self):
        self.assertEqual(benford_test([1, 1000])["reason"], "INSUFFICIENT_SAMPLES")

    def test_benford_narrow(self):
        self.assertEqual(
            benford_test([64, 1500] * 1000)["reason"], "INSUFFICIENT_MAGNITUDE_RANGE"
        )

    def test_benford_zeros_negative(self):
        result = benford_test([0, -5, None] * 1000)
        self.assertEqual(result["sample_count"], 0)
        self.assertEqual(result["excluded_count"], 3000)
        self.assertFalse(result["applicable"])
        json.dumps(result, allow_nan=False)

    def test_benford_powers(self):
        result = benford_test([10**i for i in range(-4, 5)] * 200)
        self.assertEqual(result["observed"][0], 1)

    def test_overall_ignores_diversity_and_pvalue(self):
        entropy = [
            {
                "distribution_classification": "HIGH_DIVERSITY",
                "anomaly_classification": "NORMAL",
            }
        ]
        ks = [{"classification": "NORMAL", "p_value": 1e-15}]
        self.assertEqual(overall(entropy, ks, []), "NORMAL")
        self.assertEqual(overall([], [], []), "INSUFFICIENT_DATA")


class FakeResult:
    def __init__(self, rows):
        self.result_rows = rows


class FakeClient:
    def __init__(self):
        self.queries = []
        self.closed = False

    def query(self, sql, parameters=None, settings=None):
        self.queries.append((sql, parameters, settings))
        if sql.startswith("DESCRIBE"):
            return FakeResult(
                [
                    (x, "UInt64")
                    for x in [
                        "flow_time",
                        "src_ip",
                        "dst_ip",
                        "src_port",
                        "dst_port",
                        "proto",
                        "tcp_flags",
                        "src_asn",
                        "input_if",
                        "output_if",
                        "packets",
                        "bytes",
                        "time_classification",
                    ]
                ]
            )
        if "sum(n)" in sql:
            return FakeResult([(0, 0, 0)])
        if "count()" in sql:
            return FakeResult([(0,)])
        return FakeResult([])

    def close(self):
        self.closed = True


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = StatisticsStore(Path(self.directory.name) / "statistics.db")
        self.client = FakeClient()
        self.service = StatisticsService(self.store, lambda: self.client)

    def test_empty_schema_no_fabricated_country_duration(self):
        result = self.service.summary(Scope(), end=1800000000)
        self.assertEqual(result["overall"]["statisticalAnomaly"], "INSUFFICIENT_DATA")
        self.assertEqual(result["unavailable_fields"], ["src_country"])
        self.assertEqual(len(result["ks"]), 3)
        self.assertTrue(self.client.closed)
        json.dumps(result, allow_nan=False)

    def test_queries_are_readonly_bounded_parameterized(self):
        self.service.summary(
            Scope("target", "192.0.2.1", "sensor'unsafe"), end=1800000000
        )
        for sql, params, settings in self.client.queries:
            self.assertTrue(sql.startswith(("SELECT", "DESCRIBE")))
            self.assertEqual(settings["readonly"], 1)
            self.assertEqual(settings["max_threads"], 2)
            self.assertNotIn("sensor'unsafe", sql)
        self.assertTrue(
            any("sum(toFloat64(packets))" in x[0] for x in self.client.queries)
        )

    def test_flow_weight_sql(self):
        self.service.summary(Scope(), mode="FLOW_WEIGHTED", end=1800000000)
        self.assertTrue(
            any("toFloat64(count()) AS n" in x[0] for x in self.client.queries)
        )

    def test_cache_does_not_requery(self):
        a = self.service.summary(Scope(), end=1800000000)
        queries = len(self.client.queries)
        b = self.service.summary(Scope(), end=1800000000)
        self.assertEqual(a, b)
        self.assertEqual(len(self.client.queries), queries)

    def test_baseline_excludes_current_and_overlaps(self):
        now = 1800000000
        for end in (now - 600, now - 300, now - 240, now - 60):
            self.service.summary(Scope(), end=end)
        result = self.service.summary(Scope(), end=now)
        self.assertEqual(result["baseline"]["windows"], 2)
        self.assertEqual(result["baseline"]["to"], "2027-01-15T07:55:00+00:00")

    def test_samples_nonoverlap_and_upper_bound(self):
        scope = Scope()
        for end in (1800000000, 1800000060, 1800000300):
            self.store.save(
                scope, 300, "PACKET_WEIGHTED", end, {}, [[end, {"bytes_per_flow": 1}]]
            )
        result = self.store.samples(scope, 300, 1799990000, 1800000000)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 1800000000)

    def test_scope_validation(self):
        for args in [
            ("client", "1"),
            ("attack_event", "1"),
            ("target", "not-ip"),
            ("interface", "3"),
            ("global", "1"),
        ]:
            with self.assertRaises(ValueError):
                Scope(*args)
        with self.assertRaises(ValueError):
            window_seconds("2m")
        self.assertEqual(Scope("interface", "003", "router", "192.0.2.1").id, "3")

    def test_idempotent_migration(self):
        StatisticsStore(self.store.path)
        with self.store.connect() as conn:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 1)

    def test_api_validation_and_response(self):
        app = FastAPI()
        app.include_router(api.router)
        client = TestClient(app)
        path = "/api/threat-intelligence/statistics/"
        for params in (
            {"scopeType": "bad"},
            {"window": "2m"},
            {"scopeType": "target", "scopeId": "wrong"},
            {"scopeType": "interface", "scopeId": "3"},
            {"weightMode": "BYTES"},
        ):
            self.assertEqual(
                client.get(path + "summary", params=params).status_code, 422
            )
        with patch.object(api, "get_service", return_value=self.service):
            response = client.get(path + "summary")
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()["read_only"])
            history = client.get(path + "history")
            self.assertEqual(history.status_code, 200)
            self.assertEqual(len(history.json()["items"]), 1)
            self.assertEqual(client.get(path + "history?hours=169").status_code, 422)
            self.assertEqual(
                client.get(path + "history?field=payload").status_code, 422
            )

    def test_api_failure_not_no_data(self):
        app = FastAPI()
        app.include_router(api.router)
        with patch.object(
            api, "get_service", side_effect=RuntimeError("private db detail")
        ):
            result = TestClient(app).get("/api/threat-intelligence/statistics/summary")
            self.assertEqual(result.status_code, 503)
            self.assertNotIn("private db detail", result.text)

    def test_no_actuation_dependencies(self):
        root = Path(__file__).resolve().parents[1] / "backend/app"
        for path in root.rglob("traffic_statistics*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse(
                        any(
                            term in (node.module or "")
                            for term in (
                                "mitigation",
                                "threat_engine",
                                "behavioral_detection",
                                "bgp",
                                "main",
                            )
                        )
                    )


if __name__ == "__main__":
    unittest.main()
