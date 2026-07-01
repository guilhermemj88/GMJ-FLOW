import sys
import os
import sqlite3
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.peak_hunter import PeakHunterRequest, analyze_peak_hunter, ensure_peak_analysis_db

sys.modules.setdefault("clickhouse_connect", types.SimpleNamespace(get_client=lambda **_kwargs: None))
from app.services import clickhouse as peak_clickhouse

try:
    from app.api import peak_hunter as peak_hunter_api
except (ImportError, ModuleNotFoundError):
    peak_hunter_api = None


class PeakHunterTest(unittest.TestCase):
    def setUp(self):
        self.base_time = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
        self.request = PeakHunterRequest(
            sensor="edge-a",
            interface_id=10,
            direction="sends",
            metric="packets_s",
            start_time=self.base_time,
            end_time=self.base_time + timedelta(minutes=1),
            threshold=50_000,
        )

    def test_peak_with_dominant_group_in_5s(self):
        result = analyze_peak_hunter(self.request, self._series, self._flows_with_dominant_5s)
        self.assertEqual(result["evidence_window_used"], 5)
        self.assertEqual(result["classification"], "udp_flood_outbound_to_single_destination_port")
        self.assertEqual(result["dominant_group"]["dst_ip"], "203.0.113.10")
        self.assertTrue(result["mitigation_allowed"])

    def test_peak_with_dominant_group_only_in_15s(self):
        result = analyze_peak_hunter(self.request, self._series, self._flows_dominant_only_15s)
        self.assertEqual(result["evidence_window_used"], 15)
        self.assertEqual(result["dominant_group"]["dst_port"], 443)

    def test_peak_without_dominant_group(self):
        result = analyze_peak_hunter(self.request, self._series, lambda _request, _time, _window: [])
        self.assertEqual(result["classification"], "insufficient_flow_evidence")
        self.assertEqual(result["evidence_status"], "insufficient")
        self.assertFalse(result["mitigation_allowed"])
        self.assertEqual(result["recommendation"]["recommended_action"], "alert_only")

    def test_spread_udp_does_not_generate_mitigation(self):
        result = analyze_peak_hunter(self.request, self._series, self._spread_udp)
        self.assertEqual(result["classification"], "insufficient_flow_evidence")
        self.assertFalse(result["mitigation_allowed"])

    def test_many_sources_same_destination_port_generates_dst_candidate(self):
        result = analyze_peak_hunter(self.request, self._series, self._flows_with_dominant_5s)
        templates = [candidate["template"] for candidate in result["candidates"]]
        self.assertIn("dst_external_32_proto_dst_port", templates)

    def test_bits_s_orders_by_bits_s(self):
        request = PeakHunterRequest(**{**self.request.__dict__, "metric": "bits_s", "threshold": 1_000_000})
        result = analyze_peak_hunter(request, self._series_bits, self._bits_flows)
        self.assertEqual(result["dominant_group"]["dst_ip"], "203.0.113.200")
        self.assertEqual(result["dominant_group"]["max_bits_s"], 2000000)

    def test_bits_s_analyze_returns_200(self):
        request = PeakHunterRequest(**{**self.request.__dict__, "metric": "bits_s", "threshold": 1_000_000})
        result = analyze_peak_hunter(request, self._series_bits, self._bits_flows)
        self.assertNotIn("error", result)
        self.assertEqual(result["best_peak"]["peak_value"], 3_000_000)
        self.assertEqual(result["dominant_group"]["dst_ip"], "203.0.113.200")

    def test_packets_s_orders_by_packets_s(self):
        result = analyze_peak_hunter(self.request, self._series, self._packet_flows)
        self.assertEqual(result["dominant_group"]["dst_ip"], "203.0.113.201")
        self.assertEqual(result["dominant_group"]["max_packets_s"], 5000)

    def test_apply_enabled_always_false(self):
        result = analyze_peak_hunter(self.request, self._series, self._flows_with_dominant_5s)
        self.assertFalse(result["best_peak"]["apply_enabled"])
        self.assertTrue(all(candidate.get("apply_enabled") is False for candidate in result["candidates"]))

    def test_auto_threshold_when_empty(self):
        request = PeakHunterRequest(
            **{
                **self.request.__dict__,
                "threshold": None,
                "sensitivity": "high",
                "max_peaks": 3,
            }
        )
        result = analyze_peak_hunter(request, self._series_with_clear_auto_peak, lambda _request, _time, _window: [])
        self.assertGreater(result["threshold_used"], result["baseline"]["p95"])
        self.assertEqual(result["peaks_detected"], 1)

    def test_peak_hunter_large_series_is_limited_or_downsampled(self):
        result = analyze_peak_hunter(self.request, self._large_series, lambda _request, _time, _window: [])
        self.assertLessEqual(len(result["series"]), 1000)
        self.assertTrue(result["series_downsampled"])
        self.assertEqual(result["series_points"], 1500)

    def test_no_peak_evidence_status_insufficient_not_null(self):
        request = PeakHunterRequest(**{**self.request.__dict__, "threshold": 999_000_000})
        result = analyze_peak_hunter(request, self._series, lambda _request, _time, _window: [])
        self.assertEqual(result["peaks_detected"], 0)
        self.assertEqual(result["evidence_status"], "insufficient")
        self.assertEqual(result["classification"], "insufficient_flow_evidence")

    def test_peak_analysis_table_created_by_migration(self):
        conn = sqlite3.connect(":memory:")
        try:
            ensure_peak_analysis_db(conn)
            ensure_peak_analysis_db(conn)
            columns = {row[1]: row for row in conn.execute("PRAGMA table_info(peak_analysis)").fetchall()}
        finally:
            conn.close()

        expected_columns = {
            "id",
            "peak_time",
            "interface_id",
            "sensor",
            "direction",
            "metric",
            "peak_value",
            "baseline_p95",
            "baseline_p99",
            "score",
            "evidence_status",
            "classification",
            "dominant_group",
            "candidates",
            "ai_summary",
            "created_at",
        }
        self.assertTrue(expected_columns.issubset(columns))
        self.assertEqual(columns["id"][2].upper(), "INTEGER")
        self.assertEqual(columns["created_at"][4].upper(), "CURRENT_TIMESTAMP")

    def test_rejects_invalid_time_range(self):
        if peak_hunter_api is None:
            self.skipTest("fastapi nao instalado")
        with self.assertRaises(Exception):
            peak_hunter_api._request_window(self.base_time + timedelta(minutes=1), self.base_time, None)

    def test_recent_period_defaults(self):
        if peak_hunter_api is None:
            self.skipTest("fastapi nao instalado")
        start, end = peak_hunter_api._request_window(None, None, 15)
        self.assertAlmostEqual((end - start).total_seconds(), 900, delta=2)

    def test_options_sensors(self):
        if peak_hunter_api is None:
            self.skipTest("fastapi nao instalado")
        with temporary_peak_db() as db_path:
            create_sensor_schema(db_path)
            original = peak_hunter_api.fetch_peak_hunter_sensors
            peak_hunter_api.fetch_peak_hunter_sensors = lambda: [
                {"sensor_name": "edge-a", "sensor_id": "edge-a", "last_seen": self.base_time, "row_count": 10}
            ]
            try:
                payload = peak_hunter_api.peak_hunter_sensor_options()
            finally:
                peak_hunter_api.fetch_peak_hunter_sensors = original
            self.assertEqual(payload["items"][0]["sensor_name"], "edge-a")
            self.assertEqual(payload["items"][0]["exporter_ip"], "192.0.2.10")

    def test_options_interfaces(self):
        if peak_hunter_api is None:
            self.skipTest("fastapi nao instalado")
        with temporary_peak_db() as db_path:
            create_sensor_schema(db_path)
            original = peak_hunter_api.fetch_peak_hunter_interfaces
            peak_hunter_api.fetch_peak_hunter_interfaces = lambda sensor: [
                {"interface_id": 140, "last_seen": self.base_time, "rx_packets": 10, "tx_packets": 20}
            ]
            try:
                payload = peak_hunter_api.peak_hunter_interface_options("edge-a")
            finally:
                peak_hunter_api.fetch_peak_hunter_interfaces = original
            self.assertEqual(payload["items"][0]["interface_id"], 140)
            self.assertIn("Eth-Trunk10", payload["items"][0]["label"])

    def test_history_endpoint(self):
        if peak_hunter_api is None:
            self.skipTest("fastapi nao instalado")
        with temporary_peak_db() as db_path:
            conn = sqlite3.connect(db_path)
            try:
                from app.services.peak_hunter import save_peak_analysis

                save_peak_analysis(
                    conn,
                    {
                        "peak_time": self.base_time.isoformat(),
                        "interface_id": 10,
                        "sensor": "edge-a",
                        "direction": "sends",
                        "metric": "packets_s",
                        "peak_value": 120000,
                        "baseline_p95": 1000,
                        "baseline_p99": 2000,
                        "score": 120,
                        "evidence_status": "complete",
                        "classification": "udp_flood_outbound_to_single_destination_port",
                        "dominant_group": {"dst_ip": "203.0.113.10", "dst_port": 53, "protocol": "udp"},
                        "candidates": [{"action": "alert_only"}],
                        "created_at": self.base_time.isoformat(),
                    },
                )
                conn.commit()
            finally:
                conn.close()
            payload = peak_hunter_api.peak_hunter_history(sensor="edge-a")
            self.assertEqual(len(payload["items"]), 1)
            self.assertEqual(payload["items"][0]["evidence_status"], "complete")

    def test_from_anomaly_prefills_window(self):
        if peak_hunter_api is None:
            self.skipTest("fastapi nao instalado")
        with temporary_peak_db() as db_path:
            create_sensor_schema(db_path)
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE anomaly_events (
                        id INTEGER PRIMARY KEY,
                        sensor_id INTEGER,
                        interface_if_index INTEGER,
                        output_if INTEGER,
                        input_if INTEGER,
                        direction TEXT,
                        metric_unit TEXT,
                        protocol TEXT,
                        decoder TEXT,
                        threshold_value REAL,
                        started_at TEXT,
                        last_seen_at TEXT,
                        ended_at TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO anomaly_events (
                        id, sensor_id, interface_if_index, direction, metric_unit, protocol,
                        threshold_value, started_at, last_seen_at, ended_at
                    )
                    VALUES (7, 1, 140, 'sends', 'packets_s', 'udp', 50000, ?, ?, ?)
                    """,
                    (
                        self.base_time.isoformat(),
                        (self.base_time + timedelta(minutes=3)).isoformat(),
                        (self.base_time + timedelta(minutes=4)).isoformat(),
                    ),
                )
            payload = peak_hunter_api.peak_hunter_from_anomaly(7)
            self.assertEqual(payload["anomaly_id"], 7)
            self.assertEqual(payload["interface_id"], 140)
            self.assertEqual(payload["start_time"], (self.base_time - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"))

    def test_peak_hunter_uses_sensor_default_out_for_sends(self):
        with temporary_peak_db() as db_path:
            create_sensor_schema(db_path)
            details = peak_clickhouse.peak_sample_rate_details("edge-a", 999, "output")
            self.assertEqual(details["effective_sample_rate"], 1000)
            self.assertEqual(details["source"], "sensor")

    def test_peak_hunter_uses_sensor_default_in_for_receives(self):
        with temporary_peak_db() as db_path:
            create_sensor_schema(db_path, default_in=2000, default_out=1000)
            details = peak_clickhouse.peak_sample_rate_details("edge-a", 999, "input")
            self.assertEqual(details["effective_sample_rate"], 2000)
            self.assertEqual(details["source"], "sensor")

    def test_peak_hunter_uses_interface_override_when_enabled(self):
        with temporary_peak_db() as db_path:
            create_sensor_schema(db_path, interface_out=3000, override=1)
            details = peak_clickhouse.peak_sample_rate_details("edge-a", 140, "output")
            self.assertEqual(details["effective_sample_rate"], 3000)
            self.assertEqual(details["source"], "interface")

    def test_peak_hunter_applies_effective_sample_rate_to_packets_s(self):
        with temporary_peak_db() as db_path:
            create_sensor_schema(db_path, interface_out=1000, override=1)
            request = PeakHunterRequest(**{**self.request.__dict__, "sensor": "edge-a", "interface_id": 140})
            captured = capture_clickhouse_query(lambda: peak_clickhouse.fetch_interface_series(request))
            self.assertIn("sum(toFloat64(packets) * (toFloat64(1000)))", captured["query"])
            self.assertIn("/ {window_seconds:Float64} AS packets_s", captured["query"])

    def test_peak_hunter_applies_effective_sample_rate_to_bits_s(self):
        with temporary_peak_db() as db_path:
            create_sensor_schema(db_path, interface_out=1000, override=1)
            request = PeakHunterRequest(**{**self.request.__dict__, "sensor": "edge-a", "interface_id": 140, "metric": "bits_s"})
            captured = capture_clickhouse_query(lambda: peak_clickhouse.fetch_interface_series(request))
            self.assertIn("sum(toFloat64(bytes) * (toFloat64(1000))) * 8", captured["query"])

    def test_peak_hunter_detects_real_peak_with_threshold_40000_and_sample_rate_1000(self):
        request = PeakHunterRequest(
            sensor="NE8000-BGP-FIBINET",
            interface_id=140,
            direction="sends",
            metric="packets_s",
            start_time=self.base_time,
            end_time=self.base_time + timedelta(minutes=40),
            protocol="UDP",
            threshold=40000,
            sensitivity="high",
        )
        result = analyze_peak_hunter(request, self._real_sampled_series, self._real_sampled_flows)
        self.assertGreater(result["peaks_detected"], 0)
        self.assertGreater(result["peaks_analyzed"], 0)
        self.assertAlmostEqual(result["best_peak"]["peak_value"], 1_286_600, delta=1)
        self.assertEqual(result["dominant_group"]["dst_ip"], "13.98.137.185")
        self.assertEqual(result["dominant_group"]["dst_port"], 9004)
        self.assertEqual(result["classification"], "udp_flood_outbound_to_single_destination_port")
        self.assertEqual(result["evidence_status"], "complete")
        self.assertEqual(result["dominant_group"]["effective_sample_rate"], 1000)
        self.assertTrue(all(candidate.get("apply_enabled") is False for candidate in result["candidates"]))

    def test_clickhouse_bits_s_query_uses_bytes_times_8(self):
        captured = capture_clickhouse_query(lambda: peak_clickhouse.fetch_interface_series(
            PeakHunterRequest(**{**self.request.__dict__, "metric": "bits_s"})
        ))
        self.assertIn("toFloat64(bytes)", captured["query"])
        self.assertIn("* 8", captured["query"])
        self.assertIn("flow_time >=", captured["query"])

    def test_clickhouse_query_uses_flow_time_not_time(self):
        captured = capture_clickhouse_query(lambda: peak_clickhouse.fetch_peak_flows(self.request, self.base_time, 5))
        self.assertIn("flow_time >=", captured["query"])
        self.assertIn("flow_time <=", captured["query"])
        self.assertNotIn("WHERE time", captured["query"])

    def test_clickhouse_query_maps_udp_to_proto_17(self):
        request = PeakHunterRequest(**{**self.request.__dict__, "protocol": "udp"})
        captured = capture_clickhouse_query(lambda: peak_clickhouse.fetch_interface_series(request))
        self.assertEqual(captured["parameters"]["proto"], 17)

    def test_clickhouse_illegal_aggregation_not_used(self):
        captured = capture_clickhouse_query(lambda: peak_clickhouse.fetch_peak_flows(self.request, self.base_time, 5))
        self.assertNotIn("AS flow_time", captured["query"])
        self.assertIn("min(flow_time) AS first_seen", captured["query"])
        self.assertIn("max(flow_time) AS last_seen", captured["query"])

    def test_bits_s_no_output_if_alias_in_where(self):
        request = PeakHunterRequest(**{**self.request.__dict__, "metric": "bits_s", "direction": "sends"})
        captured = capture_clickhouse_query(lambda: peak_clickhouse.fetch_peak_flows(request, self.base_time, 5))
        where_sql = captured["query"].split("WHERE", 1)[1].split("GROUP BY", 1)[0]
        self.assertIn("output_if = {interface_id:UInt32}", where_sql)
        self.assertNotIn("any(output_if)", where_sql)

    def test_clickhouse_error_returns_json(self):
        if peak_hunter_api is None:
            self.skipTest("fastapi nao instalado")
        payload = peak_hunter_api._analysis_error_response(self.request, "clickhouse_query_failed", "boom", "fetch_peak_flows")
        self.assertEqual(payload["error"], "clickhouse_query_failed")
        self.assertEqual(payload["evidence_status"], "insufficient")
        self.assertEqual(payload["recommendation"]["recommended_action"], "alert_only")

    def test_frontend_peak_hunter_uses_relative_api_paths(self):
        html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn("const API_BASE = ''", html)
        self.assertIn("apiRequest('/api/peak-hunter/options/sensors'", html)
        self.assertIn("apiRequest('/api/peak-hunter/analyze'", html)
        self.assertIn("apiRequest(`/api/peak-hunter/history?", html)
        self.assertIn("apiRequest(`/api/peak-hunter/from-anomaly/${anomalyId}`", html)
        self.assertNotIn("window.location.hostname}:8000", html)

    def test_frontend_peak_hunter_error_messages_include_http_and_cors(self):
        html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Backend retornou HTTP", html)
        self.assertIn("Falha de rede/CORS ao chamar", html)

    def test_ipv4_mapped_ipv6_normalized_for_candidate(self):
        request = PeakHunterRequest(**{**self.request.__dict__, "threshold": 1000})
        result = analyze_peak_hunter(request, self._series, self._ipv4_mapped_flows)
        self.assertEqual(result["dominant_group"]["dst_ip"], "13.98.137.185")
        self.assertTrue(any("13.98.137.185" in str(candidate) for candidate in result["candidates"]))

    def _series(self, request):
        return [
            {"time": self.base_time.isoformat(), "packets_s": 1000},
            {"time": (self.base_time + timedelta(seconds=5)).isoformat(), "packets_s": 120000},
            {"time": (self.base_time + timedelta(seconds=10)).isoformat(), "packets_s": 2000},
        ]

    def _series_with_clear_auto_peak(self, request):
        rows = [
            {"time": (self.base_time + timedelta(seconds=index * 5)).isoformat(), "packets_s": 1000}
            for index in range(20)
        ]
        rows[10]["packets_s"] = 100000
        return rows

    def _large_series(self, request):
        return [
            {"time": (self.base_time + timedelta(seconds=index * 5)).isoformat(), "packets_s": 1000 + index}
            for index in range(1500)
        ]

    def _real_sampled_series(self, request):
        return [
            {"time": self.base_time.isoformat(), "packets_s": 1000, "raw_packets": 5, "effective_sample_rate": 1000, "sample_rate_source": "interface"},
            {"time": (self.base_time + timedelta(seconds=5)).isoformat(), "packets_s": 1_286_600, "raw_packets": 6433, "effective_sample_rate": 1000, "sample_rate_source": "interface"},
            {"time": (self.base_time + timedelta(seconds=10)).isoformat(), "packets_s": 2000, "raw_packets": 10, "effective_sample_rate": 1000, "sample_rate_source": "interface"},
        ]

    def _real_sampled_flows(self, request, peak_time, window):
        if window != 5:
            return []
        return [
            {"src_ip": "::ffff:168.232.197.37", "src_port": 1000, "dst_ip": "::ffff:13.98.137.185", "dst_port": 9004, "protocol": "udp", "packets": 650000, "bytes": 50000000, "raw_packets": 3250, "raw_bytes": 250000, "packets_s": 650000, "bits_s": 40000000, "effective_sample_rate": 1000, "sample_rate_source": "interface"},
            {"src_ip": "::ffff:168.232.197.38", "src_port": 1001, "dst_ip": "::ffff:13.98.137.185", "dst_port": 9004, "protocol": "udp", "packets": 636600, "bytes": 49000000, "raw_packets": 3183, "raw_bytes": 245000, "packets_s": 636600, "bits_s": 39200000, "effective_sample_rate": 1000, "sample_rate_source": "interface"},
        ]

    def _ipv4_mapped_flows(self, request, peak_time, window):
        return [
            {"src_ip": "::ffff:168.232.197.37", "src_port": 1000, "dst_ip": "::ffff:13.98.137.185", "dst_port": 9004, "protocol": "udp", "packets": 1500, "bytes": 900000, "packets_s": 5000},
            {"src_ip": "::ffff:168.232.197.38", "src_port": 1001, "dst_ip": "::ffff:13.98.137.185", "dst_port": 9004, "protocol": "udp", "packets": 1600, "bytes": 950000, "packets_s": 5500},
        ]

    def _series_bits(self, request):
        return [
            {"time": self.base_time.isoformat(), "bits_s": 1000},
            {"time": (self.base_time + timedelta(seconds=5)).isoformat(), "bits_s": 3_000_000},
            {"time": (self.base_time + timedelta(seconds=10)).isoformat(), "bits_s": 1000},
        ]

    def _flows_with_dominant_5s(self, request, peak_time, window):
        if window != 5:
            return []
        return dominant_udp_flows()

    def _flows_dominant_only_15s(self, request, peak_time, window):
        return [] if window == 5 else [
            {"src_ip": "100.64.0.1", "dst_ip": "203.0.113.50", "dst_port": 443, "protocol": "udp", "packets": 800, "bytes": 500000, "packets_s": 3000, "src_port": 1000},
            {"src_ip": "100.64.0.2", "dst_ip": "203.0.113.50", "dst_port": 443, "protocol": "udp", "packets": 900, "bytes": 600000, "packets_s": 3500, "src_port": 1001},
        ]

    def _spread_udp(self, request, peak_time, window):
        return [
            {"src_ip": f"100.64.0.{i}", "dst_ip": f"203.0.113.{i}", "dst_port": 1000 + i, "protocol": "udp", "packets": 100, "bytes": 10000, "src_port": 2000 + i}
            for i in range(1, 8)
        ]

    def _bits_flows(self, request, peak_time, window):
        return [
            {"src_ip": "100.64.0.1", "dst_ip": "203.0.113.100", "dst_port": 9999, "protocol": "udp", "packets": 3000, "bytes": 500000, "bits_s": 500000, "src_port": 1},
            {"src_ip": "100.64.0.2", "dst_ip": "203.0.113.200", "dst_port": 9999, "protocol": "udp", "packets": 1000, "bytes": 2000000, "bits_s": 2000000, "src_port": 2},
        ]

    def _packet_flows(self, request, peak_time, window):
        return [
            {"src_ip": "100.64.0.1", "dst_ip": "203.0.113.100", "dst_port": 9999, "protocol": "udp", "packets": 1000, "bytes": 2000000, "packets_s": 1000, "src_port": 1},
            {"src_ip": "100.64.0.2", "dst_ip": "203.0.113.201", "dst_port": 9999, "protocol": "udp", "packets": 5000, "bytes": 1000000, "packets_s": 5000, "src_port": 2},
        ]


def dominant_udp_flows():
    return [
        {"src_ip": "100.64.0.1", "src_port": 1000, "dst_ip": "203.0.113.10", "dst_port": 65535, "protocol": "udp", "packets": 1500, "bytes": 900000, "packets_s": 5000},
        {"src_ip": "100.64.0.2", "src_port": 1001, "dst_ip": "203.0.113.10", "dst_port": 65535, "protocol": "udp", "packets": 1600, "bytes": 950000, "packets_s": 5500},
        {"src_ip": "100.64.0.3", "src_port": 1002, "dst_ip": "203.0.113.10", "dst_port": 65535, "protocol": "udp", "packets": 1400, "bytes": 800000, "packets_s": 4500},
        {"src_ip": "100.64.0.9", "src_port": 9999, "dst_ip": "198.51.100.9", "dst_port": 9, "protocol": "udp", "packets": 10, "bytes": 1000, "packets_s": 10},
    ]


class temporary_peak_db:
    def __enter__(self):
        self.original = os.environ.get("GMJFLOW_DB_PATH")
        handle = tempfile.NamedTemporaryFile(delete=False)
        self.path = handle.name
        handle.close()
        os.environ["GMJFLOW_DB_PATH"] = self.path
        return self.path

    def __exit__(self, exc_type, exc, tb):
        if self.original is None:
            os.environ.pop("GMJFLOW_DB_PATH", None)
        else:
            os.environ["GMJFLOW_DB_PATH"] = self.original
        try:
            os.unlink(self.path)
        except OSError:
            pass


def create_sensor_schema(db_path, default_in=1000, default_out=1000, interface_in=1000, interface_out=1000, override=1):
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE sensors (
                id INTEGER PRIMARY KEY,
                name TEXT,
                exporter_ip TEXT,
                active INTEGER,
                updated_at TEXT,
                sample_rate_default_in INTEGER,
                sample_rate_default_out INTEGER,
                sample_rate_mode TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE sensor_interfaces (
                sensor_id INTEGER,
                if_index INTEGER,
                if_name TEXT,
                if_descr TEXT,
                if_alias TEXT,
                direction TEXT,
                sample_rate_in INTEGER,
                sample_rate_out INTEGER,
                sample_rate_override INTEGER
            )
            """
        )
        conn.execute(
            "INSERT INTO sensors VALUES (1, 'edge-a', '192.0.2.10', 1, '2026-06-30T12:00:00Z', ?, ?, 'sensor_default')",
            (default_in, default_out),
        )
        conn.execute(
            "INSERT INTO sensor_interfaces VALUES (1, 140, 'Eth-Trunk10.123', 'LINK/CLIENTE', 'alias', 'sends', ?, ?, ?)",
            (interface_in, interface_out, override),
        )


def capture_clickhouse_query(callback):
    captured = {}
    original = peak_clickhouse.query_clickhouse

    def fake_query(query, parameters=None):
        captured["query"] = query
        captured["parameters"] = parameters or {}
        return []

    peak_clickhouse.query_clickhouse = fake_query
    try:
        callback()
    finally:
        peak_clickhouse.query_clickhouse = original
    return captured


if __name__ == "__main__":
    unittest.main()
