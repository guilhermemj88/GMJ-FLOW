import sys
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.peak_hunter import PeakHunterRequest, analyze_peak_hunter, ensure_peak_analysis_db


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

    def test_packets_s_orders_by_packets_s(self):
        result = analyze_peak_hunter(self.request, self._series, self._packet_flows)
        self.assertEqual(result["dominant_group"]["dst_ip"], "203.0.113.201")
        self.assertEqual(result["dominant_group"]["max_packets_s"], 5000)

    def test_apply_enabled_always_false(self):
        result = analyze_peak_hunter(self.request, self._series, self._flows_with_dominant_5s)
        self.assertFalse(result["best_peak"]["apply_enabled"])
        self.assertTrue(all(candidate.get("apply_enabled") is False for candidate in result["candidates"]))

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

    def _series(self, request):
        return [
            {"time": self.base_time.isoformat(), "packets_s": 1000},
            {"time": (self.base_time + timedelta(seconds=5)).isoformat(), "packets_s": 120000},
            {"time": (self.base_time + timedelta(seconds=10)).isoformat(), "packets_s": 2000},
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


if __name__ == "__main__":
    unittest.main()
