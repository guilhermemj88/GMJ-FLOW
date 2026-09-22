from __future__ import annotations

import re
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
CLICKHOUSE = (ROOT / "backend" / "app" / "services" / "clickhouse.py").read_text(encoding="utf-8")
BEHAVIORAL = (ROOT / "backend" / "app" / "services" / "behavioral_detection.py").read_text(encoding="utf-8")


def block(text: str, start_marker: str, end_marker: str) -> str:
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return text[start:end]


class SensorsEndpointNoSnmpTest(unittest.TestCase):
    """GET /api/sensors nao depende de SNMP e permanece rapido/deterministico."""

    def test_list_sensors_does_not_call_snmp(self) -> None:
        body = block(MAIN, "@app.get(\"/api/sensors\")\ndef list_sensors()", "def refresh_sensor_runtime_status()")
        for token in ("run_snmp", "snmp_get_", "snmp_walk_", "load_pysnmp_api", "pysnmp"):
            self.assertNotIn(token, body)

    def test_sensor_row_to_dict_is_sqlite_only(self) -> None:
        body = block(MAIN, "def sensor_row_to_dict(", "def fetch_sensor(")
        for token in ("run_snmp", "snmp_get_", "snmp_walk_", "query_clickhouse", "requests.", "urllib"):
            self.assertNotIn(token, body)

    def test_enrich_interface_metrics_is_sqlite_only(self) -> None:
        body = block(MAIN, "def enrich_interface_metrics(", "def deterministic_color(")
        for token in ("run_snmp", "snmp_get_", "snmp_walk_", "query_clickhouse"):
            self.assertNotIn(token, body)

    def test_sensors_endpoint_is_sync_fast(self) -> None:
        self.assertIn("def list_sensors()", MAIN)
        self.assertIn("SELECT * FROM sensors ORDER BY name, id", MAIN)


class SnmpIsolationTest(unittest.TestCase):
    """SNMP com timeout nao degrada as APIs web."""

    def test_dedup_prevents_concurrent_polls_of_same_sensor(self) -> None:
        self.assertIn("def snmp_poll_lock(sensor_id: int)", MAIN)
        self.assertIn("if not lock.acquire(blocking=False):", MAIN)
        self.assertIn("lock.release()", MAIN)

    def test_backoff_blocks_after_failure(self) -> None:
        self.assertIn("def snmp_backoff_failure(", MAIN)
        self.assertIn("def snmp_backoff_blocked(", MAIN)
        self.assertIn("SNMP_BACKOFF_BASE_SECONDS", MAIN)
        self.assertIn("SNMP_BACKOFF_MAX_SECONDS", MAIN)

    def test_backoff_resets_on_success(self) -> None:
        self.assertIn("def snmp_backoff_success(", MAIN)
        self.assertIn("SNMP_BACKOFF.pop(sensor_id, None)", MAIN)

    def test_backoff_only_applies_to_background_poll(self) -> None:
        body = block(MAIN, "def poll_snmp_samples(", "def snmp_polling_enabled()")
        self.assertIn("if not force:", body)
        self.assertIn("snmp_backoff_failure(sensor_pk, now)", body)
        self.assertIn("snmp_backoff_success(sensor_pk)", body)

    def test_timeout_is_bounded(self) -> None:
        self.assertIn("timeout_seconds = max(0.5, min(timeout_seconds, 10.0))", MAIN)
        self.assertIn("retries = max(0, min(retries, 3))", MAIN)
        self.assertIn("request_timeout = min(", MAIN)


class SnmpBackoffUnitTest(unittest.TestCase):
    """Validacao funcional do backoff/dedup (funcoes puras)."""

    @classmethod
    def setUpClass(cls) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "backend"))
        from app import main as app_main

        cls.m = app_main

    def test_backoff_failure_then_blocked(self) -> None:
        now = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)
        self.m.snmp_backoff_failure(4, now)
        self.assertTrue(self.m.snmp_backoff_blocked(4, now))
        self.m.snmp_backoff_success(4)
        self.assertFalse(self.m.snmp_backoff_blocked(4, now))

    def test_backoff_expires_after_delay(self) -> None:
        now = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)
        self.m.snmp_backoff_success(7)
        self.m.snmp_backoff_failure(7, now)
        later = now + timedelta(seconds=self.m.SNMP_BACKOFF_MAX_SECONDS + 60)
        self.assertFalse(self.m.snmp_backoff_blocked(7, later))
        self.m.snmp_backoff_success(7)

    def test_poll_lock_is_stable_per_sensor(self) -> None:
        lock_a = self.m.snmp_poll_lock(11)
        lock_b = self.m.snmp_poll_lock(11)
        self.assertIs(lock_a, lock_b)
        self.assertIsInstance(lock_a, type(threading.Lock()))


class RtbhQueryTest(unittest.TestCase):
    """A query do peak-hunter/RTBH nao aninha agregacoes (erro 184)."""

    def test_no_nested_aggregation(self) -> None:
        body = block(CLICKHOUSE, "def fetch_peak_hunter_interfaces(", "def _proto_number(")
        self.assertNotIn("sum(packets) AS rx_packets", body)
        self.assertNotIn("sum(bytes) AS rx_bytes", body)
        self.assertNotIn("sum(packets) AS tx_packets", body)
        self.assertNotIn("sum(bytes) AS tx_bytes", body)
        self.assertIn("packets AS rx_packets", body)
        self.assertIn("bytes AS rx_bytes", body)

    def test_semantics_preserved(self) -> None:
        body = block(CLICKHOUSE, "def fetch_peak_hunter_interfaces(", "def _proto_number(")
        self.assertIn("sum(rx_packets) AS rx_packets", body)
        self.assertIn("sum(tx_packets) AS tx_packets", body)
        self.assertIn("sum(rx_bytes) AS rx_bytes", body)
        self.assertIn("sum(tx_bytes) AS tx_bytes", body)
        self.assertIn("input_if AS interface_id", body)
        self.assertIn("output_if AS interface_id", body)

    def test_rtbh_cycles_do_not_overlap(self) -> None:
        self.assertIn("if not self._run_lock.acquire(blocking=False):", BEHAVIORAL)
        self.assertIn('"skipped": "run_in_progress"', BEHAVIORAL)

    def test_clickhouse_failure_does_not_busy_retry(self) -> None:
        body = block(MAIN, "except Exception as exc:\n        logger.warning(\"RTBH candidate generation ClickHouse query failed", "    try:\n        estimate_multiplier")
        self.assertIn("return {\"status\": \"skipped\"", body)
        self.assertIn("clickhouse_unavailable", body)
        self.assertNotIn("raise", body)


class DashboardEndpointsResilientTest(unittest.TestCase):
    """Endpoints do dashboard nao aguardam SNMP no caminho critico."""

    def test_dashboard_endpoints_do_not_call_snmp(self) -> None:
        for start, end in (
            ("@app.get(\"/api/dashboard/series\")", "def dashboard_anomaly_row_time("),
            ("@app.get(\"/api/tops/src-ip\")", "@app.get(\"/api/tops/dst-ip\")"),
        ):
            body = block(MAIN, start, end)
            for token in ("run_snmp", "snmp_get_", "snmp_walk_", "poll_snmp_samples"):
                self.assertNotIn(token, body, start)


if __name__ == "__main__":
    unittest.main()
