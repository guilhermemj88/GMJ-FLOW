from __future__ import annotations

import sqlite3
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.peak_events import (
    ensure_peak_events_db,
    find_existing_peak_event,
    get_peak_event,
    link_peak_event,
    list_peak_events,
    save_peak_event,
)


def mem_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


def sample_record(peak_time=None, sensor="sensor-A", direction="receives"):
    peak = peak_time or datetime(2026, 9, 22, 15, 42, tzinfo=timezone.utc)
    return {
        "detected_at": peak.isoformat().replace("+00:00", "Z"),
        "peak_time": peak.isoformat().replace("+00:00", "Z"),
        "sensor": sensor,
        "interface_id": 7,
        "direction": direction,
        "trigger": "both",
        "baseline_bps": 84e9,
        "peak_bps": 131e9,
        "baseline_pps": 11e6,
        "peak_pps": 17e6,
        "delta_bps": 56.0,
        "delta_pps": 54.0,
        "evidence_json": {"changed": {"protocols": []}},
        "threat_verdict": "noteworthy",
        "threat_reasons": ["ioc_signal"],
    }


class PeakEventsTest(unittest.TestCase):
    def test_save_and_get(self):
        conn = mem_conn()
        event_id = save_peak_event(conn, sample_record())
        item = get_peak_event(conn, event_id)
        self.assertIsNotNone(item)
        self.assertEqual(item["sensor"], "sensor-A")
        self.assertEqual(item["trigger"], "both")
        self.assertEqual(item["evidence_json"], {"changed": {"protocols": []}})
        self.assertEqual(item["threat_reasons"], ["ioc_signal"])

    def test_list_orders_by_peak_time(self):
        conn = mem_conn()
        older = sample_record(datetime(2026, 9, 22, 15, 40, tzinfo=timezone.utc))
        newer = sample_record(datetime(2026, 9, 22, 15, 44, tzinfo=timezone.utc))
        save_peak_event(conn, older)
        save_peak_event(conn, newer)
        items = list_peak_events(conn)
        self.assertEqual(len(items), 2)
        self.assertGreater(items[0]["peak_time"], items[1]["peak_time"])

    def test_dedup_within_tolerance(self):
        conn = mem_conn()
        peak = datetime(2026, 9, 22, 15, 42, tzinfo=timezone.utc)
        save_peak_event(conn, sample_record(peak))
        same = find_existing_peak_event(conn, "sensor-A", 7, "receives", peak + timedelta(seconds=120))
        self.assertIsNotNone(same)

    def test_dedup_outside_tolerance_is_none(self):
        conn = mem_conn()
        peak = datetime(2026, 9, 22, 15, 42, tzinfo=timezone.utc)
        save_peak_event(conn, sample_record(peak))
        later = find_existing_peak_event(conn, "sensor-A", 7, "receives", peak + timedelta(minutes=20))
        self.assertIsNone(later)

    def test_dedup_scope_direction_aware(self):
        conn = mem_conn()
        peak = datetime(2026, 9, 22, 15, 42, tzinfo=timezone.utc)
        save_peak_event(conn, sample_record(peak, direction="receives"))
        other_dir = find_existing_peak_event(conn, "sensor-A", 7, "sends", peak)
        self.assertIsNone(other_dir)

    def test_link_anomaly_and_security_event(self):
        conn = mem_conn()
        event_id = save_peak_event(conn, sample_record())
        link_peak_event(conn, event_id, anomaly_id=101, security_event_id=202)
        item = get_peak_event(conn, event_id)
        self.assertEqual(item["anomaly_id"], 101)
        self.assertEqual(item["security_event_id"], 202)

    def test_retention_prunes_old_rows(self):
        conn = mem_conn()
        ensure_peak_events_db(conn)
        old_iso = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat().replace("+00:00", "Z")
        conn.execute(
            "INSERT INTO peak_events (detected_at, peak_time, sensor, direction, trigger, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (old_iso, old_iso, "old", "receives", "bps", old_iso),
        )
        ensure_peak_events_db(conn)
        rows = conn.execute("SELECT COUNT(*) AS c FROM peak_events").fetchone()
        self.assertEqual(rows["c"], 0)


if __name__ == "__main__":
    unittest.main()
