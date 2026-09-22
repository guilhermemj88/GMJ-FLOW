from __future__ import annotations

import re
import sqlite3
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.peak_hunter_runner import run_peak_hunter_cycle
from app.services.peak_events import list_peak_events

PEAK_EPOCH = 1780000000


def iso(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def make_series(peak_epoch, step=60):
    rows = []
    for i in range(20):
        t = peak_epoch - 10 * step + i * step
        bps = 2e11 if 10 <= i <= 12 else 1e11
        pps = 3e6 if 10 <= i <= 12 else 1e6
        rows.append({"ts": t, "time": iso(t), "bits_s": bps, "packets_s": pps})
    return rows


class FakeEvidenceExecutor:
    def __call__(self, query, params):
        table = re.search(r"FROM\s+(\w+)", query).group(1)
        if "uniqExact(src_ip)" in query:
            return [{"total_bytes": 400.0, "unique_src_count": 5, "unique_dst_count": 2}]
        if table == "flow_dashboard_series_1m":
            return [{"bytes": 400.0, "packets": 40.0, "flows": 20.0}]
        return []


class FakeHotSet:
    def lookup(self, ip):
        return None


class RunnerV2Test(unittest.TestCase):
    def _conn(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        return conn

    def _run(self, conn, peak_epoch, handoff=None):
        return run_peak_hunter_cycle(
            now=datetime.fromtimestamp(peak_epoch + 15 * 60, tz=timezone.utc),
            series_fetcher=lambda s, i, d, start, end: make_series(peak_epoch),
            evidence_executor=FakeEvidenceExecutor(),
            hotset=FakeHotSet(),
            handoff=handoff,
            list_scopes=lambda c: [("sensor-A", 7, "receives")],
            conn_factory=lambda: conn,
            lookback_seconds=1800,
        )

    def test_runner_persists_detected_peak(self):
        conn = self._conn()
        created = self._run(conn, PEAK_EPOCH)
        self.assertEqual(len(created), 1)
        events = list_peak_events(conn)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["sensor"], "sensor-A")
        self.assertEqual(events[0]["direction"], "receives")

    def test_same_peak_does_not_duplicate_across_cycles(self):
        conn = self._conn()
        self._run(conn, PEAK_EPOCH)
        created_again = self._run(conn, PEAK_EPOCH + 60)  # same peak, tiny shift
        self.assertEqual(created_again, [])
        self.assertEqual(len(list_peak_events(conn)), 1)

    def test_new_later_peak_creates_new_event(self):
        conn = self._conn()
        self._run(conn, PEAK_EPOCH)
        later = PEAK_EPOCH + 3600  # well outside dedup tolerance
        created = self._run(conn, later)
        self.assertEqual(len(created), 1)
        self.assertEqual(len(list_peak_events(conn)), 2)

    def test_handoff_called_only_for_recommended(self):
        conn = self._conn()
        calls = []
        self._run(conn, PEAK_EPOCH, handoff=lambda c, event_id, entry: calls.append(event_id))
        # verdict from evidence without IOC is normal -> no handoff
        self.assertEqual(calls, [])

    def test_runner_source_has_no_legacy_pipeline(self):
        source = Path(__file__).resolve().parents[1].joinpath("backend", "app", "services", "peak_hunter_runner.py").read_text(encoding="utf-8")
        v2 = source[source.index("run_peak_hunter_cycle"):]
        for forbidden in (
            "analyze_peak_hunter",
            "generate_mitigation_candidates",
            "build_peak_hunter_response_profile_draft",
            "build_peak_hunter_detection_rule_draft",
            "export_peak_analysis_dataset",
            "classify_dominant_group",
            "fetch_peak_flows",
            "fetch_interface_series",
        ):
            self.assertNotIn(forbidden, v2, forbidden)

    def test_runner_source_uses_peak_analysis(self):
        source = Path(__file__).resolve().parents[1].joinpath("backend", "app", "services", "peak_hunter_runner.py").read_text(encoding="utf-8")
        self.assertIn("from app.services.peak_analysis import analyze_peak_scope", source)
        self.assertIn("analyze_peak_scope(", source)

    def test_no_concurrent_cycle(self):
        source = Path(__file__).resolve().parents[1].joinpath("backend", "app", "services", "peak_hunter_runner.py").read_text(encoding="utf-8")
        self.assertIn("_CYCLE_LOCK.acquire(blocking=False)", source)


if __name__ == "__main__":
    unittest.main()
