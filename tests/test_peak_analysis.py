from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.peak_analysis import analyze_peak_scope


def iso(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def bps_rows(values, start=0, step=60):
    return [{"ts": start + i * step, "time": iso(start + i * step), "bits_s": v} for i, v in enumerate(values)]


def pps_rows(values, start=0, step=60):
    return [{"ts": start + i * step, "time": iso(start + i * step), "packets_s": v} for i, v in enumerate(values)]


class FakeEvidenceExecutor:
    def __call__(self, query, params):
        import re

        table = re.search(r"FROM\s+(\w+)", query).group(1)
        phase = "peak"
        start = params["start"]
        if start < params["end"] - timedelta(seconds=180):
            phase = "baseline_before"
        if table == "flow_dashboard_series_1m":
            if phase == "baseline_before":
                return [{"bytes": 100.0, "packets": 10.0, "flows": 5.0}]
            return [{"bytes": 400.0, "packets": 40.0, "flows": 20.0}]
        if table == "flow_dashboard_dst_ip_1m" and "uniqExact(src_ip)" in query:
            return [{"total_bytes": 400.0, "unique_src_count": 10, "unique_dst_count": 3}]
        return []


class FakeHotSet:
    def lookup(self, ip):
        return None


class PeakAnalysisTest(unittest.TestCase):
    def _fetch_bps(self, sensor, interface_id, direction):
        return bps_rows([1e11] * 10 + [2e11] * 3 + [1e11] * 10)

    def _fetch_pps(self, sensor, interface_id, direction):
        return pps_rows([1e6] * 10 + [3e6] * 3 + [1e6] * 10)

    def test_pipeline_detects_and_contextualizes(self):
        result = analyze_peak_scope(
            "sensor-A",
            7,
            "receives",
            self._fetch_bps,
            self._fetch_pps,
            FakeEvidenceExecutor(),
            FakeHotSet(),
        )
        self.assertEqual(result["peaks_detected"], 1)
        peak_entry = result["peaks"][0]
        self.assertEqual(peak_entry["peak"]["metric"], "both")
        self.assertIn("evidence", peak_entry)
        self.assertIn("threat", peak_entry)
        self.assertIn("verdict", peak_entry["threat"])

    def test_no_peak_returns_empty(self):
        result = analyze_peak_scope(
            "sensor-A",
            7,
            "receives",
            lambda s, i, d: bps_rows([1e11] * 20),
            lambda s, i, d: pps_rows([1e6] * 20),
            FakeEvidenceExecutor(),
            FakeHotSet(),
        )
        self.assertEqual(result["peaks_detected"], 0)
        self.assertEqual(result["peaks"], [])


if __name__ == "__main__":
    unittest.main()
