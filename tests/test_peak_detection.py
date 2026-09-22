from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.peak_detection import (
    BPS,
    PPS,
    PeakDetectionConfig,
    detect_metric_peaks,
    detect_peaks,
    normalize_metric_series,
)


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def bps_series(values, start=0, step=60):
    rows = []
    for index, value in enumerate(values):
        ts = start + index * step
        rows.append({"ts": ts, "time": iso(ts), "bits_s": value})
    return rows


def pps_series(values, start=0, step=60):
    rows = []
    for index, value in enumerate(values):
        ts = start + index * step
        rows.append({"ts": ts, "time": iso(ts), "packets_s": value})
    return rows


class PeakDetectionBpsTest(unittest.TestCase):
    def test_bps_peak_detected(self):
        values = [1e11] * 10 + [2e11, 2.2e11, 2e11] + [1e11] * 10
        series = normalize_metric_series(bps_series(values), BPS)
        peaks = detect_metric_peaks(series, BPS, PeakDetectionConfig())
        self.assertEqual(len(peaks), 1)
        self.assertEqual(peaks[0].metric, BPS)
        self.assertAlmostEqual(peaks[0].peak_value, 2.2e11, delta=1)
        self.assertEqual(peaks[0].merged_buckets, 3)

    def test_pps_peak_detected(self):
        values = [1e6] * 10 + [3e6, 4e6, 3e6] + [1e6] * 10
        series = normalize_metric_series(pps_series(values), PPS)
        peaks = detect_metric_peaks(series, PPS, PeakDetectionConfig())
        self.assertEqual(len(peaks), 1)
        self.assertEqual(peaks[0].metric, PPS)
        self.assertAlmostEqual(peaks[0].peak_value, 4e6, delta=1)


class PeakDetectionBothTest(unittest.TestCase):
    def test_both_combines_overlapping_peaks(self):
        bps = normalize_metric_series(bps_series([1e11] * 10 + [2e11] * 3 + [1e11] * 10), BPS)
        pps = normalize_metric_series(pps_series([1e6] * 10 + [3e6] * 3 + [1e6] * 10), PPS)
        peaks = detect_peaks(bps, pps, PeakDetectionConfig())
        self.assertEqual(len(peaks), 1)
        self.assertEqual(peaks[0].metric, "both")

    def test_separate_metrics_reported_independently(self):
        bps = normalize_metric_series(bps_series([1e11] * 10 + [2e11] * 3 + [1e11] * 20), BPS)
        pps = normalize_metric_series(pps_series([1e6] * 25 + [3e6] * 3 + [1e6] * 10), PPS)
        peaks = detect_peaks(bps, pps, PeakDetectionConfig())
        metrics = sorted(peak.metric for peak in peaks)
        self.assertEqual(metrics, [BPS, PPS])


class PeakDetectionNoiseTest(unittest.TestCase):
    def test_small_oscillation_ignored(self):
        values = [1e11] * 10 + [1.1e11] * 3 + [1e11] * 10
        series = normalize_metric_series(bps_series(values), BPS)
        peaks = detect_metric_peaks(series, BPS, PeakDetectionConfig())
        self.assertEqual(len(peaks), 0)

    def test_low_traffic_ignored(self):
        # All values below min_absolute_bps (1e8); even large relative swings
        # are noise and must never trigger a peak.
        values = [1e6, 2e6, 1e6, 5e6, 1e6, 2e6, 1e6, 4e6, 1e6, 3e6]
        series = normalize_metric_series(bps_series(values), BPS)
        peaks = detect_metric_peaks(series, BPS, PeakDetectionConfig())
        self.assertEqual(len(peaks), 0)


class PeakDetectionMergeTest(unittest.TestCase):
    def test_contiguous_buckets_merge_into_single_peak(self):
        values = [1e11] * 10 + [2e11, 2.5e11, 3e11, 2e11] + [1e11] * 10
        series = normalize_metric_series(bps_series(values), BPS)
        peaks = detect_metric_peaks(series, BPS, PeakDetectionConfig())
        self.assertEqual(len(peaks), 1)
        self.assertEqual(peaks[0].merged_buckets, 4)
        self.assertAlmostEqual(peaks[0].peak_value, 3e11, delta=1)


class PeakDetectionCooldownTest(unittest.TestCase):
    def test_second_peak_within_cooldown_ignored(self):
        # Peak 1 at buckets 10..12, peak 2 at buckets 14..16 (within cooldown).
        values = [1e11] * 10 + [2e11, 2e11, 2e11, 1e11, 2.5e11, 2.5e11, 2.5e11] + [1e11] * 10
        series = normalize_metric_series(bps_series(values), BPS)
        peaks = detect_metric_peaks(series, BPS, PeakDetectionConfig())
        self.assertEqual(len(peaks), 1)


class PeakDetectionRobustBaselineTest(unittest.TestCase):
    def test_outlier_does_not_contaminate_baseline(self):
        # A 5e11 outlier sits in history; median stays 1e11 so the real
        # 2e11 peak is still detected against the correct baseline.
        values = (
            [1e11] * 6
            + [5e11]          # single outlier
            + [1e11] * 6
            + [2e11, 2e11, 2e11]
            + [1e11] * 10
        )
        series = normalize_metric_series(bps_series(values), BPS)
        peaks = detect_metric_peaks(series, BPS, PeakDetectionConfig())
        self.assertEqual(len(peaks), 2)  # outlier itself + the real peak
        real = [peak for peak in peaks if abs(peak.peak_value - 2e11) < 1e8]
        self.assertEqual(len(real), 1)
        self.assertAlmostEqual(real[0].baseline_value, 1e11, delta=1e8)


class PeakDetectionConfigTest(unittest.TestCase):
    def test_custom_relative_deviation(self):
        values = [1e11] * 10 + [1.3e11] * 3 + [1e11] * 10
        series = normalize_metric_series(bps_series(values), BPS)
        strict = detect_metric_peaks(series, BPS, PeakDetectionConfig(relative_deviation=0.5))
        self.assertEqual(len(strict), 0)
        loose = detect_metric_peaks(series, BPS, PeakDetectionConfig(relative_deviation=0.2))
        self.assertEqual(len(loose), 1)


if __name__ == "__main__":
    unittest.main()
