from __future__ import annotations

import math
import os
import sys
import unittest
from datetime import datetime, timezone


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavior_baseline import (  # noqa: E402
    CONFIDENCE_COLD,
    CONFIDENCE_GOOD,
    CONFIDENCE_LOW,
    CONFIDENCE_MATURE,
    CONFIDENCE_MEDIUM,
    ELIGIBLE,
    MAD_SCALE_FACTOR,
    MAX_ROBUST_Z,
    QUARANTINED,
    REJECTED,
    baseline_confidence,
    baseline_distribution,
    classify_candidate_window,
    effective_mad,
    mad,
    median,
    percentile,
    ratio,
    robust_z_score,
    sanitize_values,
    seasonal_bucket,
    select_baseline_bucket,
)


class PercentileMedianMadTest(unittest.TestCase):
    SAMPLES = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]

    def test_percentiles_linear_interpolation(self):
        # Known values with the same interpolation used by main.py/peak_hunter.
        self.assertAlmostEqual(5.5, percentile(self.SAMPLES, 0.50))
        self.assertAlmostEqual(7.75, percentile(self.SAMPLES, 0.75))
        self.assertAlmostEqual(9.1, percentile(self.SAMPLES, 0.90))
        self.assertAlmostEqual(9.55, percentile(self.SAMPLES, 0.95))
        self.assertAlmostEqual(9.91, percentile(self.SAMPLES, 0.99))
        self.assertAlmostEqual(1.0, percentile(self.SAMPLES, 0.0))
        self.assertAlmostEqual(10.0, percentile(self.SAMPLES, 1.0))

    def test_percentile_single_and_empty(self):
        self.assertEqual(42.0, percentile([42.0], 0.95))
        self.assertEqual(0.0, percentile([], 0.95))
        self.assertEqual(0.0, percentile(None, 0.50))

    def test_median(self):
        self.assertEqual(5.5, median(self.SAMPLES))
        self.assertEqual(3.0, median([1.0, 3.0, 100.0]))
        self.assertEqual(0.0, median([]))

    def test_mad(self):
        self.assertEqual(2.5, mad(self.SAMPLES))
        self.assertEqual(2.0, mad([10.0, 10.0, 12.0, 12.0, 14.0, 100.0]))
        self.assertEqual(0.0, mad([]))

    def test_sanitize_drops_non_numeric(self):
        values = [1.0, None, float("nan"), float("inf"), float("-inf"), "2", True, 3.0]
        self.assertEqual([1.0, 3.0], sanitize_values(values))


class RobustZScoreTest(unittest.TestCase):
    def test_robust_z_score_known_value(self):
        values = [10.0, 10.0, 12.0, 12.0, 14.0, 100.0]
        center = median(values)
        deviation = mad(values)
        # median=12, MAD=2 -> z = 1.0 exactly for current = 12 + 1.4826*2.
        current = center + MAD_SCALE_FACTOR * deviation
        self.assertAlmostEqual(1.0, robust_z_score(current, center, deviation), places=9)
        self.assertAlmostEqual(-1.0, robust_z_score(center - MAD_SCALE_FACTOR * deviation, center, deviation), places=9)

    def test_mad_zero_equal_current(self):
        self.assertEqual(0.0, robust_z_score(7.0, 7.0, 0.0))

    def test_mad_zero_different_current_saturates(self):
        self.assertEqual(MAX_ROBUST_Z, robust_z_score(7.5, 7.0, 0.0))
        self.assertEqual(-MAX_ROBUST_Z, robust_z_score(6.5, 7.0, 0.0))

    def test_constant_series(self):
        distribution = baseline_distribution([5.0, 5.0, 5.0])
        self.assertEqual(0.0, distribution["mad"])
        self.assertEqual(5.0, distribution["min"])
        self.assertEqual(5.0, distribution["max"])
        self.assertEqual(5.0, distribution["p50"])
        self.assertEqual(0.0, robust_z_score(5.0, 5.0, 0.0))

    def test_few_samples(self):
        distribution = baseline_distribution([7.0])
        self.assertEqual(1, distribution["samples"])
        self.assertEqual(7.0, distribution["p99"])
        distribution_two = baseline_distribution([7.0, 9.0])
        self.assertEqual(2, distribution_two["samples"])
        self.assertAlmostEqual(8.0, distribution_two["p50"])

    def test_non_finite_inputs_never_produce_non_finite(self):
        for value in (None, float("nan"), float("inf"), float("-inf"), "x"):
            self.assertEqual(0.0, robust_z_score(value, 1.0, 1.0))
            self.assertEqual(0.0, robust_z_score(1.0, value, 1.0))
            self.assertEqual(0.0, robust_z_score(1.0, 1.0, value))
            self.assertIsNone(ratio(value, 1.0))
            self.assertIsNone(ratio(1.0, value))
        self.assertIsNone(ratio(2.0, 0.0))
        self.assertIsNone(ratio(2.0, -1.0))
        self.assertAlmostEqual(2.0, ratio(4.0, 2.0))

    def test_saturation_and_finite_always(self):
        score = robust_z_score(1e12, 0.0, 1e-9)
        self.assertTrue(math.isfinite(score))
        self.assertLessEqual(abs(score), MAX_ROBUST_Z)


class EffectiveMadTest(unittest.TestCase):
    def test_returns_raw_deviation_when_above_floors(self):
        self.assertEqual(10.0, effective_mad(100.0, 10.0, absolute_floor=0.5, relative_floor_ratio=0.05))

    def test_absolute_floor_applies_for_near_zero_mad(self):
        # center=1.0 -> relative floor 0.05 < absolute floor 0.5.
        self.assertEqual(0.5, effective_mad(1.0, 0.001, absolute_floor=0.5, relative_floor_ratio=0.05))

    def test_relative_floor_applies_for_stable_high_volume(self):
        self.assertEqual(50.0, effective_mad(1000.0, 1.0, absolute_floor=0.5, relative_floor_ratio=0.05))

    def test_non_finite_inputs_are_clamped_to_zero(self):
        self.assertEqual(0.0, effective_mad(None, None, absolute_floor=0.0, relative_floor_ratio=0.0))

    def test_negative_deviation_is_clamped_to_zero(self):
        self.assertEqual(0.5, effective_mad(100.0, -5.0, absolute_floor=0.5, relative_floor_ratio=0.0))


class ConfidenceTest(unittest.TestCase):
    def test_cold_below_24h(self):
        self.assertEqual(CONFIDENCE_COLD, baseline_confidence(span_seconds=23 * 3600))
        self.assertEqual(CONFIDENCE_COLD, baseline_confidence())
        self.assertEqual(CONFIDENCE_COLD, baseline_confidence(span_seconds=None, sample_count=10, samples_per_hour=5))

    def test_low_24h(self):
        self.assertEqual(CONFIDENCE_LOW, baseline_confidence(span_seconds=24 * 3600))
        self.assertEqual(CONFIDENCE_LOW, baseline_confidence(span_seconds=2 * 24 * 3600))

    def test_medium_3d(self):
        self.assertEqual(CONFIDENCE_MEDIUM, baseline_confidence(span_seconds=3 * 24 * 3600))

    def test_good_7d(self):
        self.assertEqual(CONFIDENCE_GOOD, baseline_confidence(span_seconds=7 * 24 * 3600))

    def test_mature_30d(self):
        self.assertEqual(CONFIDENCE_MATURE, baseline_confidence(span_seconds=30 * 24 * 3600))

    def test_sample_count_equivalence(self):
        # 72 samples collected at 12/hour => 6 hours of observation => COLD.
        self.assertEqual(CONFIDENCE_COLD, baseline_confidence(sample_count=72, samples_per_hour=12))
        # 288 samples at 12/hour => 24 hours => LOW.
        self.assertEqual(CONFIDENCE_LOW, baseline_confidence(sample_count=288, samples_per_hour=12))


class SeasonalityTest(unittest.TestCase):
    def test_seasonal_bucket_fields(self):
        # 2026-08-21 is a Friday (Python weekday() = 4).
        bucket = seasonal_bucket(datetime(2026, 8, 21, 10, 30, tzinfo=timezone.utc))
        self.assertIsNotNone(bucket)
        self.assertEqual(10, bucket["hour_of_day"])
        self.assertEqual(4, bucket["day_of_week"])
        self.assertEqual("dow:4:10", bucket["dow_hour_key"])
        self.assertEqual("hour:10", bucket["hour_key"])
        self.assertEqual("global", bucket["global_key"])

    def test_seasonal_bucket_iso_and_naive_and_invalid(self):
        bucket = seasonal_bucket("2026-08-21T10:30:00Z")
        self.assertEqual((10, 4), (bucket["hour_of_day"], bucket["day_of_week"]))
        naive = seasonal_bucket(datetime(2026, 8, 21, 10, 30))
        self.assertEqual(10, naive["hour_of_day"])
        self.assertIsNone(seasonal_bucket("not-a-date"))

    def test_hierarchical_fallback_168_hour_global(self):
        timestamp = datetime(2026, 8, 21, 10, 30, tzinfo=timezone.utc)
        values_by_key = {
            "dow:4:10": [1.0, 2.0, 3.0],
            "hour:10": [10.0, 20.0],
            "global": [100.0],
        }
        selected = select_baseline_bucket(values_by_key, timestamp, min_samples=1)
        self.assertEqual("dow:4:10", selected["key"])
        self.assertFalse(selected["fallback_used"])
        self.assertEqual(3, selected["samples"])

        no_dow = {"dow:4:10": [], "hour:10": [10.0, 20.0], "global": [100.0]}
        selected = select_baseline_bucket(no_dow, timestamp, min_samples=2)
        self.assertEqual("hour:10", selected["key"])
        self.assertTrue(selected["fallback_used"])
        self.assertEqual(["dow:4:10", "hour:10"], selected["fallback_attempted"])

        only_global = {"global": [100.0]}
        selected = select_baseline_bucket(only_global, timestamp, min_samples=1)
        self.assertEqual("global", selected["key"])
        self.assertTrue(selected["fallback_used"])

        empty_everywhere = {"global": []}
        selected = select_baseline_bucket(empty_everywhere, timestamp)
        self.assertEqual("global", selected["key"])
        self.assertEqual(0, selected["samples"])
        self.assertEqual(0, selected["distribution"]["samples"])


class AntiContaminationTest(unittest.TestCase):
    def test_confirmed_attack_is_rejected(self):
        self.assertEqual(REJECTED, classify_candidate_window(confirmed_attack=True, anomaly_score=10))

    def test_high_anomaly_without_confirmation_is_quarantined(self):
        self.assertEqual(QUARANTINED, classify_candidate_window(confirmed_attack=False, anomaly_score=96))
        self.assertEqual(QUARANTINED, classify_candidate_window(anomaly_score=70))

    def test_normal_window_is_eligible(self):
        self.assertEqual(ELIGIBLE, classify_candidate_window(confirmed_attack=False, anomaly_score=12))
        self.assertEqual(ELIGIBLE, classify_candidate_window())

    def test_allowlist_is_not_auto_rejected(self):
        # A low anomaly window (known-benign traffic) stays ELIGIBLE: the
        # helper never treats allowlist/maintenance as REJECTED.
        self.assertEqual(ELIGIBLE, classify_candidate_window(anomaly_score=5))


class DeterminismTest(unittest.TestCase):
    def test_pure_functions_are_deterministic(self):
        values = [3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0, 6.0]
        first = baseline_distribution(values)
        second = baseline_distribution(list(values))
        self.assertEqual(first, second)
        self.assertEqual(percentile(values, 0.95), percentile(list(values), 0.95))
        self.assertEqual(robust_z_score(20.0, median(values), mad(values)),
                         robust_z_score(20.0, median(list(values)), mad(list(values))))
        self.assertEqual(classify_candidate_window(anomaly_score=80),
                         classify_candidate_window(anomaly_score=80))


if __name__ == "__main__":
    unittest.main()
