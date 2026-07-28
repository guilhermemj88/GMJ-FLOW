from __future__ import annotations

import unittest
from datetime import datetime, timezone

from backend.app.services.time_buckets import (
    aggregate_temporal_points,
    bucket_seconds_for_window,
    bucket_start,
    normalize_rate_bucket_rows,
    range_minutes_for_window,
    series_data_quality,
)


UTC = timezone.utc


class TimeBucketTest(unittest.TestCase):
    def test_temporal_aggregation_preserves_first_and_last_timestamp(self):
        points = [
            {
                "time": f"2026-07-28T10:{minute:02d}:00Z",
                "value": minute,
            }
            for minute in range(60)
        ]
        result = aggregate_temporal_points(
            points,
            maximum_data_points=10,
        )
        self.assertEqual(len(result), 10)
        self.assertEqual(result[0]["time"], points[0]["time"])
        self.assertEqual(result[-1]["time"], points[-1]["time"])
        self.assertTrue(any(point.get("aggregated") for point in result))

    def test_required_dashboard_ranges_keep_the_full_window(self):
        end = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
        for minutes in (15, 60, 1440, 10080):
            with self.subTest(minutes=minutes):
                start = datetime.fromtimestamp(
                    end.timestamp() - minutes * 60,
                    tz=UTC,
                )
                self.assertEqual(
                    range_minutes_for_window(start, end),
                    minutes,
                )

    def test_maximum_data_points_changes_bucket_not_range(self):
        start = datetime(2026, 7, 27, 12, 0, 0, tzinfo=UTC)
        end = datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC)
        dense_bucket = bucket_seconds_for_window(
            start,
            end,
            maximum_data_points=1000,
            minimum_seconds=60,
        )
        compact_bucket = bucket_seconds_for_window(
            start,
            end,
            maximum_data_points=60,
            minimum_seconds=60,
        )
        self.assertEqual(range_minutes_for_window(start, end), 1440)
        self.assertGreater(compact_bucket, dense_bucket)
        self.assertLessEqual(86400 / compact_bucket, 60)

    def test_bucket_changes_at_exact_boundary_and_minute_rollover(self):
        self.assertEqual(
            bucket_start(datetime(2026, 7, 28, 10, 0, 59, tzinfo=UTC), 5),
            datetime(2026, 7, 28, 10, 0, 55, tzinfo=UTC),
        )
        self.assertEqual(
            bucket_start(datetime(2026, 7, 28, 10, 1, 0, tzinfo=UTC), 5),
            datetime(2026, 7, 28, 10, 1, 0, tzinfo=UTC),
        )

    def test_current_partial_bucket_is_excluded_by_default(self):
        rows = [
            {"ts": "2026-07-28T10:00:00Z", "total": 6000},
            {"ts": "2026-07-28T10:01:00Z", "total": 2000},
        ]
        result = normalize_rate_bucket_rows(
            rows,
            bucket_seconds=60,
            range_end="2026-07-28T10:01:20Z",
            totals={"value": "total"},
            now=datetime(2026, 7, 28, 10, 1, 20, tzinfo=UTC),
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["value"], 100)
        self.assertFalse(result[0]["partial"])

    def test_partial_bucket_uses_elapsed_duration_when_enabled(self):
        result = normalize_rate_bucket_rows(
            [{"ts": "2026-07-28T10:01:00Z", "total": 2000}],
            bucket_seconds=60,
            range_end="2026-07-28T10:01:20Z",
            totals={"value": "total"},
            include_partial_bucket=True,
            now=datetime(2026, 7, 28, 10, 1, 20, tzinfo=UTC),
        )
        self.assertEqual(result[0]["value"], 100)
        self.assertTrue(result[0]["partial"])
        self.assertEqual(result[0]["bucket_duration_seconds"], 20)

    def test_rates_use_each_configured_bucket_duration(self):
        for seconds in (1, 5, 10, 30, 60, 300):
            with self.subTest(seconds=seconds):
                start = datetime(2026, 7, 28, 10, 0, 0, tzinfo=UTC)
                end = datetime.fromtimestamp(
                    start.timestamp() + seconds,
                    tz=UTC,
                )
                result = normalize_rate_bucket_rows(
                    [{"ts": start, "total": seconds * 125}],
                    bucket_seconds=seconds,
                    range_end=end,
                    totals={"value": "total"},
                    now=end,
                )
                self.assertEqual(result[0]["value"], 125)
                self.assertFalse(result[0]["partial"])
                self.assertEqual(
                    result[0]["bucket_duration_seconds"],
                    seconds,
                )

    def test_ingestion_delay_is_distinct_from_zero_value(self):
        rows = [
            {
                "ts": "2026-07-28T10:00:00Z",
                "value": 0,
                "partial": False,
            }
        ]
        quality = series_data_quality(
            rows,
            bucket_seconds=60,
            range_end="2026-07-28T10:05:00Z",
            now=datetime(2026, 7, 28, 10, 5, tzinfo=UTC),
            stale_after_seconds=120,
        )
        self.assertTrue(quality["has_complete_data"])
        self.assertEqual(quality["data_status"], "delayed")

    def test_no_samples_is_no_data_not_zero(self):
        quality = series_data_quality(
            [],
            bucket_seconds=10,
            range_end="2026-07-28T10:00:30Z",
            now=datetime(2026, 7, 28, 10, 0, 30, tzinfo=UTC),
        )
        self.assertFalse(quality["has_data"])
        self.assertEqual(quality["data_status"], "no_data")


if __name__ == "__main__":
    unittest.main()
