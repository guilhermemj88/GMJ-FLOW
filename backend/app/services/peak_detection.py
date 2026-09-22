from __future__ import annotations

"""Simple, robust peak detection for the refactored Peak Hunter.

Responsibilities (and nothing else):
  - detect a relevant BPS or PPS peak (or both) in an aggregated series;
  - avoid noise on low traffic;
  - avoid one peak per tiny oscillation;
  - merge contiguous buckets into a single peak;
  - apply cooldown so one sustained peak does not emit hundreds of events.

This module is PURE math: no ClickHouse, no SQLite, no network. The series is
provided by existing aggregators and the evidence/threat integration lives in
other modules.

Detection model (median baseline + robust z-score):
  - baseline = rolling median of the trailing ``baseline_window_seconds``
    (excluding the current point), so a single spike never contaminates the
    baseline;
  - a bucket triggers only when ALL hold:
      1. absolute floor (min_absolute_bps / min_absolute_pps);
      2. relative deviation (value >= baseline * (1 + relative_deviation));
      3. robust z-score >= min_robust_z (when there are enough samples);
  - contiguous triggered buckets (gap <= 1 bucket) merge into one peak;
  - after a peak, buckets inside ``cooldown_seconds`` are ignored.
"""

from dataclasses import dataclass
from typing import Any, Sequence

from app.services.behavior_baseline import mad, median, robust_z_score

BPS = "bits_s"
PPS = "packets_s"
BOTH = "both"

DEFAULT_BASELINE_WINDOW_SECONDS = 180
DEFAULT_MIN_ABSOLUTE_BPS = 100_000_000.0
DEFAULT_MIN_ABSOLUTE_PPS = 10_000.0
DEFAULT_RELATIVE_DEVIATION = 0.5
DEFAULT_MIN_ROBUST_Z = 3.0
DEFAULT_COOLDOWN_SECONDS = 300
DEFAULT_MIN_BASELINE_SAMPLES = 3
DEFAULT_BUCKET_GAP_SECONDS = 60


@dataclass
class PeakDetectionConfig:
    baseline_window_seconds: int = DEFAULT_BASELINE_WINDOW_SECONDS
    min_absolute_bps: float = DEFAULT_MIN_ABSOLUTE_BPS
    min_absolute_pps: float = DEFAULT_MIN_ABSOLUTE_PPS
    relative_deviation: float = DEFAULT_RELATIVE_DEVIATION
    min_robust_z: float = DEFAULT_MIN_ROBUST_Z
    cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS
    min_baseline_samples: int = DEFAULT_MIN_BASELINE_SAMPLES
    bucket_gap_seconds: int = DEFAULT_BUCKET_GAP_SECONDS


@dataclass
class PeakEvent:
    """A single detected peak (already merged + cooled-down)."""

    metric: str
    direction: str
    peak_time: str
    peak_value: float
    baseline_value: float
    ratio: float
    robust_z: float
    bucket_start: str
    bucket_end: str
    merged_buckets: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
            "direction": self.direction,
            "peak_time": self.peak_time,
            "peak_value": self.peak_value,
            "baseline_value": self.baseline_value,
            "ratio": round(self.ratio, 3),
            "robust_z": round(self.robust_z, 3),
            "bucket_start": self.bucket_start,
            "bucket_end": self.bucket_end,
            "merged_buckets": self.merged_buckets,
        }


def _point_ts(point: dict[str, Any]) -> float:
    return float(point["ts"])


def _point_value(point: dict[str, Any]) -> float:
    value = point.get("value")
    return float(value or 0.0)


def normalize_metric_series(rows: Sequence[dict[str, Any]], metric: str) -> list[dict[str, Any]]:
    """Normalize heterogeneous rows into [{ts, time, value}] sorted by ts."""
    series: list[dict[str, Any]] = []
    for row in rows:
        value = float(row.get(metric) or row.get("value") or 0)
        time_text = str(row.get("time") or row.get("bucket") or row.get("ts") or "")
        ts = _epoch(row.get("ts") if row.get("ts") is not None else time_text)
        if ts is None:
            continue
        series.append({"ts": ts, "time": time_text, "value": value})
    series.sort(key=lambda item: item["ts"])
    return series


def _epoch(value: Any) -> float | None:
    from datetime import datetime

    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.timestamp()


def _baseline_window(
    series: list[dict[str, Any]],
    index: int,
    window_seconds: int,
) -> list[float]:
    current_ts = _point_ts(series[index])
    values: list[float] = []
    for previous in reversed(series[:index]):
        if current_ts - _point_ts(previous) > window_seconds:
            break
        values.append(_point_value(previous))
    return list(reversed(values))


def _triggered(
    series: list[dict[str, Any]],
    index: int,
    metric: str,
    floor: float,
    config: PeakDetectionConfig,
) -> tuple[bool, float, float, float]:
    """Return (triggered, baseline_value, ratio, robust_z) for a bucket."""
    value = _point_value(series[index])
    if value < floor:
        return False, 0.0, 0.0, 0.0
    window = _baseline_window(series, index, config.baseline_window_seconds)
    if len(window) < config.min_baseline_samples:
        # Cold start: no reliable baseline yet, require absolute floor only
        # but still apply a large relative guard so a cold start is not a peak.
        return False, 0.0, 0.0, 0.0
    baseline = median(window)
    if baseline <= 0:
        return False, baseline, 0.0, 0.0
    ratio_value = value / baseline
    if ratio_value < 1.0 + config.relative_deviation:
        return False, baseline, ratio_value, 0.0
    deviation = mad(window)
    z_value = robust_z_score(value, baseline, deviation)
    if z_value < config.min_robust_z:
        return False, baseline, ratio_value, z_value
    return True, baseline, ratio_value, z_value


def detect_metric_peaks(
    series: list[dict[str, Any]],
    metric: str,
    config: PeakDetectionConfig,
    direction: str = "total",
) -> list[PeakEvent]:
    """Detect peaks for a single metric (BPS or PPS)."""
    floor = config.min_absolute_bps if metric == BPS else config.min_absolute_pps
    events: list[PeakEvent] = []
    cooldown_until: float | None = None
    index = 0
    total = len(series)
    while index < total:
        ts = _point_ts(series[index])
        if cooldown_until is not None and ts < cooldown_until:
            index += 1
            continue
        triggered, baseline, ratio_value, z_value = _triggered(series, index, metric, floor, config)
        if not triggered:
            index += 1
            continue
        # Merge contiguous (gap <= bucket_gap_seconds) buckets that stay above
        # the SAME fixed baseline captured at the group start. Using a rolling
        # baseline here would let the peak contaminate itself and split one
        # sustained peak into several fragments.
        group_start = index
        group_end = index
        peak_index = index
        peak_value = _point_value(series[index])
        j = index + 1
        while j < total:
            next_ts = _point_ts(series[j])
            prev_ts = _point_ts(series[j - 1])
            if next_ts - prev_ts > config.bucket_gap_seconds:
                break
            value_j = _point_value(series[j])
            if value_j < floor or value_j < baseline * (1.0 + config.relative_deviation):
                break
            group_end = j
            if value_j > peak_value:
                peak_value = value_j
                peak_index = j
            j += 1
        ratio_value = peak_value / baseline if baseline > 0 else 0.0
        window = _baseline_window(series, group_start, config.baseline_window_seconds)
        z_value = robust_z_score(peak_value, baseline, mad(window)) if baseline > 0 else 0.0
        events.append(
            PeakEvent(
                metric=metric,
                direction=direction,
                peak_time=series[peak_index]["time"],
                peak_value=peak_value,
                baseline_value=baseline,
                ratio=ratio_value,
                robust_z=z_value,
                bucket_start=series[group_start]["time"],
                bucket_end=series[group_end]["time"],
                merged_buckets=group_end - group_start + 1,
            )
        )
        cooldown_until = _point_ts(series[group_end]) + config.cooldown_seconds
        index = group_end + 1
    return events


def _overlap(a: PeakEvent, b: PeakEvent, tolerance_seconds: float = 60.0) -> bool:
    from datetime import datetime

    def epoch_of(event: PeakEvent) -> float | None:
        return _epoch(event.peak_time)

    a_ts = epoch_of(a)
    b_ts = epoch_of(b)
    if a_ts is None or b_ts is None:
        return False
    return abs(a_ts - b_ts) <= tolerance_seconds


def detect_peaks(
    bps_series: list[dict[str, Any]],
    pps_series: list[dict[str, Any]],
    config: PeakDetectionConfig,
    direction: str = "total",
) -> list[PeakEvent]:
    """Detect BPS and PPS peaks; combine overlapping ones into a ``both`` peak."""
    bps_peaks = detect_metric_peaks(bps_series, BPS, config, direction)
    pps_peaks = detect_metric_peaks(pps_series, PPS, config, direction)
    combined: list[PeakEvent] = []
    used_pps: set[int] = set()
    for bps_peak in bps_peaks:
        match_index: int | None = None
        for pps_index, pps_peak in enumerate(pps_peaks):
            if pps_index in used_pps:
                continue
            if _overlap(bps_peak, pps_peak):
                match_index = pps_index
                break
        if match_index is None:
            combined.append(bps_peak)
            continue
        pps_peak = pps_peaks[match_index]
        used_pps.add(match_index)
        combined.append(
            PeakEvent(
                metric=BOTH,
                direction=direction,
                peak_time=bps_peak.peak_time,
                peak_value=bps_peak.peak_value,
                baseline_value=bps_peak.baseline_value,
                ratio=bps_peak.ratio,
                robust_z=bps_peak.robust_z,
                bucket_start=bps_peak.bucket_start,
                bucket_end=bps_peak.bucket_end,
                merged_buckets=bps_peak.merged_buckets,
            )
        )
    for pps_index, pps_peak in enumerate(pps_peaks):
        if pps_index not in used_pps:
            combined.append(pps_peak)
    combined.sort(key=lambda event: event.peak_time)
    return combined
