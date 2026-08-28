from __future__ import annotations

"""Central robust-statistics module for the Behavior / Baseline Engine (V1).

This module is the future single-owner of baseline mathematics:
percentiles, MAD, robust z-score, seasonal buckets, hierarchical bucket
selection, baseline confidence and anti-contamination classification.

E2.1 scope: pure, deterministic, dependency-free math. It does NOT persist
anything, does NOT emit BEHAVIOR_ANOMALY and does NOT change existing
consumers. The algorithms mirror the validated semantics already used in:

- main.py::percentile / detection_learning_baseline (median, p90/p95/p99,
  max_clean, MAD, linear-interpolation percentile);
- peak_hunter.py::percentile (same linear-interpolation percentile);
- time_buckets.py (preferred bucket sizes, used later by the builder).

Existing consumers (detection templates, Peak Hunter, Vector Engine) keep
working unchanged; they will be migrated to import from here in a later step.
"""

import math
from datetime import datetime, timedelta, timezone
from statistics import median as _statistics_median
from typing import Any, Mapping, Sequence

# Normal-consistency constant: for normal data, MAD * 1.4826 ~= stddev.
MAD_SCALE_FACTOR = 1.4826

# Robust z-scores are saturated so a tiny MAD can never produce huge values.
MAX_ROBUST_Z = 6.0

# Baseline maturity levels (documented in the design report).
CONFIDENCE_COLD = "COLD"
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_GOOD = "GOOD"
CONFIDENCE_MATURE = "MATURE"
CONFIDENCE_LEVELS = (
    CONFIDENCE_COLD,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_GOOD,
    CONFIDENCE_MATURE,
)

# Minimum observation spans that unlock each level. A baseline is COLD while
# its span is below the first threshold.
_CONFIDENCE_SPAN_THRESHOLDS = (
    (24 * 3600, CONFIDENCE_LOW),        # >= 24h
    (3 * 24 * 3600, CONFIDENCE_MEDIUM),  # >= 3 days
    (7 * 24 * 3600, CONFIDENCE_GOOD),    # >= 7 days
    (30 * 24 * 3600, CONFIDENCE_MATURE),  # >= 30 days
)

# Anti-contamination candidate window states (pure classification only; not
# wired to the runtime in E2.1).
ELIGIBLE = "ELIGIBLE"
QUARANTINED = "QUARANTINED"
REJECTED = "REJECTED"

# Default anomaly-score threshold above which a window without a confirmed
# attack is QUARANTINED instead of ELIGIBLE.
DEFAULT_QUARANTINE_THRESHOLD = 70.0


def _finite_float(value: Any) -> float | None:
    # Strict numeric-only parsing: booleans and strings are rejected so that
    # incidental data (True, "2", flags) can never leak into statistics.
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    return None


def sanitize_values(values: Sequence[Any] | Any) -> list[float]:
    """Keep only finite numeric values, preserving order.

    None, NaN, +/-inf, non-numeric strings and booleans are dropped.
    """
    if values is None:
        return []
    if isinstance(values, (str, bytes)):
        return []
    sanitized: list[float] = []
    for value in values:
        number = _finite_float(value)
        if number is not None:
            sanitized.append(number)
    return sanitized


def percentile(values: Sequence[Any] | Any, q: float) -> float:
    """Percentile with linear interpolation, q in [0, 1].

    Matches the semantics of main.py::percentile and
    peak_hunter.py::percentile. Returns 0.0 for empty input.
    """
    ordered = sorted(sanitize_values(values))
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    quantile = min(1.0, max(0.0, float(q)))
    rank = (len(ordered) - 1) * quantile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def median(values: Sequence[Any] | Any) -> float:
    """Median of the sanitized values; 0.0 when the input is empty."""
    sanitized = sanitize_values(values)
    if not sanitized:
        return 0.0
    return float(_statistics_median(sanitized))


def mad(values: Sequence[Any] | Any) -> float:
    """Median absolute deviation around the median; 0.0 for empty/constant."""
    sanitized = sanitize_values(values)
    if not sanitized:
        return 0.0
    center = float(_statistics_median(sanitized))
    deviations = [abs(value - center) for value in sanitized]
    return float(_statistics_median(deviations))


def robust_z_score(current: Any, center: Any, deviation: Any, *, max_z: float = MAX_ROBUST_Z) -> float:
    """Robust z-score: (current - center) / (MAD_SCALE_FACTOR * MAD).

    Safety rules:
    - non-finite current/center/deviation => 0.0;
    - negative MAD is treated as 0;
    - MAD == 0 (constant series): equal values yield 0.0, any difference
      yields +/-max_z (saturated), so no division by zero ever happens;
    - the result is saturated to [-max_z, max_z] and always finite.
    """
    current_value = _finite_float(current)
    center_value = _finite_float(center)
    deviation_value = _finite_float(deviation)
    if current_value is None or center_value is None or deviation_value is None:
        return 0.0
    scale = MAD_SCALE_FACTOR * max(0.0, deviation_value)
    difference = current_value - center_value
    if scale <= 0.0:
        if difference == 0.0:
            return 0.0
        return max_z if difference > 0.0 else -max_z
    score = difference / scale
    if not math.isfinite(score):
        return 0.0
    return max(-max_z, min(max_z, score))


def ratio(current: Any, baseline: Any) -> float | None:
    """Current / baseline ratio.

    Returns None when the ratio is undefined or non-finite (baseline missing,
    zero or negative; current non-finite). Negative current values are
    preserved arithmetically; callers of rate metrics should pass
    non-negative values.
    """
    current_value = _finite_float(current)
    baseline_value = _finite_float(baseline)
    if current_value is None or baseline_value is None or baseline_value <= 0:
        return None
    result = current_value / baseline_value
    return result if math.isfinite(result) else None


def baseline_distribution(values: Sequence[Any] | Any) -> dict[str, float]:
    """Compact statistical snapshot of a sample set.

    Empty input returns samples=0 with all statistics zeroed (same behavior as
    the existing detection_learning_baseline for empty datasets).
    """
    sanitized = sanitize_values(values)
    if not sanitized:
        return {
            "samples": 0.0,
            "p50": 0.0,
            "p75": 0.0,
            "p90": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "mad": 0.0,
            "min": 0.0,
            "max": 0.0,
            "median": 0.0,
            "avg": 0.0,
        }
    center = float(_statistics_median(sanitized))
    deviations = [abs(value - center) for value in sanitized]
    return {
        "samples": float(len(sanitized)),
        "p50": percentile(sanitized, 0.50),
        "p75": percentile(sanitized, 0.75),
        "p90": percentile(sanitized, 0.90),
        "p95": percentile(sanitized, 0.95),
        "p99": percentile(sanitized, 0.99),
        "mad": float(_statistics_median(deviations)),
        "min": float(min(sanitized)),
        "max": float(max(sanitized)),
        "median": center,
        "avg": sum(sanitized) / len(sanitized),
    }


def baseline_confidence(
    span_seconds: float | None = None,
    *,
    sample_count: int | None = None,
    samples_per_hour: float | None = None,
) -> str:
    """Baseline maturity level based on observation span.

    Levels: COLD (<24h), LOW (>=24h), MEDIUM (>=3d), GOOD (>=7d),
    MATURE (>=30d).

    Equivalence when only samples are known: span_seconds is derived as
    (sample_count / samples_per_hour) * 3600. If neither span nor the
    sample/hour pair is provided the baseline is COLD.
    """
    resolved_span: float | None = None
    span_value = _finite_float(span_seconds)
    if span_value is not None:
        resolved_span = span_value
    elif sample_count is not None and samples_per_hour is not None:
        count_value = _finite_float(sample_count)
        per_hour_value = _finite_float(samples_per_hour)
        if count_value is not None and per_hour_value is not None and per_hour_value > 0:
            resolved_span = (count_value / per_hour_value) * 3600.0
    if resolved_span is None:
        return CONFIDENCE_COLD
    level = CONFIDENCE_COLD
    for threshold_seconds, candidate in _CONFIDENCE_SPAN_THRESHOLDS:
        if resolved_span >= threshold_seconds:
            level = candidate
    return level


def _parse_timestamp(timestamp: Any) -> datetime | None:
    if isinstance(timestamp, datetime):
        parsed = timestamp
    else:
        try:
            parsed = datetime.fromisoformat(str(timestamp or "").strip().replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def seasonal_bucket(timestamp: Any) -> dict[str, Any] | None:
    """Seasonality helpers for a timestamp (naive timestamps are treated as UTC).

    Returns None for unparseable timestamps. day_of_week uses Python's
    weekday() convention: 0=Monday ... 6=Sunday.
    """
    parsed = _parse_timestamp(timestamp)
    if parsed is None:
        return None
    hour_of_day = parsed.hour
    day_of_week = parsed.weekday()
    return {
        "hour_of_day": hour_of_day,
        "day_of_week": day_of_week,
        "dow_hour_key": f"dow:{day_of_week}:{hour_of_day}",
        "hour_key": f"hour:{hour_of_day}",
        "global_key": "global",
    }


def select_baseline_bucket(
    values_by_key: Mapping[str, Sequence[Any] | Any],
    timestamp: Any,
    *,
    min_samples: int = 1,
) -> dict[str, Any]:
    """Hierarchical seasonal fallback: (day_of_week, hour) -> hour -> global.

    Picks the most granular bucket with at least min_samples valid samples.
    If even the global bucket lacks samples, the global bucket is returned
    anyway with its (empty) distribution so callers always get a snapshot.
    """
    bucket = seasonal_bucket(timestamp)
    required = max(1, int(min_samples))
    fallback_attempted: list[str] = []
    if bucket is not None:
        ordered_keys = [bucket["dow_hour_key"], bucket["hour_key"], bucket["global_key"]]
    else:
        ordered_keys = ["global"]
    chosen_key = ordered_keys[-1]
    for key in ordered_keys:
        fallback_attempted.append(key)
        if len(sanitize_values(values_by_key.get(key))) >= required:
            chosen_key = key
            break
    chosen_values = values_by_key.get(chosen_key)
    return {
        "key": chosen_key,
        "samples": len(sanitize_values(chosen_values)),
        "fallback_attempted": fallback_attempted,
        "fallback_used": chosen_key != fallback_attempted[0],
        "distribution": baseline_distribution(chosen_values),
    }


def classify_candidate_window(
    *,
    confirmed_attack: bool = False,
    anomaly_score: float | None = None,
    quarantine_threshold: float = DEFAULT_QUARANTINE_THRESHOLD,
) -> str:
    """Pure anti-contamination classification for a candidate baseline window.

    Rules:
    - confirmed attack (e.g. CONFIRMED_ATTACK vector in the window) => REJECTED;
    - no confirmed attack but anomaly_score >= quarantine_threshold
      => QUARANTINED;
    - otherwise => ELIGIBLE.

    Allowlist/maintenance is intentionally NOT handled here: known-benign
    traffic may still be ELIGIBLE for baseline learning and will receive an
    explicit policy in a future step.
    """
    if confirmed_attack:
        return REJECTED
    score_value = _finite_float(anomaly_score)
    if score_value is not None and score_value >= float(quarantine_threshold):
        return QUARANTINED
    return ELIGIBLE


# --------------------------------------------------------------------------
# Safe Learning / Safe Bootstrap maturity states (E2.2 wired into the
# vector-engine baseline). The window classification still reuses
# ELIGIBLE / QUARANTINED / REJECTED; baseline_state tracks maturity.
# --------------------------------------------------------------------------

BOOTSTRAP = "BOOTSTRAP"
TRUSTED = "TRUSTED"

# Number of consecutive clean windows required to promote BOOTSTRAP -> TRUSTED.
DEFAULT_BOOTSTRAP_MIN_CLEAN_WINDOWS = 12

# Robust z-score threshold above which a TRUSTED baseline quarantines a window.
# NOTE: this is a z-score, NOT the 0-100 anomaly-score DEFAULT_QUARANTINE_THRESHOLD.
DEFAULT_SAFE_QUARANTINE_Z = 4.0

# Minimum samples before the robust-z quarantine gate becomes active.
DEFAULT_MIN_QUARANTINE_SAMPLES = 24

# How long a quarantined baseline stays frozen (per-window evaluation continues).
DEFAULT_QUARANTINE_MINUTES = 15

# Minimum deviation samples accumulated into the MAD EMA before the robust
# statistics are considered "ready". This is an observability signal only: the
# robust-z quarantine gate itself still keys off sample_count via
# DEFAULT_MIN_QUARANTINE_SAMPLES. Readiness does not change the decision math.
DEFAULT_MIN_ROBUST_SAMPLES = 24

# Observations whose timestamp deviates from wall-clock beyond this tolerance
# are treated as clock-skewed and excluded from the baseline update path.
DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS = 3600


def safe_reason_bucket(reason: str) -> str:
    """Deterministic low-cardinality bucket for a safe-learning reason.

    Keeps hourly counters bounded instead of persisting arbitrary strings.
    """
    value = (reason or "").strip().lower()
    if value == "normal":
        return "normal"
    if value == "confirmed_attack":
        return "confirmed_attack"
    if value in {"bootstrap_strong_signal", "detector_signal"}:
        return "detector_signal"
    if value == "robust_z":
        return "robust_z"
    if value in {"quarantine_extended", "quarantine_frozen"}:
        return "quarantine_active"
    if value in {"bootstrap_clean", "bootstrap_promoted"}:
        return "bootstrap_not_mature"
    if value == "clock_skew":
        return "clock_skew"
    return "other"


def _add_iso_minutes(iso: str, minutes: int) -> str:
    parsed = _parse_timestamp(iso)
    if parsed is None:
        return ""
    return (parsed + timedelta(minutes=max(0, int(minutes)))).isoformat().replace("+00:00", "Z")


def safe_learning_decision(
    *,
    baseline_state: str = BOOTSTRAP,
    bootstrap_clean_count: int = 0,
    sample_count: int = 0,
    ema_pps: float = 0.0,
    mad_pps: float = 0.0,
    window_pps: float = 0.0,
    confirmed_attack: bool = False,
    strong_detector_signal: bool = False,
    quarantined_until: str = "",
    now_iso: str = "",
    bootstrap_min_clean_windows: int = DEFAULT_BOOTSTRAP_MIN_CLEAN_WINDOWS,
    quarantine_z: float = DEFAULT_SAFE_QUARANTINE_Z,
    min_quarantine_samples: int = DEFAULT_MIN_QUARANTINE_SAMPLES,
    quarantine_minutes: int = DEFAULT_QUARANTINE_MINUTES,
    robust_stats_ready: bool = False,
) -> dict[str, Any]:
    """Deterministic Safe Learning decision for one baseline window.

    Pure: no persistence, no lookup. Returns classification, whether the
    baseline should update, the next maturity state/clean-count, promotion and
    the next quarantine deadline. The caller decides whether to actually apply
    the update (feature switch) and what to persist.
    """
    state = baseline_state if baseline_state in (BOOTSTRAP, TRUSTED) else BOOTSTRAP
    frozen = bool(quarantined_until and now_iso and str(quarantined_until) > str(now_iso))

    # A confirmed attack (or CRITICAL) signal always rejects the window and
    # never feeds the baseline.
    if confirmed_attack:
        return {
            "classification": REJECTED,
            "should_update": False,
            "next_state": state,
            "next_clean_count": 0,
            "promoted": False,
            "reason": "confirmed_attack",
            "next_quarantined_until": "",
        }

    if state == BOOTSTRAP:
        # During bootstrap there is no trusted baseline to z-score against, so
        # "clean" is decided by absolute detector evidence only.
        if strong_detector_signal:
            return {
                "classification": REJECTED,
                "should_update": False,
                "next_state": BOOTSTRAP,
                "next_clean_count": 0,
                "promoted": False,
                "reason": "bootstrap_strong_signal",
                "next_quarantined_until": "",
            }
        clean_count = max(0, int(bootstrap_clean_count)) + 1
        if clean_count >= max(1, int(bootstrap_min_clean_windows)):
            return {
                "classification": ELIGIBLE,
                "should_update": True,
                "next_state": TRUSTED,
                "next_clean_count": clean_count,
                "promoted": True,
                "reason": "bootstrap_promoted",
                "next_quarantined_until": "",
            }
        return {
            "classification": ELIGIBLE,
            "should_update": True,
            "next_state": BOOTSTRAP,
            "next_clean_count": clean_count,
            "promoted": False,
            "reason": "bootstrap_clean",
            "next_quarantined_until": "",
        }

    # TRUSTED state.
    if frozen:
        z_score = robust_z_score(window_pps, ema_pps, mad_pps)
        if abs(z_score) >= float(quarantine_z):
            return {
                "classification": QUARANTINED,
                "should_update": False,
                "next_state": TRUSTED,
                "next_clean_count": 0,
                "promoted": False,
                "reason": "quarantine_extended",
                "next_quarantined_until": _add_iso_minutes(now_iso, quarantine_minutes),
            }
        return {
            "classification": ELIGIBLE,
            "should_update": False,  # still frozen until the deadline expires
            "next_state": TRUSTED,
            "next_clean_count": 0,
            "promoted": False,
            "reason": "quarantine_frozen",
            "next_quarantined_until": quarantined_until,
        }

    # A strong detector signal while robust statistics are not yet ready must
    # not be learned into the baseline (cold-start protection without MAD).
    # When the feature is OFF this only produces a shadow divergence; V1 still
    # applies its own update.
    if strong_detector_signal and not robust_stats_ready:
        return {
            "classification": REJECTED,
            "should_update": False,
            "next_state": TRUSTED,
            "next_clean_count": 0,
            "promoted": False,
            "reason": "detector_signal",
            "next_quarantined_until": "",
        }

    # Not frozen: quarantine only via a robust z-score against a mature baseline.
    if (
        int(sample_count) >= int(min_quarantine_samples)
        and _finite_float(ema_pps) is not None
        and _finite_float(ema_pps) > 0
        and _finite_float(mad_pps) is not None
        and _finite_float(mad_pps) > 0
    ):
        z_score = robust_z_score(window_pps, ema_pps, mad_pps)
        if abs(z_score) >= float(quarantine_z):
            return {
                "classification": QUARANTINED,
                "should_update": False,
                "next_state": TRUSTED,
                "next_clean_count": 0,
                "promoted": False,
                "reason": "robust_z",
                "next_quarantined_until": _add_iso_minutes(now_iso, quarantine_minutes),
            }

    return {
        "classification": ELIGIBLE,
        "should_update": True,
        "next_state": TRUSTED,
        "next_clean_count": 0,
        "promoted": False,
        "reason": "normal",
        "next_quarantined_until": "",
    }
