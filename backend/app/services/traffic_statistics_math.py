"""Pure descriptive analytics. No detection, policy or mitigation dependencies."""

from dataclasses import dataclass
import math
from statistics import median


@dataclass(frozen=True)
class StatisticsConfig:
    concentrated: float = 0.25
    diverse: float = 0.75
    z_moderate: float = 3.0
    z_strong: float = 6.0
    # Explicit regularization for a constant baseline, in normalized entropy units.
    mad_scale_floor: float = 0.01
    baseline_min_windows: int = 12
    ks_min_samples: int = 30
    ks_thresholds: tuple = (0.10, 0.20, 0.35)
    benford_min_samples: int = 1000
    benford_min_orders: float = 2.0
    benford_mad_thresholds: tuple = (0.012, 0.018)
    current_sample_limit: int = 10000
    baseline_sample_limit: int = 20000
    baseline_days: int = 7


CONFIG = StatisticsConfig()


def entropy_from_aggregates(samples, cardinality, weighted_log, config=CONFIG):
    result = dict(
        samples=samples,
        cardinality=cardinality,
        entropy_bits=None,
        entropy_normalized=None,
        hmax=None,
        distribution_classification="NO_DATA",
    )
    if samples <= 0 or cardinality <= 0:
        return result
    hmax = math.log2(cardinality)
    bits = max(0.0, min(hmax, math.log2(samples) - weighted_log / samples))
    normalized = bits / hmax if cardinality > 1 else 0.0
    classification = (
        "CONCENTRATED"
        if normalized < config.concentrated
        else "MIXED"
        if normalized < config.diverse
        else "HIGH_DIVERSITY"
    )
    return dict(
        result,
        entropy_bits=bits,
        entropy_normalized=normalized,
        hmax=hmax,
        distribution_classification=classification,
    )


def entropy_counts(counts, config=CONFIG):
    values = [n for key, n in counts.items() if key is not None and n > 0]
    return entropy_from_aggregates(
        sum(values), len(values), sum(n * math.log2(n) for n in values), config
    )


def baseline(current, values, config=CONFIG):
    values = [v for v in values if v is not None and math.isfinite(v)]
    result = dict(
        baseline_samples=len(values),
        baseline_median=None,
        baseline_mad=None,
        delta=None,
        robust_z=None,
        regularized_z=None,
        anomaly_classification="NO_BASELINE",
    )
    if values:
        center = median(values)
        mad = median(abs(v - center) for v in values)
        result.update(baseline_median=center, baseline_mad=mad)
    if current is None:
        return dict(result, anomaly_classification="NO_DATA")
    if values:
        result["delta"] = current - center
    if len(values) < config.baseline_min_windows:
        return result
    delta = current - center
    z = delta / (1.4826 * mad) if mad > 0 else (0.0 if delta == 0 else None)
    regularized = delta / max(1.4826 * mad, config.mad_scale_floor)
    magnitude = abs(regularized)
    return dict(
        result,
        robust_z=z,
        regularized_z=regularized,
        anomaly_classification="STRONG"
        if magnitude >= config.z_strong
        else "MODERATE"
        if magnitude >= config.z_moderate
        else "NORMAL",
    )


def ks_test(current, historical, config=CONFIG):
    a = [float(v) for v in current if v is not None and math.isfinite(v)]
    b = [float(v) for v in historical if v is not None and math.isfinite(v)]
    result = dict(
        statistic=None,
        p_value=None,
        current_samples=len(a),
        baseline_samples=len(b),
        classification="INSUFFICIENT_SAMPLES",
        p_value_note="Approximate; discrete values, ties and flow dependence limit calibration.",
    )
    if min(len(a), len(b)) < config.ks_min_samples:
        return result
    from scipy.stats import ks_2samp

    test = ks_2samp(a, b, method="asymp")
    level = sum(float(test.statistic) >= t for t in config.ks_thresholds)
    return dict(
        result,
        statistic=float(test.statistic),
        p_value=float(test.pvalue),
        classification=("NORMAL", "SMALL_SHIFT", "RELEVANT_SHIFT", "STRONG_SHIFT")[
            level
        ],
    )


def benford_test(values, config=CONFIG):
    positive = [
        float(v) for v in values if v is not None and math.isfinite(v) and v > 0
    ]
    expected = [math.log10(1 + 1 / d) for d in range(1, 10)]
    orders = math.log10(max(positive)) - math.log10(min(positive)) if positive else None
    result = dict(
        applicable=False,
        reason=None,
        sample_count=len(positive),
        excluded_count=len(values) - len(positive),
        orders_of_magnitude=orders,
        magnitude_range=[min(positive), max(positive)] if positive else None,
        observed=None,
        expected=expected,
        chi_square=None,
        p_value=None,
        mad=None,
        classification=None,
    )
    if len(positive) < config.benford_min_samples:
        return dict(result, reason="INSUFFICIENT_SAMPLES")
    if orders < config.benford_min_orders:
        return dict(result, reason="INSUFFICIENT_MAGNITUDE_RANGE")
    counts = [0] * 9
    for value in positive:
        # Scientific representation avoids floating point log10 boundary errors at powers of ten.
        digit = int(format(value, ".15e")[0])
        counts[digit - 1] += 1
    observed = [n / len(positive) for n in counts]
    mad = sum(abs(o - e) for o, e in zip(observed, expected)) / 9
    statistic = sum(
        (n - len(positive) * e) ** 2 / (len(positive) * e)
        for n, e in zip(counts, expected)
    )
    level = sum(mad >= t for t in config.benford_mad_thresholds)
    from scipy.stats import chi2

    return dict(
        result,
        applicable=True,
        observed=observed,
        chi_square=statistic,
        p_value=float(chi2.sf(statistic, 8)),
        mad=mad,
        classification=(
            "NORMAL_CONFORMITY",
            "MODERATE_DIVERGENCE",
            "STRONG_DIVERGENCE",
        )[level],
    )


def overall(entropy, ks, benford):
    labels = [x["anomaly_classification"] for x in entropy] + [
        x["classification"] for x in ks
    ]
    labels += [x["classification"] for x in benford if x["applicable"]]
    if any(x in {"STRONG", "STRONG_SHIFT", "STRONG_DIVERGENCE"} for x in labels):
        return "HIGH"
    if any(
        x in {"MODERATE", "SMALL_SHIFT", "RELEVANT_SHIFT", "MODERATE_DIVERGENCE"}
        for x in labels
    ):
        return "MODERATE"
    return (
        "NORMAL"
        if any(x in {"NORMAL", "NORMAL_CONFORMITY"} for x in labels)
        else "INSUFFICIENT_DATA"
    )
