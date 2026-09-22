from __future__ import annotations

"""Orchestrates the refactored Peak Hunter pipeline.

    detect peak -> contextualize (evidence snapshot) -> threat triage -> hand off

This module is the "glue": it wires the pure detection/evidence/threat modules
together. It does NOT apply mitigation, does NOT classify attacks and does NOT
persist history — those concerns belong to the existing Threat Engine,
Anomalies and mitigation pipeline.

All inputs (series fetchers, evidence executor, IOC hot set) are injectable so
the whole pipeline is unit-testable without ClickHouse or SQLite.
"""

from datetime import datetime, timezone
from typing import Any, Callable

from app.services.peak_detection import (
    BPS,
    PPS,
    PeakDetectionConfig,
    detect_peaks,
    normalize_metric_series,
)
from app.services.peak_evidence import PeakEvidenceConfig, build_peak_evidence
from app.services.peak_threat import assess_peak_threat

SeriesFetcher = Callable[[str, int, str], list[dict[str, Any]]]
QueryExecutor = Callable[[str, dict[str, Any]], list[dict[str, Any]]]


def _parse_peak_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def analyze_peak_scope(
    sensor: str,
    interface_id: int,
    direction: str,
    bps_fetcher: SeriesFetcher,
    pps_fetcher: SeriesFetcher,
    evidence_executor: QueryExecutor,
    hotset: Any = None,
    detection_config: PeakDetectionConfig | None = None,
    evidence_config: PeakEvidenceConfig | None = None,
) -> dict[str, Any]:
    """Run the full peak pipeline for one scope (sensor + interface + direction).

    Returns a structured payload with one entry per detected peak containing
    the peak, its evidence snapshot and its threat triage. No mitigation.
    """
    detection_config = detection_config or PeakDetectionConfig()
    bps_series = normalize_metric_series(bps_fetcher(sensor, interface_id, direction), BPS)
    pps_series = normalize_metric_series(pps_fetcher(sensor, interface_id, direction), PPS)
    events = detect_peaks(bps_series, pps_series, detection_config, direction)
    peaks: list[dict[str, Any]] = []
    for event in events:
        peak_time = _parse_peak_time(event.peak_time)
        if peak_time is None:
            continue
        evidence = build_peak_evidence(evidence_executor, sensor, interface_id, direction, peak_time, evidence_config)
        threat = assess_peak_threat(evidence, hotset)
        peaks.append(
            {
                "peak": event.as_dict(),
                "evidence": evidence,
                "threat": threat,
            }
        )
    return {
        "scope": {
            "sensor": sensor,
            "interface_id": interface_id,
            "direction": direction,
        },
        "peaks_detected": len(peaks),
        "peaks": peaks,
    }
