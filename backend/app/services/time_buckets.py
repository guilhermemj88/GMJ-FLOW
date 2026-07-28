from __future__ import annotations

import os
import math
from datetime import datetime, timedelta, timezone
from typing import Any


PREFERRED_BUCKET_SECONDS = (
    1,
    5,
    10,
    15,
    30,
    60,
    120,
    300,
    600,
    900,
    1800,
    3600,
    7200,
    10800,
    21600,
    43200,
    86400,
)


def utc_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            raise ValueError("timestamp ausente")
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def utc_iso(value: datetime) -> str:
    return utc_datetime(value).isoformat().replace("+00:00", "Z")


def bucket_start(value: Any, bucket_seconds: int) -> datetime:
    size = max(1, int(bucket_seconds))
    parsed = utc_datetime(value)
    epoch = int(parsed.timestamp())
    return datetime.fromtimestamp(epoch - epoch % size, timezone.utc)


def bucket_cutoff(
    range_end: Any,
    *,
    now: datetime | None = None,
) -> datetime:
    current = utc_datetime(now or datetime.now(timezone.utc))
    return min(utc_datetime(range_end), current)


def range_minutes_for_window(start: Any, end: Any) -> int:
    start_dt = utc_datetime(start)
    end_dt = utc_datetime(end)
    duration_seconds = (end_dt - start_dt).total_seconds()
    if duration_seconds <= 0:
        raise ValueError("intervalo precisa ter duração maior que zero")
    return max(1, int(math.ceil(duration_seconds / 60)))


def bucket_seconds_for_window(
    start: Any,
    end: Any,
    *,
    maximum_data_points: int,
    minimum_seconds: int = 1,
) -> int:
    """Choose a larger bucket without shortening the requested time window."""

    start_dt = utc_datetime(start)
    end_dt = utc_datetime(end)
    duration_seconds = (end_dt - start_dt).total_seconds()
    if duration_seconds <= 0:
        raise ValueError("intervalo precisa ter duração maior que zero")
    point_limit = max(1, int(maximum_data_points))
    required = max(
        1,
        int(math.ceil(duration_seconds / point_limit)),
        int(minimum_seconds),
    )
    for candidate in PREFERRED_BUCKET_SECONDS:
        if candidate >= required:
            return candidate
    days = int(math.ceil(required / 86400))
    return max(86400, days * 86400)


def aggregate_temporal_points(
    points: list[dict[str, Any]],
    *,
    maximum_data_points: int,
    timestamp_field: str = "time",
    value_field: str = "value",
) -> list[dict[str, Any]]:
    """Reduce point density across the whole range while retaining both ends."""

    limit = max(1, int(maximum_data_points))
    ordered = sorted(
        (dict(point) for point in points),
        key=lambda point: utc_datetime(point[timestamp_field]),
    )
    if len(ordered) <= limit:
        return ordered

    def aggregate_group(group: list[dict[str, Any]]) -> dict[str, Any]:
        representative = dict(group[len(group) // 2])
        values = []
        for point in group:
            raw_value = point.get(value_field)
            if raw_value is None:
                continue
            try:
                number = float(raw_value)
            except (TypeError, ValueError):
                continue
            if math.isfinite(number):
                values.append(number)
        representative[value_field] = (
            sum(values) / len(values)
            if values
            else None
        )
        representative["bucket_start"] = group[0][timestamp_field]
        representative["bucket_end"] = group[-1][timestamp_field]
        representative["sample_count"] = len(group)
        representative["aggregated"] = len(group) > 1
        reasons = list(dict.fromkeys(
            str(point.get("reason") or "").strip()
            for point in group
            if str(point.get("reason") or "").strip()
        ))
        if reasons:
            representative["reason"] = " | ".join(reasons)
        return representative

    if limit == 1:
        result = aggregate_group(ordered)
        result[timestamp_field] = ordered[0][timestamp_field]
        return [result]
    if limit == 2:
        return [ordered[0], ordered[-1]]

    interior = ordered[1:-1]
    bucket_count = limit - 2
    aggregated = [ordered[0]]
    for index in range(bucket_count):
        start_index = int(math.floor(index * len(interior) / bucket_count))
        end_index = int(math.floor((index + 1) * len(interior) / bucket_count))
        group = interior[start_index:end_index]
        if group:
            aggregated.append(aggregate_group(group))
    aggregated.append(ordered[-1])
    return aggregated


def normalize_rate_bucket_rows(
    rows: list[dict[str, Any]],
    *,
    bucket_seconds: int,
    range_end: Any,
    totals: dict[str, str],
    timestamp_field: str = "ts",
    include_partial_bucket: bool = False,
    now: datetime | None = None,
    decimals: int = 2,
) -> list[dict[str, Any]]:
    """Turn per-bucket counters into rates using each bucket's real duration.

    ``totals`` maps output rate fields to source counter fields. Complete
    buckets use the nominal duration. The currently open bucket is omitted by
    default; when explicitly included it uses only elapsed time and is marked
    as partial.
    """

    size = max(1, int(bucket_seconds))
    cutoff = bucket_cutoff(range_end, now=now)
    normalized = []
    for source in rows:
        try:
            start = bucket_start(source.get(timestamp_field), size)
        except (TypeError, ValueError):
            continue
        elapsed = (cutoff - start).total_seconds()
        if elapsed <= 0:
            continue
        partial = elapsed < size
        if partial and not include_partial_bucket:
            continue
        duration = max(0.001, min(float(size), float(elapsed)))
        item = dict(source)
        item[timestamp_field] = start
        item["partial"] = partial
        item["bucket_duration_seconds"] = duration
        for output_field, total_field in totals.items():
            raw_value = source.get(total_field)
            if raw_value is None:
                item[output_field] = None
                continue
            try:
                item[output_field] = round(float(raw_value) / duration, decimals)
            except (TypeError, ValueError):
                item[output_field] = None
        normalized.append(item)
    normalized.sort(key=lambda item: utc_datetime(item[timestamp_field]))
    return normalized


def _stale_after_seconds(bucket_seconds: int, configured: int | None) -> int:
    if configured is not None:
        return max(int(bucket_seconds), int(configured))
    try:
        value = int(os.getenv("GMJ_FLOW_DATA_STALE_AFTER_SECONDS", "0"))
    except (TypeError, ValueError):
        value = 0
    return max(int(bucket_seconds) * 3, value or 90)


def series_data_quality(
    rows: list[dict[str, Any]],
    *,
    bucket_seconds: int,
    range_end: Any,
    timestamp_field: str = "ts",
    now: datetime | None = None,
    stale_after_seconds: int | None = None,
) -> dict[str, Any]:
    cutoff = bucket_cutoff(range_end, now=now)
    size = max(1, int(bucket_seconds))
    valid = []
    for row in rows:
        try:
            start = bucket_start(row.get(timestamp_field), size)
        except (TypeError, ValueError):
            continue
        valid.append((start, bool(row.get("partial"))))
    complete = [item for item in valid if not item[1]]
    latest = max((item[0] for item in valid), default=None)
    latest_complete = max((item[0] for item in complete), default=None)
    stale_limit = _stale_after_seconds(size, stale_after_seconds)
    last_complete_end = (
        latest_complete + timedelta(seconds=size)
        if latest_complete is not None
        else None
    )
    lag_seconds = (
        max(0, int((cutoff - last_complete_end).total_seconds()))
        if last_complete_end is not None
        else None
    )
    if latest_complete is None:
        status = "no_data"
    elif lag_seconds is not None and lag_seconds > stale_limit:
        status = "delayed"
    else:
        status = "current"
    return {
        "data_status": status,
        "has_data": latest is not None,
        "has_complete_data": latest_complete is not None,
        "last_sample_at": utc_iso(latest) if latest is not None else None,
        "last_complete_sample_at": (
            utc_iso(latest_complete) if latest_complete is not None else None
        ),
        "ingestion_lag_seconds": lag_seconds,
        "stale_after_seconds": stale_limit,
        "collector_warning": (
            "Sem ingestão no período consultado."
            if status == "no_data"
            else "A última amostra completa está atrasada."
            if status == "delayed"
            else None
        ),
        "timezone": "UTC",
    }
