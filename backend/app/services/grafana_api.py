from __future__ import annotations

import hashlib
import hmac
import logging
import math
import os
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Callable


logger = logging.getLogger("gmj-flow.grafana")

GRAFANA_API_VERSION = "v1"
GRAFANA_METRICS = {
    "traffic_bps": {
        "label": "Tráfego em bits/s",
        "kind": "timeseries",
        "unit": "bps",
        "dimensions": ["direction", "sensor", "interface", "protocol"],
    },
    "traffic_pps": {
        "label": "Pacotes por segundo",
        "kind": "timeseries",
        "unit": "pps",
        "dimensions": ["direction", "sensor", "interface", "protocol"],
    },
    "top_download_origins": {
        "label": "Top origens do download",
        "kind": "ranking",
        "unit": "bps",
        "dimensions": ["source_asn"],
    },
    "top_upload_destinations": {
        "label": "Top destinos do upload",
        "kind": "ranking",
        "unit": "bps",
        "dimensions": ["destination_asn"],
    },
    "top_protocols": {
        "label": "Top protocolos",
        "kind": "ranking",
        "unit": "bps",
        "dimensions": ["protocol"],
    },
}
GRAFANA_GROUP_BY = {"direction", "sensor", "interface", "protocol"}
GRAFANA_DIRECTIONS = {"both", "upload", "download"}
GRAFANA_CALCULATIONS = {
    "rate",
    "last",
    "last_not_null",
    "mean",
    "max",
    "min",
    "total",
    "difference",
}
GRAFANA_FORMATS = {"json", "table"}
GRAFANA_SCOPES = {
    "grafana:data:read",
    "grafana:dashboard:export",
    "grafana:dashboard:publish",
}
GRAFANA_READ_ENDPOINTS = {
    "health": "/api/v1/grafana/health",
    "catalog": "/api/v1/grafana/catalog",
    "anomalies_active": "/api/v1/grafana/anomalies/active",
    "anomalies_history": "/api/v1/grafana/anomalies/history",
    "mitigations": "/api/v1/grafana/mitigations",
    "bgp_status": "/api/v1/grafana/bgp/status",
}
GRAFANA_RESOURCE_DATASETS = {
    "anomalies_active": {
        "label": "Anomalias ativas",
        "path": GRAFANA_READ_ENDPOINTS["anomalies_active"],
    },
    "anomalies_history": {
        "label": "Histórico de anomalias",
        "path": GRAFANA_READ_ENDPOINTS["anomalies_history"],
    },
    "mitigations": {
        "label": "Mitigações",
        "path": GRAFANA_READ_ENDPOINTS["mitigations"],
    },
    "bgp_status": {
        "label": "Status BGP",
        "path": GRAFANA_READ_ENDPOINTS["bgp_status"],
    },
}
GRAFANA_ANOMALY_FIELDS = (
    "id",
    "status",
    "severity",
    "title",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "bps",
    "pps",
    "bytes",
    "packets",
    "started_at",
    "last_seen_at",
    "duration_seconds",
    "mitigation_status",
)


def is_grafana_api_path(path: Any) -> bool:
    """Identify only the namespace that owns dedicated bearer authentication."""

    normalized = str(path or "").rstrip("/")
    return (
        normalized == "/api/v1/grafana"
        or normalized.startswith("/api/v1/grafana/")
    )


def _bounded_env_int(
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


class GrafanaApiError(ValueError):
    def __init__(
        self,
        status_code: int,
        error: str,
        message: str,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error = error
        self.message = message

    def payload(self, correlation_id: str) -> dict[str, Any]:
        return {
            "error": self.error,
            "message": self.message,
            "correlation_id": correlation_id,
        }


class _GrafanaRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    def check(self, identity: str) -> None:
        limit = _bounded_env_int(
            "GMJ_FLOW_GRAFANA_RATE_LIMIT_PER_MINUTE",
            120,
            1,
            10000,
        )
        now = time.monotonic()
        with self._lock:
            events = self._requests[identity]
            while events and events[0] <= now - 60:
                events.popleft()
            if len(events) >= limit:
                raise GrafanaApiError(
                    429,
                    "rate_limit_exceeded",
                    "Limite de requisições da integração Grafana excedido.",
                )
            events.append(now)


_RATE_LIMITER = _GrafanaRateLimiter()


def correlation_id(value: Any = None) -> str:
    candidate = str(value or "").strip()
    if candidate and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", candidate):
        return candidate
    return str(uuid.uuid4())


def _configured_tokens() -> list[tuple[str, set[str]]]:
    scopes = {
        item.strip()
        for item in os.getenv(
            "GMJ_FLOW_GRAFANA_SCOPES",
            "grafana:data:read,grafana:dashboard:export",
        ).split(",")
        if item.strip() in GRAFANA_SCOPES
    }
    result = []
    for name in (
        "GMJ_FLOW_GRAFANA_TOKEN",
        "GMJ_FLOW_GRAFANA_PREVIOUS_TOKEN",
    ):
        token = os.getenv(name, "").strip()
        if token:
            result.append((token, set(scopes)))
    return result


def authenticate(
    authorization: Any,
    required_scope: str,
    *,
    request_correlation_id: str = "",
) -> dict[str, Any]:
    cid = correlation_id(request_correlation_id)
    configured = _configured_tokens()
    if not configured:
        raise GrafanaApiError(
            503,
            "grafana_auth_not_configured",
            "Token da integração Grafana não configurado.",
        )
    header = str(authorization or "").strip()
    if not header.lower().startswith("bearer "):
        raise GrafanaApiError(
            401,
            "grafana_token_required",
            "Authorization Bearer obrigatório.",
        )
    supplied = header[7:].strip()
    matched_scopes: set[str] | None = None
    for expected, scopes in configured:
        if hmac.compare_digest(
            supplied.encode("utf-8"),
            expected.encode("utf-8"),
        ):
            matched_scopes = scopes
    if matched_scopes is None:
        raise GrafanaApiError(
            401,
            "grafana_token_invalid",
            "Token da integração Grafana inválido.",
        )
    if required_scope not in matched_scopes:
        raise GrafanaApiError(
            403,
            "grafana_scope_insufficient",
            "Scope obrigatório ausente: %s" % required_scope,
        )
    identity = hashlib.sha256(supplied.encode("utf-8")).hexdigest()[:16]
    _RATE_LIMITER.check(identity)
    logger.info(
        "GRAFANA_API_AUTHORIZED correlation_id=%s scope=%s token_id=%s",
        cid,
        required_scope,
        identity,
    )
    return {
        "correlation_id": cid,
        "scopes": sorted(matched_scopes),
        "token_id": identity,
    }


def catalog() -> dict[str, Any]:
    return {
        "api_version": GRAFANA_API_VERSION,
        "metrics": [
            {"id": metric_id, **definition}
            for metric_id, definition in sorted(GRAFANA_METRICS.items())
        ],
        "datasets": [
            {"id": dataset_id, "method": "GET", **definition}
            for dataset_id, definition in sorted(
                GRAFANA_RESOURCE_DATASETS.items()
            )
        ],
        "endpoints": dict(GRAFANA_READ_ENDPOINTS),
        "group_by": sorted(GRAFANA_GROUP_BY),
        "calculations": sorted(GRAFANA_CALCULATIONS),
        "formats": sorted(GRAFANA_FORMATS),
        "limits": {
            "max_window_seconds": max_window_seconds(),
            "minimum_interval_ms": 1000,
            "maximum_interval_ms": 3600000,
            "maximum_data_points": 5000,
            "maximum_top_n": 100,
        },
    }


def service_document(timestamp: str) -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "gmj-flow-grafana-api",
        "api_version": GRAFANA_API_VERSION,
        "timestamp": timestamp,
        "endpoints": dict(GRAFANA_READ_ENDPOINTS),
    }


def _optional_utc_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _integer(value: Any) -> int:
    return int(_number(value))


def _first_text(item: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(item.get(key) or "").strip()
        if value:
            return value
    return ""


def canonical_anomaly_item(item: dict[str, Any]) -> dict[str, Any]:
    metric_unit = _first_text(item, "metric_unit").lower()
    observed = _number(item.get("observed_value"))
    bps = _number(item.get("bps") or item.get("bits_s"))
    pps = _number(item.get("pps") or item.get("packets_s"))
    if not bps and metric_unit in {"bps", "bit/s", "bits/s", "bits_s"}:
        bps = observed
    if not pps and metric_unit in {
        "pps",
        "packet/s",
        "packets/s",
        "packets_s",
    }:
        pps = observed

    started_at = _first_text(item, "started_at", "first_seen", "created_at")
    last_seen_at = _first_text(
        item,
        "last_seen_at",
        "last_seen",
        "ended_at",
        "updated_at",
        "created_at",
    )
    started = _optional_utc_timestamp(started_at)
    last_seen = _optional_utc_timestamp(last_seen_at)
    duration_seconds = (
        max(0, int((last_seen - started).total_seconds()))
        if started is not None and last_seen is not None
        else 0
    )

    result = {
        "id": item.get("id"),
        "status": _first_text(item, "status") or "unknown",
        "severity": _first_text(item, "severity") or "info",
        "title": _first_text(
            item,
            "display_name",
            "type_label",
            "title",
            "summary",
            "vector_name",
            "attack_vector_name",
            "source_name",
        ),
        "source_ip": _first_text(
            item,
            "top_src_ip",
            "dominant_src_ip",
            "src_ip",
        ),
        "destination_ip": _first_text(
            item,
            "top_dst_ip",
            "dominant_dst_ip",
            "dst_ip",
            "target_ip",
        ),
        "protocol": _first_text(
            item,
            "protocol",
            "dominant_protocol",
            "decoder",
        ),
        "source_port": item.get("top_src_port") or item.get("src_port"),
        "destination_port": (
            item.get("top_dst_port")
            or item.get("dominant_dst_port")
            or item.get("dst_port")
            or item.get("target_port")
        ),
        "bps": bps,
        "pps": pps,
        "bytes": _integer(item.get("estimated_bytes") or item.get("bytes")),
        "packets": _integer(
            item.get("estimated_packets") or item.get("packets")
        ),
        "started_at": started_at,
        "last_seen_at": last_seen_at,
        "duration_seconds": duration_seconds,
        "mitigation_status": _first_text(
            item,
            "response_status",
            "mitigation_state",
            "auto_mitigation_status",
        )
        or "none",
    }
    return {field: result[field] for field in GRAFANA_ANOMALY_FIELDS}


def canonical_active_anomalies(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result = [
        canonical_anomaly_item(item)
        for item in items
        if _first_text(item, "status").lower() == "active"
    ]
    return sorted(
        result,
        key=lambda item: (
            _optional_utc_timestamp(item["last_seen_at"])
            or datetime.min.replace(tzinfo=timezone.utc),
            str(item["id"]),
        ),
        reverse=True,
    )


def filter_anomaly_history(
    items: list[dict[str, Any]],
    *,
    from_value: Any = None,
    to_value: Any = None,
    limit: int = 100,
    offset: int = 0,
    status: str = "",
    severity: str = "",
    search: str = "",
) -> tuple[list[dict[str, Any]], int]:
    start = (
        parse_utc_timestamp(from_value, "from")
        if str(from_value or "").strip()
        else None
    )
    end = (
        parse_utc_timestamp(to_value, "to")
        if str(to_value or "").strip()
        else None
    )
    if start is not None and end is not None and start >= end:
        raise GrafanaApiError(
            400,
            "invalid_time_range",
            "from deve ser anterior a to.",
        )

    status_filter = str(status or "").strip().lower()
    severity_filter = str(severity or "").strip().lower()
    search_filter = str(search or "").strip().casefold()
    filtered: list[dict[str, Any]] = []
    for source in items:
        item = canonical_anomaly_item(source)
        if status_filter and item["status"].lower() != status_filter:
            continue
        if severity_filter and item["severity"].lower() != severity_filter:
            continue
        item_started = _optional_utc_timestamp(item["started_at"])
        item_last_seen = _optional_utc_timestamp(item["last_seen_at"])
        if start is not None and (
            item_last_seen is None or item_last_seen < start
        ):
            continue
        if end is not None and (
            item_started is None or item_started > end
        ):
            continue
        if search_filter:
            searchable = " ".join(
                str(item.get(field) or "")
                for field in (
                    "id",
                    "title",
                    "source_ip",
                    "destination_ip",
                    "protocol",
                    "source_port",
                    "destination_port",
                    "mitigation_status",
                )
            ).casefold()
            if search_filter not in searchable:
                continue
        filtered.append(item)
    filtered.sort(
        key=lambda item: (
            _optional_utc_timestamp(item["last_seen_at"])
            or datetime.min.replace(tzinfo=timezone.utc),
            str(item["id"]),
        ),
        reverse=True,
    )
    safe_limit = max(1, min(int(limit), 1000))
    safe_offset = max(0, int(offset))
    return filtered[safe_offset : safe_offset + safe_limit], len(filtered)


def canonical_mitigation_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "anomaly_id": item.get("anomaly_id"),
        "status": _first_text(item, "status") or "unknown",
        "action": _first_text(item, "action"),
        "automatic": bool(item.get("automatic")),
        "vector": _first_text(item, "vector"),
        "profile": _first_text(item, "profile"),
        "connector_id": item.get("connector_id"),
        "connector_type": _first_text(item, "connector_type"),
        "policy_reason": _first_text(item, "policy_reason"),
        "ttl_seconds": _integer(item.get("ttl_seconds")),
        "created_at": _first_text(item, "created_at"),
        "queued_at": _first_text(item, "queued_at"),
        "applied_at": _first_text(item, "applied_at"),
        "expires_at": _first_text(item, "expires_at"),
        "withdrawn_at": _first_text(item, "withdrawn_at"),
        "error_code": _first_text(item, "error_code"),
        "error_message": _first_text(item, "error_message"),
        "updated_at": _first_text(item, "updated_at"),
    }


def canonical_bgp_status_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "name": _first_text(item, "name"),
        "enabled": bool(item.get("enabled")),
        "is_active": bool(item.get("is_active")),
        "backend": _first_text(item, "backend_type", "backend"),
        "mode": _first_text(item, "mode"),
        "local_asn": item.get("local_asn"),
        "peer_asn": item.get("peer_asn"),
        "peer_ip": _first_text(item, "peer_ip"),
        "bgp_state": _first_text(item, "bgp_state") or "not_checked",
        "flowspec_state": (
            _first_text(item, "flowspec_state") or "not_checked"
        ),
        "pipe_state": _first_text(item, "pipe_state") or "not_checked",
        "last_checked_at": _first_text(item, "last_checked_at"),
        "status_message": _first_text(item, "status_message", "message"),
    }


def max_window_seconds() -> int:
    return _bounded_env_int(
        "GMJ_FLOW_GRAFANA_MAX_WINDOW_SECONDS",
        604800,
        60,
        366 * 86400,
    )


def parse_utc_timestamp(value: Any, field: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise GrafanaApiError(400, "invalid_time_range", "%s é obrigatório." % field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise GrafanaApiError(
            400,
            "invalid_time_range",
            "%s deve ser ISO-8601." % field,
        )
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validate_window(
    from_value: Any,
    to_value: Any,
) -> tuple[datetime, datetime]:
    start = parse_utc_timestamp(from_value, "from")
    end = parse_utc_timestamp(to_value, "to")
    if start >= end:
        raise GrafanaApiError(
            400,
            "invalid_time_range",
            "from deve ser anterior a to.",
        )
    if (end - start).total_seconds() > max_window_seconds():
        raise GrafanaApiError(
            400,
            "time_range_too_large",
            "Período excede o limite configurado.",
        )
    return start, end


def _validated_filters(filters: Any) -> dict[str, Any]:
    if hasattr(filters, "dict"):
        filters = filters.dict()
    filters = filters if isinstance(filters, dict) else {}
    direction = str(filters.get("direction") or "both").strip().lower()
    if direction not in GRAFANA_DIRECTIONS:
        raise GrafanaApiError(400, "filter_not_allowed", "Direção inválida.")
    try:
        sensor_ids = [int(item) for item in filters.get("sensor_ids") or []]
        interfaces = [int(item) for item in filters.get("interfaces") or []]
    except (TypeError, ValueError):
        raise GrafanaApiError(
            400,
            "filter_not_allowed",
            "Sensor ou interface inválido.",
        )
    protocols = [
        str(item).strip().lower()
        for item in filters.get("protocols") or []
    ]
    if len(sensor_ids) > 1 or len(interfaces) > 1 or len(protocols) > 1:
        raise GrafanaApiError(
            400,
            "filter_limit_exceeded",
            "O contrato público aceita um sensor, uma interface e um protocolo.",
        )
    if any(item < 1 for item in sensor_ids + interfaces):
        raise GrafanaApiError(
            400,
            "filter_not_allowed",
            "IDs de sensor e interface devem ser positivos.",
        )
    if any(
        not re.fullmatch(r"[a-z0-9][a-z0-9_+.-]{0,31}", item)
        for item in protocols
    ):
        raise GrafanaApiError(
            400,
            "filter_not_allowed",
            "Protocolo inválido.",
        )
    return {
        "sensor_ids": sensor_ids,
        "interfaces": interfaces,
        "protocols": protocols,
        "direction": direction,
    }


def _validate_timezone(value: Any) -> str:
    candidate = str(value or "UTC").strip().upper()
    if candidate not in {"UTC", "ETC/UTC"}:
        raise GrafanaApiError(
            400,
            "timezone_not_allowed",
            "A API pública retorna timestamps canônicos em UTC.",
        )
    return "UTC"


def validate_timeseries_request(payload: Any) -> dict[str, Any]:
    data = payload.dict(by_alias=True) if hasattr(payload, "dict") else dict(payload)
    metric = str(data.get("metric") or "").strip().lower()
    definition = GRAFANA_METRICS.get(metric)
    if not definition or definition["kind"] != "timeseries":
        raise GrafanaApiError(400, "metric_not_allowed", "Métrica não permitida.")
    start, end = validate_window(data.get("from"), data.get("to"))
    filters = _validated_filters(data.get("filters"))
    timezone_name = _validate_timezone(data.get("timezone"))
    group_by = list(data.get("group_by") or ["direction"])
    if len(group_by) != 1 or group_by[0] not in GRAFANA_GROUP_BY:
        raise GrafanaApiError(
            400,
            "group_by_not_allowed",
            "group_by deve conter uma dimensão permitida.",
        )
    calculation = str(data.get("calculation") or "rate").strip().lower()
    if calculation not in GRAFANA_CALCULATIONS:
        raise GrafanaApiError(400, "calculation_not_allowed", "Cálculo inválido.")
    response_format = str(data.get("format") or "json").strip().lower()
    if response_format not in GRAFANA_FORMATS:
        raise GrafanaApiError(400, "format_not_allowed", "Formato inválido.")
    interval_ms = max(1000, min(3600000, int(data.get("interval_ms") or 60000)))
    max_data_points = max(1, min(5000, int(data.get("max_data_points") or 1000)))
    window_ms = max(1, int((end - start).total_seconds() * 1000))
    effective_interval_ms = max(
        interval_ms,
        int(math.ceil(window_ms / max_data_points)),
    )
    return {
        **data,
        "metric": metric,
        "definition": definition,
        "start": start,
        "end": end,
        "interval_ms": effective_interval_ms,
        "max_data_points": max_data_points,
        "filters": filters,
        "group_by": group_by,
        "calculation": calculation,
        "include_partial_bucket": bool(
            data.get("include_partial_bucket", False)
        ),
        "timezone": timezone_name,
        "format": response_format,
    }


def validate_ranking_request(payload: Any) -> dict[str, Any]:
    data = payload.dict(by_alias=True) if hasattr(payload, "dict") else dict(payload)
    metric = str(data.get("metric") or "").strip().lower()
    definition = GRAFANA_METRICS.get(metric)
    if not definition or definition["kind"] != "ranking":
        raise GrafanaApiError(400, "metric_not_allowed", "Métrica não permitida.")
    start, end = validate_window(data.get("from"), data.get("to"))
    filters = _validated_filters(data.get("filters"))
    timezone_name = _validate_timezone(data.get("timezone"))
    calculation = str(
        data.get("calculation") or "last_not_null"
    ).strip().lower()
    if calculation not in GRAFANA_CALCULATIONS - {"rate"}:
        raise GrafanaApiError(400, "calculation_not_allowed", "Cálculo inválido.")
    response_format = str(data.get("format") or "json").strip().lower()
    if response_format not in GRAFANA_FORMATS:
        raise GrafanaApiError(400, "format_not_allowed", "Formato inválido.")
    return {
        **data,
        "metric": metric,
        "definition": definition,
        "start": start,
        "end": end,
        "top_n": max(1, min(100, int(data.get("top_n") or 10))),
        "filters": filters,
        "calculation": calculation,
        "timezone": timezone_name,
        "format": response_format,
    }


def _timestamp_ms(value: Any) -> int:
    if isinstance(value, (int, float)):
        number = int(value)
        return number if number > 100000000000 else number * 1000
    return int(parse_utc_timestamp(value, "timestamp").timestamp() * 1000)


def canonical_timeseries(
    payload: dict[str, Any],
    request: dict[str, Any],
    correlation: str,
) -> dict[str, Any]:
    normalized_series = []
    for item in payload.get("series") if isinstance(payload.get("series"), list) else []:
        direction = str(item.get("direction") or item.get("key") or "").lower()
        points: dict[int, dict[str, Any]] = {}
        for point in item.get("points") if isinstance(item.get("points"), list) else []:
            timestamp = _timestamp_ms(
                point.get("timestamp")
                or point.get("ts")
                or point.get("time")
            )
            raw_value = point.get("value")
            if raw_value is None:
                value = None
            else:
                try:
                    value = abs(float(raw_value))
                except (TypeError, ValueError):
                    continue
            points[timestamp] = {
                "value": value,
                "partial": bool(point.get("partial")),
                "bucket_duration_seconds": point.get(
                    "bucket_duration_seconds"
                ),
            }
        normalized_series.append(
            {
                "key": str(item.get("key") or direction or item.get("name") or ""),
                "name": str(item.get("name") or item.get("label") or direction),
                "labels": {"direction": direction} if direction else {},
                "points": [
                    {
                        "timestamp": timestamp,
                        "value": point["value"],
                        "partial": point["partial"],
                        "bucket_duration_seconds": point[
                            "bucket_duration_seconds"
                        ],
                    }
                    for timestamp, point in sorted(points.items())
                ],
            }
        )
    direction_order = {"upload": 0, "download": 1}
    normalized_series.sort(
        key=lambda item: (
            direction_order.get(item["labels"].get("direction"), 2),
            item["name"],
        )
    )
    result = {
        "kind": "timeseries",
        "metric": request["metric"],
        "unit": request["definition"]["unit"],
        "series": normalized_series,
        "rows": sorted(
            [
                {
                    "timestamp": point["timestamp"],
                    "series": series["name"],
                    "value": point["value"],
                }
                for series in normalized_series
                for point in series["points"]
            ],
            key=lambda row: (row["timestamp"], row["series"]),
        ),
        "meta": {
            "source": payload.get("source") or payload.get("query_source") or "raw",
            "interval_ms": request["interval_ms"],
            "partial": any(
                point.get("partial")
                for series in normalized_series
                for point in series["points"]
            ),
            "include_partial_bucket": request["include_partial_bucket"],
            "calculation": request["calculation"],
            "timezone": "UTC",
            "quality": (
                payload.get("quality")
                if isinstance(payload.get("quality"), dict)
                else {}
            ),
            "correlation_id": correlation,
        },
    }
    if request["format"] == "table":
        rows = [
            [point["timestamp"], series["name"], point["value"]]
            for series in normalized_series
            for point in series["points"]
        ]
        rows.sort(key=lambda row: (row[0], row[1]))
        return {
            "columns": [
                {"name": "time", "type": "time"},
                {"name": "series", "type": "string"},
                {"name": "value", "type": "number"},
            ],
            "rows": rows,
            "meta": result["meta"],
        }
    return result


def canonical_ranking(
    payload: dict[str, Any],
    request: dict[str, Any],
    correlation: str,
) -> dict[str, Any]:
    items = []
    for index, item in enumerate(
        payload.get("items") if isinstance(payload.get("items"), list) else []
    ):
        try:
            value = float(item.get("value") or 0)
        except (TypeError, ValueError):
            value = 0.0
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        safe_metadata = {
            key: value
            for key, value in metadata.items()
            if key in {
                "asn",
                "asn_label",
                "as_name",
                "org_name",
                "country",
                "prefix",
                "ip",
                "entity_kind",
                "resolution_state",
                "protocol",
                "direction",
            }
            and isinstance(value, (str, int, float, bool))
        }
        items.append(
            {
                "rank": index + 1,
                "key": str(item.get("key") or item.get("label") or "-"),
                "label": str(item.get("label") or item.get("key") or "-"),
                "value": value,
                "percent": float(
                    item.get("percent")
                    if item.get("percent") is not None
                    else item.get("percentage") or 0
                ),
                "metadata": safe_metadata,
            }
        )
    total = float(
        payload.get("total")
        if payload.get("total") is not None
        else sum(item["value"] for item in items)
    )
    result = {
        "kind": "ranking",
        "metric": request["metric"],
        "unit": request["definition"]["unit"],
        "items": items,
        "total": total,
        "calculation": request["calculation"],
        "meta": {
            "source": payload.get("source") or "raw",
            "timezone": "UTC",
            "correlation_id": correlation,
        },
    }
    if request["format"] == "table":
        return {
            "columns": [
                {"name": "rank", "type": "number"},
                {"name": "label", "type": "string"},
                {"name": "value", "type": "number"},
                {"name": "percent", "type": "number"},
            ],
            "rows": [
                [item["rank"], item["label"], item["value"], item["percent"]]
                for item in items
            ],
            "meta": result["meta"],
        }
    return result


def audit(
    action: str,
    context: dict[str, Any],
    *,
    metric: str = "",
    outcome: str = "success",
) -> None:
    logger.info(
        "GRAFANA_API action=%s outcome=%s correlation_id=%s token_id=%s metric=%s",
        action,
        outcome,
        context.get("correlation_id"),
        context.get("token_id"),
        metric,
    )
