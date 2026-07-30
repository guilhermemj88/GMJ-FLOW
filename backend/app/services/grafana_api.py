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
from ipaddress import ip_address, ip_network
from typing import Any, Callable

from .prefixes import normalize_prefix_filter, normalize_prefix_grouping


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
    "traffic_by_prefix_bps": {
        "label": "Tráfego por prefixo em bits/s",
        "kind": "timeseries",
        "unit": "bps",
        "dimensions": ["source_prefix", "destination_prefix"],
    },
    "traffic_by_prefix_pps": {
        "label": "Tráfego por prefixo em pacotes/s",
        "kind": "timeseries",
        "unit": "pps",
        "dimensions": ["source_prefix", "destination_prefix"],
    },
    "prefix_timeseries": {
        "label": "Série temporal por prefixo",
        "kind": "timeseries",
        "unit": "bps",
        "dimensions": ["source_prefix", "destination_prefix"],
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
    "top_source_ips": {
        "label": "Top IPs de origem",
        "kind": "ranking",
        "unit": "bps",
        "dimensions": ["source_ip"],
    },
    "top_destination_ips": {
        "label": "Top IPs de destino",
        "kind": "ranking",
        "unit": "bps",
        "dimensions": ["destination_ip"],
    },
    "top_ports": {
        "label": "Top portas",
        "kind": "ranking",
        "unit": "bps",
        "dimensions": ["protocol", "port"],
    },
    "top_tcp_flags": {
        "label": "Top TCP Flags",
        "kind": "ranking",
        "unit": "pps",
        "dimensions": ["tcp_flags"],
    },
    "top_source_prefixes": {
        "label": "Top prefixos de origem",
        "kind": "ranking",
        "unit": "bps",
        "dimensions": ["source_prefix"],
    },
    "top_destination_prefixes": {
        "label": "Top prefixos de destino",
        "kind": "ranking",
        "unit": "bps",
        "dimensions": ["destination_prefix"],
    },
    "top_ports_by_prefix": {
        "label": "Top portas no prefixo",
        "kind": "ranking",
        "unit": "bps",
        "dimensions": ["protocol", "port", "prefix"],
    },
    "top_protocols_by_prefix": {
        "label": "Top protocolos no prefixo",
        "kind": "ranking",
        "unit": "bps",
        "dimensions": ["protocol", "prefix"],
    },
}
GRAFANA_RANKING_QUERY_PLANS = {
    "top_download_origins": {
        "dimension": "src_asn",
        "direction": "download",
        "metric": "bps",
    },
    "top_upload_destinations": {
        "dimension": "dst_asn",
        "direction": "upload",
        "metric": "bps",
    },
    "top_protocols": {
        "dimension": "protocol",
        "direction": None,
        "metric": "bps",
    },
    "top_source_ips": {
        "dimension": "src_ip",
        "direction": None,
        "metric": "bps",
    },
    "top_destination_ips": {
        "dimension": "dst_ip",
        "direction": None,
        "metric": "bps",
    },
    # The MVP groups destination port together with protocol. The shared
    # dst_port query already performs GROUP BY port, proto in ClickHouse.
    "top_ports": {
        "dimension": "dst_port",
        "direction": None,
        "metric": "bps",
    },
    "top_tcp_flags": {
        "dimension": "tcp_flags",
        "direction": None,
        "metric": "pps",
    },
    "top_source_prefixes": {
        "dimension": "src_prefix",
        "direction": None,
        "metric": "bps",
    },
    "top_destination_prefixes": {
        "dimension": "dst_prefix",
        "direction": None,
        "metric": "bps",
    },
    "top_ports_by_prefix": {
        "dimension": "dst_port",
        "direction": None,
        "metric": "bps",
    },
    "top_protocols_by_prefix": {
        "dimension": "protocol",
        "direction": None,
        "metric": "bps",
    },
}
GRAFANA_GROUP_BY = {
    "direction",
    "sensor",
    "interface",
    "protocol",
    "src_prefix",
    "dst_prefix",
}
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
GRAFANA_RANKING_CALCULATIONS = {
    "rate",
    "last",
    "last_not_null",
    "mean",
    "max",
    "min",
    "total",
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
    "mitigations_active": "/api/v1/grafana/mitigations/active",
    "bgp_status": "/api/v1/grafana/bgp/status",
}
GRAFANA_CGNAT_FIELDS = (
    "cgnat_applicable",
    "cgnat_resolved",
    "cgnat_private_ip",
    "cgnat_public_ip",
    "cgnat_public_port",
    "cgnat_port_range",
    "cgnat_pool",
    "cgnat_device",
    "cgnat_vendor",
    "cgnat_mapping_source",
    "cgnat_confidence",
)
GRAFANA_RESOURCE_FIELDS = (
    "cgnat_private_ip",
    "cgnat_public_ip",
    "cgnat_public_port",
    "cgnat_pool",
    "cgnat_device",
)
GRAFANA_ACTIVE_MITIGATION_STATUSES = {
    "sent",
    "advertised",
    "active",
    "applied",
    "announced",
}
GRAFANA_EXCLUDED_MITIGATION_STATUSES = {
    "expired",
    "withdrawn",
    "failed",
    "failed_withdraw",
    "blocked",
    "rejected",
    "rejected_by_policy",
    "dry_run",
    "simulation_only",
}
GRAFANA_RESOURCE_DATASETS = {
    "anomalies_active": {
        "label": "Anomalias ativas",
        "path": GRAFANA_READ_ENDPOINTS["anomalies_active"],
        "fields": list(GRAFANA_RESOURCE_FIELDS),
    },
    "anomalies_history": {
        "label": "Histórico de anomalias",
        "path": GRAFANA_READ_ENDPOINTS["anomalies_history"],
        "fields": list(GRAFANA_RESOURCE_FIELDS),
    },
    "mitigations": {
        "label": "Mitigações",
        "path": GRAFANA_READ_ENDPOINTS["mitigations"],
        "fields": list(GRAFANA_RESOURCE_FIELDS),
    },
    "mitigations_active": {
        "label": "Mitigações ativas",
        "path": GRAFANA_READ_ENDPOINTS["mitigations_active"],
        "fields": list(GRAFANA_RESOURCE_FIELDS),
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
    *GRAFANA_CGNAT_FIELDS,
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
        "resource_fields": list(GRAFANA_RESOURCE_FIELDS),
        "fields": [
            {"id": field_id}
            for field_id in GRAFANA_RESOURCE_FIELDS
        ],
        "endpoints": dict(GRAFANA_READ_ENDPOINTS),
        "group_by": sorted(GRAFANA_GROUP_BY),
        "calculations": sorted(GRAFANA_CALCULATIONS),
        "ranking_calculations": sorted(GRAFANA_RANKING_CALCULATIONS),
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


def _optional_integer(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_text(item: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(item.get(key) or "").strip()
        if value:
            return value
    return ""


def _cgnat_vendor(source_type: str) -> str | None:
    normalized = source_type.strip().lower()
    if normalized == "a10":
        return "A10"
    if normalized in {"mikrotik", "mikrotik_netmap"}:
        return "MikroTik"
    return None


def canonical_cgnat_fields(item: dict[str, Any]) -> dict[str, Any]:
    addressing = (
        item.get("subscriber_addressing_resolution")
        if isinstance(item.get("subscriber_addressing_resolution"), dict)
        else {}
    )
    effective_mode = _first_text(
        item,
        "effective_subscriber_addressing_mode",
    ).lower() or str(addressing.get("effective_mode") or "").strip().lower()
    applicable = bool(
        item.get("cgnat_applicable")
        or item.get("cgnat_matched")
        or item.get("cgnat_lookup_performed")
        or effective_mode == "cgnat"
        or _first_text(item, "cgnat_gate").lower() == "required"
    )
    private_ip = _first_text(item, "private_ip")
    resolved = bool(
        applicable
        and item.get("cgnat_matched")
        and not item.get("cgnat_ambiguous")
        and private_ip
    )
    if not resolved:
        return {
            "cgnat_applicable": applicable,
            "cgnat_resolved": False,
            **{
                field: None
                for field in GRAFANA_CGNAT_FIELDS
                if field not in {"cgnat_applicable", "cgnat_resolved"}
            },
        }

    port_start = _optional_integer(item.get("mapped_port_start"))
    port_end = _optional_integer(item.get("mapped_port_end"))
    port_range = (
        f"{port_start}-{port_end}"
        if port_start is not None and port_end is not None
        else None
    )
    source_type = _first_text(item, "cgnat_source_type").lower()
    confidence = (
        _number(item.get("cgnat_confidence"))
        if item.get("cgnat_confidence") not in (None, "")
        else None
    )
    return {
        "cgnat_applicable": True,
        "cgnat_resolved": True,
        "cgnat_private_ip": private_ip,
        "cgnat_public_ip": _first_text(item, "public_ip") or None,
        "cgnat_public_port": _optional_integer(item.get("public_port")),
        "cgnat_port_range": port_range,
        "cgnat_pool": _first_text(item, "cgnat_pool_name") or None,
        "cgnat_device": _first_text(item, "cgnat_device_name") or None,
        "cgnat_vendor": _cgnat_vendor(source_type),
        # Expose only the parser/source type. The internal source filename,
        # batch, candidates and full mapping rule remain private.
        "cgnat_mapping_source": source_type or None,
        "cgnat_confidence": confidence,
    }


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
        **canonical_cgnat_fields(item),
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


def mitigation_is_active(
    item: dict[str, Any],
    *,
    now: datetime | None = None,
) -> bool:
    status = _first_text(item, "status").lower()
    if status not in GRAFANA_ACTIVE_MITIGATION_STATUSES:
        return False
    if status in GRAFANA_EXCLUDED_MITIGATION_STATUSES:
        return False
    if _first_text(item, "confirmation_level").lower() == "simulation_only":
        return False
    if _first_text(item, "requested_mode").lower() == "dry_run":
        return False
    expires_at = _optional_utc_timestamp(item.get("expires_at"))
    current = now or datetime.now(timezone.utc)
    return expires_at is None or expires_at > current


def validate_mitigation_filters(
    *,
    active_only: bool = False,
    anomaly_id: Any = None,
    status: str = "",
    connector_id: Any = None,
    from_value: Any = None,
    to_value: Any = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
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
    return {
        "active_only": bool(active_only),
        "anomaly_id": _optional_integer(anomaly_id),
        "status": str(status or "").strip().lower(),
        "connector_id": _optional_integer(connector_id),
        "start": start,
        "end": end,
        "limit": max(1, min(int(limit), 1000)),
        "offset": max(0, int(offset)),
    }


def canonical_mitigation_item(
    item: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    raw_payload = (
        item.get("raw_payload")
        if isinstance(item.get("raw_payload"), dict)
        else {}
    )
    raw_anomaly = (
        raw_payload.get("anomaly")
        if isinstance(raw_payload.get("anomaly"), dict)
        else {}
    )
    cgnat_event = (
        item.get("_cgnat_event")
        if isinstance(item.get("_cgnat_event"), dict)
        else raw_anomaly
    )
    top_flow = (
        cgnat_event.get("top_flow")
        if isinstance(cgnat_event.get("top_flow"), dict)
        else {}
    )
    status = _first_text(item, "status").lower() or "unknown"
    requested_mode = _first_text(item, "requested_mode").lower()
    mode = (
        "automatic"
        if requested_mode in {"auto", "automatic"}
        else "manual"
        if requested_mode in {
            "",
            "manual",
            "manual_approval",
            "announce_now",
            "semi_auto",
        }
        else requested_mode
    )
    raw_connector_mode = _first_text(item, "connector_mode").lower()
    connector_mode = (
        "automatic"
        if raw_connector_mode in {"auto", "automatic"}
        else raw_connector_mode
    )
    ttl_seconds = _integer(
        item.get("duration_seconds") or item.get("ttl_seconds")
    )
    expires_at = _first_text(item, "expires_at")
    expires = _optional_utc_timestamp(expires_at)
    current = now or datetime.now(timezone.utc)
    remaining_seconds = (
        max(0, int((expires - current).total_seconds()))
        if expires is not None
        else ttl_seconds
        if mitigation_is_active(item, now=current)
        else 0
    )
    source_ip = _first_text(
        cgnat_event,
        "public_ip",
        "top_src_ip",
        "dominant_src_ip",
        "src_ip",
    ) or _first_text(top_flow, "src_ip")
    if not source_ip:
        source_ip = _first_text(item, "src_prefix").split("/", 1)[0]
    destination_ip = _first_text(
        cgnat_event,
        "top_dst_ip",
        "dominant_dst_ip",
        "dst_ip",
    ) or _first_text(top_flow, "dst_ip") or _first_text(item, "dst_ip")
    if not destination_ip:
        destination_ip = _first_text(
            item,
            "dst_prefix",
            "target_prefix",
        ).split("/", 1)[0]
    source_port = (
        _optional_integer(cgnat_event.get("public_port"))
        or _optional_integer(cgnat_event.get("top_src_port"))
        or _optional_integer(top_flow.get("src_port"))
        or _optional_integer(item.get("src_port"))
    )
    destination_port = (
        _optional_integer(cgnat_event.get("top_dst_port"))
        or _optional_integer(cgnat_event.get("target_port"))
        or _optional_integer(top_flow.get("dst_port"))
        or _optional_integer(item.get("dst_port"))
    )
    started_at = _first_text(
        item,
        "advertised_at",
        "sent_at",
        "queued_at",
        "created_at",
    )
    result = {
        "id": item.get("id"),
        "anomaly_id": item.get("anomaly_id"),
        "status": status,
        "action": (
            "withdraw"
            if status in {"withdrawn", "expired", "failed_withdraw"}
            else "announce"
        ),
        "mode": mode,
        "connector_id": item.get("connector_id"),
        "connector_name": _first_text(item, "connector_name"),
        "connector_backend": _first_text(item, "connector_backend"),
        "connector_mode": connector_mode,
        "rule_type": _first_text(
            item,
            "attack_vector_name",
        )
        or _first_text(
            cgnat_event,
            "vector_name",
            "attack_vector_name",
            "source_name",
        ),
        "source_ip": source_ip or None,
        "destination_ip": destination_ip or None,
        "protocol": _first_text(
            item,
            "protocol",
        )
        or _first_text(cgnat_event, "protocol", "decoder")
        or _first_text(top_flow, "protocol"),
        "source_port": source_port,
        "destination_port": destination_port,
        "prefix": _first_text(
            item,
            "target_prefix",
            "dst_prefix",
            "src_prefix",
        )
        or None,
        "started_at": started_at or None,
        "expires_at": expires_at or None,
        "ttl_seconds": ttl_seconds,
        "remaining_seconds": remaining_seconds,
        **canonical_cgnat_fields(cgnat_event),
    }
    return result


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


def _optional_filter_id(value: Any, field: str) -> int | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.lower() in {"all", "*", "todos"}:
        return None
    try:
        parsed = int(text)
    except (TypeError, ValueError):
        raise GrafanaApiError(
            400,
            "filter_not_allowed",
            "%s deve ser um ID positivo ou 'all'." % field,
        )
    if parsed < 1:
        raise GrafanaApiError(
            400,
            "filter_not_allowed",
            "%s deve ser um ID positivo ou 'all'." % field,
        )
    return parsed


def _filters_with_scalar_aliases(
    data: dict[str, Any],
) -> tuple[dict[str, Any], int | None]:
    raw_filters = data.get("filters")
    if hasattr(raw_filters, "dict"):
        raw_filters = raw_filters.dict()
    raw_filters = dict(raw_filters) if isinstance(raw_filters, dict) else {}
    for alias, target in (
        ("sensor", "sensor_ids"),
        ("interface", "interfaces"),
    ):
        alias_id = _optional_filter_id(data.get(alias), alias)
        if alias_id is None:
            if str(data.get(alias) or "").strip().lower() in {
                "all",
                "*",
                "todos",
            }:
                raw_filters[target] = []
            continue
        current = raw_filters.get(target) or []
        if current and [int(item) for item in current] != [alias_id]:
            raise GrafanaApiError(
                400,
                "filter_not_allowed",
                "Filtro %s foi informado com valores conflitantes." % alias,
            )
        raw_filters[target] = [alias_id]
    if data.get("direction") not in (None, ""):
        current_direction = str(
            raw_filters.get("direction") or "both"
        ).strip().lower()
        alias_direction = str(data["direction"]).strip().lower()
        if current_direction not in {"", "both", alias_direction}:
            raise GrafanaApiError(
                400,
                "filter_not_allowed",
                "Filtro direction foi informado com valores conflitantes.",
            )
        raw_filters["direction"] = alias_direction
    return _validated_filters(raw_filters), _optional_filter_id(
        data.get("zone"),
        "zone",
    )


def validate_timeseries_request(payload: Any) -> dict[str, Any]:
    data = payload.dict(by_alias=True) if hasattr(payload, "dict") else dict(payload)
    metric = str(data.get("metric") or "").strip().lower()
    definition = GRAFANA_METRICS.get(metric)
    if not definition or definition["kind"] != "timeseries":
        raise GrafanaApiError(400, "metric_not_allowed", "Métrica não permitida.")
    start, end = validate_window(data.get("from"), data.get("to"))
    filters, zone_id = _filters_with_scalar_aliases(data)
    try:
        prefix_filter = normalize_prefix_filter(data.get("prefix_filter"))
        prefix_grouping = normalize_prefix_grouping(
            data.get("prefix_grouping")
        )
    except ValueError as exc:
        raise GrafanaApiError(400, "prefix_filter_not_allowed", str(exc))
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
        "zone_id": zone_id,
        "prefix_filter": prefix_filter,
        "prefix_grouping": prefix_grouping,
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
    filters, zone_id = _filters_with_scalar_aliases(data)
    protocol_alias = str(data.get("protocol") or "").strip().lower()
    if protocol_alias:
        current_protocols = filters.get("protocols") or []
        if current_protocols and current_protocols != [protocol_alias]:
            raise GrafanaApiError(
                400,
                "filter_not_allowed",
                "Filtro protocol foi informado com valores conflitantes.",
            )
        filters["protocols"] = [protocol_alias]
        filters = _validated_filters(filters)
    try:
        prefix_filter = normalize_prefix_filter(data.get("prefix_filter"))
        prefix_grouping = normalize_prefix_grouping(
            data.get("prefix_grouping")
        )
    except ValueError as exc:
        raise GrafanaApiError(400, "prefix_filter_not_allowed", str(exc))
    timezone_name = _validate_timezone(data.get("timezone"))
    calculation = str(
        data.get("calculation") or "last_not_null"
    ).strip().lower()
    if calculation not in GRAFANA_RANKING_CALCULATIONS:
        raise GrafanaApiError(400, "calculation_not_allowed", "Cálculo inválido.")
    response_format = str(data.get("format") or "json").strip().lower()
    if response_format not in GRAFANA_FORMATS:
        raise GrafanaApiError(400, "format_not_allowed", "Formato inválido.")
    try:
        raw_top_n = data.get("top_n")
        top_n = int(
            10
            if raw_top_n is None or raw_top_n == ""
            else raw_top_n
        )
    except (TypeError, ValueError):
        raise GrafanaApiError(
            400,
            "top_n_not_allowed",
            "top_n deve ser um inteiro entre 1 e 100.",
        )
    if top_n < 1 or top_n > 100:
        raise GrafanaApiError(
            400,
            "top_n_not_allowed",
            "top_n deve estar entre 1 e 100.",
        )
    return {
        **data,
        "metric": metric,
        "definition": definition,
        "start": start,
        "end": end,
        "top_n": top_n,
        "filters": filters,
        "zone_id": zone_id,
        "prefix_filter": prefix_filter,
        "prefix_grouping": prefix_grouping,
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
    metric = request["metric"]
    unit = request["definition"]["unit"]

    def number(value: Any) -> float:
        try:
            return float(value or 0)
        except (TypeError, ValueError):
            return 0.0

    def optional_integer(value: Any) -> int | None:
        if value in (None, ""):
            return None
        match = re.search(r"(\d+)", str(value))
        return int(match.group(1)) if match else None

    def normalized_ip(value: Any) -> str:
        text = str(value or "").strip()
        try:
            address = ip_address(text)
        except ValueError:
            return ""
        if getattr(address, "ipv4_mapped", None):
            return str(address.ipv4_mapped)
        return str(address)

    def normalized_protocol(value: Any) -> str:
        text = str(value or "").strip().upper()
        aliases = {
            "1": "ICMP",
            "6": "TCP",
            "17": "UDP",
            "47": "GRE",
            "50": "ESP",
            "58": "IPv6-ICMP",
            "ICMPV6": "IPv6-ICMP",
            "IPV6_ICMP": "IPv6-ICMP",
            "IPV6-ICMP": "IPv6-ICMP",
        }
        if text in aliases:
            return aliases[text]
        if text in {"TCP", "UDP", "ICMP", "GRE", "ESP"}:
            return text
        match = re.fullmatch(r"IP(\d{1,3})", text)
        if match and 0 <= int(match.group(1)) <= 255:
            number_text = str(int(match.group(1)))
            return aliases.get(number_text, "IP%s" % number_text)
        if text.isdigit() and 0 <= int(text) <= 255:
            return "IP%s" % int(text)
        return ""

    def normalized_flags(value: Any) -> str:
        text = str(value or "").strip()
        if not text or text.upper() in {"0", "NONE", "NULL"}:
            return "NONE"
        flag_order = (
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        )
        try:
            bits = int(text, 0)
        except ValueError:
            requested = {
                token.strip().upper()
                for token in re.split(r"[,|+ ]+", text)
                if token.strip()
            }
            valid_names = {name for _, name in flag_order}
            if not requested or not requested <= valid_names:
                return ""
            names = [
                name
                for _, name in flag_order
                if name in requested
            ]
            return ",".join(names)
        names = [name for bit, name in flag_order if bits & bit]
        return ",".join(names) if names else "NONE"

    items = []
    for item in (
        payload.get("items") if isinstance(payload.get("items"), list) else []
    ):
        raw_value = item.get("value")
        if raw_value is None:
            if unit == "pps":
                raw_value = (
                    item.get("pps")
                    if item.get("pps") is not None
                    else item.get("packets_s")
                )
            else:
                raw_value = (
                    item.get("bps")
                    if item.get("bps") is not None
                    else item.get("bits_s")
                )
        value = max(0.0, number(raw_value))
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        safe_metadata = {
            key: metadata_value
            for key, metadata_value in metadata.items()
            if key in {
                "asn",
                "asn_label",
                "as_name",
                "org_name",
                "country",
                "country_code",
                "country_name",
                "prefix",
                "ip",
                "entity_kind",
                "resolution_state",
                "protocol",
                "direction",
            }
            and isinstance(metadata_value, (str, int, float, bool))
        }
        key = str(item.get("key") or item.get("label") or "").strip()
        label = str(item.get("label") or item.get("key") or "").strip()
        bps = number(
            item.get("bps")
            if item.get("bps") is not None
            else item.get("bits_s")
        )
        pps = number(
            item.get("pps")
            if item.get("pps") is not None
            else item.get("packets_s")
        )
        if unit == "bps" and not bps:
            bps = value
        if unit == "pps" and not pps:
            pps = value
        percentage = number(
            item.get("percentage")
            if item.get("percentage") is not None
            else item.get("percent")
        )
        asn = optional_integer(
            item.get("asn")
            or item.get("asn_number")
            or metadata.get("asn")
        )
        asn_name = str(
            metadata.get("as_name")
            or metadata.get("org_name")
            or item.get("as_name")
            or item.get("description")
            or ""
        ).strip()
        if asn_name in {"-", "N/D"}:
            asn_name = ""
        country_code = str(
            metadata.get("country_code")
            or metadata.get("country")
            or item.get("country_code")
            or item.get("country")
            or ""
        ).strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", country_code):
            country_code = ""
        country_name = str(
            metadata.get("country_name")
            or item.get("country_name")
            or ""
        ).strip()
        protocol = str(
            item.get("protocol")
            or item.get("proto")
            or metadata.get("protocol")
            or ""
        ).strip()
        raw_port = str(item.get("port") or "").strip()
        port = (
            int(raw_port)
            if re.fullmatch(r"\d{1,5}", raw_port)
            else None
        )
        display_name = ""
        tcp_flags = ""
        packets = int(number(item.get("packets")))
        if metric in {"top_source_ips", "top_destination_ips"}:
            dimension_ip = normalized_ip(
                item.get("ip") or item.get("key") or item.get("label")
            )
            if not dimension_ip:
                continue
            key = dimension_ip
            label = dimension_ip
        elif metric in {"top_ports", "top_ports_by_prefix"}:
            key_match = re.fullmatch(
                r"\s*([^/]+)/(\d{1,5})\s*",
                key or label,
            )
            if key_match:
                protocol = protocol or key_match.group(1)
                if port is None:
                    port = optional_integer(key_match.group(2))
            protocol = normalized_protocol(protocol)
            if not protocol or port is None or port < 0 or port > 65535:
                continue
            display_name = "%s/%s" % (protocol.lower(), port)
            key = display_name
            label = display_name
        elif metric in {"top_protocols", "top_protocols_by_prefix"}:
            protocol = normalized_protocol(
                protocol or item.get("key") or item.get("label")
            )
            if not protocol:
                continue
            key = protocol
            label = protocol
        elif metric == "top_tcp_flags":
            raw_flags = (
                item.get("tcp_flags")
                if item.get("tcp_flags") is not None
                else item.get("flags")
                if item.get("flags") is not None
                else key or label
            )
            tcp_flags = normalized_flags(
                raw_flags
            )
            if not tcp_flags:
                continue
            key = tcp_flags
            label = tcp_flags
            protocol = "TCP"
        elif metric in {
            "top_source_prefixes",
            "top_destination_prefixes",
        }:
            candidate = str(
                item.get("prefix")
                or item.get("key")
                or item.get("label")
                or ""
            ).strip()
            try:
                prefix_label = str(ip_network(candidate, strict=False))
            except ValueError:
                continue
            key = prefix_label
            label = prefix_label
        elif metric in {
            "top_upload_destinations",
            "top_download_origins",
        }:
            if asn is not None and asn > 0:
                label_parts = ["AS%s" % asn]
                if asn_name:
                    label_parts.append(asn_name)
                label = " — ".join(label_parts)
                if country_code:
                    label = "%s (%s)" % (label, country_code)
                key = "AS%s" % asn
            else:
                key = "AS indisponível"
                label = key
        else:
            key = key or "-"
            label = label or key
        items.append(
            {
                "rank": len(items) + 1,
                "key": key,
                "label": label,
                "value": value,
                "bps": bps,
                "pps": pps,
                "percentage": percentage,
                "percent": percentage,
                "asn": asn,
                "asn_name": asn_name,
                "country_code": country_code,
                "country_name": country_name,
                "protocol": protocol or None,
                "port": port,
                "display_name": display_name or None,
                "tcp_flags": tcp_flags or None,
                "packets": packets,
                "metadata": safe_metadata,
            }
        )
    # Percentages must use the exact same unit and the exact set of values
    # returned to Grafana. Upstream totals/percentages may describe the
    # unbounded query or another metric, so they are deliberately ignored.
    total = sum(item["value"] for item in items)
    remaining_percentage = 100.0
    for index, item in enumerate(items):
        if not total:
            percentage = 0.0
        elif index == len(items) - 1:
            percentage = round(max(0.0, remaining_percentage), 2)
        else:
            percentage = min(
                remaining_percentage,
                round(item["value"] / total * 100, 2),
            )
            remaining_percentage = round(
                max(0.0, remaining_percentage - percentage),
                2,
            )
        item["percentage"] = percentage
        item["percent"] = percentage
    response_timestamp = (
        str(payload.get("timestamp") or "").strip()
        or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    result = {
        "kind": "ranking",
        "metric": metric,
        "unit": unit,
        "items": items,
        "total": total,
        "timestamp": response_timestamp,
        "calculation": request["calculation"],
        "meta": {
            "source": payload.get("source") or "raw",
            "timezone": "UTC",
            "correlation_id": correlation,
        },
    }
    if request["format"] == "table":
        fields = [
            ("rank", "number"),
            ("label", "string"),
            ("value", "number"),
            ("percent", "number"),
        ]
        return {
            "columns": [
                {"name": name, "type": field_type}
                for name, field_type in fields
            ],
            "rows": [
                [item[name] for name, _ in fields]
                for item in items
            ],
            "meta": {
                **result["meta"],
                "metric": metric,
                "unit": unit,
                "total": total,
                "timestamp": response_timestamp,
            },
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
