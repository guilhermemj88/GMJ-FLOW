from __future__ import annotations

"""Structured evidence for a detected peak.

Builds the "before / peak / after" comparison and the "what changed" answer
using the EXISTING minute aggregates (flow_dashboard_*_1m) — never flow_raw
for normal polling. This module has no business logic beyond assembling
evidence: threat interpretation belongs to the Threat Engine / Threat
Intelligence modules.

Queries are executed through an injectable ``executor`` (query, params) ->
rows so the module is fully unit-testable without ClickHouse.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

QueryExecutor = Callable[[str, dict[str, Any]], list[dict[str, Any]]]

SAMPLE_RATE_EXPR = "greatest(toFloat64(sample_rate), 1.0)"

DIRECTION_LABELS = {
    "sends": "upload",
    "transmits": "upload",
    "outbound": "upload",
    "receives": "download",
    "inbound": "download",
    "total": "total",
    "both": "total",
}

PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp", 0: "hopopt"}

# Common service/port mapping used only as a human-readable label (codec-like
# classification). It is NOT a verdict and NOT a whitelist.
SERVICE_BY_PORT = {
    53: "DNS", 80: "HTTP", 443: "HTTPS", 8443: "HTTPS-alt", 8080: "HTTP-alt",
    25: "SMTP", 465: "SMTPS", 587: "SMTP-submission", 22: "SSH",
    123: "NTP", 853: "DNS-over-TLS", 143: "IMAP", 993: "IMAPS",
    110: "POP3", 995: "POP3S", 21: "FTP", 20: "FTP-data",
    161: "SNMP", 162: "SNMP-trap", 67: "DHCP", 68: "DHCP",
    5060: "SIP", 3478: "STUN", 4433: "QUIC", 1935: "RTMP",
}


@dataclass
class PeakEvidenceConfig:
    baseline_window_seconds: int = 120
    peak_window_seconds: int = 60
    after_window_seconds: int = 120
    top_n: int = 5


def direction_label(direction: str) -> str:
    return DIRECTION_LABELS.get(str(direction or "total").strip().lower(), "total")


def _service_label(port: Any) -> str:
    try:
        number = int(port)
    except (TypeError, ValueError):
        return str(port or "?")
    return SERVICE_BY_PORT.get(number, f"port-{number}")


def _direction_columns(direction: str) -> dict[str, str]:
    """External vs local ASN/IP columns for the given direction.

    DOWNLOAD (receives): external = src side, local = dst side.
    UPLOAD (sends):      external = dst side, local = src side.
    """
    direction = str(direction or "total").strip().lower()
    if direction in {"receives", "inbound"}:
        return {
            "external_asn_table": "flow_dashboard_asn_src_1m",
            "external_asn_dim": "src_asn",
            "external_asn_name": "src_as_name",
            "external_ip_dim": "src_ip",
            "local_ip_dim": "dst_ip",
        }
    if direction in {"sends", "transmits", "outbound"}:
        return {
            "external_asn_table": "flow_dashboard_asn_dst_1m",
            "external_asn_dim": "dst_asn",
            "external_asn_name": "dst_as_name",
            "external_ip_dim": "dst_ip",
            "local_ip_dim": "src_ip",
        }
    return {
        "external_asn_table": "flow_dashboard_asn_dst_1m",
        "external_asn_dim": "dst_asn",
        "external_asn_name": "dst_as_name",
        "external_ip_dim": "dst_ip",
        "local_ip_dim": "src_ip",
    }


def _interface_predicate(direction: str, interface_id: int) -> str:
    """SQL predicate selecting the interface for the given direction."""
    direction = str(direction or "total").strip().lower()
    if direction in {"sends", "transmits", "outbound"}:
        return f"output_if = {int(interface_id)}"
    if direction in {"receives", "inbound"}:
        return f"input_if = {int(interface_id)}"
    return f"(input_if = {int(interface_id)} OR output_if = {int(interface_id)})"


def _window_bounds(peak_time: datetime, config: PeakEvidenceConfig) -> dict[str, tuple[datetime, datetime]]:
    peak = peak_time.astimezone(timezone.utc)
    peak_start = peak - timedelta(seconds=config.peak_window_seconds)
    peak_end = peak + timedelta(seconds=config.peak_window_seconds)
    return {
        "baseline_before": (peak_start - timedelta(seconds=config.baseline_window_seconds), peak_start),
        "peak": (peak_start, peak_end),
        "after": (peak_end, peak_end + timedelta(seconds=config.after_window_seconds)),
    }


def fetch_window_totals(
    executor: QueryExecutor,
    sensor: str,
    interface_id: int,
    direction: str,
    start: datetime,
    end: datetime,
) -> dict[str, float]:
    window_seconds = max(1.0, float((end - start).total_seconds()))
    predicate = _interface_predicate(direction, interface_id)
    rows = executor(
        f"""
        SELECT
            sum(bytes * {SAMPLE_RATE_EXPR}) AS bytes,
            sum(packets * {SAMPLE_RATE_EXPR}) AS packets,
            sum(flows) AS flows
        FROM flow_dashboard_series_1m
        WHERE minute >= {{start:DateTime}} AND minute < {{end:DateTime}}
          AND sensor = {{sensor:String}}
          AND {predicate}
        """,
        {"start": start, "end": end, "sensor": sensor},
    )
    row = rows[0] if rows else {}
    bytes_value = float(row.get("bytes") or 0)
    packets = float(row.get("packets") or 0)
    flows = float(row.get("flows") or 0)
    return {
        "bps": round(bytes_value * 8 / window_seconds, 3),
        "pps": round(packets / window_seconds, 3),
        "flows_s": round(flows / window_seconds, 3),
        "avg_packet_size": round(bytes_value / packets, 2) if packets > 0 else 0.0,
    }


def fetch_dimension(
    executor: QueryExecutor,
    table: str,
    dimension: str,
    extra_dimensions: str,
    sensor: str,
    interface_id: int,
    direction: str,
    start: datetime,
    end: datetime,
    top_n: int,
) -> list[dict[str, Any]]:
    predicate = _interface_predicate(direction, interface_id)
    extra_select = ", ".join(f"{column} AS {column}" for column in extra_dimensions.split(",")) if extra_dimensions else ""
    extra_group = ", ".join(extra_dimensions.split(",")) if extra_dimensions else ""
    rows = executor(
        f"""
        SELECT {dimension} AS dimension,
               {extra_select}
               sum(bytes * {SAMPLE_RATE_EXPR}) AS bytes,
               sum(packets * {SAMPLE_RATE_EXPR}) AS packets
        FROM {table}
        WHERE minute >= {{start:DateTime}} AND minute < {{end:DateTime}}
          AND sensor = {{sensor:String}}
          AND {predicate}
        GROUP BY {dimension}{(", " + extra_group) if extra_group else ""}
        ORDER BY bytes DESC
        LIMIT {int(top_n)}
        """,
        {"start": start, "end": end, "sensor": sensor},
    )
    return [dict(row) for row in rows]


def _proto_label(proto: Any) -> str:
    try:
        number = int(proto)
    except (TypeError, ValueError):
        return str(proto or "?")
    return PROTO_NAMES.get(number, str(number))


def _delta_pct(before: float, peak: float) -> float:
    if before <= 0:
        return 0.0
    return round((peak - before) / before * 100.0, 2)


def _changed_rows(
    executor: QueryExecutor,
    table: str,
    dimension: str,
    extra_dimensions: str,
    sensor: str,
    interface_id: int,
    direction: str,
    bounds: dict[str, tuple[datetime, datetime]],
    top_n: int,
    key_label: Callable[[Any], str] | None = None,
) -> list[dict[str, Any]]:
    before_rows = fetch_dimension(
        executor, table, dimension, extra_dimensions, sensor, interface_id, direction,
        bounds["baseline_before"][0], bounds["baseline_before"][1], top_n,
    )
    peak_rows = fetch_dimension(
        executor, table, dimension, extra_dimensions, sensor, interface_id, direction,
        bounds["peak"][0], bounds["peak"][1], top_n,
    )
    before_by_key = {str(row.get("dimension")): row for row in before_rows}
    peak_by_key = {str(row.get("dimension")): row for row in peak_rows}
    labels: dict[str, str] = {}
    rows_by_dim = {}
    for row in list(before_rows) + list(peak_rows):
        key = str(row.get("dimension"))
        before_bytes = float((before_by_key.get(key) or {}).get("bytes") or 0)
        peak_bytes = float((peak_by_key.get(key) or {}).get("bytes") or 0)
        if key_label is not None:
            labels[key] = key_label(row.get("dimension"))
        elif key not in labels:
            labels[key] = key
        rows_by_dim[key] = {
            "key": key,
            "label": labels.get(key, key),
            "before_bps": before_bytes * 8 / max(1.0, float((bounds["baseline_before"][1] - bounds["baseline_before"][0]).total_seconds())),
            "peak_bps": peak_bytes * 8 / max(1.0, float((bounds["peak"][1] - bounds["peak"][0]).total_seconds())),
            "before_bytes": before_bytes,
            "peak_bytes": peak_bytes,
        }
    changed = []
    for row in rows_by_dim.values():
        delta = _delta_pct(row["before_bps"], row["peak_bps"])
        if peak_bytes_for_row := row["peak_bytes"]:
            changed.append(
                {
                    "key": row["key"],
                    "label": row["label"],
                    "before_bps": round(row["before_bps"], 2),
                    "peak_bps": round(row["peak_bps"], 2),
                    "delta_bps_pct": delta,
                }
            )
    changed.sort(key=lambda item: item["peak_bps"], reverse=True)
    return changed[:top_n]


def fetch_concentration(
    executor: QueryExecutor,
    sensor: str,
    interface_id: int,
    direction: str,
    start: datetime,
    end: datetime,
    top_n: int,
) -> dict[str, Any]:
    predicate = _interface_predicate(direction, interface_id)
    rows = executor(
        f"""
        SELECT
            sum(bytes * {SAMPLE_RATE_EXPR}) AS total_bytes,
            uniqExact(src_ip) AS unique_src_count,
            uniqExact(dst_ip) AS unique_dst_count
        FROM flow_dashboard_dst_ip_1m
        WHERE minute >= {{start:DateTime}} AND minute < {{end:DateTime}}
          AND sensor = {{sensor:String}}
          AND {predicate}
        """,
        {"start": start, "end": end, "sensor": sensor},
    )
    row = rows[0] if rows else {}
    total_bytes = float(row.get("total_bytes") or 0)
    top = fetch_dimension(
        executor, "flow_dashboard_dst_ip_1m", "dst_ip", "", sensor, interface_id, direction, start, end, top_n,
    )
    top_bytes = sum(float(item.get("bytes") or 0) for item in top)
    return {
        "unique_src_count": int(row.get("unique_src_count") or 0),
        "unique_dst_count": int(row.get("unique_dst_count") or 0),
        "top_dst_ips": [{"dst_ip": str(item.get("dimension")), "bytes": float(item.get("bytes") or 0)} for item in top],
        "top_dst_share_pct": round(top_bytes / total_bytes * 100.0, 2) if total_bytes > 0 else 0.0,
    }


def build_peak_evidence(
    executor: QueryExecutor,
    sensor: str,
    interface_id: int,
    direction: str,
    peak_time: datetime,
    config: PeakEvidenceConfig | None = None,
) -> dict[str, Any]:
    config = config or PeakEvidenceConfig()
    bounds = _window_bounds(peak_time, config)
    totals = {
        name: fetch_window_totals(executor, sensor, interface_id, direction, start, end)
        for name, (start, end) in bounds.items()
    }
    before = totals["baseline_before"]
    peak = totals["peak"]
    after = totals["after"]
    label = direction_label(direction)
    dir_cols = _direction_columns(direction)

    protocols = _changed_rows(executor, "flow_dashboard_protocol_1m", "proto", "", sensor, interface_id, direction, bounds, config.top_n, key_label=_proto_label)
    dst_ports = _changed_rows(executor, "flow_dashboard_dst_port_1m", "dst_port", "proto", sensor, interface_id, direction, bounds, config.top_n)
    src_ports = _changed_rows(executor, "flow_dashboard_prefix_1m", "src_port", "", sensor, interface_id, direction, bounds, config.top_n)
    src_ips = _changed_rows(executor, "flow_dashboard_src_ip_1m", "src_ip", "", sensor, interface_id, direction, bounds, config.top_n)
    dst_ips = _changed_rows(executor, "flow_dashboard_dst_ip_1m", "dst_ip", "", sensor, interface_id, direction, bounds, config.top_n)
    external_asns = _changed_rows(executor, dir_cols["external_asn_table"], dir_cols["external_asn_dim"], dir_cols["external_asn_name"], sensor, interface_id, direction, bounds, config.top_n)

    # services are derived from dst_ports (no extra query)
    services = [{**row, "label": _service_label(row.get("key"))} for row in dst_ports]

    # external/local IPs follow direction (no extra query)
    if direction in {"receives", "inbound"}:
        external_ips, local_ips = src_ips, dst_ips
    else:
        external_ips, local_ips = dst_ips, src_ips

    return {
        "scope": {
            "sensor": sensor,
            "interface_id": interface_id,
            "direction": direction,
            "direction_label": label,
        },
        "peak_time": peak_time.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "windows": {
            "baseline_before": {"start": bounds["baseline_before"][0].isoformat().replace("+00:00", "Z"), "end": bounds["baseline_before"][1].isoformat().replace("+00:00", "Z"), **before},
            "peak": {"start": bounds["peak"][0].isoformat().replace("+00:00", "Z"), "end": bounds["peak"][1].isoformat().replace("+00:00", "Z"), **peak},
            "after": {"start": bounds["after"][0].isoformat().replace("+00:00", "Z"), "end": bounds["after"][1].isoformat().replace("+00:00", "Z"), **after},
        },
        "deltas": {
            "bps": before["bps"],
            "bps_peak": peak["bps"],
            "bps_delta_pct": _delta_pct(before["bps"], peak["bps"]),
            "pps": before["pps"],
            "pps_peak": peak["pps"],
            "pps_delta_pct": _delta_pct(before["pps"], peak["pps"]),
            "flows_s": before["flows_s"],
            "flows_s_peak": peak["flows_s"],
            "flows_s_delta_pct": _delta_pct(before["flows_s"], peak["flows_s"]),
            "avg_packet_size_before": before["avg_packet_size"],
            "avg_packet_size_peak": peak["avg_packet_size"],
        },
        "changed": {
            "protocols": protocols,
            "services": services,
            "dst_ports": dst_ports,
            "src_ports": src_ports,
            "dst_asns": external_asns,
            "external_asns": external_asns,
            "src_ips": src_ips,
            "dst_ips": dst_ips,
            "external_ips": external_ips,
            "local_ips": local_ips,
        },
        "concentration": fetch_concentration(executor, sensor, interface_id, direction, bounds["peak"][0], bounds["peak"][1], config.top_n),
    }
