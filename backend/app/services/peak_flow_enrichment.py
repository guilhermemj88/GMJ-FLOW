from __future__ import annotations

from datetime import datetime
from typing import Any


MIN_EVIDENCE_SHARE_PERCENT = 20.0
MIN_EVIDENCE_PACKETS = 1000
MIN_EVIDENCE_BYTES = 1_000_000


def enrich_peak_flows(
    flows: list[dict[str, Any]],
    metric: str,
    window_seconds: int,
    direction: str = "sends",
) -> dict[str, Any]:
    normalized = [_normalize_flow(flow, window_seconds) for flow in flows]
    normalized = [flow for flow in normalized if flow.get("dst_ip") and flow.get("dst_port") and flow.get("protocol")]
    sort_field = "bits_s" if metric == "bits_s" else "packets_s"
    normalized.sort(key=lambda item: (float(item.get(sort_field) or 0), int(item.get("packets") or 0), int(item.get("bytes") or 0)), reverse=True)
    total_packets = sum(int(flow.get("packets") or 0) for flow in normalized)
    total_bytes = sum(int(flow.get("bytes") or 0) for flow in normalized)
    total_bits = total_bytes * 8

    groups: dict[tuple[str, int, str], dict[str, Any]] = {}
    for flow in normalized:
        key = (flow["dst_ip"], int(flow["dst_port"]), flow["protocol"])
        group = groups.setdefault(
            key,
            {
                "dst_ip": flow["dst_ip"],
                "dst_port": int(flow["dst_port"]),
                "protocol": flow["protocol"],
                "total_packets": 0,
                "total_bytes": 0,
                "raw_packets": 0,
                "raw_bytes": 0,
                "total_bits": 0,
                "max_packets_s": 0.0,
                "max_bits_s": 0.0,
                "effective_sample_rate": 0.0,
                "sample_rate_source": "",
                "unique_src_ips": set(),
                "flows": [],
            },
        )
        group["total_packets"] += int(flow.get("packets") or 0)
        group["total_bytes"] += int(flow.get("bytes") or 0)
        group["raw_packets"] += int(flow.get("raw_packets") or 0)
        group["raw_bytes"] += int(flow.get("raw_bytes") or 0)
        group["total_bits"] += int(flow.get("bytes") or 0) * 8
        group["max_packets_s"] = max(float(group["max_packets_s"]), float(flow.get("packets_s") or 0))
        group["max_bits_s"] = max(float(group["max_bits_s"]), float(flow.get("bits_s") or 0))
        group["effective_sample_rate"] = max(float(group["effective_sample_rate"]), float(flow.get("effective_sample_rate") or 0))
        group["sample_rate_source"] = group["sample_rate_source"] or str(flow.get("sample_rate_source") or "")
        if flow.get("src_ip"):
            group["unique_src_ips"].add(flow["src_ip"])
        group["flows"].append(flow)

    public_groups = []
    for group in groups.values():
        item = {
            **group,
            "unique_src_ips": sorted(group["unique_src_ips"]),
            "unique_src_count": len(group["unique_src_ips"]),
            "share_packets": _percent(group["total_packets"], total_packets),
            "share_bits": _percent(group["total_bits"], total_bits),
            "avg_packets_s": _rate(group["total_packets"], window_seconds),
            "avg_bits_s": _rate(group["total_bits"], window_seconds),
        }
        public_groups.append(item)
    public_groups.sort(
        key=lambda item: (
            float(item.get("share_bits") if metric == "bits_s" else item.get("share_packets") or 0),
            float(item.get("max_bits_s") if metric == "bits_s" else item.get("max_packets_s") or 0),
        ),
        reverse=True,
    )
    dominant = public_groups[0] if public_groups else None
    evidence_status = "complete" if _has_sufficient_evidence(dominant, metric) else "insufficient"
    classification = classify_dominant_group(dominant, metric, evidence_status, direction)
    return {
        "flows": normalized,
        "groups": [_public_group(group) for group in public_groups],
        "top_conversations": normalized[:20],
        "top_sources": _top_endpoints(normalized, "src_ip", total_packets, total_bytes),
        "top_destinations": _top_endpoints(normalized, "dst_ip", total_packets, total_bytes),
        "dominant_group": _public_group(dominant) if dominant else None,
        "classification": classification,
        "evidence_status": evidence_status,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "sort_field": sort_field,
    }


def classify_dominant_group(
    dominant_group: dict[str, Any] | None,
    metric: str,
    evidence_status: str,
    direction: str = "sends",
) -> str:
    if evidence_status != "complete" or not dominant_group:
        return "insufficient_flow_evidence"
    protocol = str(dominant_group.get("protocol") or "").lower()
    dst_port = int(dominant_group.get("dst_port") or 0)
    unique_src_count = int(dominant_group.get("unique_src_count") or 0)
    if protocol == "udp" and dst_port == 53 and direction in {"sends", "transmits", "outbound"}:
        return "dns_udp_abuse_outbound"
    if protocol == "udp" and unique_src_count >= 2 and direction in {"sends", "transmits", "outbound"}:
        return "udp_flood_outbound_to_single_destination_port"
    if protocol == "tcp":
        return "tcp_syn_flood_to_single_destination_port"
    if protocol == "icmp":
        return "icmp_flood"
    if protocol == "udp":
        return "aggregate_udp_without_dominant_vector"
    return "insufficient_flow_evidence"


def _has_sufficient_evidence(dominant_group: dict[str, Any] | None, metric: str) -> bool:
    if not dominant_group:
        return False
    share = float(dominant_group.get("share_bits") if metric == "bits_s" else dominant_group.get("share_packets") or 0)
    volume_ok = int(dominant_group.get("total_packets") or 0) >= MIN_EVIDENCE_PACKETS or int(dominant_group.get("total_bytes") or 0) >= MIN_EVIDENCE_BYTES
    return share >= MIN_EVIDENCE_SHARE_PERCENT and volume_ok


def _normalize_flow(flow: dict[str, Any], window_seconds: int) -> dict[str, Any]:
    seconds = max(int(window_seconds or 1), 1)
    packets = int(float(flow.get("packets") or 0))
    bytes_value = int(float(flow.get("bytes") or 0))
    protocol = _protocol_name(flow.get("protocol") or flow.get("proto_name") or flow.get("proto"))
    return {
        "flow_time": _string_time(flow.get("flow_time") or flow.get("first_seen") or flow.get("last_seen")),
        "src_ip": _normalize_ip_text(flow.get("src_ip")),
        "src_port": _to_int(flow.get("src_port")),
        "dst_ip": _normalize_ip_text(flow.get("dst_ip")),
        "dst_port": _to_int(flow.get("dst_port")),
        "protocol": protocol,
        "proto_name": protocol.upper(),
        "bytes": bytes_value,
        "packets": packets,
        "raw_bytes": int(float(flow.get("raw_bytes") or bytes_value)),
        "raw_packets": int(float(flow.get("raw_packets") or packets)),
        "db_sample_rate": float(flow.get("db_sample_rate") or 0),
        "effective_sample_rate": float(flow.get("effective_sample_rate") or 0),
        "sample_rate_source": str(flow.get("sample_rate_source") or "").strip(),
        "bits": bytes_value * 8,
        "packets_s": float(flow.get("packets_s") or packets / seconds),
        "bits_s": float(flow.get("bits_s") or (bytes_value * 8) / seconds),
        "flow_count": max(_to_int(flow.get("flow_count")), 1),
        "input_if": _to_int(flow.get("input_if")),
        "output_if": _to_int(flow.get("output_if")),
    }


def _public_group(group: dict[str, Any] | None) -> dict[str, Any] | None:
    if not group:
        return None
    return {
        "dst_ip": group["dst_ip"],
        "dst_port": int(group["dst_port"]),
        "protocol": group["protocol"],
        "total_packets": int(group["total_packets"]),
        "total_bytes": int(group["total_bytes"]),
        "raw_packets": int(group.get("raw_packets") or 0),
        "raw_bytes": int(group.get("raw_bytes") or 0),
        "total_bits": int(group["total_bits"]),
        "max_packets_s": round(float(group["max_packets_s"]), 2),
        "max_bits_s": round(float(group["max_bits_s"]), 2),
        "avg_packets_s": round(float(group.get("avg_packets_s") or 0), 2),
        "avg_bits_s": round(float(group.get("avg_bits_s") or 0), 2),
        "effective_sample_rate": round(float(group.get("effective_sample_rate") or 0), 2),
        "sample_rate_source": group.get("sample_rate_source") or "",
        "unique_src_ips": list(group["unique_src_ips"]),
        "unique_src_count": int(group["unique_src_count"]),
        "share_packets": round(float(group["share_packets"]), 2),
        "share_bits": round(float(group["share_bits"]), 2),
        "top_flows": group.get("flows", [])[:5],
    }


def _top_endpoints(
    flows: list[dict[str, Any]],
    field: str,
    total_packets: int,
    total_bytes: int,
) -> list[dict[str, Any]]:
    endpoints: dict[str, dict[str, Any]] = {}
    for flow in flows:
        key = str(flow.get(field) or "").strip()
        if not key:
            continue
        item = endpoints.setdefault(key, {field: key, "packets": 0, "bytes": 0})
        item["packets"] += int(flow.get("packets") or 0)
        item["bytes"] += int(flow.get("bytes") or 0)
    rows = []
    for item in endpoints.values():
        packets = int(item["packets"])
        bytes_value = int(item["bytes"])
        rows.append(
            {
                **item,
                "share_packets": round(_percent(packets, total_packets), 2),
                "share_bytes": round(_percent(bytes_value, total_bytes), 2),
                "share": round(_percent(bytes_value, total_bytes), 2),
            }
        )
    rows.sort(key=lambda item: (int(item["bytes"]), int(item["packets"])), reverse=True)
    return rows[:20]


def _percent(value: int | float, total: int | float) -> float:
    return (float(value) / float(total) * 100.0) if total else 0.0


def _rate(value: int | float, seconds: int | float) -> float:
    return float(value) / max(float(seconds or 1), 1.0)


def _normalize_ip_text(value: Any) -> str:
    text = str(value or "").strip()
    if text.lower().startswith("::ffff:"):
        return text.split(":")[-1]
    return text


def _protocol_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"17", "udp"}:
        return "udp"
    if text in {"6", "tcp"}:
        return "tcp"
    if text in {"1", "icmp"}:
        return "icmp"
    return text


def _to_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _string_time(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value or "")
