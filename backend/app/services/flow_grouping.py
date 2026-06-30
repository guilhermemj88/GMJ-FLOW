from __future__ import annotations

from ipaddress import ip_address
from typing import Any


DEFAULT_GROUPING_PARAMS = {
    "min_unique_sources": 2,
    "min_share_of_top_packets_percent": 50.0,
    "min_share_of_top_bytes_percent": 50.0,
    "prefer_same_dst_ip_port_protocol": True,
}


FLOW_FIELDS = (
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "proto_name",
    "bytes",
    "packets",
    "flow_count",
    "flow_time",
)


def analyze_flow_groups(
    incident: dict[str, Any],
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    grouping_params = dict(DEFAULT_GROUPING_PARAMS)
    if params:
        grouping_params.update(params)

    flows = _extract_flows(incident)
    if not flows:
        return _empty_result()

    total_bytes = sum(_to_int(flow.get("bytes")) for flow in flows)
    total_packets = sum(_to_int(flow.get("packets")) for flow in flows)
    groups: dict[tuple[str, int, str], dict[str, Any]] = {}

    for index, flow in enumerate(flows):
        dst_ip = str(flow.get("dst_ip") or "").strip()
        dst_port = _to_int(flow.get("dst_port"))
        protocol = _protocol_name(flow.get("protocol") or flow.get("proto_name"))
        if not dst_ip or dst_port <= 0 or not protocol:
            continue
        key = (dst_ip, dst_port, protocol)
        group = groups.setdefault(
            key,
            {
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "total_bytes": 0,
                "total_packets": 0,
                "total_flow_count": 0,
                "unique_src_ips": set(),
                "unique_src_ports": set(),
                "flows_count": 0,
                "_flow_indexes": [],
            },
        )
        group["total_bytes"] += _to_int(flow.get("bytes"))
        group["total_packets"] += _to_int(flow.get("packets"))
        group["total_flow_count"] += max(_to_int(flow.get("flow_count")), 1)
        group["flows_count"] += 1
        group["_flow_indexes"].append(index)
        if flow.get("src_ip"):
            group["unique_src_ips"].add(str(flow.get("src_ip")).strip())
        if flow.get("src_port") not in (None, ""):
            group["unique_src_ports"].add(_to_int(flow.get("src_port")))

    ranked_groups = []
    for group in groups.values():
        share_bytes = _percent(group["total_bytes"], total_bytes)
        share_packets = _percent(group["total_packets"], total_packets)
        ranked_groups.append(_public_group(group, share_bytes, share_packets))
    ranked_groups.sort(key=lambda item: (item["total_packets"], item["total_bytes"], item["flows_count"]), reverse=True)

    dominant_group = _select_dominant_group(ranked_groups, grouping_params)
    primary_flows: list[dict[str, Any]] = []
    noise_flows: list[dict[str, Any]] = []
    if dominant_group:
        dominant_key = (dominant_group["dst_ip"], dominant_group["dst_port"], dominant_group["protocol"])
        for flow in flows:
            key = (
                str(flow.get("dst_ip") or "").strip(),
                _to_int(flow.get("dst_port")),
                _protocol_name(flow.get("protocol") or flow.get("proto_name")),
            )
            if key == dominant_key:
                primary_flows.append(flow)
            else:
                noise = dict(flow)
                noise["classification"] = "not_part_of_primary_vector"
                noise["reason"] = "tail_flows"
                noise_flows.append(noise)
        dominant_group["attack_vector"] = _attack_vector_for_group(incident, dominant_group)

    return {
        "dominant_attack_group": dominant_group,
        "groups": ranked_groups,
        "primary_flows": primary_flows,
        "noise_flows": noise_flows,
        "tail_flows": noise_flows,
        "ignored_noise_flows_count": len(noise_flows),
        "total_flows_considered": len(flows),
        "params": grouping_params,
    }


def incident_from_dominant_group(incident: dict[str, Any], grouping: dict[str, Any]) -> dict[str, Any]:
    dominant = grouping.get("dominant_attack_group") if isinstance(grouping, dict) else None
    if not isinstance(dominant, dict):
        enriched = dict(incident)
        enriched["flow_grouping"] = grouping
        return enriched

    enriched = {
        key: value
        for key, value in incident.items()
        if key not in {"related_flows", "top_conversations", "flows"}
    }
    enriched.update(
        {
            "dst_ip": dominant.get("dst_ip") or incident.get("dst_ip"),
            "dst_port": dominant.get("dst_port") or incident.get("dst_port"),
            "protocol": dominant.get("protocol") or incident.get("protocol"),
            "dst_prefix": incident.get("dst_prefix") or _ipv4_24(dominant.get("dst_ip")),
            "same_dst_24": incident.get("same_dst_24", True),
            "dominant_attack_group": dominant,
            "flow_grouping": _compact_grouping(grouping),
            "ignored_noise_flows_count": grouping.get("ignored_noise_flows_count", 0),
            "dominant_group_top_flows": grouping.get("primary_flows", [])[:5],
            "related_flows": grouping.get("primary_flows", [])[:10],
            "top_conversations": grouping.get("primary_flows", [])[:10],
        }
    )
    unique_src_ips = dominant.get("unique_src_ips") or []
    if unique_src_ips:
        enriched["src_ips"] = unique_src_ips
        enriched.setdefault("src_ip", unique_src_ips[0])
    return enriched


def dominant_group_summary(grouping: dict[str, Any], direction: str | None = None) -> str:
    dominant = grouping.get("dominant_attack_group") if isinstance(grouping, dict) else None
    if not isinstance(dominant, dict):
        return "Nenhum grupo dominante claro foi identificado; manter revisao manual."
    protocol = str(dominant.get("protocol") or "").upper()
    dst_ip = dominant.get("dst_ip") or "-"
    dst_port = dominant.get("dst_port") or "-"
    src_count = len(dominant.get("unique_src_ips") or [])
    noise_count = int(grouping.get("ignored_noise_flows_count") or 0)
    direction_text = f" {direction}" if direction else ""
    return (
        f"Foi identificado grupo dominante de {protocol}{direction_text} para {dst_ip}:{dst_port}, "
        f"com {src_count} origens distintas. {noise_count} flows relacionados foram tratados como cauda/ruido."
    )


def _extract_flows(incident: dict[str, Any]) -> list[dict[str, Any]]:
    flows: list[dict[str, Any]] = []
    for field in ("top_conversations", "related_flows"):
        values = incident.get(field)
        if isinstance(values, list):
            for item in values:
                if isinstance(item, dict):
                    normalized = _normalize_flow(item)
                    if normalized:
                        flows.append(normalized)
    seen = set()
    unique_flows = []
    for flow in flows:
        identity = tuple(flow.get(field) for field in FLOW_FIELDS)
        if identity in seen:
            continue
        seen.add(identity)
        unique_flows.append(flow)
    return unique_flows


def _normalize_flow(flow: dict[str, Any]) -> dict[str, Any]:
    protocol = _protocol_name(flow.get("protocol") or flow.get("proto_name") or flow.get("proto"))
    dst_port = _to_int(flow.get("dst_port"))
    dst_ip = str(flow.get("dst_ip") or "").strip()
    if not dst_ip or dst_port <= 0 or not protocol:
        return {}
    return {
        "src_ip": str(flow.get("src_ip") or "").strip(),
        "src_port": _to_int(flow.get("src_port")),
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "proto_name": protocol.upper(),
        "bytes": _to_int(flow.get("bytes")),
        "packets": _to_int(flow.get("packets")),
        "flow_count": max(_to_int(flow.get("flow_count")), 1),
        "flow_time": flow.get("flow_time") or "",
    }


def _public_group(group: dict[str, Any], share_bytes: float, share_packets: float) -> dict[str, Any]:
    return {
        "dst_ip": group["dst_ip"],
        "dst_port": group["dst_port"],
        "protocol": group["protocol"],
        "total_bytes": group["total_bytes"],
        "total_packets": group["total_packets"],
        "total_flow_count": group["total_flow_count"],
        "unique_src_ips": sorted(group["unique_src_ips"]),
        "unique_src_ports": sorted(port for port in group["unique_src_ports"] if port > 0),
        "flows_count": group["flows_count"],
        "share_bytes_percent": round(share_bytes, 2),
        "share_packets_percent": round(share_packets, 2),
    }


def _select_dominant_group(groups: list[dict[str, Any]], params: dict[str, Any]) -> dict[str, Any] | None:
    if not groups:
        return None
    top = groups[0]
    runner_up = groups[1] if len(groups) > 1 else None
    enough_sources = len(top.get("unique_src_ips") or []) >= int(params["min_unique_sources"])
    enough_share = (
        float(top.get("share_packets_percent") or 0) >= float(params["min_share_of_top_packets_percent"])
        or float(top.get("share_bytes_percent") or 0) >= float(params["min_share_of_top_bytes_percent"])
    )
    much_larger_than_next = runner_up is None or (
        int(top.get("total_packets") or 0) >= max(int(runner_up.get("total_packets") or 0) * 3, 1)
        or int(top.get("total_bytes") or 0) >= max(int(runner_up.get("total_bytes") or 0) * 3, 1)
    )
    if enough_share and (enough_sources or much_larger_than_next):
        return dict(top)
    return None


def _attack_vector_for_group(incident: dict[str, Any], group: dict[str, Any]) -> str:
    direction = str(incident.get("direction") or "").lower()
    protocol = str(group.get("protocol") or "").lower()
    if direction in {"outbound", "sends"} and protocol == "udp":
        return "udp_flood_outbound_to_single_destination_port"
    if protocol == "tcp":
        return "tcp_flow_to_single_destination_port"
    return f"{protocol or 'unknown'}_to_single_destination_port"


def _compact_grouping(grouping: dict[str, Any]) -> dict[str, Any]:
    return {
        "dominant_attack_group": grouping.get("dominant_attack_group"),
        "ignored_noise_flows_count": grouping.get("ignored_noise_flows_count", 0),
        "total_flows_considered": grouping.get("total_flows_considered", 0),
    }


def _protocol_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"17", "udp"}:
        return "udp"
    if text in {"6", "tcp"}:
        return "tcp"
    if text in {"1", "icmp"}:
        return "icmp"
    return text


def _percent(value: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return (float(value) / float(total)) * 100.0


def _ipv4_24(value: Any) -> str:
    try:
        parsed = ip_address(str(value or "").strip())
    except ValueError:
        return ""
    if parsed.version != 4:
        return ""
    parts = str(parsed).split(".")
    return ".".join(parts[:3] + ["0"]) + "/24"


def _to_int(value: Any) -> int:
    try:
        if value is None or value == "":
            return 0
        return int(value)
    except (TypeError, ValueError):
        return 0


def _empty_result() -> dict[str, Any]:
    return {
        "dominant_attack_group": None,
        "groups": [],
        "primary_flows": [],
        "noise_flows": [],
        "tail_flows": [],
        "ignored_noise_flows_count": 0,
        "total_flows_considered": 0,
        "params": dict(DEFAULT_GROUPING_PARAMS),
    }
