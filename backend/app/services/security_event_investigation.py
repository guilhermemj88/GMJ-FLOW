from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from app.services.threat_intelligence import clean_text


QueryExecutor = Callable[..., Any]
PROTOCOL_NUMBERS = {"icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50}
PROTOCOL_NAMES = {value: key.upper() for key, value in PROTOCOL_NUMBERS.items()}
SOURCE_SORTS = {"packets": "packets", "bytes": "bytes", "pps": "pps"}


def _default_query_executor(context: str, query: str, parameters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    # Detector-only/test nodes do not need the optional ClickHouse client until
    # an investigation endpoint actually requests an aggregate.
    from app.services.clickhouse import query_clickhouse_context

    return query_clickhouse_context(context, query, parameters)


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _parse_time(value: Any) -> datetime:
    text = clean_text(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def investigation_window(event: Mapping[str, Any], padding_seconds: int = 600) -> dict[str, Any]:
    padding = _bounded_int(padding_seconds, 600, 0, 3600)
    first_seen = _parse_time(event.get("first_seen"))
    last_seen = max(first_seen, _parse_time(event.get("last_seen")))
    requested_start = first_seen - timedelta(seconds=padding)
    requested_end = last_seen + timedelta(seconds=padding)
    maximum = _bounded_int(os.getenv("GMJFLOW_SECURITY_EVENT_QUERY_MAX_SECONDS"), 21600, 1200, 86400)
    truncated = (requested_end - requested_start).total_seconds() > maximum
    end = min(requested_end, requested_start + timedelta(seconds=maximum))
    total_seconds = max(1, int((end - requested_start).total_seconds()))
    bucket_seconds = 10 if total_seconds <= 1800 else 30 if total_seconds <= 7200 else 60
    return {
        "start": requested_start,
        "end": end,
        "event_start": first_seen,
        "event_end": last_seen,
        "padding_seconds": padding,
        "bucket_seconds": bucket_seconds,
        "truncated": truncated,
        "max_window_seconds": maximum,
    }


def _event_filters(event: Mapping[str, Any], params: dict[str, Any]) -> list[str]:
    filters: list[str] = []
    scoped = False
    sensor = clean_text(event.get("sensor"))
    if sensor:
        filters.append("sensor = {sensor:String}")
        params["sensor"] = sensor
        scoped = True
    protocol = clean_text(event.get("protocol")).lower()
    if protocol in PROTOCOL_NUMBERS:
        filters.append("proto = {protocol:UInt8}")
        params["protocol"] = PROTOCOL_NUMBERS[protocol]
    # IPv4 flows are persisted as IPv4-mapped IPv6 (e.g. ::ffff:1.2.3.4) in the
    # IPv6 columns of behavior_flow_10s. Plain `toString(ip) = '1.2.3.4'`
    # comparisons never match that representation, so equality uses the typed
    # toIPv6() cast (which maps IPv4 text to ::ffff:...) and prefix checks
    # normalize the mapped string back to dotted-quad before matching.
    source = clean_text(event.get("src_ip"))
    if source:
        filters.append("src_ip = toIPv6({source_ip:String})")
        params["source_ip"] = source
        scoped = True
    target_ip = clean_text(event.get("target_ip"))
    target_prefix = clean_text(event.get("target_prefix"))
    if target_ip:
        filters.append("dst_ip = toIPv6({target_ip:String})")
        params["target_ip"] = target_ip
        scoped = True
    elif target_prefix:
        filters.append(
            "isIPAddressInRange(replaceRegexpOne(toString(dst_ip), '^::ffff:', ''), {target_prefix:String})"
        )
        params["target_prefix"] = target_prefix
        scoped = True
    if not scoped:
        # Never let a legacy/incomplete event turn an investigation into a
        # time-only scan across every sensor.
        filters.append("0")
    return filters


def _query_parts(event: Mapping[str, Any], padding_seconds: int = 600) -> tuple[dict[str, Any], dict[str, Any], str]:
    window = investigation_window(event, padding_seconds)
    params = {"start": window["start"], "end": window["end"]}
    filters = _event_filters(event, params)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    return window, params, where


def _intel_for_source(event: Mapping[str, Any], source_ip: str) -> dict[str, Any]:
    threat_intel = event.get("threat_intel") if isinstance(event.get("threat_intel"), Mapping) else {}
    source_intel = threat_intel.get("source_intel") if isinstance(threat_intel.get("source_intel"), Mapping) else {}
    matches = source_intel.get("sources") if isinstance(source_intel.get("sources"), Mapping) else {}
    source_matches = [item for item in (matches.get(source_ip) or []) if isinstance(item, Mapping)][:10]
    priority = {"malicious": 4, "c2": 4, "suspicious": 3, "scanner": 2, "benign": 1}
    primary = max(source_matches, key=lambda item: priority.get(clean_text(item.get("classification")).lower(), 0), default={})
    tags: list[str] = []
    cves: list[str] = []
    for match in source_matches:
        for target, values in ((tags, match.get("tags") or []), (cves, match.get("cves") or [])):
            for value in values:
                text = clean_text(value)
                if text and text not in target:
                    target.append(text)
    return {
        "classification": clean_text(primary.get("classification")),
        "providers": sorted({clean_text(item.get("provider")) for item in source_matches if clean_text(item.get("provider"))}),
        "provider": clean_text(primary.get("provider")),
        "organization": clean_text(primary.get("organization")),
        "country": clean_text(primary.get("country") or primary.get("country_code")),
        "actor": clean_text(primary.get("actor")),
        "last_seen": clean_text(primary.get("last_seen")),
        "tags": tags[:20],
        "cves": cves[:20],
        "matches": source_matches,
    }


def _source_rows(event: Mapping[str, Any], rows: list[dict[str, Any]], sort_by: str, limit: int) -> list[dict[str, Any]]:
    total_packets = sum(max(0, int(row.get("packets") or 0)) for row in rows) or int(event.get("packets") or 0)
    result: list[dict[str, Any]] = []
    for row in rows[:limit]:
        source_ip = clean_text(row.get("source_ip") or row.get("src_ip"))
        packets = max(0, int(row.get("packets") or 0))
        intel = _intel_for_source(event, source_ip)
        result.append({
            "source_ip": source_ip,
            "source_asn": int(row.get("source_asn") or row.get("src_asn") or 0),
            "asn_organization": clean_text(row.get("asn_organization") or intel.get("organization")),
            "country": clean_text(row.get("country") or intel.get("country")),
            "packets": packets,
            "bytes": max(0, int(row.get("bytes") or 0)),
            "flows": max(0, int(row.get("flows") or 0)),
            "pps": max(0.0, float(row.get("pps") or 0)),
            "share": round((packets / total_packets * 100) if total_packets else 0, 4),
            "threat_intelligence_classification": intel.get("classification") or "",
            "threat_intelligence_provider": intel.get("provider") or "",
            "threat_intelligence_providers": intel.get("providers") or [],
            "threat_intelligence": intel,
        })
    key = SOURCE_SORTS.get(sort_by, "packets")
    return sorted(result, key=lambda item: (-float(item.get(key) or 0), item["source_ip"]))[:limit]


def event_sources(
    event: Mapping[str, Any],
    *,
    sort_by: str = "packets",
    limit: int = 100,
    query_executor: QueryExecutor = _default_query_executor,
) -> dict[str, Any]:
    bounded_limit = _bounded_int(limit, 100, 1, 100)
    normalized_sort = sort_by if sort_by in SOURCE_SORTS else "packets"
    window, params, where = _query_parts(event, 0)
    duration = max(1.0, (window["event_end"] - window["event_start"]).total_seconds())
    params.update({"duration": duration, "limit": bounded_limit})
    try:
        rows = query_executor(
            "security_event_sources",
            f"""
            SELECT toString(src_ip) AS source_ip, any(src_asn) AS source_asn,
                   sum(packets) AS packets, sum(bytes) AS bytes, sum(flows) AS flows,
                   sum(packets) / {{duration:Float64}} AS pps
            FROM behavior_flow_10s
            PREWHERE bucket >= {{start:DateTime}} AND bucket <= {{end:DateTime}}
            {where}
            GROUP BY src_ip
            ORDER BY {SOURCE_SORTS[normalized_sort]} DESC, source_ip
            LIMIT {{limit:UInt32}}
            """,
            params,
        )
        if not rows:
            # Do not present an empty live result as success when the window
            # may simply predate behavior_flow_10s retention; fall back to the
            # persisted event snapshot instead.
            raise RuntimeError("security_event_sources_no_rows")
        available = True
        source = "behavior_flow_10s"
    except Exception:
        investigation = event.get("investigation") if isinstance(event.get("investigation"), Mapping) else {}
        rows = [dict(item) for item in (investigation.get("top_sources") or []) if isinstance(item, Mapping)][:bounded_limit]
        available = bool(rows)
        source = "persisted_event_snapshot" if rows else "unavailable"
    return {
        "event_id": event.get("event_id") or event.get("id"),
        "items": _source_rows(event, rows, normalized_sort, bounded_limit),
        "total_returned": min(len(rows), bounded_limit),
        "limit": bounded_limit,
        "sort": normalized_sort,
        "source": source,
        "available": available,
        "distributed": int(event.get("unique_sources") or 0) > 1,
    }


def event_traffic(
    event: Mapping[str, Any],
    *,
    padding_seconds: int = 600,
    query_executor: QueryExecutor = _default_query_executor,
) -> dict[str, Any]:
    window, params, where = _query_parts(event, padding_seconds)
    params["bucket_seconds"] = window["bucket_seconds"]
    try:
        rows = query_executor(
            "security_event_traffic",
            f"""
            WITH toStartOfInterval(bucket, INTERVAL {{bucket_seconds:UInt32}} SECOND) AS time_bucket
            SELECT time_bucket AS timestamp,
                   sum(packets) / {{bucket_seconds:Float64}} AS pps,
                   sum(bytes) * 8 / {{bucket_seconds:Float64}} AS bps,
                   sum(flows) / {{bucket_seconds:Float64}} AS flows,
                   uniqExact(src_ip) AS source_count
            FROM behavior_flow_10s
            PREWHERE bucket >= {{start:DateTime}} AND bucket <= {{end:DateTime}}
            {where}
            GROUP BY time_bucket
            ORDER BY time_bucket
            LIMIT 8640
            """,
            params,
        )
        if not rows:
            raise RuntimeError("security_event_traffic_no_rows")
        points = [{
            "timestamp": clean_text(row.get("timestamp")),
            "pps": float(row.get("pps") or 0),
            "bps": float(row.get("bps") or 0),
            "flows": float(row.get("flows") or 0),
            "source_count": int(row.get("source_count") or 0),
        } for row in rows[:8640]]
        available = True
        source = "behavior_flow_10s"
    except Exception:
        points = [{
            "timestamp": clean_text(event.get("last_seen")),
            "pps": float(event.get("packets_per_second") or 0),
            "bps": float(event.get("bits_per_second") or 0),
            "flows": float(event.get("flows_per_second") or 0),
            "source_count": int(event.get("unique_sources") or 0),
        }]
        available = False
        source = "persisted_event_summary"
    return {
        "event_id": event.get("event_id") or event.get("id"),
        "items": points,
        "event_interval": {"start": clean_text(event.get("first_seen")), "end": clean_text(event.get("last_seen"))},
        "query_window": {
            "start": window["start"].isoformat().replace("+00:00", "Z"),
            "end": window["end"].isoformat().replace("+00:00", "Z"),
            "padding_seconds": window["padding_seconds"],
            "bucket_seconds": window["bucket_seconds"],
            "truncated": window["truncated"],
        },
        "source": source,
        "available": available,
    }


def _aggregate_query(
    query_executor: QueryExecutor,
    context: str,
    select: str,
    group_by: str,
    order_by: str,
    event: Mapping[str, Any],
    limit: int,
) -> list[dict[str, Any]]:
    _window, params, where = _query_parts(event, 0)
    params["limit"] = limit
    return query_executor(
        context,
        f"""
        SELECT {select}
        FROM behavior_flow_10s
        PREWHERE bucket >= {{start:DateTime}} AND bucket <= {{end:DateTime}}
        {where}
        GROUP BY {group_by}
        ORDER BY {order_by} DESC
        LIMIT {{limit:UInt32}}
        """,
        params,
    )


def event_evidence(
    event: Mapping[str, Any],
    *,
    sample_limit: int = 100,
    query_executor: QueryExecutor = _default_query_executor,
) -> dict[str, Any]:
    bounded_samples = _bounded_int(sample_limit, 100, 1, 100)
    investigation = event.get("investigation") if isinstance(event.get("investigation"), Mapping) else {}
    top_source_ports = list(investigation.get("top_source_ports") or [])[:20]
    top_destination_ports = list(investigation.get("top_destination_ports") or [])[:50]
    protocols = list(investigation.get("protocols") or [])[:20]
    conversations: list[dict[str, Any]] = []
    aggregate_available = False
    try:
        source_ports = _aggregate_query(
            query_executor, "security_event_source_ports",
            "src_port AS port, sum(packets) AS packets, sum(bytes) AS bytes, sum(flows) AS flows",
            "src_port", "packets", event, 20,
        )
        destination_ports = _aggregate_query(
            query_executor, "security_event_destination_ports",
            "dst_port AS port, sum(packets) AS packets, sum(bytes) AS bytes, sum(flows) AS flows",
            "dst_port", "packets", event, 50,
        )
        protocol_rows = _aggregate_query(
            query_executor, "security_event_protocols",
            "proto AS protocol_number, sum(packets) AS packets, sum(bytes) AS bytes, sum(flows) AS flows",
            "proto", "packets", event, 20,
        )
        conversation_rows = _aggregate_query(
            query_executor, "security_event_conversations",
            "toString(src_ip) AS source_ip, toString(dst_ip) AS destination_ip, src_port, dst_port, proto AS protocol_number, tcp_flags, sum(packets) AS packets, sum(bytes) AS bytes, sum(flows) AS flows, min(bucket) AS first_seen, max(bucket) AS last_seen",
            "src_ip, dst_ip, src_port, dst_port, proto, tcp_flags", "packets", event, bounded_samples,
        )
        if not source_ports and not destination_ports and not protocol_rows and not conversation_rows:
            raise RuntimeError("security_event_evidence_no_rows")
        top_source_ports = source_ports
        top_destination_ports = destination_ports
        protocols = [{**row, "protocol": PROTOCOL_NAMES.get(int(row.get("protocol_number") or 0), str(row.get("protocol_number") or 0))} for row in protocol_rows]
        conversations = conversation_rows
        for row in conversations:
            row["protocol"] = PROTOCOL_NAMES.get(int(row.get("protocol_number") or 0), str(row.get("protocol_number") or 0))
        aggregate_available = True
    except Exception:
        conversations = []
    evidence = event.get("evidence") if isinstance(event.get("evidence"), Mapping) else {}
    return {
        "event_id": event.get("event_id") or event.get("id"),
        "detector": event.get("detector"),
        "score": event.get("detector_score"),
        "score_components": event.get("score_components") or {},
        "evidence": evidence,
        "detection_evidence": investigation.get("detection_evidence") or {},
        "network_context": event.get("network_context") or {},
        "top_source_ports": top_source_ports[:20],
        "top_destination_ports": top_destination_ports[:50],
        "protocols": protocols[:20],
        "sample_conversations": conversations[:bounded_samples],
        "limits": {"source_ports": 20, "destination_ports": 50, "sample_conversations": bounded_samples},
        "source": "behavior_flow_10s" if aggregate_available else "persisted_event_snapshot",
        "aggregate_available": aggregate_available,
        "raw_flows_returned": False,
    }
