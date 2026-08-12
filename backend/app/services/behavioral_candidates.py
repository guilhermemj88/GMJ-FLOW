from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

from app.services.clickhouse import query_clickhouse


CandidateQuery = Callable[[str, Optional[Dict[str, Any]]], List[Dict[str, Any]]]


def _threshold(thresholds: Any, attribute: str, env_name: str, default: int | float) -> int | float:
    if thresholds is not None and getattr(thresholds, attribute, None) is not None:
        return getattr(thresholds, attribute)
    raw = os.getenv(env_name, str(default))
    return float(raw) if isinstance(default, float) else int(raw)


def _run(
    sql: str,
    lookback_seconds: int,
    limit: int,
    parameters: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    values = dict(parameters or {})
    values.update({
        "lookback_seconds": max(60, min(int(lookback_seconds), 3600)),
        "candidate_limit": max(100, min(int(limit), 10000)),
    })
    return query_clickhouse(
        sql,
        values,
    )


def scan_candidates(lookback_seconds: int = 300, limit: int = 5000, thresholds: Any = None) -> list[dict[str, Any]]:
    return _run(
        """
        SELECT
            toString(src_ip) AS src_ip,
            uniqExact(dst_ip) AS unique_destinations,
            uniqExact(dst_port) AS unique_dst_ports,
            sum(packets) AS packets,
            sum(flows) AS flows,
            min(bucket) AS first_seen,
            max(bucket) AS last_seen,
            groupUniqArray(50)(dst_port) AS destination_ports_sample,
            groupUniqArray(50)(toString(dst_ip)) AS destinations_sample,
            groupUniqArray(20)(src_asn) AS source_asns_sample,
            any(sensor) AS sensor,
            any(toString(exporter_ip)) AS exporter,
            any(input_if) AS input_if,
            any(output_if) AS output_if
        FROM behavior_flow_10s
        WHERE bucket >= subtractSeconds(now(), {lookback_seconds:UInt32})
          AND proto = 6 AND bitAnd(tcp_flags, 2) != 0 AND bitAnd(tcp_flags, 16) = 0
        GROUP BY src_ip
        HAVING unique_destinations >= {scan_horizontal_hosts:UInt32}
            OR unique_dst_ports >= {scan_vertical_ports:UInt32}
            OR greatest(unique_destinations, unique_dst_ports) >= {scan_low_slow_unique:UInt32}
        ORDER BY greatest(unique_destinations, unique_dst_ports) DESC
        LIMIT {candidate_limit:UInt32}
        """,
        lookback_seconds,
        limit,
        {
            "scan_horizontal_hosts": int(_threshold(thresholds, "horizontal_hosts", "GMJFLOW_SCAN_HORIZONTAL_HOSTS", 20)),
            "scan_vertical_ports": int(_threshold(thresholds, "vertical_ports", "GMJFLOW_SCAN_VERTICAL_PORTS", 20)),
            "scan_low_slow_unique": int(_threshold(thresholds, "low_slow_unique", "GMJFLOW_SCAN_LOW_SLOW_UNIQUE", 10)),
        },
    )


def syn_flood_candidates(lookback_seconds: int = 300, limit: int = 5000, thresholds: Any = None) -> list[dict[str, Any]]:
    return _run(
        """
        SELECT
            toString(dst_ip) AS target_ip,
            sumIf(packets, bitAnd(tcp_flags, 2) != 0 AND bitAnd(tcp_flags, 16) = 0) AS syn_packets,
            sumIf(packets, bitAnd(tcp_flags, 16) != 0) AS ack_packets,
            sum(bytes) * 8 / {lookback_seconds:UInt32} AS bits_per_second,
            syn_packets / {lookback_seconds:UInt32} AS packets_per_second,
            uniqExact(src_ip) AS unique_sources,
            uniqExactIf(src_asn, src_asn > 0) AS unique_source_asns,
            groupUniqArray(100)(src_asn) AS source_asns_sample,
            min(bucket) AS first_seen,
            max(bucket) AS last_seen,
            uniqExact(toStartOfInterval(bucket, INTERVAL 10 SECOND)) AS temporal_windows,
            any(sensor) AS sensor,
            any(toString(exporter_ip)) AS exporter,
            any(input_if) AS input_if,
            any(output_if) AS output_if
        FROM behavior_flow_10s
        WHERE bucket >= subtractSeconds(now(), {lookback_seconds:UInt32}) AND proto = 6
        GROUP BY dst_ip
        HAVING packets_per_second >= {syn_min_pps:Float64}
           AND (syn_packets >= {syn_min_packets:UInt64}
                OR bits_per_second >= {syn_min_bps:Float64})
        ORDER BY syn_packets DESC
        LIMIT {candidate_limit:UInt32}
        """,
        lookback_seconds,
        limit,
        {
            "syn_min_packets": int(_threshold(thresholds, "syn_min_packets", "GMJFLOW_SYN_FLOOD_MIN_PACKETS", 3000)),
            "syn_min_pps": float(_threshold(thresholds, "syn_min_pps", "GMJFLOW_SYN_FLOOD_MIN_PPS", 100.0)),
            "syn_min_bps": float(_threshold(thresholds, "syn_min_bps", "GMJFLOW_SYN_FLOOD_MIN_BPS", 1_000_000.0)),
        },
    )


def udp_flood_candidates(lookback_seconds: int = 300, limit: int = 5000, thresholds: Any = None) -> list[dict[str, Any]]:
    return _run(
        """
        SELECT
            toString(dst_ip) AS target_ip,
            sum(packets) AS packets,
            sum(bytes) * 8 / {lookback_seconds:UInt32} AS bits_per_second,
            packets / {lookback_seconds:UInt32} AS packets_per_second,
            sum(flows) AS flows,
            uniqExact(src_ip) AS unique_sources,
            uniqExactIf(src_asn, src_asn > 0) AS unique_source_asns,
            uniqExact(src_port) AS unique_src_ports,
            uniqExact(dst_port) AS unique_dst_ports,
            topKWeighted(20)(src_port, packets) AS top_source_ports,
            topKWeighted(20)(dst_port, packets) AS top_destination_ports,
            topKWeighted(20)(toString(src_ip), packets) AS top_sources,
            groupUniqArray(100)(src_asn) AS source_asns_sample,
            min(bucket) AS first_seen,
            max(bucket) AS last_seen,
            uniqExact(toStartOfInterval(bucket, INTERVAL 10 SECOND)) AS temporal_windows,
            any(sensor) AS sensor,
            any(toString(exporter_ip)) AS exporter,
            any(input_if) AS input_if,
            any(output_if) AS output_if
        FROM behavior_flow_10s
        WHERE bucket >= subtractSeconds(now(), {lookback_seconds:UInt32}) AND proto = 17
        GROUP BY dst_ip
        HAVING packets_per_second >= {udp_min_pps:Float64}
           AND (packets >= {udp_min_packets:UInt64}
                OR bits_per_second >= {udp_min_bps:Float64})
        ORDER BY packets DESC
        LIMIT {candidate_limit:UInt32}
        """,
        lookback_seconds,
        limit,
        {
            "udp_min_packets": int(_threshold(thresholds, "udp_min_packets", "GMJFLOW_UDP_FLOOD_MIN_PACKETS", 3000)),
            "udp_min_pps": float(_threshold(thresholds, "udp_min_pps", "GMJFLOW_UDP_FLOOD_MIN_PPS", 100.0)),
            "udp_min_bps": float(_threshold(thresholds, "udp_min_bps", "GMJFLOW_UDP_FLOOD_MIN_BPS", 1_000_000.0)),
        },
    )


def carpet_candidates(lookback_seconds: int = 300, limit: int = 5000, thresholds: Any = None) -> list[dict[str, Any]]:
    return _run(
        """
        SELECT
            concat(toString(tupleElement(IPv6CIDRToRange(dst_ip, 120), 1)), '/120') AS target_prefix,
            sum(packets) AS packets,
            sum(bytes) * 8 / {lookback_seconds:UInt32} AS bits_per_second,
            packets / {lookback_seconds:UInt32} AS packets_per_second,
            max(packets) / {lookback_seconds:UInt32} AS max_observed_host_bucket_pps,
            uniqExact(dst_ip) AS unique_destinations,
            uniqExact(src_ip) AS unique_sources,
            uniqExactIf(src_asn, src_asn > 0) AS unique_source_asns,
            groupUniqArray(100)(src_asn) AS source_asns_sample,
            min(bucket) AS first_seen,
            max(bucket) AS last_seen,
            uniqExact(toStartOfInterval(bucket, INTERVAL 10 SECOND)) AS temporal_windows,
            any(sensor) AS sensor,
            any(toString(exporter_ip)) AS exporter,
            any(input_if) AS input_if,
            any(output_if) AS output_if
        FROM behavior_flow_10s
        WHERE bucket >= subtractSeconds(now(), {lookback_seconds:UInt32})
        GROUP BY target_prefix
        HAVING packets >= {carpet_min_packets:UInt64}
           AND unique_destinations >= {carpet_min_hosts:UInt32}
           AND (packets_per_second >= {carpet_min_pps:Float64}
                OR bits_per_second >= {carpet_min_bps:Float64})
           AND max_observed_host_bucket_pps < {carpet_max_host_pps:Float64}
        ORDER BY packets DESC
        LIMIT {candidate_limit:UInt32}
        """,
        lookback_seconds,
        limit,
        {
            "carpet_min_packets": int(_threshold(thresholds, "carpet_min_packets", "GMJFLOW_CARPET_MIN_PACKETS", 3000)),
            "carpet_min_hosts": int(_threshold(thresholds, "carpet_unique_hosts", "GMJFLOW_CARPET_MIN_HOSTS", 8)),
            "carpet_min_pps": float(_threshold(thresholds, "carpet_prefix_pps", "GMJFLOW_CARPET_MIN_PPS", 200.0)),
            "carpet_min_bps": float(_threshold(thresholds, "carpet_min_bps", "GMJFLOW_CARPET_MIN_BPS", 1_000_000.0)),
            "carpet_max_host_pps": float(_threshold(thresholds, "carpet_host_pps", "GMJFLOW_CARPET_MAX_HOST_PPS", 100.0)),
        },
    )


def fetch_candidate_summary_v2(
    lookback_seconds: int = 300,
    limit: int = 5000,
    thresholds: Any = None,
) -> dict[str, Any]:
    candidates = {
        "scan_candidates": scan_candidates(lookback_seconds, limit, thresholds),
        "syn_flood_candidates": syn_flood_candidates(lookback_seconds, limit, thresholds),
        "udp_flood_candidates": udp_flood_candidates(lookback_seconds, limit, thresholds),
        "carpet_candidates": carpet_candidates(lookback_seconds, limit, thresholds),
    }
    return {
        "engine": "clickhouse_candidate_v2",
        "lookback_seconds": lookback_seconds,
        "candidate_count": sum(len(items) for items in candidates.values()),
        "counts": {name: len(items) for name, items in candidates.items()},
        "candidates": candidates,
    }
