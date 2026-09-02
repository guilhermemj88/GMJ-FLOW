from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sqlite3
import statistics
import threading
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from typing import Any, Callable, Iterable, Mapping, Sequence

from app.services.threat_intelligence import (
    THREAT_INTEL_MANAGER,
    ThreatIntelManager,
    clean_text,
    json_dump,
    safe_json,
    sqlite_connection,
    utc_now,
    utc_now_iso,
)
from app.services.behavior_flow_table import behavior_flow_table
from app.services.network_context import NetworkContextEngine
from app.services.security_events import (
    canonical_event_key,
    cleanup_security_events,
    ensure_security_event_schema,
    migrate_legacy_security_events,
    security_event_row,
    update_security_event_mitigation_status,
    upsert_security_event,
)
from app.services.campaign_context_evaluator import evaluate_campaign_context
from app.services.campaign_score import calculate_campaign_risk_score
from app.services.behavior_baseline import (
    BOOTSTRAP,
    DEFAULT_BOOTSTRAP_MIN_CLEAN_WINDOWS,
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
    DEFAULT_MAD_ABSOLUTE_FLOOR_PPS,
    DEFAULT_MAD_RELATIVE_FLOOR_RATIO,
    DEFAULT_MIN_QUARANTINE_SAMPLES,
    DEFAULT_MIN_ROBUST_SAMPLES,
    DEFAULT_QUARANTINE_MINUTES,
    DEFAULT_SAFE_QUARANTINE_Z,
    ELIGIBLE,
    QUARANTINED,
    REJECTED,
    TRUSTED,
    effective_mad,
    robust_z_score,
    safe_learning_decision,
    safe_reason_bucket,
)
from app.services.config_effective import behavior_safe_learning_enabled
from app.services.network_sweep_policy import _is_protected_subject
from app.services.network_assets import (
    CGNAT_POOL,
    CDN_CACHE,
    DNS_RESOLVER,
    DOWNSTREAM_ISP,
    NetworkAssetResolver,
    ensure_network_assets_schema,
    resolve_network_context as resolve_network_asset_context,
    shannon_entropy,
    target_role_distribution,
)
from app.services.threat_contracts import (
    FLOOD_ATTACK_TYPES,
    SCAN_ATTACK_TYPES,
    attack_family,
    detector_verdict,
)


LOGGER = logging.getLogger("gmj-flow")
WINDOWS = (10, 30, 60, 300)
PREFIX_LENGTHS_V4 = (32, 29, 28, 27, 26, 25, 24, 23, 22)

NORMAL = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
PORT_SCAN_VERTICAL = "PORT_SCAN_VERTICAL"
PORT_SCAN_HORIZONTAL = "PORT_SCAN_HORIZONTAL"
NETWORK_SWEEP = "NETWORK_SWEEP"
LOW_SLOW_SCAN = "LOW_SLOW_SCAN"
SSH_BRUTE_FORCE = "SSH_BRUTE_FORCE"
SYN_FLOOD = "SYN_FLOOD"
DISTRIBUTED_SYN_FLOOD = "DISTRIBUTED_SYN_FLOOD"
SPOOFED_SYN_FLOOD = "SPOOFED_SYN_FLOOD"
UDP_FLOOD = "UDP_FLOOD"
DISTRIBUTED_UDP_FLOOD = "DISTRIBUTED_UDP_FLOOD"
UDP_REFLECTION_SUSPECTED = "UDP_REFLECTION_SUSPECTED"
COORDINATED_DDOS = "COORDINATED_DDOS"
SCANNING_CAMPAIGN = "SCANNING_CAMPAIGN"
COORDINATED_SCANNING = "COORDINATED_SCANNING"
BOTNET_LIKELY = "BOTNET_LIKELY"
CARPET_BOMBING = "CARPET_BOMBING"
MULTI_VECTOR_DDOS = "MULTI_VECTOR_DDOS"
UNKNOWN_ANOMALY = "UNKNOWN_ANOMALY"
COMPROMISED_CUSTOMER = "COMPROMISED_CUSTOMER"

# Traffic classifications used by the carpet-bombing detector when the observed
# distribution is compatible with legitimate (usually web-return) traffic.
EXPECTED_DISTRIBUTED_TRAFFIC = "EXPECTED_DISTRIBUTED_TRAFFIC"
SUSPICIOUS_DISTRIBUTED_TRAFFIC = "SUSPICIOUS_DISTRIBUTED_TRAFFIC"

CLASSIFICATIONS = {
    NORMAL,
    SUSPICIOUS,
    PORT_SCAN_VERTICAL,
    PORT_SCAN_HORIZONTAL,
    NETWORK_SWEEP,
    LOW_SLOW_SCAN,
    SSH_BRUTE_FORCE,
    SYN_FLOOD,
    DISTRIBUTED_SYN_FLOOD,
    SPOOFED_SYN_FLOOD,
    UDP_FLOOD,
    DISTRIBUTED_UDP_FLOOD,
    UDP_REFLECTION_SUSPECTED,
    COORDINATED_DDOS,
    SCANNING_CAMPAIGN,
    COORDINATED_SCANNING,
    BOTNET_LIKELY,
    CARPET_BOMBING,
    MULTI_VECTOR_DDOS,
    UNKNOWN_ANOMALY,
}


def behavioral_clickhouse_schema_statements() -> tuple[str, ...]:
    return (
        """
        CREATE TABLE IF NOT EXISTS behavior_flow_10s (
            bucket DateTime('UTC'), sensor LowCardinality(String), exporter_ip IPv6,
            src_ip IPv6, dst_ip IPv6, src_port UInt16, dst_port UInt16,
            proto UInt8, tcp_flags UInt16, input_if UInt32, output_if UInt32,
            src_asn UInt32, dst_asn UInt32, bytes UInt64, packets UInt64, flows UInt64
        ) ENGINE = SummingMergeTree((bytes, packets, flows))
        PARTITION BY toYYYYMMDD(bucket)
        ORDER BY (bucket, sensor, exporter_ip, src_ip, dst_ip, proto, dst_port,
                  src_port, tcp_flags, input_if, output_if, src_asn, dst_asn)
        TTL bucket + INTERVAL 24 HOUR DELETE
        """,
        """
        CREATE MATERIALIZED VIEW IF NOT EXISTS mv_flow_raw_to_behavior_10s TO behavior_flow_10s AS
        SELECT toStartOfInterval(flow_time, INTERVAL 10 SECOND) AS bucket,
               sensor, exporter_ip, src_ip, dst_ip, src_port, dst_port, proto, tcp_flags,
               input_if, output_if, src_asn, dst_asn,
               sum(bytes * greatest(sample_rate, 1)) AS bytes,
               sum(packets * greatest(sample_rate, 1)) AS packets,
               sum(flow_count) AS flows
        FROM flow_raw
        GROUP BY bucket, sensor, exporter_ip, src_ip, dst_ip, src_port, dst_port,
                 proto, tcp_flags, input_if, output_if, src_asn, dst_asn
        """,
        """
        CREATE TABLE IF NOT EXISTS behavior_flow_10s_v2 (
            bucket DateTime('UTC'), sensor LowCardinality(String), exporter_ip IPv6,
            src_ip IPv6, dst_ip IPv6, src_port UInt16, dst_port UInt16,
            proto UInt8, tcp_flags UInt16, input_if UInt32, output_if UInt32,
            src_asn UInt32, dst_asn UInt32, bytes UInt64, packets UInt64, flows UInt64
        ) ENGINE = SummingMergeTree((bytes, packets, flows))
        PARTITION BY toYYYYMMDD(bucket)
        ORDER BY (bucket, sensor, exporter_ip, src_ip, dst_ip, proto, dst_port,
                  src_port, tcp_flags, input_if, output_if, src_asn, dst_asn)
        TTL bucket + INTERVAL 24 HOUR DELETE
        """,
        """
        CREATE MATERIALIZED VIEW IF NOT EXISTS mv_flow_raw_to_behavior_10s_v2 TO behavior_flow_10s_v2 AS
        SELECT toStartOfInterval(flow_time, INTERVAL 10 SECOND) AS bucket,
               sensor, exporter_ip, src_ip, dst_ip, src_port, dst_port, proto, tcp_flags,
               input_if, output_if, src_asn, dst_asn,
               sum(bytes * greatest(sample_rate, 1)) AS bytes,
               sum(packets * greatest(sample_rate, 1)) AS packets,
               sum(flow_count) AS flows
        FROM flow_raw
        WHERE time_classification = 'VALID_TIME'
        GROUP BY bucket, sensor, exporter_ip, src_ip, dst_ip, src_port, dst_port,
                 proto, tcp_flags, input_if, output_if, src_asn, dst_asn
        """,
    )


def parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = clean_text(value)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            parsed = utc_now()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def clamp(value: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    return max(minimum, min(maximum, value))


def ratio(numerator: float, denominator: float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def safe_int(value: Any) -> int:
    try:
        return max(0, int(float(value or 0)))
    except (TypeError, ValueError):
        return 0


def normalized_ip(value: Any) -> str:
    try:
        parsed = ip_address(clean_text(value))
    except ValueError:
        return ""
    if parsed.version == 6 and parsed.ipv4_mapped:
        return str(parsed.ipv4_mapped)
    return str(parsed)


@dataclass(frozen=True)
class FlowObservation:
    observed_at: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    tcp_flags: int
    packets: int
    bytes: int
    flow_count: int = 1
    src_asn: int = 0
    dst_asn: int = 0
    sensor: str = ""
    exporter_ip: str = ""
    input_if: int = 0
    output_if: int = 0

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FlowObservation | None":
        src = normalized_ip(value.get("src_ip"))
        dst = normalized_ip(value.get("dst_ip"))
        if not src or not dst:
            return None
        protocol_value = clean_text(value.get("protocol") or value.get("proto")).lower()
        protocol = {"tcp": 6, "udp": 17, "icmp": 1}.get(protocol_value, safe_int(protocol_value))
        return cls(
            observed_at=parse_time(value.get("observed_at") or value.get("flow_time") or value.get("last_seen")),
            src_ip=src,
            dst_ip=dst,
            src_port=safe_int(value.get("src_port")),
            dst_port=safe_int(value.get("dst_port")),
            protocol=protocol,
            tcp_flags=safe_int(value.get("tcp_flags")),
            packets=safe_int(value.get("packets")),
            bytes=safe_int(value.get("bytes")),
            flow_count=max(1, safe_int(value.get("flow_count") or value.get("flows") or 1)),
            src_asn=safe_int(value.get("src_asn")),
            dst_asn=safe_int(value.get("dst_asn")),
            sensor=clean_text(value.get("sensor")),
            exporter_ip=normalized_ip(value.get("exporter_ip")),
            input_if=safe_int(value.get("input_if")),
            output_if=safe_int(value.get("output_if")),
        )


@dataclass
class AttackVector:
    attack_type: str
    detector: str
    detector_score: int
    confidence: float
    first_seen: str
    last_seen: str
    src_ip: str = ""
    target_ip: str = ""
    target_prefix: str = ""
    direction: str = "UNKNOWN"
    attack_family: str = "OTHER_FAMILY"
    severity: str = "INFO"
    verdict: str = "INFO"
    protocol: str = ""
    network_context: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    score_components: dict[str, int] = field(default_factory=dict)
    window_seconds: int = 60
    baseline_deviation: float = 0.0
    features: dict[str, Any] = field(default_factory=dict)
    threat_intel: dict[str, Any] = field(default_factory=dict)
    intel_sources: list[str] = field(default_factory=list)
    external_correlation: bool = False
    compromised_host_score: int = 0
    campaign_id: str = ""
    decision_source: str = "GMJ_FLOW"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CampaignVector:
    campaign_id: str
    target_prefix: str
    classification: str
    unique_sources: int
    unique_source_asns: int
    packets_per_second: float
    bits_per_second: float
    flows_per_second: float
    coordination_score: int
    first_seen: str
    last_seen: str
    campaign_key: str = ""
    recurrence_count: int = 1
    features: dict[str, Any] = field(default_factory=dict)
    threat_intel: dict[str, Any] = field(default_factory=dict)
    intel_sources: list[str] = field(default_factory=list)
    decision_source: str = "GMJ_FLOW"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectorThresholds:
    vertical_ports: int = 20
    horizontal_hosts: int = 20
    low_slow_unique: int = 10
    flood_packets: int = 1000
    flood_pps: float = 100.0
    distributed_sources: int = 20
    carpet_unique_hosts: int = 8
    carpet_prefix_pps: float = 200.0
    carpet_host_pps: float = 100.0
    carpet_min_packets: int = 3000
    carpet_min_bps: float = 1_000_000.0
    carpet_min_absolute_pps: float = 5000.0
    carpet_min_absolute_bps: float = 50_000_000.0
    carpet_web_return_share: float = 0.6
    carpet_web_return_ack_ratio: float = 0.5
    carpet_dst_port_diversity: int = 100
    udp_min_packets: int = 3000
    udp_min_pps: float = 100.0
    udp_min_bps: float = 1_000_000.0
    syn_min_packets: int = 3000
    syn_min_pps: float = 100.0
    syn_min_bps: float = 1_000_000.0
    ssh_attempts: int = 30
    ssh_min_elapsed: float = 30.0

    @classmethod
    def from_env(cls) -> "DetectorThresholds":
        return cls(
            vertical_ports=int(os.getenv("GMJFLOW_SCAN_VERTICAL_PORTS", "20")),
            horizontal_hosts=int(os.getenv("GMJFLOW_SCAN_HORIZONTAL_HOSTS", "20")),
            low_slow_unique=int(os.getenv("GMJFLOW_SCAN_LOW_SLOW_UNIQUE", "10")),
            carpet_unique_hosts=int(os.getenv("GMJFLOW_CARPET_MIN_HOSTS", "8")),
            carpet_prefix_pps=float(os.getenv("GMJFLOW_CARPET_MIN_PPS", "200")),
            carpet_host_pps=float(os.getenv("GMJFLOW_CARPET_MAX_HOST_PPS", "100")),
            carpet_min_packets=int(os.getenv("GMJFLOW_CARPET_MIN_PACKETS", "3000")),
            carpet_min_bps=float(os.getenv("GMJFLOW_CARPET_MIN_BPS", "1000000")),
            carpet_min_absolute_pps=float(os.getenv("GMJFLOW_CARPET_MIN_ABSOLUTE_PPS", "5000")),
            carpet_min_absolute_bps=float(os.getenv("GMJFLOW_CARPET_MIN_ABSOLUTE_BPS", "50000000")),
            carpet_web_return_share=float(os.getenv("GMJFLOW_CARPET_WEB_RETURN_SHARE", "0.6")),
            carpet_web_return_ack_ratio=float(os.getenv("GMJFLOW_CARPET_WEB_RETURN_ACK_RATIO", "0.5")),
            carpet_dst_port_diversity=int(os.getenv("GMJFLOW_CARPET_DST_PORT_DIVERSITY", "100")),
            udp_min_packets=int(os.getenv("GMJFLOW_UDP_FLOOD_MIN_PACKETS", "3000")),
            udp_min_pps=float(os.getenv("GMJFLOW_UDP_FLOOD_MIN_PPS", "100")),
            udp_min_bps=float(os.getenv("GMJFLOW_UDP_FLOOD_MIN_BPS", "1000000")),
            syn_min_packets=int(os.getenv("GMJFLOW_SYN_FLOOD_MIN_PACKETS", "3000")),
            syn_min_pps=float(os.getenv("GMJFLOW_SYN_FLOOD_MIN_PPS", "100")),
            syn_min_bps=float(os.getenv("GMJFLOW_SYN_FLOOD_MIN_BPS", "1000000")),
            ssh_attempts=int(os.getenv("GMJFLOW_SSH_BRUTE_FORCE_MIN_ATTEMPTS", "30")),
            ssh_min_elapsed=float(os.getenv("GMJFLOW_SSH_BRUTE_FORCE_MIN_SECONDS", "30")),
        )


def flow_features(rows: Sequence[FlowObservation], window_seconds: int) -> dict[str, Any]:
    flow_count = sum(row.flow_count for row in rows)
    packet_count = sum(row.packets for row in rows)
    byte_count = sum(row.bytes for row in rows)
    syn_flows = sum(row.flow_count for row in rows if row.protocol == 6 and row.tcp_flags & 0x02)
    ack_flows = sum(row.flow_count for row in rows if row.protocol == 6 and row.tcp_flags & 0x10)
    rst_flows = sum(row.flow_count for row in rows if row.protocol == 6 and row.tcp_flags & 0x04)
    first = min(row.observed_at for row in rows)
    last = max(row.observed_at for row in rows)
    elapsed = max(1.0, min(float(window_seconds), (last - first).total_seconds()))
    source_ports = Counter(row.src_port for row in rows)
    destination_ports = Counter(row.dst_port for row in rows)
    sources = Counter(row.src_ip for row in rows)
    destinations = Counter(row.dst_ip for row in rows)
    packet_sizes = [ratio(row.bytes, row.packets) for row in rows if row.packets]
    temporal_buckets = {
        int(row.observed_at.timestamp()) // 10
        for row in rows
    }
    source_asns = sorted({row.src_asn for row in rows if row.src_asn})
    source_details: dict[str, dict[str, Any]] = {}
    destination_details: dict[str, dict[str, Any]] = {}
    source_port_details: dict[int, dict[str, Any]] = {}
    destination_port_details: dict[int, dict[str, Any]] = {}
    protocol_details: dict[int, dict[str, Any]] = {}
    tcp_flag_details: dict[int, dict[str, Any]] = {}
    for row in rows:
        source = source_details.setdefault(
            row.src_ip,
            {"source_ip": row.src_ip, "source_asn": row.src_asn, "packets": 0, "bytes": 0, "flows": 0},
        )
        source["packets"] += row.packets
        source["bytes"] += row.bytes
        source["flows"] += row.flow_count
        if not source["source_asn"] and row.src_asn:
            source["source_asn"] = row.src_asn
        destination = destination_details.setdefault(
            row.dst_ip,
            {"destination_ip": row.dst_ip, "dst_asn": row.dst_asn, "packets": 0, "bytes": 0, "flows": 0},
        )
        destination["packets"] += row.packets
        destination["bytes"] += row.bytes
        destination["flows"] += row.flow_count
        if not destination["dst_asn"] and row.dst_asn:
            destination["dst_asn"] = row.dst_asn
        for container, port in ((source_port_details, row.src_port), (destination_port_details, row.dst_port)):
            detail = container.setdefault(port, {"port": port, "packets": 0, "bytes": 0, "flows": 0})
            detail["packets"] += row.packets
            detail["bytes"] += row.bytes
            detail["flows"] += row.flow_count
        protocol = protocol_details.setdefault(
            row.protocol,
            {"protocol": {1: "icmp", 6: "tcp", 17: "udp"}.get(row.protocol, str(row.protocol)), "protocol_number": row.protocol, "packets": 0, "bytes": 0, "flows": 0},
        )
        protocol["packets"] += row.packets
        protocol["bytes"] += row.bytes
        protocol["flows"] += row.flow_count
        if row.protocol == 6:
            flags = tcp_flag_details.setdefault(
                row.tcp_flags,
                {"flags": row.tcp_flags, "packets": 0, "bytes": 0, "flows": 0},
            )
            flags["packets"] += row.packets
            flags["bytes"] += row.bytes
            flags["flows"] += row.flow_count

    def ranked_details(values: Mapping[Any, dict[str, Any]], limit: int) -> list[dict[str, Any]]:
        result = []
        for item in sorted(values.values(), key=lambda value: (-int(value["packets"]), str(value)))[:limit]:
            normalized = dict(item)
            normalized["pps"] = round(ratio(normalized["packets"], window_seconds), 4)
            normalized["share"] = round(ratio(normalized["packets"], packet_count) * 100, 4)
            result.append(normalized)
        return result

    return {
        "flow_count": flow_count,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "unique_dst_ips": len({row.dst_ip for row in rows}),
        "unique_dst_ports": len({row.dst_port for row in rows}),
        "unique_src_ips": len({row.src_ip for row in rows}),
        "unique_src_asns": len({row.src_asn for row in rows if row.src_asn}),
        "unique_source_asns": len(source_asns),
        "source_asns": source_asns[:100],
        "source_asns_sample": source_asns[:100],
        "unique_src_ports": len({row.src_port for row in rows}),
        "syn_flows": syn_flows,
        "ack_flows": ack_flows,
        "rst_flows": rst_flows,
        "syn_ratio": round(ratio(syn_flows, flow_count), 4),
        "rst_ratio": round(ratio(rst_flows, flow_count), 4),
        "syn_ack_ratio": round(ratio(syn_flows, ack_flows), 4),
        "avg_packets_per_flow": round(ratio(packet_count, flow_count), 4),
        "avg_bytes_per_flow": round(ratio(byte_count, flow_count), 4),
        "flows_per_second": round(ratio(flow_count, window_seconds), 4),
        "packets_per_second": round(ratio(packet_count, window_seconds), 4),
        "bits_per_second": round(ratio(byte_count * 8, window_seconds), 4),
        "average_packet_size": round(ratio(sum(packet_sizes), len(packet_sizes)), 2) if packet_sizes else 0.0,
        "packet_size_stddev": round(statistics.pstdev(packet_sizes), 2) if len(packet_sizes) > 1 else 0.0,
        "top_source_ports": dict(source_ports.most_common(20)),
        "top_destination_ports": dict(destination_ports.most_common(20)),
        "top_sources": dict(sources.most_common(20)),
        "top_destinations": dict(destinations.most_common(20)),
        # Investigation snapshots are bounded before they are persisted with the
        # event. They make the drawer useful without querying flow_raw.
        "top_source_details": ranked_details(source_details, 50),
        "top_destination_details": ranked_details(destination_details, 50),
        "top_source_port_details": ranked_details(source_port_details, 20),
        "top_destination_port_details": ranked_details(destination_port_details, 20),
        "protocol_distribution": ranked_details(protocol_details, 20),
        "tcp_flag_distribution": ranked_details(tcp_flag_details, 20),
        "observation_samples": len(rows),
        "persistent_windows": len(temporal_buckets),
        "first_seen": first.isoformat().replace("+00:00", "Z"),
        "last_seen": last.isoformat().replace("+00:00", "Z"),
        "elapsed_seconds": round(elapsed, 3),
    }


def finalize_vector(vector: AttackVector) -> AttackVector:
    vector.attack_family = attack_family(vector.attack_type)
    persistent = safe_int(vector.features.get("persistent_windows") or vector.features.get("consecutive_windows") or 1)
    vector.verdict = detector_verdict(vector.detector_score, persistent_windows=max(1, persistent))
    if vector.verdict == "CONFIRMED_ATTACK" or vector.detector_score >= 90:
        vector.severity = "CRITICAL"
    elif vector.verdict == "LIKELY_ATTACK" or vector.detector_score >= 75:
        vector.severity = "HIGH"
    elif vector.detector_score >= 55:
        vector.severity = "MEDIUM"
    else:
        vector.severity = "LOW"
    vector.features["attack_family"] = vector.attack_family
    vector.features["verdict"] = vector.verdict
    vector.features["severity"] = vector.severity
    vector.features["score_components"] = dict(vector.score_components)
    vector.features["evidence"] = list(vector.evidence)
    return vector


class PortScanDetector:
    name = "port_scan"

    def __init__(self, thresholds: DetectorThresholds | None = None) -> None:
        self.thresholds = thresholds or DetectorThresholds()

    def detect(
        self,
        observations: Sequence[FlowObservation],
        intel_lookup: Callable[[str, Mapping[str, Any] | None], Mapping[str, Any]] | None = None,
    ) -> list[AttackVector]:
        if not observations:
            return []

        # Port-scan detection must only consider connection attempts (SYN without ACK).
        # Counting established/response traffic makes high-volume services look like scanners.
        scan_observations = [
            row
            for row in observations
            if row.protocol == 6
            and (row.tcp_flags & 0x02)
            and not (row.tcp_flags & 0x10)
        ]
        if not scan_observations:
            return []

        now = max(item.observed_at for item in scan_observations)
        best: dict[tuple[str, str], AttackVector] = {}
        for window in WINDOWS:
            grouped: dict[str, list[FlowObservation]] = defaultdict(list)
            cutoff = now - timedelta(seconds=window)
            for row in scan_observations:
                if row.observed_at >= cutoff:
                    grouped[row.src_ip].append(row)
            for source, rows in grouped.items():
                features = flow_features(rows, window)
                dst_ips = features["unique_dst_ips"]
                dst_ports = features["unique_dst_ports"]
                attack_type = ""
                if dst_ports >= self.thresholds.vertical_ports and dst_ips <= 3:
                    attack_type = PORT_SCAN_VERTICAL
                elif dst_ips >= self.thresholds.horizontal_hosts and dst_ports <= 5:
                    attack_type = PORT_SCAN_HORIZONTAL
                elif dst_ips >= self.thresholds.horizontal_hosts and dst_ports > 5:
                    attack_type = NETWORK_SWEEP
                elif (
                    window == 300
                    and max(dst_ips, dst_ports) >= self.thresholds.low_slow_unique
                    and features["flows_per_second"] < 1.0
                    and features["elapsed_seconds"] >= 60
                ):
                    attack_type = LOW_SLOW_SCAN
                if not attack_type:
                    continue
                cardinality = dst_ports if attack_type == PORT_SCAN_VERTICAL else dst_ips
                base = 45 + math.log2(max(2, cardinality)) * 8
                if features["syn_ratio"] >= 0.7:
                    base += 8
                if attack_type == LOW_SLOW_SCAN:
                    base = max(55, base - 10)
                score = int(clamp(base))
                target_prefix = ""
                if dst_ips > 1:
                    parsed_target = ip_address(rows[0].dst_ip)
                    prefix_length = 24 if parsed_target.version == 4 else 64
                    candidate_prefix = ip_network(f"{parsed_target}/{prefix_length}", strict=False)
                    if all(ip_address(row.dst_ip).version == candidate_prefix.version and ip_address(row.dst_ip) in candidate_prefix for row in rows):
                        target_prefix = str(candidate_prefix)
                vector = AttackVector(
                    attack_type=attack_type,
                    detector=self.name,
                    detector_score=score,
                    confidence=round(score / 100.0, 3),
                    first_seen=features["first_seen"],
                    last_seen=features["last_seen"],
                    src_ip=source,
                    target_ip=rows[0].dst_ip if dst_ips == 1 else "",
                    target_prefix=target_prefix,
                    window_seconds=window,
                    protocol="tcp",
                    features=features,
                )
                vector.score_components = {
                    "cardinality": min(35, int(math.log2(max(2, cardinality)) * 8)),
                    "syn_attempts": 8 if features["syn_ratio"] >= 0.7 else 0,
                    "persistence": 12 if features["elapsed_seconds"] >= 60 else 4,
                    "threat_intel": 0,
                }
                vector.evidence = [
                    f"{dst_ips} destinos em {window} segundos",
                    f"{dst_ports} portas de destino",
                    f"{features['flow_count']} tentativas TCP SYN sem ACK",
                    f"persistência observada de {features['elapsed_seconds']:.0f} segundos",
                ]
                vector.features["behavioral_score"] = score
                finalize_vector(vector)
                key = (source, attack_type)
                if key not in best or best[key].detector_score < score:
                    best[key] = vector
        vectors = list(best.values())
        if intel_lookup is None:
            return vectors
        rows_by_source: dict[str, list[FlowObservation]] = defaultdict(list)
        for row in scan_observations:
            rows_by_source[row.src_ip].append(row)
        for vector in vectors:
            intel = source_intel_stats(rows_by_source.get(vector.src_ip, []), intel_lookup, maximum_lookups=1)
            attach_source_intel(vector, intel)
            boost = source_intel_score_boost(intel, maximum=10)
            if boost:
                vector.detector_score = int(clamp(vector.detector_score + boost))
                vector.confidence = round(clamp(vector.confidence + boost / 100.0, 0, 1), 3)
                vector.features["source_intel_score_boost"] = boost
                vector.score_components["threat_intel"] = boost
                finalize_vector(vector)
        return vectors


class SshBruteForceDetector:
    name = "ssh_brute_force"

    def __init__(self, thresholds: DetectorThresholds | None = None) -> None:
        self.thresholds = thresholds or DetectorThresholds()
        self.last_suppressed_multi_target: dict[str, dict[str, Any]] = {}

    def detect(
        self,
        observations: Sequence[FlowObservation],
        intel_lookup: Callable[[str, Mapping[str, Any] | None], Mapping[str, Any]] | None = None,
        window_seconds: int = 300,
    ) -> list[AttackVector]:
        latest = max((row.observed_at for row in observations), default=utc_now())
        cutoff = latest - timedelta(seconds=window_seconds)
        grouped: dict[tuple[str, str], list[FlowObservation]] = defaultdict(list)
        for row in observations:
            if (
                row.observed_at >= cutoff
                and row.protocol == 6
                and row.dst_port == 22
                and (row.tcp_flags & 0x02)
                and not (row.tcp_flags & 0x10)
            ):
                grouped[(row.src_ip, row.dst_ip)].append(row)
        self.last_suppressed_multi_target = {}
        source_target_counts = Counter(source for source, _target in grouped)
        vectors: list[AttackVector] = []
        for (source, target), rows in grouped.items():
            features = flow_features(rows, window_seconds)
            attempts = max(features["packet_count"], features["syn_flows"])
            if attempts < self.thresholds.ssh_attempts:
                continue
            if features["elapsed_seconds"] < self.thresholds.ssh_min_elapsed:
                continue
            if source_target_counts[source] >= self.thresholds.horizontal_hosts:
                summary = self.last_suppressed_multi_target.setdefault(source, {
                    "target_count": source_target_counts[source],
                    "qualifying_targets": 0,
                    "attempts": 0,
                    "elapsed_seconds": 0.0,
                })
                summary["qualifying_targets"] += 1
                summary["attempts"] += attempts
                summary["elapsed_seconds"] = max(
                    float(summary["elapsed_seconds"]),
                    float(features["elapsed_seconds"]),
                )
                continue
            intel = source_intel_stats(rows, intel_lookup, maximum_lookups=1)
            volume = min(35, int(math.log10(max(10, attempts)) * 12))
            persistence = min(25, int(features["elapsed_seconds"] / 6))
            recurrence = min(15, safe_int(features.get("persistent_windows")) * 3)
            behavioral_score = int(clamp(35 + volume + persistence + recurrence))
            intel_boost = source_intel_score_boost(intel, maximum=8)
            score = int(clamp(behavioral_score + intel_boost))
            features.update({
                "protocol": "tcp",
                "ssh_attempts": attempts,
                "unique_sources": 1,
                "unique_destinations": 1,
                "behavioral_score": behavioral_score,
                "source_intel_score_boost": intel_boost,
            })
            vector = AttackVector(
                attack_type=SSH_BRUTE_FORCE,
                detector=self.name,
                detector_score=score,
                confidence=round(score / 100.0, 3),
                first_seen=features["first_seen"],
                last_seen=features["last_seen"],
                src_ip=source,
                target_ip=target,
                target_prefix=f"{target}/32" if ":" not in target else f"{target}/128",
                window_seconds=window_seconds,
                protocol="tcp",
                features=features,
                evidence=[
                    f"{attempts} tentativas TCP/22 SYN sem ACK",
                    f"uma origem para um único servidor",
                    f"persistência observada de {features['elapsed_seconds']:.0f} segundos",
                ],
                score_components={
                    "volume": volume,
                    "target_concentration": 15,
                    "persistence": persistence,
                    "recurrence": recurrence,
                    "threat_intel": intel_boost,
                },
            )
            attach_source_intel(vector, intel)
            vectors.append(finalize_vector(vector))
        return vectors


def target_prefixes(ip_text: str) -> Iterable[str]:
    parsed = ip_address(ip_text)
    if parsed.version == 4:
        for length in PREFIX_LENGTHS_V4:
            yield str(ip_network(f"{parsed}/{length}", strict=False))
    else:
        yield str(ip_network(f"{parsed}/128", strict=False))


def _overlaps_any_network(prefix: str, networks: Sequence[Any]) -> bool:
    """True if the prefix overlaps any network in the sequence (lazy parse)."""
    if not networks:
        return False
    try:
        net = ip_network(prefix, strict=False)
    except ValueError:
        return False
    for other in networks:
        if isinstance(other, str):
            try:
                other = ip_network(other, strict=False)
            except ValueError:
                continue
        if net.overlaps(other):
            return True
    return False


def _record_safe_learning_audit_v2(
    conn: sqlite3.Connection,
    *,
    now_iso: str,
    prefix: str,
    protocol: str,
    classification: str,
    reason: str,
    safe_would_update: bool,
    confirmed_attack: bool,
    strong_signal: bool,
    protected_or_internal: bool,
    campaign_blocked: bool,
    audit_z: float | None,
    baseline_state: str,
) -> None:
    """Aggregated (per-hour, per classification/reason) Safe Learning shadow audit.

    The key is (hour_bucket, protocol, classification, reason) — NOT target_prefix.
    The detector fans each destination across 9 prefix lengths (IPv4 /22../32 +
    IPv6 /128), so a per-prefix key retained ~30% of rows. The meta-only key
    yields ~15-20 rows/hour (99.99% reduction); the last-seen prefix is kept in
    sample_prefix for traceability, and per-prefix detail remains available in
    behavior_safe_learning_shadow_audit (72h retention).
    """
    hour_bucket = clean_text(now_iso)[:13] + ":00:00Z"
    conn.execute(
        """
        INSERT INTO behavior_safe_learning_shadow_audit_v2(
            hour_bucket, protocol, classification, reason, policy_version,
            evaluation_count, would_learn_count, rejected_count, quarantined_count,
            confirmed_attack_count, strong_detector_signal_count,
            protected_or_internal_count, campaign_blocked_count,
            robust_z_min, robust_z_max, robust_z_sum, robust_z_count,
            baseline_state, sample_prefix, first_seen, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hour_bucket, protocol, classification, reason) DO UPDATE SET
            evaluation_count = evaluation_count + 1,
            would_learn_count = would_learn_count + excluded.would_learn_count,
            rejected_count = rejected_count + excluded.rejected_count,
            quarantined_count = quarantined_count + excluded.quarantined_count,
            confirmed_attack_count = confirmed_attack_count + excluded.confirmed_attack_count,
            strong_detector_signal_count = strong_detector_signal_count + excluded.strong_detector_signal_count,
            protected_or_internal_count = protected_or_internal_count + excluded.protected_or_internal_count,
            campaign_blocked_count = campaign_blocked_count + excluded.campaign_blocked_count,
            robust_z_min = CASE WHEN robust_z_min IS NULL THEN excluded.robust_z_min
                                WHEN excluded.robust_z_min IS NULL THEN robust_z_min
                                ELSE MIN(robust_z_min, excluded.robust_z_min) END,
            robust_z_max = CASE WHEN robust_z_max IS NULL THEN excluded.robust_z_max
                                WHEN excluded.robust_z_max IS NULL THEN robust_z_max
                                ELSE MAX(robust_z_max, excluded.robust_z_max) END,
            robust_z_sum = COALESCE(robust_z_sum, 0) + COALESCE(excluded.robust_z_sum, 0),
            robust_z_count = robust_z_count + excluded.robust_z_count,
            baseline_state = excluded.baseline_state,
            sample_prefix = excluded.sample_prefix,
            last_seen = excluded.last_seen
        """,
        (
            hour_bucket, protocol, classification, reason, "safe_learning_shadow_v2",
            1, int(safe_would_update), int(classification == REJECTED), int(classification == QUARANTINED),
            int(confirmed_attack), int(strong_signal), int(protected_or_internal), int(campaign_blocked),
            audit_z, audit_z, audit_z, 1 if audit_z is not None else 0,
            baseline_state, prefix, now_iso, now_iso,
        ),
    )


def _attack_signal(prefix: str, attack_networks: Sequence[Any], confirmed_networks: Sequence[Any]) -> tuple[bool, bool]:
    """Return (strong_signal, confirmed_attack) for a baseline prefix.

    Reuses only the current run's AttackVectors (already validated detector
    output) — no new detection, no second threshold collection.
    """
    if not attack_networks:
        return False, False
    try:
        network = ip_network(prefix, strict=False)
    except ValueError:
        return False, False
    strong = any(network.overlaps(other) for other in attack_networks)
    confirmed = any(network.overlaps(other) for other in confirmed_networks)
    return strong, confirmed


def normalized_intel_match(match: Mapping[str, Any]) -> dict[str, Any]:
    tags = []
    for item in match.get("tags") or []:
        if isinstance(item, Mapping):
            label = clean_text(item.get("name") or item.get("slug"))
        else:
            label = clean_text(item)
        if label and label not in tags:
            tags.append(label)
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    cves = []
    for item in [*(match.get("cves") or []), *(metadata.get("cves") or [])]:
        value = clean_text(item)
        if value and value not in cves:
            cves.append(value)
    return {
        "provider": clean_text(match.get("provider")).upper(),
        "indicator_type": clean_text(match.get("indicator_type")).upper(),
        "classification": clean_text(match.get("classification")).lower(),
        "tags": tags[:20],
        "last_seen": clean_text(match.get("last_seen")),
        "organization": clean_text(match.get("organization")),
        "country": clean_text(match.get("country") or match.get("country_code")),
        "country_code": clean_text(match.get("country_code")).upper(),
        "actor": clean_text(match.get("actor")),
        "asn": safe_int(match.get("asn")),
        "cves": cves[:20],
        "metadata": {clean_text(key): value for key, value in list(metadata.items())[:30] if clean_text(key)},
        "botnet_family": clean_text(match.get("botnet_family")),
        "network": clean_text(match.get("network")),
        "spoofing_likelihood": safe_int(match.get("spoofing_likelihood")),
    }


def source_intel_stats(
    rows: Sequence[FlowObservation],
    intel_lookup: Callable[[str, Mapping[str, Any] | None], Mapping[str, Any]] | None,
    maximum_lookups: int | None = None,
) -> dict[str, Any]:
    if intel_lookup is None:
        return {
            "matches": 0, "match_count": 0, "matched_source_count": 0,
            "bogon_sources": 0, "c2_sources": 0, "malicious_sources": 0,
            "scanner_sources": 0, "sources": {}, "intel_sources": [],
            "indicator_types": [], "classifications": [], "tags": [],
            "lookup_count": 0, "lookup_truncated": False,
        }
    sources: dict[str, Any] = {}
    providers: set[str] = set()
    indicator_types: set[str] = set()
    classifications: set[str] = set()
    tag_names: set[str] = set()
    bogon_sources: set[str] = set()
    c2_sources: set[str] = set()
    malicious_sources: set[str] = set()
    scanner_sources: set[str] = set()
    representatives: dict[str, FlowObservation] = {}
    for row in rows:
        representatives.setdefault(row.src_ip, row)
    candidates = sorted(
        representatives,
        key=lambda value: (hashlib.sha256(value.encode("utf-8")).hexdigest(), value),
    )
    configured_maximum = max(1, int(os.getenv("GMJFLOW_BEHAVIOR_MAX_INTEL_LOOKUPS_PER_VECTOR", "500")))
    lookup_limit = configured_maximum if maximum_lookups is None else max(1, min(configured_maximum, maximum_lookups))
    selected = candidates[:lookup_limit]
    match_count = 0
    for source in selected:
        row = representatives[source]
        try:
            result = intel_lookup(
                source,
                {
                    "sensor": row.sensor,
                    "exporter_ip": row.exporter_ip,
                    "input_if": row.input_if,
                    "output_if": row.output_if,
                    "context_type": "UNKNOWN",
                },
            )
        except Exception as exc:
            LOGGER.debug("THREAT_INTEL_LOOKUP_FAILED source=%s error=%s", source, exc)
            continue
        matches = [normalized_intel_match(item) for item in (result.get("matches") or []) if isinstance(item, Mapping)]
        matches = [item for item in matches if item["provider"] or item["indicator_type"]]
        if matches:
            sources[source] = matches
        match_count += len(matches)
        for match in matches:
            provider = match["provider"]
            indicator_type = match["indicator_type"]
            classification = match["classification"]
            tags = {clean_text(item).lower() for item in match["tags"]}
            providers.add(provider)
            indicator_types.add(indicator_type)
            classifications.add(classification)
            tag_names.update(match["tags"])
            if indicator_type in {"BOGON", "FULLBOGON"} and classification == "anomalous_source":
                bogon_sources.add(source)
            if indicator_type == "C2" or classification == "c2":
                c2_sources.add(source)
            if classification == "malicious":
                malicious_sources.add(source)
            if classification in {"scanner", "malicious"} or any("scan" in tag for tag in tags):
                scanner_sources.add(source)
    return {
        "matches": len(sources),
        "match_count": match_count,
        "matched_source_count": len(sources),
        "bogon_sources": len(bogon_sources),
        "c2_sources": len(c2_sources),
        "malicious_sources": len(malicious_sources),
        "scanner_sources": len(scanner_sources),
        "sources": sources,
        "intel_sources": sorted(providers - {""}),
        "indicator_types": sorted(indicator_types - {""}),
        "classifications": sorted(classifications - {""}),
        "tags": sorted(tag_names - {""})[:50],
        "lookup_count": len(selected),
        "lookup_truncated": len(candidates) > len(selected),
    }


def source_intel_score_boost(intel: Mapping[str, Any], maximum: int = 10) -> int:
    if safe_int(intel.get("matched_source_count") or intel.get("matches")) <= 0:
        return 0
    boost = 2
    boost += 3 if safe_int(intel.get("c2_sources")) else 0
    boost += 3 if safe_int(intel.get("bogon_sources")) else 0
    boost += 2 if safe_int(intel.get("malicious_sources")) else 0
    boost += 1 if safe_int(intel.get("scanner_sources")) else 0
    return min(max(0, int(maximum)), boost)


def contextual_intel_score_boost(intel: Mapping[str, Any], attack_type: str, maximum: int = 8) -> tuple[int, str]:
    """Return a bounded boost and explain relevance to the current behavior."""
    matches = safe_int(intel.get("matched_source_count") or intel.get("matches"))
    if not matches:
        return 0, "no_match"
    tags = {clean_text(value).lower() for value in intel.get("tags") or []}
    classifications = {clean_text(value).lower() for value in intel.get("classifications") or []}
    if attack_type in SCAN_ATTACK_TYPES:
        relevant = safe_int(intel.get("scanner_sources")) or "scanner" in classifications or any("scan" in value for value in tags)
        return (min(maximum, 8 if relevant else 2), "direct_scan_relevance" if relevant else "historical_reputation_only")
    if "SYN" in attack_type and safe_int(intel.get("bogon_sources")):
        return min(maximum, 6), "source_validity_relevance"
    if safe_int(intel.get("c2_sources")):
        return min(maximum, 4), "botnet_reputation_support"
    # Telnet/scanner history does not confirm an unrelated UDP flood.
    return min(maximum, 2), "historical_reputation_only"


def attach_source_intel(vector: AttackVector, intel: Mapping[str, Any]) -> None:
    source = dict(intel)
    vector.threat_intel["source_intel"] = source
    vector.threat_intel.setdefault("target_campaign_intel", {"matches": 0, "observations": []})
    # Compatibility summaries for campaign aggregation and existing consumers.
    for key in ("matches", "match_count", "bogon_sources", "c2_sources", "lookup_count", "lookup_truncated"):
        vector.threat_intel[key] = source.get(key, 0)
    vector.intel_sources = sorted(set(vector.intel_sources) | set(source.get("intel_sources") or []))


def cached_intel_lookup(
    lookup: Callable[[str, Mapping[str, Any] | None], Mapping[str, Any]],
) -> Callable[[str, Mapping[str, Any] | None], Mapping[str, Any]]:
    cache: dict[tuple[Any, ...], Mapping[str, Any]] = {}

    def cached(ip: str, context: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        supplied = dict(context or {})
        key = (
            normalized_ip(ip), clean_text(supplied.get("sensor")),
            normalized_ip(supplied.get("exporter_ip")), supplied.get("input_if"),
            supplied.get("output_if"), clean_text(supplied.get("context_type")).upper(),
        )
        if key not in cache:
            cache[key] = lookup(ip, supplied)
        return cache[key]

    setattr(cached, "cache", cache)
    return cached


class SynFloodDetector:
    name = "syn_flood"

    def __init__(self, thresholds: DetectorThresholds | None = None) -> None:
        self.thresholds = thresholds or DetectorThresholds()

    def detect(
        self,
        observations: Sequence[FlowObservation],
        intel_lookup: Callable[[str, Mapping[str, Any] | None], Mapping[str, Any]] | None = None,
        baseline: Mapping[str, float] | None = None,
        window_seconds: int = 60,
    ) -> list[AttackVector]:
        latest = max((row.observed_at for row in observations), default=utc_now())
        cutoff = latest - timedelta(seconds=window_seconds)
        tcp_rows = [row for row in observations if row.protocol == 6 and row.observed_at >= cutoff]
        grouped: dict[str, list[FlowObservation]] = defaultdict(list)
        for row in tcp_rows:
            for prefix in target_prefixes(row.dst_ip):
                grouped[prefix].append(row)
        vectors = []
        for prefix, rows in grouped.items():
            features = flow_features(rows, window_seconds)
            syn_packets = sum(row.packets for row in rows if row.tcp_flags & 0x02 and not row.tcp_flags & 0x10)
            ack_packets = sum(row.packets for row in rows if row.tcp_flags & 0x10)
            rst_packets = sum(row.packets for row in rows if row.tcp_flags & 0x04)
            syn_ratio = ratio(syn_packets, max(1, features["packet_count"]))
            syn_ack_ratio = ratio(syn_packets, max(1, ack_packets))
            pps = ratio(syn_packets, window_seconds)
            bps = features["bits_per_second"]
            current_baseline = float((baseline or {}).get(prefix) or 0)
            deviation = ratio(pps, current_baseline) if current_baseline else 0.0
            volume_signals = sum((
                syn_packets >= self.thresholds.syn_min_packets,
                pps >= self.thresholds.syn_min_pps,
                bps >= self.thresholds.syn_min_bps,
                deviation >= 3 and pps >= self.thresholds.syn_min_pps / 2,
            ))
            if volume_signals < 2:
                continue
            if syn_ratio < 0.55 and syn_ack_ratio < 3:
                continue
            unique_sources = features["unique_src_ips"]
            intel = source_intel_stats(rows, intel_lookup)
            spoofing_likelihood = int(clamp(ratio(intel["bogon_sources"], max(1, unique_sources)) * 100 + min(30, unique_sources / 10)))
            attack_type = SYN_FLOOD
            if unique_sources >= self.thresholds.distributed_sources:
                attack_type = DISTRIBUTED_SYN_FLOOD
            if spoofing_likelihood >= 60 and unique_sources >= self.thresholds.distributed_sources:
                attack_type = SPOOFED_SYN_FLOOD
            score_components = {
                "volume": min(30, int(math.log10(max(10, syn_packets)) * 7)),
                "source_diversity": min(12, int(math.log2(max(1, unique_sources)) * 3)),
                "syn_imbalance": min(18, int(max(0, syn_ack_ratio - 1) * 3)),
                "persistence": min(20, safe_int(features.get("persistent_windows")) * 4),
                "baseline": min(10, int(deviation * 2)) if deviation else 0,
                "threat_intel": 0,
                "network_context": 0,
            }
            behavioral_score = int(clamp(20 + sum(score_components.values())))
            intel_boost, intel_relevance = contextual_intel_score_boost(intel, attack_type, maximum=8)
            score_components["threat_intel"] = intel_boost
            score = int(clamp(behavioral_score + intel_boost))
            features.update(
                {
                    "protocol": "tcp",
                    "syn_count": syn_packets,
                    "ack_count": ack_packets,
                    "rst_count": rst_packets,
                    "syn_ratio": round(syn_ratio, 4),
                    "syn_ack_ratio": round(syn_ack_ratio, 4),
                    "unique_sources": unique_sources,
                    "pps": round(features["packets_per_second"], 4),
                    "bps": round(features["bits_per_second"], 4),
                    "spoofing_likelihood": spoofing_likelihood,
                    "behavioral_score": behavioral_score,
                    "source_intel_score_boost": intel_boost,
                    "threat_intel_relevance": intel_relevance,
                    "volume_signals": volume_signals,
                }
            )
            vector_intel: dict[str, Any] = {}
            vector = AttackVector(
                attack_type=attack_type,
                detector=self.name,
                detector_score=score,
                confidence=round(clamp(behavioral_score / 100.0 + intel_boost / 100.0, 0, 1), 3),
                first_seen=features["first_seen"],
                last_seen=features["last_seen"],
                target_ip=rows[0].dst_ip if prefix.endswith("/32") else "",
                target_prefix=prefix,
                protocol="tcp",
                window_seconds=window_seconds,
                baseline_deviation=round(deviation, 3),
                features=features,
                threat_intel=vector_intel,
                evidence=[
                    f"{syn_packets} pacotes SYN sem ACK em {window_seconds} segundos",
                    f"{pps:.1f} pps e {bps:.0f} bit/s",
                    f"relação SYN/ACK de {syn_ack_ratio:.2f}",
                    f"{unique_sources} fontes e {features['unique_source_asns']} ASNs",
                    f"baseline {deviation:.2f}x" if deviation else "baseline ainda indisponível",
                ],
                score_components=score_components,
            )
            attach_source_intel(vector, intel)
            vectors.append(finalize_vector(vector))
        return suppress_contained_vectors(vectors)


AMPLIFICATION_PORTS = {19, 53, 123, 137, 161, 389, 1900, 3702, 11211}


class UdpFloodDetector:
    name = "udp_flood"

    def __init__(self, thresholds: DetectorThresholds | None = None) -> None:
        self.thresholds = thresholds or DetectorThresholds()

    def detect(
        self,
        observations: Sequence[FlowObservation],
        intel_lookup: Callable[[str, Mapping[str, Any] | None], Mapping[str, Any]] | None = None,
        baseline: Mapping[str, float] | None = None,
        window_seconds: int = 60,
    ) -> list[AttackVector]:
        latest = max((row.observed_at for row in observations), default=utc_now())
        cutoff = latest - timedelta(seconds=window_seconds)
        udp_rows = [row for row in observations if row.protocol == 17 and row.observed_at >= cutoff]
        grouped: dict[str, list[FlowObservation]] = defaultdict(list)
        for row in udp_rows:
            for prefix in target_prefixes(row.dst_ip):
                grouped[prefix].append(row)
        vectors = []
        for prefix, rows in grouped.items():
            features = flow_features(rows, window_seconds)
            pps = features["packets_per_second"]
            bps = features["bits_per_second"]
            current_baseline = float((baseline or {}).get(prefix) or 0)
            deviation = ratio(pps, current_baseline) if current_baseline else 0.0
            volume_signals = sum((
                features["packet_count"] >= self.thresholds.udp_min_packets,
                pps >= self.thresholds.udp_min_pps,
                bps >= self.thresholds.udp_min_bps,
                deviation >= 3 and pps >= self.thresholds.udp_min_pps / 2,
            ))
            # Cardinality and a single packet threshold are never sufficient.
            if pps < self.thresholds.udp_min_pps or volume_signals < 2:
                continue
            unique_sources = features["unique_src_ips"]
            source_ports: Counter[int] = Counter()
            destination_ports: Counter[int] = Counter()
            destination_packets: Counter[str] = Counter()
            for row in rows:
                source_ports[row.src_port] += row.packets
                destination_ports[row.dst_port] += row.packets
                destination_packets[row.dst_ip] += row.packets
            sizes = [ratio(row.bytes, row.packets) for row in rows if row.packets]
            dominant_src_port, dominant_src_count = source_ports.most_common(1)[0] if source_ports else (0, 0)
            source_port_concentration = ratio(dominant_src_count, sum(source_ports.values()))
            average_packet_size = ratio(sum(sizes), len(sizes)) if sizes else 0.0
            packet_size_stddev = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0
            ephemeral_packets = sum(count for port, count in destination_ports.items() if port >= 32768)
            ephemeral_destination_ratio = ratio(ephemeral_packets, features["packet_count"])
            pps_per_destination = ratio(pps, max(1, features["unique_dst_ips"]))
            target_concentration = ratio(max(destination_packets.values(), default=0), features["packet_count"])
            quic_return_pattern = (
                dominant_src_port == 443
                and source_port_concentration >= 0.3
                and ephemeral_destination_ratio >= 0.7
                and features["unique_dst_ports"] >= 20
                and pps_per_destination < 5
            )
            if quic_return_pattern and pps < 500 and (not deviation or deviation < 3):
                continue
            distributed = unique_sources >= self.thresholds.distributed_sources
            # A known port is only one signal. Diversity, concentration and packet shape are also required.
            reflection = (
                distributed
                and dominant_src_port in AMPLIFICATION_PORTS
                and source_port_concentration >= 0.5
                and average_packet_size >= 300
            )
            attack_type = UDP_REFLECTION_SUSPECTED if reflection else DISTRIBUTED_UDP_FLOOD if distributed else UDP_FLOOD
            intel = source_intel_stats(rows, intel_lookup)
            score_components = {
                "volume": min(30, int(math.log10(max(10, features["packet_count"])) * 7)),
                "source_diversity": min(12, int(math.log2(max(1, unique_sources)) * 2)),
                "target_concentration": min(18, int(target_concentration * 18)),
                "persistence": min(20, safe_int(features.get("persistent_windows")) * 4),
                "baseline": min(10, int(deviation * 2)) if deviation else 0,
                "reflection": 10 if reflection else 0,
                "threat_intel": 0,
                "network_context": 0,
            }
            behavioral_score = int(clamp(20 + sum(score_components.values())))
            intel_boost, intel_relevance = contextual_intel_score_boost(intel, attack_type, maximum=6)
            score_components["threat_intel"] = intel_boost
            score = int(clamp(behavioral_score + intel_boost))
            features.update(
                {
                    "protocol": "udp",
                    "unique_sources": unique_sources,
                    "unique_source_asns": features["unique_src_asns"],
                    "destination_port_distribution": dict(destination_ports.most_common(20)),
                    "source_port_distribution": dict(source_ports.most_common(20)),
                    "dominant_source_port": dominant_src_port,
                    "source_port_concentration": round(source_port_concentration, 4),
                    "ephemeral_destination_ratio": round(ephemeral_destination_ratio, 4),
                    "pps_per_destination": round(pps_per_destination, 4),
                    "target_concentration": round(target_concentration, 4),
                    "quic_return_pattern": quic_return_pattern,
                    "average_packet_size": round(average_packet_size, 2),
                    "packet_size_stddev": round(packet_size_stddev, 2),
                    "protocol_ratio": round(ratio(len(rows), len(observations)), 4),
                    "temporal_burst": round(ratio(pps, current_baseline), 3) if current_baseline else 0.0,
                    "amplification_port_signal": dominant_src_port in AMPLIFICATION_PORTS,
                    "reflection_evidence_satisfied": reflection,
                    "behavioral_score": behavioral_score,
                    "source_intel_score_boost": intel_boost,
                    "threat_intel_relevance": intel_relevance,
                    "volume_signals": volume_signals,
                }
            )
            vector = AttackVector(
                attack_type=attack_type,
                detector=self.name,
                detector_score=score,
                confidence=round(clamp(behavioral_score / 100.0 + intel_boost / 100.0, 0, 1), 3),
                first_seen=features["first_seen"],
                last_seen=features["last_seen"],
                target_ip=rows[0].dst_ip if prefix.endswith("/32") else "",
                target_prefix=prefix,
                protocol="udp",
                window_seconds=window_seconds,
                baseline_deviation=round(deviation, 3),
                features=features,
                evidence=[
                    f"{features['packet_count']} pacotes UDP em {window_seconds} segundos",
                    f"{pps:.1f} pps e {bps:.0f} bit/s",
                    f"{unique_sources} fontes, {features['unique_source_asns']} ASNs e {features['unique_dst_ips']} destinos",
                    f"porta UDP de origem dominante {dominant_src_port} = {source_port_concentration * 100:.1f}%",
                    f"portas efêmeras de destino = {ephemeral_destination_ratio * 100:.1f}%",
                    f"baseline {deviation:.2f}x" if deviation else "baseline ainda indisponível",
                ],
                score_components=score_components,
            )
            attach_source_intel(vector, intel)
            vectors.append(finalize_vector(vector))
        return suppress_contained_vectors(vectors)


def suppress_contained_vectors(vectors: list[AttackVector]) -> list[AttackVector]:
    """Keep host evidence and the strongest useful aggregate, not every overlapping prefix."""
    by_type: dict[str, list[AttackVector]] = defaultdict(list)
    for vector in vectors:
        by_type[vector.attack_type].append(vector)
    result: list[AttackVector] = []
    for items in by_type.values():
        hosts = [item for item in items if item.target_prefix.endswith("/32")]
        aggregates = [item for item in items if not item.target_prefix.endswith("/32")]
        result.extend(sorted(hosts, key=lambda item: item.detector_score, reverse=True)[:100])
        if aggregates:
            result.append(max(aggregates, key=lambda item: (item.detector_score, item.features.get("packets_per_second", 0))))
    return result


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(math.ceil(percentile * len(ordered))) - 1))
    return ordered[index]


def carpet_bombing_features(
    rows: Sequence[FlowObservation],
    window_seconds: int,
    resolver: Callable[[Any], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Carpet-bombing specific signals beyond the generic `flow_features`.

    The resolver is expected to be an in-memory/cached resolver; lookups are
    bounded to distinct destinations (not one call per flow)."""
    packet_count = max(1, sum(row.packets for row in rows))
    flow_count = max(1, sum(row.flow_count for row in rows))
    byte_count = sum(row.bytes for row in rows)
    src_port_packets: Counter[int] = Counter()
    dst_port_packets: Counter[int] = Counter()
    per_host_packets: Counter[str] = Counter()
    tcp_packets = 0
    tcp_syn_packets = 0
    tcp_ack_packets = 0
    tcp_psh_ack_packets = 0
    udp_packets = 0
    udp_quic_packets = 0
    web_return_packets = 0
    for row in rows:
        src_port_packets[row.src_port] += row.packets
        dst_port_packets[row.dst_port] += row.packets
        per_host_packets[row.dst_ip] += row.packets
        if row.protocol == 6:
            tcp_packets += row.packets
            if row.tcp_flags & 0x02:
                tcp_syn_packets += row.packets
            if row.tcp_flags & 0x10:
                tcp_ack_packets += row.packets
                if row.tcp_flags & 0x08:
                    tcp_psh_ack_packets += row.packets
            if row.src_port in (80, 443) and (row.tcp_flags & 0x10):
                web_return_packets += row.packets
        elif row.protocol == 17:
            udp_packets += row.packets
            if row.src_port == 443:
                udp_quic_packets += row.packets
                web_return_packets += row.packets
    top_src_port, top_src_port_count = src_port_packets.most_common(1)[0] if src_port_packets else (0, 0)
    top_dst_port, top_dst_port_count = dst_port_packets.most_common(1)[0] if dst_port_packets else (0, 0)
    host_pps = [ratio(packets, window_seconds) for packets in per_host_packets.values()]
    role_distribution: dict[str, float] = {}
    if resolver is not None:
        role_distribution = target_role_distribution(
            per_host_packets.keys(),
            resolver,
            weights=dict(per_host_packets),
        )
    return {
        "aggregate_pps": round(ratio(packet_count, window_seconds), 3),
        "aggregate_bps": round(ratio(byte_count * 8, window_seconds), 3),
        "unique_src_ports": len({row.src_port for row in rows}),
        "unique_dst_ports": len({row.dst_port for row in rows}),
        "max_host_pps": round(max(host_pps, default=0.0), 3),
        "p95_host_pps": round(_percentile(host_pps, 0.95), 3),
        "avg_pps_per_host": round(ratio(packet_count, len(per_host_packets)) / window_seconds, 3),
        "top_src_port": int(top_src_port),
        "top_src_port_share": round(ratio(top_src_port_count, packet_count), 4),
        "top_dst_port": int(top_dst_port),
        "top_dst_port_share": round(ratio(top_dst_port_count, packet_count), 4),
        "dst_port_entropy": shannon_entropy(dst_port_packets),
        "tcp_syn_ratio": round(ratio(tcp_syn_packets, tcp_packets), 4),
        "tcp_ack_ratio": round(ratio(tcp_ack_packets, tcp_packets), 4),
        "tcp_psh_ack_ratio": round(ratio(tcp_psh_ack_packets, tcp_packets), 4),
        "udp_quic_share": round(ratio(udp_quic_packets, packet_count), 4),
        "web_return_share": round(ratio(web_return_packets, packet_count), 4),
        "flows_s": round(ratio(flow_count, window_seconds), 4),
        "packets_per_flow": round(ratio(packet_count, flow_count), 4),
        "target_role_distribution": role_distribution,
        "target_cgnat_share": float(role_distribution.get(CGNAT_POOL, 0.0)),
        "target_downstream_isp_share": float(role_distribution.get(DOWNSTREAM_ISP, 0.0)),
        "target_customer_public_share": float(role_distribution.get("CUSTOMER_PUBLIC", 0.0)),
        "known_infra_source_share": float(
            sum(
                share
                for role, share in role_distribution.items()
                if role in {CDN_CACHE, DNS_RESOLVER, "SERVER_INFRA", "NETWORK_INFRA", "PEERING_INFRA"}
            )
        ),
    }


def _carpet_web_return_likely(cf: Mapping[str, Any], thresholds: DetectorThresholds) -> bool:
    """TCP src-port 80/443 + ACK, or UDP src-port 443 (QUIC), with highly diverse
    destination ports — the fingerprint of normal web traffic returning to many
    subscribers behind a prefix/CGNAT."""
    web_return_share = float(cf.get("web_return_share") or 0.0)
    tcp_ack_ratio = float(cf.get("tcp_ack_ratio") or 0.0)
    tcp_syn_ratio = float(cf.get("tcp_syn_ratio") or 0.0)
    udp_quic_share = float(cf.get("udp_quic_share") or 0.0)
    dst_entropy = float(cf.get("dst_port_entropy") or 0.0)
    unique_dst_ports = int(cf.get("unique_dst_ports") or 0)
    established_tcp_return = tcp_ack_ratio >= thresholds.carpet_web_return_ack_ratio and tcp_syn_ratio < 0.2
    diverse_destinations = dst_entropy >= 0.4 or unique_dst_ports >= thresholds.carpet_dst_port_diversity
    return bool(
        web_return_share >= thresholds.carpet_web_return_share
        and (established_tcp_return or udp_quic_share >= 0.1)
        and diverse_destinations
    )


class CarpetBombingDetector:
    name = "prefix_carpet_bombing"

    def __init__(
        self,
        thresholds: DetectorThresholds | None = None,
        max_groups: int = 50000,
        resolver: Callable[[Any], Mapping[str, Any]] | None = None,
    ) -> None:
        self.thresholds = thresholds or DetectorThresholds()
        self.max_groups = max(1000, max_groups)
        self.resolver = resolver

    def detect(
        self,
        observations: Sequence[FlowObservation],
        baseline: Mapping[str, float] | None = None,
        window_seconds: int = 60,
    ) -> list[AttackVector]:
        latest = max((row.observed_at for row in observations), default=utc_now())
        cutoff = latest - timedelta(seconds=window_seconds)
        groups: dict[str, list[FlowObservation]] = defaultdict(list)
        for row in observations:
            if row.observed_at < cutoff:
                continue
            parsed = ip_address(row.dst_ip)
            if parsed.version != 4:
                continue
            for length in PREFIX_LENGTHS_V4[1:]:
                if len(groups) >= self.max_groups:
                    break
                groups[str(ip_network(f"{parsed}/{length}", strict=False))].append(row)
        vectors = []
        for prefix, rows in groups.items():
            features = flow_features(rows, window_seconds)
            cf = carpet_bombing_features(rows, window_seconds, self.resolver)
            unique_hosts = features["unique_dst_ips"]
            aggregate_pps = features["packets_per_second"]
            bits_per_second = features["bits_per_second"]
            per_host = Counter()
            for row in rows:
                per_host[row.dst_ip] += row.packets
            max_host_pps = ratio(max(per_host.values(), default=0), window_seconds)
            historical = float((baseline or {}).get(prefix) or 0)
            deviation = ratio(aggregate_pps, historical) if historical else 0.0
            if unique_hosts < self.thresholds.carpet_unique_hosts:
                continue
            # Baseline is complementary evidence; an absolute traffic floor is mandatory.
            if features["packet_count"] < self.thresholds.carpet_min_packets:
                continue
            if aggregate_pps < self.thresholds.carpet_prefix_pps and bits_per_second < self.thresholds.carpet_min_bps:
                continue
            if max_host_pps >= self.thresholds.carpet_host_pps:
                continue

            # Absolute floor: a high relative baseline can never turn tiny
            # absolute traffic into a CONFIRMED_ATTACK.
            below_absolute_floor = bool(
                aggregate_pps < self.thresholds.carpet_min_absolute_pps
                and bits_per_second < self.thresholds.carpet_min_absolute_bps
            )
            web_return_likely = _carpet_web_return_likely(cf, self.thresholds)
            cgnat_or_isp_share = cf["target_cgnat_share"] + cf["target_downstream_isp_share"]
            persistence = safe_int(features.get("persistent_windows"))
            reflection = bool(
                cf["top_src_port"] in AMPLIFICATION_PORTS and cf["top_src_port_share"] >= 0.5
            )

            # Independent evidence categories (section 13). CONFIRMED_ATTACK
            # requires at least DISTRIBUTION + VOLUME + (ATTACK_PATTERN or
            # ANOMALOUS_SERVICE).
            categories_passed: set[str] = set()
            categories_failed: set[str] = set()
            if not below_absolute_floor:
                categories_passed.add("VOLUME")
            else:
                categories_failed.add("VOLUME")
            if unique_hosts >= self.thresholds.carpet_unique_hosts and features["unique_src_ips"] >= 20:
                categories_passed.add("DISTRIBUTION")
            else:
                categories_failed.add("DISTRIBUTION")
            if max_host_pps < self.thresholds.carpet_host_pps and persistence >= 2:
                categories_passed.add("ATTACK_PATTERN")
            else:
                categories_failed.add("ATTACK_PATTERN")
            if reflection:
                categories_passed.add("ANOMALOUS_SERVICE")
            else:
                categories_failed.add("ANOMALOUS_SERVICE")

            # Bidirectional network-context signal (positive and negative).
            network_context_points = 0
            if below_absolute_floor:
                network_context_points -= 15
            if web_return_likely:
                network_context_points -= 25
            elif cgnat_or_isp_share >= 0.5:
                network_context_points -= 12
            if cgnat_or_isp_share >= 0.7 and not reflection:
                network_context_points -= 8
            if reflection:
                network_context_points += 15
            if cf["known_infra_source_share"] >= 0.5 and not web_return_likely:
                network_context_points -= 10
            network_context_points = int(clamp(network_context_points, -45, 20))

            score_components = {
                "volume": min(30, int(math.log10(max(10, features["packet_count"])) * 7)),
                "host_distribution": min(20, int(unique_hosts / 2)),
                "low_per_host_rate": 12,
                "persistence": min(20, persistence * 4),
                "baseline": min(10, int(deviation * 2)) if deviation else 0,
                "threat_intel": 0,
                "network_context": network_context_points,
            }
            score = int(clamp(20 + sum(score_components.values())))

            # Final traffic classification and reason codes.
            reason_codes: list[str] = []
            traffic_classification = "CONFIRMED_ATTACK"
            if web_return_likely and below_absolute_floor:
                traffic_classification = EXPECTED_DISTRIBUTED_TRAFFIC
                reason_codes.extend(["LIKELY_WEB_RETURN_TRAFFIC", "ABSOLUTE_VOLUME_TOO_LOW"])
                score = min(score, 54)
            elif web_return_likely:
                traffic_classification = EXPECTED_DISTRIBUTED_TRAFFIC
                reason_codes.append("LIKELY_WEB_RETURN_TRAFFIC")
                score = min(score, 54)
            elif below_absolute_floor:
                traffic_classification = SUSPICIOUS_DISTRIBUTED_TRAFFIC
                reason_codes.append("ABSOLUTE_VOLUME_TOO_LOW")
                score = min(score, 54)
            elif cgnat_or_isp_share >= 0.7 and not reflection:
                traffic_classification = SUSPICIOUS_DISTRIBUTED_TRAFFIC
                reason_codes.append(
                    "CGNAT_DISTRIBUTION_EXPECTED"
                    if cf["target_cgnat_share"] >= cf["target_downstream_isp_share"]
                    else "DOWNSTREAM_ISP_DISTRIBUTION_EXPECTED"
                )
                score = min(score, 74)
            elif not (
                "VOLUME" in categories_passed
                and "DISTRIBUTION" in categories_passed
                and ("ATTACK_PATTERN" in categories_passed or "ANOMALOUS_SERVICE" in categories_passed)
            ):
                traffic_classification = SUSPICIOUS_DISTRIBUTED_TRAFFIC
                reason_codes.append("INSUFFICIENT_ATTACK_EVIDENCE")
                score = min(score, 74)
            if not reason_codes:
                reason_codes.append("CONFIRMED_CARPET_BOMBING")

            features.update(
                {
                    "protocol": "mixed",
                    "target_prefix": prefix,
                    "target_hosts": unique_hosts,
                    "max_host_pps": round(max_host_pps, 3),
                    "aggregate_pps": aggregate_pps,
                    "aggregate_bps": round(bits_per_second, 3),
                    "p95_host_pps": cf["p95_host_pps"],
                    "avg_pps_per_host": cf["avg_pps_per_host"],
                    "unique_src_ports": cf["unique_src_ports"],
                    "unique_dst_ports": cf["unique_dst_ports"],
                    "top_src_port": cf["top_src_port"],
                    "top_src_port_share": cf["top_src_port_share"],
                    "top_dst_port": cf["top_dst_port"],
                    "top_dst_port_share": cf["top_dst_port_share"],
                    "dst_port_entropy": cf["dst_port_entropy"],
                    "tcp_syn_ratio": cf["tcp_syn_ratio"],
                    "tcp_ack_ratio": cf["tcp_ack_ratio"],
                    "tcp_psh_ack_ratio": cf["tcp_psh_ack_ratio"],
                    "udp_quic_share": cf["udp_quic_share"],
                    "web_return_share": cf["web_return_share"],
                    "flows_s": cf["flows_s"],
                    "packets_per_flow": cf["packets_per_flow"],
                    "target_role_distribution": cf["target_role_distribution"],
                    "target_cgnat_share": cf["target_cgnat_share"],
                    "target_downstream_isp_share": cf["target_downstream_isp_share"],
                    "target_customer_public_share": cf["target_customer_public_share"],
                    "known_infra_source_share": cf["known_infra_source_share"],
                    "below_absolute_floor": below_absolute_floor,
                    "web_return_likely": web_return_likely,
                    "network_context_score": network_context_points,
                    "traffic_classification": traffic_classification,
                    "reason_codes": reason_codes,
                    "evidence_categories_passed": sorted(categories_passed),
                    "evidence_categories_failed": sorted(categories_failed),
                    "behavioral_score": score,
                }
            )
            vector = finalize_vector(
                AttackVector(
                    attack_type=CARPET_BOMBING,
                    detector=self.name,
                    detector_score=score,
                    confidence=round(score / 100.0, 3),
                    first_seen=features["first_seen"],
                    last_seen=features["last_seen"],
                    target_prefix=prefix,
                    protocol="mixed",
                    window_seconds=window_seconds,
                    baseline_deviation=round(deviation, 3),
                    features=features,
                    evidence=[
                        f"{features['packet_count']} pacotes para {unique_hosts} hosts em {window_seconds} segundos",
                        f"taxa agregada {aggregate_pps:.1f} pps; máximo por host {max_host_pps:.1f} pps",
                        f"{features['unique_src_ips']} fontes e {features['unique_source_asns']} ASNs",
                        f"web return share {cf['web_return_share'] * 100:.1f}%" if cf["web_return_share"] else "",
                        f"baseline {deviation:.2f}x" if deviation else "baseline ainda indisponível",
                    ],
                    score_components=score_components,
                )
            )
            if traffic_classification != "CONFIRMED_ATTACK":
                vector.verdict = "SUSPICIOUS" if traffic_classification == SUSPICIOUS_DISTRIBUTED_TRAFFIC else "INFO"
                vector.severity = "MEDIUM" if traffic_classification == SUSPICIOUS_DISTRIBUTED_TRAFFIC else "LOW"
                vector.features["verdict"] = vector.verdict
                vector.features["severity"] = vector.severity
            vectors.append(vector)
        return sorted(vectors, key=lambda item: (item.detector_score, ip_network(item.target_prefix).prefixlen), reverse=True)[:100]


def campaign_prefix(vector: AttackVector) -> str:
    target = vector.target_prefix or (f"{vector.target_ip}/32" if vector.target_ip else "")
    if not target:
        return ""
    try:
        network = ip_network(target, strict=False)
    except ValueError:
        return ""
    length = min(network.prefixlen, 24) if network.version == 4 else min(network.prefixlen, 64)
    return str(ip_network(f"{network.network_address}/{length}", strict=False))


class CampaignEngine:
    def __init__(self, campaign_id_factory: Callable[..., str] | None = None) -> None:
        self.campaign_id_factory = campaign_id_factory

    @staticmethod
    def new_campaign_id(campaign_key: str = "") -> str:
        stable = clean_text(campaign_key) or hashlib.sha256(f"{utc_now_iso()}|{os.getpid()}".encode()).hexdigest()
        return f"GMJ-C-{stable[:16].upper()}"

    def campaign_id_for(self, campaign_key: str) -> str:
        if self.campaign_id_factory is None:
            return self.new_campaign_id(campaign_key)
        try:
            return self.campaign_id_factory(campaign_key)  # type: ignore[call-arg]
        except TypeError:
            return self.campaign_id_factory()

    @staticmethod
    def semantic_key(classification: str, target_prefix: str, items: Sequence[AttackVector]) -> str:
        return CampaignEngine.semantic_key_from_attack_types(
            classification,
            target_prefix,
            {item.attack_type for item in items},
        )

    @staticmethod
    def semantic_key_from_attack_types(
        classification: str,
        target_prefix: str,
        attack_types: Sequence[str] | set[str],
    ) -> str:
        item_types = {clean_text(value) for value in attack_types if clean_text(value)}
        protocol_families = sorted({
            "tcp_syn" if "SYN" in attack_type else
            "udp" if "UDP" in attack_type else
            "scan" if attack_type in SCAN_ATTACK_TYPES else
            "other"
            for attack_type in item_types
        })
        campaign_family = (
            "FLOOD_FAMILY" if item_types & FLOOD_ATTACK_TYPES else
            "SCAN_FAMILY" if item_types & SCAN_ATTACK_TYPES else
            "OTHER_FAMILY"
        )
        identity = {
            "campaign_family": campaign_family,
            "classification": classification,
            "target_prefix": target_prefix,
            "protocol_families": protocol_families,
        }
        return hashlib.sha256(json_dump(identity).encode("utf-8")).hexdigest()

    def correlate(self, vectors: Sequence[AttackVector]) -> list[CampaignVector]:
        grouped: dict[str, list[AttackVector]] = defaultdict(list)
        for vector in vectors:
            prefix = campaign_prefix(vector)
            if prefix:
                grouped[prefix].append(vector)
        campaigns = []
        for prefix, items in grouped.items():
            types = {item.attack_type for item in items}
            scan_items = [item for item in items if item.attack_type in SCAN_ATTACK_TYPES]
            flood_items = [item for item in items if item.attack_type in FLOOD_ATTACK_TYPES]
            sources = {item.src_ip for item in items if item.src_ip}
            source_asns: set[int] = set()
            for item in items:
                source_asns.update(int(value) for value in item.features.get("source_asns", []) if int(value))
            unique_sources = max(len(sources), max((safe_int(item.features.get("unique_sources") or item.features.get("unique_src_ips")) for item in items), default=0))
            if len(items) < 2 and unique_sources < 20 and CARPET_BOMBING not in types:
                continue
            first = min(parse_time(item.first_seen) for item in items)
            last = max(parse_time(item.last_seen) for item in items)
            duration = max(1.0, (last - first).total_seconds())
            protocol_similarity = 1.0 if len(types & {SYN_FLOOD, DISTRIBUTED_SYN_FLOOD, SPOOFED_SYN_FLOOD}) == len(types) or len(types & {UDP_FLOOD, DISTRIBUTED_UDP_FLOOD, UDP_REFLECTION_SUSPECTED}) == len(types) else 0.5
            packet_sizes = [float(item.features.get("average_packet_size") or item.features.get("avg_bytes_per_flow") or 0) for item in items]
            packet_sizes = [value for value in packet_sizes if value > 0]
            packet_size_similarity = 0.0
            if packet_sizes:
                packet_size_similarity = clamp(1.0 - ratio(statistics.pstdev(packet_sizes), statistics.mean(packet_sizes)), 0, 1)
            target_similarity = min(1.0, len(items) / 4)
            source_arrival_rate = ratio(unique_sources, duration)
            source_churn_rate = min(1.0, ratio(unique_sources, max(1, sum(safe_int(item.features.get("flow_count")) for item in items))))
            intel_sources = sorted({source for item in items for source in item.intel_sources})
            c2_common = sum(safe_int(item.threat_intel.get("c2_sources")) for item in items)
            source_match_count = sum(
                safe_int((item.threat_intel.get("source_intel") or {}).get("match_count"))
                for item in items
            )
            source_matched_count = sum(
                safe_int((item.threat_intel.get("source_intel") or {}).get("matched_source_count") or (item.threat_intel.get("source_intel") or {}).get("matches"))
                for item in items
            )
            source_indicator_types = sorted({
                value
                for item in items
                for value in ((item.threat_intel.get("source_intel") or {}).get("indicator_types") or [])
            })
            source_classifications = sorted({
                value
                for item in items
                for value in ((item.threat_intel.get("source_intel") or {}).get("classifications") or [])
            })
            source_tags = sorted({
                value
                for item in items
                for value in ((item.threat_intel.get("source_intel") or {}).get("tags") or [])
            })[:50]
            target_observations = [
                observation
                for item in items
                for observation in ((item.threat_intel.get("target_campaign_intel") or {}).get("observations") or [])
            ][:20]
            packets_per_second = sum(float(item.features.get("packets_per_second") or item.features.get("pps") or 0) for item in items)
            bits_per_second = sum(float(item.features.get("bits_per_second") or item.features.get("bps") or 0) for item in items)
            flows_per_second = sum(float(item.features.get("flows_per_second") or 0) for item in items)
            persisted = duration >= 30 or max((safe_int(item.features.get("persistent_windows")) for item in items), default=0) >= 3
            target_correlated = len({campaign_prefix(item) for item in items if campaign_prefix(item)}) == 1
            ddos_minimum = (
                len(flood_items) >= 2
                and unique_sources >= int(os.getenv("GMJFLOW_CAMPAIGN_DDOS_MIN_SOURCES", "20"))
                and packets_per_second >= float(os.getenv("GMJFLOW_CAMPAIGN_DDOS_MIN_PPS", "200"))
                and bits_per_second >= float(os.getenv("GMJFLOW_CAMPAIGN_DDOS_MIN_BPS", "1000000"))
                and persisted
                and target_correlated
            )
            if flood_items and not scan_items and CARPET_BOMBING not in types and not ddos_minimum:
                continue
            score = int(
                clamp(
                    25
                    + min(25, unique_sources / 4)
                    + 15 * protocol_similarity
                    + 15 * target_similarity
                    + min(10, source_arrival_rate)
                    + (10 if c2_common else 0)
                )
            )
            if scan_items and not flood_items:
                classification = COORDINATED_SCANNING if unique_sources > 1 else SCANNING_CAMPAIGN
            elif CARPET_BOMBING in types and not ddos_minimum:
                classification = CARPET_BOMBING
            elif ddos_minimum and len({
                "tcp" if "SYN" in item.attack_type else "udp" if "UDP" in item.attack_type else item.attack_type
                for item in flood_items
            }) > 1:
                classification = MULTI_VECTOR_DDOS
            elif ddos_minimum:
                classification = COORDINATED_DDOS
            elif any(item.attack_type in {DISTRIBUTED_SYN_FLOOD, SPOOFED_SYN_FLOOD} for item in flood_items):
                classification = DISTRIBUTED_SYN_FLOOD
            elif any(item.attack_type in {DISTRIBUTED_UDP_FLOOD, UDP_REFLECTION_SUSPECTED} for item in flood_items):
                classification = DISTRIBUTED_UDP_FLOOD
            else:
                classification = SCANNING_CAMPAIGN if scan_items else SUSPICIOUS
            if c2_common and unique_sources >= 10 and ddos_minimum:
                classification = BOTNET_LIKELY
            campaign_key = self.semantic_key(classification, prefix, items)
            campaign_id = self.campaign_id_for(campaign_key)
            for item in items:
                item.campaign_id = campaign_id
            source_asn_count = max(
                len(source_asns),
                max((safe_int(item.features.get("unique_source_asns") or item.features.get("unique_src_asns")) for item in items), default=0),
            )
            campaigns.append(
                CampaignVector(
                    campaign_id=campaign_id,
                    target_prefix=prefix,
                    classification=classification,
                    unique_sources=unique_sources,
                    unique_source_asns=source_asn_count,
                    packets_per_second=round(packets_per_second, 3),
                    bits_per_second=round(bits_per_second, 3),
                    flows_per_second=round(flows_per_second, 3),
                    coordination_score=score,
                    first_seen=first.isoformat().replace("+00:00", "Z"),
                    last_seen=last.isoformat().replace("+00:00", "Z"),
                    campaign_key=campaign_key,
                    features={
                        "concurrent_sources": unique_sources,
                        "source_arrival_rate": round(source_arrival_rate, 4),
                        "source_churn_rate": round(source_churn_rate, 4),
                        "temporal_correlation": round(1.0 / max(1.0, duration / 60), 4),
                        "protocol_similarity": protocol_similarity,
                        "port_similarity": round(sum(1 for item in items if item.features.get("unique_dst_ports") == 1) / len(items), 4),
                        "packet_size_similarity": round(packet_size_similarity, 4),
                        "target_similarity": target_similarity,
                        "source_asn_diversity": source_asn_count,
                        "source_asns_sample": sorted(source_asns)[:100],
                        "attack_family": "SCAN_FAMILY" if scan_items and not flood_items else "FLOOD_FAMILY" if flood_items else "OTHER_FAMILY",
                        "ddos_minimum_satisfied": ddos_minimum,
                        "target_correlation": target_correlated,
                        "persistence_satisfied": persisted,
                        "common_c2_intelligence": c2_common,
                        "historical_recurrence": max((safe_int(item.features.get("historical_recurrence") or item.features.get("recurrence_count")) for item in items), default=0),
                        "attack_types": sorted(types),
                    },
                    threat_intel={
                        "matches": sum(safe_int(item.threat_intel.get("matches")) for item in items),
                        "source_intel": {
                            "matched_source_count": source_matched_count,
                            "match_count": source_match_count,
                            "indicator_types": source_indicator_types,
                            "classifications": source_classifications,
                            "tags": source_tags,
                            "intel_sources": sorted({
                                source
                                for item in items
                                for source in ((item.threat_intel.get("source_intel") or {}).get("intel_sources") or [])
                            }),
                        },
                        "target_campaign_intel": {
                            "matches": sum(
                                safe_int((item.threat_intel.get("target_campaign_intel") or {}).get("matches"))
                                for item in items
                            ),
                            "observations": target_observations,
                            "intel_sources": sorted({clean_text(item.get("provider")) for item in target_observations} - {""}),
                        },
                    },
                    intel_sources=intel_sources,
                )
            )
        return campaigns


def direction_for_flow(row: FlowObservation, customer_networks: Sequence[str]) -> str:
    networks = []
    for value in customer_networks:
        try:
            networks.append(ip_network(value, strict=False))
        except ValueError:
            continue
    src = ip_address(row.src_ip)
    dst = ip_address(row.dst_ip)
    src_internal = any(src.version == network.version and src in network for network in networks)
    dst_internal = any(dst.version == network.version and dst in network for network in networks)
    if src_internal and dst_internal:
        return "INTERNAL"
    if src_internal:
        return "OUTBOUND"
    if dst_internal:
        return "INBOUND"
    return "EXTERNAL"


def compromised_host_score(vectors: Sequence[AttackVector], c2_match: bool, recurrence_count: int = 0) -> int:
    score = 45 if c2_match else 0
    types = {item.attack_type for item in vectors}
    if types & {PORT_SCAN_VERTICAL, PORT_SCAN_HORIZONTAL, NETWORK_SWEEP, LOW_SLOW_SCAN}:
        score += 25
    if types & {SYN_FLOOD, DISTRIBUTED_SYN_FLOOD, UDP_FLOOD, DISTRIBUTED_UDP_FLOOD, UDP_REFLECTION_SUSPECTED}:
        score += 25
    if any(item.campaign_id for item in vectors):
        score += 10
    score += min(15, recurrence_count * 3)
    return int(clamp(score))


def ensure_behavioral_schema(conn: sqlite3.Connection) -> None:
    # One-time migration: the first v2 draft keyed on target_prefix. Because the
    # detector fans each destination out across 9 prefix lengths (IPv4 /22../32
    # + IPv6 /128), a per-prefix key still retained ~30% of rows. Rebuild the
    # (empty, shadow-only) table with the meta-only key defined below.
    _v2_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='behavior_safe_learning_shadow_audit_v2'"
    ).fetchone()
    if _v2_sql and "target_prefix" in (_v2_sql[0] or ""):
        conn.execute("DROP TABLE behavior_safe_learning_shadow_audit_v2")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS behavioral_attack_vectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL UNIQUE,
            attack_type TEXT NOT NULL,
            detector TEXT NOT NULL,
            detector_score INTEGER NOT NULL,
            confidence REAL NOT NULL,
            src_ip TEXT NOT NULL DEFAULT '',
            target_ip TEXT NOT NULL DEFAULT '',
            target_prefix TEXT NOT NULL DEFAULT '',
            direction TEXT NOT NULL,
            window_seconds INTEGER NOT NULL,
            baseline_deviation REAL NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            feature_json TEXT NOT NULL DEFAULT '{}',
            threat_intel_json TEXT NOT NULL DEFAULT '{}',
            intel_sources_json TEXT NOT NULL DEFAULT '[]',
            external_correlation INTEGER NOT NULL DEFAULT 0,
            compromised_host_score INTEGER NOT NULL DEFAULT 0,
            campaign_id TEXT NOT NULL DEFAULT '',
            decision_source TEXT NOT NULL DEFAULT 'GMJ_FLOW',
            status TEXT NOT NULL DEFAULT 'active',
            recurrence_count INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS threat_campaigns (
            campaign_id TEXT PRIMARY KEY,
            campaign_key TEXT NOT NULL DEFAULT '',
            target_prefix TEXT NOT NULL,
            classification TEXT NOT NULL,
            coordination_score INTEGER NOT NULL,
            unique_sources INTEGER NOT NULL,
            unique_source_asns INTEGER NOT NULL,
            packets_per_second REAL NOT NULL DEFAULT 0,
            bits_per_second REAL NOT NULL DEFAULT 0,
            flows_per_second REAL NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            feature_json TEXT NOT NULL DEFAULT '{}',
            threat_intel_json TEXT NOT NULL DEFAULT '{}',
            intel_sources_json TEXT NOT NULL DEFAULT '[]',
            decision_source TEXT NOT NULL DEFAULT 'GMJ_FLOW',
            status TEXT NOT NULL DEFAULT 'active',
            recurrence_count INTEGER NOT NULL DEFAULT 1,
            campaign_risk_score INTEGER NOT NULL DEFAULT 0,
            campaign_risk_band TEXT NOT NULL DEFAULT '',
            campaign_risk_components_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS gmj_threat_history (
            entity_type TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            first_seen_gmj TEXT NOT NULL,
            last_seen_gmj TEXT NOT NULL,
            attacks_seen INTEGER NOT NULL DEFAULT 0,
            campaigns_seen INTEGER NOT NULL DEFAULT 0,
            external_matches INTEGER NOT NULL DEFAULT 0,
            prior_mitigations INTEGER NOT NULL DEFAULT 0,
            recurrence_count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(entity_type, entity_key)
        );
        CREATE TABLE IF NOT EXISTS threat_engine_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            detector TEXT NOT NULL DEFAULT '',
            attack_vector_json TEXT NOT NULL DEFAULT '{}',
            campaign_vector_json TEXT NOT NULL DEFAULT '{}',
            threat_intel_json TEXT NOT NULL DEFAULT '{}',
            groq_result_json TEXT NOT NULL DEFAULT '{}',
            policy_result_json TEXT NOT NULL DEFAULT '{}',
            mitigation_decision_json TEXT NOT NULL DEFAULT '{}',
            flowspec_json TEXT NOT NULL DEFAULT '{}',
            router_response_json TEXT NOT NULL DEFAULT '{}',
            reason TEXT NOT NULL DEFAULT '',
            non_mitigation_reason TEXT NOT NULL DEFAULT '',
            ttl_seconds INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS prefix_behavior_baselines (
            prefix TEXT NOT NULL,
            protocol TEXT NOT NULL,
            packets_per_second_ema REAL NOT NULL DEFAULT 0,
            bits_per_second_ema REAL NOT NULL DEFAULT 0,
            sample_count INTEGER NOT NULL DEFAULT 0,
            baseline_state TEXT NOT NULL DEFAULT 'BOOTSTRAP',
            bootstrap_clean_count INTEGER NOT NULL DEFAULT 0,
            last_classification TEXT NOT NULL DEFAULT '',
            quarantined_until TEXT NOT NULL DEFAULT '',
            mad_pps REAL NOT NULL DEFAULT 0,
            rejected_count INTEGER NOT NULL DEFAULT 0,
            quarantined_count INTEGER NOT NULL DEFAULT 0,
            trusted_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            PRIMARY KEY(prefix, protocol)
        );
        CREATE TABLE IF NOT EXISTS behavioral_runtime_counters (
            hour TEXT PRIMARY KEY,
            observations INTEGER NOT NULL DEFAULT 0,
            runs INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS behavior_safe_learning_counters (
            hour TEXT NOT NULL,
            metric TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(hour, metric)
        );
        CREATE TABLE IF NOT EXISTS behavior_safe_learning_shadow_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL,
            sensor TEXT NOT NULL DEFAULT '',
            target_prefix TEXT NOT NULL,
            protocol TEXT NOT NULL,
            v1_would_update INTEGER NOT NULL DEFAULT 0,
            safe_would_update INTEGER NOT NULL DEFAULT 0,
            baseline_state TEXT NOT NULL DEFAULT '',
            classification TEXT NOT NULL,
            reason TEXT NOT NULL,
            observed_pps REAL NOT NULL DEFAULT 0,
            observed_bps REAL NOT NULL DEFAULT 0,
            baseline_pps REAL NOT NULL DEFAULT 0,
            baseline_bps REAL NOT NULL DEFAULT 0,
            mad_pps REAL NOT NULL DEFAULT 0,
            robust_z REAL,
            sample_count INTEGER NOT NULL DEFAULT 0,
            bootstrap_clean_count INTEGER NOT NULL DEFAULT 0,
            confirmed_attack INTEGER NOT NULL DEFAULT 0,
            strong_detector_signal INTEGER NOT NULL DEFAULT 0,
            quarantined_until TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_safe_learning_shadow_audit_time
            ON behavior_safe_learning_shadow_audit(observed_at);
        CREATE TABLE IF NOT EXISTS behavior_safe_learning_shadow_audit_v2 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hour_bucket TEXT NOT NULL,
            protocol TEXT NOT NULL,
            classification TEXT NOT NULL,
            reason TEXT NOT NULL,
            policy_version TEXT NOT NULL DEFAULT 'safe_learning_shadow_v2',
            evaluation_count INTEGER NOT NULL DEFAULT 0,
            would_learn_count INTEGER NOT NULL DEFAULT 0,
            rejected_count INTEGER NOT NULL DEFAULT 0,
            quarantined_count INTEGER NOT NULL DEFAULT 0,
            confirmed_attack_count INTEGER NOT NULL DEFAULT 0,
            strong_detector_signal_count INTEGER NOT NULL DEFAULT 0,
            protected_or_internal_count INTEGER NOT NULL DEFAULT 0,
            campaign_blocked_count INTEGER NOT NULL DEFAULT 0,
            robust_z_min REAL,
            robust_z_max REAL,
            robust_z_sum REAL,
            robust_z_count INTEGER NOT NULL DEFAULT 0,
            baseline_state TEXT NOT NULL DEFAULT '',
            sample_prefix TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(hour_bucket, protocol, classification, reason)
        );
        CREATE INDEX IF NOT EXISTS idx_safe_learning_shadow_v2_time
            ON behavior_safe_learning_shadow_audit_v2(hour_bucket);
        CREATE INDEX IF NOT EXISTS idx_behavior_vectors_status_time
            ON behavioral_attack_vectors(status, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_behavior_vectors_campaign
            ON behavioral_attack_vectors(campaign_id, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_threat_campaigns_status_time
            ON threat_campaigns(status, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_threat_engine_audit_time
            ON threat_engine_audit(created_at DESC);
        """
    )
    campaign_columns = {
        row["name"] if isinstance(row, sqlite3.Row) else row[1]
        for row in conn.execute("PRAGMA table_info(threat_campaigns)").fetchall()
    }
    if "campaign_key" not in campaign_columns:
        conn.execute("ALTER TABLE threat_campaigns ADD COLUMN campaign_key TEXT NOT NULL DEFAULT ''")
    if "recurrence_count" not in campaign_columns:
        conn.execute("ALTER TABLE threat_campaigns ADD COLUMN recurrence_count INTEGER NOT NULL DEFAULT 1")
    if "campaign_risk_score" not in campaign_columns:
        conn.execute("ALTER TABLE threat_campaigns ADD COLUMN campaign_risk_score INTEGER NOT NULL DEFAULT 0")
    if "campaign_risk_band" not in campaign_columns:
        conn.execute("ALTER TABLE threat_campaigns ADD COLUMN campaign_risk_band TEXT NOT NULL DEFAULT ''")
    if "campaign_risk_components_json" not in campaign_columns:
        conn.execute("ALTER TABLE threat_campaigns ADD COLUMN campaign_risk_components_json TEXT NOT NULL DEFAULT '{}'")
    baseline_columns = {
        row["name"] if isinstance(row, sqlite3.Row) else row[1]
        for row in conn.execute("PRAGMA table_info(prefix_behavior_baselines)").fetchall()
    }
    baseline_additions = {
        "baseline_state": "baseline_state TEXT NOT NULL DEFAULT 'BOOTSTRAP'",
        "bootstrap_clean_count": "bootstrap_clean_count INTEGER NOT NULL DEFAULT 0",
        "last_classification": "last_classification TEXT NOT NULL DEFAULT ''",
        "quarantined_until": "quarantined_until TEXT NOT NULL DEFAULT ''",
        "mad_pps": "mad_pps REAL NOT NULL DEFAULT 0",
        "rejected_count": "rejected_count INTEGER NOT NULL DEFAULT 0",
        "quarantined_count": "quarantined_count INTEGER NOT NULL DEFAULT 0",
        "trusted_at": "trusted_at TEXT NOT NULL DEFAULT ''",
        "mad_sample_count": "mad_sample_count INTEGER NOT NULL DEFAULT 0",
    }
    for column, ddl in baseline_additions.items():
        if column not in baseline_columns:
            conn.execute(f"ALTER TABLE prefix_behavior_baselines ADD COLUMN {ddl}")
    legacy_campaigns = conn.execute(
        "SELECT campaign_id, target_prefix, classification, feature_json FROM threat_campaigns WHERE campaign_key=''"
    ).fetchall()
    for row in legacy_campaigns:
        item = dict(row) if isinstance(row, sqlite3.Row) else {
            "campaign_id": row[0], "target_prefix": row[1], "classification": row[2], "feature_json": row[3]
        }
        features = safe_json(item.get("feature_json"), {})
        key = CampaignEngine.semantic_key_from_attack_types(
            clean_text(item.get("classification")),
            clean_text(item.get("target_prefix")),
            features.get("attack_types") or [],
        )
        conn.execute(
            "UPDATE threat_campaigns SET campaign_key=? WHERE campaign_id=? AND campaign_key=''",
            (key, item["campaign_id"]),
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_threat_campaigns_key ON threat_campaigns(campaign_key, last_seen DESC)"
    )


def event_key(vector: AttackVector) -> str:
    return canonical_event_key(
        vector.detector,
        vector.attack_type,
        vector.src_ip,
        vector.target_ip,
        vector.target_prefix,
        vector.direction,
        vector.protocol,
    )


class BehavioralDetectionEngine:
    def __init__(
        self,
        connection_factory: Callable[[], sqlite3.Connection],
        intel_manager: ThreatIntelManager,
        thresholds: DetectorThresholds | None = None,
    ) -> None:
        self.connection_factory = connection_factory
        self.intel_manager = intel_manager
        self.thresholds = thresholds or DetectorThresholds.from_env()
        self.port_scan = PortScanDetector(self.thresholds)
        self.ssh_brute_force = SshBruteForceDetector(self.thresholds)
        self.syn_flood = SynFloodDetector(self.thresholds)
        self.udp_flood = UdpFloodDetector(self.thresholds)
        self.asset_resolver = NetworkAssetResolver(connection_factory)
        self.carpet = CarpetBombingDetector(
            self.thresholds,
            max_groups=int(os.getenv("GMJFLOW_BEHAVIOR_MAX_PREFIX_GROUPS", "50000")),
            resolver=self.asset_resolver.resolve,
        )
        self.campaigns = CampaignEngine()
        self.network_context = NetworkContextEngine(connection_factory)
        self._last_observations: list[FlowObservation] = []
        self._last_shadow_audit_cleanup = 0.0

    def ensure_schema(self) -> None:
        with self.connection_factory() as conn:
            ensure_behavioral_schema(conn)
            ensure_security_event_schema(conn)
            ensure_network_assets_schema(conn)
            migrate_legacy_security_events(conn)
            conn.commit()

    def prefix_baselines(self, protocol: str) -> dict[str, float]:
        self.ensure_schema()
        with self.connection_factory() as conn:
            rows = conn.execute(
                "SELECT prefix, packets_per_second_ema FROM prefix_behavior_baselines WHERE protocol = ?",
                (clean_text(protocol).lower(),),
            ).fetchall()
        return {clean_text(row[0]): float(row[1] or 0) for row in rows}

    def enrich_internal_history(self, vectors: Sequence[AttackVector]) -> None:
        if not vectors:
            return
        with self.connection_factory() as conn:
            for vector in vectors:
                key = vector.src_ip or vector.target_ip or vector.target_prefix
                if not key:
                    continue
                row = conn.execute(
                    "SELECT recurrence_count, prior_mitigations FROM gmj_threat_history WHERE entity_type='IP' AND entity_key=?",
                    (key,),
                ).fetchone()
                if row is None:
                    continue
                vector.features["historical_recurrence"] = safe_int(row[0])
                vector.features["prior_mitigations"] = safe_int(row[1])

    def update_prefix_baselines(
        self,
        conn: sqlite3.Connection,
        observations: Sequence[FlowObservation],
        window_seconds: int = 60,
        vectors: Sequence[AttackVector] = (),
    ) -> None:
        groups: dict[tuple[str, str], list[Any]] = defaultdict(lambda: [0, 0, ""])
        maximum = max(1000, int(os.getenv("GMJFLOW_BEHAVIOR_MAX_PREFIX_GROUPS", "50000")))
        now_dt = utc_now()
        now = utc_now_iso()
        alpha = clamp(float(os.getenv("GMJFLOW_BEHAVIOR_BASELINE_ALPHA", "0.1")), 0.01, 0.5)
        safe_enabled = behavior_safe_learning_enabled(conn)
        mad_absolute_floor = max(0.0, float(os.getenv("GMJFLOW_SAFE_MAD_ABSOLUTE_FLOOR_PPS", str(DEFAULT_MAD_ABSOLUTE_FLOOR_PPS))))
        mad_relative_floor_ratio = max(0.0, float(os.getenv("GMJFLOW_SAFE_MAD_RELATIVE_FLOOR_RATIO", str(DEFAULT_MAD_RELATIVE_FLOOR_RATIO))))

        # Guardrail inputs (deterministic, reused system owners).
        customer_networks: list[Any] = []
        try:
            rows = conn.execute(
                "SELECT p.cidr FROM ip_zone_prefixes p "
                "JOIN ip_zones z ON z.id = p.zone_id "
                "WHERE p.active = 1 AND z.active = 1"
            ).fetchall()
            for row in rows:
                cidr = clean_text(row[0])
                if not cidr:
                    continue
                try:
                    customer_networks.append(ip_network(cidr, strict=False))
                except ValueError:
                    continue
        except sqlite3.OperationalError:
            customer_networks = []

        # Exclude future clock-skewed observations (documented NE8000 exporter
        # bug): a far-future timestamp would otherwise become max(observed_at)
        # and make the window cutoff discard every legitimate observation.
        # Past-skew is already handled upstream by the SQL lookback and here by
        # the 60s cutoff relative to the newest valid observation.
        skewed_observations = 0
        clean_observations: list[FlowObservation] = []
        for row in observations:
            delta = (row.observed_at - now_dt).total_seconds()
            if delta > DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS:
                skewed_observations += 1
                continue
            clean_observations.append(row)

        latest = max((row.observed_at for row in clean_observations), default=now_dt)
        cutoff = latest - timedelta(seconds=window_seconds)
        for row in clean_observations:
            if row.observed_at < cutoff:
                continue
            protocol = "tcp" if row.protocol == 6 else "udp" if row.protocol == 17 else "other"
            for prefix in target_prefixes(row.dst_ip):
                key = (prefix, protocol)
                if key not in groups and len(groups) >= maximum:
                    break
                groups[key][0] += row.packets
                groups[key][1] += row.bytes
                if not groups[key][2]:
                    groups[key][2] = row.sensor

        attack_networks: list[Any] = []
        confirmed_networks: list[Any] = []
        campaign_networks: list[Any] = []
        for vector in vectors:
            target = vector.target_prefix or (f"{vector.target_ip}/32" if vector.target_ip else "")
            if not target:
                continue
            try:
                network = ip_network(target, strict=False)
            except ValueError:
                continue
            attack_networks.append(network)
            if vector.verdict == "CONFIRMED_ATTACK" or clean_text(vector.severity).upper() == "CRITICAL":
                confirmed_networks.append(network)
            if clean_text(getattr(vector, "campaign_id", "") or ""):
                campaign_networks.append(network)

        counters: dict[str, int] = defaultdict(int)
        if skewed_observations:
            counters["clock_skew_observations"] = skewed_observations
            counters["safe_reason_clock_skew"] = skewed_observations

        eligible_sample_rate = max(0, int(os.getenv("GMJFLOW_SAFE_SHADOW_AUDIT_ELIGIBLE_SAMPLE_RATE", "0")))
        eligible_seen = 0

        for (prefix, protocol), (packets, byte_count, sensor) in groups.items():
            pps = ratio(packets, max(1, window_seconds))
            bps = ratio(byte_count * 8, max(1, window_seconds))
            current = conn.execute(
                "SELECT packets_per_second_ema, bits_per_second_ema, sample_count, baseline_state, "
                "bootstrap_clean_count, mad_pps, quarantined_until, rejected_count, quarantined_count, "
                "trusted_at, mad_sample_count "
                "FROM prefix_behavior_baselines WHERE prefix=? AND protocol=?",
                (prefix, protocol),
            ).fetchone()

            # V1 EMA update (unchanged math).
            if current is None:
                next_pps, next_bps, samples = pps, bps, 1
                old_pps, old_bps, old_mad = pps, bps, 0.0
                old_mad_sample_count = 0
            else:
                old_pps, old_bps, old_samples = float(current[0] or 0), float(current[1] or 0), safe_int(current[2])
                old_mad = float(current[5] or 0)
                old_mad_sample_count = safe_int(current[10])
                bounded_pps = min(pps, old_pps * 3) if old_samples >= 5 and old_pps > 0 else pps
                bounded_bps = min(bps, old_bps * 3) if old_samples >= 5 and old_bps > 0 else bps
                next_pps = old_pps * (1 - alpha) + bounded_pps * alpha
                next_bps = old_bps * (1 - alpha) + bounded_bps * alpha
                samples = old_samples + 1

            state, clean_count = self._safe_state(current, samples)
            strong_signal, confirmed_attack = _attack_signal(prefix, attack_networks, confirmed_networks)
            protected_or_internal = _is_protected_subject(conn, prefix) or _overlaps_any_network(prefix, customer_networks)
            campaign_blocked = _overlaps_any_network(prefix, campaign_networks)
            robust_stats_ready = old_mad > 0 and old_mad_sample_count >= DEFAULT_MIN_ROBUST_SAMPLES
            decision = safe_learning_decision(
                baseline_state=state,
                bootstrap_clean_count=clean_count,
                sample_count=samples,
                ema_pps=old_pps,
                mad_pps=old_mad,
                window_pps=pps,
                confirmed_attack=confirmed_attack,
                strong_detector_signal=strong_signal,
                quarantined_until=clean_text(current[6]) if current is not None else "",
                now_iso=now,
                robust_stats_ready=robust_stats_ready,
                protected_or_internal=protected_or_internal,
                campaign_blocked=campaign_blocked,
                mad_absolute_floor=mad_absolute_floor,
                mad_relative_floor_ratio=mad_relative_floor_ratio,
            )
            classification = decision["classification"]
            final_state = decision["next_state"]
            final_clean = decision["next_clean_count"]
            next_quarantine = decision["next_quarantined_until"]
            rejected_count = safe_int(current[7]) if current is not None else 0
            quarantined_count = safe_int(current[8]) if current is not None else 0
            trusted_at = clean_text(current[9]) if current is not None else ""

            if classification == REJECTED:
                rejected_count += 1
            elif classification == QUARANTINED:
                quarantined_count += 1
            if final_state == TRUSTED and not trusted_at:
                trusted_at = now

            if classification == ELIGIBLE and decision["should_update"]:
                next_mad = old_mad * (1 - alpha) + abs(pps - next_pps) * alpha
                next_mad_sample_count = old_mad_sample_count + 1
            else:
                next_mad = old_mad
                next_mad_sample_count = old_mad_sample_count

            # Explicit V1-vs-Safe observability. V1 legacy math always updates;
            # Safe proposes should_update. While the feature is OFF the actual
            # applied update remains V1.
            v1_would_update = True
            safe_would_update = bool(decision["should_update"])
            divergence = v1_would_update != safe_would_update
            update_allowed = (not safe_enabled) or safe_would_update
            applied_pps = next_pps if update_allowed else old_pps
            applied_bps = next_bps if update_allowed else old_bps
            applied_samples = samples if update_allowed else (safe_int(current[2]) if current is not None else 0)

            conn.execute(
                """
                INSERT INTO prefix_behavior_baselines(
                    prefix, protocol, packets_per_second_ema, bits_per_second_ema, sample_count,
                    baseline_state, bootstrap_clean_count, last_classification, quarantined_until,
                    mad_pps, rejected_count, quarantined_count, trusted_at, mad_sample_count, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(prefix, protocol) DO UPDATE SET
                    packets_per_second_ema=excluded.packets_per_second_ema,
                    bits_per_second_ema=excluded.bits_per_second_ema,
                    sample_count=excluded.sample_count,
                    baseline_state=excluded.baseline_state,
                    bootstrap_clean_count=excluded.bootstrap_clean_count,
                    last_classification=excluded.last_classification,
                    quarantined_until=excluded.quarantined_until,
                    mad_pps=excluded.mad_pps,
                    rejected_count=excluded.rejected_count,
                    quarantined_count=excluded.quarantined_count,
                    trusted_at=excluded.trusted_at,
                    mad_sample_count=excluded.mad_sample_count,
                    updated_at=excluded.updated_at
                """,
                (
                    prefix, protocol, applied_pps, applied_bps, applied_samples,
                    final_state, final_clean, classification, next_quarantine,
                    next_mad, rejected_count, quarantined_count, trusted_at,
                    next_mad_sample_count, now,
                ),
            )

            # Hourly observability counters (V1 x Safe, reasons, readiness).
            counters["v1_updates_allowed"] += 1
            if safe_would_update:
                counters["safe_updates_allowed"] += 1
            else:
                counters["safe_updates_blocked"] += 1
            if divergence:
                counters["safe_v1_divergence"] += 1
            else:
                counters["safe_v1_same"] += 1
            if robust_stats_ready:
                counters["robust_stats_ready"] += 1
            else:
                counters["robust_stats_not_ready"] += 1
            counters[f"safe_reason_{safe_reason_bucket(decision['reason'])}"] += 1

            if final_state == BOOTSTRAP:
                counters["bootstrap"] += 1
            if decision["promoted"]:
                counters["promoted_to_trusted"] += 1
            if classification == ELIGIBLE:
                counters["eligible"] += 1
            elif classification == QUARANTINED:
                counters["quarantined"] += 1
            elif classification == REJECTED:
                counters["rejected"] += 1
            if update_allowed:
                counters["baseline_updates_allowed"] += 1
            else:
                counters["baseline_updates_blocked"] += 1

            # Compact shadow audit v2: aggregate by (hour, prefix, protocol,
            # classification, reason) instead of one row per evaluation. This
            # collapses the repetitive quarantine_frozen / quarantine_extended /
            # robust_z re-evaluations into a few counter rows per hour.
            audit_z: float | None = None
            if old_pps > 0:
                audit_z = round(robust_z_score(
                    pps, old_pps,
                    effective_mad(old_pps, old_mad,
                                  absolute_floor=mad_absolute_floor,
                                  relative_floor_ratio=mad_relative_floor_ratio),
                ), 4)
            if classification == ELIGIBLE:
                eligible_seen += 1
                sample_hit = eligible_sample_rate > 0 and eligible_seen % eligible_sample_rate == 0
            else:
                sample_hit = False
            if divergence or classification in (REJECTED, QUARANTINED) or decision["promoted"] or sample_hit:
                _record_safe_learning_audit_v2(
                    conn,
                    now_iso=now,
                    prefix=prefix,
                    protocol=protocol,
                    classification=classification,
                    reason=decision["reason"],
                    safe_would_update=bool(safe_would_update),
                    confirmed_attack=bool(confirmed_attack),
                    strong_signal=bool(strong_signal),
                    protected_or_internal=bool(protected_or_internal),
                    campaign_blocked=bool(campaign_blocked),
                    audit_z=audit_z,
                    baseline_state=final_state,
                )

        self._record_safe_learning_counters(conn, counters, now)
        self._cleanup_shadow_audit(conn, now_dt)


    @staticmethod
    def _safe_state(current: Any, samples: int) -> tuple[str, int]:
        if current is None:
            return BOOTSTRAP, 0
        stored_state = clean_text(current[3])
        clean_count = safe_int(current[4])
        trusted_at = clean_text(current[9])
        if stored_state == TRUSTED:
            return TRUSTED, clean_count
        # Legacy pre-safe-learning baselines (or mature-enough history): derive
        # TRUSTED opportunistically. Fresh rows promote at ~12 clean windows
        # (sample_count ~= 12), long before 24, so sample_count >= 24 while
        # not-yet-trusted implies legacy maturity. No mass UPDATE on disk.
        if samples >= DEFAULT_MIN_QUARANTINE_SAMPLES and not trusted_at:
            return TRUSTED, 0
        return BOOTSTRAP, clean_count

    def _record_safe_learning_counters(self, conn: sqlite3.Connection, counters: Mapping[str, int], now_iso: str) -> None:
        if not counters:
            return
        hour = clean_text(now_iso)[:13] + ":00:00Z"
        for metric, value in counters.items():
            conn.execute(
                """
                INSERT INTO behavior_safe_learning_counters(hour, metric, count, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(hour, metric) DO UPDATE SET
                    count = count + excluded.count, updated_at = excluded.updated_at
                """,
                (hour, metric, int(value), now_iso),
            )

    def _cleanup_shadow_audit(self, conn: sqlite3.Connection, now_dt: datetime) -> None:
        """Throttled retention for the shadow audit table (72h, no unbounded growth)."""
        now_epoch = now_dt.timestamp()
        if now_epoch - self._last_shadow_audit_cleanup < 3600:
            return
        self._last_shadow_audit_cleanup = now_epoch
        cutoff_iso = (now_dt - timedelta(hours=72)).isoformat().replace("+00:00", "Z")
        conn.execute(
            "DELETE FROM behavior_safe_learning_shadow_audit WHERE observed_at < ?",
            (cutoff_iso,),
        )
        conn.execute(
            "DELETE FROM behavior_safe_learning_shadow_audit_v2 WHERE hour_bucket < ?",
            (cutoff_iso,),
        )

    def detect(self, raw_observations: Iterable[Mapping[str, Any]], customer_networks: Sequence[str] = ()) -> tuple[list[AttackVector], list[CampaignVector]]:
        limit = max(1000, int(os.getenv("GMJFLOW_BEHAVIOR_MAX_OBSERVATIONS", "100000")))
        observations = []
        for raw in raw_observations:
            item = FlowObservation.from_mapping(raw)
            if item:
                observations.append(item)
            if len(observations) >= limit:
                break
        self._last_observations = observations
        lookup = cached_intel_lookup(self.intel_manager.lookup_ip)
        tcp_baseline = self.prefix_baselines("tcp")
        udp_baseline = self.prefix_baselines("udp")
        carpet_baseline = {**tcp_baseline}
        for prefix, value in udp_baseline.items():
            carpet_baseline[prefix] = carpet_baseline.get(prefix, 0) + value
        scan_vectors = self.port_scan.detect(observations, lookup)
        ssh_vectors = self.ssh_brute_force.detect(observations, lookup)
        for scan_vector in scan_vectors:
            ssh_summary = self.ssh_brute_force.last_suppressed_multi_target.get(scan_vector.src_ip)
            if not ssh_summary or scan_vector.attack_type not in {PORT_SCAN_HORIZONTAL, NETWORK_SWEEP}:
                continue
            scan_vector.features["ssh_multi_target_evidence"] = dict(ssh_summary)
            scan_vector.evidence.append(
                f"padrão TCP/22 multi-alvo: {ssh_summary['attempts']} tentativas persistentes "
                f"em {ssh_summary['qualifying_targets']} de {ssh_summary['target_count']} hosts; "
                "vetores SSH por host suprimidos"
            )
        vectors = [*scan_vectors, *ssh_vectors]
        vectors += self.syn_flood.detect(observations, lookup, tcp_baseline)
        vectors += self.udp_flood.detect(observations, lookup, udp_baseline)
        vectors += self.carpet.detect(observations, carpet_baseline)
        by_source: dict[str, list[AttackVector]] = defaultdict(list)
        for vector in vectors:
            vector.threat_intel.setdefault("source_intel", {
                "matches": 0, "match_count": 0, "sources": {}, "intel_sources": [],
                "lookup_count": 0, "lookup_truncated": False,
            })
            vector.threat_intel.setdefault("target_campaign_intel", {"matches": 0, "observations": []})
            if vector.src_ip:
                by_source[vector.src_ip].append(vector)
            target_network = None
            if vector.target_prefix:
                try:
                    target_network = ip_network(vector.target_prefix, strict=False)
                except ValueError:
                    target_network = None
            evidence_rows = [
                row for row in observations
                if (vector.src_ip and row.src_ip == vector.src_ip)
                or (vector.target_ip and row.dst_ip == vector.target_ip)
                or (
                    target_network is not None
                    and ip_address(row.dst_ip).version == target_network.version
                    and ip_address(row.dst_ip) in target_network
                )
            ]
            if evidence_rows:
                representative = evidence_rows[0]
                context = self.network_context.resolve(
                    representative.src_ip,
                    representative.dst_ip,
                    representative.input_if,
                    representative.output_if,
                    sensor=representative.sensor,
                    exporter=representative.exporter_ip,
                ).as_dict()
                if context["traffic_direction"] in {"EXTERNAL", "UNKNOWN"} and customer_networks:
                    legacy_direction = direction_for_flow(representative, customer_networks)
                    if legacy_direction != "EXTERNAL":
                        context["traffic_direction"] = legacy_direction
                        if legacy_direction == "INBOUND":
                            context["dst_role"] = "CUSTOMER"
                        elif legacy_direction == "OUTBOUND":
                            context["src_role"] = "CUSTOMER"
                        elif legacy_direction == "INTERNAL":
                            context["src_role"] = context["dst_role"] = "CUSTOMER"
                vector.network_context = context
                vector.direction = context["traffic_direction"]
                vector.features.update({
                    "network_context": context,
                    "src_role": context["src_role"],
                    "dst_role": context["dst_role"],
                    "src_is_cgnat": context["src_is_cgnat"],
                    "dst_is_cgnat": context["dst_is_cgnat"],
                    "input_if": context["input_if"],
                    "output_if": context["output_if"],
                    "sensor": context["sensor"],
                    "exporter": context["exporter"],
                })
                if context["dst_is_cgnat"]:
                    vector.evidence.append(
                        "o destino é CGNAT_PUBLIC; diversidade de conexões é contexto esperado e não prova ataque"
                    )
            target = vector.target_prefix or (f"{vector.target_ip}/32" if vector.target_ip else "")
            if target:
                correlations = self.intel_manager.external_attack_matches(target, "tcp" if "SYN" in vector.attack_type else "udp" if "UDP" in vector.attack_type else "", vector.last_seen)
                if correlations:
                    vector.external_correlation = True
                    vector.detector_score = int(clamp(vector.detector_score + 8))
                    vector.confidence = round(clamp(vector.confidence + 0.08, 0, 1), 3)
                    vector.threat_intel["target_campaign_intel"] = {
                        "matches": len(correlations),
                        "observations": correlations[:20],
                        "intel_sources": sorted({clean_text(item.get("provider")) for item in correlations} - {""}),
                    }
                    vector.intel_sources = sorted((set(vector.intel_sources) | {clean_text(item.get("provider")) for item in correlations}) - {""})
                    vector.score_components["threat_intel"] = min(10, safe_int(vector.score_components.get("threat_intel")) + 8)
            finalize_vector(vector)
        self.enrich_internal_history(vectors)
        campaigns = self.campaigns.correlate(vectors)
        for source, items in by_source.items():
            source_matches = []
            for item in items:
                source_matches.extend((item.threat_intel.get("source_intel") or {}).get("sources", {}).get(source, []))
            c2 = any(clean_text(match.get("indicator_type")).upper() == "C2" for match in source_matches)
            recurrence = max((safe_int(item.features.get("historical_recurrence")) for item in items), default=0)
            score = compromised_host_score(items, c2, recurrence)
            for item in items:
                item.compromised_host_score = score
                if score >= 70 and item.direction == "OUTBOUND":
                    item.features["host_classification"] = COMPROMISED_CUSTOMER
        return vectors, campaigns

    def persist(self, vectors: Sequence[AttackVector], campaigns: Sequence[CampaignVector]) -> dict[str, int]:
        self.ensure_schema()
        stats = {"vectors": 0, "campaigns": 0}
        now = utc_now_iso()
        with self.connection_factory() as conn:
            self.update_prefix_baselines(conn, self._last_observations, vectors=vectors)
            for campaign in campaigns:
                existing = conn.execute(
                    "SELECT campaign_id FROM threat_campaigns WHERE campaign_key=? ORDER BY last_seen DESC LIMIT 1",
                    (campaign.campaign_key,),
                ).fetchone()
                if existing is None:
                    continue
                generated_id = campaign.campaign_id
                campaign.campaign_id = clean_text(existing[0])
                for vector in vectors:
                    if vector.campaign_id == generated_id:
                        vector.campaign_id = campaign.campaign_id
            for vector in vectors:
                key = event_key(vector)
                conn.execute(
                    """
                    INSERT INTO behavioral_attack_vectors (
                        event_key, attack_type, detector, detector_score, confidence, src_ip,
                        target_ip, target_prefix, direction, window_seconds, baseline_deviation,
                        first_seen, last_seen, feature_json, threat_intel_json, intel_sources_json,
                        external_correlation, compromised_host_score, campaign_id, decision_source,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(event_key) DO UPDATE SET
                        detector_score=MAX(detector_score, excluded.detector_score),
                        confidence=MAX(confidence, excluded.confidence), last_seen=excluded.last_seen,
                        feature_json=excluded.feature_json, threat_intel_json=excluded.threat_intel_json,
                        intel_sources_json=excluded.intel_sources_json,
                        external_correlation=excluded.external_correlation,
                        compromised_host_score=excluded.compromised_host_score,
                        campaign_id=excluded.campaign_id, recurrence_count=recurrence_count+1,
                        updated_at=excluded.updated_at
                    """,
                    (
                        key, vector.attack_type, vector.detector, vector.detector_score, vector.confidence,
                        vector.src_ip, vector.target_ip, vector.target_prefix, vector.direction,
                        vector.window_seconds, vector.baseline_deviation, vector.first_seen, vector.last_seen,
                        json_dump(vector.features), json_dump(vector.threat_intel), json_dump(vector.intel_sources),
                        int(vector.external_correlation), vector.compromised_host_score, vector.campaign_id,
                        vector.decision_source, now, now,
                    ),
                )
                self._history(conn, "IP", vector.src_ip or vector.target_ip or vector.target_prefix, attacks=1, external=int(bool(vector.intel_sources)))
                upsert_security_event(conn, vector)
                self._audit(conn, "DETECTOR_RESULT", vector=vector)
                self._audit(conn, "CONTEXT_RESOLUTION", vector=vector, reason=vector.direction)
                self._audit(
                    conn,
                    "THREAT_INTEL_ENRICHMENT",
                    vector=vector,
                    reason=clean_text(vector.features.get("threat_intel_relevance")) or "enrichment_only",
                )
                stats["vectors"] += 1
            for campaign in campaigns:
                campaign_vectors = [item.as_dict() for item in vectors if item.campaign_id == campaign.campaign_id]
                try:
                    event_rows = conn.execute(
                        "SELECT * FROM security_events WHERE campaign_id=?",
                        (campaign.campaign_id,),
                    ).fetchall()
                except sqlite3.OperationalError:
                    event_rows = []
                campaign_context = evaluate_campaign_context(
                    campaign.as_dict(),
                    vectors=campaign_vectors,
                    correlated_events=[security_event_row(item) for item in event_rows],
                )
                campaign_risk = calculate_campaign_risk_score(
                    coordination_score=campaign.coordination_score,
                    recurrence_count=campaign.recurrence_count,
                    context_evaluation=campaign_context,
                    persistence_satisfied=bool(campaign.features.get("persistence_satisfied")),
                )
                conn.execute(
                    """
                    INSERT INTO threat_campaigns (
                        campaign_id, campaign_key, target_prefix, classification, coordination_score,
                        unique_sources, unique_source_asns, packets_per_second, bits_per_second,
                        flows_per_second, first_seen, last_seen, feature_json, threat_intel_json,
                        intel_sources_json, decision_source, campaign_risk_score, campaign_risk_band,
                        campaign_risk_components_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(campaign_id) DO UPDATE SET
                        campaign_key=excluded.campaign_key,
                        coordination_score=MAX(coordination_score, excluded.coordination_score),
                        unique_sources=MAX(unique_sources, excluded.unique_sources),
                        unique_source_asns=MAX(unique_source_asns, excluded.unique_source_asns),
                        packets_per_second=MAX(packets_per_second, excluded.packets_per_second),
                        bits_per_second=MAX(bits_per_second, excluded.bits_per_second),
                        flows_per_second=MAX(flows_per_second, excluded.flows_per_second),
                        first_seen=MIN(first_seen, excluded.first_seen),
                        last_seen=MAX(last_seen, excluded.last_seen),
                        recurrence_count=recurrence_count+1,
                        feature_json=excluded.feature_json,
                        threat_intel_json=excluded.threat_intel_json,
                        intel_sources_json=excluded.intel_sources_json,
                        campaign_risk_score=excluded.campaign_risk_score,
                        campaign_risk_band=excluded.campaign_risk_band,
                        campaign_risk_components_json=excluded.campaign_risk_components_json,
                        updated_at=excluded.updated_at
                    """,
                    (
                        campaign.campaign_id, campaign.campaign_key, campaign.target_prefix, campaign.classification,
                        campaign.coordination_score, campaign.unique_sources, campaign.unique_source_asns,
                        campaign.packets_per_second, campaign.bits_per_second, campaign.flows_per_second,
                        campaign.first_seen, campaign.last_seen, json_dump(campaign.features),
                        json_dump(campaign.threat_intel), json_dump(campaign.intel_sources),
                        campaign.decision_source, campaign_risk["score"], campaign_risk["band"],
                        json_dump(campaign_risk["components"]), now, now,
                    ),
                )
                self._history(conn, "PREFIX", campaign.target_prefix, campaigns=1, external=int(bool(campaign.intel_sources)))
                self._audit(conn, "CAMPAIGN_RESULT", campaign=campaign)
                stats["campaigns"] += 1
            stats["expired_events"] = cleanup_security_events(conn)
            conn.commit()
        return stats

    def _history(self, conn: sqlite3.Connection, entity_type: str, entity_key: str, *, attacks: int = 0, campaigns: int = 0, external: int = 0) -> None:
        if not entity_key:
            return
        now = utc_now_iso()
        conn.execute(
            """
            INSERT INTO gmj_threat_history (
                entity_type, entity_key, first_seen_gmj, last_seen_gmj,
                attacks_seen, campaigns_seen, external_matches, recurrence_count, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(entity_type, entity_key) DO UPDATE SET
                last_seen_gmj=excluded.last_seen_gmj,
                attacks_seen=attacks_seen+excluded.attacks_seen,
                campaigns_seen=campaigns_seen+excluded.campaigns_seen,
                external_matches=external_matches+excluded.external_matches,
                recurrence_count=recurrence_count+1, updated_at=excluded.updated_at
            """,
            (entity_type, entity_key, now, now, attacks, campaigns, external, now),
        )

    def _audit(self, conn: sqlite3.Connection, event_type: str, *, vector: AttackVector | None = None, campaign: CampaignVector | None = None, reason: str = "") -> None:
        conn.execute(
            """
            INSERT INTO threat_engine_audit (
                event_type, detector, attack_vector_json, campaign_vector_json,
                threat_intel_json, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                vector.detector if vector else "campaign_engine" if campaign else "",
                json_dump(vector.as_dict()) if vector else "{}",
                json_dump(campaign.as_dict()) if campaign else "{}",
                json_dump(vector.threat_intel if vector else campaign.threat_intel if campaign else {}),
                reason,
                utc_now_iso(),
            ),
        )


def attack_vector_row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["features"] = safe_json(item.pop("feature_json", "{}"), {})
    item["threat_intel"] = safe_json(item.pop("threat_intel_json", "{}"), {})
    item["intel_sources"] = safe_json(item.pop("intel_sources_json", "[]"), [])
    item["external_correlation"] = bool(item.get("external_correlation"))
    return item


def campaign_row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["features"] = safe_json(item.pop("feature_json", "{}"), {})
    item["threat_intel"] = safe_json(item.pop("threat_intel_json", "{}"), {})
    item["intel_sources"] = safe_json(item.pop("intel_sources_json", "[]"), [])
    item["campaign_risk_components"] = safe_json(item.pop("campaign_risk_components_json", "{}"), {})
    item.setdefault("campaign_risk_score", 0)
    item.setdefault("campaign_risk_band", "")
    return item


def fetch_recent_observations(lookback_seconds: int = 300, limit: int = 100000) -> list[dict[str, Any]]:
    """Fetch bounded 10-second flow dimensions; ClickHouse performs the heavy aggregation."""
    from app.services.clickhouse import query_clickhouse

    sql = (
        """
        SELECT
            max(bucket) AS observed_at,
            sensor,
            toString(exporter_ip) AS exporter_ip,
            toString(src_ip) AS src_ip,
            toString(dst_ip) AS dst_ip,
            src_port,
            dst_port,
            proto,
            tcp_flags,
            input_if,
            output_if,
            src_asn,
            dst_asn,
            sum(packets) AS packets,
            sum(bytes) AS bytes,
            sum(flows) AS flow_count
        FROM behavior_flow_10s
        WHERE bucket >= subtractSeconds(now(), {lookback_seconds:UInt32})
        GROUP BY
            bucket,
            sensor, exporter_ip, src_ip, dst_ip, src_port, dst_port, proto,
            tcp_flags, input_if, output_if, src_asn, dst_asn
        ORDER BY observed_at DESC
        LIMIT {row_limit:UInt32}
        """
    ).replace("behavior_flow_10s", behavior_flow_table())
    return query_clickhouse(
        sql,
        {
            "lookback_seconds": max(10, min(int(lookback_seconds), 3600)),
            "row_limit": max(1000, min(int(limit), 250000)),
        },
    )


class BehavioralThreatRuntime:
    def __init__(
        self,
        connection_factory: Callable[[], sqlite3.Connection] = sqlite_connection,
        intel_manager: ThreatIntelManager = THREAT_INTEL_MANAGER,
        observation_loader: Callable[[int, int], list[dict[str, Any]]] = fetch_recent_observations,
    ) -> None:
        self.connection_factory = connection_factory
        self.engine = BehavioralDetectionEngine(connection_factory, intel_manager)
        # Created on first policy evaluation so detector-only deployments do not
        # acquire the central AI provider's optional crypto dependency at import.
        self.policy_engine: Any = None
        self.observation_loader = observation_loader
        self.mitigation_handler: Callable[[AttackVector | CampaignVector, Any], dict[str, Any]] | None = None
        # Threat Intelligence -> RTBH candidate generation (RECOMMEND_ONLY).
        # The handler is invoked after every policy evaluation regardless of
        # the FlowSpec decision; it never announces anything.
        self.rtbh_candidate_handler: Callable[[AttackVector | CampaignVector, Any], dict[str, Any]] | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._run_lock = threading.Lock()
        self.state: dict[str, Any] = {
            "running": False,
            "last_run": None,
            "last_error": "",
            "vectors": 0,
            "campaigns": 0,
            "policy_decisions": 0,
            "automatic_authorizations": 0,
            "mitigations_submitted": 0,
            "rtbh_candidates": 0,
            "mode": "shadow",
        }

    def set_mitigation_handler(
        self,
        handler: Callable[[AttackVector | CampaignVector, Any], dict[str, Any]] | None,
    ) -> None:
        self.mitigation_handler = handler

    def set_rtbh_candidate_handler(
        self,
        handler: Callable[[AttackVector | CampaignVector, Any], dict[str, Any]] | None,
    ) -> None:
        self.rtbh_candidate_handler = handler

    def get_policy_engine(self) -> Any:
        if self.policy_engine is None:
            from app.services.threat_policy import ThreatPolicyEngine

            self.policy_engine = ThreatPolicyEngine(self.connection_factory)
        return self.policy_engine

    def mark_mitigation_status(
        self,
        candidate: AttackVector | CampaignVector,
        status: str,
        decision_source: str = "GMJ_FLOW",
    ) -> None:
        with self.connection_factory() as conn:
            ensure_behavioral_schema(conn)
            update_security_event_mitigation_status(
                conn,
                candidate,
                status,
                decision_source=decision_source,
            )
            conn.commit()

    @staticmethod
    def mitigation_status_from_result(result: Mapping[str, Any]) -> str:
        status = clean_text(result.get("status")).lower()
        if status in {"advertised", "active", "announced", "applied", "executed"}:
            return "executed"
        if status in {"expired", "withdrawn"}:
            return "expired"
        if status in {"dry_run", "shadow"}:
            return "shadow"
        if status in {"queued", "sent", "generated", "applying", "pending", "pending_approval", "requested"}:
            return "requested"
        return "failed"

    def customer_networks(self) -> list[str]:
        with self.connection_factory() as conn:
            try:
                rows = conn.execute(
                    """
                    SELECT p.cidr
                    FROM ip_zone_prefixes p
                    JOIN ip_zones z ON z.id = p.zone_id
                    WHERE p.active = 1 AND z.active = 1
                    """
                ).fetchall()
            except sqlite3.OperationalError:
                return []
        return [clean_text(row[0]) for row in rows if clean_text(row[0])]

    def run_once(self) -> dict[str, Any]:
        if not self._run_lock.acquire(blocking=False):
            return {**self.state, "skipped": "run_in_progress"}
        self.state["running"] = True
        try:
            lookback = max(60, min(int(os.getenv("GMJFLOW_BEHAVIOR_LOOKBACK_SECONDS", "300")), 3600))
            limit = max(1000, min(int(os.getenv("GMJFLOW_BEHAVIOR_MAX_OBSERVATIONS", "100000")), 250000))
            rows = self.observation_loader(lookback, limit)
            self._record_runtime_counter(len(rows))
            candidate_v2: dict[str, Any] = {}
            candidate_v2_error = ""
            if os.getenv("GMJFLOW_BEHAVIOR_CANDIDATE_ENGINE_V2", "false").strip().lower() in {"1", "true", "yes", "on"}:
                try:
                    from app.services.behavioral_candidates import fetch_candidate_summary_v2

                    candidate_v2 = fetch_candidate_summary_v2(
                        lookback,
                        min(limit, 10000),
                        thresholds=self.engine.thresholds,
                    )
                except Exception as exc:
                    candidate_v2_error = clean_text(exc) or exc.__class__.__name__
            vectors, campaigns = self.engine.detect(rows, self.customer_networks())
            stats = self.engine.persist(vectors, campaigns)
            # NETWORK_SWEEP shadow policy evaluator (Phase 6B) — read-only
            # observer. Never returns ALLOW_AUTO, never calls mitigation.
            try:
                from app.services.network_sweep_policy import evaluate_and_audit_network_sweep_shadow

                with self.connection_factory() as conn:
                    evaluate_and_audit_network_sweep_shadow(conn)
                    conn.commit()
            except Exception:
                LOGGER.exception("network_sweep_shadow_evaluator_failed")
            # NETWORK_SWEEP NO-OP adapter — simulates the full execution path
            # (policy -> proposal -> adapter -> audit) with executed=false.
            # Never writes BGP/FlowSpec/exabgp/FIFO.
            try:
                from app.services.network_sweep_noop_adapter import run_noop_adapter

                with self.connection_factory() as conn:
                    run_noop_adapter(conn)
                    conn.commit()
            except Exception:
                LOGGER.exception("network_sweep_noop_adapter_failed")
            if candidate_v2 or candidate_v2_error:
                v1_counts = Counter(item.detector for item in vectors)
                comparison = {
                    "mode": "shadow_compare",
                    "v1_observations": len(rows),
                    "v1_vectors": len(vectors),
                    "v1_counts": dict(v1_counts),
                    "v2_candidate_count": candidate_v2.get("candidate_count", 0),
                    "v2_counts": candidate_v2.get("counts", {}),
                    "v2_error": candidate_v2_error,
                    "production_source": "V1",
                }
                with self.connection_factory() as conn:
                    ensure_behavioral_schema(conn)
                    conn.execute(
                        """
                        INSERT INTO threat_engine_audit (
                            event_type, detector, attack_vector_json, reason,
                            non_mitigation_reason, created_at
                        ) VALUES ('CANDIDATE_ENGINE_SHADOW_COMPARISON', 'candidate_engine_v2', ?, ?, ?, ?)
                        """,
                        (
                            json_dump(comparison),
                            "V1 and V2 candidate counts compared in shadow mode",
                            "candidate_engine_v2_does_not_drive_mitigation",
                            utc_now_iso(),
                        ),
                    )
                    conn.commit()
            minimum_evidence = max(0, min(int(os.getenv("GMJFLOW_THREAT_POLICY_MIN_EVIDENCE_SCORE", "75")), 100))
            maximum_evaluations = max(1, min(int(os.getenv("GMJFLOW_THREAT_POLICY_MAX_EVALUATIONS", "10")), 100))
            candidates: list[AttackVector | CampaignVector] = [
                *[item for item in vectors if item.detector_score >= minimum_evidence],
                *[item for item in campaigns if item.coordination_score >= minimum_evidence],
            ]
            candidates.sort(
                key=lambda item: item.detector_score if isinstance(item, AttackVector) else item.coordination_score,
                reverse=True,
            )
            decisions = 0
            authorizations = 0
            submitted = 0
            mitigation_errors: list[str] = []
            for candidate in candidates[:maximum_evaluations]:
                decision = self.get_policy_engine().evaluate(candidate)
                decisions += 1
                # Threat Intelligence -> RTBH candidates: generated after every
                # evaluation, independent of the FlowSpec decision. RECOMMEND_ONLY.
                if self.rtbh_candidate_handler is not None:
                    try:
                        rtbh_result = self.rtbh_candidate_handler(candidate, decision)
                        created = safe_int(rtbh_result.get("candidates")) if isinstance(rtbh_result, Mapping) else 0
                        if created:
                            self.state["rtbh_candidates"] = safe_int(self.state.get("rtbh_candidates")) + created
                    except Exception as exc:
                        mitigation_errors.append("rtbh_candidates:" + (clean_text(exc) or exc.__class__.__name__))
                if not decision.allowed:
                    if decision.gates.get("shadow_policy_verdict") == "WOULD_BLOCK":
                        self.mark_mitigation_status(candidate, "shadow", decision.decision_source)
                    continue
                authorizations += 1
                self.mark_mitigation_status(candidate, "requested", decision.decision_source)
                if self.mitigation_handler is None:
                    mitigation_errors.append("flowspec_handler_not_configured")
                    self.mark_mitigation_status(candidate, "failed", decision.decision_source)
                    continue
                try:
                    result = self.mitigation_handler(candidate, decision)
                    mitigation_status = self.mitigation_status_from_result(result)
                    self.mark_mitigation_status(candidate, mitigation_status, decision.decision_source)
                    if mitigation_status == "executed":
                        submitted += 1
                except Exception as exc:
                    mitigation_errors.append(clean_text(exc) or exc.__class__.__name__)
                    self.mark_mitigation_status(candidate, "failed", decision.decision_source)
            self.state.update(
                {
                    "last_run": utc_now_iso(),
                    "last_error": "",
                    "vectors": stats["vectors"],
                    "campaigns": stats["campaigns"],
                    "policy_decisions": decisions,
                    "automatic_authorizations": authorizations,
                    "mitigations_submitted": submitted,
                    "mitigation_errors": mitigation_errors[:20],
                    "observations": len(rows),
                    "candidate_engine": "v1_with_v2_shadow" if candidate_v2 or candidate_v2_error else "v1",
                    "candidate_v2": candidate_v2.get("counts", {}),
                    "candidate_v2_error": candidate_v2_error,
                    "mode": "shadow" if not automatic_policy_enabled() else "policy",
                }
            )
        except Exception as exc:
            self.state.update({"last_run": utc_now_iso(), "last_error": clean_text(exc) or exc.__class__.__name__})
            LOGGER.warning("BEHAVIORAL_THREAT_ENGINE_FAILED error=%s", exc)
        finally:
            self.state["running"] = False
            self._run_lock.release()
        return dict(self.state)

    def _record_runtime_counter(self, observations: int) -> None:
        """Aggregated per-hour telemetry for the Security Overview. This is
        bookkeeping only and does not change detection or policy behavior."""
        now = utc_now_iso()
        hour = now[:13] + ":00:00Z"
        with self.connection_factory() as conn:
            ensure_behavioral_schema(conn)
            conn.execute(
                """
                INSERT INTO behavioral_runtime_counters (hour, observations, runs, updated_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(hour) DO UPDATE SET
                    observations = observations + excluded.observations,
                    runs = runs + 1,
                    updated_at = excluded.updated_at
                """,
                (hour, int(observations), now),
            )
            conn.commit()

    def start(self) -> None:
        self.engine.ensure_schema()
        if os.getenv("GMJFLOW_BEHAVIORAL_DETECTION_ENABLED", "true").strip().lower() not in {"1", "true", "yes", "on"}:
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            initial = max(1, int(os.getenv("GMJFLOW_BEHAVIOR_INITIAL_DELAY_SECONDS", "30")))
            if self._stop.wait(initial):
                return
            interval = max(10, int(os.getenv("GMJFLOW_BEHAVIOR_INTERVAL_SECONDS", "30")))
            while not self._stop.is_set():
                self.run_once()
                self._stop.wait(interval)

        self._thread = threading.Thread(target=loop, name="gmj-flow-behavioral-threat-engine", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2)


def automatic_policy_enabled() -> bool:
    from app.services.config_effective import threat_policy_auto_enabled

    try:
        with sqlite_connection() as conn:
            return threat_policy_auto_enabled(conn)
    except Exception:
        return False


BEHAVIORAL_THREAT_RUNTIME = BehavioralThreatRuntime()
