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


LOGGER = logging.getLogger("gmj-flow")
WINDOWS = (10, 30, 60, 300)
PREFIX_LENGTHS_V4 = (32, 29, 28, 27, 26, 25, 24, 23, 22)

NORMAL = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
PORT_SCAN_VERTICAL = "PORT_SCAN_VERTICAL"
PORT_SCAN_HORIZONTAL = "PORT_SCAN_HORIZONTAL"
NETWORK_SWEEP = "NETWORK_SWEEP"
LOW_SLOW_SCAN = "LOW_SLOW_SCAN"
SYN_FLOOD = "SYN_FLOOD"
DISTRIBUTED_SYN_FLOOD = "DISTRIBUTED_SYN_FLOOD"
SPOOFED_SYN_FLOOD = "SPOOFED_SYN_FLOOD"
UDP_FLOOD = "UDP_FLOOD"
DISTRIBUTED_UDP_FLOOD = "DISTRIBUTED_UDP_FLOOD"
UDP_REFLECTION_SUSPECTED = "UDP_REFLECTION_SUSPECTED"
COORDINATED_DDOS = "COORDINATED_DDOS"
BOTNET_LIKELY = "BOTNET_LIKELY"
CARPET_BOMBING = "CARPET_BOMBING"
MULTI_VECTOR_DDOS = "MULTI_VECTOR_DDOS"
UNKNOWN_ANOMALY = "UNKNOWN_ANOMALY"
COMPROMISED_CUSTOMER = "COMPROMISED_CUSTOMER"

CLASSIFICATIONS = {
    NORMAL,
    SUSPICIOUS,
    PORT_SCAN_VERTICAL,
    PORT_SCAN_HORIZONTAL,
    NETWORK_SWEEP,
    LOW_SLOW_SCAN,
    SYN_FLOOD,
    DISTRIBUTED_SYN_FLOOD,
    SPOOFED_SYN_FLOOD,
    UDP_FLOOD,
    DISTRIBUTED_UDP_FLOOD,
    UDP_REFLECTION_SUSPECTED,
    COORDINATED_DDOS,
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
    direction: str = "INTERNAL"
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


def flow_features(rows: Sequence[FlowObservation], window_seconds: int) -> dict[str, Any]:
    flow_count = sum(row.flow_count for row in rows)
    packet_count = sum(row.packets for row in rows)
    byte_count = sum(row.bytes for row in rows)
    syn_flows = sum(row.flow_count for row in rows if row.protocol == 6 and row.tcp_flags & 0x02)
    ack_flows = sum(row.flow_count for row in rows if row.protocol == 6 and row.tcp_flags & 0x10)
    rst_flows = sum(row.flow_count for row in rows if row.protocol == 6 and row.tcp_flags & 0x04)
    first = min(row.observed_at for row in rows)
    last = max(row.observed_at for row in rows)
    elapsed = max(1.0, min(float(window_seconds), (last - first).total_seconds() or float(window_seconds)))
    return {
        "flow_count": flow_count,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "unique_dst_ips": len({row.dst_ip for row in rows}),
        "unique_dst_ports": len({row.dst_port for row in rows}),
        "unique_src_ips": len({row.src_ip for row in rows}),
        "unique_src_asns": len({row.src_asn for row in rows if row.src_asn}),
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
        "first_seen": first.isoformat().replace("+00:00", "Z"),
        "last_seen": last.isoformat().replace("+00:00", "Z"),
        "elapsed_seconds": round(elapsed, 3),
    }


class PortScanDetector:
    name = "port_scan"

    def __init__(self, thresholds: DetectorThresholds | None = None) -> None:
        self.thresholds = thresholds or DetectorThresholds()

    def detect(self, observations: Sequence[FlowObservation]) -> list[AttackVector]:
        if not observations:
            return []
        now = max(item.observed_at for item in observations)
        best: dict[tuple[str, str], AttackVector] = {}
        for window in WINDOWS:
            grouped: dict[str, list[FlowObservation]] = defaultdict(list)
            cutoff = now - timedelta(seconds=window)
            for row in observations:
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
                vector = AttackVector(
                    attack_type=attack_type,
                    detector=self.name,
                    detector_score=score,
                    confidence=round(score / 100.0, 3),
                    first_seen=features["first_seen"],
                    last_seen=features["last_seen"],
                    src_ip=source,
                    target_ip=rows[0].dst_ip if dst_ips == 1 else "",
                    target_prefix="",
                    window_seconds=window,
                    features=features,
                )
                key = (source, attack_type)
                if key not in best or best[key].detector_score < score:
                    best[key] = vector
        return list(best.values())


def target_prefixes(ip_text: str) -> Iterable[str]:
    parsed = ip_address(ip_text)
    if parsed.version == 4:
        for length in PREFIX_LENGTHS_V4:
            yield str(ip_network(f"{parsed}/{length}", strict=False))
    else:
        yield str(ip_network(f"{parsed}/128", strict=False))


def source_intel_stats(rows: Sequence[FlowObservation], intel_lookup: Callable[[str, Mapping[str, Any] | None], Mapping[str, Any]] | None) -> dict[str, Any]:
    if intel_lookup is None:
        return {"matches": 0, "bogon_sources": 0, "c2_sources": 0, "sources": {}, "intel_sources": []}
    sources: dict[str, Any] = {}
    seen_sources: set[str] = set()
    providers: set[str] = set()
    bogon = c2 = 0
    maximum_lookups = max(1, int(os.getenv("GMJFLOW_BEHAVIOR_MAX_INTEL_LOOKUPS_PER_VECTOR", "500")))
    unique_candidates = len({row.src_ip for row in rows})
    for row in rows:
        if row.src_ip in seen_sources:
            continue
        if len(seen_sources) >= maximum_lookups:
            break
        seen_sources.add(row.src_ip)
        result = intel_lookup(
            row.src_ip,
            {
                "sensor": row.sensor,
                "exporter_ip": row.exporter_ip,
                "input_if": row.input_if,
                "output_if": row.output_if,
                "context_type": "UNKNOWN",
            },
        )
        matches = list(result.get("matches") or [])
        if matches:
            sources[row.src_ip] = matches
        for match in matches:
            providers.add(clean_text(match.get("provider")))
            if clean_text(match.get("indicator_type")) in {"BOGON", "FULLBOGON"} and match.get("classification") == "anomalous_source":
                bogon += 1
            if clean_text(match.get("indicator_type")) == "C2":
                c2 += 1
    return {
        "matches": len(sources),
        "bogon_sources": bogon,
        "c2_sources": c2,
        "sources": sources,
        "intel_sources": sorted(providers - {""}),
        "lookup_count": len(seen_sources),
        "lookup_truncated": unique_candidates > len(seen_sources),
    }


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
            if syn_packets < self.thresholds.flood_packets and pps < self.thresholds.flood_pps:
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
            current_baseline = float((baseline or {}).get(prefix) or 0)
            deviation = ratio(pps, current_baseline) if current_baseline else 0.0
            score = int(clamp(45 + min(25, math.log10(max(10, syn_packets)) * 6) + min(15, unique_sources / 5) + min(15, max(0, syn_ack_ratio - 1))))
            features.update(
                {
                    "syn_count": syn_packets,
                    "ack_count": ack_packets,
                    "rst_count": rst_packets,
                    "syn_ratio": round(syn_ratio, 4),
                    "syn_ack_ratio": round(syn_ack_ratio, 4),
                    "unique_sources": unique_sources,
                    "pps": round(features["packets_per_second"], 4),
                    "bps": round(features["bits_per_second"], 4),
                    "spoofing_likelihood": spoofing_likelihood,
                }
            )
            vectors.append(
                AttackVector(
                    attack_type=attack_type,
                    detector=self.name,
                    detector_score=score,
                    confidence=round(score / 100.0, 3),
                    first_seen=features["first_seen"],
                    last_seen=features["last_seen"],
                    target_ip=rows[0].dst_ip if prefix.endswith("/32") else "",
                    target_prefix=prefix,
                    window_seconds=window_seconds,
                    baseline_deviation=round(deviation, 3),
                    features=features,
                    threat_intel=intel,
                    intel_sources=intel["intel_sources"],
                )
            )
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
            if features["packet_count"] < self.thresholds.flood_packets and pps < self.thresholds.flood_pps:
                continue
            unique_sources = features["unique_src_ips"]
            source_ports = Counter(row.src_port for row in rows)
            destination_ports = Counter(row.dst_port for row in rows)
            sizes = [ratio(row.bytes, row.packets) for row in rows if row.packets]
            dominant_src_port, dominant_src_count = source_ports.most_common(1)[0] if source_ports else (0, 0)
            source_port_concentration = ratio(dominant_src_count, sum(source_ports.values()))
            average_packet_size = ratio(sum(sizes), len(sizes)) if sizes else 0.0
            packet_size_stddev = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0
            distributed = unique_sources >= self.thresholds.distributed_sources
            # A known port is only one signal. Diversity, concentration and packet shape are also required.
            reflection = (
                distributed
                and dominant_src_port in AMPLIFICATION_PORTS
                and source_port_concentration >= 0.5
                and average_packet_size >= 300
            )
            attack_type = UDP_REFLECTION_SUSPECTED if reflection else DISTRIBUTED_UDP_FLOOD if distributed else UDP_FLOOD
            current_baseline = float((baseline or {}).get(prefix) or 0)
            deviation = ratio(pps, current_baseline) if current_baseline else 0.0
            intel = source_intel_stats(rows, intel_lookup)
            score = int(clamp(45 + min(25, math.log10(max(10, features["packet_count"])) * 6) + min(20, unique_sources / 5) + (10 if reflection else 0)))
            features.update(
                {
                    "unique_sources": unique_sources,
                    "unique_source_asns": features["unique_src_asns"],
                    "destination_port_distribution": dict(destination_ports.most_common(20)),
                    "source_port_distribution": dict(source_ports.most_common(20)),
                    "dominant_source_port": dominant_src_port,
                    "source_port_concentration": round(source_port_concentration, 4),
                    "average_packet_size": round(average_packet_size, 2),
                    "packet_size_stddev": round(packet_size_stddev, 2),
                    "protocol_ratio": round(ratio(len(rows), len(observations)), 4),
                    "temporal_burst": round(ratio(pps, current_baseline), 3) if current_baseline else 0.0,
                    "amplification_port_signal": dominant_src_port in AMPLIFICATION_PORTS,
                    "reflection_evidence_satisfied": reflection,
                }
            )
            vectors.append(
                AttackVector(
                    attack_type=attack_type,
                    detector=self.name,
                    detector_score=score,
                    confidence=round(score / 100.0, 3),
                    first_seen=features["first_seen"],
                    last_seen=features["last_seen"],
                    target_ip=rows[0].dst_ip if prefix.endswith("/32") else "",
                    target_prefix=prefix,
                    window_seconds=window_seconds,
                    baseline_deviation=round(deviation, 3),
                    features=features,
                    threat_intel=intel,
                    intel_sources=intel["intel_sources"],
                )
            )
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


class CarpetBombingDetector:
    name = "prefix_carpet_bombing"

    def __init__(self, thresholds: DetectorThresholds | None = None, max_groups: int = 50000) -> None:
        self.thresholds = thresholds or DetectorThresholds()
        self.max_groups = max(1000, max_groups)

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
            unique_hosts = features["unique_dst_ips"]
            aggregate_pps = features["packets_per_second"]
            per_host = Counter()
            for row in rows:
                per_host[row.dst_ip] += row.packets
            max_host_pps = ratio(max(per_host.values(), default=0), window_seconds)
            historical = float((baseline or {}).get(prefix) or 0)
            deviation = ratio(aggregate_pps, historical) if historical else 0.0
            if unique_hosts < self.thresholds.carpet_unique_hosts:
                continue
            if aggregate_pps < self.thresholds.carpet_prefix_pps and deviation < 3:
                continue
            if max_host_pps >= self.thresholds.carpet_host_pps:
                continue
            score = int(clamp(55 + min(20, unique_hosts / 4) + min(25, deviation * 4 if deviation else aggregate_pps / 100)))
            features.update({"target_prefix": prefix, "target_hosts": unique_hosts, "max_host_pps": round(max_host_pps, 3), "aggregate_pps": aggregate_pps})
            vectors.append(
                AttackVector(
                    attack_type=CARPET_BOMBING,
                    detector=self.name,
                    detector_score=score,
                    confidence=round(score / 100.0, 3),
                    first_seen=features["first_seen"],
                    last_seen=features["last_seen"],
                    target_prefix=prefix,
                    window_seconds=window_seconds,
                    baseline_deviation=round(deviation, 3),
                    features=features,
                )
            )
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
    def __init__(self, campaign_id_factory: Callable[[], str] | None = None) -> None:
        self.campaign_id_factory = campaign_id_factory or self.new_campaign_id

    @staticmethod
    def new_campaign_id() -> str:
        stamp = utc_now().strftime("%Y%m%d")
        suffix = hashlib.sha256(f"{utc_now_iso()}|{os.getpid()}".encode()).hexdigest()[:5].upper()
        return f"GMJ-{stamp}-{suffix}"

    def correlate(self, vectors: Sequence[AttackVector]) -> list[CampaignVector]:
        grouped: dict[str, list[AttackVector]] = defaultdict(list)
        for vector in vectors:
            prefix = campaign_prefix(vector)
            if prefix:
                grouped[prefix].append(vector)
        campaigns = []
        for prefix, items in grouped.items():
            types = {item.attack_type for item in items}
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
            classification = COORDINATED_DDOS
            if len({"tcp" if "SYN" in item.attack_type else "udp" if "UDP" in item.attack_type else item.attack_type for item in items}) > 1:
                classification = MULTI_VECTOR_DDOS
            elif CARPET_BOMBING in types:
                classification = CARPET_BOMBING
            elif any(item.attack_type in {DISTRIBUTED_SYN_FLOOD, SPOOFED_SYN_FLOOD} for item in items):
                classification = DISTRIBUTED_SYN_FLOOD
            elif any(item.attack_type in {DISTRIBUTED_UDP_FLOOD, UDP_REFLECTION_SUSPECTED} for item in items):
                classification = DISTRIBUTED_UDP_FLOOD
            if c2_common and unique_sources >= 10:
                classification = BOTNET_LIKELY
            campaign_id = self.campaign_id_factory()
            for item in items:
                item.campaign_id = campaign_id
            packets_per_second = sum(float(item.features.get("packets_per_second") or item.features.get("pps") or 0) for item in items)
            bits_per_second = sum(float(item.features.get("bits_per_second") or item.features.get("bps") or 0) for item in items)
            flows_per_second = sum(float(item.features.get("flows_per_second") or 0) for item in items)
            campaigns.append(
                CampaignVector(
                    campaign_id=campaign_id,
                    target_prefix=prefix,
                    classification=classification,
                    unique_sources=unique_sources,
                    unique_source_asns=max(len(source_asns), max((safe_int(item.features.get("unique_source_asns")) for item in items), default=0)),
                    packets_per_second=round(packets_per_second, 3),
                    bits_per_second=round(bits_per_second, 3),
                    flows_per_second=round(flows_per_second, 3),
                    coordination_score=score,
                    first_seen=first.isoformat().replace("+00:00", "Z"),
                    last_seen=last.isoformat().replace("+00:00", "Z"),
                    features={
                        "concurrent_sources": unique_sources,
                        "source_arrival_rate": round(source_arrival_rate, 4),
                        "source_churn_rate": round(source_churn_rate, 4),
                        "temporal_correlation": round(1.0 / max(1.0, duration / 60), 4),
                        "protocol_similarity": protocol_similarity,
                        "port_similarity": round(sum(1 for item in items if item.features.get("unique_dst_ports") == 1) / len(items), 4),
                        "packet_size_similarity": round(packet_size_similarity, 4),
                        "target_similarity": target_similarity,
                        "source_asn_diversity": len(source_asns),
                        "common_c2_intelligence": c2_common,
                        "historical_recurrence": max((safe_int(item.features.get("historical_recurrence") or item.features.get("recurrence_count")) for item in items), default=0),
                        "attack_types": sorted(types),
                    },
                    threat_intel={"matches": sum(safe_int(item.threat_intel.get("matches")) for item in items)},
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
    return "INTERNAL"


def compromised_host_score(vectors: Sequence[AttackVector], c2_match: bool, recurrence_count: int = 0) -> int:
    score = 45 if c2_match else 0
    types = {item.attack_type for item in vectors}
    if types & {PORT_SCAN_VERTICAL, PORT_SCAN_HORIZONTAL, NETWORK_SWEEP, LOW_SLOW_SCAN}:
        score += 20
    if types & {SYN_FLOOD, DISTRIBUTED_SYN_FLOOD, UDP_FLOOD, DISTRIBUTED_UDP_FLOOD, UDP_REFLECTION_SUSPECTED}:
        score += 25
    if any(item.campaign_id for item in vectors):
        score += 10
    score += min(15, recurrence_count * 3)
    return int(clamp(score))


def ensure_behavioral_schema(conn: sqlite3.Connection) -> None:
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
            updated_at TEXT NOT NULL,
            PRIMARY KEY(prefix, protocol)
        );
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


def event_key(vector: AttackVector) -> str:
    bucket = int(parse_time(vector.last_seen).timestamp()) // max(10, vector.window_seconds)
    raw = f"{vector.detector}|{vector.attack_type}|{vector.src_ip}|{vector.target_prefix}|{vector.target_ip}|{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()


class BehavioralDetectionEngine:
    def __init__(
        self,
        connection_factory: Callable[[], sqlite3.Connection],
        intel_manager: ThreatIntelManager,
        thresholds: DetectorThresholds | None = None,
    ) -> None:
        self.connection_factory = connection_factory
        self.intel_manager = intel_manager
        self.thresholds = thresholds or DetectorThresholds()
        self.port_scan = PortScanDetector(self.thresholds)
        self.syn_flood = SynFloodDetector(self.thresholds)
        self.udp_flood = UdpFloodDetector(self.thresholds)
        self.carpet = CarpetBombingDetector(
            self.thresholds,
            max_groups=int(os.getenv("GMJFLOW_BEHAVIOR_MAX_PREFIX_GROUPS", "50000")),
        )
        self.campaigns = CampaignEngine()
        self._last_observations: list[FlowObservation] = []

    def ensure_schema(self) -> None:
        with self.connection_factory() as conn:
            ensure_behavioral_schema(conn)
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

    def update_prefix_baselines(self, conn: sqlite3.Connection, observations: Sequence[FlowObservation], window_seconds: int = 60) -> None:
        groups: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
        maximum = max(1000, int(os.getenv("GMJFLOW_BEHAVIOR_MAX_PREFIX_GROUPS", "50000")))
        latest = max((row.observed_at for row in observations), default=utc_now())
        cutoff = latest - timedelta(seconds=window_seconds)
        for row in observations:
            if row.observed_at < cutoff:
                continue
            protocol = "tcp" if row.protocol == 6 else "udp" if row.protocol == 17 else "other"
            for prefix in target_prefixes(row.dst_ip):
                key = (prefix, protocol)
                if key not in groups and len(groups) >= maximum:
                    break
                groups[key][0] += row.packets
                groups[key][1] += row.bytes
        now = utc_now_iso()
        alpha = clamp(float(os.getenv("GMJFLOW_BEHAVIOR_BASELINE_ALPHA", "0.1")), 0.01, 0.5)
        for (prefix, protocol), (packets, byte_count) in groups.items():
            pps = ratio(packets, max(1, window_seconds))
            bps = ratio(byte_count * 8, max(1, window_seconds))
            current = conn.execute(
                "SELECT packets_per_second_ema, bits_per_second_ema, sample_count FROM prefix_behavior_baselines WHERE prefix=? AND protocol=?",
                (prefix, protocol),
            ).fetchone()
            if current is None:
                next_pps, next_bps, samples = pps, bps, 1
            else:
                old_pps, old_bps, old_samples = float(current[0] or 0), float(current[1] or 0), safe_int(current[2])
                bounded_pps = min(pps, old_pps * 3) if old_samples >= 5 and old_pps > 0 else pps
                bounded_bps = min(bps, old_bps * 3) if old_samples >= 5 and old_bps > 0 else bps
                next_pps = old_pps * (1 - alpha) + bounded_pps * alpha
                next_bps = old_bps * (1 - alpha) + bounded_bps * alpha
                samples = old_samples + 1
            conn.execute(
                """
                INSERT INTO prefix_behavior_baselines(prefix, protocol, packets_per_second_ema, bits_per_second_ema, sample_count, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(prefix, protocol) DO UPDATE SET
                    packets_per_second_ema=excluded.packets_per_second_ema,
                    bits_per_second_ema=excluded.bits_per_second_ema,
                    sample_count=excluded.sample_count, updated_at=excluded.updated_at
                """,
                (prefix, protocol, next_pps, next_bps, samples, now),
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
        lookup = self.intel_manager.lookup_ip
        tcp_baseline = self.prefix_baselines("tcp")
        udp_baseline = self.prefix_baselines("udp")
        carpet_baseline = {**tcp_baseline}
        for prefix, value in udp_baseline.items():
            carpet_baseline[prefix] = carpet_baseline.get(prefix, 0) + value
        vectors = self.port_scan.detect(observations)
        vectors += self.syn_flood.detect(observations, lookup, tcp_baseline)
        vectors += self.udp_flood.detect(observations, lookup, udp_baseline)
        vectors += self.carpet.detect(observations, carpet_baseline)
        by_source: dict[str, list[AttackVector]] = defaultdict(list)
        for vector in vectors:
            if vector.src_ip:
                by_source[vector.src_ip].append(vector)
            evidence_rows = [row for row in observations if (vector.src_ip and row.src_ip == vector.src_ip) or (vector.target_ip and row.dst_ip == vector.target_ip)]
            if evidence_rows:
                vector.direction = direction_for_flow(evidence_rows[0], customer_networks)
            target = vector.target_prefix or (f"{vector.target_ip}/32" if vector.target_ip else "")
            if target:
                correlations = self.intel_manager.external_attack_matches(target, "tcp" if "SYN" in vector.attack_type else "udp" if "UDP" in vector.attack_type else "", vector.last_seen)
                if correlations:
                    vector.external_correlation = True
                    vector.detector_score = int(clamp(vector.detector_score + 8))
                    vector.confidence = round(clamp(vector.confidence + 0.08, 0, 1), 3)
                    vector.threat_intel["external_attack_observations"] = correlations[:20]
                    vector.intel_sources = sorted(set(vector.intel_sources) | {clean_text(item.get("provider")) for item in correlations})
        self.enrich_internal_history(vectors)
        campaigns = self.campaigns.correlate(vectors)
        for source, items in by_source.items():
            lookup_result = self.intel_manager.lookup_ip(source)
            c2 = any(item.get("indicator_type") == "C2" for item in lookup_result.get("matches") or [])
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
            self.update_prefix_baselines(conn, self._last_observations)
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
                self._audit(conn, "DETECTOR_RESULT", vector=vector)
                stats["vectors"] += 1
            for campaign in campaigns:
                conn.execute(
                    """
                    INSERT INTO threat_campaigns (
                        campaign_id, target_prefix, classification, coordination_score,
                        unique_sources, unique_source_asns, packets_per_second, bits_per_second,
                        flows_per_second, first_seen, last_seen, feature_json, threat_intel_json,
                        intel_sources_json, decision_source, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(campaign_id) DO UPDATE SET
                        coordination_score=MAX(coordination_score, excluded.coordination_score),
                        unique_sources=MAX(unique_sources, excluded.unique_sources),
                        unique_source_asns=MAX(unique_source_asns, excluded.unique_source_asns),
                        packets_per_second=MAX(packets_per_second, excluded.packets_per_second),
                        bits_per_second=MAX(bits_per_second, excluded.bits_per_second),
                        flows_per_second=MAX(flows_per_second, excluded.flows_per_second),
                        last_seen=excluded.last_seen, feature_json=excluded.feature_json,
                        threat_intel_json=excluded.threat_intel_json,
                        intel_sources_json=excluded.intel_sources_json, updated_at=excluded.updated_at
                    """,
                    (
                        campaign.campaign_id, campaign.target_prefix, campaign.classification,
                        campaign.coordination_score, campaign.unique_sources, campaign.unique_source_asns,
                        campaign.packets_per_second, campaign.bits_per_second, campaign.flows_per_second,
                        campaign.first_seen, campaign.last_seen, json_dump(campaign.features),
                        json_dump(campaign.threat_intel), json_dump(campaign.intel_sources),
                        campaign.decision_source, now, now,
                    ),
                )
                self._history(conn, "PREFIX", campaign.target_prefix, campaigns=1, external=int(bool(campaign.intel_sources)))
                self._audit(conn, "CAMPAIGN_RESULT", campaign=campaign)
                stats["campaigns"] += 1
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
    return item


def fetch_recent_observations(lookback_seconds: int = 300, limit: int = 100000) -> list[dict[str, Any]]:
    """Fetch bounded 10-second flow dimensions; ClickHouse performs the heavy aggregation."""
    from app.services.clickhouse import query_clickhouse

    return query_clickhouse(
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
        """,
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
            "mode": "shadow",
        }

    def set_mitigation_handler(
        self,
        handler: Callable[[AttackVector | CampaignVector, Any], dict[str, Any]] | None,
    ) -> None:
        self.mitigation_handler = handler

    def get_policy_engine(self) -> Any:
        if self.policy_engine is None:
            from app.services.threat_policy import ThreatPolicyEngine

            self.policy_engine = ThreatPolicyEngine(self.connection_factory)
        return self.policy_engine

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
            vectors, campaigns = self.engine.detect(rows, self.customer_networks())
            stats = self.engine.persist(vectors, campaigns)
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
                if not decision.allowed:
                    continue
                authorizations += 1
                if self.mitigation_handler is None:
                    mitigation_errors.append("flowspec_handler_not_configured")
                    continue
                try:
                    result = self.mitigation_handler(candidate, decision)
                    if clean_text(result.get("status")) not in {"", "not_applied", "blocked", "failed"}:
                        submitted += 1
                except Exception as exc:
                    mitigation_errors.append(clean_text(exc) or exc.__class__.__name__)
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
    return os.getenv("GMJFLOW_THREAT_POLICY_AUTO_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


BEHAVIORAL_THREAT_RUNTIME = BehavioralThreatRuntime()
