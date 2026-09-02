"""Shadow replay/calibration for the CARPET_BOMBING detector.

Read-only re-analysis of historical security events using the current detector
decision rules. It never writes events, never creates anomalies/campaigns and
never touches BGP/FlowSpec. Used to measure how many historical events the new
absolute-floor + web-return + role-context logic would reclassify.
"""

from __future__ import annotations

import math
from typing import Any, Mapping

from app.services.behavioral_detection import (
    AMPLIFICATION_PORTS,
    EXPECTED_DISTRIBUTED_TRAFFIC,
    SUSPICIOUS_DISTRIBUTED_TRAFFIC,
    DetectorThresholds,
)
from app.services.threat_contracts import detector_verdict

ATTACK_VERDICTS = {"CONFIRMED_ATTACK", "LIKELY_ATTACK"}

COMPARISONS = (
    "UNCHANGED_ATTACK",
    "FALSE_POSITIVE_REDUCED",
    "ATTACK_DOWNGRADED",
    "NEW_ATTACK_DETECTED",
    "REVIEW_REQUIRED",
)


def _clamp(value: float, minimum: float = 0.0, maximum: float = 100.0) -> int:
    return int(max(minimum, min(maximum, value)))


def _verdict_severity(
    score: int,
    persistence: int,
    traffic_classification: str,
) -> tuple[str, str]:
    if traffic_classification == SUSPICIOUS_DISTRIBUTED_TRAFFIC:
        return "SUSPICIOUS", "MEDIUM"
    if traffic_classification == EXPECTED_DISTRIBUTED_TRAFFIC:
        return "INFO", "LOW"
    verdict = detector_verdict(score, persistent_windows=max(1, persistence))
    if verdict == "CONFIRMED_ATTACK" or score >= 90:
        severity = "CRITICAL"
    elif verdict == "LIKELY_ATTACK" or score >= 75:
        severity = "HIGH"
    elif score >= 55:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    return verdict, severity


def replay_carpet_decision(
    features: Mapping[str, Any],
    thresholds: DetectorThresholds | None = None,
) -> dict[str, Any]:
    """Re-apply the carpet decision to persisted aggregate features.

    Mirrors `CarpetBombingDetector.detect` (absolute floor, web-return
    fingerprint, role context, evidence categories). Purely functional: no DB,
    no writes.
    """
    thresholds = thresholds or DetectorThresholds()
    aggregate_pps = float(features.get("aggregate_pps") or features.get("packets_per_second") or 0)
    aggregate_bps = float(features.get("aggregate_bps") or features.get("bits_per_second") or 0)
    unique_hosts = int(features.get("unique_destinations") or features.get("unique_dst_ips") or features.get("target_hosts") or 0)
    unique_sources = int(features.get("unique_sources") or features.get("unique_src_ips") or 0)
    max_host_pps = float(features.get("max_host_pps") or 0)
    persistence = int(features.get("persistent_windows") or 1)
    packet_count = int(features.get("packets") or features.get("packet_count") or 0)
    baseline_deviation = float(features.get("baseline_deviation") or 0)
    web_return_share = float(features.get("web_return_share") or 0)
    udp_quic_share = float(features.get("udp_quic_share") or 0)
    tcp_ack_ratio = float(features.get("tcp_ack_ratio") or 0)
    tcp_syn_ratio = float(features.get("tcp_syn_ratio") or 0)
    dst_port_entropy = float(features.get("dst_port_entropy") or 0)
    unique_dst_ports = int(features.get("unique_dst_ports") or 0)
    top_src_port = int(features.get("top_src_port") or 0)
    top_src_port_share = float(features.get("top_src_port_share") or 0)
    cgnat_share = float(features.get("target_cgnat_share") or 0)
    isp_share = float(features.get("target_downstream_isp_share") or 0)

    below_absolute_floor = bool(
        aggregate_pps < thresholds.carpet_min_absolute_pps
        and aggregate_bps < thresholds.carpet_min_absolute_bps
    )
    web_return_likely = bool(
        web_return_share >= thresholds.carpet_web_return_share
        and (
            (tcp_ack_ratio >= thresholds.carpet_web_return_ack_ratio and tcp_syn_ratio < 0.2)
            or udp_quic_share >= 0.1
        )
        and (dst_port_entropy >= 0.4 or unique_dst_ports >= thresholds.carpet_dst_port_diversity)
    )
    cgnat_or_isp = cgnat_share + isp_share
    reflection = bool(top_src_port in AMPLIFICATION_PORTS and top_src_port_share >= 0.5)

    categories_passed: set[str] = set()
    categories_failed: set[str] = set()
    if not below_absolute_floor:
        categories_passed.add("VOLUME")
    else:
        categories_failed.add("VOLUME")
    if unique_hosts >= thresholds.carpet_unique_hosts and unique_sources >= 20:
        categories_passed.add("DISTRIBUTION")
    else:
        categories_failed.add("DISTRIBUTION")
    if max_host_pps < thresholds.carpet_host_pps and persistence >= 2:
        categories_passed.add("ATTACK_PATTERN")
    else:
        categories_failed.add("ATTACK_PATTERN")
    if reflection:
        categories_passed.add("ANOMALOUS_SERVICE")
    else:
        categories_failed.add("ANOMALOUS_SERVICE")

    network_context_points = 0
    if below_absolute_floor:
        network_context_points -= 15
    if web_return_likely:
        network_context_points -= 25
    elif cgnat_or_isp >= 0.5:
        network_context_points -= 12
    if cgnat_or_isp >= 0.7 and not reflection:
        network_context_points -= 8
    if reflection:
        network_context_points += 15
    network_context_points = int(max(-45, min(20, network_context_points)))

    volume = min(30, int(math.log10(max(10, packet_count)) * 7))
    host_distribution = min(20, int(unique_hosts / 2))
    persistence_points = min(20, persistence * 4)
    baseline_points = min(10, int(baseline_deviation * 2)) if baseline_deviation else 0
    score = _clamp(20 + volume + host_distribution + 12 + persistence_points + baseline_points + network_context_points)

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
    elif cgnat_or_isp >= 0.7 and not reflection:
        traffic_classification = SUSPICIOUS_DISTRIBUTED_TRAFFIC
        reason_codes.append(
            "CGNAT_DISTRIBUTION_EXPECTED"
            if cgnat_share >= isp_share
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

    verdict, severity = _verdict_severity(score, persistence, traffic_classification)
    return {
        "detector_score": score,
        "traffic_classification": traffic_classification,
        "verdict": verdict,
        "severity": severity,
        "reason_codes": reason_codes,
        "evidence_categories_passed": sorted(categories_passed),
        "evidence_categories_failed": sorted(categories_failed),
        "network_context_score": network_context_points,
        "below_absolute_floor": below_absolute_floor,
        "web_return_likely": web_return_likely,
        "features": {
            "aggregate_pps": round(aggregate_pps, 3),
            "aggregate_bps": round(aggregate_bps, 3),
            "unique_sources": unique_sources,
            "unique_destinations": unique_hosts,
            "max_host_pps": round(max_host_pps, 3),
            "web_return_share": round(web_return_share, 4),
            "udp_quic_share": round(udp_quic_share, 4),
            "tcp_ack_ratio": round(tcp_ack_ratio, 4),
            "tcp_syn_ratio": round(tcp_syn_ratio, 4),
            "dst_port_entropy": round(dst_port_entropy, 4),
        },
    }


def _reconstruct_features(event: Mapping[str, Any]) -> dict[str, Any]:
    """Best-effort reconstruction of new carpet features from persisted
    investigation snapshots for events recorded before the feature existed."""
    investigation = event.get("investigation") if isinstance(event.get("investigation"), Mapping) else {}
    nc = investigation.get("network_context") if isinstance(investigation.get("network_context"), Mapping) else {}
    evidence = investigation.get("detection_evidence") if isinstance(investigation.get("detection_evidence"), Mapping) else {}
    samples = investigation.get("samples") if isinstance(investigation.get("samples"), Mapping) else {}
    features = {
        "packets_per_second": float(event.get("packets_per_second") or 0),
        "bits_per_second": float(event.get("bits_per_second") or 0),
        "unique_sources": int(event.get("unique_sources") or evidence.get("source_count") or 0),
        "unique_destinations": int(event.get("unique_destinations") or evidence.get("destination_diversity") or 0),
        "unique_dst_ports": int(event.get("unique_dst_ports") or 0),
        "packets": int(event.get("packets") or 0),
        "baseline_deviation": float(event.get("baseline_deviation") or 0),
        "persistent_windows": int(samples.get("persistent_windows") or nc.get("persistent_windows") or 1),
        "max_host_pps": float(nc.get("max_host_pps") or 0),
        "target_cgnat_share": float(nc.get("target_cgnat_share") or 0),
        "target_downstream_isp_share": float(nc.get("target_downstream_isp_share") or 0),
    }
    if nc.get("web_return_share") is not None:
        # New events already carry the full network context.
        features.update(
            {
                "web_return_share": float(nc.get("web_return_share") or 0),
                "udp_quic_share": float(nc.get("udp_quic_share") or 0),
                "tcp_ack_ratio": float(nc.get("tcp_ack_ratio") or 0),
                "tcp_syn_ratio": float(nc.get("tcp_syn_ratio") or 0),
                "dst_port_entropy": float(nc.get("dst_port_entropy") or 0),
                "top_src_port": int(nc.get("top_src_port") or 0),
                "top_src_port_share": float(nc.get("top_src_port_share") or 0),
            }
        )
        return features
    # Legacy reconstruction from top_source_ports / tcp_flags / protocols.
    top_src = list(investigation.get("top_source_ports") or [])[:20]
    tcp_flags = list(investigation.get("tcp_flags") or [])[:20]
    protocols = list(investigation.get("protocols") or [])[:20]
    total_packets = max(1, sum(int(item.get("packets") or 0) for item in top_src))
    tcp_packets = sum(int(item.get("packets") or 0) for item in protocols if clean_lower(item.get("protocol")) == "tcp")
    udp_packets = sum(int(item.get("packets") or 0) for item in protocols if clean_lower(item.get("protocol")) == "udp")
    ack_packets = sum(int(item.get("packets") or 0) for item in tcp_flags if (int(item.get("flags") or 0) & 0x10))
    syn_packets = sum(int(item.get("packets") or 0) for item in tcp_flags if (int(item.get("flags") or 0) & 0x02))
    web_packets = sum(
        int(item.get("packets") or 0) for item in top_src if int(item.get("port") or 0) in (80, 443)
    )
    features["web_return_share"] = round(web_packets / total_packets, 4)
    features["tcp_ack_ratio"] = round(ack_packets / max(1, tcp_packets), 4)
    features["tcp_syn_ratio"] = round(syn_packets / max(1, tcp_packets), 4)
    features["udp_quic_share"] = round(
        sum(int(item.get("packets") or 0) for item in top_src if int(item.get("port") or 0) == 443 and udp_packets)
        / total_packets,
        4,
    )
    features["dst_port_entropy"] = 0.0
    return features


def clean_lower(value: Any) -> str:
    return str(value or "").strip().lower()


def replay_carpet_event(
    event: Mapping[str, Any],
    thresholds: DetectorThresholds | None = None,
) -> dict[str, Any]:
    """Compare a historical event against the current detector decision."""
    old_verdict = str(event.get("verdict") or "INFO").upper()
    old_score = int(event.get("detector_score") or 0)
    decision = replay_carpet_decision(_reconstruct_features(event), thresholds)
    new_verdict = decision["verdict"]
    classification = decision["traffic_classification"]

    old_attack = old_verdict in ATTACK_VERDICTS
    new_attack = new_verdict in ATTACK_VERDICTS
    if classification == EXPECTED_DISTRIBUTED_TRAFFIC and old_attack:
        comparison = "FALSE_POSITIVE_REDUCED"
    elif old_attack and new_attack:
        comparison = "UNCHANGED_ATTACK"
    elif old_attack and not new_attack:
        comparison = "ATTACK_DOWNGRADED"
    elif not old_attack and new_attack:
        comparison = "NEW_ATTACK_DETECTED"
    else:
        comparison = "REVIEW_REQUIRED"

    return {
        "event_id": event.get("event_id") or event.get("public_id") or event.get("id"),
        "attack_type": event.get("attack_type") or "CARPET_BOMBING",
        "target_prefix": event.get("target_prefix") or "",
        "first_seen": event.get("first_seen") or "",
        "last_seen": event.get("last_seen") or "",
        "old_detector_score": old_score,
        "old_verdict": old_verdict,
        "old_severity": event.get("severity") or "",
        "new_detector_score": decision["detector_score"],
        "new_traffic_classification": classification,
        "new_verdict": new_verdict,
        "new_severity": decision["severity"],
        "reason_codes": decision["reason_codes"],
        "comparison": comparison,
        "features": decision["features"],
        "evidence_categories_passed": decision["evidence_categories_passed"],
        "evidence_categories_failed": decision["evidence_categories_failed"],
        "network_context_score": decision["network_context_score"],
        "below_absolute_floor": decision["below_absolute_floor"],
        "web_return_likely": decision["web_return_likely"],
    }


def summarize_replay(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    old_confirmed = sum(1 for item in results if item["old_verdict"] in ATTACK_VERDICTS)
    new_confirmed = sum(1 for item in results if item["new_verdict"] in ATTACK_VERDICTS)
    expected = sum(1 for item in results if item["new_traffic_classification"] == EXPECTED_DISTRIBUTED_TRAFFIC)
    suspicious = sum(1 for item in results if item["new_traffic_classification"] == SUSPICIOUS_DISTRIBUTED_TRAFFIC)
    downgraded = sum(1 for item in results if item["comparison"] in {"FALSE_POSITIVE_REDUCED", "ATTACK_DOWNGRADED"})
    unchanged = sum(1 for item in results if item["comparison"] == "UNCHANGED_ATTACK")
    absolute_floor_downgrades = sum(
        1 for item in results
        if item["comparison"] in {"FALSE_POSITIVE_REDUCED", "ATTACK_DOWNGRADED"}
        and "ABSOLUTE_VOLUME_TOO_LOW" in item["reason_codes"]
        and "LIKELY_WEB_RETURN_TRAFFIC" not in item["reason_codes"]
    )
    web_return_downgrades = sum(
        1 for item in results
        if item["comparison"] in {"FALSE_POSITIVE_REDUCED", "ATTACK_DOWNGRADED"}
        and "LIKELY_WEB_RETURN_TRAFFIC" in item["reason_codes"]
    )
    reason_counter: dict[str, int] = {}
    for item in results:
        if item["comparison"] in {"FALSE_POSITIVE_REDUCED", "ATTACK_DOWNGRADED"}:
            for code in item["reason_codes"]:
                reason_counter[code] = reason_counter.get(code, 0) + 1
    return {
        "total_events": total,
        "old_confirmed": old_confirmed,
        "new_confirmed": new_confirmed,
        "expected": expected,
        "suspicious": suspicious,
        "downgraded": downgraded,
        "unchanged_attack": unchanged,
        "absolute_floor_downgrades": absolute_floor_downgrades,
        "web_return_downgrades": web_return_downgrades,
        "top_reason_codes": sorted(reason_counter.items(), key=lambda item: (-item[1], item[0])),
        "comparisons": {
            comparison: sum(1 for item in results if item["comparison"] == comparison)
            for comparison in COMPARISONS
        },
    }


__all__ = [
    "ATTACK_VERDICTS",
    "COMPARISONS",
    "replay_carpet_decision",
    "replay_carpet_event",
    "summarize_replay",
]
