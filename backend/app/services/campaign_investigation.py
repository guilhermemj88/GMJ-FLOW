from __future__ import annotations

from datetime import datetime
import sqlite3
from typing import Any, Mapping, Sequence

from app.services.behavioral_detection import attack_vector_row, campaign_row
from app.services.security_events import security_event_row
from app.services.threat_contracts import attack_family
from app.services.threat_intelligence import clean_text


SOURCE_LIMIT = 100
ASN_LIMIT = 100
DETAIL_LIMIT = 20


def _duration_seconds(first_seen: Any, last_seen: Any) -> float | None:
    try:
        first = datetime.fromisoformat(clean_text(first_seen).replace("Z", "+00:00"))
        last = datetime.fromisoformat(clean_text(last_seen).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return max(0.0, round((last - first).total_seconds(), 3))


def _optional_number(value: Mapping[str, Any], *keys: str, integer: bool = False) -> int | float | None:
    for key in keys:
        if key not in value or value.get(key) in (None, ""):
            continue
        try:
            return int(float(value[key])) if integer else float(value[key])
        except (TypeError, ValueError):
            continue
    return None


def _sum_vector_feature(vectors: Sequence[Mapping[str, Any]], *keys: str, integer: bool = False) -> int | float | None:
    values: list[int | float] = []
    for vector in vectors:
        features = vector.get("features") if isinstance(vector.get("features"), Mapping) else {}
        parsed = _optional_number(features, *keys, integer=integer)
        if parsed is not None:
            values.append(parsed)
    if not values:
        return None
    total = sum(values)
    return int(total) if integer else round(float(total), 4)


def _source_intel_maps(campaign: Mapping[str, Any], vectors: Sequence[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    merged: dict[str, list[dict[str, Any]]] = {}
    for owner in [campaign, *vectors]:
        threat = owner.get("threat_intel") if isinstance(owner.get("threat_intel"), Mapping) else {}
        source_intel = threat.get("source_intel") if isinstance(threat.get("source_intel"), Mapping) else {}
        sources = source_intel.get("sources") if isinstance(source_intel.get("sources"), Mapping) else {}
        for ip, matches in list(sources.items())[:SOURCE_LIMIT]:
            normalized = merged.setdefault(clean_text(ip), [])
            for match in [item for item in (matches or []) if isinstance(item, Mapping)][:10]:
                candidate = dict(match)
                if candidate not in normalized:
                    normalized.append(candidate)
    return merged


def _primary_intel(matches: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    priority = {"malicious": 5, "c2": 5, "suspicious": 4, "scanner": 3, "benign": 1}
    return max(
        matches,
        key=lambda item: priority.get(clean_text(item.get("classification") or item.get("indicator_type")).lower(), 2),
        default={},
    )


def _source_snapshots(owner: Mapping[str, Any]) -> list[dict[str, Any]]:
    features = owner.get("features") if isinstance(owner.get("features"), Mapping) else {}
    details = [dict(item) for item in (features.get("top_source_details") or []) if isinstance(item, Mapping)]
    if details:
        return details[:SOURCE_LIMIT]
    compact = features.get("top_sources") if isinstance(features.get("top_sources"), Mapping) else {}
    return [
        {"source_ip": clean_text(ip), "packets": packets}
        for ip, packets in list(compact.items())[:SOURCE_LIMIT]
        if clean_text(ip)
    ]


def campaign_top_sources(campaign: Mapping[str, Any], vectors: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    # A campaign-level snapshot, when present, is authoritative. Older rows did
    # not persist it, so linked behavioral vectors are the local persisted
    # fallback. Canonical security_events are intentionally not consulted.
    snapshots = _source_snapshots(campaign)
    if not snapshots:
        snapshots = [item for vector in vectors for item in _source_snapshots(vector)]
    intel_by_ip = _source_intel_maps(campaign, vectors)
    aggregated: dict[str, dict[str, Any]] = {}
    for source in snapshots[: SOURCE_LIMIT * 10]:
        ip = clean_text(source.get("source_ip") or source.get("src_ip"))
        if not ip:
            continue
        row = aggregated.setdefault(
            ip,
            {
                "source_ip": ip,
                "source_asn": 0,
                "asn_organization": "",
                "packets": 0,
                "bytes": 0,
                "flows": 0,
                "pps": 0.0,
            },
        )
        row["source_asn"] = int(source.get("source_asn") or source.get("src_asn") or row["source_asn"] or 0)
        row["asn_organization"] = clean_text(
            source.get("asn_organization") or source.get("organization") or row["asn_organization"]
        )
        row["packets"] += max(0, int(source.get("packets") or 0))
        row["bytes"] += max(0, int(source.get("bytes") or 0))
        row["flows"] += max(0, int(source.get("flows") or source.get("flow_count") or 0))
        row["pps"] = round(float(row["pps"]) + max(0.0, float(source.get("pps") or 0)), 4)

    total_packets = sum(int(item["packets"]) for item in aggregated.values())
    result: list[dict[str, Any]] = []
    for row in aggregated.values():
        matches = intel_by_ip.get(row["source_ip"], [])
        primary = _primary_intel(matches)
        providers = sorted({clean_text(item.get("provider")) for item in matches if clean_text(item.get("provider"))})
        if not row["asn_organization"]:
            row["asn_organization"] = clean_text(primary.get("organization"))
        row.update(
            {
                "share": round((int(row["packets"]) / total_packets * 100) if total_packets else 0.0, 4),
                "threat_intelligence_classification": clean_text(
                    primary.get("classification") or primary.get("indicator_type")
                ),
                "threat_intelligence_provider": clean_text(primary.get("provider")),
                "threat_intelligence_providers": providers,
                "threat_intelligence": {"matches": list(matches)[:10]},
            }
        )
        result.append(row)
    return sorted(result, key=lambda item: (-int(item["packets"]), item["source_ip"]))[:SOURCE_LIMIT]


def campaign_asn_distribution(campaign: Mapping[str, Any], top_sources: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    features = campaign.get("features") if isinstance(campaign.get("features"), Mapping) else {}
    persisted = [dict(item) for item in (features.get("asn_distribution") or []) if isinstance(item, Mapping)]
    if persisted:
        result = []
        for item in persisted[:ASN_LIMIT]:
            result.append(
                {
                    "asn": int(item.get("asn") or item.get("source_asn") or 0),
                    "organization": clean_text(item.get("organization") or item.get("asn_organization")),
                    "sources": _optional_number(item, "sources", "source_count", integer=True),
                    "percentage": _optional_number(item, "percentage", "percent", "share"),
                }
            )
        return result

    totals: dict[int, dict[str, Any]] = {}
    for source in top_sources:
        asn = int(source.get("source_asn") or 0)
        if not asn:
            continue
        row = totals.setdefault(
            asn,
            {"asn": asn, "organization": clean_text(source.get("asn_organization")), "source_ips": set()},
        )
        row["source_ips"].add(clean_text(source.get("source_ip")))
        if not row["organization"]:
            row["organization"] = clean_text(source.get("asn_organization"))
    represented = sum(len(item["source_ips"]) for item in totals.values())
    if totals:
        return sorted(
            [
                {
                    "asn": asn,
                    "organization": item["organization"],
                    "sources": len(item["source_ips"]),
                    "percentage": round(len(item["source_ips"]) / represented * 100, 2) if represented else None,
                }
                for asn, item in totals.items()
            ],
            key=lambda item: (-int(item["sources"] or 0), int(item["asn"])),
        )[:ASN_LIMIT]

    sample = features.get("source_asns_sample") or []
    return [
        {"asn": int(asn), "organization": "", "sources": None, "percentage": None}
        for asn in sample[:ASN_LIMIT]
        if int(asn or 0)
    ]


def _ranked_feature_details(
    campaign: Mapping[str, Any],
    vectors: Sequence[Mapping[str, Any]],
    feature_name: str,
    identity: str,
) -> list[dict[str, Any]]:
    campaign_features = campaign.get("features") if isinstance(campaign.get("features"), Mapping) else {}
    owners: Sequence[Mapping[str, Any]] = [campaign] if campaign_features.get(feature_name) else vectors
    rows: dict[str, dict[str, Any]] = {}
    for owner in owners:
        features = owner.get("features") if isinstance(owner.get("features"), Mapping) else {}
        for detail in [item for item in (features.get(feature_name) or []) if isinstance(item, Mapping)]:
            key = clean_text(detail.get(identity))
            if not key:
                continue
            row = rows.setdefault(key, {identity: detail.get(identity), "packets": 0, "bytes": 0, "flows": 0})
            for metric in ("packets", "bytes", "flows"):
                row[metric] += max(0, int(detail.get(metric) or 0))
    return sorted(rows.values(), key=lambda item: (-int(item["packets"]), clean_text(item.get(identity))))[:DETAIL_LIMIT]


def _enrichment_summary(campaign: Mapping[str, Any]) -> dict[str, Any]:
    threat = campaign.get("threat_intel") if isinstance(campaign.get("threat_intel"), Mapping) else {}
    source = threat.get("source_intel") if isinstance(threat.get("source_intel"), Mapping) else {}
    target = threat.get("target_campaign_intel") if isinstance(threat.get("target_campaign_intel"), Mapping) else {}
    persisted_sources = source.get("sources") if isinstance(source.get("sources"), Mapping) else {}
    persisted_matches = [
        item
        for matches in persisted_sources.values()
        for item in (matches or [])
        if isinstance(item, Mapping)
    ][:100]
    target_observations = [item for item in (target.get("observations") or []) if isinstance(item, Mapping)][:20]
    providers = sorted(
        {
            clean_text(item)
            for item in [
                *(campaign.get("intel_sources") or []),
                *(source.get("intel_sources") or []),
                *(target.get("intel_sources") or []),
                *(match.get("provider") for match in persisted_matches),
                *(observation.get("provider") for observation in target_observations),
            ]
            if clean_text(item)
        }
    )
    source_matches = int(source.get("matched_source_count") or source.get("matches") or 0)
    target_matches = int(target.get("matches") or 0)
    total_matches = int(threat.get("matches") or 0) or source_matches + target_matches
    available = bool(total_matches or providers or source.get("sources") or target.get("observations"))
    return {
        "available": available,
        "matches": total_matches,
        "matched_sources": source_matches,
        "lookup_count": int(source.get("lookup_count") or 0),
        "target_matches": target_matches,
        "providers": providers,
        "classifications": list(source.get("classifications") or sorted({
            clean_text(item.get("classification")) for item in persisted_matches if clean_text(item.get("classification"))
        }))[:20],
        "indicator_types": list(source.get("indicator_types") or [])[:20],
        "tags": list(source.get("tags") or [])[:50],
    }


def _correlated_event_summary(event: Mapping[str, Any]) -> dict[str, Any]:
    threat = event.get("threat_intel") if isinstance(event.get("threat_intel"), Mapping) else {}
    source = threat.get("source_intel") if isinstance(threat.get("source_intel"), Mapping) else {}
    return {
        "id": event.get("id"),
        "public_id": event.get("event_id") or event.get("public_id"),
        "event_type": event.get("attack_type"),
        "score": event.get("detector_score"),
        "target": event.get("target_prefix") or event.get("target_ip"),
        "first_seen": event.get("first_seen"),
        "last_seen": event.get("last_seen"),
        "source_count": event.get("unique_sources"),
        "threat_intelligence": {
            "matched_sources": int(source.get("matched_source_count") or source.get("matches") or 0),
            "providers": list(source.get("intel_sources") or event.get("intel_sources") or [])[:20],
            "classifications": list(source.get("classifications") or [])[:20],
        },
    }


def get_campaign_investigation(conn: sqlite3.Connection, campaign_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM threat_campaigns WHERE campaign_id=?", (clean_text(campaign_id),)).fetchone()
    if row is None:
        return None
    campaign = campaign_row(row)
    vector_rows = conn.execute(
        "SELECT * FROM behavioral_attack_vectors WHERE campaign_id=? ORDER BY last_seen DESC, id DESC",
        (campaign["campaign_id"],),
    ).fetchall()
    vectors = [attack_vector_row(item) for item in vector_rows]
    try:
        event_rows = conn.execute(
            "SELECT * FROM security_events WHERE campaign_id=? ORDER BY last_seen DESC, id DESC",
            (campaign["campaign_id"],),
        ).fetchall()
    except sqlite3.OperationalError:
        event_rows = []
    events = [security_event_row(item) for item in event_rows]
    features = campaign.get("features") if isinstance(campaign.get("features"), Mapping) else {}
    persistence_value = features.get("persistence_satisfied") if "persistence_satisfied" in features else None
    top_sources = campaign_top_sources(campaign, vectors)
    asn_distribution = campaign_asn_distribution(campaign, top_sources)
    protocols = _ranked_feature_details(campaign, vectors, "protocol_distribution", "protocol")
    destination_ports = _ranked_feature_details(campaign, vectors, "top_destination_port_details", "port")
    source_ports = _ranked_feature_details(campaign, vectors, "top_source_port_details", "port")
    packets = _optional_number(features, "packet_count", "packets", "aggregate_packets", integer=True)
    bytes_count = _optional_number(features, "byte_count", "bytes", "aggregate_bytes", integer=True)
    flows = _optional_number(features, "flow_count", "flows", "aggregate_flows", integer=True)
    if packets is None:
        packets = _sum_vector_feature(vectors, "packet_count", "packets", integer=True)
    if bytes_count is None:
        bytes_count = _sum_vector_feature(vectors, "byte_count", "bytes", integer=True)
    if flows is None:
        flows = _sum_vector_feature(vectors, "flow_count", "flows", integer=True)
    family = clean_text(features.get("attack_family")) or attack_family(campaign.get("classification"))
    detectors = sorted({clean_text(item.get("detector")) for item in vectors if clean_text(item.get("detector"))})
    enrichment = _enrichment_summary(campaign)
    duration = _duration_seconds(campaign.get("first_seen"), campaign.get("last_seen"))
    campaign.update(
        {
            "family": family,
            "target": campaign.get("target_prefix"),
            "duration_seconds": duration,
            "persistence_satisfied": persistence_value,
            "persistence": "satisfied" if persistence_value is True else "insufficient" if persistence_value is False else "unknown",
            "detector": clean_text(features.get("detector")) or "campaign_engine",
            "contributing_detectors": detectors,
            "enrichment_summary": enrichment,
        }
    )
    target_traffic = {
        "target": campaign.get("target_prefix"),
        "protocol": ", ".join(clean_text(item.get("protocol")) for item in protocols if clean_text(item.get("protocol"))) or None,
        "protocols": protocols,
        "ports": destination_ports,
        "source_ports": source_ports,
        "pps": campaign.get("packets_per_second"),
        "bps": campaign.get("bits_per_second"),
        "flows_per_second": campaign.get("flows_per_second"),
        "packets": packets,
        "bytes": bytes_count,
        "flows": flows,
        "source_count": campaign.get("unique_sources"),
        "asn_diversity": campaign.get("unique_source_asns"),
    }
    correlation_features = {
        key: features.get(key)
        for key in (
            "concurrent_sources", "source_arrival_rate", "source_churn_rate", "temporal_correlation",
            "protocol_similarity", "port_similarity", "packet_size_similarity", "target_similarity",
            "source_asn_diversity", "ddos_minimum_satisfied", "target_correlation",
            "persistence_satisfied", "historical_recurrence", "attack_types",
        )
        if key in features
    }
    evidence = {
        "campaign_detector": campaign["detector"],
        "correlation_features": correlation_features,
        "contributing_vectors": [
            {
                "attack_type": item.get("attack_type"),
                "detector": item.get("detector"),
                "score": item.get("detector_score"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "source": item.get("src_ip"),
                "target": item.get("target_prefix") or item.get("target_ip"),
            }
            for item in vectors[:50]
        ],
    }
    return {
        "campaign": campaign,
        "top_sources": top_sources,
        "asn_distribution": asn_distribution,
        "asn_distribution_context": {
            "represented_sources": sum(int(item.get("sources") or 0) for item in asn_distribution),
            "campaign_source_count": campaign.get("unique_sources"),
            "percentage_scope": "persisted_campaign_distribution" if features.get("asn_distribution") else "persisted_top_sources_snapshot",
        },
        "target_traffic": target_traffic,
        "correlated_events": [_correlated_event_summary(item) for item in events],
        # Kept for clients that already consumed the original endpoint.
        "events": events,
        "detection_correlation_evidence": evidence,
        "data_sources": {
            "campaign": "threat_campaigns",
            "investigation_snapshots": "behavioral_attack_vectors",
            "correlated_events": "security_events",
            "external_lookups_performed": False,
        },
    }


def campaign_analysis_payload(investigation: Mapping[str, Any]) -> dict[str, Any]:
    campaign = investigation.get("campaign") if isinstance(investigation.get("campaign"), Mapping) else {}
    traffic = investigation.get("target_traffic") if isinstance(investigation.get("target_traffic"), Mapping) else {}
    threat = campaign.get("threat_intel") if isinstance(campaign.get("threat_intel"), Mapping) else {}
    source_intel = threat.get("source_intel") if isinstance(threat.get("source_intel"), Mapping) else {}
    source_matches = source_intel.get("sources") if isinstance(source_intel.get("sources"), Mapping) else {}
    target_intel = threat.get("target_campaign_intel") if isinstance(threat.get("target_campaign_intel"), Mapping) else {}
    bounded_sources = [
        {
            key: item.get(key)
            for key in (
                "source_ip", "source_asn", "asn_organization", "packets", "bytes", "flows", "pps",
                "share", "threat_intelligence_classification", "threat_intelligence_providers",
            )
        }
        for item in [value for value in (investigation.get("top_sources") or []) if isinstance(value, Mapping)][:50]
    ]
    bounded_intel_rows = []
    for ip, matches in list(source_matches.items())[:50]:
        for match in [item for item in (matches or []) if isinstance(item, Mapping)][:5]:
            bounded_intel_rows.append(
                {
                    "source_ip": clean_text(ip)[:64],
                    "provider": clean_text(match.get("provider"))[:100],
                    "classification": clean_text(match.get("classification") or match.get("indicator_type"))[:100],
                    "organization": clean_text(match.get("organization"))[:300],
                    "country": clean_text(match.get("country") or match.get("country_code"))[:100],
                    "last_seen": clean_text(match.get("last_seen"))[:100],
                    "tags": [clean_text(value)[:100] for value in (match.get("tags") or [])[:20]],
                }
            )
            if len(bounded_intel_rows) >= 50:
                break
        if len(bounded_intel_rows) >= 50:
            break
    return {
        "campaign_metadata": {
            "campaign_id": campaign.get("campaign_id"),
            "classification": campaign.get("classification"),
            "family": campaign.get("family"),
            "coordination_score": campaign.get("coordination_score"),
            "first_seen": campaign.get("first_seen"),
            "last_seen": campaign.get("last_seen"),
            "duration_seconds": campaign.get("duration_seconds"),
            "persistence": campaign.get("persistence"),
            "recurrence_count": campaign.get("recurrence_count"),
            "detector": campaign.get("detector"),
            "contributing_detectors": campaign.get("contributing_detectors"),
        },
        "target": {"prefix": campaign.get("target"), "protocol": traffic.get("protocol"), "ports": traffic.get("ports")},
        "coordination_score": campaign.get("coordination_score"),
        "top_sources": bounded_sources,
        "asn_diversity": {
            "count": campaign.get("unique_source_asns"),
            "distribution": list(investigation.get("asn_distribution") or [])[:20],
            "distribution_context": investigation.get("asn_distribution_context") or {},
        },
        "traffic_metrics": dict(traffic),
        "correlated_events": list(investigation.get("correlated_events") or [])[:20],
        "threat_intelligence": {
            "summary": campaign.get("enrichment_summary") or {},
            "source_matches": bounded_intel_rows,
            "target_observations": [dict(item) for item in (target_intel.get("observations") or []) if isinstance(item, Mapping)][:20],
        },
        "detection_correlation_evidence": investigation.get("detection_correlation_evidence") or {},
        "analysis_constraints": {
            "threat_intelligence_is_enrichment_only": True,
            "ai_is_manual_and_advisory_only": True,
            "automatic_mitigation_enabled": False,
            "external_lookups_performed": False,
        },
    }
