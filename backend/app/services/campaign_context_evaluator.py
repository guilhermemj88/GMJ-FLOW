from __future__ import annotations

from datetime import datetime
import os
from typing import Any, Mapping, Sequence


MALICIOUS_MARKERS = ("malicious", "c2", "botnet", "exploit", "scanner", "scan")


def _number(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _integer(value: Any) -> int | None:
    parsed = _number(value)
    return int(parsed) if parsed is not None else None


def _first_number(owner: Mapping[str, Any], *keys: str) -> float | None:
    for key in keys:
        parsed = _number(owner.get(key))
        if parsed is not None:
            return parsed
    return None


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    parsed = _number(os.getenv(name))
    value = default if parsed is None else parsed
    return max(minimum, min(value, maximum))


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    parsed = _integer(os.getenv(name))
    value = default if parsed is None else parsed
    return max(minimum, min(value, maximum))


def campaign_context_thresholds() -> dict[str, int | float]:
    """Readable, investigation-only thresholds; never mitigation inputs."""
    return {
        "cgnat_min_pps_for_suspicious": _env_float(
            "GMJFLOW_CAMPAIGN_CGNAT_MIN_PPS_FOR_SUSPICIOUS", 1000.0, 0.0, 1_000_000_000.0
        ),
        "cgnat_min_bps_for_suspicious": _env_float(
            "GMJFLOW_CAMPAIGN_CGNAT_MIN_BPS_FOR_SUSPICIOUS", 100_000_000.0, 0.0, 10_000_000_000_000.0
        ),
        "cgnat_min_baseline_ratio": _env_float(
            "GMJFLOW_CAMPAIGN_CGNAT_MIN_BASELINE_RATIO", 2.0, 1.0, 1000.0
        ),
        "cgnat_min_per_host_pps": _env_float(
            "GMJFLOW_CAMPAIGN_CGNAT_MIN_PER_HOST_PPS", 10.0, 0.0, 1_000_000.0
        ),
        "cgnat_min_per_host_bps": _env_float(
            "GMJFLOW_CAMPAIGN_CGNAT_MIN_PER_HOST_BPS", 10_000_000.0, 0.0, 1_000_000_000_000.0
        ),
        "ti_min_malicious_ratio": _env_float(
            "GMJFLOW_CAMPAIGN_TI_MIN_MALICIOUS_RATIO", 0.01, 0.0, 1.0
        ),
        "ti_min_top_malicious": _env_int(
            "GMJFLOW_CAMPAIGN_TI_MIN_TOP_MALICIOUS", 3, 1, 100
        ),
    }


def _duration_seconds(first_seen: Any, last_seen: Any) -> float | None:
    try:
        first = datetime.fromisoformat(str(first_seen or "").replace("Z", "+00:00"))
        last = datetime.fromisoformat(str(last_seen or "").replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return max(0.0, round((last - first).total_seconds(), 3))


def _features(owner: Mapping[str, Any]) -> Mapping[str, Any]:
    value = owner.get("features")
    return value if isinstance(value, Mapping) else {}


def _network_context(owner: Mapping[str, Any]) -> Mapping[str, Any]:
    direct = owner.get("network_context")
    if isinstance(direct, Mapping):
        return direct
    value = _features(owner).get("network_context")
    return value if isinstance(value, Mapping) else {}


def _primary_vector(vectors: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    def rate(item: Mapping[str, Any]) -> float:
        features = _features(item)
        return _first_number(features, "aggregate_pps", "packets_per_second", "pps") or 0.0

    return max(vectors, key=rate, default={})


def _is_malicious(value: Any) -> bool:
    normalized = str(value or "").strip().lower()
    return any(marker in normalized for marker in MALICIOUS_MARKERS)


def _intel_matches(owner: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    threat = owner.get("threat_intel")
    threat = threat if isinstance(threat, Mapping) else {}
    source = threat.get("source_intel")
    source = source if isinstance(source, Mapping) else {}
    sources = source.get("sources")
    sources = sources if isinstance(sources, Mapping) else {}
    target = threat.get("target_campaign_intel")
    target = target if isinstance(target, Mapping) else {}
    return source, sources, target


def _top_source_rows(campaign: Mapping[str, Any], vectors: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    supplied = campaign.get("top_sources")
    if isinstance(supplied, list):
        return [dict(item) for item in supplied if isinstance(item, Mapping)]
    for owner in (campaign, *vectors):
        details = _features(owner).get("top_source_details")
        if isinstance(details, list) and details:
            return [dict(item) for item in details if isinstance(item, Mapping)]
    return []


def evaluate_campaign_context(
    campaign: Mapping[str, Any],
    *,
    vectors: Sequence[Mapping[str, Any]] = (),
    correlated_events: Sequence[Mapping[str, Any]] = (),
    top_sources: Sequence[Mapping[str, Any]] | None = None,
    target_traffic: Mapping[str, Any] | None = None,
    detection_context: Mapping[str, Any] | None = None,
    thresholds: Mapping[str, int | float] | None = None,
) -> dict[str, Any]:
    """Evaluate a Campaign using persisted local evidence only.

    This function is deliberately pure: it performs no lookup, persistence,
    Security Event creation, policy decision, or mitigation action.
    """
    limits = campaign_context_thresholds()
    limits.update(thresholds or {})
    vectors = [item for item in vectors if isinstance(item, Mapping)]
    correlated_events = [item for item in correlated_events if isinstance(item, Mapping)]
    primary = _primary_vector(vectors)
    features = _features(primary)
    campaign_features = _features(campaign)
    traffic = target_traffic if isinstance(target_traffic, Mapping) else {}
    detection = detection_context if isinstance(detection_context, Mapping) else {}
    network = detection.get("network_context") if isinstance(detection.get("network_context"), Mapping) else _network_context(primary)

    target_role = str(
        detection.get("target_role")
        or traffic.get("target_role")
        or network.get("dst_role")
        or features.get("dst_role")
        or campaign_features.get("target_role")
        or "UNKNOWN"
    ).strip().upper()
    is_cgnat = target_role == "CGNAT_PUBLIC" or bool(network.get("dst_is_cgnat") or features.get("dst_is_cgnat"))
    if is_cgnat:
        target_role = "CGNAT_PUBLIC"

    peak_pps = _first_number(campaign, "packets_per_second", "peak_pps")
    peak_bps = _first_number(campaign, "bits_per_second", "peak_bps")
    observed_pps = _first_number(detection, "observed_pps") or _first_number(features, "aggregate_pps", "packets_per_second", "pps") or peak_pps
    observed_bps = _first_number(detection, "observed_bps") or _first_number(features, "aggregate_bps", "bits_per_second", "bps") or peak_bps
    baseline_delta = _first_number(detection, "baseline_delta") or _first_number(primary, "baseline_deviation") or _first_number(features, "baseline_delta")
    baseline_ratio = _first_number(features, "baseline_ratio") or baseline_delta
    baseline_pps = _first_number(detection, "baseline_pps") or _first_number(features, "baseline_pps")
    baseline_bps = _first_number(detection, "baseline_bps") or _first_number(features, "baseline_bps")
    if baseline_pps is None and observed_pps is not None and baseline_ratio and baseline_ratio > 0:
        baseline_pps = round(observed_pps / baseline_ratio, 4)
    if baseline_bps is None and observed_bps is not None and baseline_ratio and baseline_ratio > 0:
        baseline_bps = round(observed_bps / baseline_ratio, 4)

    max_pps_per_host = _first_number(detection, "max_per_host_pps") or _first_number(features, "max_host_pps", "max_per_host_pps")
    max_bps_per_host = _first_number(detection, "max_per_host_bps") or _first_number(features, "max_host_bps", "max_per_host_bps")
    source_count = _integer(detection.get("source_count")) or _integer(traffic.get("source_count")) or _integer(campaign.get("unique_sources")) or 0
    asn_count = _integer(detection.get("asn_diversity")) or _integer(traffic.get("asn_diversity")) or _integer(campaign.get("unique_source_asns")) or 0
    destination_count = _integer(detection.get("destination_count")) or _integer(features.get("unique_destinations")) or _integer(features.get("unique_dst_ips")) or 0
    recurrence_count = _integer(campaign.get("recurrence_count")) or 0
    persistence_seconds = _first_number(campaign_features, "persistence_seconds")
    if persistence_seconds is None:
        persistence_seconds = _number(campaign.get("duration_seconds"))
    if persistence_seconds is None:
        persistence_seconds = _duration_seconds(campaign.get("first_seen"), campaign.get("last_seen"))

    source_intel, _, target_intel = _intel_matches(campaign)
    matched_source_ips: set[str] = set()
    malicious_source_ips: set[str] = set()
    matches_by_ip: dict[str, list[Mapping[str, Any]]] = {}
    for owner in (campaign, *vectors):
        owner_source, owner_sources, _ = _intel_matches(owner)
        for ip, matches in owner_sources.items():
            normalized_ip = str(ip or "").strip()
            if not normalized_ip:
                continue
            matched_source_ips.add(normalized_ip)
            destination = matches_by_ip.setdefault(normalized_ip, [])
            for match in matches or []:
                if not isinstance(match, Mapping):
                    continue
                destination.append(match)
                classification = match.get("classification") or match.get("indicator_type")
                tags = " ".join(str(item) for item in (match.get("tags") or []))
                if _is_malicious(classification) or _is_malicious(tags) or _is_malicious(match.get("botnet_family")):
                    malicious_source_ips.add(normalized_ip)
        if not owner_sources and any(_is_malicious(value) for value in (owner_source.get("classifications") or [])):
            reported = _integer(owner_source.get("matched_source_count") or owner_source.get("matches")) or 0
            for index in range(reported):
                malicious_source_ips.add(f"persisted-summary-{index}")

    ranked_sources = [dict(item) for item in (top_sources or _top_source_rows(campaign, vectors)) if isinstance(item, Mapping)]
    malicious_top = 0
    sources_with_intel = 0
    for source in ranked_sources:
        ip = str(source.get("source_ip") or source.get("src_ip") or "").strip()
        matches = matches_by_ip.get(ip, [])
        classification = source.get("threat_intelligence_classification")
        has_intel = bool(matches or classification or source.get("threat_intelligence_provider"))
        malicious = _is_malicious(classification) or any(
            _is_malicious(match.get("classification") or match.get("indicator_type"))
            or _is_malicious(" ".join(str(item) for item in (match.get("tags") or [])))
            for match in matches
        )
        if has_intel and ip:
            matched_source_ips.add(ip)
        if malicious:
            malicious_source_ips.add(ip or f"persisted-top-source-{malicious_top}")
        sources_with_intel += int(has_intel)
        malicious_top += int(malicious)
    first_top = ranked_sources[0] if ranked_sources else {}
    first_ip = str(first_top.get("source_ip") or first_top.get("src_ip") or "").strip()
    first_matches = matches_by_ip.get(first_ip, [])
    top_source_has_threat_intel = bool(
        first_matches
        or first_top.get("threat_intelligence_classification")
        or first_top.get("threat_intelligence_provider")
    )
    top_source_malicious = _is_malicious(first_top.get("threat_intelligence_classification")) or any(
        _is_malicious(match.get("classification") or match.get("indicator_type"))
        or _is_malicious(" ".join(str(item) for item in (match.get("tags") or [])))
        for match in first_matches
    )

    reported_matches = _integer(source_intel.get("matched_source_count") or source_intel.get("matches")) or 0
    target_matches = _integer(target_intel.get("matches")) or 0
    threat_intel_match_count = max(len(matched_source_ips), reported_matches) + target_matches
    threat_intel_malicious_count = len(malicious_source_ips)
    threat_intel_match_ratio = round(threat_intel_match_count / source_count, 6) if source_count else 0.0
    malicious_match_ratio = round(threat_intel_malicious_count / source_count, 6) if source_count else 0.0

    baseline_elevated = bool(baseline_ratio is not None and baseline_ratio >= float(limits["cgnat_min_baseline_ratio"]))
    aggregate_volume_elevated = bool(
        (peak_pps is not None and peak_pps >= float(limits["cgnat_min_pps_for_suspicious"]))
        or (peak_bps is not None and peak_bps >= float(limits["cgnat_min_bps_for_suspicious"]))
    )
    per_host_elevated = bool(
        (max_pps_per_host is not None and max_pps_per_host >= float(limits["cgnat_min_per_host_pps"]))
        or (max_bps_per_host is not None and max_bps_per_host >= float(limits["cgnat_min_per_host_bps"]))
    )
    multiple_top_malicious = malicious_top >= int(limits["ti_min_top_malicious"])
    relevant_ti_ratio = bool(
        threat_intel_malicious_count > 0
        and malicious_match_ratio >= float(limits["ti_min_malicious_ratio"])
    )
    relevant_threat_intel = bool(multiple_top_malicious or relevant_ti_ratio or top_source_malicious)
    threat_intel_reinforced = bool(
        multiple_top_malicious or relevant_ti_ratio or (top_source_malicious and recurrence_count >= 3)
    )
    strong_traffic_signal = bool(
        baseline_elevated and (aggregate_volume_elevated or per_host_elevated)
    )
    event_count = len(correlated_events)
    vector_count = len(vectors)

    signals = {
        "security_event_correlated": event_count > 0,
        "attack_vector_correlated": vector_count > 0,
        "aggregate_volume_elevated": aggregate_volume_elevated,
        "baseline_elevated": baseline_elevated,
        "per_host_rate_elevated": per_host_elevated,
        "strong_traffic_deviation": strong_traffic_signal,
        "relevant_threat_intel": relevant_threat_intel,
        "multiple_top_sources_malicious": multiple_top_malicious,
        "top_source_malicious": top_source_malicious,
        "threat_intel_reinforced_by_context": threat_intel_reinforced,
        "single_match_is_proportionally_weak": threat_intel_malicious_count == 1 and source_count >= 100,
    }
    reasons: list[str] = []
    strong_categories = int(strong_traffic_signal) + int(relevant_threat_intel)
    if event_count:
        state = "corroborated"
        attack_confidence = "high"
        false_positive_risk = "low"
        reasons.append(f"Há {event_count} Security Event(s) canônico(s) correlacionado(s) à campanha.")
    elif vector_count:
        state = "corroborated"
        attack_confidence = "high" if strong_categories else "medium"
        false_positive_risk = "low" if strong_categories else "medium"
        reasons.append(f"Há {vector_count} Attack Vector(s) local(is) correlacionado(s) à campanha.")
    elif strong_categories >= 2:
        state = "corroborated"
        attack_confidence = "high"
        false_positive_risk = "low"
        reasons.append("Desvio forte de tráfego e Threat Intelligence relevante fornecem evidências independentes.")
    elif strong_categories == 1:
        state = "suspicious"
        attack_confidence = "medium" if threat_intel_reinforced else "low"
        false_positive_risk = "medium"
        reasons.append(
            "Há desvio relevante de tráfego em relação ao baseline."
            if strong_traffic_signal
            else "Threat Intelligence persistida é relevante pela posição ou proporção entre as fontes analisadas."
        )
    else:
        state = "observed"
        attack_confidence = "low"
        false_positive_risk = "high" if is_cgnat else "medium"
        reasons.append("O padrão comportamental foi observado, mas não há evidência local ou contextual forte suficiente.")

    if is_cgnat and state == "observed":
        reasons.append("Em CGNAT_PUBLIC, diversidade alta, persistência e muitas fontes podem refletir agregação carrier-grade normal.")
        if not aggregate_volume_elevated and not per_host_elevated:
            reasons.append("As taxas agregada e por host estão abaixo dos limites contextuais conservadores.")
    if signals["single_match_is_proportionally_weak"]:
        reasons.append("Um único match malicioso entre muitas fontes é sinal proporcionalmente fraco e não corrobora a campanha sozinho.")
    if threat_intel_match_count == 0:
        reasons.append("Não há Threat Intelligence persistida relevante; ausência de match não significa origem benigna.")

    protocol_distribution = list(traffic.get("protocols") or campaign_features.get("protocol_distribution") or features.get("protocol_distribution") or [])
    port_distribution = list(traffic.get("ports") or campaign_features.get("top_destination_port_details") or features.get("top_destination_port_details") or [])
    context = {
        "target_role": target_role,
        "network_role": target_role,
        "is_cgnat_public": is_cgnat,
        "traffic_direction": network.get("traffic_direction") or primary.get("direction"),
        "sensor": network.get("sensor") or features.get("sensor"),
        "exporter": network.get("exporter") or features.get("exporter"),
        "input_if": network.get("input_if") or features.get("input_if"),
        "output_if": network.get("output_if") or features.get("output_if"),
        "protocol_distribution": protocol_distribution,
        "port_distribution": port_distribution,
    }
    metrics = {
        "peak_pps": peak_pps,
        "peak_bps": peak_bps,
        "baseline_pps": baseline_pps,
        "baseline_bps": baseline_bps,
        "baseline_ratio": baseline_ratio,
        "baseline_delta": baseline_delta,
        "max_pps_per_host": max_pps_per_host,
        "max_bps_per_host": max_bps_per_host,
        "source_count": source_count,
        "asn_count": asn_count,
        "destination_count": destination_count,
        "recurrence_count": recurrence_count,
        "persistence_seconds": persistence_seconds,
        "correlated_security_event_count": event_count,
        "correlated_attack_vector_count": vector_count,
        "threat_intel_match_count": threat_intel_match_count,
        "threat_intel_malicious_count": threat_intel_malicious_count,
        "threat_intel_match_ratio": threat_intel_match_ratio,
        "malicious_match_ratio": malicious_match_ratio,
        "malicious_matches_among_top_sources": malicious_top,
        "top_sources_with_threat_intel": sources_with_intel,
        "top_source_has_threat_intel": top_source_has_threat_intel,
        "top_source_malicious": top_source_malicious,
    }
    return {
        "state": state,
        "attack_confidence": attack_confidence,
        "false_positive_risk": false_positive_risk,
        "should_analyze_ai": state in {"suspicious", "corroborated"},
        "behavioral_score": _number(campaign.get("coordination_score")),
        "score_semantics": "O score comportamental reflete critérios locais de correlação; não é probabilidade de ataque.",
        "reasons": reasons,
        "signals": signals,
        "metrics": metrics,
        "context": context,
        "thresholds": limits,
        "data_source": "persisted_local_only",
        "external_lookups_performed": False,
        "advisory_only": True,
        "automatic_mitigation": False,
    }
