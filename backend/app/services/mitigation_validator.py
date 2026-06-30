from __future__ import annotations

from typing import Any

from app.services.mitigation_playbook import minimum_ttl_for_template, ttl_to_seconds

MIN_FALLBACK_CANDIDATE_PACKETS = 1000
MIN_FALLBACK_CANDIDATE_BYTES = 1000000
MIN_FALLBACK_SHARE_PERCENT = 20.0
HIGH_ANOMALY_PEAK_PPS = 40000


def validate_mitigation_decision(
    ai_decision: dict[str, Any],
    candidates: list[dict[str, Any]],
    incident: dict[str, Any],
    playbook: dict[str, Any],
    suspected_template: str,
) -> dict[str, Any]:
    violations: list[str] = []
    messages: list[str] = []
    normalized = dict(ai_decision)
    candidate = _candidate_by_index(candidates, _to_int(normalized.get("recommended_candidate_index"), default=-1))

    if candidate is None:
        violations.append("recommended_candidate_index does not exist")
        candidate = _fallback_candidate(candidates, incident)
        normalized["recommended_candidate_index"] = candidate.get("candidate_index", 0) if candidate else 0

    if _to_bool(normalized.get("allow_auto")):
        violations.append("allow_auto must be 0 in this phase")
    normalized["allow_auto"] = 0

    if not _to_bool(normalized.get("manual_approval_required"), default=True):
        violations.append("manual_approval_required must be 1 in this phase")
    normalized["manual_approval_required"] = 1

    minimum_ttl = minimum_ttl_for_template(playbook, suspected_template)
    requested_ttl = str(normalized.get("recommended_ttl") or candidate.get("ttl") if candidate else minimum_ttl)
    if ttl_to_seconds(requested_ttl) < ttl_to_seconds(minimum_ttl):
        violations.append(f"recommended_ttl must be at least {minimum_ttl}")
        requested_ttl = minimum_ttl
    policy = playbook.get("global_policy") if isinstance(playbook.get("global_policy"), dict) else {}
    candidate_ttl = str(candidate.get("ttl") or minimum_ttl) if candidate else minimum_ttl
    if policy.get("ai_can_change_ttl") is False and requested_ttl != candidate_ttl:
        violations.append("ai_can_change_ttl is false")
        requested_ttl = candidate_ttl
    normalized["recommended_ttl"] = requested_ttl

    normalized["recommended_candidate_index"] = _to_int(normalized.get("recommended_candidate_index"), default=0)
    normalized["risk"] = str(normalized.get("risk") or (candidate.get("risk") if candidate else "medium"))
    normalized["reason"] = str(normalized.get("reason") or "Candidato validado contra playbook.")
    normalized["confidence"] = normalized.get("confidence") or "medium"
    normalized["attack_vector"] = str(normalized.get("attack_vector") or suspected_template)

    if candidate is not None:
        candidate_violations = validate_candidate(candidate, incident, playbook)
        violations.extend(candidate_violations)
        direction_violations, direction_messages = validate_direction_scope(candidate, incident)
        violations.extend(direction_violations)
        messages.extend(direction_messages)
        if candidate.get("action") == "alert_only":
            normalized["allow_auto"] = 0
            normalized["manual_approval_required"] = 1

    return {
        "valid": not violations,
        "violations": violations,
        "messages": messages,
        "ai_decision": normalized,
        "selected_candidate": candidate,
    }


def validate_candidate(candidate: dict[str, Any], incident: dict[str, Any], playbook: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    action = str(candidate.get("action") or "")
    template = str(candidate.get("template") or "")
    match = candidate.get("match") if isinstance(candidate.get("match"), dict) else {}
    forbidden_actions = set(playbook.get("forbidden_actions") or [])

    if action != "alert_only":
        violations.extend(_flow_evidence_violations(candidate, incident))
    if _blocks_customer_ip_only(candidate, incident):
        violations.append("block_customer_ip_only")
    if _blocks_customer_prefix(candidate, incident):
        violations.append("block_customer_prefix")
    if action in {"flowspec_block", "blackhole_dst"} and not any(key in match for key in ("src_ip", "dst_ip", "dst_prefix")):
        violations.append("block_without_ip")
    if action == "flowspec_block" and not match.get("protocol") and template != "alert_only":
        if template not in {"dst_blackhole_32"}:
            violations.append("block_without_protocol")
    if action == "flowspec_rate_limit" and _rate_limit_customer_service_port(candidate, incident):
        port = _to_int(match.get("dst_port") or incident.get("dst_port"))
        if port == 53:
            violations.append("rate_limit_dns_as_customer_destination")
        if port in {80, 443}:
            violations.append("rate_limit_http_https_as_customer_destination")

    return [
        violation
        for violation in violations
        if violation in forbidden_actions
        or violation.startswith("recommended_")
        or violation.startswith("insufficient_")
        or violation.startswith("fallback_")
        or violation.startswith("top_flow_")
    ]


def _flow_evidence_violations(candidate: dict[str, Any], incident: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    packets = _to_int(candidate.get("packets") or candidate.get("top_packets") or incident.get("packets"), default=0)
    bytes_value = _to_int(candidate.get("bytes") or candidate.get("top_bytes") or incident.get("bytes"), default=0)
    share = _to_float(candidate.get("share_top_flow_percent") or candidate.get("top_packet_share") or incident.get("share_top_flow_percent"))
    peak_pps = _anomaly_peak_pps(incident)
    is_fallback = clean_reason(candidate.get("reason")) == "fallback_analysis" or clean_reason(candidate.get("source")) == "fallback_analysis" or clean_reason(candidate.get("mitigation_basis")) == "fallback_analysis"

    if is_fallback:
        if share == 0:
            violations.append("fallback_analysis_share_top_flow_zero")
        if packets < MIN_FALLBACK_CANDIDATE_PACKETS:
            violations.append("fallback_analysis_packets_below_min")
        if bytes_value < MIN_FALLBACK_CANDIDATE_BYTES:
            violations.append("fallback_analysis_bytes_below_min")
        if share < MIN_FALLBACK_SHARE_PERCENT:
            violations.append("fallback_analysis_share_below_min")
    if packets < MIN_FALLBACK_CANDIDATE_PACKETS and peak_pps > HIGH_ANOMALY_PEAK_PPS:
        violations.append("insufficient_flow_evidence_packets_vs_peak")
    if _top_flow_scope_empty(candidate, incident):
        violations.append("top_flow_scope_empty")
    return violations


def _top_flow_scope_empty(candidate: dict[str, Any], incident: dict[str, Any]) -> bool:
    match = candidate.get("match") if isinstance(candidate.get("match"), dict) else {}
    top_flow = incident.get("top_flow")
    if isinstance(top_flow, dict):
        explicit_values = (
            top_flow.get("src_ip"),
            top_flow.get("dst_ip"),
            top_flow.get("dst_port"),
            top_flow.get("packets"),
            top_flow.get("bytes"),
        )
        if not any(_has_value(value) for value in explicit_values):
            return True
    top_src = candidate.get("top_src") or incident.get("top_src") or incident.get("top_src_ip") or match.get("src_ip")
    top_dst = candidate.get("top_dst") or incident.get("top_dst") or incident.get("top_dst_ip") or match.get("dst_ip") or match.get("dst_prefix")
    top_port = candidate.get("top_port") or incident.get("top_port") or incident.get("top_dst_port") or match.get("dst_port")
    protocol = candidate.get("protocol") or incident.get("protocol") or match.get("protocol")
    return not any(_has_value(value) for value in (top_src, top_dst, top_port, protocol))


def validate_direction_scope(candidate: dict[str, Any], incident: dict[str, Any]) -> tuple[list[str], list[str]]:
    action = str(candidate.get("action") or "")
    if action == "alert_only":
        return [], ["Sem aplicacao automatica; apenas alerta para revisao manual."]
    direction = str(incident.get("direction") or "").strip().lower()
    if direction in {"outbound", "sends"}:
        if not _origin_internal_or_protected(incident):
            return ["Origem interna/protegida nao confirmada para mitigacao outbound."], []
        return [], [
            "Origem interna/protegida confirmada; destino externo usado como alvo de mitigacao outbound; vetor/perfil nao esta em modo automatico."
        ]
    if direction == "inbound":
        if not _destination_internal_or_protected(incident):
            return ["Destino nao confirmado dentro de prefixo protegido."], []
        return [], ["Destino protegido confirmado para mitigacao inbound; aprovacao manual obrigatoria."]
    return [], []


def _candidate_by_index(candidates: list[dict[str, Any]], index: int) -> dict[str, Any] | None:
    for candidate in candidates:
        if _to_int(candidate.get("candidate_index"), default=-1) == index:
            return candidate
    return None


def _fallback_candidate(candidates: list[dict[str, Any]], incident: dict[str, Any]) -> dict[str, Any] | None:
    alert = next((candidate for candidate in candidates if candidate.get("action") == "alert_only"), None)
    if alert:
        return alert
    for candidate in candidates:
        if not _blocks_customer_ip_only(candidate, incident):
            return candidate
    return candidates[0] if candidates else None


def _blocks_customer_ip_only(candidate: dict[str, Any], incident: dict[str, Any]) -> bool:
    action = str(candidate.get("action") or "")
    if action not in {"flowspec_block", "blackhole_dst"}:
        return False
    match = candidate.get("match") if isinstance(candidate.get("match"), dict) else {}
    if not match:
        return False
    customer_ip_only = False
    if incident.get("src_is_customer") and set(match.keys()) == {"src_ip"}:
        customer_ip_only = True
    if incident.get("dst_is_customer") and set(match.keys()) == {"dst_ip"}:
        customer_ip_only = True
    customer_ip_with_no_context = any(
        [
            incident.get("src_is_customer") and "src_ip" in match,
            incident.get("dst_is_customer") and "dst_ip" in match,
        ]
    ) and not (match.get("protocol") and (match.get("dst_port") or match.get("dst_ip") or match.get("src_ip")))
    return customer_ip_only or customer_ip_with_no_context


def _blocks_customer_prefix(candidate: dict[str, Any], incident: dict[str, Any]) -> bool:
    match = candidate.get("match") if isinstance(candidate.get("match"), dict) else {}
    return bool(incident.get("src_is_customer") and match.get("src_prefix")) or bool(
        incident.get("dst_is_customer") and match.get("dst_prefix")
    )


def _rate_limit_customer_service_port(candidate: dict[str, Any], incident: dict[str, Any]) -> bool:
    match = candidate.get("match") if isinstance(candidate.get("match"), dict) else {}
    port = _to_int(match.get("dst_port") or incident.get("dst_port"))
    return bool(incident.get("dst_is_customer")) and port in {53, 80, 443}


def _origin_internal_or_protected(incident: dict[str, Any]) -> bool:
    if any(
        bool(incident.get(field))
        for field in (
            "src_is_customer",
            "src_is_internal",
            "src_is_protected",
            "src_in_protected_prefix",
            "src_ips_are_internal",
            "src_ips_in_protected_prefix",
        )
    ):
        return True
    dominant = incident.get("dominant_attack_group") if isinstance(incident.get("dominant_attack_group"), dict) else {}
    unique_src_ips = dominant.get("unique_src_ips") if isinstance(dominant.get("unique_src_ips"), list) else []
    return bool(unique_src_ips and incident.get("direction") in {"outbound", "sends"} and incident.get("src_is_customer") is not False)


def _destination_internal_or_protected(incident: dict[str, Any]) -> bool:
    return any(
        bool(incident.get(field))
        for field in (
            "dst_is_customer",
            "dst_is_internal",
            "dst_is_protected",
            "dst_in_protected_prefix",
            "dst_ip_in_protected_prefix",
        )
    )


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "sim"}
    return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _anomaly_peak_pps(incident: dict[str, Any]) -> float:
    for field in ("anomaly_peak_pps", "peak_pps", "observed_value", "packets_s", "pps"):
        value = _to_float(incident.get(field), default=0.0)
        if value > 0:
            return value
    packets = _to_float(incident.get("estimated_packets") or incident.get("packets"), default=0.0)
    window = _to_float(incident.get("window_seconds"), default=0.0)
    return packets / window if packets > 0 and window > 0 else 0.0


def _has_value(value: Any) -> bool:
    if value in (None, ""):
        return False
    if isinstance(value, (int, float)):
        return value > 0
    text = str(value).strip()
    return bool(text and text not in {"0", "0.0", "0/0"})


def clean_reason(value: Any) -> str:
    return str(value or "").strip().lower()
