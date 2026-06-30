from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from app.services.mitigation_playbook import infer_attack_template, load_playbook, minimum_ttl_for_template


def generate_mitigation_candidates(
    incident: dict[str, Any],
    playbook: dict[str, Any] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    playbook = playbook or load_playbook()
    suspected_template = str(incident.get("suspected_template") or infer_attack_template(incident, playbook))
    attack_template = (playbook.get("attack_templates") or {}).get(suspected_template, {})
    candidate_templates = playbook.get("candidate_templates") or {}
    preferred = attack_template.get("preferred_candidates") if isinstance(attack_template, dict) else None
    if not preferred:
        preferred = playbook.get("preferred_candidate_order") or ["alert_only"]

    if suspected_template == "possible_l7_http_https" and _is_clear_syn_flood(incident):
        preferred = attack_template.get("allowed_if_syn_flood") or preferred
    if _has_multi_source_dominant_outbound_group(incident):
        preferred = ["dst_external_32_proto_dst_port", "dst_external_prefix_proto_dst_port", "alert_only"]

    candidates: list[dict[str, Any]] = []
    for template_name in preferred:
        template = candidate_templates.get(template_name)
        if not isinstance(template, dict):
            continue
        if not _requirements_met(template.get("requirements") or [], incident):
            continue
        if _forbidden_if_matches(template.get("forbidden_if") or [], incident):
            continue
        candidate = _build_candidate(template_name, template, incident, suspected_template, playbook)
        if candidate:
            candidates.append(candidate)

    if not any(candidate.get("template") == "alert_only" for candidate in candidates):
        alert_template = candidate_templates.get("alert_only") or {"action": "alert_only", "risk": "none", "match_fields": []}
        candidates.append(_build_candidate("alert_only", alert_template, incident, suspected_template, playbook))

    for index, candidate in enumerate(candidates):
        candidate["candidate_index"] = index
    return suspected_template, candidates


def _build_candidate(
    template_name: str,
    template: dict[str, Any],
    incident: dict[str, Any],
    suspected_template: str,
    playbook: dict[str, Any],
) -> dict[str, Any]:
    match = _candidate_match(template.get("match_fields") or [], incident)
    return {
        "candidate_index": 0,
        "template": template_name,
        "action": str(template.get("action") or "alert_only"),
        "match": match,
        "ttl": minimum_ttl_for_template(playbook, suspected_template),
        "risk": str(template.get("risk") or "medium"),
        "manual_only": bool(template.get("manual_only", False)),
        "allow_auto": False,
        "manual_approval_required": True,
        "description": str(template.get("description") or ""),
    }


def _candidate_match(fields: list[str], incident: dict[str, Any]) -> dict[str, Any]:
    match: dict[str, Any] = {}
    for field in fields:
        if field == "src_ip" and incident.get("src_ip"):
            match["src_ip"] = _host_cidr(incident.get("src_ip"))
        elif field == "dst_ip" and incident.get("dst_ip"):
            match["dst_ip"] = _host_cidr(incident.get("dst_ip"))
        elif field == "dst_prefix" and incident.get("dst_prefix"):
            match["dst_prefix"] = str(incident.get("dst_prefix"))
        elif field == "protocol" and incident.get("protocol"):
            match["protocol"] = str(incident.get("protocol")).lower()
        elif field == "dst_port" and incident.get("dst_port") not in (None, ""):
            match["dst_port"] = _to_int(incident.get("dst_port"))
        elif field == "tcp_flags":
            flags = str(incident.get("tcp_flags") or incident.get("flags") or "syn").lower()
            match["tcp_flags"] = flags if "syn" in flags else "syn"
        elif field == "rate_limit":
            match["rate_limit"] = incident.get("rate_limit") or "manual"
        elif field == "icmp_type_code":
            if incident.get("icmp_type_code") not in (None, ""):
                match["icmp_type_code"] = str(incident.get("icmp_type_code"))
            elif incident.get("icmp_type") not in (None, "") and incident.get("icmp_code") not in (None, ""):
                match["icmp_type_code"] = f"{incident.get('icmp_type')}/{incident.get('icmp_code')}"
    return {key: value for key, value in match.items() if value not in (None, "")}


def _requirements_met(requirements: list[str], incident: dict[str, Any]) -> bool:
    return all(_requirement_met(requirement, incident) for requirement in requirements)


def _requirement_met(requirement: str, incident: dict[str, Any]) -> bool:
    if requirement == "src_is_customer":
        return bool(incident.get("src_is_customer"))
    if requirement == "dst_is_external":
        return bool(incident.get("dst_is_external")) and not bool(incident.get("dst_is_customer"))
    if requirement == "dst_is_customer":
        return bool(incident.get("dst_is_customer"))
    if requirement == "src_is_external":
        return not bool(incident.get("src_is_customer")) and not bool(incident.get("src_is_internal"))
    if requirement == "protocol_known":
        return bool(str(incident.get("protocol") or "").strip())
    if requirement == "dst_port_known":
        return incident.get("dst_port") not in (None, "")
    if requirement == "dst_prefix_is_external":
        return bool(incident.get("dst_prefix")) and not bool(incident.get("dst_is_customer"))
    if requirement == "same_asn_or_same_prefix_detected":
        return bool(incident.get("same_asn") or incident.get("same_dst_24") or incident.get("same_prefix"))
    if requirement == "protocol_tcp":
        return str(incident.get("protocol") or "").lower() == "tcp"
    if requirement == "protocol_udp":
        return str(incident.get("protocol") or "").lower() == "udp"
    if requirement == "protocol_icmp":
        return str(incident.get("protocol") or "").lower() == "icmp"
    if requirement == "icmp_type_code_known":
        return incident.get("icmp_type_code") not in (None, "") or (
            incident.get("icmp_type") not in (None, "") and incident.get("icmp_code") not in (None, "")
        )
    if requirement == "tcp_flag_syn":
        return _is_clear_syn_flood(incident)
    if requirement == "dst_port_53":
        return _to_int(incident.get("dst_port")) == 53
    if requirement == "manual_approval":
        return True
    if requirement == "service_should_remain_available":
        return bool(incident.get("service_should_remain_available") or incident.get("allow_rate_limit_candidate"))
    if requirement == "dst_is_external_or_attack_destination":
        return not bool(incident.get("dst_is_customer")) or bool(incident.get("dst_is_attack_destination"))
    return bool(incident.get(requirement))


def _forbidden_if_matches(forbidden_if: list[str], incident: dict[str, Any]) -> bool:
    return any(_forbidden_condition_matches(condition, incident) for condition in forbidden_if)


def _forbidden_condition_matches(condition: str, incident: dict[str, Any]) -> bool:
    dst_port = _to_int(incident.get("dst_port"))
    dst_is_customer = bool(incident.get("dst_is_customer"))
    if condition == "dst_port_53_and_destination_is_customer":
        return dst_port == 53 and dst_is_customer
    if condition == "dst_port_80_and_destination_is_customer":
        return dst_port == 80 and dst_is_customer
    if condition == "dst_port_443_and_destination_is_customer":
        return dst_port == 443 and dst_is_customer
    return False


def _has_multi_source_dominant_outbound_group(incident: dict[str, Any]) -> bool:
    dominant = incident.get("dominant_attack_group") if isinstance(incident.get("dominant_attack_group"), dict) else None
    if not dominant:
        return False
    direction = str(incident.get("direction") or "").strip().lower()
    unique_src_ips = dominant.get("unique_src_ips") if isinstance(dominant.get("unique_src_ips"), list) else []
    return (
        direction in {"outbound", "sends"}
        and len(unique_src_ips) >= 2
        and bool(dominant.get("dst_ip"))
        and bool(dominant.get("dst_port"))
        and bool(dominant.get("protocol"))
    )


def _is_clear_syn_flood(incident: dict[str, Any]) -> bool:
    flags = str(incident.get("tcp_flags") or incident.get("flags") or "").lower()
    return str(incident.get("protocol") or "").lower() == "tcp" and (
        "syn" in flags or incident.get("tcp_flag_syn") is True or incident.get("syn_pps_above_baseline") is True
    )


def _host_cidr(value: Any) -> str:
    text = str(value).strip()
    if "/" in text:
        return text
    try:
        parsed = ip_address(text)
    except ValueError:
        return text
    return f"{parsed}/32" if parsed.version == 4 else f"{parsed}/128"


def _to_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
