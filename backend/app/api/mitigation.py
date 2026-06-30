from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.services.ai_mitigation_decision import decide_mitigation_with_ai
from app.services.flow_grouping import analyze_flow_groups, dominant_group_summary, incident_from_dominant_group
from app.services.mitigation_candidates import generate_mitigation_candidates
from app.services.mitigation_playbook import load_playbook
from app.services.mitigation_validator import validate_mitigation_decision


router = APIRouter(prefix="/api/mitigation", tags=["mitigation"])


@router.post("/analyze")
def analyze_mitigation(payload: dict[str, Any]) -> dict[str, Any]:
    playbook = load_playbook()
    flow_grouping = analyze_flow_groups(payload)
    analysis_payload = incident_from_dominant_group(payload, flow_grouping)
    suspected_template, candidates = generate_mitigation_candidates(analysis_payload, playbook)
    ai_decision = decide_mitigation_with_ai(
        analysis_payload,
        candidates,
        suspected_template,
        ai_response=payload.get("ai_response"),
    )
    validation = validate_mitigation_decision(ai_decision, candidates, analysis_payload, playbook, suspected_template)
    selected = validation.get("selected_candidate") or {}
    normalized_ai_decision = validation.get("ai_decision") or ai_decision
    evidence_status = _evidence_status(flow_grouping, candidates, validation)
    mitigation_allowed = evidence_status == "complete" and selected.get("action") not in {None, "alert_only"} and bool(validation.get("valid"))
    if not mitigation_allowed:
        selected = _alert_candidate(candidates) or selected
        normalized_ai_decision = {
            **normalized_ai_decision,
            "classification": "insufficient_flow_evidence",
            "recommended_candidate": "alert_only",
            "reason": "Anomalia detectada por serie temporal, mas flows relacionados nao contem volume suficiente para identificar vetor dominante.",
        }

    return {
        "incident_id": payload.get("incident_id"),
        "suspected_template": suspected_template,
        "evidence_status": evidence_status,
        "mitigation_allowed": mitigation_allowed,
        "dominant_group": flow_grouping.get("dominant_attack_group"),
        "ignored_noise_flows_count": flow_grouping.get("ignored_noise_flows_count", 0),
        "flow_grouping": {
            "dominant_attack_group": flow_grouping.get("dominant_attack_group"),
            "ignored_noise_flows_count": flow_grouping.get("ignored_noise_flows_count", 0),
            "total_flows_considered": flow_grouping.get("total_flows_considered", 0),
            "groups": flow_grouping.get("groups", [])[:5],
        },
        "candidates": candidates,
        "ai_decision": normalized_ai_decision,
        "validation": {
            "valid": validation.get("valid", False),
            "violations": validation.get("violations") or [],
            "messages": validation.get("messages") or [],
        },
        "operator_recommendation": _operator_recommendation(
            analysis_payload,
            suspected_template,
            selected,
            normalized_ai_decision,
            flow_grouping,
            evidence_status,
            mitigation_allowed,
        ),
    }


def _operator_recommendation(
    incident: dict[str, Any],
    suspected_template: str,
    selected: dict[str, Any],
    ai_decision: dict[str, Any],
    flow_grouping: dict[str, Any] | None = None,
    evidence_status: str = "weak",
    mitigation_allowed: bool = False,
) -> dict[str, Any]:
    action = str(selected.get("action") or "alert_only")
    title = _template_title(suspected_template)
    group_summary = dominant_group_summary(flow_grouping or {}, incident.get("direction"))
    summary = _dominant_operator_summary(incident, selected, flow_grouping) if flow_grouping and flow_grouping.get("dominant_attack_group") else _incident_summary(incident)
    return {
        "title": title,
        "summary": summary,
        "dominant_group": (flow_grouping or {}).get("dominant_attack_group"),
        "ignored_noise_flows_count": (flow_grouping or {}).get("ignored_noise_flows_count", 0),
        "dominant_group_summary": group_summary,
        "evidence_status": evidence_status,
        "mitigation_allowed": mitigation_allowed,
        "classification": ai_decision.get("classification") or ("insufficient_flow_evidence" if not mitigation_allowed else "unknown"),
        "recommended_action": action if mitigation_allowed else "alert_only",
        "recommended_candidate": selected.get("template") or "alert_only",
        "reason": ai_decision.get("reason") or "",
        "recommended_candidate_index": selected.get("candidate_index", ai_decision.get("recommended_candidate_index")),
        "manual_approval_required": True,
        "allow_auto": False,
        "apply_enabled": False,
    }


def _evidence_status(flow_grouping: dict[str, Any], candidates: list[dict[str, Any]], validation: dict[str, Any]) -> str:
    if flow_grouping.get("dominant_attack_group"):
        return "complete" if validation.get("valid", False) else "weak"
    has_mitigation_candidate = any(candidate.get("action") != "alert_only" for candidate in candidates)
    if not has_mitigation_candidate:
        return "insufficient"
    return "weak"


def _alert_candidate(candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((candidate for candidate in candidates if candidate.get("action") == "alert_only"), None)


def _template_title(template_name: str) -> str:
    titles = {
        "udp_flood_outbound_cpe": "UDP flood outbound de CPE/TV Box infectado",
        "dns_udp_abuse_outbound": "Abuso DNS UDP outbound",
        "tcp_syn_flood": "TCP SYN flood",
        "icmp_flood": "ICMP flood",
        "possible_l7_http_https": "Possivel ataque HTTP/HTTPS visto por flow",
    }
    return titles.get(template_name, template_name)


def _incident_summary(incident: dict[str, Any]) -> str:
    src_ip = incident.get("src_ip") or "origem desconhecida"
    dst_ip = incident.get("dst_ip") or "destino desconhecido"
    protocol = str(incident.get("protocol") or "protocolo desconhecido").upper()
    dst_port = incident.get("dst_port")
    pps_score = incident.get("pps_score")
    port_text = f"/{dst_port}" if dst_port not in (None, "") else ""
    score_text = f" com PPS {pps_score}x acima do baseline" if pps_score not in (None, "") else ""
    return f"{src_ip} gerou {protocol}{port_text} para {dst_ip}{score_text}."


def _dominant_operator_summary(incident: dict[str, Any], selected: dict[str, Any], flow_grouping: dict[str, Any] | None) -> str:
    dominant = (flow_grouping or {}).get("dominant_attack_group") or {}
    protocol = str(dominant.get("protocol") or incident.get("protocol") or "").upper()
    dst_ip = dominant.get("dst_ip") or incident.get("dst_ip") or "destino desconhecido"
    dst_port = dominant.get("dst_port") or incident.get("dst_port") or "-"
    action = selected.get("action") or "alert_only"
    template = selected.get("template") or "alert_only"
    noise_count = int((flow_grouping or {}).get("ignored_noise_flows_count") or 0)
    if action == "flowspec_block" and template == "dst_external_32_proto_dst_port":
        recommendation = f"A mitigacao recomendada e FlowSpec por destino externo /32 + {protocol} + porta {dst_port}"
    else:
        recommendation = f"A recomendacao selecionada e {action}"
    return (
        f"Foi identificado grupo dominante de {protocol} outbound para {dst_ip}:{dst_port}, com multiplas origens internas. "
        f"Os demais {noise_count} flows relacionados possuem baixo volume e destinos diferentes, sendo tratados como cauda/ruido da anomalia. "
        f"{recommendation}, TTL minimo {selected.get('ttl') or '2h'}, com aprovacao manual."
    )
