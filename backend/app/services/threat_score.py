from __future__ import annotations

from typing import Any, Mapping

# Advisory threat score for Security Events. SHADOW mode: it only says "I would
# block" — it never executes, queues or requests any mitigation. Severity is a
# detection property; the mitigation decision is computed separately here from
# score, recurrence, direction, roles, reputation/history and technical evidence.
BANDS = (
    (0, 39, "informational"),
    (40, 59, "suspicious"),
    (60, 74, "needs_review"),
    (75, 84, "mitigation_candidate"),
    (85, 100, "auto_mitigation_eligible"),
)

_ATTACK_TYPE_POINTS = {
    "SYN_FLOOD": 15,
    "DISTRIBUTED_SYN_FLOOD": 15,
    "SPOOFED_SYN_FLOOD": 15,
    "SSH_BRUTE_FORCE": 15,
    "CARPET_BOMBING": 15,
    "NETWORK_SWEEP": 15,
    "PORT_SCAN_HORIZONTAL": 12,
    "PORT_SCAN_VERTICAL": 12,
    "UDP_FLOOD": 12,
    "DISTRIBUTED_UDP_FLOOD": 12,
    "UDP_REFLECTION_SUSPECTED": 12,
    "LOW_SLOW_SCAN": 10,
}


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return float(default)


def _int(value: Any, default: int = 0) -> int:
    return int(_num(value, default))


def _tcp_flag_share(investigation: Mapping[str, Any] | None, flag: int) -> float:
    items = (investigation or {}).get("tcp_flags")
    if not isinstance(items, list) or not items:
        return 0.0
    total = sum(_int(item.get("packets")) for item in items if isinstance(item, Mapping))
    if total <= 0:
        return 0.0
    flagged = sum(_int(item.get("packets")) for item in items if isinstance(item, Mapping) and _int(item.get("flags")) & flag)
    return flagged / total


def threat_score_payload(event: Mapping[str, Any], history: Mapping[str, Any] | None = None) -> dict[str, Any]:
    severity = str(event.get("severity") or "LOW").upper()
    attack_type = str(event.get("attack_type") or "").upper()
    direction = str(event.get("direction") or "UNKNOWN").upper()
    src_role = str(event.get("src_role") or "UNKNOWN").upper()
    dst_role = str(event.get("dst_role") or "UNKNOWN").upper()
    recurrence = _int(event.get("recurrence_count"))
    unique_destinations = _int(event.get("unique_destinations"))
    baseline = _num(event.get("baseline_deviation"))
    detector_score = _num(event.get("detector_score"))
    investigation = event.get("investigation") if isinstance(event.get("investigation"), Mapping) else {}
    syn_share = _tcp_flag_share(investigation, 0x02)

    history = history if isinstance(history, Mapping) else {}
    historical_recurrence = _int(history.get("historical_recurrence"))
    prior_mitigations = _int(history.get("prior_mitigations"))

    components: list[dict[str, Any]] = []

    sev_points = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 10, "LOW": 0}.get(severity, 0)
    if sev_points:
        components.append({"label": f"severity {severity.lower()}", "points": sev_points})

    type_points = _ATTACK_TYPE_POINTS.get(attack_type, 0)
    if type_points:
        components.append({"label": attack_type.lower(), "points": type_points})

    if recurrence:
        components.append({"label": "recorrência", "points": min(15, recurrence * 3)})

    if unique_destinations >= 20:
        components.append({"label": "20+ destinos", "points": 10})
    elif unique_destinations >= 5:
        components.append({"label": "5+ destinos", "points": 5})

    if attack_type.startswith("SYN") or syn_share >= 0.7:
        components.append({"label": "SYN predominante", "points": 10})

    if baseline >= 3:
        components.append({"label": "baseline elevado", "points": 5})

    history_points = min(12, historical_recurrence * 2 + prior_mitigations * 4)
    if history_points:
        components.append({"label": "histórico", "points": history_points})

    if direction == "INBOUND" and src_role == "EXTERNAL":
        components.append({"label": "origem externa", "points": 5})

    score = min(100, sum(int(component["points"]) for component in components))
    if score == 0 and detector_score > 0:
        score = min(100, int(detector_score))

    band = next(band for low, high, band in BANDS if low <= score <= high)

    # SHADOW decision — advisory only. Never based solely on severity.
    cgnat_or_outbound = src_role in {"CGNAT_PUBLIC", "CUSTOMER", "INFRASTRUCTURE", "MANAGEMENT"} or direction in {"OUTBOUND", "INTERNAL"}
    inbound_external = direction == "INBOUND" and src_role in {"EXTERNAL", "UNKNOWN"}
    protected_target = dst_role in {"INFRASTRUCTURE", "MANAGEMENT"}
    if score >= 85 and inbound_external and not protected_target:
        shadow_decision = "WOULD_BLOCK"
        reason = "score alto com origem externa e alvo não protegido — candidato a bloqueio de origem (SHADOW, sem execução)"
    elif cgnat_or_outbound:
        shadow_decision = "WOULD_NOT_BLOCK"
        reason = "origem interna/CGNAT ou tráfego de saída — não elegível para bloqueio automático de origem"
    elif protected_target:
        shadow_decision = "WOULD_NOT_BLOCK"
        reason = "alvo é infraestrutura/gerência — requer avaliação humana"
    else:
        shadow_decision = "WOULD_NOT_BLOCK"
        reason = "score abaixo do limiar de mitigação automática"

    return {
        "score": score,
        "band": band,
        "mode": "shadow",
        "components": components,
        "shadow_decision": shadow_decision,
        "decision_reason": reason,
        "mitigation_executed": False,
    }
