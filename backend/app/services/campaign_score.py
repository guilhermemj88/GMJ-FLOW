from __future__ import annotations

from typing import Any, Mapping

from app.services.threat_score import BANDS as THREAT_SCORE_BANDS


# Reutiliza as fronteiras numéricas de threat_score.BANDS (0/40/60/75/85/100)
# com rótulos neutros de priorização, sem qualquer semântica de mitigação.
# Não há terceira tabela de thresholds: a fonte das fronteiras é única.
_RISK_BAND_LABELS: dict[str, str] = {
    "informational": "informational",
    "suspicious": "suspicious",
    "needs_review": "needs_review",
    "mitigation_candidate": "elevated",
    "auto_mitigation_eligible": "critical",
}

# Pesos máximos por componente. A soma é 100.
COORDINATION_MAX = 25
TRAFFIC_DEVIATION_MAX = 20
RECURRENCE_MAX = 15
THREAT_INTEL_MAX = 15
SECURITY_EVENTS_MAX = 15
PERSISTENCE_MAX = 10


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


def _band_for(score: int) -> str:
    for low, high, band in THREAT_SCORE_BANDS:
        if low <= score <= high:
            return _RISK_BAND_LABELS.get(band, band)
    return "informational"


def _coordination_points(coordination_score: Any) -> int:
    # coordination_score é 0..100; o componente vale no máximo 25.
    value = max(0, min(100, _as_int(coordination_score)))
    return min(COORDINATION_MAX, value * COORDINATION_MAX // 100)


def _recurrence_points(recurrence_count: Any) -> int:
    # A primeira observação não é recorrência; cada recorrência adicional vale 3.
    return max(0, min(RECURRENCE_MAX, (_as_int(recurrence_count) - 1) * 3))


def calculate_campaign_risk_score(
    *,
    coordination_score: int = 0,
    recurrence_count: int = 1,
    context_evaluation: Mapping[str, Any] | None = None,
    persistence_satisfied: bool | None = None,
) -> dict[str, Any]:
    """Score de risco de campanha determinístico e advisory-only (priorização).

    Consome somente sinais determinísticos já existentes e nunca alimenta
    ThreatPolicyEngine nem decisão automática de bloqueio. Não altera
    classification, verdict, coordination_score, recurrence_count, campaign_key
    ou a avaliação contextual (que permanece soberana).
    """
    evaluation = context_evaluation if isinstance(context_evaluation, Mapping) else {}
    signals = evaluation.get("signals") if isinstance(evaluation.get("signals"), Mapping) else {}

    persistence = persistence_satisfied
    if persistence is None:
        persistence = bool(signals.get("persistence_satisfied"))

    components = {
        "coordination": _coordination_points(coordination_score),
        "traffic_deviation": TRAFFIC_DEVIATION_MAX if signals.get("strong_traffic_deviation") else 0,
        "recurrence": _recurrence_points(recurrence_count),
        "threat_intel": THREAT_INTEL_MAX if signals.get("threat_intel_reinforced_by_context") else 0,
        "security_events": SECURITY_EVENTS_MAX if signals.get("security_event_correlated") else 0,
        "persistence": PERSISTENCE_MAX if persistence else 0,
    }
    score = max(0, min(100, sum(components.values())))
    return {
        "score": score,
        "band": _band_for(score),
        "components": components,
        "advisory_only": True,
    }


def campaign_risk_from_context(
    campaign: Mapping[str, Any],
    context_evaluation: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Deriva o risk score a partir de uma linha de campanha + context evaluation.

    Usado nos caminhos de leitura para preencher campanhas legadas cujo score
    ainda não foi persistido (somente cálculo, sem escrita).
    """
    features = campaign.get("features") if isinstance(campaign.get("features"), Mapping) else {}
    persistence = features.get("persistence_satisfied")
    if not isinstance(persistence, bool):
        persistence = None
    return calculate_campaign_risk_score(
        coordination_score=_as_int(campaign.get("coordination_score")),
        recurrence_count=_as_int(campaign.get("recurrence_count"), default=1),
        context_evaluation=context_evaluation,
        persistence_satisfied=persistence,
    )
