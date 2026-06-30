from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


AI_PROMPT = (
    "Voce e um assistente de mitigacao DDoS para provedor ISP.\n"
    "A anomalia ja foi detectada. Nao crie regra, FlowSpec, blackhole, ACL ou rate-limit.\n"
    "Escolha somente um candidate_index existente. Todo bloqueio exige aprovacao manual nesta fase.\n"
    "Nunca recomende bloqueio somente do IP do cliente ou prefixo de cliente. allow_auto deve ser 0.\n"
    "Se a evidencia de flow for fraca ou fallback_analysis sem volume, escolha alert_only/manual_review e diga: "
    "\"Nao ha evidencia suficiente para recomendar descarte. Confirmar top flows no ClickHouse/roteador.\"\n"
    "Responda somente JSON valido."
)


def decide_mitigation_with_ai(
    incident: dict[str, Any],
    candidates: list[dict[str, Any]],
    suspected_template: str,
    ai_response: dict[str, Any] | str | None = None,
) -> dict[str, Any]:
    if ai_response is not None:
        return normalize_ai_response(ai_response, suspected_template)
    if _truthy(os.getenv("MITIGATION_AI_USE_OLLAMA")):
        response = _ollama_decision(incident, candidates, suspected_template)
        if response:
            return normalize_ai_response(response, suspected_template)
    return _deterministic_mock_decision(candidates, suspected_template)


def build_ai_prompt(incident: dict[str, Any], candidates: list[dict[str, Any]], suspected_template: str) -> str:
    payload = {
        "suspected_template": suspected_template,
        "incident": _compact_incident(incident),
        "candidates": candidates,
    }
    return f"{AI_PROMPT}\n{json.dumps(payload, ensure_ascii=False, separators=(',', ':'))}"


def normalize_ai_response(value: dict[str, Any] | str, suspected_template: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = {}
    else:
        parsed = dict(value)
    return {
        "attack_vector": str(parsed.get("attack_vector") or suspected_template),
        "recommended_candidate_index": _to_int(parsed.get("recommended_candidate_index"), default=0),
        "confidence": parsed.get("confidence") if parsed.get("confidence") not in (None, "") else "medium",
        "recommended_ttl": str(parsed.get("recommended_ttl") or ""),
        "allow_auto": _to_bool_int(parsed.get("allow_auto")),
        "manual_approval_required": _to_bool_int(parsed.get("manual_approval_required"), default=1),
        "risk": str(parsed.get("risk") or "medium"),
        "reason": str(parsed.get("reason") or "Escolha baseada no candidato seguro gerado pelo backend."),
    }


def _deterministic_mock_decision(candidates: list[dict[str, Any]], suspected_template: str) -> dict[str, Any]:
    selected = next((candidate for candidate in candidates if candidate.get("action") != "alert_only"), None)
    if selected is None:
        selected = candidates[0] if candidates else {"candidate_index": 0, "ttl": "30m", "risk": "none"}
    return {
        "attack_vector": suspected_template,
        "recommended_candidate_index": int(selected.get("candidate_index") or 0),
        "confidence": "high" if selected.get("action") != "alert_only" else "medium",
        "recommended_ttl": str(selected.get("ttl") or "30m"),
        "allow_auto": 0,
        "manual_approval_required": 1,
        "risk": str(selected.get("risk") or "medium"),
        "reason": "Candidato existente escolhido por ser a opcao mais especifica gerada pelo backend.",
    }


def _ollama_decision(incident: dict[str, Any], candidates: list[dict[str, Any]], suspected_template: str) -> dict[str, Any] | None:
    url = os.getenv("OLLAMA_URL", "http://ollama:11434").rstrip("/") + "/api/generate"
    model = os.getenv("MITIGATION_AI_MODEL") or os.getenv("OLLAMA_MODEL") or "qwen2.5:3b"
    payload = {
        "model": model,
        "prompt": build_ai_prompt(incident, candidates, suspected_template),
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0,
            "num_predict": 256,
            "num_ctx": 2048,
            "top_p": 0.9,
        },
    }
    try:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=float(os.getenv("MITIGATION_AI_TIMEOUT", "8"))) as response:
            data = json.loads(response.read().decode("utf-8"))
        text = data.get("response") if isinstance(data, dict) else None
        if isinstance(text, str):
            return json.loads(text)
    except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError):
        return None
    return None


def _compact_incident(incident: dict[str, Any]) -> dict[str, Any]:
    fields = [
        "incident_id",
        "direction",
        "src_is_customer",
        "dst_is_customer",
        "src_is_internal",
        "dst_is_external",
        "protocol",
        "dst_port",
        "src_ip",
        "dst_ip",
        "dst_prefix",
        "same_dst_24",
        "same_asn",
        "burst_detected",
        "window_seconds",
        "packets",
        "bytes",
        "pps_score",
        "bps_score",
        "flows_score",
        "tcp_flags",
        "dominant_attack_group",
        "dominant_group_top_flows",
        "flow_grouping",
        "ignored_noise_flows_count",
    ]
    return {field: incident.get(field) for field in fields if incident.get(field) not in (None, "")}


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_bool_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return 1 if value else 0
    if isinstance(value, str):
        return 1 if value.strip().lower() in {"1", "true", "yes", "sim"} else 0
    return default


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "sim"}
