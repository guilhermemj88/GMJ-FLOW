from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from typing import Any, Callable, Mapping

from app.services.security_events import ensure_security_event_schema, find_security_event, security_event_row
from app.services.threat_contracts import SECURITY_EVENT_ANALYSIS_SCHEMA
from app.services.threat_intelligence import clean_text, json_dump, safe_json, utc_now_iso


ANALYSIS_VERSION = "security-event-analysis/v2"
SECURITY_AI_SYSTEM_PROMPT = """You are a network security analyst specialized in ISP, carrier and broadband networks.

Analyze only the evidence provided by GMJ-FLOW. Do not invent facts.

Differentiate detection evidence, threat intelligence enrichment, and inference. Threat intelligence must never be described as the reason the event was detected unless it actually participated in the local detector.

Consider ISP-specific contexts such as CGNAT, customer prefixes, infrastructure, management, transit, peering, external traffic, NAT concentration, and shared source addresses.

Return concise operational guidance as valid JSON matching the requested schema. Never perform or request automatic mitigation. Any recommendation is advisory only."""


def _enabled(value: Any) -> bool:
    return clean_text(value).lower() in {"1", "true", "yes", "on", "enabled"}


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def security_ai_config() -> dict[str, Any]:
    provider = clean_text(os.getenv("GMJFLOW_SECURITY_AI_PROVIDER", "groq")).lower().replace("-", "_")
    supported = provider in {"groq", "openai_compatible"}
    model = clean_text(os.getenv("GMJFLOW_SECURITY_AI_MODEL"))
    base_url = clean_text(os.getenv("GMJFLOW_SECURITY_AI_BASE_URL"))
    if provider == "groq" and not base_url:
        base_url = "https://api.groq.com/openai/v1"
    api_key_configured = bool(clean_text(
        os.getenv("GROQ_API_KEY") if provider == "groq" else os.getenv("GMJFLOW_SECURITY_AI_API_KEY") or os.getenv("OPENAI_API_KEY")
    ))
    enabled = _enabled(os.getenv("GMJFLOW_SECURITY_AI_ENABLED", "false"))
    return {
        "enabled": enabled,
        "provider": provider,
        "model": model,
        "timeout_seconds": _bounded_int(os.getenv("GMJFLOW_SECURITY_AI_TIMEOUT_SECONDS"), 30, 1, 120),
        "max_prompt_chars": _bounded_int(os.getenv("GMJFLOW_SECURITY_AI_MAX_PROMPT_CHARS"), 30000, 4000, 100000),
        "max_output_tokens": _bounded_int(os.getenv("GMJFLOW_SECURITY_AI_MAX_OUTPUT_TOKENS"), 1600, 256, 4096),
        "base_url_configured": bool(base_url),
        "api_key_configured": api_key_configured,
        "configured": enabled and supported and bool(model) and bool(base_url) and api_key_configured,
        "supported": supported,
        "advisory_only": True,
        "automatic_mitigation": False,
    }


def _limited_text(value: Any, maximum: int = 2000) -> str:
    return clean_text(value)[:maximum]


def _limited_mapping(value: Any, maximum: int = 50) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {clean_text(key)[:100]: item for key, item in list(value.items())[:maximum] if clean_text(key)}


def _related_events(conn: sqlite3.Connection, event: dict[str, Any], limit: int = 20) -> list[dict[str, Any]]:
    clauses = []
    values: list[Any] = []
    for field in ("campaign_id", "src_ip", "target_ip", "target_prefix"):
        value = clean_text(event.get(field))
        if value:
            clauses.append(f"{field} = ?")
            values.append(value)
    if not clauses:
        return []
    rows = conn.execute(
        f"SELECT * FROM security_events WHERE id <> ? AND ({' OR '.join(clauses)}) ORDER BY last_seen DESC LIMIT ?",
        (int(event["id"]), *values, max(1, min(int(limit), 20))),
    ).fetchall()
    return [security_event_row(row) for row in rows]


def _campaign(conn: sqlite3.Connection, campaign_id: str) -> dict[str, Any]:
    if not clean_text(campaign_id):
        return {}
    try:
        row = conn.execute("SELECT * FROM threat_campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
    except sqlite3.OperationalError:
        return {}
    if row is None:
        return {}
    item = dict(row)
    return {
        "campaign_id": clean_text(item.get("campaign_id")),
        "classification": clean_text(item.get("classification")),
        "coordination_score": int(item.get("coordination_score") or 0),
        "unique_sources": int(item.get("unique_sources") or 0),
        "unique_source_asns": int(item.get("unique_source_asns") or 0),
        "first_seen": clean_text(item.get("first_seen")),
        "last_seen": clean_text(item.get("last_seen")),
        "features": _limited_mapping(safe_json(item.get("feature_json"), {}), 30),
    }


def _threat_intelligence_rows(event: Mapping[str, Any]) -> list[dict[str, Any]]:
    threat = event.get("threat_intel") if isinstance(event.get("threat_intel"), Mapping) else {}
    source_intel = threat.get("source_intel") if isinstance(threat.get("source_intel"), Mapping) else {}
    sources = source_intel.get("sources") if isinstance(source_intel.get("sources"), Mapping) else {}
    result: list[dict[str, Any]] = []
    for ip, matches in list(sources.items())[:50]:
        for match in [item for item in (matches or []) if isinstance(item, Mapping)][:5]:
            result.append({
                "ip": _limited_text(ip, 64),
                "provider": _limited_text(match.get("provider"), 50),
                "classification": _limited_text(match.get("classification"), 50),
                "last_seen": _limited_text(match.get("last_seen"), 80),
                "organization": _limited_text(match.get("organization"), 200),
                "country": _limited_text(match.get("country") or match.get("country_code"), 100),
                "actor": _limited_text(match.get("actor"), 200),
                "tags": [_limited_text(item, 100) for item in (match.get("tags") or [])[:20]],
                "cves": [_limited_text(item, 100) for item in (match.get("cves") or [])[:20]],
            })
            if len(result) >= 50:
                return result
    return result


def structured_analysis_payload(conn: sqlite3.Connection, event: dict[str, Any]) -> dict[str, Any]:
    investigation = event.get("investigation") if isinstance(event.get("investigation"), Mapping) else {}
    detection = investigation.get("detection_evidence") if isinstance(investigation.get("detection_evidence"), Mapping) else {}
    top_sources = []
    for item in [value for value in (investigation.get("top_sources") or []) if isinstance(value, Mapping)][:50]:
        top_sources.append({
            key: item.get(key)
            for key in ("source_ip", "source_asn", "packets", "bytes", "flows", "pps", "share")
        })
    source_ports = [dict(item) for item in (investigation.get("top_source_ports") or []) if isinstance(item, Mapping)][:20]
    destination_ports = [dict(item) for item in (investigation.get("top_destination_ports") or []) if isinstance(item, Mapping)][:20]
    asn_totals: dict[int, dict[str, Any]] = {}
    for source in top_sources:
        asn = int(source.get("source_asn") or 0)
        row = asn_totals.setdefault(asn, {"asn": asn, "packets": 0, "bytes": 0, "sources": 0})
        row["packets"] += int(source.get("packets") or 0)
        row["bytes"] += int(source.get("bytes") or 0)
        row["sources"] += 1
    related = _related_events(conn, event)
    return {
        "event": {
            "event_id": event.get("event_id"),
            "event_type": event.get("attack_type"),
            "score": event.get("detector_score"),
            "severity": event.get("severity"),
            "status": event.get("status"),
            "first_seen": event.get("first_seen"),
            "last_seen": event.get("last_seen"),
            "recurrence_count": event.get("recurrence_count"),
            "target": event.get("target_prefix") or event.get("target_ip"),
            "detector": event.get("detector"),
            "detection_reason": _limited_text(event.get("detection_reason"), 3000),
        },
        "network_context": _limited_mapping(event.get("network_context"), 50),
        "metrics": {
            "protocol": event.get("protocol"),
            "pps": event.get("packets_per_second"),
            "bps": event.get("bits_per_second"),
            "packets": event.get("packets"),
            "bytes": event.get("bytes"),
            "flows": event.get("flows"),
            "source_count": event.get("unique_sources"),
            "destination_count": event.get("unique_destinations"),
        },
        "top_sources": top_sources,
        "top_ports": {"source": source_ports, "destination": destination_ports},
        "asn_distribution": sorted(asn_totals.values(), key=lambda item: -item["packets"])[:20],
        "protocol_distribution": [dict(item) for item in (investigation.get("protocols") or []) if isinstance(item, Mapping)][:20],
        "threat_intelligence": _threat_intelligence_rows(event),
        "detection_evidence": {
            **_limited_mapping(detection, 30),
            "facts": [_limited_text(item, 500) for item in ((event.get("evidence") or {}).get("facts") or [])[:50]],
            "score_components": _limited_mapping(event.get("score_components"), 30),
        },
        "campaign": _campaign(conn, clean_text(event.get("campaign_id"))),
        "related_events": [{
            "event_id": item.get("event_id"), "event_type": item.get("attack_type"),
            "score": item.get("detector_score"), "last_seen": item.get("last_seen"),
            "recurrence_count": item.get("recurrence_count"),
        } for item in related[:20]],
        "analysis_constraints": {
            "threat_intelligence_is_enrichment_only": True,
            "ai_is_manual_and_advisory_only": True,
            "automatic_mitigation_enabled": False,
        },
    }


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def event_analysis_fingerprints(event: Mapping[str, Any], payload: Mapping[str, Any]) -> tuple[str, str]:
    event_fingerprint = _fingerprint({
        "event_key": event.get("event_key"),
        "last_seen": event.get("last_seen"),
        "recurrence_count": event.get("recurrence_count"),
        "score": event.get("detector_score"),
    })
    evidence_fingerprint = _fingerprint({
        key: payload.get(key)
        for key in ("network_context", "metrics", "top_sources", "top_ports", "asn_distribution", "threat_intelligence", "detection_evidence")
    })
    return event_fingerprint, evidence_fingerprint


def _environment_executor(
    _conn: sqlite3.Connection,
    _function_key: str,
    prompt: str,
    *,
    system_prompt: str,
    schema: dict[str, Any],
    anomaly_id: int | None = None,
) -> dict[str, Any]:
    del anomaly_id
    from app.services.ai_integration import AIProviderError, build_ai_provider, sanitize_error, validate_structured_response

    config = security_ai_config()
    if not config["enabled"]:
        return {"ok": False, "status": "disabled", "error_type": "disabled", "error_message": "Security AI desabilitada"}
    if not config["configured"]:
        return {"ok": False, "status": "not_configured", "error_type": "not_configured", "error_message": "Security AI habilitada, mas provider/modelo/credencial não estão configurados"}
    if len(prompt) > config["max_prompt_chars"]:
        return {"ok": False, "status": "failed", "error_type": "payload_too_large", "error_message": "Payload estruturado excede o limite configurado"}
    provider_type = config["provider"]
    api_key = clean_text(os.getenv("GROQ_API_KEY") if provider_type == "groq" else os.getenv("GMJFLOW_SECURITY_AI_API_KEY") or os.getenv("OPENAI_API_KEY"))
    base_url = clean_text(os.getenv("GMJFLOW_SECURITY_AI_BASE_URL")) or ("https://api.groq.com/openai/v1" if provider_type == "groq" else "")
    runtime = {
        "name": f"security-ai-{provider_type}",
        "provider_type": provider_type,
        "base_url": base_url,
        "api_key": api_key,
        "default_model": config["model"],
        "timeout_seconds": config["timeout_seconds"],
        "max_output_tokens": config["max_output_tokens"],
        "max_context_tokens": max(1024, config["max_prompt_chars"] // 3),
        "temperature": 0.1,
        "top_p": 1.0,
        "supports_json": True,
        "models_endpoint": "/models" if provider_type == "groq" else "/v1/models",
        "chat_endpoint": "/chat/completions" if provider_type == "groq" else "/v1/chat/completions",
    }
    provider = build_ai_provider(runtime)
    try:
        generated = provider.generate(prompt, model=config["model"], structured=True, system_prompt=system_prompt)
        structured = validate_structured_response(generated.get("content"), schema)
        return {
            "ok": True,
            "provider": f"{provider_type.upper()} (env)",
            "provider_type": provider_type,
            "model": generated.get("model") or config["model"],
            "structured": structured,
            "duration_ms": generated.get("latency_ms"),
        }
    except AIProviderError as exc:
        return {"ok": False, "status": "failed", "error_type": exc.category, "error_message": sanitize_error(exc, [api_key])}
    except (ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "status": "failed", "error_type": "invalid_response", "error_message": sanitize_error(exc)}
    except Exception as exc:
        return {"ok": False, "status": "failed", "error_type": "unavailable", "error_message": sanitize_error(exc, [api_key])}


def _normalize_analysis(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or not clean_text(value.get("summary")):
        return None
    result: dict[str, Any] = {}
    for key, item in list(value.items())[:40]:
        name = clean_text(key)[:100]
        if isinstance(item, list):
            result[name] = [_limited_text(entry, 1000) if not isinstance(entry, Mapping) else _limited_mapping(entry, 20) for entry in item[:50]]
        elif isinstance(item, Mapping):
            result[name] = _limited_mapping(item, 30)
        elif isinstance(item, str):
            result[name] = _limited_text(item, 5000)
        elif isinstance(item, (bool, int, float)) or item is None:
            result[name] = item
    result["mitigation_executed"] = False
    result["advisory_only"] = True
    result["decision_source"] = "AI_ADVISORY"
    return result


def get_security_event_analysis(conn: sqlite3.Connection, event_reference: Any) -> dict[str, Any]:
    event = find_security_event(conn, event_reference)
    if event is None:
        return {"ok": False, "status": "not_found", "error_message": "Evento de segurança não encontrado"}
    config = security_ai_config()
    row = conn.execute(
        "SELECT * FROM security_event_ai_analyses WHERE event_id=? ORDER BY id DESC LIMIT 1",
        (int(event["id"]),),
    ).fetchone()
    history = dict(row) if row is not None else {}
    if history:
        history["result"] = safe_json(history.pop("result_json", "{}"), {})
    return {
        "ok": True,
        "event_id": event["event_id"],
        "enabled": config["enabled"],
        "configured": config["configured"],
        "provider": event.get("ai_provider") or config["provider"],
        "model": event.get("ai_model") or config["model"],
        "analysis": event.get("ai_analysis") or {},
        "analysis_status": event.get("ai_analysis_status") or "not_analyzed",
        "stale": event.get("ai_analysis_status") == "stale",
        "analyzed_at": event.get("analyzed_at"),
        "analysis_version": event.get("analysis_version"),
        "error": _limited_text(event.get("ai_analysis_error"), 1000),
        "latest_attempt": history,
        "advisory_only": True,
        "automatic_mitigation": False,
    }


def analyze_security_event(
    conn: sqlite3.Connection,
    event_id: Any,
    *,
    force: bool = False,
    executor: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ensure_security_event_schema(conn)
    event = find_security_event(conn, event_id)
    if event is None:
        return {"ok": False, "status": "not_found", "error_message": "Evento de segurança não encontrado"}
    if executor is None and not security_ai_config()["enabled"]:
        return {"ok": False, "status": "disabled", "error_type": "disabled", "error_message": "Security AI desabilitada por configuração"}

    payload = structured_analysis_payload(conn, event)
    event_fingerprint, evidence_fingerprint = event_analysis_fingerprints(event, payload)
    legacy_cache = not clean_text(event.get("ai_event_fingerprint"))
    cache_matches = legacy_cache or (
        clean_text(event.get("ai_event_fingerprint")) == event_fingerprint
        and clean_text(event.get("ai_evidence_fingerprint")) == evidence_fingerprint
    )
    if event.get("ai_analysis") and event.get("ai_analysis_status") == "valid" and cache_matches and not force:
        return {
            "ok": True, "cached": True, "analysis": event["ai_analysis"],
            "analyzed_at": event.get("analyzed_at"), "provider": event.get("ai_provider"),
            "model": event.get("ai_model"), "analysis_version": event.get("analysis_version"),
            "analysis_status": "valid", "event_fingerprint": event_fingerprint,
            "evidence_fingerprint": evidence_fingerprint, "advisory_only": True,
        }

    prompt = (
        "Analyze the bounded structured evidence below and return only JSON matching the requested schema. "
        "Clearly distinguish why the local detector fired from Threat Intelligence enrichment and from your inferences.\n"
        f"SECURITY_EVENT_JSON_BEGIN\n{json.dumps(payload, ensure_ascii=False, separators=(',', ':'), default=str)}\n"
        "SECURITY_EVENT_JSON_END"
    )
    now = utc_now_iso()
    cursor = conn.execute(
        """
        INSERT INTO security_event_ai_analyses (
            event_id, event_version, event_fingerprint, evidence_fingerprint,
            status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
        """,
        (int(event["id"]), int(event.get("recurrence_count") or 1), event_fingerprint, evidence_fingerprint, now, now),
    )
    analysis_id = int(cursor.lastrowid)
    conn.execute(
        """
        INSERT INTO threat_engine_audit (
            event_type, detector, attack_vector_json, reason, non_mitigation_reason, created_at
        ) VALUES ('AI_REQUEST', 'security_event_ai', ?, ?, 'ai_is_manual_advisory_only', ?)
        """,
        (json_dump({"event_id": event["event_id"], "analysis_version": ANALYSIS_VERSION, "evidence_fingerprint": evidence_fingerprint}), "structured_event_analysis", now),
    )
    selected_executor = executor or _environment_executor
    result = selected_executor(
        conn, "security_event_analysis", prompt,
        system_prompt=SECURITY_AI_SYSTEM_PROMPT,
        schema=SECURITY_EVENT_ANALYSIS_SCHEMA,
        anomaly_id=int(event["id"]),
    )
    if not result.get("ok"):
        error_type = _limited_text(result.get("error_type") or result.get("status") or "unavailable", 100)
        error_message = _limited_text(result.get("error_message") or "Análise de IA indisponível", 1000)
        failed_at = utc_now_iso()
        conn.execute(
            "UPDATE security_event_ai_analyses SET provider=?, model=?, status='failed', error_type=?, error_message=?, updated_at=? WHERE id=?",
            (_limited_text(result.get("provider"), 100), _limited_text(result.get("model"), 200), error_type, error_message, failed_at, analysis_id),
        )
        conn.execute("UPDATE security_events SET ai_analysis_error=?, updated_at=? WHERE id=?", (error_message, failed_at, int(event["id"])))
        conn.execute(
            """
            INSERT INTO threat_engine_audit (
                event_type, detector, groq_result_json, reason, non_mitigation_reason, created_at
            ) VALUES ('AI_RESPONSE', 'security_event_ai', ?, ?, 'analysis_failed_no_mitigation', ?)
            """,
            (json_dump({key: value for key, value in result.items() if key not in {"content"}}), error_message, failed_at),
        )
        conn.commit()
        return {**result, "analysis_id": analysis_id}

    analysis = _normalize_analysis(result.get("structured"))
    if analysis is None:
        invalid = {"ok": False, "status": "failed", "error_type": "invalid_response", "error_message": "Resposta estruturada da IA inválida", "analysis_id": analysis_id}
        failed_at = utc_now_iso()
        conn.execute(
            "UPDATE security_event_ai_analyses SET status='failed', error_type='invalid_response', error_message=?, updated_at=? WHERE id=?",
            (invalid["error_message"], failed_at, analysis_id),
        )
        conn.execute("UPDATE security_events SET ai_analysis_error=?, updated_at=? WHERE id=?", (invalid["error_message"], failed_at, int(event["id"])))
        conn.commit()
        return invalid

    analyzed_at = utc_now_iso()
    provider = _limited_text(result.get("provider"), 100)
    model = _limited_text(result.get("model"), 200)
    conn.execute(
        """
        UPDATE security_events SET
            ai_analysis_json=?, analyzed_at=?, ai_provider=?, ai_model=?,
            analysis_version=?, ai_analysis_status='valid', ai_analysis_stale_at=NULL,
            ai_event_fingerprint=?, ai_evidence_fingerprint=?, ai_analysis_error='', updated_at=?
        WHERE id=?
        """,
        (json_dump(analysis), analyzed_at, provider, model, ANALYSIS_VERSION, event_fingerprint, evidence_fingerprint, analyzed_at, int(event["id"])),
    )
    conn.execute(
        """
        UPDATE security_event_ai_analyses SET provider=?, model=?, generated_at=?, result_json=?,
               status='valid', error_type='', error_message='', updated_at=? WHERE id=?
        """,
        (provider, model, analyzed_at, json_dump(analysis), analyzed_at, analysis_id),
    )
    conn.execute(
        """
        INSERT INTO threat_engine_audit (
            event_type, detector, groq_result_json, policy_result_json,
            mitigation_decision_json, reason, non_mitigation_reason, created_at
        ) VALUES ('AI_RESPONSE', 'security_event_ai', ?, ?, ?, ?, 'ai_is_manual_advisory_only', ?)
        """,
        (
            json_dump({"event_id": event["event_id"], "analysis_id": analysis_id, "analysis": analysis, "provider": provider, "model": model, "analysis_version": ANALYSIS_VERSION}),
            json_dump({"policy_verdict": "NOT_EVALUATED"}),
            json_dump({"mitigation_executed": False}),
            clean_text(analysis.get("summary")), analyzed_at,
        ),
    )
    conn.commit()
    return {
        "ok": True, "cached": False, "analysis_id": analysis_id, "analysis": analysis,
        "analyzed_at": analyzed_at, "provider": provider, "model": model,
        "analysis_version": ANALYSIS_VERSION, "analysis_status": "valid",
        "event_fingerprint": event_fingerprint, "evidence_fingerprint": evidence_fingerprint,
        "advisory_only": True, "mitigation_executed": False,
    }
