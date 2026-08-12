from __future__ import annotations

import json
import sqlite3
from typing import Any, Callable

from app.services.security_events import ensure_security_event_schema, security_event_row
from app.services.threat_contracts import SECURITY_EVENT_ANALYSIS_SCHEMA
from app.services.threat_intelligence import clean_text, json_dump, safe_json, utc_now_iso


ANALYSIS_VERSION = "security-event-analysis/v1"


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
        f"""
        SELECT * FROM security_events
        WHERE id <> ? AND ({' OR '.join(clauses)})
        ORDER BY last_seen DESC LIMIT ?
        """,
        (int(event["id"]), *values, max(1, min(int(limit), 100))),
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
    item["features"] = safe_json(item.pop("feature_json", "{}"), {})
    item["threat_intel"] = safe_json(item.pop("threat_intel_json", "{}"), {})
    item["intel_sources"] = safe_json(item.pop("intel_sources_json", "[]"), [])
    return item


def structured_analysis_payload(conn: sqlite3.Connection, event: dict[str, Any]) -> dict[str, Any]:
    related = _related_events(conn, event)
    campaign = _campaign(conn, clean_text(event.get("campaign_id")))
    fields = (
        "id", "event_key", "detector", "attack_type", "attack_family", "severity",
        "detector_score", "confidence", "verdict", "src_ip", "src_prefix",
        "target_ip", "target_prefix", "src_role", "dst_role", "direction",
        "protocol", "first_seen", "last_seen", "recurrence_count", "status",
        "packets", "packets_per_second", "bits_per_second", "flows",
        "flows_per_second", "unique_sources", "unique_destinations",
        "unique_src_ports", "unique_dst_ports", "unique_source_asns",
        "baseline_deviation", "input_if", "output_if", "sensor", "exporter",
        "cgnat_context", "network_context", "evidence", "score_components",
        "threat_intel", "campaign_id", "mitigation_status", "decision_source",
    )
    return {
        "event": {field: event.get(field) for field in fields},
        "related_events": [
            {
                field: item.get(field)
                for field in (
                    "id", "attack_type", "attack_family", "verdict", "severity",
                    "detector_score", "src_ip", "target_ip", "target_prefix",
                    "direction", "protocol", "first_seen", "last_seen",
                    "recurrence_count", "packets_per_second", "bits_per_second",
                    "unique_sources", "unique_source_asns", "campaign_id",
                )
            }
            for item in related
        ],
        "campaign": campaign,
        "analysis_constraints": {
            "threat_intel_is_enrichment_only": True,
            "cgnat_is_context_not_allowlist": True,
            "ai_must_not_execute_mitigation": True,
            "policy_engine_is_authoritative": True,
            "automatic_policy_enabled": False,
        },
    }


def analyze_security_event(
    conn: sqlite3.Connection,
    event_id: int,
    *,
    force: bool = False,
    executor: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ensure_security_event_schema(conn)
    row = conn.execute("SELECT * FROM security_events WHERE id=?", (int(event_id),)).fetchone()
    if row is None:
        return {"ok": False, "status": "not_found", "error_message": "Evento de segurança não encontrado"}
    event = security_event_row(row)
    if event.get("ai_analysis") and event.get("ai_analysis_status") == "valid" and not force:
        return {
            "ok": True,
            "cached": True,
            "analysis": event["ai_analysis"],
            "analyzed_at": event.get("analyzed_at"),
            "provider": event.get("ai_provider"),
            "model": event.get("ai_model"),
            "analysis_version": event.get("analysis_version"),
            "analysis_status": "valid",
        }

    if executor is None:
        # Keep central AI provider dependencies optional for detector-only nodes.
        from app.services.ai_integration import ensure_ai_schema, execute_ai_route

        ensure_ai_schema(conn)
        executor = execute_ai_route
    payload = structured_analysis_payload(conn, event)
    prompt = (
        "Analise o JSON a seguir. Não trate cardinalidade isolada como ataque; avalie volume absoluto, "
        "persistência, concentração, baseline, direção e papéis da rede. Descreva Threat Intelligence como "
        "histórico/reputação e sua relevância ao vetor presente. Responda exatamente no schema solicitado.\n"
        f"SECURITY_EVENT_JSON_BEGIN\n{json.dumps(payload, ensure_ascii=False, separators=(',', ':'))}\n"
        "SECURITY_EVENT_JSON_END"
    )
    now = utc_now_iso()
    conn.execute(
        """
        INSERT INTO threat_engine_audit (
            event_type, detector, attack_vector_json, reason, non_mitigation_reason, created_at
        ) VALUES ('AI_REQUEST', 'security_event_ai', ?, ?, 'ai_is_advisory_only', ?)
        """,
        (json_dump({"event_id": int(event_id), "analysis_version": ANALYSIS_VERSION}), "structured_event_analysis", now),
    )
    result = executor(
        conn,
        "security_event_analysis",
        prompt,
        system_prompt=(
            "Atue somente como analista. Nunca afirme que Threat Intelligence confirmou o ataque atual. "
            "Nunca execute mitigação. Retorne somente JSON válido."
        ),
        schema=SECURITY_EVENT_ANALYSIS_SCHEMA,
        anomaly_id=int(event_id),
    )
    if not result.get("ok"):
        conn.execute(
            """
            INSERT INTO threat_engine_audit (
                event_type, detector, groq_result_json, reason, non_mitigation_reason, created_at
            ) VALUES ('AI_RESPONSE', 'security_event_ai', ?, ?, 'analysis_failed_no_mitigation', ?)
            """,
            (json_dump({key: value for key, value in result.items() if key not in {"content"}}), clean_text(result.get("error_message")), utc_now_iso()),
        )
        conn.commit()
        return result
    analysis = dict(result.get("structured") or {})
    analysis["mitigation_executed"] = False
    analysis["decision_source"] = "AI_ADVISORY"
    analyzed_at = utc_now_iso()
    conn.execute(
        """
        UPDATE security_events SET
            ai_analysis_json=?, analyzed_at=?, ai_provider=?, ai_model=?,
            analysis_version=?, ai_analysis_status='valid',
            ai_analysis_stale_at=NULL, updated_at=?
        WHERE id=?
        """,
        (
            json_dump(analysis), analyzed_at, clean_text(result.get("provider")),
            clean_text(result.get("model")), ANALYSIS_VERSION, analyzed_at, int(event_id),
        ),
    )
    conn.execute(
        """
        INSERT INTO threat_engine_audit (
            event_type, detector, groq_result_json, policy_result_json,
            mitigation_decision_json, reason, non_mitigation_reason, created_at
        ) VALUES ('AI_RESPONSE', 'security_event_ai', ?, ?, ?, ?, 'ai_is_advisory_only', ?)
        """,
        (
            json_dump({
                "event_id": int(event_id), "analysis": analysis,
                "provider": result.get("provider"), "model": result.get("model"),
                "analysis_version": ANALYSIS_VERSION,
            }),
            json_dump({"policy_verdict": "NOT_EVALUATED"}),
            json_dump({"mitigation_executed": False}),
            clean_text(analysis.get("summary")),
            analyzed_at,
        ),
    )
    conn.commit()
    return {
        "ok": True,
        "cached": False,
        "analysis": analysis,
        "analyzed_at": analyzed_at,
        "provider": clean_text(result.get("provider")),
        "model": clean_text(result.get("model")),
        "analysis_version": ANALYSIS_VERSION,
        "analysis_status": "valid",
    }
