from __future__ import annotations

import json
import sqlite3
from typing import Any, Callable, Mapping

from app.services.campaign_investigation import campaign_analysis_payload, get_campaign_investigation
from app.services.security_event_ai import (
    analysis_fingerprint,
    execute_security_ai_provider,
    normalize_advisory_analysis,
    security_ai_config,
)
from app.services.threat_contracts import SECURITY_EVENT_ANALYSIS_SCHEMA
from app.services.threat_intelligence import clean_text, json_dump, safe_json, utc_now_iso


ANALYSIS_VERSION = "campaign-analysis/v1"
CAMPAIGN_AI_SYSTEM_PROMPT = """You are a network security analyst specialized in ISP, carrier and broadband networks.

Analyze this campaign as a campaign, not as an individual Security Event. Use only the bounded evidence provided by GMJ-FLOW and do not invent facts.

Differentiate campaign detection/correlation evidence, persisted Threat Intelligence enrichment, correlated canonical events, and inference. Threat Intelligence is enrichment and must not be described as the reason the campaign detector fired unless the payload explicitly says so.

Return concise operational guidance as valid JSON matching the requested schema. The analysis is advisory only. Never perform, request, or imply automatic mitigation."""


def ensure_campaign_ai_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS campaign_ai_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT NOT NULL,
            provider TEXT NOT NULL DEFAULT '',
            model TEXT NOT NULL DEFAULT '',
            generated_at TEXT,
            campaign_fingerprint TEXT NOT NULL DEFAULT '',
            evidence_fingerprint TEXT NOT NULL DEFAULT '',
            result_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'pending',
            error_type TEXT NOT NULL DEFAULT '',
            error_message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_campaign_ai_history
            ON campaign_ai_analyses(campaign_id, id DESC);
        """
    )


def campaign_analysis_fingerprints(investigation: Mapping[str, Any], payload: Mapping[str, Any]) -> tuple[str, str]:
    campaign = investigation.get("campaign") if isinstance(investigation.get("campaign"), Mapping) else {}
    campaign_fingerprint = analysis_fingerprint(
        {
            "campaign_id": campaign.get("campaign_id"),
            "last_seen": campaign.get("last_seen"),
            "recurrence_count": campaign.get("recurrence_count"),
            "coordination_score": campaign.get("coordination_score"),
            "unique_sources": campaign.get("unique_sources"),
            "unique_source_asns": campaign.get("unique_source_asns"),
        }
    )
    evidence_fingerprint = analysis_fingerprint(
        {
            key: payload.get(key)
            for key in (
                "target", "top_sources", "asn_diversity", "traffic_metrics", "correlated_events",
                "threat_intelligence", "detection_correlation_evidence",
            )
        }
    )
    return campaign_fingerprint, evidence_fingerprint


def _latest_attempt(conn: sqlite3.Connection, campaign_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM campaign_ai_analyses WHERE campaign_id=? ORDER BY id DESC LIMIT 1",
        (clean_text(campaign_id),),
    ).fetchone()
    item = dict(row) if row is not None else {}
    if item:
        item["result"] = safe_json(item.pop("result_json", "{}"), {})
    return item


def _latest_valid_analysis(conn: sqlite3.Connection, campaign_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM campaign_ai_analyses WHERE campaign_id=? AND status='valid' ORDER BY id DESC LIMIT 1",
        (clean_text(campaign_id),),
    ).fetchone()
    item = dict(row) if row is not None else {}
    if item:
        item["result"] = safe_json(item.pop("result_json", "{}"), {})
    return item


def get_campaign_analysis(conn: sqlite3.Connection, campaign_id: str) -> dict[str, Any]:
    ensure_campaign_ai_schema(conn)
    investigation = get_campaign_investigation(conn, campaign_id)
    if investigation is None:
        return {"ok": False, "status": "not_found", "error_message": "Campanha não encontrada"}
    config = security_ai_config()
    latest = _latest_attempt(conn, campaign_id)
    valid = latest if latest.get("status") == "valid" else _latest_valid_analysis(conn, campaign_id)
    analysis = valid.get("result") or {}
    payload = campaign_analysis_payload(investigation)
    campaign_fingerprint, evidence_fingerprint = campaign_analysis_fingerprints(investigation, payload)
    stale = bool(
        analysis
        and (
            clean_text(valid.get("campaign_fingerprint")) != campaign_fingerprint
            or clean_text(valid.get("evidence_fingerprint")) != evidence_fingerprint
        )
    )
    return {
        "ok": True,
        "campaign_id": campaign_id,
        "enabled": config["enabled"],
        "configured": config["configured"],
        "provider": valid.get("provider") or latest.get("provider") or config["provider"],
        "model": valid.get("model") or latest.get("model") or config["model"],
        "analysis": analysis or {},
        "analysis_status": "stale" if stale else "valid" if analysis else latest.get("status") or "not_analyzed",
        "stale": stale,
        "analyzed_at": valid.get("generated_at"),
        "analysis_version": ANALYSIS_VERSION if analysis else "",
        "error": clean_text(latest.get("error_message"))[:1000],
        "latest_attempt": latest,
        "advisory_only": True,
        "automatic_mitigation": False,
    }


def analyze_campaign(
    conn: sqlite3.Connection,
    campaign_id: str,
    *,
    force: bool = False,
    executor: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ensure_campaign_ai_schema(conn)
    investigation = get_campaign_investigation(conn, campaign_id)
    if investigation is None:
        return {"ok": False, "status": "not_found", "error_message": "Campanha não encontrada"}
    if executor is None and not security_ai_config()["enabled"]:
        return {
            "ok": False,
            "status": "disabled",
            "error_type": "disabled",
            "error_message": "Security AI desabilitada por configuração",
        }

    payload = campaign_analysis_payload(investigation)
    campaign_fingerprint, evidence_fingerprint = campaign_analysis_fingerprints(investigation, payload)
    latest = _latest_attempt(conn, campaign_id)
    valid = latest if latest.get("status") == "valid" else _latest_valid_analysis(conn, campaign_id)
    cached_analysis = valid.get("result") or {}
    if (
        cached_analysis
        and clean_text(valid.get("campaign_fingerprint")) == campaign_fingerprint
        and clean_text(valid.get("evidence_fingerprint")) == evidence_fingerprint
        and not force
    ):
        return {
            "ok": True,
            "cached": True,
            "analysis": cached_analysis,
            "analyzed_at": valid.get("generated_at"),
            "provider": valid.get("provider"),
            "model": valid.get("model"),
            "analysis_version": ANALYSIS_VERSION,
            "analysis_status": "valid",
            "campaign_fingerprint": campaign_fingerprint,
            "evidence_fingerprint": evidence_fingerprint,
            "advisory_only": True,
            "mitigation_executed": False,
        }

    prompt = (
        "Analyze the bounded Campaign Investigation payload below and return only JSON matching the requested schema. "
        "Keep campaign evidence, correlated Security Events, Threat Intelligence enrichment, and inference distinct.\n"
        f"CAMPAIGN_JSON_BEGIN\n{json.dumps(payload, ensure_ascii=False, separators=(',', ':'), default=str)}\n"
        "CAMPAIGN_JSON_END"
    )
    now = utc_now_iso()
    cursor = conn.execute(
        """
        INSERT INTO campaign_ai_analyses (
            campaign_id, campaign_fingerprint, evidence_fingerprint, status, created_at, updated_at
        ) VALUES (?, ?, ?, 'pending', ?, ?)
        """,
        (campaign_id, campaign_fingerprint, evidence_fingerprint, now, now),
    )
    analysis_id = int(cursor.lastrowid)
    conn.execute(
        """
        INSERT INTO threat_engine_audit (
            event_type, detector, campaign_vector_json, reason, non_mitigation_reason, created_at
        ) VALUES ('AI_REQUEST', 'campaign_ai', ?, 'structured_campaign_analysis', 'ai_is_manual_advisory_only', ?)
        """,
        (json_dump({"campaign_id": campaign_id, "analysis_version": ANALYSIS_VERSION, "evidence_fingerprint": evidence_fingerprint}), now),
    )
    selected_executor = executor or execute_security_ai_provider
    result = selected_executor(
        conn,
        "security_campaign_analysis",
        prompt,
        system_prompt=CAMPAIGN_AI_SYSTEM_PROMPT,
        schema=SECURITY_EVENT_ANALYSIS_SCHEMA,
        anomaly_id=None,
    )
    if not result.get("ok"):
        error_type = clean_text(result.get("error_type") or result.get("status") or "unavailable")[:100]
        error_message = clean_text(result.get("error_message") or "Análise de IA indisponível")[:1000]
        failed_at = utc_now_iso()
        conn.execute(
            """
            UPDATE campaign_ai_analyses
            SET provider=?, model=?, status='failed', error_type=?, error_message=?, updated_at=?
            WHERE id=?
            """,
            (clean_text(result.get("provider"))[:100], clean_text(result.get("model"))[:200], error_type, error_message, failed_at, analysis_id),
        )
        conn.execute(
            """
            INSERT INTO threat_engine_audit (
                event_type, detector, groq_result_json, reason, non_mitigation_reason, created_at
            ) VALUES ('AI_RESPONSE', 'campaign_ai', ?, ?, 'analysis_failed_no_mitigation', ?)
            """,
            (json_dump({key: value for key, value in result.items() if key != "content"}), error_message, failed_at),
        )
        conn.commit()
        return {**result, "analysis_id": analysis_id}

    analysis = normalize_advisory_analysis(result.get("structured"))
    if analysis is None:
        failed_at = utc_now_iso()
        error_message = "Resposta estruturada da IA inválida"
        conn.execute(
            """
            UPDATE campaign_ai_analyses
            SET status='failed', error_type='invalid_response', error_message=?, updated_at=? WHERE id=?
            """,
            (error_message, failed_at, analysis_id),
        )
        conn.commit()
        return {
            "ok": False,
            "status": "failed",
            "error_type": "invalid_response",
            "error_message": error_message,
            "analysis_id": analysis_id,
        }

    analyzed_at = utc_now_iso()
    provider = clean_text(result.get("provider"))[:100]
    model = clean_text(result.get("model"))[:200]
    conn.execute(
        """
        UPDATE campaign_ai_analyses
        SET provider=?, model=?, generated_at=?, result_json=?, status='valid',
            error_type='', error_message='', updated_at=? WHERE id=?
        """,
        (provider, model, analyzed_at, json_dump(analysis), analyzed_at, analysis_id),
    )
    conn.execute(
        """
        INSERT INTO threat_engine_audit (
            event_type, detector, groq_result_json, policy_result_json,
            mitigation_decision_json, reason, non_mitigation_reason, created_at
        ) VALUES ('AI_RESPONSE', 'campaign_ai', ?, ?, ?, ?, 'ai_is_manual_advisory_only', ?)
        """,
        (
            json_dump({"campaign_id": campaign_id, "analysis_id": analysis_id, "analysis": analysis, "provider": provider, "model": model, "analysis_version": ANALYSIS_VERSION}),
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
        "analysis_id": analysis_id,
        "analysis": analysis,
        "analyzed_at": analyzed_at,
        "provider": provider,
        "model": model,
        "analysis_version": ANALYSIS_VERSION,
        "analysis_status": "valid",
        "campaign_fingerprint": campaign_fingerprint,
        "evidence_fingerprint": evidence_fingerprint,
        "advisory_only": True,
        "mitigation_executed": False,
    }
