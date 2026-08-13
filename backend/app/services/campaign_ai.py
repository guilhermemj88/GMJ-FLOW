from __future__ import annotations

import json
import logging
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


ANALYSIS_VERSION = "campaign-analysis/v2"
logger = logging.getLogger("gmj-flow")
CAMPAIGN_AI_SYSTEM_PROMPT = """You are a network security analyst specialized in ISP, carrier and broadband networks.

Analyze this campaign as a campaign, not as an individual Security Event. Use only the bounded evidence provided by GMJ-FLOW and do not invent facts.

Differentiate detector evidence, correlation evidence, persisted Threat Intelligence enrichment, correlated canonical events, and inference. Threat Intelligence is enrichment and must never be described as the reason the campaign detector fired.

Do not call a campaign confirmed only because its detector or coordination score is high; scores reflect satisfied local criteria, not probabilistic certainty. Consider ISP and CGNAT context, baseline and delta, low per-host rate, source count and ASN diversity, persistence, and historical recurrence. Respect metric provenance: peak/detection PPS is not the average PPS across the campaign lifetime.

A single persisted GreyNoise malicious match among thousands of sources is contextual support, not isolated confirmation of the whole campaign. Absence of a GreyNoise match does not mean a source is benign. State clearly when evidence is inconclusive.

Return concise operational guidance as valid JSON matching the requested schema. The analysis is advisory only. Never claim mitigation happened and never perform, request, or imply automatic mitigation."""


CAMPAIGN_PROMPT_PREFIX = (
    "Analyze the bounded Campaign Investigation payload below and return only JSON matching the requested schema. "
    "Keep campaign evidence, correlated Security Events, Threat Intelligence enrichment, and inference distinct.\n"
    "CAMPAIGN_JSON_BEGIN\n"
)
CAMPAIGN_PROMPT_SUFFIX = "\nCAMPAIGN_JSON_END"
_REDUCIBLE_CAMPAIGN_SECTIONS = (
    ("correlated_events",),
    ("detection_correlation_evidence", "contributors"),
    ("threat_intelligence", "matches"),
    ("asn_diversity", "distribution"),
    ("top_sources",),
    ("target", "ports"),
    ("detection_correlation_evidence", "detector_facts"),
    ("campaign_metadata", "contributing_detectors"),
    ("threat_intelligence", "summary", "tags"),
    ("threat_intelligence", "summary", "indicator_types"),
    ("threat_intelligence", "summary", "classifications"),
    ("threat_intelligence", "summary", "providers"),
)


def _campaign_prompt(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
    return f"{CAMPAIGN_PROMPT_PREFIX}{encoded}{CAMPAIGN_PROMPT_SUFFIX}"


def _payload_section(payload: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any] | None:
    value: Any = payload
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value if isinstance(value, dict) and isinstance(value.get("items"), list) else None


def _campaign_section_counts(payload: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    paths = {
        "top_sources": ("top_sources",),
        "asn_distribution": ("asn_diversity", "distribution"),
        "ports": ("target", "ports"),
        "protocols": ("target", "protocols"),
        "correlated_events": ("correlated_events",),
        "threat_intelligence_matches": ("threat_intelligence", "matches"),
        "detector_facts": ("detection_correlation_evidence", "detector_facts"),
        "contributors": ("detection_correlation_evidence", "contributors"),
    }
    counts: dict[str, dict[str, int]] = {}
    for name, path in paths.items():
        value: Any = payload
        for key in path:
            value = value.get(key) if isinstance(value, Mapping) else None
        section = value if isinstance(value, Mapping) else {}
        counts[name] = {
            "total_count": int(section.get("total_count") or 0),
            "included_count": int(section.get("included_count") or 0),
        }
    return counts


def _trim_payload_text(value: Any, max_chars: int) -> Any:
    if isinstance(value, str):
        return value if len(value) <= max_chars else value[:max_chars]
    if isinstance(value, list):
        return [_trim_payload_text(item, max_chars) for item in value]
    if isinstance(value, dict):
        return {key: _trim_payload_text(item, max_chars) for key, item in value.items()}
    return value


def _compact_campaign_core(payload: dict[str, Any]) -> None:
    """Remove descriptive duplication while retaining the required scalar evidence."""
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    if (target.get("protocols") or {}).get("items"):
        target.pop("protocol_summary", None)
    if not target.get("network_context"):
        target.pop("network_context", None)

    traffic = payload.get("traffic_metrics") if isinstance(payload.get("traffic_metrics"), dict) else {}
    for group_name in ("peak_rates", "snapshot_totals"):
        group = traffic.get(group_name) if isinstance(traffic.get(group_name), dict) else {}
        for metric in group.values():
            provenance = metric.get("provenance") if isinstance(metric, dict) and isinstance(metric.get("provenance"), dict) else {}
            provenance.pop("note", None)
            provenance.pop("aggregation", None)
    (traffic.get("peak_rates") or {}).pop("flows_per_second", None)

    baseline = payload.get("baseline_and_per_host_context")
    if isinstance(baseline, dict):
        baseline.pop("interpretation", None)
    asn = payload.get("asn_diversity") if isinstance(payload.get("asn_diversity"), dict) else {}
    asn.pop("distribution_context", None)
    metadata = payload.get("campaign_metadata") if isinstance(payload.get("campaign_metadata"), dict) else {}
    metadata.pop("contributing_detectors", None)
    evidence = payload.get("detection_correlation_evidence") if isinstance(payload.get("detection_correlation_evidence"), dict) else {}
    evidence.pop("score_semantics", None)
    threat = payload.get("threat_intelligence") if isinstance(payload.get("threat_intelligence"), dict) else {}
    summary = threat.get("summary") if isinstance(threat.get("summary"), dict) else {}
    for name in ("classifications", "indicator_types", "tags"):
        section = summary.get(name) if isinstance(summary.get(name), dict) else {}
        if not int(section.get("total_count") or 0):
            summary.pop(name, None)


def build_campaign_analysis_prompt(
    investigation: Mapping[str, Any],
    *,
    max_prompt_chars: int | None = None,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Build a bounded valid-JSON Campaign prompt using progressive list reduction."""
    hard_limit = max(4000, min(int(max_prompt_chars or 30000), 100000))
    practical_target = min(hard_limit, 25000)
    payload = campaign_analysis_payload(investigation)
    prompt = _campaign_prompt(payload)

    # Reduce one section at a time and re-measure so useful evidence is retained.
    while len(prompt) > practical_target:
        changed = False
        for path in _REDUCIBLE_CAMPAIGN_SECTIONS:
            current = _payload_section(payload, path)
            if current is None or not current["items"]:
                continue
            size = len(current["items"])
            reduced_size = max(0, size // 2)
            current["items"] = current["items"][:reduced_size]
            current["included_count"] = reduced_size
            changed = True
            prompt = _campaign_prompt(payload)
            if len(prompt) <= practical_target:
                break
        if not changed:
            break

    # Extremely verbose persisted labels/facts can still exceed a small configured cap.
    # Text is only truncated; fields and values are never synthesized.
    if len(prompt) > hard_limit:
        _compact_campaign_core(payload)
        prompt = _campaign_prompt(payload)

    if len(prompt) > hard_limit:
        for text_limit in (240, 120, 60):
            payload = _trim_payload_text(payload, text_limit)
            prompt = _campaign_prompt(payload)
            if len(prompt) <= hard_limit:
                break

    if len(prompt) > hard_limit:
        for path in _REDUCIBLE_CAMPAIGN_SECTIONS:
            current = _payload_section(payload, path)
            if current is not None and current["items"]:
                current["items"] = []
                current["included_count"] = 0
                prompt = _campaign_prompt(payload)
                if len(prompt) <= hard_limit:
                    break

    diagnostic = {
        "prompt_chars": len(prompt),
        "approx_tokens": (len(prompt) + 3) // 4,
        "sections": _campaign_section_counts(payload),
    }
    logger.info(
        "campaign_ai_payload prompt_chars=%s approx_tokens=%s sections=%s",
        diagnostic["prompt_chars"],
        diagnostic["approx_tokens"],
        diagnostic["sections"],
    )
    return prompt, payload, diagnostic


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
                "target", "top_sources", "asn_diversity", "traffic_metrics", "baseline_and_per_host_context", "correlated_events",
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
    config = security_ai_config(conn, "security_campaign_analysis")
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
        "kill_switch_enabled": config["kill_switch_enabled"],
        "route_configured": config["route_configured"],
        "route_enabled": config["route_enabled"],
        "routing_global_enabled": config["routing_global_enabled"],
        "config_source": config["config_source"],
        "provider": valid.get("provider") or latest.get("provider") or config["provider"],
        "provider_name": valid.get("provider") or latest.get("provider") or config["provider_name"],
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
    config = security_ai_config(conn, "security_campaign_analysis")
    if executor is None and not config["kill_switch_enabled"]:
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

    prompt, _bounded_payload, payload_diagnostic = build_campaign_analysis_prompt(
        investigation,
        max_prompt_chars=config["max_prompt_chars"],
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
        (json_dump(payload_diagnostic), now),
    )
    if payload_diagnostic["prompt_chars"] > config["max_prompt_chars"]:
        error_message = "Payload estruturado da campanha excede o limite configurado após compactação"
        conn.execute(
            """
            UPDATE campaign_ai_analyses
            SET status='failed', error_type='payload_too_large', error_message=?, updated_at=? WHERE id=?
            """,
            (error_message, utc_now_iso(), analysis_id),
        )
        conn.commit()
        return {
            "ok": False,
            "status": "failed",
            "error_type": "payload_too_large",
            "error_message": error_message,
            "analysis_id": analysis_id,
            "payload_diagnostic": payload_diagnostic,
        }
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
        return {**result, "analysis_id": analysis_id, "payload_diagnostic": payload_diagnostic}

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
            json_dump({"campaign_id": campaign_id, "analysis_id": analysis_id, "provider": provider, "model": model, "analysis_version": ANALYSIS_VERSION}),
            json_dump({"policy_verdict": "NOT_EVALUATED"}),
            json_dump({"mitigation_executed": False}),
            "structured_campaign_analysis_completed",
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
        "payload_diagnostic": payload_diagnostic,
    }
