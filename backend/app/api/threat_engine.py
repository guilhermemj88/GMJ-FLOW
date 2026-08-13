from __future__ import annotations

from typing import Any

try:
    from fastapi import APIRouter, HTTPException, Query
except ImportError:  # Compatibility with the repository's minimal static-test FastAPI stub.
    from fastapi import FastAPI as APIRouter, HTTPException, Query

from app.services.behavioral_detection import (
    BEHAVIORAL_THREAT_RUNTIME,
    attack_vector_row,
    campaign_row,
    ensure_behavioral_schema,
)
from app.services.threat_policy import ensure_threat_policy_schema, policy_decision_row
from app.services.campaign_ai import analyze_campaign, get_campaign_analysis
from app.services.campaign_investigation import get_campaign_investigation
from app.services.security_event_ai import analyze_security_event, get_security_event_analysis
from app.services.security_event_investigation import event_evidence, event_sources, event_traffic
from app.services.security_events import (
    ensure_security_event_schema,
    find_security_event,
    migrate_legacy_security_events,
    security_event_row,
    update_event_status,
)


router = APIRouter(prefix="/api/threat-engine", tags=["threat-engine"])
security_router = APIRouter(prefix="/security", tags=["security-investigation"])
api_security_router = APIRouter(prefix="/api/security", tags=["security-investigation"])


@router.get("/status")
def threat_engine_status() -> dict[str, Any]:
    return dict(BEHAVIORAL_THREAT_RUNTIME.state)


@router.post("/run")
def run_threat_engine() -> dict[str, Any]:
    return BEHAVIORAL_THREAT_RUNTIME.run_once()


@router.get("/attack-vectors")
def list_attack_vectors(
    status: str = "",
    attack_type: str = "",
    limit: int = Query(200, ge=1, le=1000),
) -> dict[str, Any]:
    filters = []
    values: list[Any] = []
    if status:
        filters.append("status = ?")
        values.append(status)
    if attack_type:
        filters.append("attack_type = ?")
        values.append(attack_type)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        rows = conn.execute(
            f"SELECT * FROM behavioral_attack_vectors {where} ORDER BY last_seen DESC, id DESC LIMIT ?",
            (*values, limit),
        ).fetchall()
    return {"items": [attack_vector_row(row) for row in rows]}


@router.get("/campaigns")
def list_campaigns(status: str = "", limit: int = Query(200, ge=1, le=1000)) -> dict[str, Any]:
    where = "WHERE status = ?" if status else ""
    values = (status, limit) if status else (limit,)
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        rows = conn.execute(
            f"SELECT * FROM threat_campaigns {where} ORDER BY last_seen DESC, campaign_id DESC LIMIT ?",
            values,
        ).fetchall()
    return {"items": [campaign_row(row) for row in rows]}


@router.get("/history")
def threat_history(limit: int = Query(200, ge=1, le=1000)) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        rows = conn.execute(
            "SELECT * FROM gmj_threat_history ORDER BY last_seen_gmj DESC LIMIT ?", (limit,)
        ).fetchall()
    return {"items": [dict(row) for row in rows]}


@router.get("/policy-decisions")
def policy_decisions(
    decision: str = "",
    limit: int = Query(200, ge=1, le=1000),
) -> dict[str, Any]:
    where = "WHERE decision = ?" if decision else ""
    values = (decision, limit) if decision else (limit,)
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_threat_policy_schema(conn)
        rows = conn.execute(
            f"SELECT * FROM threat_policy_decisions {where} ORDER BY id DESC LIMIT ?",
            values,
        ).fetchall()
    return {"items": [policy_decision_row(row) for row in rows]}


@router.get("/audit")
def threat_engine_audit(limit: int = Query(200, ge=1, le=1000)) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        rows = conn.execute(
            "SELECT * FROM threat_engine_audit ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return {"items": [dict(row) for row in rows]}


def _event_or_404(event_id: Any) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        ensure_security_event_schema(conn)
        migrate_legacy_security_events(conn)
        conn.commit()
        event = find_security_event(conn, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Evento de segurança não encontrado")
    return event


@security_router.get("/events")
@api_security_router.get("/events")
def list_security_events(
    status: str = "",
    attack_type: str = "",
    verdict: str = "",
    campaign_id: str = "",
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    filters = []
    values: list[Any] = []
    for column, value in (
        ("status", status), ("attack_type", attack_type),
        ("verdict", verdict), ("campaign_id", campaign_id),
    ):
        if value:
            filters.append(f"{column} = ?")
            values.append(value)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        ensure_security_event_schema(conn)
        migrate_legacy_security_events(conn)
        total = int(conn.execute(f"SELECT COUNT(*) FROM security_events {where}", values).fetchone()[0])
        rows = conn.execute(
            f"SELECT * FROM security_events {where} ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?",
            (*values, int(limit), int(offset)),
        ).fetchall()
        conn.commit()
    return {"items": [security_event_row(row) for row in rows], "total": total, "limit": limit, "offset": offset}


@security_router.get("/events/{event_id}")
@api_security_router.get("/events/{event_id}")
def get_security_event(event_id: str) -> dict[str, Any]:
    return _event_or_404(event_id)


@security_router.get("/events/{event_id}/evidence")
@api_security_router.get("/events/{event_id}/evidence")
def get_security_event_evidence(event_id: str, sample_limit: int = Query(100, ge=1, le=100)) -> dict[str, Any]:
    event = _event_or_404(event_id)
    return event_evidence(event, sample_limit=sample_limit)


@security_router.get("/events/{event_id}/traffic")
@api_security_router.get("/events/{event_id}/traffic")
def get_security_event_traffic(event_id: str, padding_seconds: int = Query(600, ge=0, le=3600)) -> dict[str, Any]:
    return event_traffic(_event_or_404(event_id), padding_seconds=padding_seconds)


@security_router.get("/events/{event_id}/sources")
@api_security_router.get("/events/{event_id}/sources")
def get_security_event_sources(
    event_id: str,
    sort: str = Query("packets"),
    limit: int = Query(100, ge=1, le=100),
) -> dict[str, Any]:
    return event_sources(_event_or_404(event_id), sort_by=sort, limit=limit)


@security_router.get("/events/{event_id}/threat-intel")
@api_security_router.get("/events/{event_id}/threat-intel")
def get_security_event_threat_intel(event_id: str) -> dict[str, Any]:
    event = _event_or_404(event_id)
    source_intel = event["threat_intel"].get("source_intel") or {}
    return {
        "event_id": event["event_id"],
        "threat_intel": event["threat_intel"],
        "interpretation": (
            f"Threat Intelligence encontrou {int(source_intel.get('matched_source_count') or source_intel.get('matches') or 0)} "
            f"de {int(source_intel.get('lookup_count') or 0)} origens consultadas com histórico registrado. "
            "Isso enriquece a investigação e não confirma, por si só, o vetor comportamental atual."
        ),
    }


@security_router.get("/events/{event_id}/related")
@api_security_router.get("/events/{event_id}/related")
def related_security_events(event_id: str, limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    event = _event_or_404(event_id)
    clauses = []
    values: list[Any] = []
    for field in ("campaign_id", "src_ip", "target_ip", "target_prefix"):
        value = event.get(field)
        if value:
            clauses.append(f"{field}=?")
            values.append(value)
    if not clauses:
        return {"event_id": event_id, "items": []}
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_security_event_schema(conn)
        rows = conn.execute(
            f"SELECT * FROM security_events WHERE id<>? AND ({' OR '.join(clauses)}) ORDER BY last_seen DESC LIMIT ?",
            (int(event["id"]), *values, int(limit)),
        ).fetchall()
    return {"event_id": event["event_id"], "items": [security_event_row(row) for row in rows]}


def _run_event_ai(event_id: Any, force: bool) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        result = analyze_security_event(conn, event_id, force=force)
    if result.get("status") == "not_found":
        raise HTTPException(status_code=404, detail=result.get("error_message"))
    if not result.get("ok"):
        status_code = {
            "disabled": 409, "not_configured": 409, "rate_limit": 429,
            "timeout": 504, "unavailable": 503, "invalid_response": 502, "invalid_json": 502,
            "payload_too_large": 413,
        }.get(result.get("error_type") or result.get("status"), 503)
        raise HTTPException(status_code=status_code, detail={
            "status": result.get("status") or "failed",
            "error_type": result.get("error_type") or "unavailable",
            "message": result.get("error_message") or "Análise de IA indisponível",
        })
    return result


@security_router.post("/events/{event_id}/analyze-ai")
def analyze_event_ai(event_id: str) -> dict[str, Any]:
    return _run_event_ai(event_id, force=False)


@security_router.post("/events/{event_id}/reanalyze-ai")
def reanalyze_event_ai(event_id: str) -> dict[str, Any]:
    return _run_event_ai(event_id, force=True)


@security_router.get("/events/{event_id}/ai-analysis")
@api_security_router.get("/events/{event_id}/ai-analysis")
def get_event_ai_analysis(event_id: str) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        result = get_security_event_analysis(conn, event_id)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error_message"))
    return result


@security_router.post("/events/{event_id}/ai-analysis")
@api_security_router.post("/events/{event_id}/ai-analysis")
def create_event_ai_analysis(event_id: str, force: bool = Query(False)) -> dict[str, Any]:
    return _run_event_ai(event_id, force=force)


@security_router.get("/campaigns/{campaign_id}")
@api_security_router.get("/campaigns/{campaign_id}")
def get_security_campaign(campaign_id: str) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        ensure_security_event_schema(conn)
        result = get_campaign_investigation(conn, campaign_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Campanha não encontrada")
    return result


def _run_campaign_ai(campaign_id: str, force: bool) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        ensure_security_event_schema(conn)
        result = analyze_campaign(conn, campaign_id, force=force)
    if result.get("status") == "not_found":
        raise HTTPException(status_code=404, detail=result.get("error_message"))
    if not result.get("ok"):
        status_code = {
            "disabled": 409, "not_configured": 409, "rate_limit": 429,
            "timeout": 504, "unavailable": 503, "invalid_response": 502, "invalid_json": 502,
            "payload_too_large": 413,
        }.get(result.get("error_type") or result.get("status"), 503)
        raise HTTPException(status_code=status_code, detail={
            "status": result.get("status") or "failed",
            "error_type": result.get("error_type") or "unavailable",
            "message": result.get("error_message") or "Análise de IA indisponível",
        })
    return result


@security_router.get("/campaigns/{campaign_id}/ai-analysis")
@api_security_router.get("/campaigns/{campaign_id}/ai-analysis")
def get_security_campaign_ai_analysis(campaign_id: str) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        ensure_security_event_schema(conn)
        result = get_campaign_analysis(conn, campaign_id)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error_message"))
    return result


@security_router.post("/campaigns/{campaign_id}/ai-analysis")
@api_security_router.post("/campaigns/{campaign_id}/ai-analysis")
def create_security_campaign_ai_analysis(campaign_id: str, force: bool = Query(False)) -> dict[str, Any]:
    return _run_campaign_ai(campaign_id, force=force)


def _set_event_status(event_id: Any, status: str) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        event = find_security_event(conn, event_id)
        item = update_event_status(conn, int(event["id"]), status) if event else None
        conn.commit()
    if item is None:
        raise HTTPException(status_code=404, detail="Evento de segurança não encontrado")
    return item


@security_router.post("/events/{event_id}/mark-benign")
@api_security_router.post("/events/{event_id}/mark-benign")
def mark_event_benign(event_id: str) -> dict[str, Any]:
    return _set_event_status(event_id, "benign")


@security_router.post("/events/{event_id}/mark-confirmed")
@api_security_router.post("/events/{event_id}/mark-confirmed")
def mark_event_confirmed(event_id: str) -> dict[str, Any]:
    return _set_event_status(event_id, "confirmed")


@security_router.post("/events/{event_id}/investigating")
@api_security_router.post("/events/{event_id}/investigating")
def mark_event_investigating(event_id: str) -> dict[str, Any]:
    return _set_event_status(event_id, "investigating")
