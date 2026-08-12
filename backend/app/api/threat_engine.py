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
from app.services.security_event_ai import analyze_security_event
from app.services.security_events import (
    ensure_security_event_schema,
    migrate_legacy_security_events,
    security_event_row,
    update_event_status,
)


router = APIRouter(prefix="/api/threat-engine", tags=["threat-engine"])
security_router = APIRouter(prefix="/security", tags=["security-investigation"])


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


def _event_or_404(event_id: int) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        ensure_security_event_schema(conn)
        migrate_legacy_security_events(conn)
        conn.commit()
        row = conn.execute("SELECT * FROM security_events WHERE id=?", (int(event_id),)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Evento de segurança não encontrado")
    return security_event_row(row)


@security_router.get("/events")
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
def get_security_event(event_id: int) -> dict[str, Any]:
    return _event_or_404(event_id)


@security_router.get("/events/{event_id}/evidence")
def get_security_event_evidence(event_id: int) -> dict[str, Any]:
    event = _event_or_404(event_id)
    return {
        "event_id": event_id,
        "detector": event["detector"],
        "score": event["detector_score"],
        "score_components": event["score_components"],
        "evidence": event["evidence"],
        "network_context": event["network_context"],
    }


@security_router.get("/events/{event_id}/threat-intel")
def get_security_event_threat_intel(event_id: int) -> dict[str, Any]:
    event = _event_or_404(event_id)
    source_intel = event["threat_intel"].get("source_intel") or {}
    return {
        "event_id": event_id,
        "threat_intel": event["threat_intel"],
        "interpretation": (
            f"Threat Intelligence encontrou {int(source_intel.get('matched_source_count') or source_intel.get('matches') or 0)} "
            f"de {int(source_intel.get('lookup_count') or 0)} origens consultadas com histórico registrado. "
            "Isso enriquece a investigação e não confirma, por si só, o vetor comportamental atual."
        ),
    }


@security_router.get("/events/{event_id}/related")
def related_security_events(event_id: int, limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
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
            (int(event_id), *values, int(limit)),
        ).fetchall()
    return {"event_id": event_id, "items": [security_event_row(row) for row in rows]}


def _run_event_ai(event_id: int, force: bool) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        result = analyze_security_event(conn, event_id, force=force)
    if result.get("status") == "not_found":
        raise HTTPException(status_code=404, detail=result.get("error_message"))
    if not result.get("ok"):
        raise HTTPException(status_code=409, detail={
            "status": result.get("status") or "failed",
            "error_type": result.get("error_type") or "unavailable",
            "message": result.get("error_message") or "Análise de IA indisponível",
        })
    return result


@security_router.post("/events/{event_id}/analyze-ai")
def analyze_event_ai(event_id: int) -> dict[str, Any]:
    return _run_event_ai(event_id, force=False)


@security_router.post("/events/{event_id}/reanalyze-ai")
def reanalyze_event_ai(event_id: int) -> dict[str, Any]:
    return _run_event_ai(event_id, force=True)


@security_router.get("/campaigns/{campaign_id}")
def get_security_campaign(campaign_id: str) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        ensure_security_event_schema(conn)
        row = conn.execute("SELECT * FROM threat_campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
        event_rows = conn.execute(
            "SELECT * FROM security_events WHERE campaign_id=? ORDER BY last_seen DESC",
            (campaign_id,),
        ).fetchall()
    if row is None:
        raise HTTPException(status_code=404, detail="Campanha não encontrada")
    return {"campaign": campaign_row(row), "events": [security_event_row(item) for item in event_rows]}


def _set_event_status(event_id: int, status: str) -> dict[str, Any]:
    with BEHAVIORAL_THREAT_RUNTIME.connection_factory() as conn:
        ensure_behavioral_schema(conn)
        item = update_event_status(conn, event_id, status)
        conn.commit()
    if item is None:
        raise HTTPException(status_code=404, detail="Evento de segurança não encontrado")
    return item


@security_router.post("/events/{event_id}/mark-benign")
def mark_event_benign(event_id: int) -> dict[str, Any]:
    return _set_event_status(event_id, "benign")


@security_router.post("/events/{event_id}/mark-confirmed")
def mark_event_confirmed(event_id: int) -> dict[str, Any]:
    return _set_event_status(event_id, "confirmed")


@security_router.post("/events/{event_id}/investigating")
def mark_event_investigating(event_id: int) -> dict[str, Any]:
    return _set_event_status(event_id, "investigating")
