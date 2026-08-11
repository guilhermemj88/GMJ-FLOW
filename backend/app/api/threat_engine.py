from __future__ import annotations

from typing import Any

try:
    from fastapi import APIRouter, Query
except ImportError:  # Compatibility with the repository's minimal static-test FastAPI stub.
    from fastapi import FastAPI as APIRouter, Query

from app.services.behavioral_detection import (
    BEHAVIORAL_THREAT_RUNTIME,
    attack_vector_row,
    campaign_row,
    ensure_behavioral_schema,
)
from app.services.threat_policy import ensure_threat_policy_schema, policy_decision_row


router = APIRouter(prefix="/api/threat-engine", tags=["threat-engine"])


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
