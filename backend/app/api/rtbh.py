"""API for Transit Providers + RTBH policies + TI mitigation candidates.

RECOMMEND_ONLY / DRY RUN version:

- No endpoint here ever reaches a BGP executor, ExaBGP pipe or router.
- Candidate transitions are limited to PROPOSED / REVIEW_REQUIRED /
  REJECTED / DRY_RUN / FAILED.
- Community values are masked for callers without ``bgp.manage``.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

try:
    from fastapi import APIRouter, HTTPException, Query, Request
except ImportError:  # Pragmatic compatibility with the repository static-test stub.
    from fastapi import FastAPI as APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.sqlite_managed import open_managed
from app.services.threat_intelligence import clean_text
from app.services.transit_rtbh import (
    ACTION_TYPE_MANUAL_LARGE_PREFIX_RTBH,
    CANDIDATE_STATUS_REVIEW_REQUIRED,
    RTBH_MODES,
    RTBH_MODE_RECOMMEND_ONLY,
    apply_candidate_status,
    audit_candidate_event,
    candidate_row_to_dict,
    ensure_transit_rtbh_schema,
    policy_row_to_dict,
    provider_row_to_dict,
    rtbh_dry_run,
    rtbh_execution_enabled_env,
    rtbh_report_section,
    rtbh_version_allows_execution,
    safe_int,
    validate_community_list,
)

router = APIRouter(prefix="/api/rtbh", tags=["rtbh"])

ADDRESS_FAMILIES = {"ipv4", "ipv6"}


def sqlite_connection() -> sqlite3.Connection:
    path = Path(os.getenv("GMJFLOW_DB_PATH", "/app/data/gmjflow.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = open_managed(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def actor_from_request(request: Request) -> str:
    user = getattr(getattr(request, "state", None), "user", None)
    if isinstance(user, dict):
        return clean_text(user.get("username") or user.get("id") or "operator")
    return "operator"


def actor_can_manage_bgp(request: Request) -> bool:
    user = getattr(getattr(request, "state", None), "user", None)
    if not isinstance(user, dict):
        return False
    permissions = set(user.get("permissions") or [])
    return bool(permissions) and (
        "bgp.manage" in permissions
        or "settings.manage" in permissions
        or permissions == {"*"}
    )


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------


class TransitProviderPayload(BaseModel):
    name: str
    sensor_id: int | None = None
    input_if: int = Field(0, ge=0)
    enabled: bool = True
    notes: str = ""


class TransitRtbhPolicyPayload(BaseModel):
    enabled: bool = True
    standard_communities: list[str] = Field(default_factory=list)
    large_communities: list[str] = Field(default_factory=list)
    communities_sensitive: bool = True
    address_family: str = "ipv4"
    mode: str = RTBH_MODE_RECOMMEND_ONLY
    min_prefix_length: int = Field(32, ge=0, le=128)
    max_prefix_length: int = Field(32, ge=0, le=128)
    min_confidence: float = Field(0.90, ge=0, le=1)
    min_attack_bps: float = Field(1_000_000_000.0, ge=0)
    min_duration_seconds: int = Field(60, ge=0)
    cooldown_seconds: int = Field(3600, ge=0)
    allow_auto: bool = False
    require_manual_approval: bool = True


class CandidateActionPayload(BaseModel):
    reason: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalize_policy_payload(payload: TransitRtbhPolicyPayload) -> dict[str, Any]:
    mode = clean_text(payload.mode).upper()
    if mode not in RTBH_MODES:
        raise HTTPException(status_code=422, detail=f"mode invalido: {mode}")
    address_family = clean_text(payload.address_family).lower()
    if address_family not in ADDRESS_FAMILIES:
        raise HTTPException(status_code=422, detail="address_family invalido")
    if payload.min_prefix_length > payload.max_prefix_length:
        raise HTTPException(
            status_code=422,
            detail="min_prefix_length nao pode exceder max_prefix_length",
        )
    try:
        standard = validate_community_list("standard", payload.standard_communities)
        large = validate_community_list("large", payload.large_communities)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "enabled": 1 if payload.enabled else 0,
        "standard_communities_json": _json(standard),
        "large_communities_json": _json(large),
        "communities_sensitive": 1 if payload.communities_sensitive else 0,
        "address_family": address_family,
        "mode": mode,
        "min_prefix_length": int(payload.min_prefix_length),
        "max_prefix_length": int(payload.max_prefix_length),
        "min_confidence": float(payload.min_confidence),
        "min_attack_bps": float(payload.min_attack_bps),
        "min_duration_seconds": int(payload.min_duration_seconds),
        "cooldown_seconds": int(payload.cooldown_seconds),
        "allow_auto": 1 if payload.allow_auto else 0,
        "require_manual_approval": 1 if payload.require_manual_approval else 0,
    }


def _json(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def provider_detail(conn: sqlite3.Connection, provider_id: int, request: Request) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM transit_providers WHERE id = ?", (provider_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Transit Provider nao encontrado")
    item = provider_row_to_dict(row)
    policy_row = conn.execute(
        "SELECT * FROM transit_rtbh_policies WHERE provider_id = ?",
        (provider_id,),
    ).fetchone()
    item["policy"] = (
        policy_row_to_dict(policy_row, include_communities=actor_can_manage_bgp(request))
        if policy_row is not None
        else None
    )
    return item


# ---------------------------------------------------------------------------
# Kill switch / overview
# ---------------------------------------------------------------------------


@router.get("/overview")
def rtbh_overview(request: Request) -> dict[str, Any]:
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        provider_count = int(
            conn.execute("SELECT COUNT(*) FROM transit_providers").fetchone()[0]
        )
        policy_count = int(
            conn.execute("SELECT COUNT(*) FROM transit_rtbh_policies").fetchone()[0]
        )
        candidate_counts: dict[str, int] = {}
        for row in conn.execute(
            "SELECT status, COUNT(*) AS total FROM rtbh_mitigation_candidates GROUP BY status"
        ).fetchall():
            candidate_counts[clean_text(row["status"])] = int(row["total"])
    return {
        "kill_switch": {
            "env_var": "RTBH_EXECUTION_ENABLED",
            "environment_execution_enabled": rtbh_execution_enabled_env(),
            "version_allows_execution": rtbh_version_allows_execution(),
            "effective_execution": rtbh_execution_enabled_env() and rtbh_version_allows_execution(),
            "note": "Esta versão é RECOMMEND_ONLY / DRY RUN. Nenhum anúncio BGP é realizado.",
        },
        "providers": provider_count,
        "policies": policy_count,
        "candidate_counts": candidate_counts,
    }


# ---------------------------------------------------------------------------
# Transit providers CRUD
# ---------------------------------------------------------------------------


@router.get("/providers")
def rtbh_providers(request: Request) -> dict[str, Any]:
    include_communities = actor_can_manage_bgp(request)
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        rows = conn.execute(
            "SELECT * FROM transit_providers ORDER BY name, id"
        ).fetchall()
        items = []
        for row in rows:
            item = provider_row_to_dict(row)
            policy_row = conn.execute(
                "SELECT * FROM transit_rtbh_policies WHERE provider_id = ?",
                (int(row["id"]),),
            ).fetchone()
            item["policy"] = (
                policy_row_to_dict(policy_row, include_communities=include_communities)
                if policy_row is not None
                else None
            )
            items.append(item)
    return {"items": items}


@router.post("/providers", status_code=201)
def rtbh_providers_create(request: Request, payload: TransitProviderPayload) -> dict[str, Any]:
    from app.services.threat_intelligence import utc_now_iso

    name = clean_text(payload.name)
    if not name:
        raise HTTPException(status_code=422, detail="name obrigatorio")
    now = utc_now_iso()
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        existing = conn.execute(
            "SELECT id FROM transit_providers WHERE lower(name) = lower(?)",
            (name,),
        ).fetchone()
        if existing is not None:
            raise HTTPException(status_code=409, detail="Transit Provider ja existe")
        cursor = conn.execute(
            """
            INSERT INTO transit_providers (name, sensor_id, input_if, enabled, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                payload.sensor_id,
                int(payload.input_if),
                1 if payload.enabled else 0,
                clean_text(payload.notes),
                now,
                now,
            ),
        )
        provider_id = int(cursor.lastrowid)
        audit_candidate_event(
            conn,
            actor=actor_from_request(request),
            action="provider_created",
            provider_id=provider_id,
            target_prefix=name,
            old_state="",
            new_state="ENABLED" if payload.enabled else "DISABLED",
            reason="transit_provider_registered",
        )
        conn.commit()
        item = provider_detail(conn, provider_id, request)
    return {"ok": True, "provider": item}


@router.put("/providers/{provider_id}")
def rtbh_providers_update(
    provider_id: int,
    request: Request,
    payload: TransitProviderPayload,
) -> dict[str, Any]:
    from app.services.threat_intelligence import utc_now_iso

    name = clean_text(payload.name)
    if not name:
        raise HTTPException(status_code=422, detail="name obrigatorio")
    now = utc_now_iso()
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        row = conn.execute(
            "SELECT * FROM transit_providers WHERE id = ?",
            (provider_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Transit Provider nao encontrado")
        duplicate = conn.execute(
            "SELECT id FROM transit_providers WHERE lower(name) = lower(?) AND id <> ?",
            (name, provider_id),
        ).fetchone()
        if duplicate is not None:
            raise HTTPException(status_code=409, detail="Transit Provider ja existe")
        conn.execute(
            """
            UPDATE transit_providers
            SET name = ?, sensor_id = ?, input_if = ?, enabled = ?, notes = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                name,
                payload.sensor_id,
                int(payload.input_if),
                1 if payload.enabled else 0,
                clean_text(payload.notes),
                now,
                provider_id,
            ),
        )
        audit_candidate_event(
            conn,
            actor=actor_from_request(request),
            action="provider_updated",
            provider_id=provider_id,
            target_prefix=name,
            old_state=clean_text(row["name"]),
            new_state=name,
            reason="transit_provider_updated",
        )
        conn.commit()
        item = provider_detail(conn, provider_id, request)
    return {"ok": True, "provider": item}


@router.delete("/providers/{provider_id}")
def rtbh_providers_delete(provider_id: int, request: Request) -> dict[str, Any]:
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        row = conn.execute(
            "SELECT * FROM transit_providers WHERE id = ?",
            (provider_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Transit Provider nao encontrado")
        audit_candidate_event(
            conn,
            actor=actor_from_request(request),
            action="provider_deleted",
            provider_id=provider_id,
            target_prefix=clean_text(row["name"]),
            old_state=clean_text(row["name"]),
            new_state="DELETED",
            reason="transit_provider_deleted",
        )
        conn.execute("DELETE FROM transit_providers WHERE id = ?", (provider_id,))
        conn.commit()
    return {"ok": True, "deleted": True}


# ---------------------------------------------------------------------------
# RTBH policies
# ---------------------------------------------------------------------------


@router.put("/providers/{provider_id}/policy")
def rtbh_policy_upsert(
    provider_id: int,
    request: Request,
    payload: TransitRtbhPolicyPayload,
) -> dict[str, Any]:
    from app.services.threat_intelligence import utc_now_iso

    data = normalize_policy_payload(payload)
    now = utc_now_iso()
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        provider = conn.execute(
            "SELECT * FROM transit_providers WHERE id = ?",
            (provider_id,),
        ).fetchone()
        if provider is None:
            raise HTTPException(status_code=404, detail="Transit Provider nao encontrado")
        existing = conn.execute(
            "SELECT id FROM transit_rtbh_policies WHERE provider_id = ?",
            (provider_id,),
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO transit_rtbh_policies (
                    provider_id, enabled, standard_communities_json, large_communities_json,
                    communities_sensitive, address_family, mode, min_prefix_length,
                    max_prefix_length, min_confidence, min_attack_bps, min_duration_seconds,
                    cooldown_seconds, allow_auto, require_manual_approval, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    provider_id,
                    data["enabled"],
                    data["standard_communities_json"],
                    data["large_communities_json"],
                    data["communities_sensitive"],
                    data["address_family"],
                    data["mode"],
                    data["min_prefix_length"],
                    data["max_prefix_length"],
                    data["min_confidence"],
                    data["min_attack_bps"],
                    data["min_duration_seconds"],
                    data["cooldown_seconds"],
                    data["allow_auto"],
                    data["require_manual_approval"],
                    now,
                    now,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE transit_rtbh_policies
                SET enabled = ?, standard_communities_json = ?, large_communities_json = ?,
                    communities_sensitive = ?, address_family = ?, mode = ?,
                    min_prefix_length = ?, max_prefix_length = ?, min_confidence = ?,
                    min_attack_bps = ?, min_duration_seconds = ?, cooldown_seconds = ?,
                    allow_auto = ?, require_manual_approval = ?, updated_at = ?
                WHERE provider_id = ?
                """,
                (
                    data["enabled"],
                    data["standard_communities_json"],
                    data["large_communities_json"],
                    data["communities_sensitive"],
                    data["address_family"],
                    data["mode"],
                    data["min_prefix_length"],
                    data["max_prefix_length"],
                    data["min_confidence"],
                    data["min_attack_bps"],
                    data["min_duration_seconds"],
                    data["cooldown_seconds"],
                    data["allow_auto"],
                    data["require_manual_approval"],
                    now,
                    provider_id,
                ),
            )
        policy_row = conn.execute(
            "SELECT * FROM transit_rtbh_policies WHERE provider_id = ?",
            (provider_id,),
        ).fetchone()
        audit_candidate_event(
            conn,
            actor=actor_from_request(request),
            action="provider_policy_updated",
            provider_id=provider_id,
            target_prefix=clean_text(provider["name"]),
            policy_id=safe_int(policy_row["id"]),
            old_state="",
            new_state=data["mode"],
            reason="provider_rtbh_policy_updated",
        )
        conn.commit()
        policy = policy_row_to_dict(policy_row, include_communities=actor_can_manage_bgp(request))
    return {"ok": True, "policy": policy}


# ---------------------------------------------------------------------------
# Mitigation candidates
# ---------------------------------------------------------------------------


def candidate_detail(
    conn: sqlite3.Connection,
    candidate_id: int,
    *,
    include_communities: bool = False,
) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT c.*, v.name AS provider_name
        FROM rtbh_mitigation_candidates c
        LEFT JOIN transit_providers v ON v.id = c.provider_id
        WHERE c.id = ?
        """,
        (candidate_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Candidate nao encontrado")
    item = candidate_row_to_dict(row)
    if include_communities:
        dry_run = rtbh_dry_run(conn, item, include_community_values=True)
        item["dry_run"] = dry_run
    return item


@router.get("/candidates")
def rtbh_candidates(
    request: Request,
    status: str = "",
    incident_id: str = "",
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    filters = ["1 = 1"]
    params: list[Any] = []
    if clean_text(status):
        normalized = clean_text(status).upper()
        filters.append("c.status = ?")
        params.append(normalized)
    if clean_text(incident_id):
        filters.append("c.incident_id = ?")
        params.append(clean_text(incident_id))
    where = " AND ".join(filters)
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        total = int(
            conn.execute(
                f"SELECT COUNT(*) FROM rtbh_mitigation_candidates c WHERE {where}",
                params,
            ).fetchone()[0]
        )
        rows = conn.execute(
            f"""
            SELECT c.*, v.name AS provider_name
            FROM rtbh_mitigation_candidates c
            LEFT JOIN transit_providers v ON v.id = c.provider_id
            WHERE {where}
            ORDER BY c.created_at DESC, c.id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, int(limit), int(offset)],
        ).fetchall()
        items = [candidate_row_to_dict(row) for row in rows]
    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.get("/candidates/{candidate_id}")
def rtbh_candidate_detail(candidate_id: int, request: Request) -> dict[str, Any]:
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        item = candidate_detail(
            conn,
            candidate_id,
            include_communities=actor_can_manage_bgp(request),
        )
    return {"candidate": item}


@router.post("/candidates/{candidate_id}/review")
def rtbh_candidate_review(
    candidate_id: int,
    request: Request,
    payload: CandidateActionPayload,
) -> dict[str, Any]:
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        try:
            item = apply_candidate_status(
                conn,
                candidate_id,
                CANDIDATE_STATUS_REVIEW_REQUIRED,
                actor=actor_from_request(request),
                reason=clean_text(payload.reason) or "marked_for_review",
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        conn.commit()
    return {"ok": True, "candidate": item}


@router.post("/candidates/{candidate_id}/reject")
def rtbh_candidate_reject(
    candidate_id: int,
    request: Request,
    payload: CandidateActionPayload,
) -> dict[str, Any]:
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        try:
            item = apply_candidate_status(
                conn,
                candidate_id,
                "REJECTED",
                actor=actor_from_request(request),
                reason=clean_text(payload.reason) or "rejected_by_operator",
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        conn.commit()
    return {"ok": True, "candidate": item}


@router.post("/candidates/{candidate_id}/dry-run")
def rtbh_candidate_dry_run(
    candidate_id: int,
    request: Request,
    payload: CandidateActionPayload,
) -> dict[str, Any]:
    """Execute an RTBH DRY RUN: builds the action that would be sent to BGP
    without touching ExaBGP, pipes, connectors or routers."""
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        try:
            item = apply_candidate_status(
                conn,
                candidate_id,
                "DRY_RUN",
                actor=actor_from_request(request),
                reason=clean_text(payload.reason) or "dry_run_requested",
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        conn.commit()
    dry_run = item.get("dry_run") or {}
    return {
        "ok": True,
        "candidate": item,
        "dry_run": {
            **dry_run,
            "actually_announced": False,
            "note": "DRY RUN somente. Nenhum anuncio BGP foi realizado.",
        },
    }


@router.get("/incidents/{incident_id}/candidates")
def rtbh_incident_candidates(incident_id: str, request: Request) -> dict[str, Any]:
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        report = rtbh_report_section(conn, clean_text(incident_id))
    return report


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


@router.get("/audit")
def rtbh_audit(
    request: Request,
    candidate_id: int | None = None,
    provider_id: int | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    filters = ["1 = 1"]
    params: list[Any] = []
    if candidate_id is not None:
        filters.append("candidate_id = ?")
        params.append(candidate_id)
    if provider_id is not None:
        filters.append("provider_id = ?")
        params.append(provider_id)
    where = " AND ".join(filters)
    with sqlite_connection() as conn:
        ensure_transit_rtbh_schema(conn)
        total = int(
            conn.execute(
                f"SELECT COUNT(*) FROM rtbh_candidate_audit WHERE {where}",
                params,
            ).fetchone()[0]
        )
        rows = conn.execute(
            f"""
            SELECT * FROM rtbh_candidate_audit
            WHERE {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, int(limit), int(offset)],
        ).fetchall()
        items = [dict(row) for row in rows]
    return {"items": items, "total": total, "offset": offset, "limit": limit}
