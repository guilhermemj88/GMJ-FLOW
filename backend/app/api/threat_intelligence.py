from __future__ import annotations

from ipaddress import ip_network
from typing import Any

try:
    from fastapi import APIRouter, HTTPException, Query
except ImportError:  # Compatibility with the repository's minimal static-test FastAPI stub.
    from fastapi import FastAPI as APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.threat_intelligence import (
    INTEL_SOURCES,
    THREAT_INTEL_MANAGER,
    clean_text,
    ensure_threat_intel_schema,
    json_dump,
    safe_json,
    utc_now_iso,
)


router = APIRouter(prefix="/api/threat-intelligence", tags=["threat-intelligence"])


class ProviderStatePayload(BaseModel):
    enabled: bool


class NetworkContextPayload(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    sensor_name: str = Field("", max_length=128)
    exporter_ip: str = Field("", max_length=64)
    input_if: int | None = Field(None, ge=0)
    output_if: int | None = Field(None, ge=0)
    context_type: str = Field(..., min_length=1, max_length=32)
    protected_ranges: list[str] = Field(default_factory=list)
    enabled: bool = True


NETWORK_CONTEXT_TYPES = {
    "CUSTOMER", "CGNAT_PUBLIC", "INFRASTRUCTURE", "MANAGEMENT",
    "TRANSIT", "PEERING", "EXTERNAL", "UNKNOWN",
    # Backward-compatible aliases already stored by previous releases.
    "INTERNAL", "CGNAT", "BRAS", "INTERNET",
}


def normalized_network_context(payload: NetworkContextPayload) -> dict[str, Any]:
    item = payload.dict()
    item["context_type"] = clean_text(item["context_type"]).upper()
    if item["context_type"] not in NETWORK_CONTEXT_TYPES:
        raise HTTPException(status_code=422, detail="context_type invalido")
    ranges = []
    for value in item["protected_ranges"]:
        if not clean_text(value):
            continue
        try:
            ranges.append(str(ip_network(clean_text(value), strict=False)))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"range protegido invalido: {clean_text(value)}") from None
    item["protected_ranges"] = sorted(set(ranges))
    return item


def provider_name(value: str) -> str:
    normalized = clean_text(value).upper()
    if normalized not in INTEL_SOURCES:
        raise HTTPException(status_code=404, detail="Provider de Threat Intelligence nao encontrado")
    return normalized


@router.get("")
@router.get("/providers")
def list_providers() -> dict[str, Any]:
    items = THREAT_INTEL_MANAGER.statuses()
    return {
        "items": items,
        "summary": {
            "providers": len(items),
            "enabled": sum(bool(item.get("enabled")) for item in items),
            "online": sum(item.get("status") == "ACTIVE" for item in items),
            "records": sum(int(item.get("item_count") or 0) for item in items),
        },
    }


@router.get("/providers/{provider}")
def get_provider(provider: str) -> dict[str, Any]:
    return THREAT_INTEL_MANAGER.provider(provider_name(provider)).status()


@router.put("/providers/{provider}")
def update_provider(provider: str, payload: ProviderStatePayload) -> dict[str, Any]:
    return THREAT_INTEL_MANAGER.set_enabled(provider_name(provider), payload.enabled)


@router.post("/providers/{provider}/test")
def test_provider(provider: str) -> dict[str, Any]:
    return THREAT_INTEL_MANAGER.health_check(provider_name(provider))


@router.post("/providers/{provider}/sync")
def sync_provider(provider: str) -> dict[str, Any]:
    return THREAT_INTEL_MANAGER.sync(provider_name(provider))


@router.get("/lookup/{ip}")
def lookup_ip(
    ip: str,
    context_type: str = Query("", max_length=32),
    sensor: str = Query("", max_length=128),
    exporter_ip: str = Query("", max_length=64),
    input_if: int | None = None,
    output_if: int | None = None,
) -> dict[str, Any]:
    return THREAT_INTEL_MANAGER.lookup_ip(
        ip,
        {
            "context_type": context_type,
            "sensor": sensor,
            "exporter_ip": exporter_ip,
            "input_if": input_if,
            "output_if": output_if,
        },
    )


@router.get("/iocs")
def list_consolidated_iocs(
    tier: str = "",
    category: str = "",
    provider: str = "",
    freshness: str = "",
    search: str = Query("", max_length=64),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    return THREAT_INTEL_MANAGER.consolidated_iocs(
        tier=tier,
        category=category,
        provider=provider,
        freshness=freshness,
        search=search,
        limit=limit,
        offset=offset,
    )


@router.get("/iocs/{ip}")
def get_consolidated_ioc(ip: str) -> dict[str, Any]:
    return THREAT_INTEL_MANAGER.consolidated_ioc(ip)


@router.get("/map")
def threat_intel_map(
    group_by: str = Query("country", pattern="^(country|asn|organization|ip)$"),
    provider: str = "",
    classification: str = "",
    tag: str = "",
    limit: int = Query(500, ge=1, le=2000),
) -> dict[str, Any]:
    items = THREAT_INTEL_MANAGER.map_aggregates(
        group_by=group_by,
        provider=provider,
        classification=classification,
        tag=tag,
        limit=limit,
    )
    return {"group_by": group_by, "items": items}


@router.get("/security-map")
def security_situation_map(
    period: str = Query("24h", pattern="^(15m|30m|1h|6h|24h|7d)$"),
    severity: str = "",
    verdict: str = "",
    attack_type: str = "",
    status: str = "",
    campaign: str = Query("all", pattern="^(with|without|all)$"),
    ai_status: str = Query("all", pattern="^(analyzed|not_analyzed|campaign|all)$"),
    direction: str = Query("all", pattern="^(all|inbound|outbound|internal|external)$"),
    context: str = Query("all", pattern="^(all|external|customer|cgnat|infrastructure)$"),
    target_scope: str = Query("all", pattern="^(all|single|prefix|multi)$"),
    group_by: str = Query("country", pattern="^(country|city|asn|campaign)$"),
    limit: int = Query(200, ge=1, le=1000),
) -> dict[str, Any]:
    from app.services.security_situation_map import build_security_map

    with THREAT_INTEL_MANAGER.connection_factory() as conn:
        return build_security_map(
            conn,
            period=period,
            severity=severity,
            verdict=verdict,
            attack_type=attack_type,
            status=status,
            campaign=campaign,
            ai_status=ai_status,
            direction=direction,
            context=context,
            target_scope=target_scope,
            group_by=group_by,
            limit=limit,
        )


@router.get("/audit")
def sync_audit(provider: str = "", limit: int = Query(100, ge=1, le=1000)) -> dict[str, Any]:
    return {"items": THREAT_INTEL_MANAGER.audit(provider, limit)}


@router.get("/network-contexts")
def list_network_contexts() -> dict[str, Any]:
    with THREAT_INTEL_MANAGER.connection_factory() as conn:
        ensure_threat_intel_schema(conn)
        rows = conn.execute("SELECT * FROM threat_network_contexts ORDER BY name, id").fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["enabled"] = bool(item.get("enabled"))
        item["protected_ranges"] = safe_json(item.pop("protected_ranges_json", "[]"), [])
        items.append(item)
    return {"items": items}


@router.post("/network-contexts")
def create_network_context(payload: NetworkContextPayload) -> dict[str, Any]:
    item = normalized_network_context(payload)
    now = utc_now_iso()
    with THREAT_INTEL_MANAGER.connection_factory() as conn:
        ensure_threat_intel_schema(conn)
        cursor = conn.execute(
            """
            INSERT INTO threat_network_contexts (
                name, sensor_name, exporter_ip, input_if, output_if, context_type,
                protected_ranges_json, enabled, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item["name"], item["sensor_name"], item["exporter_ip"], item["input_if"],
                item["output_if"], item["context_type"], json_dump(item["protected_ranges"]),
                int(item["enabled"]), now, now,
            ),
        )
        conn.commit()
        context_id = int(cursor.lastrowid)
    return {"id": context_id, **item, "created_at": now, "updated_at": now}


@router.put("/network-contexts/{context_id}")
def update_network_context(context_id: int, payload: NetworkContextPayload) -> dict[str, Any]:
    item = normalized_network_context(payload)
    now = utc_now_iso()
    with THREAT_INTEL_MANAGER.connection_factory() as conn:
        ensure_threat_intel_schema(conn)
        cursor = conn.execute(
            """
            UPDATE threat_network_contexts SET
                name=?, sensor_name=?, exporter_ip=?, input_if=?, output_if=?,
                context_type=?, protected_ranges_json=?, enabled=?, updated_at=?
            WHERE id=?
            """,
            (
                item["name"], item["sensor_name"], item["exporter_ip"], item["input_if"],
                item["output_if"], item["context_type"], json_dump(item["protected_ranges"]),
                int(item["enabled"]), now, context_id,
            ),
        )
        if cursor.rowcount != 1:
            raise HTTPException(status_code=404, detail="Contexto de rede nao encontrado")
        conn.commit()
    return {"id": context_id, **item, "updated_at": now}


@router.delete("/network-contexts/{context_id}")
def disable_network_context(context_id: int) -> dict[str, Any]:
    now = utc_now_iso()
    with THREAT_INTEL_MANAGER.connection_factory() as conn:
        ensure_threat_intel_schema(conn)
        cursor = conn.execute(
            "UPDATE threat_network_contexts SET enabled=0, updated_at=? WHERE id=?",
            (now, context_id),
        )
        if cursor.rowcount != 1:
            raise HTTPException(status_code=404, detail="Contexto de rede nao encontrado")
        conn.commit()
    return {"id": context_id, "enabled": False, "updated_at": now}
