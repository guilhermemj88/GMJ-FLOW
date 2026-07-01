from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.clickhouse import (
    ClickHouseQueryError,
    fetch_interface_series,
    fetch_peak_flows,
    fetch_peak_hunter_interfaces,
    fetch_peak_hunter_sensors,
)
from app.services.peak_hunter import (
    PeakHunterRequest,
    analyze_peak_hunter,
    anomaly_peak_hunter_prefill,
    list_peak_analysis_history,
    save_peak_analysis,
)


router = APIRouter(prefix="/api/peak-hunter", tags=["peak-hunter"])


class PeakHunterPayload(BaseModel):
    sensor: str = ""
    interface_id: int = Field(..., ge=1)
    direction: str = "sends"
    metric: str = "packets_s"
    start_time: datetime | None = None
    end_time: datetime | None = None
    recent_period_minutes: int | None = Field(None, ge=1, le=1440)
    protocol: str | None = None
    threshold: float | None = None
    baseline: float | dict[str, Any] | None = None
    window_seconds: int = Field(5, ge=1, le=10)
    max_peaks: int = Field(5, ge=1, le=50)
    sensitivity: str = "medium"


@router.post("/analyze")
def analyze_peak_hunter_endpoint(payload: PeakHunterPayload) -> dict[str, Any]:
    start_time, end_time = _request_window(payload.start_time, payload.end_time, payload.recent_period_minutes)
    request = PeakHunterRequest(
        sensor=payload.sensor,
        interface_id=payload.interface_id,
        direction=_normalize_direction(payload.direction),
        metric=_normalize_metric(payload.metric),
        start_time=start_time,
        end_time=end_time,
        protocol=payload.protocol,
        threshold=payload.threshold,
        baseline=payload.baseline,
        window_seconds=payload.window_seconds,
        max_peaks=payload.max_peaks,
        sensitivity=payload.sensitivity,
    )

    def save(record: dict[str, Any]) -> None:
        with sqlite3.connect(os.getenv("GMJFLOW_DB_PATH", "/app/data/gmjflow.db")) as conn:
            save_peak_analysis(conn, record)
            conn.commit()

    try:
        return analyze_peak_hunter(request, fetch_interface_series, fetch_peak_flows, save_history=save)
    except ClickHouseQueryError as exc:
        return _analysis_error_response(request, "clickhouse_query_failed", str(exc), exc.query_context)
    except Exception as exc:
        return _analysis_error_response(request, "peak_hunter_analyze_failed", str(exc), "analyze_peak_hunter")


@router.get("/options/sensors")
def peak_hunter_sensor_options() -> dict[str, Any]:
    clickhouse_rows = _safe_clickhouse(fetch_peak_hunter_sensors)
    sqlite_rows = _sqlite_sensor_options()
    by_name: dict[str, dict[str, Any]] = {}
    for row in sqlite_rows:
        name = str(row.get("sensor_name") or "").strip()
        if name:
            by_name[name] = row
    for row in clickhouse_rows:
        name = str(row.get("sensor_name") or row.get("sensor") or "").strip()
        if not name:
            continue
        item = by_name.setdefault(
            name,
            {
                "sensor_id": row.get("sensor_id") or name,
                "sensor_name": name,
                "exporter_ip": "",
                "status": "seen",
            },
        )
        item["last_seen"] = _string_time(row.get("last_seen"))
        item["row_count"] = int(row.get("row_count") or item.get("row_count") or 0)
        if not item.get("status"):
            item["status"] = "seen"
    items = sorted(by_name.values(), key=lambda item: (item.get("last_seen") or "", item.get("sensor_name") or ""), reverse=True)
    return {"items": items}


@router.get("/options/interfaces")
def peak_hunter_interface_options(sensor: str = Query("")) -> dict[str, Any]:
    clickhouse_rows = _safe_clickhouse(fetch_peak_hunter_interfaces, sensor)
    sqlite_map = _sqlite_interface_options(sensor)
    items = []
    seen = set()
    for row in clickhouse_rows:
        interface_id = int(row.get("interface_id") or 0)
        if interface_id <= 0:
            continue
        seen.add(interface_id)
        meta = sqlite_map.get(interface_id, {})
        items.append(_interface_option(interface_id, row, meta))
    for interface_id, meta in sqlite_map.items():
        if interface_id not in seen:
            items.append(_interface_option(interface_id, {}, meta))
    items.sort(key=lambda item: int(item.get("interface_id") or 0))
    return {"items": items}


@router.get("/history")
def peak_hunter_history(
    sensor: str = "",
    interface_id: int | None = Query(None, ge=1),
    direction: str = "",
    metric: str = "",
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    evidence_status: str = "",
    classification: str = "",
    limit: int = Query(200, ge=1, le=1000),
) -> dict[str, Any]:
    filters = {
        "sensor": sensor,
        "interface_id": interface_id,
        "direction": direction,
        "metric": metric,
        "start_time": _string_time(_as_utc(start_time)) if start_time else "",
        "end_time": _string_time(_as_utc(end_time)) if end_time else "",
        "evidence_status": evidence_status,
        "classification": classification,
    }
    with _sqlite_connect() as conn:
        items = list_peak_analysis_history(conn, filters, limit=limit)
    return {"items": items}


@router.get("/from-anomaly/{anomaly_id}")
def peak_hunter_from_anomaly(anomaly_id: int) -> dict[str, Any]:
    with _sqlite_connect() as conn:
        row = conn.execute(
            """
            SELECT e.*, s.name AS sensor_name
            FROM anomaly_events e
            LEFT JOIN sensors s ON s.id = e.sensor_id
            WHERE e.id = ?
            """,
            (anomaly_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Anomalia nao encontrada")
    return anomaly_peak_hunter_prefill(dict(row))


def _normalize_direction(value: str) -> str:
    text = str(value or "sends").strip().lower()
    aliases = {"outbound": "sends", "transmits": "sends", "inbound": "receives"}
    normalized = aliases.get(text, text)
    if normalized not in {"sends", "receives"}:
        raise HTTPException(status_code=400, detail="direction invalida")
    return normalized


def _normalize_metric(value: str) -> str:
    text = str(value or "packets_s").strip().lower()
    if text not in {"packets_s", "bits_s"}:
        raise HTTPException(status_code=400, detail="metric invalida")
    return text


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _request_window(
    start_time: datetime | None,
    end_time: datetime | None,
    recent_period_minutes: int | None,
) -> tuple[datetime, datetime]:
    if recent_period_minutes and (start_time is None or end_time is None):
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=recent_period_minutes)
    elif start_time is not None and end_time is not None:
        start = _as_utc(start_time)
        end = _as_utc(end_time)
    else:
        raise HTTPException(status_code=400, detail="Informe start_time/end_time ou periodo recente")
    if start >= end:
        raise HTTPException(status_code=400, detail="start_time deve ser menor que end_time")
    if end - start > timedelta(hours=24):
        raise HTTPException(status_code=400, detail="Periodo maximo permitido: 24h")
    return start, end


def _sqlite_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(os.getenv("GMJFLOW_DB_PATH", "/app/data/gmjflow.db"))
    conn.row_factory = sqlite3.Row
    return conn


def _safe_clickhouse(fetcher: Any, *args: Any) -> list[dict[str, Any]]:
    try:
        rows = fetcher(*args)
    except Exception:
        return []
    return [dict(row) for row in rows]


def _sqlite_sensor_options() -> list[dict[str, Any]]:
    try:
        with _sqlite_connect() as conn:
            rows = conn.execute(
                """
                SELECT id, name, exporter_ip, active, updated_at
                FROM sensors
                ORDER BY active DESC, name
                """
            ).fetchall()
    except sqlite3.Error:
        return []
    return [
        {
            "sensor_id": row["id"],
            "sensor_name": row["name"],
            "exporter_ip": row["exporter_ip"],
            "last_seen": row["updated_at"],
            "status": "active" if row["active"] else "inactive",
        }
        for row in rows
    ]


def _sqlite_interface_options(sensor: str) -> dict[int, dict[str, Any]]:
    try:
        with _sqlite_connect() as conn:
            row = conn.execute(
                """
                SELECT id
                FROM sensors
                WHERE name = ? OR exporter_ip = ? OR CAST(id AS TEXT) = ?
                ORDER BY active DESC, id
                LIMIT 1
                """,
                (sensor, sensor, sensor),
            ).fetchone()
            if row is None:
                return {}
            rows = conn.execute(
                """
                SELECT *
                FROM sensor_interfaces
                WHERE sensor_id = ?
                ORDER BY if_index
                """,
                (row["id"],),
            ).fetchall()
    except sqlite3.Error:
        return {}
    return {int(row["if_index"]): dict(row) for row in rows if int(row["if_index"] or 0) > 0}


def _interface_option(interface_id: int, row: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    if_name = str(meta.get("if_name") or "").strip()
    if_descr = str(meta.get("if_descr") or "").strip()
    if_alias = str(meta.get("if_alias") or "").strip()
    details = " - ".join(part for part in (if_name, if_descr, if_alias) if part)
    label = f"{interface_id} - {details}" if details else f"ifIndex {interface_id}"
    return {
        "interface_id": interface_id,
        "ifIndex": interface_id,
        "ifName": if_name,
        "ifDescr": if_descr,
        "ifAlias": if_alias,
        "direction_hints": meta.get("direction") or "",
        "last_seen": _string_time(row.get("last_seen")),
        "rx_last": int(row.get("rx_packets") or 0),
        "tx_last": int(row.get("tx_packets") or 0),
        "rx_bytes": int(row.get("rx_bytes") or 0),
        "tx_bytes": int(row.get("tx_bytes") or 0),
        "label": label,
    }


def _string_time(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    return str(value or "")


def _analysis_error_response(
    request: PeakHunterRequest,
    error: str,
    message: str,
    query_context: str,
) -> dict[str, Any]:
    return {
        "error": error,
        "message": message,
        "query_context": query_context,
        "peaks_detected": 0,
        "peaks_analyzed": 0,
        "series": [],
        "series_points": 0,
        "series_returned_points": 0,
        "series_downsampled": False,
        "baseline": {"p95": 0.0, "p99": 0.0},
        "threshold_used": float(request.threshold or 0),
        "best_peak": None,
        "evidence_window_used": None,
        "evidence_windows_tried": [],
        "dominant_group": None,
        "classification": "insufficient_flow_evidence",
        "top_groups": [],
        "top_conversations": [],
        "top_sources": [],
        "top_destinations": [],
        "candidates": [],
        "mitigation_allowed": False,
        "recommendation": {
            "recommended_action": "alert_only",
            "reason": f"Falha ao consultar ClickHouse: {message}",
        },
        "error_message": message,
    }
