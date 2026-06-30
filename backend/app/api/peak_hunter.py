from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.clickhouse import fetch_interface_series, fetch_peak_flows
from app.services.peak_hunter import PeakHunterRequest, analyze_peak_hunter, save_peak_analysis


router = APIRouter(prefix="/api/peak-hunter", tags=["peak-hunter"])


class PeakHunterPayload(BaseModel):
    sensor: str = ""
    interface_id: int = Field(..., ge=1)
    direction: str = "sends"
    metric: str = "packets_s"
    start_time: datetime
    end_time: datetime
    protocol: str | None = None
    threshold: float | None = None
    baseline: float | dict[str, Any] | None = None
    window_seconds: int = Field(5, ge=1, le=10)
    max_peaks: int = Field(5, ge=1, le=50)


@router.post("/analyze")
def analyze_peak_hunter_endpoint(payload: PeakHunterPayload) -> dict[str, Any]:
    request = PeakHunterRequest(
        sensor=payload.sensor,
        interface_id=payload.interface_id,
        direction=_normalize_direction(payload.direction),
        metric=_normalize_metric(payload.metric),
        start_time=_as_utc(payload.start_time),
        end_time=_as_utc(payload.end_time),
        protocol=payload.protocol,
        threshold=payload.threshold,
        baseline=payload.baseline,
        window_seconds=payload.window_seconds,
        max_peaks=payload.max_peaks,
    )

    def save(record: dict[str, Any]) -> None:
        with sqlite3.connect(os.getenv("GMJFLOW_DB_PATH", "/app/data/gmjflow.db")) as conn:
            save_peak_analysis(conn, record)
            conn.commit()

    return analyze_peak_hunter(request, fetch_interface_series, fetch_peak_flows, save_history=save)


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
