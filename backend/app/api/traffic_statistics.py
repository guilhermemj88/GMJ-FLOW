"""Shares the Threat Intelligence authentication/RBAC prefix."""

from typing import Any, Literal
import logging
import time

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.traffic_statistics import Scope, get_service, window_seconds

router = APIRouter(
    prefix="/api/threat-intelligence/statistics", tags=["threat-statistics"]
)
LOGGER = logging.getLogger("gmj-flow.statistics")


class EntropyResult(BaseModel):
    field: str
    weight_mode: Literal["PACKET_WEIGHTED", "FLOW_WEIGHTED"]
    samples: float = Field(ge=0)
    cardinality: int = Field(ge=0)
    entropy_bits: float | None = Field(ge=0)
    entropy_normalized: float | None = Field(ge=0, le=1)
    hmax: float | None
    distribution_classification: Literal[
        "NO_DATA", "CONCENTRATED", "MIXED", "HIGH_DIVERSITY"
    ]
    baseline_samples: int
    baseline_median: float | None
    baseline_mad: float | None
    delta: float | None
    robust_z: float | None
    regularized_z: float | None
    anomaly_classification: Literal[
        "NO_DATA", "NO_BASELINE", "NORMAL", "MODERATE", "STRONG"
    ]


class KSResult(BaseModel):
    metric: str
    statistic: float | None = Field(ge=0, le=1)
    p_value: float | None = Field(ge=0, le=1)
    current_samples: int
    baseline_samples: int
    classification: Literal[
        "NO_DATA",
        "INSUFFICIENT_SAMPLES",
        "NORMAL",
        "SMALL_SHIFT",
        "RELEVANT_SHIFT",
        "STRONG_SHIFT",
    ]
    p_value_note: str


class BenfordResult(BaseModel):
    metric: str
    applicable: bool
    reason: str | None
    sample_count: int
    excluded_count: int
    orders_of_magnitude: float | None
    magnitude_range: list[float] | None
    observed: list[float] | None
    expected: list[float]
    chi_square: float | None
    p_value: float | None = Field(ge=0, le=1)
    mad: float | None
    classification: (
        Literal["NORMAL_CONFORMITY", "MODERATE_DIVERGENCE", "STRONG_DIVERGENCE"] | None
    )


class SummaryResponse(BaseModel):
    window: dict[str, Any]
    scope: dict[str, Any]
    weight_mode: Literal["PACKET_WEIGHTED", "FLOW_WEIGHTED"]
    entropy: list[EntropyResult]
    ks: list[KSResult]
    benford: list[BenfordResult]
    overall: dict[str, Any]
    baseline: dict[str, Any]
    sampling: dict[str, Any]
    unavailable_fields: list[str]
    query_ms: dict[str, float]
    config: dict[str, Any]
    read_only: Literal[True]


def validate_scope(scope_type, scope_id, sensor, exporter, direction):
    try:
        return Scope(scope_type, scope_id, sensor, exporter, direction)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc


@router.get("/summary", response_model=SummaryResponse)
def summary(
    scopeType: Literal["global", "target", "interface"] = "global",
    scopeId: str = Query("", max_length=128),
    window: Literal["1m", "5m", "15m", "1h"] = "5m",
    weightMode: Literal["PACKET_WEIGHTED", "FLOW_WEIGHTED"] = "PACKET_WEIGHTED",
    sensor: str = Query("", max_length=128),
    exporter: str = Query("", max_length=64),
    direction: Literal["both", "input", "output"] = "both",
):
    scope = validate_scope(scopeType, scopeId, sensor, exporter, direction)
    try:
        return get_service().summary(scope, window, weightMode)
    except Exception as exc:
        LOGGER.exception("Statistics calculation unavailable")
        raise HTTPException(
            503,
            detail="Análise indisponível ou limite de recursos atingido. Tente um escopo menor.",
        ) from exc


class HistoryResponse(BaseModel):
    scope: dict[str, Any]
    window: str
    field: str
    items: list[dict[str, Any]]


@router.get("/history", response_model=HistoryResponse)
def history(
    scopeType: Literal["global", "target", "interface"] = "global",
    scopeId: str = Query("", max_length=128),
    window: Literal["1m", "5m", "15m", "1h"] = "5m",
    weightMode: Literal["PACKET_WEIGHTED", "FLOW_WEIGHTED"] = "PACKET_WEIGHTED",
    sensor: str = Query("", max_length=128),
    exporter: str = Query("", max_length=64),
    direction: Literal["both", "input", "output"] = "both",
    field: Literal[
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "tcp_flags",
        "src_asn",
        "src_country",
        "input_interface",
        "output_interface",
    ] = "src_ip",
    hours: int = Query(24, ge=1, le=168),
):
    scope = validate_scope(scopeType, scopeId, sensor, exporter, direction)
    end = int(time.time())
    try:
        rows = get_service().store.history(
            scope,
            window_seconds(window),
            weightMode,
            end - hours * 3600,
            end,
            compact=True,
        )
        items = [
            dict(timestamp=row["window"]["to"], **value)
            for row in rows
            for value in row["entropy"]
            if value["field"] == field
        ]
        return dict(
            scope=rows[-1]["scope"] if rows else {"type": scope.type, "id": scope.id},
            window=window,
            field=field,
            items=items,
        )
    except Exception as exc:
        LOGGER.exception("Statistics history unavailable")
        raise HTTPException(503, detail="Histórico estatístico indisponível.") from exc
