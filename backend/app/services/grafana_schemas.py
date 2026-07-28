from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class GrafanaQueryFilters(BaseModel):
    sensor_ids: list[int] = Field(default_factory=list)
    interfaces: list[int] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    direction: str = "both"


class GrafanaTimeseriesQuery(BaseModel):
    metric: str
    from_time: str = Field(alias="from")
    to_time: str = Field(alias="to")
    interval_ms: int = Field(60000, ge=1000, le=3600000)
    max_data_points: int = Field(1000, ge=1, le=5000)
    filters: GrafanaQueryFilters = Field(default_factory=GrafanaQueryFilters)
    group_by: list[str] = Field(default_factory=lambda: ["direction"])
    calculation: str = "rate"
    timezone: str = "UTC"
    format: str = "json"

    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "metric": "traffic_bps",
                "from": "2026-07-28T10:00:00Z",
                "to": "2026-07-28T10:10:00Z",
                "interval_ms": 60000,
                "max_data_points": 1000,
                "filters": {"direction": "both"},
                "group_by": ["direction"],
                "calculation": "rate",
            }
        }


class GrafanaRankingQuery(BaseModel):
    metric: str
    from_time: str = Field(alias="from")
    to_time: str = Field(alias="to")
    top_n: int = Field(10, ge=1, le=100)
    filters: GrafanaQueryFilters = Field(default_factory=GrafanaQueryFilters)
    calculation: str = "last_not_null"
    timezone: str = "UTC"
    format: str = "json"

    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "metric": "top_download_origins",
                "from": "2026-07-28T10:00:00Z",
                "to": "2026-07-28T10:10:00Z",
                "top_n": 10,
                "filters": {},
                "calculation": "last_not_null",
            }
        }


class GrafanaTableQuery(BaseModel):
    metric: str
    from_time: str = Field(alias="from")
    to_time: str = Field(alias="to")
    limit: int = Field(100, ge=1, le=1000)
    filters: GrafanaQueryFilters = Field(default_factory=GrafanaQueryFilters)
    timezone: str = "UTC"

    class Config:
        allow_population_by_field_name = True


class GrafanaHealthResponse(BaseModel):
    status: str
    service: str
    api_version: str
    timestamp: str
    correlation_id: str


class GrafanaTimeseriesPoint(BaseModel):
    timestamp: int
    value: float


class GrafanaTimeseriesSeries(BaseModel):
    key: str
    name: str
    labels: dict[str, str]
    points: list[GrafanaTimeseriesPoint]


class GrafanaTimeseriesRow(BaseModel):
    timestamp: int
    series: str
    value: float


class GrafanaTimeseriesResponse(BaseModel):
    kind: str
    metric: str
    unit: str
    series: list[GrafanaTimeseriesSeries]
    rows: list[GrafanaTimeseriesRow]
    meta: dict[str, Any]


class GrafanaRankingItem(BaseModel):
    rank: int
    key: str
    label: str
    value: float
    percent: float
    metadata: dict[str, Any]


class GrafanaRankingResponse(BaseModel):
    kind: str
    metric: str
    unit: str
    items: list[GrafanaRankingItem]
    total: float
    calculation: str
    meta: dict[str, Any]


class GrafanaTableColumn(BaseModel):
    name: str
    type: str


class GrafanaTableResponse(BaseModel):
    columns: list[GrafanaTableColumn]
    rows: list[list[Any]]
    meta: dict[str, Any]


class GrafanaPublishRequest(BaseModel):
    grafana_connection_id: str = "grafana-principal"
    folder_uid: str = "gmj-flow"
    datasource_uid: str = "gmj-flow-api"
    overwrite: bool = False
    dry_run: bool = True
