from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class GrafanaQueryFilters(BaseModel):
    sensor_ids: list[int] = Field(default_factory=list)
    interfaces: list[int] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    direction: str = "both"


class GrafanaPrefixFilter(BaseModel):
    enabled: bool = True
    cidr: Optional[str] = None
    prefix_id: Optional[Any] = None
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    address_family: str = "both"
    match_side: str = "either"
    direction: Optional[str] = None
    temporary: bool = False


class GrafanaPrefixGrouping(BaseModel):
    enabled: bool = False
    ipv4_prefix_length: int = Field(24, ge=0, le=32)
    ipv6_prefix_length: int = Field(64, ge=0, le=128)
    side: str = "destination"
    mode: str = "top_n"
    top_n: int = Field(10, ge=1, le=50)
    include_empty: bool = False


class GrafanaTimeseriesQuery(BaseModel):
    metric: str
    from_time: str = Field(alias="from")
    to_time: str = Field(alias="to")
    interval_ms: int = Field(60000, ge=1000, le=3600000)
    max_data_points: int = Field(300, ge=1, le=5000)
    filters: GrafanaQueryFilters = Field(default_factory=GrafanaQueryFilters)
    prefix_filter: GrafanaPrefixFilter = Field(
        default_factory=GrafanaPrefixFilter
    )
    prefix_grouping: GrafanaPrefixGrouping = Field(
        default_factory=GrafanaPrefixGrouping
    )
    direction: Optional[str] = None
    sensor: Optional[Any] = None
    interface: Optional[Any] = None
    zone: Optional[Any] = None
    group_by: list[str] = Field(default_factory=lambda: ["direction"])
    calculation: str = "rate"
    include_partial_bucket: bool = False
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
                "include_partial_bucket": False,
            }
        }


class GrafanaRankingQuery(BaseModel):
    metric: str
    from_time: str = Field(alias="from")
    to_time: str = Field(alias="to")
    top_n: int = Field(10, ge=1, le=100)
    filters: GrafanaQueryFilters = Field(default_factory=GrafanaQueryFilters)
    prefix_filter: GrafanaPrefixFilter = Field(
        default_factory=GrafanaPrefixFilter
    )
    prefix_grouping: GrafanaPrefixGrouping = Field(
        default_factory=GrafanaPrefixGrouping
    )
    direction: Optional[str] = None
    sensor: Optional[Any] = None
    interface: Optional[Any] = None
    zone: Optional[Any] = None
    protocol: Optional[str] = None
    calculation: str = "last_not_null"
    timezone: str = "UTC"
    format: str = "json"

    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "metric": "top_ports",
                "from": "2026-07-28T10:00:00Z",
                "to": "2026-07-28T10:10:00Z",
                "top_n": 10,
                "direction": "both",
                "sensor": 2,
                "interface": 17,
                "protocol": "udp",
                "calculation": "rate",
            }
        }


class GrafanaTableQuery(BaseModel):
    metric: str
    from_time: str = Field(alias="from")
    to_time: str = Field(alias="to")
    limit: int = Field(100, ge=1, le=1000)
    top_n: Optional[int] = Field(None, ge=1, le=100)
    filters: GrafanaQueryFilters = Field(default_factory=GrafanaQueryFilters)
    prefix_filter: GrafanaPrefixFilter = Field(
        default_factory=GrafanaPrefixFilter
    )
    prefix_grouping: GrafanaPrefixGrouping = Field(
        default_factory=GrafanaPrefixGrouping
    )
    direction: Optional[str] = None
    sensor: Optional[Any] = None
    interface: Optional[Any] = None
    zone: Optional[Any] = None
    protocol: Optional[str] = None
    calculation: str = "last_not_null"
    timezone: str = "UTC"

    class Config:
        allow_population_by_field_name = True


class GrafanaHealthResponse(BaseModel):
    status: str
    service: str
    api_version: str
    timestamp: str
    correlation_id: str

    class Config:
        schema_extra = {
            "example": {
                "status": "ok",
                "service": "gmj-flow-grafana-api",
                "api_version": "v1",
                "timestamp": "2026-07-28T10:10:00Z",
                "correlation_id": "grafana-health-01",
            }
        }


class GrafanaTimeseriesPoint(BaseModel):
    timestamp: int
    value: Optional[float]
    partial: bool = False
    bucket_duration_seconds: Optional[float] = None


class GrafanaTimeseriesSeries(BaseModel):
    key: str
    name: str
    labels: dict[str, str]
    points: list[GrafanaTimeseriesPoint]


class GrafanaTimeseriesRow(BaseModel):
    timestamp: int
    series: str
    value: Optional[float]


class GrafanaTimeseriesResponse(BaseModel):
    kind: str
    metric: str
    unit: str
    series: list[GrafanaTimeseriesSeries]
    rows: list[GrafanaTimeseriesRow]
    meta: dict[str, Any]

    class Config:
        schema_extra = {
            "example": {
                "kind": "timeseries",
                "metric": "traffic_bps",
                "unit": "bps",
                "series": [
                    {
                        "key": "download",
                        "name": "Total Download",
                        "labels": {"direction": "download"},
                        "points": [
                            {
                                "timestamp": 1785233340000,
                                "value": 12500000.0,
                                "partial": False,
                                "bucket_duration_seconds": 60.0,
                            }
                        ],
                    }
                ],
                "rows": [
                    {
                        "timestamp": 1785233340000,
                        "series": "Total Download",
                        "value": 12500000.0,
                    }
                ],
                "meta": {
                    "interval_ms": 60000,
                    "partial": False,
                    "include_partial_bucket": False,
                    "timezone": "UTC",
                    "quality": {
                        "data_status": "current",
                        "last_complete_sample_at": "2026-07-28T10:09:00Z",
                    },
                    "correlation_id": "grafana-query-01",
                },
            }
        }


class GrafanaRankingItem(BaseModel):
    rank: int
    key: str
    label: str
    value: float
    bps: float
    pps: float
    percentage: float
    percent: float
    asn: Optional[int] = None
    asn_name: str = ""
    country_code: str = ""
    country_name: str = ""
    protocol: Optional[str] = None
    port: Optional[int] = None
    display_name: Optional[str] = None
    tcp_flags: Optional[str] = None
    packets: int = 0
    metadata: dict[str, Any]


class GrafanaRankingResponse(BaseModel):
    kind: str
    metric: str
    unit: str
    items: list[GrafanaRankingItem]
    total: float
    timestamp: str
    calculation: str
    meta: dict[str, Any]

    class Config:
        schema_extra = {
            "example": {
                "kind": "ranking",
                "metric": "top_download_origins",
                "unit": "bps",
                "items": [
                    {
                        "rank": 1,
                        "key": "AS15169",
                        "label": "AS15169 — Google LLC (US)",
                        "value": 8500000.0,
                        "bps": 8500000.0,
                        "pps": 12500.0,
                        "percentage": 68.0,
                        "percent": 68.0,
                        "asn": 15169,
                        "asn_name": "Google LLC",
                        "country_code": "US",
                        "country_name": "United States",
                        "protocol": None,
                        "port": None,
                        "display_name": None,
                        "tcp_flags": None,
                        "packets": 7500000,
                        "metadata": {
                            "asn": 15169,
                            "as_name": "Google LLC",
                            "country": "US",
                            "entity_kind": "asn",
                        },
                    }
                ],
                "total": 12500000.0,
                "timestamp": "2026-07-28T10:10:00Z",
                "calculation": "last_not_null",
                "meta": {
                    "timezone": "UTC",
                    "correlation_id": "grafana-ranking-01",
                },
            }
        }


class GrafanaTableColumn(BaseModel):
    name: str
    type: str


class GrafanaTableResponse(BaseModel):
    columns: list[GrafanaTableColumn]
    rows: list[list[Any]]
    meta: dict[str, Any]

    class Config:
        schema_extra = {
            "example": {
                "columns": [
                    {"name": "time", "type": "time"},
                    {"name": "series", "type": "string"},
                    {"name": "value", "type": "number"},
                ],
                "rows": [
                    [
                        1785233340000,
                        "Total Download",
                        12500000.0,
                    ]
                ],
                "meta": {
                    "timezone": "UTC",
                    "correlation_id": "grafana-table-01",
                },
            }
        }


class GrafanaPublishRequest(BaseModel):
    grafana_connection_id: str = "grafana-principal"
    folder_uid: str = "gmj-flow"
    datasource_uid: str = "gmj-flow-api"
    overwrite: bool = False
    dry_run: bool = True
