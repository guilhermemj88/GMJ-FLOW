from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import sqlite3
import threading
from datetime import datetime, timezone
from ipaddress import ip_network
from typing import Any

from .dashboard_layout import (
    layout_signature,
    normalize_grid_item,
    repair_dashboard_layout,
    resolve_collisions,
    validate_layout,
)
from .dashboard_visualizations import (
    CALCULATIONS,
    COMPACT_MODES,
    LAYOUT_MODES,
    TIMESERIES_VISUALIZATIONS,
    TRAFFIC_ORIENTATIONS,
    data_kind_for_widget,
    normalize_visualization_config,
    visualization_choices,
)


DASHBOARD_SCHEMA_VERSION = 2
DASHBOARD_EXPORT_VERSION = 1
DASHBOARD_GRID_COLUMNS = 12
COLLAPSED_GRID_HEIGHT = 2
MAX_WIDGET_LIMIT = 100
MAX_DASHBOARD_WIDGETS = 80
ALLOWED_REFRESH_INTERVALS = {0, 5, 10, 15, 30, 60, 120, 300}
COMPARISON_MODES = {
    "none",
    "previous_period",
    "yesterday_same_time",
    "last_week_same_time",
}
ALLOWED_RESOLUTIONS = {0, 1, 5, 10, 30, 60, 300, 900, 3600}
DEFAULT_WIDGET_APPEARANCE = {
    "palette_mode": "default",
    "upload_color": "#2563eb",
    "download_color": "#16a34a",
    "line_width": 2,
    "area_opacity": 0.22,
    "smooth_lines": True,
    "show_area": True,
    "show_point_labels": False,
    "show_value_labels": False,
    "show_legend": True,
    "legend_position": "top",
    "axis_label_density": "auto",
    "bar_color": "#0f766e",
    "positive_color": "#16a34a",
    "negative_color": "#dc2626",
    "minimum_slice_label_percent": 3,
}
DIRECTION_SERIES_ORDER = ("upload", "download")
STATUS_SOURCES = {
    "anomalies",
    "alerts",
    "sensors",
    "interfaces",
    "collectors",
    "clickhouse",
    "exabgp",
    "bgp",
    "mitigations",
    "ingestion",
    "resources",
}

WIDGET_TYPES = {"top_n", "timeseries", "kpi", "status_list", "recent_events"}
WIDGET_CATEGORIES = {"traffic", "security", "operation"}
TOP_DIMENSIONS = {
    "src_ip",
    "dst_ip",
    "src_prefix",
    "dst_prefix",
    "src_asn",
    "dst_asn",
    "src_port",
    "dst_port",
    "protocol",
    "tcp_flags",
    "input_if",
    "output_if",
    "sensor",
    "country",
    "conversation",
    "zone",
    "subscriber",
}
DIMENSION_ALIASES = {
    "input_interface": "input_if",
    "output_interface": "output_if",
}
METRICS = {
    "bps",
    "bytes",
    "pps",
    "packets",
    "fps",
    "flows",
    "duration",
    "percentage",
}
METRIC_ALIASES = {
    "bits_per_second": "bps",
    "packets_per_second": "pps",
    "flows_per_second": "fps",
}
DIRECTIONS = {
    "both",
    "input",
    "output",
    "upload",
    "download",
    "source",
    "destination",
    "transmits",
    "receives",
}
DIRECTION_ALIASES = {
    "ingress": "download",
    "egress": "upload",
    "involving_zone": "both",
    "originated_from_zone": "transmits",
    "destined_to_zone": "receives",
}
TIME_GROUPS = {
    "total",
    "protocol",
    "sensor",
    "interface",
    "src_asn",
    "dst_asn",
    "zone",
    "asn",
}
AGGREGATIONS = {"sum", "avg", "max", "min", "p95"}
VISUALIZATIONS = {
    "table",
    "bar",
    "vertical_bar",
    "horizontal_bar",
    "line",
    "area",
    "line_area",
    "time_bars",
    "stacked_area",
    "donut",
    "pie",
    "number",
    "stat",
    "bar_gauge",
    "chart_table",
    "status",
}
FILTER_FIELDS = {
    "protocol",
    "src_port",
    "dst_port",
    "port",
    "src_ip",
    "dst_ip",
    "ip",
    "src_prefix",
    "dst_prefix",
    "prefix",
    "src_asn",
    "dst_asn",
    "asn",
    "country",
    "tcp_flags",
    "sensor",
    "input_if",
    "output_if",
    "interface",
    "zone",
    "subscriber",
    "ip_version",
    "addressing_mode",
    "exclude_internal",
    "exclude_whitelist",
}
FILTER_FIELD_ALIASES = {
    "input_interface": "input_if",
    "output_interface": "output_if",
}
FILTER_OPERATORS = {
    "eq",
    "neq",
    "in",
    "not_in",
    "gt",
    "gte",
    "lt",
    "lte",
    "contains",
    "not_contains",
    "exists",
    "not_exists",
    "prefix_contains",
    "prefix_not_contains",
    "between",
}
VISUALIZATION_ALIASES = {
    "vertical_bar": "bar",
}
INHERITANCE_FIELDS = {"range", "sensor", "interface", "zone", "direction"}
logger = logging.getLogger("gmj-flow.dashboard-layout")

DIMENSION_PLANS = {
    "src_ip": {"expression": "toString(src_ip)", "columns": ["src_ip"], "aggregate": "src_ip"},
    "dst_ip": {"expression": "toString(dst_ip)", "columns": ["dst_ip"], "aggregate": "dst_ip"},
    "src_prefix": {
        "expression": "concat(toString(IPv6CIDRToRange(src_ip, 64).1), '/64')",
        "columns": ["src_ip"],
        "aggregate": "src_ip",
    },
    "dst_prefix": {
        "expression": "concat(toString(IPv6CIDRToRange(dst_ip, 64).1), '/64')",
        "columns": ["dst_ip"],
        "aggregate": "dst_ip",
    },
    "src_asn": {"expression": "toString(src_asn)", "columns": ["src_asn"], "aggregate": "asn_src"},
    "dst_asn": {"expression": "toString(dst_asn)", "columns": ["dst_asn"], "aggregate": "asn_dst"},
    "src_port": {"expression": "toString(src_port)", "columns": ["src_port"], "aggregate": None},
    "dst_port": {"expression": "toString(dst_port)", "columns": ["dst_port"], "aggregate": "dst_port"},
    "protocol": {"expression": "toString(proto)", "columns": ["proto"], "aggregate": "protocol"},
    "tcp_flags": {"expression": "toString(tcp_flags)", "columns": ["tcp_flags"], "aggregate": "tcp_flags"},
    "input_if": {"expression": "toString(input_if)", "columns": [], "aggregate": "series"},
    "output_if": {"expression": "toString(output_if)", "columns": [], "aggregate": "series"},
    "sensor": {"expression": "sensor", "columns": [], "aggregate": "series"},
    "conversation": {
        "expression": (
            "concat(toString(src_ip), ':', toString(src_port), ' -> ', "
            "toString(dst_ip), ':', toString(dst_port), '/', toString(proto))"
        ),
        "columns": ["src_ip", "dst_ip", "src_port", "dst_port", "proto"],
        "aggregate": "conversations",
    },
    # Country, zone and subscriber require enrichment/resolution before ClickHouse.
    "country": {"expression": "", "columns": ["src_ip", "dst_ip"], "aggregate": None, "resolver": "geoip"},
    "zone": {"expression": "", "columns": ["src_ip", "dst_ip"], "aggregate": None, "resolver": "zone"},
    "subscriber": {
        "expression": "",
        "columns": ["src_ip", "dst_ip", "src_port", "dst_port", "proto"],
        "aggregate": None,
        "resolver": "subscriber",
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _json_loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return copy.deepcopy(default)
    if isinstance(value, (dict, list)):
        return copy.deepcopy(value)
    try:
        loaded = json.loads(str(value))
    except (TypeError, ValueError):
        return copy.deepcopy(default)
    return loaded


def _bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _bounded_float(
    value: Any,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = float(default)
    return max(minimum, min(maximum, number))


def _appearance_color(value: Any, default: str) -> str:
    color = str(value or "").strip().lower()
    return color if re.fullmatch(r"#[0-9a-f]{6}", color) else default


def normalize_widget_appearance(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    defaults = DEFAULT_WIDGET_APPEARANCE
    palette_mode = (
        "custom"
        if str(source.get("palette_mode") or "").strip().lower() == "custom"
        else "default"
    )
    custom = palette_mode == "custom"

    def color(field: str) -> str:
        return (
            _appearance_color(source.get(field), defaults[field])
            if custom
            else defaults[field]
        )

    legend_position = str(
        source.get("legend_position") or defaults["legend_position"]
    ).strip().lower()
    if legend_position not in {"top", "bottom", "right"}:
        legend_position = defaults["legend_position"]
    axis_label_density = str(
        source.get("axis_label_density") or defaults["axis_label_density"]
    ).strip().lower()
    if axis_label_density not in {"auto", "sparse", "normal", "dense"}:
        axis_label_density = defaults["axis_label_density"]
    show_point_labels = _bool(
        source.get(
            "show_point_labels",
            source.get(
                "show_value_labels",
                defaults["show_point_labels"],
            ),
        )
    )
    show_value_labels = _bool(
        source.get(
            "show_value_labels",
            source.get(
                "show_point_labels",
                defaults["show_value_labels"],
            ),
        )
    )
    return {
        "palette_mode": palette_mode,
        "upload_color": color("upload_color"),
        "download_color": color("download_color"),
        "line_width": _bounded_float(
            source.get("line_width"),
            defaults["line_width"],
            1,
            5,
        ),
        "area_opacity": _bounded_float(
            source.get("area_opacity"),
            defaults["area_opacity"],
            0,
            1,
        ),
        "smooth_lines": _bool(
            source.get("smooth_lines", defaults["smooth_lines"])
        ),
        "show_area": _bool(source.get("show_area", defaults["show_area"])),
        "show_point_labels": show_point_labels,
        "show_value_labels": show_value_labels,
        "show_legend": _bool(
            source.get("show_legend", defaults["show_legend"])
        ),
        "legend_position": legend_position,
        "axis_label_density": axis_label_density,
        "bar_color": color("bar_color"),
        "positive_color": color("positive_color"),
        "negative_color": color("negative_color"),
        "minimum_slice_label_percent": _bounded_float(
            source.get("minimum_slice_label_percent"),
            defaults["minimum_slice_label_percent"],
            0,
            100,
        ),
    }


def normalize_widget_responsive_breakpoints(value: Any) -> dict[str, int]:
    source = value if isinstance(value, dict) else {}
    stacked = int(
        _bounded_float(source.get("stacked"), 600, 320, 1200)
    )
    wide = int(
        _bounded_float(source.get("wide"), 900, stacked + 100, 1800)
    )
    tiny = int(
        _bounded_float(source.get("tiny"), 420, 240, stacked - 1)
    )
    return {
        "stacked": stacked,
        "wide": wide,
        "tiny": tiny,
    }


def canonical_dashboard_metric(metric: Any) -> str:
    normalized = str(metric or "").strip().lower()
    if normalized in {"bps", "bits_s", "bits_per_second"}:
        return "bits_s"
    if normalized in {"pps", "packets_s", "packets_per_second"}:
        return "packets_s"
    return normalized or "count"


def consolidate_direction_series(
    metric: Any,
    series: Any,
    requested_direction: str = "both",
) -> list[dict[str, Any]]:
    direction = str(requested_direction or "both").strip().lower()
    requested = (
        (direction,)
        if direction in DIRECTION_SERIES_ORDER
        else DIRECTION_SERIES_ORDER
    )
    points_by_direction: dict[str, dict[str, dict[str, Any]]] = {
        current: {} for current in requested
    }
    for item in series if isinstance(series, list) else []:
        if not isinstance(item, dict):
            continue
        item_direction = str(
            item.get("direction") or item.get("key") or ""
        ).strip().lower()
        if item_direction not in points_by_direction:
            continue
        target = points_by_direction[item_direction]
        item_points: dict[str, dict[str, Any]] = {}
        for point in item.get("points") if isinstance(item.get("points"), list) else []:
            if not isinstance(point, dict):
                continue
            timestamp = str(
                point.get("ts")
                or point.get("time")
                or point.get("timestamp")
                or ""
            ).strip()
            if not timestamp:
                continue
            raw_value = point.get("value")
            try:
                value = float(raw_value) if raw_value is not None else None
            except (TypeError, ValueError):
                value = None
            item_points[timestamp] = {
                "value": value,
                "partial": bool(point.get("partial")),
                "bucket_duration_seconds": point.get(
                    "bucket_duration_seconds"
                ),
            }
        for timestamp, point in item_points.items():
            current = target.setdefault(
                timestamp,
                {
                    "values": [],
                    "partial": False,
                    "bucket_duration_seconds": None,
                },
            )
            if point["value"] is not None:
                current["values"].append(point["value"])
            current["partial"] = current["partial"] or point["partial"]
            current["bucket_duration_seconds"] = (
                point["bucket_duration_seconds"]
                or current["bucket_duration_seconds"]
            )
    canonical_metric = canonical_dashboard_metric(metric)
    return [
        {
            "key": current,
            "name": (
                "Total Upload"
                if current == "upload"
                else "Total Download"
            ),
            "direction": current,
            "metric": canonical_metric,
            "color": (
                DEFAULT_WIDGET_APPEARANCE["upload_color"]
                if current == "upload"
                else DEFAULT_WIDGET_APPEARANCE["download_color"]
            ),
            "points": [
                {
                    "ts": timestamp,
                    "value": (
                        round(sum(point["values"]), 2)
                        if point["values"]
                        else None
                    ),
                    "partial": point["partial"],
                    "bucket_duration_seconds": point[
                        "bucket_duration_seconds"
                    ],
                }
                for timestamp, point in sorted(
                    points_by_direction[current].items()
                )
            ],
        }
        for current in requested
    ]


def _ensure_column(conn: sqlite3.Connection, table: str, name: str, ddl: str) -> None:
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(%s)" % table).fetchall()}
    if name not in columns:
        conn.execute("ALTER TABLE %s ADD COLUMN %s" % (table, ddl))


def _contains_sql_escape(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in {"sql", "raw_sql", "query", "query_sql", "where_sql"}:
                return True
            if _contains_sql_escape(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_sql_escape(item) for item in value)
    return False


def _default_widget(
    key: str,
    title: str,
    widget_type: str,
    category: str,
    config: dict[str, Any],
    x: int,
    y: int,
    width: int,
    height: int,
) -> dict[str, Any]:
    return {
        "widget_key": key,
        "title": title,
        "description": "",
        "type": widget_type,
        "category": category,
        "config": {
            **config,
            "appearance": copy.deepcopy(DEFAULT_WIDGET_APPEARANCE),
        },
        "filters": [],
        "visualization": {"type": config.get("visualization", "table"), "show_legend": True},
        "grid": {"x": x, "y": y, "w": width, "h": height},
        "collapsed": False,
        "hidden": False,
        "height_mode": "fixed",
        "refresh_interval_seconds": 30,
        "use_global_filters": True,
        "use_global_time_range": True,
        "custom_time_range": {},
    }


GENERAL_WIDGETS = [
    _default_widget(
        "traffic-bps",
        "Bits/s",
        "timeseries",
        "traffic",
        {"metric": "bps", "direction": "both", "group_by": "total", "aggregation": "sum", "visualization": "area"},
        0,
        0,
        6,
        8,
    ),
    _default_widget(
        "traffic-pps",
        "Pacotes/s",
        "timeseries",
        "traffic",
        {"metric": "pps", "direction": "both", "group_by": "total", "aggregation": "sum", "visualization": "area"},
        6,
        0,
        6,
        8,
    ),
    _default_widget(
        "top-src-ip",
        "Top IP origem",
        "top_n",
        "traffic",
        {"dimension": "src_ip", "metric": "bps", "direction": "source", "limit": 10, "visualization": "horizontal_bar"},
        0,
        8,
        4,
        6,
    ),
    _default_widget(
        "top-dst-ip",
        "Top IP destino",
        "top_n",
        "traffic",
        {"dimension": "dst_ip", "metric": "bps", "direction": "destination", "limit": 10, "visualization": "horizontal_bar"},
        4,
        8,
        4,
        6,
    ),
    _default_widget(
        "top-ports",
        "Top portas",
        "top_n",
        "traffic",
        {"dimension": "dst_port", "metric": "bps", "direction": "both", "limit": 10, "visualization": "bar"},
        8,
        8,
        4,
        6,
    ),
    _default_widget(
        "top-protocols",
        "Protocolos",
        "top_n",
        "traffic",
        {"dimension": "protocol", "metric": "bps", "direction": "both", "limit": 10, "visualization": "donut"},
        0,
        14,
        4,
        6,
    ),
    _default_widget(
        "top-flags",
        "TCP flags",
        "top_n",
        "security",
        {"dimension": "tcp_flags", "metric": "flows", "direction": "both", "limit": 10, "visualization": "bar"},
        4,
        14,
        4,
        6,
    ),
    dict(
        _default_widget(
            "top-syn-src",
            "Top SYN origem",
            "top_n",
            "security",
            {"dimension": "src_ip", "metric": "pps", "direction": "both", "limit": 10, "visualization": "table"},
            0,
            35,
            4,
            7,
        ),
        filters=[
            {"field": "protocol", "operator": "eq", "value": "tcp"},
            {"field": "tcp_flags", "operator": "eq", "value": "SYN"},
        ],
    ),
    dict(
        _default_widget(
            "top-syn-dst",
            "Top SYN destino",
            "top_n",
            "security",
            {"dimension": "dst_ip", "metric": "pps", "direction": "both", "limit": 10, "visualization": "table"},
            4,
            35,
            4,
            7,
        ),
        filters=[
            {"field": "protocol", "operator": "eq", "value": "tcp"},
            {"field": "tcp_flags", "operator": "eq", "value": "SYN"},
        ],
    ),
    _default_widget(
        "top-conversations",
        "Maiores conversas",
        "top_n",
        "traffic",
        {"dimension": "conversation", "metric": "bps", "direction": "both", "limit": 10, "visualization": "table"},
        0,
        20,
        6,
        8,
    ),
    _default_widget(
        "top-asn-src",
        "Destinos do upload",
        "top_n",
        "traffic",
        {"dimension": "dst_asn", "metric": "bps", "direction": "upload", "limit": 10, "visualization": "chart_table", "combined_chart_kind": "donut", "slice_limit": 8, "chart_table_ratio": 55},
        0,
        28,
        6,
        7,
    ),
    _default_widget(
        "top-asn-dst",
        "Origens do download",
        "top_n",
        "traffic",
        {"dimension": "src_asn", "metric": "bps", "direction": "download", "limit": 10, "visualization": "chart_table", "combined_chart_kind": "donut", "slice_limit": 8, "chart_table_ratio": 55},
        6,
        28,
        6,
        7,
    ),
    _default_widget(
        "recent-anomalies",
        "Anomalias recentes",
        "recent_events",
        "security",
        {"source": "anomalies", "limit": 10, "visualization": "table"},
        0,
        42,
        12,
        7,
    ),
]

SYSTEM_TEMPLATES = (
    {"key": "general", "name": "Visão Geral", "description": "Tráfego, conversas, segurança e operação.", "widgets": GENERAL_WIDGETS},
    {
        "key": "noc",
        "name": "NOC",
        "description": "Capacidade, interfaces e sensores.",
        "widgets": [GENERAL_WIDGETS[index] for index in (0, 1, 2, 3, 4, 5)],
    },
    {
        "key": "security",
        "name": "Segurança",
        "description": "Protocolos, flags, conversas e eventos de segurança.",
        "widgets": [GENERAL_WIDGETS[index] for index in (5, 6, 7, 8, 9, 12)],
    },
    {
        "key": "dns",
        "name": "DNS",
        "description": "Visão inicial de DNS, personalizável por filtros.",
        "widgets": [
            dict(
                copy.deepcopy(GENERAL_WIDGETS[4]),
                widget_key="dns-destinations",
                title="Top destinos DNS",
                filters=[{"field": "protocol", "operator": "eq", "value": "udp"}, {"field": "dst_port", "operator": "eq", "value": 53}],
            )
        ],
    },
    {
        "key": "bgp",
        "name": "BGP",
        "description": "Visão de tráfego por ASN e prefixos.",
        "widgets": [GENERAL_WIDGETS[index] for index in (0, 10, 11)],
    },
    {
        "key": "cgnat",
        "name": "CGNAT",
        "description": "Visão de assinantes e endereçamento compartilhado.",
        "widgets": [
            _default_widget(
                "top-subscribers",
                "Top assinantes",
                "top_n",
                "operation",
                {"dimension": "subscriber", "metric": "bps", "direction": "both", "limit": 10, "visualization": "table"},
                0,
                0,
                12,
                5,
            )
        ],
    },
    {
        "key": "ipv6",
        "name": "IPv6",
        "description": "Visão de tráfego IPv6.",
        "widgets": [
            dict(
                copy.deepcopy(GENERAL_WIDGETS[2]),
                widget_key="ipv6-sources",
                title="Top origens IPv6",
                filters=[{"field": "ip_version", "operator": "eq", "value": 6}],
            ),
            dict(
                copy.deepcopy(GENERAL_WIDGETS[3]),
                widget_key="ipv6-destinations",
                title="Top destinos IPv6",
                filters=[{"field": "ip_version", "operator": "eq", "value": 6}],
            ),
        ],
    },
)

WIDGET_PRESETS = (
    {"id": "timeseries", "category": "traffic", "label": "Série temporal", "type": "timeseries", "config": {"metric": "bps", "direction": "both", "group_by": "total", "aggregation": "sum", "visualization": "area"}},
    {"id": "top-n", "category": "traffic", "label": "Top N", "type": "top_n", "config": {"dimension": "src_ip", "metric": "bps", "direction": "both", "limit": 10, "visualization": "table"}},
    {"id": "top-upload-destinations", "category": "traffic", "label": "Destinos do upload", "type": "top_n", "config": {"dimension": "dst_asn", "metric": "bps", "direction": "upload", "limit": 10, "visualization": "chart_table", "combined_chart_kind": "donut", "slice_limit": 8, "chart_table_ratio": 55}},
    {"id": "top-download-origins", "category": "traffic", "label": "Origens do download", "type": "top_n", "config": {"dimension": "src_asn", "metric": "bps", "direction": "download", "limit": 10, "visualization": "chart_table", "combined_chart_kind": "donut", "slice_limit": 8, "chart_table_ratio": 55}},
    {"id": "top-download-destinations", "category": "traffic", "label": "Destinos do download", "type": "top_n", "config": {"dimension": "dst_asn", "metric": "bps", "direction": "download", "limit": 10, "visualization": "chart_table", "combined_chart_kind": "donut", "slice_limit": 8, "chart_table_ratio": 55}},
    {"id": "top-upload-origins", "category": "traffic", "label": "Origens do upload", "type": "top_n", "config": {"dimension": "src_asn", "metric": "bps", "direction": "upload", "limit": 10, "visualization": "chart_table", "combined_chart_kind": "donut", "slice_limit": 8, "chart_table_ratio": 55}},
    {"id": "conversations", "category": "traffic", "label": "Top conversas", "type": "top_n", "config": {"dimension": "conversation", "metric": "bps", "direction": "both", "limit": 10, "visualization": "table"}},
    {"id": "protocols", "category": "traffic", "label": "Protocolos", "type": "top_n", "config": {"dimension": "protocol", "metric": "bps", "direction": "both", "limit": 10, "visualization": "donut"}},
    {"id": "tcp-flags", "category": "traffic", "label": "TCP flags", "type": "top_n", "config": {"dimension": "tcp_flags", "metric": "flows", "direction": "both", "limit": 10, "visualization": "bar"}},
    {"id": "interfaces", "category": "traffic", "label": "Interfaces", "type": "top_n", "config": {"dimension": "input_interface", "metric": "bps", "direction": "ingress", "limit": 10, "visualization": "bar"}},
    {"id": "sensors", "category": "traffic", "label": "Sensores", "type": "top_n", "config": {"dimension": "sensor", "metric": "bps", "direction": "both", "limit": 10, "visualization": "bar"}},
    {"id": "syn-source", "category": "security", "label": "Top SYN origem", "type": "top_n", "config": {"dimension": "src_ip", "metric": "pps", "direction": "both", "limit": 10, "visualization": "table"}, "filters": [{"field": "protocol", "operator": "eq", "value": "tcp"}, {"field": "tcp_flags", "operator": "eq", "value": "SYN"}]},
    {"id": "syn-destination", "category": "security", "label": "Top SYN destino", "type": "top_n", "config": {"dimension": "dst_ip", "metric": "pps", "direction": "both", "limit": 10, "visualization": "table"}, "filters": [{"field": "protocol", "operator": "eq", "value": "tcp"}, {"field": "tcp_flags", "operator": "eq", "value": "SYN"}]},
    {"id": "recent-anomalies", "category": "security", "label": "Anomalias recentes", "type": "recent_events", "config": {"source": "anomalies", "limit": 10, "visualization": "table"}},
    {"id": "active-attacks", "category": "security", "label": "Ataques ativos", "type": "recent_events", "config": {"source": "anomalies", "limit": 10, "visualization": "table"}},
    {"id": "active-mitigations", "category": "security", "label": "Mitigações ativas", "type": "recent_events", "config": {"source": "mitigations", "limit": 10, "visualization": "table"}},
    {"id": "mitigated-destinations", "category": "security", "label": "Destinos mitigados", "type": "recent_events", "config": {"source": "mitigations", "limit": 20, "visualization": "table"}},
    {"id": "sensor-status", "category": "operation", "label": "Estado dos sensores", "type": "status_list", "config": {"source": "sensors", "limit": 20, "visualization": "status"}},
    {"id": "collector-status", "category": "operation", "label": "Estado dos coletores", "type": "status_list", "config": {"source": "collectors", "limit": 20, "visualization": "status"}},
    {"id": "clickhouse-status", "category": "operation", "label": "Estado do ClickHouse", "type": "status_list", "config": {"source": "clickhouse", "limit": 10, "visualization": "status"}},
    {"id": "exabgp-status", "category": "operation", "label": "Estado do ExaBGP", "type": "status_list", "config": {"source": "exabgp", "limit": 10, "visualization": "status"}},
    {"id": "bgp-peers", "category": "operation", "label": "Peers BGP", "type": "status_list", "config": {"source": "bgp", "limit": 20, "visualization": "status"}},
    {"id": "ingestion", "category": "operation", "label": "Taxa de ingestão", "type": "kpi", "config": {"metric": "fps", "direction": "both", "visualization": "number"}},
    {"id": "resources", "category": "operation", "label": "Recursos do sistema", "type": "status_list", "config": {"source": "resources", "limit": 10, "visualization": "status"}},
)


def widget_catalog() -> dict[str, Any]:
    return {
        "schema_version": DASHBOARD_SCHEMA_VERSION,
        "types": [
            {"id": "top_n", "label": "Top N", "categories": ["traffic", "security", "operation"]},
            {"id": "timeseries", "label": "Série temporal", "categories": ["traffic", "operation"]},
            {"id": "kpi", "label": "Indicador", "categories": ["traffic", "security", "operation"]},
            {"id": "status_list", "label": "Lista de status", "categories": ["security", "operation"]},
            {"id": "recent_events", "label": "Eventos recentes", "categories": ["security", "operation"]},
        ],
        "categories": sorted(WIDGET_CATEGORIES),
        "dimensions": sorted(TOP_DIMENSIONS | set(DIMENSION_ALIASES)),
        "dimension_aliases": dict(DIMENSION_ALIASES),
        "metrics": sorted(METRICS | set(METRIC_ALIASES)),
        "metric_aliases": dict(METRIC_ALIASES),
        "directions": sorted(DIRECTIONS | set(DIRECTION_ALIASES)),
        "direction_aliases": dict(DIRECTION_ALIASES),
        "group_by": sorted(TIME_GROUPS),
        "aggregations": sorted(AGGREGATIONS),
        "visualizations": sorted(VISUALIZATIONS),
        "visualizations_by_data_kind": {
            data_kind: list(visualization_choices(data_kind))
            for data_kind in (
                "ranking_snapshot",
                "timeseries",
                "stat",
                "status",
                "table",
            )
        },
        "calculations": sorted(CALCULATIONS),
        "traffic_orientations": sorted(TRAFFIC_ORIENTATIONS),
        "layout_modes": sorted(LAYOUT_MODES),
        "compact_modes": sorted(COMPACT_MODES),
        "filter_fields": sorted(FILTER_FIELDS | set(FILTER_FIELD_ALIASES)),
        "filter_operators": sorted(FILTER_OPERATORS),
        "limits": [5, 10, 20, 50, 100],
        "refresh_intervals": sorted(ALLOWED_REFRESH_INTERVALS),
        "comparison_modes": sorted(COMPARISON_MODES),
        "resolutions": sorted(ALLOWED_RESOLUTIONS),
        "status_sources": sorted(STATUS_SOURCES),
        "presets": copy.deepcopy(WIDGET_PRESETS),
    }


def validate_filters(filters: Any) -> list[dict[str, Any]]:
    if filters in (None, ""):
        return []
    if not isinstance(filters, list):
        raise ValueError("filters deve ser uma lista")
    if len(filters) > 30:
        raise ValueError("um widget aceita no máximo 30 filtros")
    normalized = []
    for item in filters:
        if not isinstance(item, dict):
            raise ValueError("filtro inválido")
        field = str(item.get("field") or "").strip().lower()
        operator = str(item.get("operator") or "eq").strip().lower()
        field = FILTER_FIELD_ALIASES.get(field, field)
        if field not in FILTER_FIELDS:
            raise ValueError("campo de filtro não permitido: %s" % field)
        if operator not in FILTER_OPERATORS:
            raise ValueError("operador de filtro não permitido: %s" % operator)
        value = item.get("value")
        values = value if isinstance(value, list) else [value]
        if operator not in {"exists", "not_exists"} and not values:
            raise ValueError("filtro sem valor")
        if operator == "between" and len(values) != 2:
            raise ValueError("operador between exige dois valores")
        if field in {"src_port", "dst_port", "port", "input_if", "output_if", "interface", "src_asn", "dst_asn", "asn"}:
            parsed = []
            for current in values:
                try:
                    number = int(current)
                except (TypeError, ValueError):
                    raise ValueError("valor numérico inválido para %s" % field)
                upper = 65535 if "port" in field else 4294967295
                if number < 0 or number > upper:
                    raise ValueError("valor fora do intervalo para %s" % field)
                parsed.append(number)
            value = parsed if isinstance(value, list) else parsed[0]
        elif field in {"src_ip", "dst_ip", "ip", "src_prefix", "dst_prefix", "prefix"}:
            parsed_ips = []
            for current in values:
                try:
                    parsed_ips.append(str(ip_network(str(current), strict=False)))
                except ValueError:
                    raise ValueError("IP ou prefixo inválido para %s" % field)
            value = parsed_ips if isinstance(value, list) else parsed_ips[0]
        elif field == "ip_version":
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise ValueError("ip_version deve ser 4 ou 6")
            if value not in {4, 6}:
                raise ValueError("ip_version deve ser 4 ou 6")
        elif field == "addressing_mode":
            value = str(value or "").strip().lower()
            if value not in {"direct", "cgnat", "both"}:
                raise ValueError("addressing_mode inválido")
        elif field in {"exclude_internal", "exclude_whitelist"}:
            if isinstance(value, str):
                value = value.strip().lower() in {"1", "true", "yes", "on"}
            else:
                value = bool(value)
        normalized.append({"field": field, "operator": operator, "value": value})
    return normalized


def normalize_grid(grid: Any) -> dict[str, int]:
    value = grid if isinstance(grid, dict) else {}
    normalized = normalize_grid_item(
        {
            "x": value.get("x", 0),
            "y": value.get("y", 0),
            "w": value.get("w", value.get("width", 4)),
            "h": value.get("h", value.get("height", 4)),
        },
        {"columns": DASHBOARD_GRID_COLUMNS, "min_h": 2, "max_h": 12},
    )
    return {
        "x": normalized["x"],
        "y": normalized["y"],
        "w": normalized["w"],
        "h": normalized["h"],
    }


def widget_layout_constraints(widget: dict[str, Any]) -> dict[str, int]:
    widget_type = str(widget.get("type") or "top_n")
    config = widget.get("config") if isinstance(widget.get("config"), dict) else {}
    visualization = (
        widget.get("visualization")
        if isinstance(widget.get("visualization"), dict)
        else {}
    )
    visualization_type = str(
        visualization.get("type")
        or config.get("visualization")
        or "table"
    ).lower()
    if widget_type == "timeseries":
        default_width, default_height, min_width, min_height = 6, 8, 5, 6
    elif widget_type == "top_n" and visualization_type == "chart_table":
        default_width, default_height, min_width, min_height = 8, 8, 6, 6
    elif widget_type == "top_n" and config.get("dimension") == "conversation":
        default_width, default_height, min_width, min_height = 6, 8, 5, 6
    elif widget_type == "top_n" and visualization_type in {
        "pie",
        "donut",
        "horizontal_bar",
        "bar",
    }:
        default_width, default_height, min_width, min_height = 4, 6, 3, 5
    elif widget_type == "top_n":
        default_width, default_height, min_width, min_height = 4, 7, 3, 5
    elif widget_type == "recent_events":
        default_width, default_height, min_width, min_height = 12, 7, 6, 5
    elif widget_type == "status_list":
        default_width, default_height, min_width, min_height = 4, 5, 3, 4
    elif widget_type == "kpi":
        default_width, default_height, min_width, min_height = 3, 3, 2, 2
    else:
        default_width, default_height, min_width, min_height = 4, 5, 3, 4
    if bool(widget.get("collapsed")):
        default_height = COLLAPSED_GRID_HEIGHT
        min_height = COLLAPSED_GRID_HEIGHT
        max_height = COLLAPSED_GRID_HEIGHT
    else:
        max_height = 12
    return {
        "columns": DASHBOARD_GRID_COLUMNS,
        "default_w": default_width,
        "default_h": default_height,
        "min_w": min_width,
        "min_h": min_height,
        "max_w": DASHBOARD_GRID_COLUMNS,
        "max_h": max_height,
    }


def normalize_widget_grid(
    widget: dict[str, Any],
    grid: Any | None = None,
) -> dict[str, int]:
    source = grid if isinstance(grid, dict) else {}
    normalized = normalize_grid_item(
        {
            "x": source.get("x", 0),
            "y": source.get("y", 0),
            "w": source.get("w"),
            "h": source.get("h"),
        },
        widget_layout_constraints(widget),
    )
    return {
        "x": normalized["x"],
        "y": normalized["y"],
        "w": normalized["w"],
        "h": normalized["h"],
    }


def validate_inheritance(value: Any) -> dict[str, dict[str, Any]]:
    source = value if isinstance(value, dict) else {}
    unknown = set(source) - INHERITANCE_FIELDS
    if unknown:
        raise ValueError(
            "herança desconhecida: %s" % ", ".join(sorted(unknown))
        )
    normalized: dict[str, dict[str, Any]] = {}
    for field in sorted(INHERITANCE_FIELDS):
        item = source.get(field, {})
        if isinstance(item, str):
            item = {"mode": item}
        if not isinstance(item, dict):
            raise ValueError("herança inválida para %s" % field)
        mode = str(item.get("mode") or "inherit").strip().lower()
        if mode not in {"inherit", "custom"}:
            raise ValueError("modo de herança inválido para %s" % field)
        custom_value = item.get("value")
        if mode == "custom" and field in {"sensor", "interface", "zone"}:
            try:
                custom_value = int(custom_value)
            except (TypeError, ValueError):
                raise ValueError("valor customizado inválido para %s" % field)
            if custom_value < 1:
                raise ValueError("valor customizado inválido para %s" % field)
        normalized[field] = {
            "mode": mode,
            "value": custom_value if mode == "custom" else None,
        }
    return normalized


def validate_widget_definition(payload: Any, partial: bool = False) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("widget deve ser um objeto")
    if _contains_sql_escape(payload):
        raise ValueError("SQL livre não é permitido em widgets")
    normalized = copy.deepcopy(payload)
    widget_type = str(payload.get("type") or "").strip().lower()
    if not widget_type and partial:
        widget_type = ""
    elif widget_type not in WIDGET_TYPES:
        raise ValueError("tipo de widget inválido")
    category = str(payload.get("category") or "traffic").strip().lower()
    if category not in WIDGET_CATEGORIES:
        raise ValueError("categoria inválida")
    title = str(payload.get("title") or "").strip()
    if not title and not partial:
        raise ValueError("título é obrigatório")
    if len(title) > 160:
        raise ValueError("título excede 160 caracteres")
    config = payload.get("config") or {}
    if not isinstance(config, dict):
        raise ValueError("config deve ser um objeto")
    config["appearance"] = normalize_widget_appearance(
        config.get("appearance")
    )
    if "responsive_breakpoints" in config:
        config["responsive_breakpoints"] = (
            normalize_widget_responsive_breakpoints(
                config.get("responsive_breakpoints")
            )
        )
    comparison_mode = str(
        config.get("comparison_mode") or "none"
    ).strip().lower()
    if comparison_mode not in COMPARISON_MODES:
        raise ValueError("modo de comparação inválido")
    config["comparison_mode"] = comparison_mode
    if widget_type == "top_n":
        dimension = str(config.get("dimension") or "").strip().lower()
        metric = str(config.get("metric") or "").strip().lower()
        direction = str(config.get("direction") or "both").strip().lower()
        dimension = DIMENSION_ALIASES.get(dimension, dimension)
        metric = METRIC_ALIASES.get(metric, metric)
        direction = DIRECTION_ALIASES.get(direction, direction)
        if dimension not in TOP_DIMENSIONS:
            raise ValueError("dimensão inválida")
        if metric not in METRICS:
            raise ValueError("métrica inválida")
        if direction not in DIRECTIONS:
            raise ValueError("direção inválida")
        limit = int(config.get("limit") or 10)
        if limit < 1 or limit > MAX_WIDGET_LIMIT:
            raise ValueError("limit deve estar entre 1 e %s" % MAX_WIDGET_LIMIT)
        combined_chart_kind = str(
            config.get("combined_chart_kind") or "donut"
        ).strip().lower()
        if combined_chart_kind not in {
            "horizontal_bar",
            "pie",
            "donut",
        }:
            combined_chart_kind = "donut"
        config.update(
            {
                "dimension": dimension,
                "metric": metric,
                "direction": direction,
                "limit": limit,
                "combined_chart_kind": combined_chart_kind,
                "slice_limit": max(
                    2,
                    min(20, int(config.get("slice_limit") or 8)),
                ),
                "chart_table_ratio": max(
                    25,
                    min(75, int(config.get("chart_table_ratio") or 55)),
                ),
            }
        )
    elif widget_type in {"timeseries", "kpi"}:
        metric = str(config.get("metric") or "").strip().lower()
        direction = str(config.get("direction") or "both").strip().lower()
        metric = METRIC_ALIASES.get(metric, metric)
        direction = DIRECTION_ALIASES.get(direction, direction)
        if metric not in METRICS:
            raise ValueError("métrica inválida")
        if widget_type == "timeseries" and metric not in {"bps", "pps", "fps"}:
            raise ValueError(
                "série temporal aceita bits/s, pacotes/s ou flows/s"
            )
        if direction not in DIRECTIONS:
            raise ValueError("direção inválida")
        config.update({"metric": metric, "direction": direction})
        if widget_type == "timeseries":
            group_by = str(config.get("group_by") or "total").strip().lower()
            aggregation = str(config.get("aggregation") or "sum").strip().lower()
            if group_by not in TIME_GROUPS:
                raise ValueError("agrupamento inválido")
            if aggregation not in AGGREGATIONS:
                raise ValueError("agregação inválida")
            resolution_seconds = int(config.get("resolution_seconds") or 0)
            if resolution_seconds not in ALLOWED_RESOLUTIONS:
                raise ValueError("resolução inválida")
            config.update(
                {
                    "group_by": group_by,
                    "aggregation": aggregation,
                    "resolution_seconds": resolution_seconds,
                    "include_partial_bucket": _bool(
                        config.get("include_partial_bucket")
                    ),
                }
            )
    elif widget_type in {"status_list", "recent_events"}:
        source = str(config.get("source") or ("anomalies" if widget_type == "recent_events" else "sensors")).strip().lower()
        if source not in STATUS_SOURCES:
            raise ValueError("fonte de status/eventos inválida")
        config["source"] = source
        config["limit"] = max(1, min(MAX_WIDGET_LIMIT, int(config.get("limit") or 10)))
    visualization = payload.get("visualization") or {}
    if isinstance(visualization, str):
        visualization = {"type": visualization}
    if not isinstance(visualization, dict):
        raise ValueError("visualization deve ser um objeto")
    visualization_type = str(
        visualization.get("type") or config.get("visualization") or ("line" if widget_type == "timeseries" else "table")
    ).strip().lower()
    visualization_type = VISUALIZATION_ALIASES.get(
        visualization_type,
        visualization_type,
    )
    if visualization_type not in VISUALIZATIONS:
        raise ValueError("visualização inválida")
    refresh = int(payload.get("refresh_interval_seconds", 30) or 0)
    if refresh not in ALLOWED_REFRESH_INTERVALS:
        raise ValueError("intervalo de atualização inválido")
    collapsed = _bool(payload.get("collapsed"))
    height_mode = str(payload.get("height_mode") or "fixed").strip().lower()
    if height_mode not in {"fixed", "auto"}:
        raise ValueError("height_mode inválido")
    normalized_visualization = dict(
        visualization,
        type=visualization_type,
    )
    config, normalized_visualization = normalize_visualization_config(
        widget_type,
        config,
        normalized_visualization,
    )
    grid = normalize_widget_grid(
        {
            "type": widget_type,
            "config": config,
            "visualization": normalized_visualization,
            "collapsed": collapsed,
        },
        payload.get("grid"),
    )
    use_global_time_range = _bool(payload.get("use_global_time_range", True))
    custom_time_range = (
        payload.get("custom_time_range")
        if (
            not use_global_time_range
            and isinstance(payload.get("custom_time_range"), dict)
        )
        else {}
    )
    normalized.update(
        {
            "title": title,
            "description": str(payload.get("description") or "").strip()[:500],
            "type": widget_type,
            "category": category,
            "config": config,
            "filters": validate_filters(payload.get("filters")),
            "visualization": normalized_visualization,
            "grid": grid,
            "collapsed": collapsed,
            "hidden": _bool(payload.get("hidden")),
            "height_mode": height_mode,
            "refresh_interval_seconds": refresh,
            "use_global_filters": _bool(payload.get("use_global_filters", True)),
            "use_global_time_range": use_global_time_range,
            "inheritance": validate_inheritance(payload.get("inheritance")),
            "custom_time_range": custom_time_range,
        }
    )
    return normalized


def normalize_dashboard_payload(payload: Any, partial: bool = False) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("dashboard deve ser um objeto")
    if _contains_sql_escape(payload):
        raise ValueError("SQL livre não é permitido")
    name = str(payload.get("name") or "").strip()
    if not name and not partial:
        raise ValueError("nome é obrigatório")
    if len(name) > 120:
        raise ValueError("nome excede 120 caracteres")
    refresh = int(payload.get("refresh_interval_seconds", 30) or 0)
    if refresh not in ALLOWED_REFRESH_INTERVALS:
        raise ValueError("intervalo de atualização inválido")
    time_range = (
        copy.deepcopy(payload.get("time_range"))
        if isinstance(payload.get("time_range"), dict)
        else {"mode": "relative", "minutes": 10}
    )
    layout_mode = str(
        payload.get("layout_mode")
        or time_range.get("_layout_mode")
        or "custom"
    ).strip().lower()
    if layout_mode not in LAYOUT_MODES:
        raise ValueError("layout_mode inválido")
    compact_mode = str(
        payload.get("compact_mode")
        or time_range.get("_compact_mode")
        or ("vertical" if layout_mode == "auto_grid" else "none")
    ).strip().lower()
    if compact_mode not in COMPACT_MODES:
        raise ValueError("compact_mode inválido")
    time_range["_layout_mode"] = layout_mode
    time_range["_compact_mode"] = compact_mode
    result = {
        "name": name,
        "description": str(payload.get("description") or "").strip()[:500],
        "is_default": _bool(payload.get("is_default")),
        "is_shared": _bool(payload.get("is_shared")),
        "global_filters": validate_filters(payload.get("global_filters")),
        "time_range": time_range,
        "layout_mode": layout_mode,
        "compact_mode": compact_mode,
        "refresh_interval_seconds": refresh,
    }
    return result


def ensure_dashboard_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dashboards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            owner_user_id INTEGER,
            is_default INTEGER NOT NULL DEFAULT 0,
            is_shared INTEGER NOT NULL DEFAULT 0,
            is_system INTEGER NOT NULL DEFAULT 0,
            template_key TEXT,
            global_filters_json TEXT NOT NULL DEFAULT '[]',
            time_range_json TEXT NOT NULL DEFAULT '{"mode":"relative","minutes":10}',
            refresh_interval_seconds INTEGER NOT NULL DEFAULT 30,
            layout_version INTEGER NOT NULL DEFAULT 1,
            legacy_layout_migrated INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dashboard_widgets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dashboard_id INTEGER NOT NULL,
            widget_key TEXT NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT 'traffic',
            config_json TEXT NOT NULL DEFAULT '{}',
            filters_json TEXT NOT NULL DEFAULT '[]',
            visualization_json TEXT NOT NULL DEFAULT '{}',
            grid_x INTEGER NOT NULL DEFAULT 0,
            grid_y INTEGER NOT NULL DEFAULT 0,
            grid_w INTEGER NOT NULL DEFAULT 4,
            grid_h INTEGER NOT NULL DEFAULT 4,
            expanded_grid_h INTEGER,
            collapsed_grid_h INTEGER NOT NULL DEFAULT 2,
            collapsed INTEGER NOT NULL DEFAULT 0,
            hidden INTEGER NOT NULL DEFAULT 0,
            height_mode TEXT NOT NULL DEFAULT 'fixed',
            refresh_interval_seconds INTEGER NOT NULL DEFAULT 30,
            use_global_filters INTEGER NOT NULL DEFAULT 1,
            use_global_time_range INTEGER NOT NULL DEFAULT 1,
            inheritance_json TEXT NOT NULL DEFAULT '{}',
            custom_time_range_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(dashboard_id) REFERENCES dashboards(id) ON DELETE CASCADE,
            UNIQUE(dashboard_id, widget_key)
        )
        """
    )
    _ensure_column(conn, "dashboards", "layout_version", "layout_version INTEGER NOT NULL DEFAULT 1")
    _ensure_column(conn, "dashboards", "template_key", "template_key TEXT")
    _ensure_column(
        conn,
        "dashboards",
        "legacy_layout_migrated",
        "legacy_layout_migrated INTEGER NOT NULL DEFAULT 0",
    )
    _ensure_column(
        conn,
        "dashboard_widgets",
        "use_global_filters",
        "use_global_filters INTEGER NOT NULL DEFAULT 1",
    )
    _ensure_column(
        conn,
        "dashboard_widgets",
        "inheritance_json",
        "inheritance_json TEXT NOT NULL DEFAULT '{}'",
    )
    _ensure_column(
        conn,
        "dashboard_widgets",
        "expanded_grid_h",
        "expanded_grid_h INTEGER",
    )
    _ensure_column(
        conn,
        "dashboard_widgets",
        "collapsed_grid_h",
        "collapsed_grid_h INTEGER NOT NULL DEFAULT 2",
    )
    _ensure_column(
        conn,
        "dashboard_widgets",
        "height_mode",
        "height_mode TEXT NOT NULL DEFAULT 'fixed'",
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboards_owner ON dashboards(owner_user_id, is_default)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboards_visible ON dashboards(is_system, is_shared)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboards_updated ON dashboards(updated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_widgets_layout ON dashboard_widgets(dashboard_id, grid_y, grid_x)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_widgets_updated ON dashboard_widgets(updated_at)")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboards_template_key ON dashboards(template_key) WHERE template_key IS NOT NULL"
    )
    conn.execute(
        """
        UPDATE dashboard_widgets
        SET custom_time_range_json = '{}'
        WHERE use_global_time_range = 1
          AND custom_time_range_json <> '{}'
        """
    )
    _seed_system_templates(conn)
    _migrate_legacy_asn_ranking_widgets(conn)


def insert_widget(conn: sqlite3.Connection, dashboard_id: int, widget: dict[str, Any], now: str | None = None) -> int:
    normalized = validate_widget_definition(widget)
    timestamp = now or _utc_now()
    widget_key = str(widget.get("widget_key") or "widget-%s" % hashlib.sha1(_canonical_json(normalized).encode("utf-8")).hexdigest()[:12])
    cursor = conn.execute(
        """
        INSERT INTO dashboard_widgets (
            dashboard_id, widget_key, type, title, description, category,
            config_json, filters_json, visualization_json,
            grid_x, grid_y, grid_w, grid_h,
            expanded_grid_h, collapsed_grid_h, collapsed, hidden, height_mode,
            refresh_interval_seconds, use_global_filters, use_global_time_range,
            inheritance_json, custom_time_range_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            dashboard_id,
            widget_key,
            normalized["type"],
            normalized["title"],
            normalized["description"],
            normalized["category"],
            _canonical_json(normalized["config"]),
            _canonical_json(normalized["filters"]),
            _canonical_json(normalized["visualization"]),
            normalized["grid"]["x"],
            normalized["grid"]["y"],
            normalized["grid"]["w"],
            normalized["grid"]["h"],
            None,
            COLLAPSED_GRID_HEIGHT,
            int(normalized["collapsed"]),
            int(normalized["hidden"]),
            normalized["height_mode"],
            normalized["refresh_interval_seconds"],
            int(normalized["use_global_filters"]),
            int(normalized["use_global_time_range"]),
            _canonical_json(normalized["inheritance"]),
            _canonical_json(normalized["custom_time_range"]),
            timestamp,
            timestamp,
        ),
    )
    return int(cursor.lastrowid)


def _seed_system_templates(conn: sqlite3.Connection) -> None:
    now = _utc_now()
    for template in SYSTEM_TEMPLATES:
        row = conn.execute("SELECT id FROM dashboards WHERE template_key = ?", (template["key"],)).fetchone()
        if row is not None:
            continue
        cursor = conn.execute(
            """
            INSERT INTO dashboards (
                name, description, owner_user_id, is_default, is_shared, is_system,
                template_key, global_filters_json, time_range_json,
                refresh_interval_seconds, layout_version, created_at, updated_at
            ) VALUES (?, ?, NULL, ?, 1, 1, ?, '[]', ?, 30, ?, ?, ?)
            """,
            (
                template["name"],
                template["description"],
                1 if template["key"] == "general" else 0,
                template["key"],
                _canonical_json({"mode": "relative", "minutes": 10}),
                DASHBOARD_SCHEMA_VERSION,
                now,
                now,
            ),
        )
        dashboard_id = int(cursor.lastrowid)
        for widget in template["widgets"]:
            insert_widget(conn, dashboard_id, copy.deepcopy(widget), now)


def _migrate_legacy_asn_ranking_widgets(
    conn: sqlite3.Connection,
) -> None:
    """Correct the two historical ranking definitions without touching custom keys."""

    migrations = {
        "top-asn-src": {
            "legacy_dimension": "src_asn",
            "dimension": "dst_asn",
            "direction": "upload",
        },
        "top-asn-dst": {
            "legacy_dimension": "dst_asn",
            "dimension": "src_asn",
            "direction": "download",
        },
    }
    rows = conn.execute(
        """
        SELECT w.id, w.widget_key, w.config_json, w.visualization_json,
               d.is_system
        FROM dashboard_widgets AS w
        JOIN dashboards AS d ON d.id = w.dashboard_id
        WHERE w.widget_key IN ('top-asn-src', 'top-asn-dst')
        """
    ).fetchall()
    timestamp = _utc_now()
    for row in rows:
        migration = migrations[str(row["widget_key"])]
        config = _json_loads(row["config_json"], {})
        if (
            config.get("dimension") != migration["legacy_dimension"]
            or config.get("direction") != migration["direction"]
        ):
            continue
        config["dimension"] = migration["dimension"]
        visualization = _json_loads(row["visualization_json"], {})
        if _bool(row["is_system"]):
            config.update(
                {
                    "visualization": "chart_table",
                    "visualization_kind": "chart_table",
                    "combined_chart_kind": "donut",
                    "slice_limit": 8,
                    "chart_table_ratio": 55,
                }
            )
            visualization.update(
                {
                    "type": "chart_table",
                    "visualization_kind": "chart_table",
                }
            )
            conn.execute(
                """
                UPDATE dashboard_widgets
                SET config_json = ?, visualization_json = ?,
                    grid_x = ?, grid_w = 6, updated_at = ?
                WHERE id = ?
                """,
                (
                    _canonical_json(config),
                    _canonical_json(visualization),
                    0 if row["widget_key"] == "top-asn-src" else 6,
                    timestamp,
                    int(row["id"]),
                ),
            )
        else:
            conn.execute(
                """
                UPDATE dashboard_widgets
                SET config_json = ?, visualization_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    _canonical_json(config),
                    _canonical_json(visualization),
                    timestamp,
                    int(row["id"]),
                ),
            )


def widget_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "dashboard_id": int(row["dashboard_id"]),
        "widget_key": row["widget_key"],
        "type": row["type"],
        "title": row["title"],
        "description": row["description"],
        "category": row["category"],
        "config": _json_loads(row["config_json"], {}),
        "filters": _json_loads(row["filters_json"], []),
        "visualization": _json_loads(row["visualization_json"], {}),
        "grid": {"x": int(row["grid_x"]), "y": int(row["grid_y"]), "w": int(row["grid_w"]), "h": int(row["grid_h"])},
        "expanded_grid_h": (
            int(row["expanded_grid_h"])
            if row["expanded_grid_h"] is not None
            else None
        ),
        "collapsed_grid_h": int(row["collapsed_grid_h"] or COLLAPSED_GRID_HEIGHT),
        "collapsed": _bool(row["collapsed"]),
        "hidden": _bool(row["hidden"]),
        "height_mode": str(row["height_mode"] or "fixed"),
        "refresh_interval_seconds": int(row["refresh_interval_seconds"]),
        "use_global_filters": _bool(row["use_global_filters"]),
        "use_global_time_range": _bool(row["use_global_time_range"]),
        "inheritance": _json_loads(row["inheritance_json"], {}),
        "custom_time_range": (
            {}
            if _bool(row["use_global_time_range"])
            else _json_loads(row["custom_time_range_json"], {})
        ),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def dashboard_row_to_dict(
    row: sqlite3.Row | dict[str, Any],
    widgets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    time_range = _json_loads(
        row["time_range_json"],
        {"mode": "relative", "minutes": 10},
    )
    layout_mode = str(time_range.pop("_layout_mode", "custom"))
    compact_mode = str(
        time_range.pop(
            "_compact_mode",
            "vertical" if layout_mode == "auto_grid" else "none",
        )
    )
    result = {
        "id": int(row["id"]),
        "name": row["name"],
        "description": row["description"],
        "owner_user_id": int(row["owner_user_id"]) if row["owner_user_id"] is not None else None,
        "is_default": _bool(row["is_default"]),
        "is_shared": _bool(row["is_shared"]),
        "is_system": _bool(row["is_system"]),
        "template_key": row["template_key"],
        "global_filters": _json_loads(row["global_filters_json"], []),
        "time_range": time_range,
        "layout_mode": layout_mode,
        "compact_mode": compact_mode,
        "refresh_interval_seconds": int(row["refresh_interval_seconds"]),
        "layout_version": int(row["layout_version"]),
        "revision": int(row["layout_version"]),
        "legacy_layout_migrated": _bool(row["legacy_layout_migrated"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if widgets is not None:
        result["widgets"] = widgets
    return result


def repair_dashboard_widgets(
    conn: sqlite3.Connection,
    dashboard_id: int,
    priority_widget_id: int | None = None,
) -> bool:
    dashboard_row = conn.execute(
        "SELECT layout_version FROM dashboards WHERE id = ?",
        (dashboard_id,),
    ).fetchone()
    current_layout_version = (
        int(dashboard_row["layout_version"] or 0)
        if dashboard_row is not None
        else 0
    )
    schema_outdated = bool(
        dashboard_row is not None
        and current_layout_version < DASHBOARD_SCHEMA_VERSION
    )
    rows = conn.execute(
        """
        SELECT *
        FROM dashboard_widgets
        WHERE dashboard_id = ?
        ORDER BY grid_y, grid_x, id
        """,
        (dashboard_id,),
    ).fetchall()
    if not rows:
        if schema_outdated:
            conn.execute(
                """
                UPDATE dashboards
                SET layout_version = ?, updated_at = ?
                WHERE id = ?
                """,
                (DASHBOARD_SCHEMA_VERSION, _utc_now(), dashboard_id),
            )
        return schema_outdated
    widgets = [widget_row_to_dict(row) for row in rows]
    items = []
    expanded_heights: dict[int, int | None] = {}
    for widget in widgets:
        constraints = widget_layout_constraints(widget)
        expanded_height = widget.get("expanded_grid_h")
        grid = dict(widget["grid"])
        if widget.get("collapsed"):
            if expanded_height is None:
                expanded_height = max(
                    int(grid["h"]),
                    int(
                        widget_layout_constraints(
                            {**widget, "collapsed": False}
                        )["default_h"]
                    ),
                )
            grid["h"] = int(
                widget.get("collapsed_grid_h")
                or COLLAPSED_GRID_HEIGHT
            )
        expanded_heights[int(widget["id"])] = expanded_height
        items.append(
            {
                "id": int(widget["id"]),
                **grid,
                "hidden": bool(widget.get("hidden")),
                "min_w": constraints["min_w"],
                "min_h": constraints["min_h"],
                "max_w": constraints["max_w"],
                "max_h": constraints["max_h"],
            }
        )
    before = layout_signature(items)
    repaired = repair_dashboard_layout(items, priority_widget_id)
    validation = validate_layout(repaired)
    if not validation["valid"]:
        raise ValueError("; ".join(validation["errors"]))
    repaired_by_id = {int(item["id"]): item for item in repaired}
    layout_changed = before != layout_signature(repaired)
    changed = layout_changed or schema_outdated
    now = _utc_now()
    for widget in widgets:
        widget_id = int(widget["id"])
        grid = repaired_by_id[widget_id]
        expanded_height = expanded_heights[widget_id]
        if (
            widget["grid"] != {
                "x": int(grid["x"]),
                "y": int(grid["y"]),
                "w": int(grid["w"]),
                "h": int(grid["h"]),
            }
            or widget.get("expanded_grid_h") != expanded_height
        ):
            changed = True
            conn.execute(
                """
                UPDATE dashboard_widgets
                SET grid_x = ?, grid_y = ?, grid_w = ?, grid_h = ?,
                    expanded_grid_h = ?, collapsed_grid_h = ?,
                    updated_at = ?
                WHERE id = ? AND dashboard_id = ?
                """,
                (
                    int(grid["x"]),
                    int(grid["y"]),
                    int(grid["w"]),
                    int(grid["h"]),
                    expanded_height,
                    int(
                        widget.get("collapsed_grid_h")
                        or COLLAPSED_GRID_HEIGHT
                    ),
                    now,
                    widget_id,
                    dashboard_id,
                ),
            )
    if changed:
        next_layout_version = max(
            DASHBOARD_SCHEMA_VERSION,
            current_layout_version + (1 if layout_changed else 0),
        )
        conn.execute(
            """
            UPDATE dashboards
            SET layout_version = ?, updated_at = ?
            WHERE id = ?
            """,
            (next_layout_version, now, dashboard_id),
        )
        logger.info(
            "DASHBOARD_LAYOUT_REPAIRED dashboard_id=%s priority_widget_id=%s widgets=%s",
            dashboard_id,
            priority_widget_id,
            len(widgets),
        )
    return changed


class DashboardLayoutVersionConflict(ValueError):
    pass


def persist_dashboard_layout(
    conn: sqlite3.Connection,
    dashboard_id: int,
    widgets_payload: Any,
    *,
    layout_version: int | None = None,
    base_revision: int | None = None,
    active_widget_id: int | None = None,
    idempotency_key: str = "",
    interaction_id: str = "",
    compact_mode: str = "vertical",
) -> dict[str, Any]:
    if not isinstance(widgets_payload, list):
        raise ValueError("widgets deve ser uma lista")
    dashboard_row = conn.execute(
        "SELECT layout_version FROM dashboards WHERE id = ?",
        (dashboard_id,),
    ).fetchone()
    if dashboard_row is None:
        raise ValueError("dashboard não encontrado")
    current_version = int(dashboard_row["layout_version"] or 0)
    requested_revision = (
        int(base_revision)
        if base_revision is not None
        else layout_version
    )
    if (
        layout_version is not None
        and base_revision is not None
        and int(layout_version) != int(base_revision)
    ):
        raise ValueError("layout_version e base_revision divergem")
    compact_mode = str(compact_mode or "vertical").strip().lower()
    if compact_mode not in COMPACT_MODES:
        raise ValueError("compact_mode inválido")
    rows = conn.execute(
        """
        SELECT *
        FROM dashboard_widgets
        WHERE dashboard_id = ?
        ORDER BY grid_y, grid_x, id
        """,
        (dashboard_id,),
    ).fetchall()
    current_widgets = [widget_row_to_dict(row) for row in rows]
    current_by_id = {
        int(widget["id"]): widget for widget in current_widgets
    }
    payload_by_id: dict[int, dict[str, Any]] = {}
    for value in widgets_payload:
        if not isinstance(value, dict):
            raise ValueError("item de layout inválido")
        try:
            widget_id = int(value.get("id"))
        except (TypeError, ValueError):
            raise ValueError("id de widget inválido")
        if widget_id in payload_by_id:
            raise ValueError("layout contém IDs duplicados")
        if widget_id not in current_by_id:
            raise ValueError("widget %s não pertence ao dashboard" % widget_id)
        grid = value.get("grid")
        if not isinstance(grid, dict):
            raise ValueError("grid ausente no widget %s" % widget_id)
        payload_by_id[widget_id] = grid
    expected_ids = set(current_by_id)
    received_ids = set(payload_by_id)
    if received_ids != expected_ids:
        missing = sorted(expected_ids - received_ids)
        unknown = sorted(received_ids - expected_ids)
        details = []
        if missing:
            details.append(
                "widgets ausentes: %s" % ", ".join(map(str, missing))
            )
        if unknown:
            details.append(
                "widgets desconhecidos: %s" % ", ".join(map(str, unknown))
            )
        raise ValueError("; ".join(details))
    if active_widget_id is not None and int(active_widget_id) not in expected_ids:
        raise ValueError("widget ativo não pertence ao dashboard")

    requested_items: list[dict[str, Any]] = []
    normalized_input = False
    for widget_id, widget in current_by_id.items():
        grid = payload_by_id[widget_id]
        constraints = widget_layout_constraints(widget)
        item = normalize_grid_item(
            {
                "id": widget_id,
                **grid,
                "hidden": bool(widget.get("hidden")),
                "min_w": constraints["min_w"],
                "min_h": constraints["min_h"],
                "max_w": constraints["max_w"],
                "max_h": constraints["max_h"],
            },
            constraints,
        )
        for field in ("x", "y", "w", "h"):
            try:
                received = int(grid.get(field))
            except (TypeError, ValueError):
                received = None
            if received != int(item[field]):
                normalized_input = True
        requested_items.append(item)

    priority = int(active_widget_id) if active_widget_id is not None else None
    resolved = resolve_collisions(
        requested_items,
        priority,
        compact=compact_mode == "vertical",
    )
    validation = validate_layout(resolved)
    if not validation["valid"]:
        raise ValueError("; ".join(validation["errors"]))
    current_items = [
        {
            "id": int(widget["id"]),
            **widget["grid"],
            "hidden": bool(widget.get("hidden")),
            **{
                key: value
                for key, value in widget_layout_constraints(widget).items()
                if key in {"min_w", "min_h", "max_w", "max_h"}
            },
        }
        for widget in current_widgets
    ]
    current_signature = layout_signature(current_items)
    requested_signature = layout_signature(requested_items)
    resolved_signature = layout_signature(resolved)
    if (
        requested_revision is not None
        and int(requested_revision) != current_version
    ):
        if resolved_signature == current_signature:
            return {
                "widgets": [
                    {
                        "id": int(item["id"]),
                        "grid": {
                            field: int(item[field])
                            for field in ("x", "y", "w", "h")
                        },
                    }
                    for item in resolved
                ],
                "layout_version": current_version,
                "revision": current_version,
                "layout_repaired": False,
                "idempotent_replay": True,
                "idempotency_key": str(idempotency_key or ""),
                "interaction_id": str(interaction_id or ""),
                "compact_mode": compact_mode,
            }
        raise DashboardLayoutVersionConflict(
            "revision desatualizada: esperado %s, recebido %s"
            % (current_version, requested_revision)
        )

    changed = resolved_signature != current_signature
    now = _utc_now()
    if changed:
        resolved_by_id = {
            int(item["id"]): item for item in resolved
        }
        conn.executemany(
            """
            UPDATE dashboard_widgets
            SET grid_x = ?, grid_y = ?, grid_w = ?, grid_h = ?, updated_at = ?
            WHERE id = ? AND dashboard_id = ?
            """,
            [
                (
                    int(resolved_by_id[widget_id]["x"]),
                    int(resolved_by_id[widget_id]["y"]),
                    int(resolved_by_id[widget_id]["w"]),
                    int(resolved_by_id[widget_id]["h"]),
                    now,
                    widget_id,
                    dashboard_id,
                )
                for widget_id in sorted(resolved_by_id)
            ],
        )
    next_version = (
        max(DASHBOARD_SCHEMA_VERSION, current_version + 1)
        if changed
        else current_version
    )
    if changed:
        conn.execute(
            """
            UPDATE dashboards
            SET layout_version = ?, updated_at = ?
            WHERE id = ?
            """,
            (next_version, now, dashboard_id),
        )
    return {
        "widgets": [
            {
                "id": int(item["id"]),
                "grid": {
                    field: int(item[field])
                    for field in ("x", "y", "w", "h")
                },
            }
            for item in resolved
        ],
        "layout_version": next_version,
        "revision": next_version,
        "layout_repaired": (
            normalized_input or requested_signature != resolved_signature
        ),
        "idempotent_replay": not changed,
        "idempotency_key": str(idempotency_key or ""),
        "interaction_id": str(interaction_id or ""),
        "compact_mode": compact_mode,
    }


def get_dashboard(
    conn: sqlite3.Connection,
    dashboard_id: int,
    priority_widget_id: int | None = None,
) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM dashboards WHERE id = ?", (dashboard_id,)).fetchone()
    if row is None:
        return None
    layout_repaired = repair_dashboard_widgets(
        conn,
        dashboard_id,
        priority_widget_id,
    )
    if layout_repaired:
        row = conn.execute(
            "SELECT * FROM dashboards WHERE id = ?",
            (dashboard_id,),
        ).fetchone()
    widgets = [
        widget_row_to_dict(widget)
        for widget in conn.execute(
            "SELECT * FROM dashboard_widgets WHERE dashboard_id = ? ORDER BY grid_y, grid_x, id",
            (dashboard_id,),
        ).fetchall()
    ]
    result = dashboard_row_to_dict(row, widgets)
    result["layout_repaired"] = layout_repaired
    return result


def create_dashboard(
    conn: sqlite3.Connection,
    payload: dict[str, Any],
    owner_user_id: int,
    *,
    widgets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    normalized = normalize_dashboard_payload(payload)
    now = _utc_now()
    if normalized["is_default"]:
        conn.execute("UPDATE dashboards SET is_default = 0 WHERE owner_user_id = ?", (owner_user_id,))
    cursor = conn.execute(
        """
        INSERT INTO dashboards (
            name, description, owner_user_id, is_default, is_shared, is_system,
            template_key, global_filters_json, time_range_json,
            refresh_interval_seconds, layout_version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 0, NULL, ?, ?, ?, ?, ?, ?)
        """,
        (
            normalized["name"],
            normalized["description"],
            owner_user_id,
            int(normalized["is_default"]),
            int(normalized["is_shared"]),
            _canonical_json(normalized["global_filters"]),
            _canonical_json(normalized["time_range"]),
            normalized["refresh_interval_seconds"],
            DASHBOARD_SCHEMA_VERSION,
            now,
            now,
        ),
    )
    dashboard_id = int(cursor.lastrowid)
    for widget in widgets or []:
        insert_widget(conn, dashboard_id, widget, now)
    return get_dashboard(conn, dashboard_id) or {}


def duplicate_dashboard(
    conn: sqlite3.Connection,
    source: dict[str, Any],
    owner_user_id: int,
    name: str | None = None,
) -> dict[str, Any]:
    payload = {
        "name": name or "%s (cópia)" % source["name"],
        "description": source.get("description", ""),
        "is_default": False,
        "is_shared": False,
        "global_filters": source.get("global_filters", []),
        "time_range": source.get("time_range", {}),
        "layout_mode": source.get("layout_mode", "custom"),
        "compact_mode": source.get("compact_mode", "none"),
        "refresh_interval_seconds": source.get("refresh_interval_seconds", 30),
    }
    return create_dashboard(conn, payload, owner_user_id, widgets=source.get("widgets", []))


def ensure_user_default_dashboard(conn: sqlite3.Connection, owner_user_id: int) -> dict[str, Any]:
    row = conn.execute(
        "SELECT id FROM dashboards WHERE owner_user_id = ? ORDER BY is_default DESC, id LIMIT 1",
        (owner_user_id,),
    ).fetchone()
    if row is not None:
        return get_dashboard(conn, int(row["id"])) or {}
    template_row = conn.execute(
        "SELECT id FROM dashboards WHERE template_key = 'general' LIMIT 1"
    ).fetchone()
    template = get_dashboard(conn, int(template_row["id"])) if template_row is not None else None
    widgets = template.get("widgets", []) if template else GENERAL_WIDGETS
    return create_dashboard(
        conn,
        {
            "name": "Meu Dashboard",
            "description": "Layout padrão migrado para o motor de widgets.",
            "is_default": True,
            "is_shared": False,
            "global_filters": [],
            "time_range": {"mode": "relative", "minutes": 10},
            "refresh_interval_seconds": 30,
        },
        owner_user_id,
        widgets=widgets,
    )


def widget_data_signature(widget: dict[str, Any], query_context: dict[str, Any]) -> str:
    data_definition = {
        "schema_version": DASHBOARD_SCHEMA_VERSION,
        "type": widget.get("type"),
        "config": {
            key: value
            for key, value in (widget.get("config") or {}).items()
            if key not in {
                "appearance",
                "axis_show_negative_sign",
                "calculation",
                "data_kind",
                "field_config",
                "legend_calculation",
                "palette",
                "show_labels",
                "show_legend",
                "traffic_orientation",
                "unit",
                "visualization",
                "visualization_kind",
                "decimals",
            }
        },
        "filters": widget.get("filters") or [],
        "time_range": query_context.get("time_range") or {},
        "range_minutes": query_context.get("range_minutes"),
        "start": query_context.get("start"),
        "end": query_context.get("end"),
        "global_filters": query_context.get("global_filters") or [],
        "sensor_id": query_context.get("sensor_id"),
        "interface_id": query_context.get("interface_id"),
        "if_index": query_context.get("if_index"),
        "zone_id": query_context.get("zone_id"),
        "zone_direction": query_context.get("zone_direction"),
        "series_limit": query_context.get("series_limit"),
        "interval": query_context.get("interval"),
        "maximum_data_points": query_context.get("maximum_data_points"),
    }
    return hashlib.sha256(_canonical_json(data_definition).encode("utf-8")).hexdigest()


def build_widget_query_plan(widget: dict[str, Any]) -> dict[str, Any]:
    normalized = validate_widget_definition(widget)
    widget_type = normalized["type"]
    config = normalized["config"]
    if widget_type == "top_n":
        dimension = config["dimension"]
        dimension_plan = DIMENSION_PLANS[dimension]
        return {
            "kind": "top_n",
            "dimension": dimension,
            "dimension_expression": dimension_plan.get("expression", ""),
            "columns": list(dimension_plan.get("columns") or []),
            "aggregate": dimension_plan.get("aggregate"),
            "resolver": dimension_plan.get("resolver"),
            "metric": config["metric"],
            "direction": config["direction"],
            "limit": config["limit"],
            "calculation": config.get("calculation", "current"),
            "filters": normalized["filters"],
        }
    if widget_type in {"timeseries", "kpi"}:
        return {
            "kind": widget_type,
            "metric": config["metric"],
            "direction": config["direction"],
            "group_by": config.get("group_by", "total"),
            "aggregation": config.get("aggregation", "sum"),
            "comparison_mode": config.get("comparison_mode", "none"),
            "calculation": config.get("calculation", "last_not_null"),
            "legend_calculation": config.get(
                "legend_calculation",
                "last_not_null",
            ),
            "resolution_seconds": config.get("resolution_seconds", 0),
            "include_partial_bucket": bool(
                config.get("include_partial_bucket", False)
            ),
            "filters": normalized["filters"],
        }
    return {
        "kind": widget_type,
        "source": config["source"],
        "limit": config["limit"],
        "filters": normalized["filters"],
    }


class DashboardWidgetMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values = {
            "queries_total": 0,
            "query_errors_total": 0,
            "query_timeouts_total": 0,
            "aggregate_queries_total": 0,
            "raw_queries_total": 0,
            "preview_queries_total": 0,
            "lazy_skips_total": 0,
            "widget_cache_hits_total": 0,
            "widget_cache_misses_total": 0,
            "rows_returned_total": 0,
            "response_bytes_total": 0,
        }
        self._query_seconds_total = 0.0
        self._queries_by_type: dict[str, int] = {}

    def record(
        self,
        *,
        duration_seconds: float,
        source: str,
        widget_type: str = "",
        rows: int = 0,
        response_bytes: int = 0,
        preview: bool = False,
        error: bool = False,
        timeout: bool = False,
    ) -> None:
        with self._lock:
            self._values["queries_total"] += 1
            self._query_seconds_total += max(0.0, float(duration_seconds))
            self._values["rows_returned_total"] += max(0, int(rows))
            self._values["response_bytes_total"] += max(0, int(response_bytes))
            if widget_type:
                self._queries_by_type[widget_type] = (
                    self._queries_by_type.get(widget_type, 0) + 1
                )
            if source == "aggregate":
                self._values["aggregate_queries_total"] += 1
            else:
                self._values["raw_queries_total"] += 1
            if preview:
                self._values["preview_queries_total"] += 1
            if error:
                self._values["query_errors_total"] += 1
            if timeout:
                self._values["query_timeouts_total"] += 1

    def cache_event(self, hit: bool) -> None:
        with self._lock:
            key = (
                "widget_cache_hits_total"
                if hit
                else "widget_cache_misses_total"
            )
            self._values[key] += 1

    def lazy_skip(self) -> None:
        with self._lock:
            self._values["lazy_skips_total"] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            result = dict(self._values)
            result["query_seconds_total"] = round(self._query_seconds_total, 6)
            result["query_seconds_avg"] = round(
                self._query_seconds_total / self._values["queries_total"],
                6,
            ) if self._values["queries_total"] else 0.0
            result["queries_by_type"] = dict(self._queries_by_type)
            return result


DASHBOARD_WIDGET_METRICS = DashboardWidgetMetrics()
