from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from ipaddress import ip_network
from typing import Any


DASHBOARD_SCHEMA_VERSION = 1
DASHBOARD_EXPORT_VERSION = 1
DASHBOARD_GRID_COLUMNS = 12
MAX_WIDGET_LIMIT = 100
MAX_DASHBOARD_WIDGETS = 80
ALLOWED_REFRESH_INTERVALS = {0, 5, 10, 15, 30, 60, 120, 300}
COMPARISON_MODES = {
    "none",
    "previous_period",
    "yesterday_same_time",
    "last_week_same_time",
}
ALLOWED_RESOLUTIONS = {0, 5, 10, 30, 60, 300, 900, 3600}
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
    "horizontal_bar",
    "line",
    "area",
    "stacked_area",
    "donut",
    "pie",
    "number",
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
        "config": config,
        "filters": [],
        "visualization": {"type": config.get("visualization", "table"), "show_legend": True},
        "grid": {"x": x, "y": y, "w": width, "h": height},
        "collapsed": False,
        "hidden": False,
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
        4,
    ),
    _default_widget(
        "traffic-pps",
        "Pacotes/s",
        "timeseries",
        "traffic",
        {"metric": "pps", "direction": "both", "group_by": "total", "aggregation": "sum", "visualization": "line"},
        6,
        0,
        6,
        4,
    ),
    _default_widget(
        "top-src-ip",
        "Top IP origem",
        "top_n",
        "traffic",
        {"dimension": "src_ip", "metric": "bps", "direction": "source", "limit": 10, "visualization": "horizontal_bar"},
        0,
        4,
        4,
        4,
    ),
    _default_widget(
        "top-dst-ip",
        "Top IP destino",
        "top_n",
        "traffic",
        {"dimension": "dst_ip", "metric": "bps", "direction": "destination", "limit": 10, "visualization": "horizontal_bar"},
        4,
        4,
        4,
        4,
    ),
    _default_widget(
        "top-ports",
        "Top portas",
        "top_n",
        "traffic",
        {"dimension": "dst_port", "metric": "bps", "direction": "both", "limit": 10, "visualization": "bar"},
        8,
        4,
        4,
        4,
    ),
    _default_widget(
        "top-protocols",
        "Protocolos",
        "top_n",
        "traffic",
        {"dimension": "protocol", "metric": "bps", "direction": "both", "limit": 10, "visualization": "donut"},
        0,
        8,
        4,
        4,
    ),
    _default_widget(
        "top-flags",
        "TCP flags",
        "top_n",
        "security",
        {"dimension": "tcp_flags", "metric": "flows", "direction": "both", "limit": 10, "visualization": "bar"},
        4,
        8,
        4,
        4,
    ),
    dict(
        _default_widget(
            "top-syn-src",
            "Top SYN origem",
            "top_n",
            "security",
            {"dimension": "src_ip", "metric": "pps", "direction": "both", "limit": 10, "visualization": "table"},
            0,
            16,
            4,
            4,
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
            16,
            4,
            4,
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
        8,
        8,
        4,
        4,
    ),
    _default_widget(
        "top-asn-src",
        "Destinos do upload",
        "top_n",
        "traffic",
        {"dimension": "src_asn", "metric": "bps", "direction": "upload", "limit": 10, "visualization": "table"},
        0,
        12,
        4,
        4,
    ),
    _default_widget(
        "top-asn-dst",
        "Origens do download",
        "top_n",
        "traffic",
        {"dimension": "dst_asn", "metric": "bps", "direction": "download", "limit": 10, "visualization": "table"},
        4,
        12,
        4,
        4,
    ),
    _default_widget(
        "recent-anomalies",
        "Anomalias recentes",
        "recent_events",
        "security",
        {"source": "anomalies", "limit": 10, "visualization": "table"},
        8,
        12,
        4,
        4,
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
    width = max(1, min(DASHBOARD_GRID_COLUMNS, int(value.get("w", value.get("width", 4)) or 4)))
    height = max(2, min(12, int(value.get("h", value.get("height", 4)) or 4)))
    x = max(0, min(DASHBOARD_GRID_COLUMNS - width, int(value.get("x", 0) or 0)))
    y = max(0, min(10000, int(value.get("y", 0) or 0)))
    return {"x": x, "y": y, "w": width, "h": height}


def resolve_grid_collision(grid: dict[str, int], occupied: list[dict[str, int]]) -> dict[str, int]:
    resolved = normalize_grid(grid)

    def overlaps(left: dict[str, int], right: dict[str, int]) -> bool:
        return not (
            left["x"] + left["w"] <= right["x"]
            or right["x"] + right["w"] <= left["x"]
            or left["y"] + left["h"] <= right["y"]
            or right["y"] + right["h"] <= left["y"]
        )

    attempts = 0
    while any(overlaps(resolved, normalize_grid(item)) for item in occupied):
        resolved["y"] += 1
        attempts += 1
        if attempts > 10000:
            raise ValueError("não foi possível posicionar o widget")
    return resolved


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
        config.update({"dimension": dimension, "metric": metric, "direction": direction, "limit": limit})
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
    grid = normalize_grid(payload.get("grid"))
    minimums = {
        "timeseries": (4, 3),
        "top_n": (3, 3),
        "recent_events": (4, 3),
        "status_list": (3, 3),
        "kpi": (2, 2),
    }
    minimum_width, minimum_height = minimums.get(widget_type, (2, 2))
    grid["w"] = max(minimum_width, grid["w"])
    grid["x"] = min(grid["x"], DASHBOARD_GRID_COLUMNS - grid["w"])
    grid["h"] = max(minimum_height, grid["h"])
    normalized.update(
        {
            "title": title,
            "description": str(payload.get("description") or "").strip()[:500],
            "type": widget_type,
            "category": category,
            "config": config,
            "filters": validate_filters(payload.get("filters")),
            "visualization": dict(visualization, type=visualization_type),
            "grid": grid,
            "collapsed": _bool(payload.get("collapsed")),
            "hidden": _bool(payload.get("hidden")),
            "refresh_interval_seconds": refresh,
            "use_global_filters": _bool(payload.get("use_global_filters", True)),
            "use_global_time_range": _bool(payload.get("use_global_time_range", True)),
            "inheritance": validate_inheritance(payload.get("inheritance")),
            "custom_time_range": payload.get("custom_time_range") if isinstance(payload.get("custom_time_range"), dict) else {},
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
    result = {
        "name": name,
        "description": str(payload.get("description") or "").strip()[:500],
        "is_default": _bool(payload.get("is_default")),
        "is_shared": _bool(payload.get("is_shared")),
        "global_filters": validate_filters(payload.get("global_filters")),
        "time_range": payload.get("time_range") if isinstance(payload.get("time_range"), dict) else {"mode": "relative", "minutes": 10},
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
            collapsed INTEGER NOT NULL DEFAULT 0,
            hidden INTEGER NOT NULL DEFAULT 0,
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
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboards_owner ON dashboards(owner_user_id, is_default)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboards_visible ON dashboards(is_system, is_shared)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboards_updated ON dashboards(updated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_widgets_layout ON dashboard_widgets(dashboard_id, grid_y, grid_x)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_widgets_updated ON dashboard_widgets(updated_at)")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboards_template_key ON dashboards(template_key) WHERE template_key IS NOT NULL"
    )
    _seed_system_templates(conn)


def insert_widget(conn: sqlite3.Connection, dashboard_id: int, widget: dict[str, Any], now: str | None = None) -> int:
    normalized = validate_widget_definition(widget)
    timestamp = now or _utc_now()
    widget_key = str(widget.get("widget_key") or "widget-%s" % hashlib.sha1(_canonical_json(normalized).encode("utf-8")).hexdigest()[:12])
    cursor = conn.execute(
        """
        INSERT INTO dashboard_widgets (
            dashboard_id, widget_key, type, title, description, category,
            config_json, filters_json, visualization_json,
            grid_x, grid_y, grid_w, grid_h, collapsed, hidden,
            refresh_interval_seconds, use_global_filters, use_global_time_range,
            inheritance_json, custom_time_range_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            int(normalized["collapsed"]),
            int(normalized["hidden"]),
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
        "collapsed": _bool(row["collapsed"]),
        "hidden": _bool(row["hidden"]),
        "refresh_interval_seconds": int(row["refresh_interval_seconds"]),
        "use_global_filters": _bool(row["use_global_filters"]),
        "use_global_time_range": _bool(row["use_global_time_range"]),
        "inheritance": _json_loads(row["inheritance_json"], {}),
        "custom_time_range": _json_loads(row["custom_time_range_json"], {}),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def dashboard_row_to_dict(
    row: sqlite3.Row | dict[str, Any],
    widgets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
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
        "time_range": _json_loads(row["time_range_json"], {"mode": "relative", "minutes": 10}),
        "refresh_interval_seconds": int(row["refresh_interval_seconds"]),
        "layout_version": int(row["layout_version"]),
        "legacy_layout_migrated": _bool(row["legacy_layout_migrated"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if widgets is not None:
        result["widgets"] = widgets
    return result


def get_dashboard(conn: sqlite3.Connection, dashboard_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM dashboards WHERE id = ?", (dashboard_id,)).fetchone()
    if row is None:
        return None
    widgets = [
        widget_row_to_dict(widget)
        for widget in conn.execute(
            "SELECT * FROM dashboard_widgets WHERE dashboard_id = ? ORDER BY grid_y, grid_x, id",
            (dashboard_id,),
        ).fetchall()
    ]
    return dashboard_row_to_dict(row, widgets)


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
            if key not in {"visualization", "palette", "show_legend", "show_labels", "decimals", "unit"}
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
            "resolution_seconds": config.get("resolution_seconds", 0),
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
