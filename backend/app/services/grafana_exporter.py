from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from .prefixes import normalize_prefix_filter, normalize_prefix_grouping

from .dashboard_visualizations import (
    infer_visualization_kind,
    normalize_field_config,
)


GRAFANA_PANEL_TYPES = {
    "line": "timeseries",
    "area": "timeseries",
    "line_area": "timeseries",
    "time_bars": "timeseries",
    "horizontal_bar": "barchart",
    "vertical_bar": "barchart",
    "pie": "piechart",
    "donut": "piechart",
    "bar_gauge": "bargauge",
    "stat": "stat",
    "table": "table",
}
GRAFANA_CALCULATIONS = {
    "last": "last",
    "last_not_null": "lastNotNull",
    "mean": "mean",
    "max": "max",
    "min": "min",
    "total": "sum",
    "difference": "diff",
}
GRAFANA_COLOR_MODES = {
    "classic": "palette-classic",
    "continuous": "continuous-GrYlRd",
    "thresholds": "thresholds",
}
SECRET_FIELD_PATTERN = re.compile(
    r"(?:^|_)(?:authorization|api_?key|access_?key|client_?secret|"
    r"password|passwd|secret|token|credential|cookie)(?:$|_)",
    re.IGNORECASE,
)


def _clean_identifier(value: Any, fallback: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_-]+", "-", str(value or "").strip())
    return candidate.strip("-")[:80] or fallback


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _without_secrets(value: Any) -> Any:
    """Return a deep JSON-safe copy with credential-shaped fields removed."""

    if isinstance(value, dict):
        return {
            str(key): _without_secrets(item)
            for key, item in value.items()
            if not SECRET_FIELD_PATTERN.search(str(key))
        }
    if isinstance(value, list):
        return [_without_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [_without_secrets(item) for item in value]
    return copy.deepcopy(value)


def _dashboard_uid(dashboard: dict[str, Any]) -> str:
    source = "%s:%s" % (
        dashboard.get("id") or "new",
        dashboard.get("name") or "dashboard",
    )
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    return "gmj-flow-%s-%s" % (
        _clean_identifier(dashboard.get("id"), "dashboard"),
        digest,
    )


def _metric_for_widget(widget: dict[str, Any]) -> str:
    config = widget.get("config") if isinstance(widget.get("config"), dict) else {}
    widget_alias = str(config.get("widget_alias") or "").strip().lower()
    if widget_alias in {
        "traffic_by_prefix_bps",
        "traffic_by_prefix_pps",
        "top_source_prefixes",
        "top_destination_prefixes",
        "prefix_timeseries",
        "top_ports_by_prefix",
        "top_protocols_by_prefix",
    }:
        return widget_alias
    if widget_alias in {"prefix_table", "prefix_distribution"}:
        return "top_destination_prefixes"
    metric = str(config.get("metric") or "").strip().lower()
    if widget.get("type") == "top_n":
        dimension = str(config.get("dimension") or "").strip().lower()
        direction = str(config.get("direction") or "both").strip().lower()
        if dimension == "src_prefix":
            return "top_source_prefixes"
        if dimension == "dst_prefix":
            return "top_destination_prefixes"
        if dimension in {"asn_src", "src_asn"} and direction != "upload":
            return "top_download_origins"
        if dimension in {"asn_dst", "dst_asn"} and direction != "download":
            return "top_upload_destinations"
        if dimension in {"proto", "protocol"}:
            return (
                "top_protocols_by_prefix"
                if config.get("requires_prefix")
                else "top_protocols"
            )
        if dimension in {"src_port", "dst_port"} and config.get(
            "requires_prefix"
        ):
            return "top_ports_by_prefix"
    group_by = str(config.get("group_by") or "").strip().lower()
    if group_by in {"src_prefix", "dst_prefix"}:
        return (
            "traffic_by_prefix_pps"
            if metric in {"pps", "packets_s", "traffic_pps"}
            else "traffic_by_prefix_bps"
        )
    if metric in {"bps", "bits_s", "traffic_bps"}:
        return "traffic_bps"
    if metric in {"pps", "packets_s", "traffic_pps"}:
        return "traffic_pps"
    return metric or "traffic_bps"


def _query_kind(widget: dict[str, Any]) -> str:
    config = widget.get("config") if isinstance(widget.get("config"), dict) else {}
    data_kind = str(config.get("data_kind") or "").strip().lower()
    if widget.get("type") == "top_n" or data_kind == "ranking_snapshot":
        return "ranking"
    return "timeseries"


def _dashboard_saved_filters(
    dashboard: dict[str, Any],
) -> dict[str, Any]:
    filters = {
        "sensor_ids": [],
        "interfaces": [],
        "protocols": [],
        "direction": "both",
        "zone": None,
    }
    for rule in (
        dashboard.get("global_filters")
        if isinstance(dashboard.get("global_filters"), list)
        else []
    ):
        if not isinstance(rule, dict) or rule.get("operator") != "eq":
            continue
        field = str(rule.get("field") or "").strip().lower()
        value = rule.get("value")
        if field == "sensor":
            try:
                filters["sensor_ids"] = [int(value)]
            except (TypeError, ValueError):
                pass
        elif field in {"interface", "input_if", "output_if"}:
            try:
                filters["interfaces"] = [int(value)]
            except (TypeError, ValueError):
                pass
        elif field == "protocol":
            filters["protocols"] = [str(value).strip().lower()]
        elif field == "direction":
            filters["direction"] = str(value).strip().lower() or "both"
        elif field == "zone":
            try:
                filters["zone"] = int(value)
            except (TypeError, ValueError):
                pass
    return filters


def _target_body(
    widget: dict[str, Any],
    query_kind: str,
    dashboard: dict[str, Any],
    options: dict[str, Any],
) -> dict[str, Any]:
    config = widget.get("config") if isinstance(widget.get("config"), dict) else {}
    filters = (
        _dashboard_saved_filters(dashboard)
        if options["include_saved_filters"]
        else {
            "sensor_ids": [],
            "interfaces": [],
            "protocols": [],
            "direction": "both",
            "zone": None,
        }
    )
    configured_direction = str(
        config.get("direction") or "both"
    ).strip().lower()
    saved_direction = str(
        filters.get("direction") or "both"
    ).strip().lower()
    filters["direction"] = (
        configured_direction
        if configured_direction != "both"
        else saved_direction
    )
    editable = bool(options["make_filters_editable"])
    if editable:
        # Scalar aliases accept numeric IDs or "all". Keeping these values
        # outside the typed arrays makes a Grafana "All" selection valid.
        filters["sensor_ids"] = []
        filters["interfaces"] = []
        filters["direction"] = "both"
    body: dict[str, Any] = {
        "metric": _metric_for_widget(widget),
        "from": "$__isoFrom()",
        "to": "$__isoTo()",
        "filters": filters,
        "calculation": str(config.get("calculation") or "last_not_null"),
        "include_partial_bucket": bool(
            config.get("include_partial_bucket", False)
        ),
        "timezone": "UTC",
        "format": "json",
    }
    if editable:
        body.update(
            {
                "sensor": "${sensor}",
                "interface": "${interface}",
                "direction": "${direction}",
                "zone": "${zone}",
            }
        )
    elif filters.get("zone") is not None:
        body["zone"] = int(filters["zone"])
    filters.pop("zone", None)
    prefix_filter = normalize_prefix_filter(
        dashboard.get("prefix_filter")
        if options["include_saved_filters"] and options["include_prefixes"]
        else {}
    )
    prefix_grouping = normalize_prefix_grouping(
        dashboard.get("prefix_grouping")
        if options["include_saved_filters"] and options["include_prefixes"]
        else {}
    )
    if editable and options["include_prefixes"]:
        prefix_filter = {
            "enabled": True,
            "cidr": "${prefix}",
            "prefix_id": "${prefix_id}",
            "start_ip": "${prefix_start}",
            "end_ip": "${prefix_end}",
            "address_family": "${address_family}",
            "match_side": "${match_side}",
            "direction": None,
            "temporary": True,
        }
        prefix_grouping = {
            "enabled": True,
            "ipv4_prefix_length": "${ipv4_prefix_length}",
            "ipv6_prefix_length": "${ipv6_prefix_length}",
            "side": (
                "source"
                if str(config.get("group_by") or "").lower() == "src_prefix"
                else "destination"
            ),
            "top_n": "${top_n}",
            "mode": "top_n",
            "include_empty": False,
        }
    body["prefix_filter"] = prefix_filter
    body["prefix_grouping"] = prefix_grouping
    if query_kind == "ranking":
        body["top_n"] = (
            "${top_n}"
            if editable
            else max(1, min(50, int(config.get("limit") or 10)))
        )
    else:
        group_by = str(config.get("group_by") or "direction").lower()
        body.update(
            {
                "interval_ms": "${__interval_ms}",
                "max_data_points": "${__maxDataPoints}",
                "group_by": [
                    "direction" if group_by in {"total", "direction"} else group_by
                ],
            }
        )
    return body


def _infinity_target(
    widget: dict[str, Any],
    panel_index: int,
    datasource_uid: str,
    datasource_type: str,
    dashboard: dict[str, Any],
    options: dict[str, Any],
) -> dict[str, Any]:
    query_kind = _query_kind(widget)
    body = _target_body(widget, query_kind, dashboard, options)
    columns = (
        [
            {
                "selector": "timestamp",
                "text": "Time",
                "type": "timestamp_epoch",
            },
            {
                "selector": "series",
                "text": "Series",
                "type": "string",
            },
            {
                "selector": "value",
                "text": "Value",
                "type": "number",
            },
        ]
        if query_kind == "timeseries"
        else [
            {"selector": "rank", "text": "Rank", "type": "number"},
            {"selector": "label", "text": "Label", "type": "string"},
            {"selector": "value", "text": "Value", "type": "number"},
            {"selector": "percent", "text": "Percent", "type": "number"},
        ]
    )
    return {
        "refId": chr(65 + (panel_index % 26)),
        "datasource": {
            "type": datasource_type,
            "uid": datasource_uid,
        },
        "type": "json",
        "source": "url",
        "format": "timeseries" if query_kind == "timeseries" else "table",
        "url": "/api/v1/grafana/query/%s" % query_kind,
        "url_options": {
            "method": "POST",
            "body_type": "raw",
            "body_content_type": "application/json",
            "data": _stable_json(body),
        },
        "parser": "backend",
        "root_selector": "$.rows" if query_kind == "timeseries" else "$.items",
        "columns": columns,
        "filters": [],
    }


def _override_matcher(matcher: dict[str, Any]) -> dict[str, Any] | None:
    match_type = str(matcher.get("type") or "").lower()
    value = matcher.get("value")
    if match_type == "field_name":
        return {"id": "byName", "options": str(value or "")}
    if match_type == "regex":
        return {"id": "byRegexp", "options": str(value or "")}
    if match_type == "direction":
        direction = str(value or "").lower()
        return {
            "id": "byRegexp",
            "options": "(?i)%s" % re.escape(direction),
        }
    if match_type == "metric":
        return {
            "id": "byRegexp",
            "options": "(?i)%s" % re.escape(str(value or "")),
        }
    return None


def _override_properties(properties: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    if properties.get("color"):
        result.append(
            {
                "id": "color",
                "value": {
                    "mode": "fixed",
                    "fixedColor": str(properties["color"]),
                },
            }
        )
    if properties.get("line_width") is not None:
        result.append(
            {"id": "custom.lineWidth", "value": int(properties["line_width"])}
        )
    if properties.get("fill_opacity") is not None:
        result.append(
            {
                "id": "custom.fillOpacity",
                "value": int(properties["fill_opacity"]),
            }
        )
    if properties.get("smooth") is not None:
        result.append(
            {
                "id": "custom.lineInterpolation",
                "value": "smooth" if properties["smooth"] else "linear",
            }
        )
    if properties.get("visible") is False:
        result.append({"id": "custom.hideFrom", "value": {"viz": True}})
    if properties.get("negative_y"):
        result.append({"id": "custom.transform", "value": "negative-Y"})
    return result


def _field_config(
    widget: dict[str, Any],
    visualization: str,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    config = widget.get("config") if isinstance(widget.get("config"), dict) else {}
    appearance = (
        config.get("appearance")
        if isinstance(config.get("appearance"), dict)
        else {}
    )
    normalized = normalize_field_config(
        config.get("field_config"),
        str(config.get("metric") or "count"),
        appearance,
    )
    defaults = normalized["defaults"]
    unit = str(defaults.get("unit") or config.get("unit") or "short")
    custom = {
        "drawStyle": "bars" if visualization == "time_bars" else "line",
        "lineInterpolation": (
            "smooth"
            if defaults.get("smooth", appearance.get("smooth_lines", True))
            else "linear"
        ),
        "lineWidth": int(defaults.get("line_width") or 2),
        "fillOpacity": int(defaults.get("fill_opacity") or 0),
        "showPoints": "never",
        "stacking": {
            "mode": (
                "normal"
                if defaults.get("stacked")
                or str(config.get("traffic_orientation")) == "stacked"
                else "none"
            ),
            "group": "A",
        },
    }
    result_defaults: dict[str, Any] = {
        "unit": unit,
        "color": {
            "mode": (
                defaults.get("color", {}).get("mode")
                if isinstance(defaults.get("color"), dict)
                else "palette-classic"
            )
            or "palette-classic"
        },
        "custom": custom,
        "thresholds": {
            "mode": "absolute",
            "steps": [
                {"color": "green", "value": None},
                {"color": "red", "value": 80},
            ],
        },
    }
    if defaults.get("decimals") != "auto":
        result_defaults["decimals"] = int(defaults.get("decimals") or 0)
    if defaults.get("min") is not None:
        result_defaults["min"] = float(defaults["min"])
    if defaults.get("max") is not None:
        result_defaults["max"] = float(defaults["max"])
    warnings = []
    overrides = []
    for override in normalized["overrides"]:
        matcher = _override_matcher(override.get("matcher") or {})
        properties = _override_properties(override.get("properties") or {})
        if matcher and properties:
            overrides.append({"matcher": matcher, "properties": properties})
        elif override:
            warnings.append(
                {
                    "field": "field_config.overrides",
                    "message": (
                        "Override de campo não pôde ser convertido "
                        "integralmente."
                    ),
                }
            )
    orientation = str(config.get("traffic_orientation") or "natural")
    if orientation == "split_zero":
        overrides.append(
            {
                "matcher": {
                    "id": "byRegexp",
                    "options": "(?i)(upload|transmit|saída|saida)",
                },
                "properties": [
                    {"id": "custom.transform", "value": "negative-Y"},
                ],
            }
        )
        result_defaults["custom"]["axisCenteredZero"] = True
    return {
        "defaults": result_defaults,
        "overrides": overrides,
    }, warnings


def _panel_options(
    widget: dict[str, Any],
    visualization: str,
) -> dict[str, Any]:
    config = widget.get("config") if isinstance(widget.get("config"), dict) else {}
    calculation = GRAFANA_CALCULATIONS.get(
        str(config.get("legend_calculation") or "last_not_null"),
        "lastNotNull",
    )
    if visualization in {"line", "area", "line_area", "time_bars"}:
        return {
            "legend": {
                "displayMode": "list",
                "placement": "bottom",
                "calcs": [calculation],
                "showLegend": True,
            },
            "tooltip": {"mode": "multi", "sort": "desc"},
        }
    if visualization in {"pie", "donut"}:
        return {
            "pieType": "donut" if visualization == "donut" else "pie",
            "legend": {
                "displayMode": "list",
                "placement": "right",
                "values": ["percent", "value"],
                "showLegend": True,
            },
            "reduceOptions": {"calcs": [calculation], "values": False},
        }
    if visualization == "horizontal_bar":
        return {"orientation": "horizontal", "legend": {"showLegend": False}}
    if visualization == "vertical_bar":
        return {"orientation": "vertical", "legend": {"showLegend": False}}
    if visualization == "bar_gauge":
        return {
            "orientation": "horizontal",
            "displayMode": "gradient",
            "reduceOptions": {"calcs": [calculation], "values": False},
        }
    if visualization == "stat":
        return {
            "orientation": "auto",
            "colorMode": "value",
            "graphMode": "area",
            "reduceOptions": {"calcs": [calculation], "values": False},
        }
    return {"showHeader": True}


def _panel(
    widget: dict[str, Any],
    index: int,
    datasource_uid: str,
    datasource_type: str,
    dashboard: dict[str, Any],
    options: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    config = widget.get("config") if isinstance(widget.get("config"), dict) else {}
    requested_visualization = infer_visualization_kind(
        str(widget.get("type") or ""),
        config,
        (
            widget.get("visualization")
            if isinstance(widget.get("visualization"), dict)
            else {}
        ),
    )
    visualization = requested_visualization
    if requested_visualization == "chart_table":
        visualization = str(
            config.get("combined_chart_kind") or "donut"
        ).strip().lower()
        if visualization not in {"horizontal_bar", "pie", "donut"}:
            visualization = "donut"
    panel_type = GRAFANA_PANEL_TYPES.get(visualization, "table")
    field_config, warnings = _field_config(widget, visualization)
    if requested_visualization == "chart_table":
        warnings.append(
            {
                "field": "visualization_kind",
                "message": (
                    "O modo gráfico + tabela foi exportado como o painel "
                    "gráfico; a tabela permanece disponível pelo mesmo "
                    "endpoint no Infinity."
                ),
            }
        )
    if visualization not in GRAFANA_PANEL_TYPES:
        warnings.append(
            {
                "field": "visualization_kind",
                "message": (
                    "Visualização '%s' exportada como tabela." % visualization
                ),
            }
        )
    appearance = (
        config.get("appearance")
        if isinstance(config.get("appearance"), dict)
        else {}
    )
    if appearance.get("custom_gradient"):
        warnings.append(
            {
                "field": "appearance.custom_gradient",
                "message": (
                    "Gradiente personalizado não possui equivalente exato "
                    "no Grafana."
                ),
            }
        )
    grid = widget.get("grid") if isinstance(widget.get("grid"), dict) else {}
    panel = {
        "id": index + 1,
        "type": panel_type,
        "title": str(widget.get("title") or "Widget %s" % (index + 1)),
        "description": str(widget.get("description") or ""),
        "gridPos": {
            "x": max(0, min(23, int(grid.get("x") or 0) * 2)),
            "y": max(0, int(grid.get("y") or 0)),
            "w": max(2, min(24, int(grid.get("w") or 6) * 2)),
            "h": max(2, int(grid.get("h") or 6)),
        },
        "datasource": {
            "type": datasource_type,
            "uid": datasource_uid,
        },
        "targets": [
            _infinity_target(
                widget,
                index,
                datasource_uid,
                datasource_type,
                dashboard,
                options,
            )
        ],
        "fieldConfig": field_config,
        "options": _panel_options(widget, visualization),
        "transparent": bool(
            (config.get("appearance") or {}).get("transparent")
            if isinstance(config.get("appearance"), dict)
            else False
        ),
        "gmj_flow": {
            "widget_id": widget.get("id"),
            "widget_key": widget.get("widget_key"),
        },
    }
    return panel, warnings


def _variable(
    name: str,
    values: list[str],
    *,
    current: str = "",
    include_all: bool = True,
) -> dict[str, Any]:
    normalized = list(
        dict.fromkeys(str(value) for value in values if str(value) != "")
    )
    if not normalized:
        normalized = ["all"]
    selected = current if current in normalized else normalized[0]
    return {
        "name": name,
        "label": name.replace("_", " ").title(),
        "type": "custom",
        "query": ",".join(normalized),
        "options": [
            {
                "text": value,
                "value": value,
                "selected": value == selected,
            }
            for value in normalized
        ],
        "current": {"text": selected, "value": selected},
        "includeAll": bool(include_all),
        "allValue": normalized[0],
        "hide": 0,
        "skipUrlSync": False,
    }


def _grafana_variables(
    dashboard: dict[str, Any],
    options: dict[str, Any],
) -> list[dict[str, Any]]:
    if not (
        options["include_variables"]
        and options["make_filters_editable"]
    ):
        return []
    prefix_filter = normalize_prefix_filter(dashboard.get("prefix_filter"))
    prefix_grouping = normalize_prefix_grouping(
        dashboard.get("prefix_grouping")
    )
    saved_filters = _dashboard_saved_filters(dashboard)
    saved_cidr = str(prefix_filter.get("cidr") or "all")
    saved_sensor = (
        str(saved_filters["sensor_ids"][0])
        if saved_filters["sensor_ids"]
        else "all"
    )
    saved_interface = (
        str(saved_filters["interfaces"][0])
        if saved_filters["interfaces"]
        else "all"
    )
    saved_zone = (
        str(saved_filters["zone"])
        if saved_filters.get("zone") is not None
        else "all"
    )
    variables = [
        _variable("prefix", [saved_cidr, "all"], current=saved_cidr),
        _variable(
            "prefix_id",
            [
                str(prefix_filter.get("prefix_id") or "all"),
                "all",
            ],
            current=str(prefix_filter.get("prefix_id") or "all"),
        ),
        _variable(
            "prefix_start",
            [str(prefix_filter.get("start_ip") or "all"), "all"],
            current=str(prefix_filter.get("start_ip") or "all"),
        ),
        _variable(
            "prefix_end",
            [str(prefix_filter.get("end_ip") or "all"), "all"],
            current=str(prefix_filter.get("end_ip") or "all"),
        ),
        _variable("prefix_group", ["all", "block", "subprefix"]),
        _variable(
            "ipv4_prefix_length",
            ["24", "20", "21", "22", "23", "25", "26", "27", "28", "32"],
            current=str(prefix_grouping["ipv4_prefix_length"]),
            include_all=False,
        ),
        _variable(
            "ipv6_prefix_length",
            ["64", "48", "56", "128"],
            current=str(prefix_grouping["ipv6_prefix_length"]),
            include_all=False,
        ),
        _variable(
            "match_side",
            ["either", "source", "destination", "both"],
            current=str(prefix_filter.get("match_side") or "either"),
            include_all=False,
        ),
        _variable(
            "address_family",
            ["both", "ipv4", "ipv6"],
            current=str(prefix_filter.get("address_family") or "both"),
            include_all=False,
        ),
        _variable(
            "sensor",
            [saved_sensor, "all"],
            current=saved_sensor,
        ),
        _variable(
            "interface",
            [saved_interface, "all"],
            current=saved_interface,
        ),
        _variable(
            "direction",
            ["both", "upload", "download"],
            current=str(saved_filters.get("direction") or "both"),
            include_all=False,
        ),
        _variable("zone", [saved_zone, "all"], current=saved_zone),
        _variable(
            "top_n",
            ["10", "5", "20", "50"],
            current="10",
            include_all=False,
        ),
    ]
    return variables


def _safe_dashboard_definition(
    dashboard: dict[str, Any],
) -> dict[str, Any]:
    allowed_dashboard_fields = {
        "name",
        "description",
        "global_filters",
        "prefix_filter",
        "prefix_grouping",
        "time_range",
        "layout_mode",
        "compact_mode",
        "refresh_interval_seconds",
    }
    definition = {
        key: _without_secrets(value)
        for key, value in dashboard.items()
        if key in allowed_dashboard_fields
    }
    definition["widgets"] = []
    for widget in (
        dashboard.get("widgets")
        if isinstance(dashboard.get("widgets"), list)
        else []
    ):
        if not isinstance(widget, dict):
            continue
        definition["widgets"].append(
            {
                key: _without_secrets(value)
                for key, value in widget.items()
                if key
                in {
                    "widget_key",
                    "type",
                    "title",
                    "description",
                    "category",
                    "config",
                    "filters",
                    "visualization",
                    "grid",
                    "collapsed",
                    "hidden",
                    "height_mode",
                    "refresh_interval_seconds",
                    "use_global_filters",
                    "use_global_time_range",
                    "inheritance",
                    "custom_time_range",
                }
            }
        )
    return definition


def _content_hash(grafana_dashboard: dict[str, Any]) -> str:
    value = copy.deepcopy(grafana_dashboard)
    metadata = value.get("gmj_flow")
    if isinstance(metadata, dict):
        metadata.pop("export_hash", None)
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def dashboard_from_grafana_export(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("JSON Grafana deve ser um objeto")
    dashboard = (
        payload.get("dashboard")
        if isinstance(payload.get("dashboard"), dict)
        else payload
    )
    metadata = (
        dashboard.get("gmj_flow")
        if isinstance(dashboard.get("gmj_flow"), dict)
        else {}
    )
    if (
        metadata.get("source") != "gmj-flow"
        or int(metadata.get("schema_version") or 0) != 1
    ):
        raise ValueError(
            "somente dashboards JSON gerados pelo GMJ-FLOW podem ser reimportados"
        )
    expected_hash = str(metadata.get("export_hash") or "")
    if not expected_hash or expected_hash != _content_hash(dashboard):
        raise ValueError("assinatura estrutural do export GMJ-FLOW é inválida")
    definition = metadata.get("dashboard_definition")
    if not isinstance(definition, dict):
        raise ValueError("dashboard_definition ausente no export GMJ-FLOW")
    if not isinstance(definition.get("widgets"), list):
        raise ValueError("widgets ausentes no export GMJ-FLOW")
    return copy.deepcopy(definition)


def export_dashboard(
    dashboard: dict[str, Any],
    *,
    grafana_version: str = "12",
    datasource_uid: str = "${DS_GMJ_FLOW}",
    datasource_type: str = "yesoreyeram-infinity-datasource",
    folder_uid: str = "gmj-flow",
    include_hidden: bool = False,
    include_saved_filters: bool = True,
    make_filters_editable: bool = False,
    include_variables: bool = True,
    include_prefixes: bool = True,
    include_top_n: bool = True,
    include_tables: bool = True,
    include_charts: bool = True,
    include_anomalies: bool = True,
    include_mitigations: bool = True,
    dashboard_title: str = "",
    dashboard_uid: str = "",
    refresh: str = "",
    default_from: str = "",
    default_to: str = "",
) -> dict[str, Any]:
    datasource = str(datasource_uid or "").strip() or "${DS_GMJ_FLOW}"
    datasource_plugin = (
        re.sub(
            r"[^A-Za-z0-9_.-]+",
            "",
            str(datasource_type or "").strip(),
        )
        or "yesoreyeram-infinity-datasource"
    )
    folder = _clean_identifier(folder_uid, "gmj-flow")
    options = {
        "include_saved_filters": bool(include_saved_filters),
        "make_filters_editable": bool(make_filters_editable),
        "include_variables": bool(include_variables),
        "include_prefixes": bool(include_prefixes),
        "include_top_n": bool(include_top_n),
        "include_tables": bool(include_tables),
        "include_charts": bool(include_charts),
        "include_anomalies": bool(include_anomalies),
        "include_mitigations": bool(include_mitigations),
    }
    panels = []
    warnings = []
    widgets = (
        dashboard.get("widgets")
        if isinstance(dashboard.get("widgets"), list)
        else []
    )
    for widget in widgets:
        if not isinstance(widget, dict):
            warnings.append(
                {
                    "widget_id": None,
                    "field": "widget",
                    "message": "Um widget inválido foi ignorado.",
                }
            )
            continue
        if widget.get("hidden") and not include_hidden:
            continue
        config = (
            widget.get("config")
            if isinstance(widget.get("config"), dict)
            else {}
        )
        source = str(config.get("source") or "").strip().lower()
        if widget.get("type") == "top_n" and not include_top_n:
            continue
        if source == "anomalies" and not include_anomalies:
            continue
        if source == "mitigations" and not include_mitigations:
            continue
        panel, panel_warnings = _panel(
            widget,
            len(panels),
            datasource,
            datasource_plugin,
            dashboard,
            options,
        )
        if panel["type"] == "table" and not include_tables:
            continue
        if panel["type"] != "table" and not include_charts:
            continue
        panels.append(panel)
        warnings.extend(
            {
                "widget_id": widget.get("id"),
                "field": warning["field"],
                "message": warning["message"],
            }
            for warning in panel_warnings
        )
    time_range = (
        dashboard.get("time_range")
        if isinstance(dashboard.get("time_range"), dict)
        else {}
    )
    minutes = max(1, int(time_range.get("minutes") or 10))
    requested_refresh = str(refresh or "").strip()
    if not re.fullmatch(r"(?:off|[1-9]\d*[smhd])", requested_refresh):
        requested_refresh = "%ss" % max(
            5,
            int(dashboard.get("refresh_interval_seconds") or 30),
        )
    requested_from = str(default_from or "").strip() or "now-%sm" % minutes
    requested_to = str(default_to or "").strip() or "now"
    exported_at = str(dashboard.get("updated_at") or "").strip()
    if not exported_at:
        exported_at = (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    grafana_dashboard = {
        "id": None,
        "uid": (
            _clean_identifier(dashboard_uid, _dashboard_uid(dashboard))
            if str(dashboard_uid or "").strip()
            else _dashboard_uid(dashboard)
        ),
        "title": str(
            dashboard_title
            or dashboard.get("name")
            or "GMJ-FLOW Dashboard"
        )[:190],
        "description": str(dashboard.get("description") or ""),
        "tags": [
            "GMJ-FLOW",
            "generated-by-gmj-flow",
            "network-observability",
        ],
        "timezone": "utc",
        "schemaVersion": 41 if str(grafana_version).startswith("12") else 39,
        "version": 0,
        "editable": True,
        "refresh": requested_refresh,
        "time": {"from": requested_from, "to": requested_to},
        "panels": panels,
        "templating": {
            "list": _grafana_variables(dashboard, options)
        },
        "annotations": {"list": []},
        "__inputs": [
            {
                "name": "DS_GMJ_FLOW",
                "label": "GMJ-FLOW API",
                "description": "Infinity datasource configurado sem credenciais no JSON.",
                "type": "datasource",
                "pluginId": datasource_plugin,
                "pluginName": datasource_plugin,
            }
        ],
        "__requires": [
            {
                "type": "grafana",
                "id": "grafana",
                "name": "Grafana",
                "version": str(grafana_version),
            },
            {
                "type": "datasource",
                "id": datasource_plugin,
                "name": datasource_plugin,
                "version": "3.x",
            },
        ],
        "gmj_flow": {
            "schema_version": 1,
            "dashboard_id": dashboard.get("id"),
            "dashboard_revision": int(
                dashboard.get("revision")
                or dashboard.get("layout_version")
                or 0
            ),
            "exported_at": exported_at,
            "source": "gmj-flow",
            "time_macros": {
                "from": "$__isoFrom()",
                "to": "$__isoTo()",
            },
            "dashboard_definition": _safe_dashboard_definition(dashboard),
        },
    }
    export_hash = _content_hash(grafana_dashboard)
    grafana_dashboard["gmj_flow"]["export_hash"] = export_hash
    return {
        "dashboard": grafana_dashboard,
        "folderUid": folder,
        "overwrite": False,
        "message": "Exportado pelo GMJ-FLOW",
        "meta": {
            "format": "grafana-dashboard",
            "grafana_version": str(grafana_version),
            "export_hash": export_hash,
            "warnings": warnings,
            "credentials_included": False,
            "publish_enabled": False,
        },
    }
