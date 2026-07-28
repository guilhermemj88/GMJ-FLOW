from __future__ import annotations

import hashlib
import json
import re
from typing import Any

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
    metric = str(config.get("metric") or "").strip().lower()
    if widget.get("type") == "top_n":
        dimension = str(config.get("dimension") or "").strip().lower()
        direction = str(config.get("direction") or "both").strip().lower()
        if dimension in {"asn_src", "src_asn"} and direction != "upload":
            return "top_download_origins"
        if dimension in {"asn_dst", "dst_asn"} and direction != "download":
            return "top_upload_destinations"
        if dimension in {"proto", "protocol"}:
            return "top_protocols"
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


def _target_body(widget: dict[str, Any], query_kind: str) -> dict[str, Any]:
    config = widget.get("config") if isinstance(widget.get("config"), dict) else {}
    filters = {
        "sensor_ids": [],
        "interfaces": [],
        "protocols": [],
        "direction": str(config.get("direction") or "both").lower(),
    }
    body: dict[str, Any] = {
        "metric": _metric_for_widget(widget),
        "from": "${__timeFrom:date:iso}",
        "to": "${__timeTo:date:iso}",
        "filters": filters,
        "calculation": str(config.get("calculation") or "last_not_null"),
        "include_partial_bucket": bool(
            config.get("include_partial_bucket", False)
        ),
        "timezone": "UTC",
        "format": "json",
    }
    if query_kind == "ranking":
        body["top_n"] = max(1, min(100, int(config.get("limit") or 10)))
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
) -> dict[str, Any]:
    query_kind = _query_kind(widget)
    body = _target_body(widget, query_kind)
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
            "type": "yesoreyeram-infinity-datasource",
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
            "type": "yesoreyeram-infinity-datasource",
            "uid": datasource_uid,
        },
        "targets": [_infinity_target(widget, index, datasource_uid)],
        "fieldConfig": field_config,
        "options": _panel_options(widget, visualization),
        "transparent": bool(
            (config.get("appearance") or {}).get("transparent")
            if isinstance(config.get("appearance"), dict)
            else False
        ),
    }
    return panel, warnings


def export_dashboard(
    dashboard: dict[str, Any],
    *,
    grafana_version: str = "12",
    datasource_uid: str = "${DS_GMJ_FLOW}",
    folder_uid: str = "gmj-flow",
    include_hidden: bool = False,
) -> dict[str, Any]:
    datasource = str(datasource_uid or "").strip() or "${DS_GMJ_FLOW}"
    folder = _clean_identifier(folder_uid, "gmj-flow")
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
        panel, panel_warnings = _panel(widget, len(panels), datasource)
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
    grafana_dashboard = {
        "id": None,
        "uid": _dashboard_uid(dashboard),
        "title": str(dashboard.get("name") or "GMJ-FLOW Dashboard"),
        "description": str(dashboard.get("description") or ""),
        "tags": ["gmj-flow", "network-observability"],
        "timezone": "utc",
        "schemaVersion": 41 if str(grafana_version).startswith("12") else 39,
        "version": 0,
        "editable": True,
        "refresh": "%ss" % max(
            5,
            int(dashboard.get("refresh_interval_seconds") or 30),
        ),
        "time": {"from": "now-%sm" % minutes, "to": "now"},
        "panels": panels,
        "templating": {"list": []},
        "annotations": {"list": []},
        "__inputs": [
            {
                "name": "DS_GMJ_FLOW",
                "label": "GMJ-FLOW API",
                "description": "Infinity datasource configurado sem credenciais no JSON.",
                "type": "datasource",
                "pluginId": "yesoreyeram-infinity-datasource",
                "pluginName": "Infinity",
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
                "id": "yesoreyeram-infinity-datasource",
                "name": "Infinity",
                "version": "3.x",
            },
        ],
    }
    export_hash = hashlib.sha256(
        _stable_json(grafana_dashboard).encode("utf-8")
    ).hexdigest()
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
