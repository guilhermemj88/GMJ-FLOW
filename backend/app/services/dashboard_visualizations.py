from __future__ import annotations

import copy
import re
from typing import Any


CALCULATIONS = {
    "current",
    "last",
    "last_not_null",
    "mean",
    "max",
    "min",
    "total",
    "difference",
}
LEGEND_CALCULATIONS = CALCULATIONS - {"current"}
TRAFFIC_ORIENTATIONS = {"positive_both", "split_zero", "stacked"}
FIELD_MATCH_TYPES = {"field_name", "direction", "regex", "metric"}
LAYOUT_MODES = {"custom", "auto_grid"}
COMPACT_MODES = {"vertical", "none"}

RANKING_VISUALIZATIONS = (
    "table",
    "horizontal_bar",
    "vertical_bar",
    "pie",
    "donut",
    "bar_gauge",
    "chart_table",
    "stat",
)
TIMESERIES_VISUALIZATIONS = (
    "line",
    "area",
    "time_bars",
    "line_area",
    "stat",
)
TABLE_VISUALIZATIONS = ("table",)
STATUS_VISUALIZATIONS = ("status", "table", "stat")

VISUALIZATION_ALIASES = {
    "bar": "vertical_bar",
    "number": "stat",
    "stacked_area": "area",
}
LEGACY_VISUALIZATION_TYPES = {
    "vertical_bar": "bar",
    "stat": "number",
}


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _number(
    value: Any,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        result = float(default)
    return max(minimum, min(maximum, result))


def _optional_number(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _color(value: Any, default: str) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if re.fullmatch(r"#[0-9a-f]{6}", normalized) else default


def data_kind_for_widget(widget_type: str) -> str:
    return {
        "top_n": "ranking_snapshot",
        "timeseries": "timeseries",
        "kpi": "stat",
        "status_list": "status",
        "recent_events": "table",
    }.get(str(widget_type or "").strip().lower(), "table")


def visualization_choices(data_kind: str) -> tuple[str, ...]:
    choices = {
        "ranking_snapshot": RANKING_VISUALIZATIONS,
        "timeseries": TIMESERIES_VISUALIZATIONS,
        "stat": ("stat",),
        "status": STATUS_VISUALIZATIONS,
        "table": TABLE_VISUALIZATIONS,
    }.get(data_kind, TABLE_VISUALIZATIONS)
    return tuple(choices)


def infer_visualization_kind(
    widget_type: str,
    config: dict[str, Any],
    visualization: dict[str, Any],
) -> str:
    data_kind = data_kind_for_widget(widget_type)
    candidate = str(
        config.get("visualization_kind")
        or visualization.get("visualization_kind")
        or visualization.get("type")
        or config.get("visualization")
        or (
            "line"
            if data_kind == "timeseries"
            else "stat"
            if data_kind == "stat"
            else "status"
            if data_kind == "status"
            else "table"
        )
    ).strip().lower()
    candidate = VISUALIZATION_ALIASES.get(candidate, candidate)
    return (
        candidate
        if candidate in visualization_choices(data_kind)
        else visualization_choices(data_kind)[0]
    )


def default_field_config(
    metric: str,
    appearance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    style = appearance if isinstance(appearance, dict) else {}
    unit = {
        "bps": "bps",
        "bits_s": "bps",
        "pps": "pps",
        "packets_s": "pps",
        "fps": "flows/s",
    }.get(str(metric or "").lower(), "short")
    return {
        "defaults": {
            "unit": unit,
            "decimals": "auto",
            "color": {"mode": "palette-classic"},
            "line_width": _number(style.get("line_width"), 2, 1, 5),
            "fill_opacity": round(
                _number(style.get("area_opacity"), 0.22, 0, 1) * 100,
                2,
            ),
            "show_points": "never",
            "null_value": "null",
            "min": None,
            "max": None,
            "smooth": _bool(style.get("smooth_lines"), True),
            "stacked": False,
        },
        "overrides": [],
    }


def normalize_field_config(
    value: Any,
    metric: str,
    appearance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    baseline = default_field_config(metric, appearance)
    source = value if isinstance(value, dict) else {}
    source_defaults = (
        source.get("defaults")
        if isinstance(source.get("defaults"), dict)
        else {}
    )
    decimals: int | str = source_defaults.get("decimals", "auto")
    if decimals != "auto":
        try:
            decimals = max(0, min(8, int(decimals)))
        except (TypeError, ValueError):
            decimals = "auto"
    show_points = str(
        source_defaults.get("show_points")
        or baseline["defaults"]["show_points"]
    ).strip().lower()
    if show_points not in {"auto", "always", "never"}:
        show_points = baseline["defaults"]["show_points"]
    null_value = str(
        source_defaults.get("null_value")
        or baseline["defaults"]["null_value"]
    ).strip().lower()
    if null_value not in {"null", "zero", "connected"}:
        null_value = baseline["defaults"]["null_value"]
    source_color = (
        source_defaults.get("color")
        if isinstance(source_defaults.get("color"), dict)
        else baseline["defaults"]["color"]
    )
    color_mode = str(source_color.get("mode") or "palette-classic").strip()
    if color_mode not in {
        "palette-classic",
        "fixed",
        "thresholds",
        "continuous-GrYlRd",
    }:
        color_mode = "palette-classic"
    normalized_color = {"mode": color_mode}
    if color_mode == "fixed":
        normalized_color["fixedColor"] = _color(
            source_color.get("fixedColor"),
            "#2563eb",
        )
    minimum = _optional_number(source_defaults.get("min"))
    maximum = _optional_number(source_defaults.get("max"))
    if minimum is not None and maximum is not None and minimum > maximum:
        minimum, maximum = maximum, minimum
    defaults = {
        **baseline["defaults"],
        "unit": str(
            source_defaults.get("unit")
            or baseline["defaults"]["unit"]
        ).strip()[:32],
        "decimals": decimals,
        "color": normalized_color,
        "line_width": _number(
            source_defaults.get("line_width"),
            baseline["defaults"]["line_width"],
            1,
            5,
        ),
        "fill_opacity": _number(
            source_defaults.get("fill_opacity"),
            baseline["defaults"]["fill_opacity"],
            0,
            100,
        ),
        "show_points": show_points,
        "null_value": null_value,
        "min": minimum,
        "max": maximum,
        "smooth": _bool(
            source_defaults.get("smooth"),
            baseline["defaults"]["smooth"],
        ),
        "stacked": _bool(
            source_defaults.get("stacked"),
            baseline["defaults"]["stacked"],
        ),
    }
    overrides = []
    source_overrides = (
        source.get("overrides")
        if isinstance(source.get("overrides"), list)
        else []
    )
    if len(source_overrides) > 30:
        raise ValueError("field_config aceita no máximo 30 overrides")
    for item in source_overrides:
        if not isinstance(item, dict):
            raise ValueError("override de campo inválido")
        matcher = item.get("matcher")
        properties = item.get("properties")
        if not isinstance(matcher, dict) or not isinstance(properties, dict):
            raise ValueError("override precisa de matcher e properties")
        match_type = str(matcher.get("type") or "").strip().lower()
        match_value = str(matcher.get("value") or "").strip()
        if match_type not in FIELD_MATCH_TYPES or not match_value:
            raise ValueError("matcher de override inválido")
        if match_type == "regex":
            if len(match_value) > 160:
                raise ValueError("regex de override excede 160 caracteres")
            try:
                re.compile(match_value)
            except re.error:
                raise ValueError("regex de override inválida")
        normalized_properties: dict[str, Any] = {}
        if "color" in properties:
            normalized_properties["color"] = _color(
                properties.get("color"),
                "#2563eb",
            )
        if "line_width" in properties:
            normalized_properties["line_width"] = _number(
                properties.get("line_width"),
                defaults["line_width"],
                1,
                5,
            )
        if "fill_opacity" in properties:
            normalized_properties["fill_opacity"] = _number(
                properties.get("fill_opacity"),
                defaults["fill_opacity"],
                0,
                100,
            )
        for boolean_key in ("smooth", "visible", "negative_y"):
            if boolean_key in properties:
                normalized_properties[boolean_key] = _bool(
                    properties.get(boolean_key)
                )
        overrides.append(
            {
                "matcher": {
                    "type": match_type,
                    "value": match_value,
                },
                "properties": normalized_properties,
            }
        )
    return {"defaults": defaults, "overrides": overrides}


def normalize_visualization_config(
    widget_type: str,
    config: dict[str, Any],
    visualization: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized_config = copy.deepcopy(config)
    normalized_visualization = copy.deepcopy(visualization)
    data_kind = data_kind_for_widget(widget_type)
    visualization_kind = infer_visualization_kind(
        widget_type,
        normalized_config,
        normalized_visualization,
    )
    default_calculation = (
        "current" if data_kind == "ranking_snapshot" else "last_not_null"
    )
    calculation = str(
        normalized_config.get("calculation") or default_calculation
    ).strip().lower()
    if calculation not in CALCULATIONS:
        calculation = default_calculation
    legend_calculation = str(
        normalized_config.get("legend_calculation") or "last_not_null"
    ).strip().lower()
    if legend_calculation not in LEGEND_CALCULATIONS:
        legend_calculation = "last_not_null"
    orientation = str(
        normalized_config.get("traffic_orientation") or "positive_both"
    ).strip().lower()
    if orientation not in TRAFFIC_ORIENTATIONS:
        orientation = "positive_both"
    appearance = (
        normalized_config.get("appearance")
        if isinstance(normalized_config.get("appearance"), dict)
        else {}
    )
    metric = str(normalized_config.get("metric") or "count").strip().lower()
    normalized_config.update(
        {
            "data_kind": data_kind,
            "visualization_kind": visualization_kind,
            "calculation": calculation,
            "legend_calculation": legend_calculation,
            "traffic_orientation": orientation,
            "axis_show_negative_sign": _bool(
                normalized_config.get("axis_show_negative_sign"),
                False,
            ),
            "field_config": normalize_field_config(
                normalized_config.get("field_config"),
                metric,
                appearance,
            ),
        }
    )
    normalized_visualization.update(
        {
            "type": LEGACY_VISUALIZATION_TYPES.get(
                visualization_kind,
                visualization_kind,
            ),
            "visualization_kind": visualization_kind,
            "data_kind": data_kind,
        }
    )
    return normalized_config, normalized_visualization
