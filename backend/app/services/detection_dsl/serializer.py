"""AST v1 -> texto canonico da DSL (deterministico)."""
from __future__ import annotations

from . import catalog
from .ast import BooleanGroup, Condition, NotNode, RuleAst
from .units import format_quantity

_PREC = {"or": 1, "and": 2, "not": 3, "cond": 4}


def _field_text(name: str) -> str:
    spec = catalog.FIELDS.get(name)
    return spec.display_name if spec else name


def _format_value(spec: catalog.FieldSpec | None, value, display: str | None = None) -> str:
    # O display so vale para metricas (unidade amigavel). Para enum/IP/CIDR/porta
    # o texto canonico do AST sempre vence (ex.: transmits -> outbound).
    if spec is not None and spec.type == catalog.TYPE_METRIC:
        if display:
            return display
        return format_quantity(value)
    if display and spec is None:
        return display
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _condition_text(condition: Condition) -> str:
    spec = catalog.FIELDS.get(condition.field)
    field = _field_text(condition.field)
    if condition.op == "BETWEEN":
        low, high = condition.value if isinstance(condition.value, tuple) else (condition.value, None)
        return f"{field} BETWEEN {_format_value(spec, low)} AND {_format_value(spec, high)}"
    if condition.op in ("IN", "NOT IN"):
        values = condition.value if isinstance(condition.value, tuple) else (condition.value,)
        rendered = ", ".join(_format_value(spec, item) for item in values)
        return f"{field} {condition.op} ({rendered})"
    return f"{field} {condition.op} {_format_value(spec, condition.value, condition.display)}"


def render_node(node, parent_prec: int = 0) -> str:
    if isinstance(node, Condition):
        return _condition_text(node)
    if isinstance(node, NotNode):
        inner = render_node(node.child, _PREC["not"])
        text = f"NOT {inner}"
        return f"({text})" if _PREC["not"] < parent_prec else text
    if isinstance(node, BooleanGroup):
        joiner = " AND " if node.op == "and" else " OR "
        prec = _PREC[node.op]
        text = joiner.join(render_node(child, prec) for child in node.children)
        return f"({text})" if prec < parent_prec else text
    raise TypeError(f"no booleano invalido: {node!r}")


def _duration_text(seconds: int, display: str | None = None) -> str:
    if display:
        return display
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def serialize(ast: RuleAst) -> str:
    """Gera texto canonico: mesma AST => mesmo texto."""
    blocks: list[str] = []
    header: list[str] = []
    if ast.name:
        header.append(f"RULE {ast.name}")
    if ast.display_name:
        header.append(f'DISPLAY_NAME "{ast.display_name}"')
    if not ast.enabled:
        header.append("ENABLED no")
    if ast.severity != "critical":
        header.append(f"SEVERITY {ast.severity}")

    if ast.match is not None:
        blocks.append("MATCH\n" + render_node(ast.match))
    if ast.triggers.warning is not None:
        blocks.append("WARNING\n" + render_node(ast.triggers.warning))
    if ast.triggers.critical is not None:
        blocks.append("CRITICAL\n" + render_node(ast.triggers.critical))
    if ast.evidence:
        blocks.append("EVIDENCE\n" + ", ".join(_field_text(item.field) for item in ast.evidence))

    advanced: list[str] = []
    if ast.window is not None:
        advanced.append(f"window = {_duration_text(ast.window.seconds, ast.window.display)}")
    advanced.append(f"consecutive = {ast.execution.consecutive}")
    if ast.execution.cooldown_seconds is not None:
        advanced.append(
            "cooldown = "
            + _duration_text(ast.execution.cooldown_seconds, ast.execution.cooldown_display)
        )
    if ast.scope.group_by is not None:
        group_by = ast.scope.group_by
        value = group_by.preset if group_by.preset else ", ".join(group_by.fields)
        advanced.append(f"group_by = {value}")
    if ast.scope.dedupe_profile:
        advanced.append(f"dedupe = {ast.scope.dedupe_profile}")
    if ast.requires:
        advanced.append("requires = " + ", ".join(ast.requires))
    blocks.append("ADVANCED\n" + "\n".join(advanced))

    response: list[str] = [f"mode = {ast.response.mode}"]
    if ast.response.response_profile_id is not None:
        response.append(f"response_profile_id = {ast.response.response_profile_id}")
    if ast.response.connector_id is not None:
        response.append(f"connector_id = {ast.response.connector_id}")
    if ast.response.require_protected_prefix is not None:
        response.append(
            "require_protected_prefix = " + ("yes" if ast.response.require_protected_prefix else "no")
        )
    if ast.response.max_auto_prefixlen_v4 is not None:
        response.append(f"max_auto_prefixlen_v4 = {ast.response.max_auto_prefixlen_v4}")
    if ast.response.max_auto_prefixlen_v6 is not None:
        response.append(f"max_auto_prefixlen_v6 = {ast.response.max_auto_prefixlen_v6}")
    if ast.response.duration_seconds is not None:
        response.append(f"duration_seconds = {ast.response.duration_seconds}")
    if ast.response.max_active_announcements is not None:
        response.append(f"max_active_announcements = {ast.response.max_active_announcements}")
    if ast.response.min_confidence_for_auto is not None:
        response.append(f"min_confidence_for_auto = {ast.response.min_confidence_for_auto}")
    blocks.append("RESPONSE\n" + "\n".join(response))

    text = "\n\n".join(blocks)
    if header:
        text = "\n".join(header) + "\n\n" + text
    return text.strip() + "\n"
