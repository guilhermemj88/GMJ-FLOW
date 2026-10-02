"""Validator semantico/de capability da DSL (AST -> ValidationResult)."""
from __future__ import annotations

import ipaddress

from . import catalog
from .ast import BooleanGroup, Condition, NotNode, RuleAst, is_builder_compatible, iter_conditions
from .errors import (
    CAPABILITY_EXPERIMENTAL,
    CAPABILITY_UNAVAILABLE,
    FIELD_NOT_ALLOWED_IN_SECTION,
    INVALID_ENUM,
    INVALID_GROUP_BY_FIELD,
    INVALID_OPERATOR,
    INVALID_RANGE,
    INVALID_RESPONSE_MODE,
    INVALID_VALUE,
    OUT_OF_RANGE,
    UNKNOWN_CAPABILITY,
    UNKNOWN_DEDUPE_PROFILE,
    UNKNOWN_FIELD,
    UNSUPPORTED_VERSION,
    ValidationResult,
    DslCapabilityError,
    DslSemanticError,
)

_SECTION_OF_NODE = {
    "match": catalog.SECTION_MATCH,
    "warning": catalog.SECTION_WARNING,
    "critical": catalog.SECTION_CRITICAL,
}


def _condition_values(condition: Condition):
    if condition.op == "BETWEEN":
        return tuple(condition.value) if isinstance(condition.value, tuple) else (condition.value,)
    if condition.op in ("IN", "NOT IN"):
        return tuple(condition.value) if isinstance(condition.value, tuple) else (condition.value,)
    return (condition.value,)


def _check_condition(result: ValidationResult, condition: Condition, section: str) -> None:
    spec = catalog.FIELDS.get(condition.field)
    if spec is None:
        result.add_error(
            UNKNOWN_FIELD,
            f"campo desconhecido: '{condition.field}'",
            line=condition.line,
            column=condition.column,
            token=condition.field,
        )
        return
    if section not in spec.sections:
        result.add_error(
            FIELD_NOT_ALLOWED_IN_SECTION,
            f"campo '{spec.name}' nao e permitido na secao {section}",
            line=condition.line,
            column=condition.column,
            token=spec.name,
            suggestion="secoes validas: " + ", ".join(spec.sections),
        )
        return
    if condition.op not in spec.operators:
        result.add_error(
            INVALID_OPERATOR,
            f"operador {condition.op!r} nao permitido para '{spec.name}'",
            line=condition.line,
            column=condition.column,
            token=condition.op,
            suggestion="operadores validos: " + ", ".join(spec.operators),
        )
    values = _condition_values(condition)
    if condition.op == "BETWEEN" and len(values) == 2:
        try:
            if values[0] > values[1]:
                result.add_error(
                    INVALID_RANGE,
                    f"BETWEEN invertido em '{spec.name}': {values[0]} > {values[1]}",
                    line=condition.line,
                    column=condition.column,
                    token=spec.name,
                )
        except TypeError:
            result.add_error(INVALID_VALUE, f"BETWEEN com valores incomparaveis em '{spec.name}'")
    for value in values:
        if value is None:
            result.add_error(INVALID_VALUE, f"valor ausente em '{spec.name}'", token=spec.name)
            continue
        if spec.type in (catalog.TYPE_PORT, catalog.TYPE_INT):
            if not isinstance(value, int) or isinstance(value, bool):
                result.add_error(INVALID_VALUE, f"'{spec.name}' exige inteiro", token=str(value))
                continue
            if value < 0:
                result.add_error(OUT_OF_RANGE, f"'{spec.name}' nao aceita valor negativo: {value}", token=str(value))
            if spec.type == catalog.TYPE_PORT and value > 65535:
                result.add_error(OUT_OF_RANGE, f"porta fora do range (0-65535): {value}", token=str(value))
        elif spec.type == catalog.TYPE_METRIC:
            try:
                if float(value) < 0:
                    result.add_error(OUT_OF_RANGE, f"'{spec.name}' nao aceita valor negativo: {value}", token=str(value))
            except (TypeError, ValueError):
                result.add_error(INVALID_VALUE, f"'{spec.name}' exige numero", token=str(value))
        elif spec.type == catalog.TYPE_ENUM:
            allowed = {item.lower() for item in spec.enum_values}
            if str(value).lower() not in allowed:
                result.add_error(INVALID_ENUM, f"valor invalido para '{spec.name}': {value}", token=str(value))
        elif spec.type in (catalog.TYPE_IP, catalog.TYPE_CIDR):
            try:
                if spec.type == catalog.TYPE_IP:
                    ipaddress.ip_address(str(value))
                else:
                    ipaddress.ip_network(str(value), strict=False)
            except ValueError:
                result.add_error(INVALID_VALUE, f"valor de rede invalido em '{spec.name}': {value}", token=str(value))
    _check_capability(result, spec, condition)


def _check_capability(result: ValidationResult, spec: catalog.FieldSpec, condition: Condition) -> None:
    if not spec.capability:
        return
    status = catalog.capability_status(spec.capability)
    if status == catalog.STATUS_UNAVAILABLE:
        result.add_error(
            CAPABILITY_UNAVAILABLE,
            f"campo '{spec.name}' exige capability indisponivel: {spec.capability}",
            line=condition.line,
            column=condition.column,
            token=spec.capability,
        )
    elif status == catalog.STATUS_EXPERIMENTAL:
        result.add_warning(
            CAPABILITY_EXPERIMENTAL,
            f"campo '{spec.name}' usa capability experimental: {spec.capability}",
            line=condition.line,
            column=condition.column,
            token=spec.capability,
        )


def _walk(result: ValidationResult, node, section: str) -> None:
    if node is None:
        return
    if isinstance(node, Condition):
        _check_condition(result, node, section)
        return
    if isinstance(node, NotNode):
        _walk(result, node.child, section)
        return
    if isinstance(node, BooleanGroup):
        for child in node.children:
            _walk(result, child, section)


def _check_requires(result: ValidationResult, requires) -> None:
    for name in requires:
        status = catalog.capability_status(name)
        if status is None:
            result.add_error(UNKNOWN_CAPABILITY, f"capability desconhecida: '{name}'", token=name)
        elif status == catalog.STATUS_UNAVAILABLE:
            result.add_error(
                CAPABILITY_UNAVAILABLE, f"capability exigida indisponivel: '{name}'", token=name
            )
        elif status == catalog.STATUS_EXPERIMENTAL:
            result.add_warning(
                CAPABILITY_EXPERIMENTAL, f"capability experimental exigida: '{name}'", token=name
            )


def validate(ast: RuleAst) -> ValidationResult:
    result = ValidationResult()
    if ast.version != catalog.AST_VERSION:
        result.add_error(UNSUPPORTED_VERSION, f"versao de AST nao suportada: {ast.version}")

    _walk(result, ast.match, catalog.SECTION_MATCH)
    _walk(result, ast.triggers.warning, catalog.SECTION_WARNING)
    _walk(result, ast.triggers.critical, catalog.SECTION_CRITICAL)

    for item in ast.evidence:
        spec = catalog.FIELDS.get(item.field)
        if spec is None:
            result.add_error(UNKNOWN_FIELD, f"campo de evidence desconhecido: '{item.field}'", token=item.field)
            continue
        if catalog.SECTION_EVIDENCE not in spec.sections:
            result.add_error(
                FIELD_NOT_ALLOWED_IN_SECTION,
                f"campo '{spec.name}' nao e permitido em EVIDENCE",
                token=spec.name,
            )

    if ast.window is not None and ast.window.seconds <= 0:
        result.add_error(OUT_OF_RANGE, "window deve ser maior que zero", token=str(ast.window.seconds))
    if ast.execution.consecutive < 1:
        result.add_error(OUT_OF_RANGE, "consecutive deve ser >= 1", token=str(ast.execution.consecutive))
    if ast.execution.cooldown_seconds is not None and ast.execution.cooldown_seconds < 0:
        result.add_error(OUT_OF_RANGE, "cooldown nao pode ser negativo", token=str(ast.execution.cooldown_seconds))

    group_by = ast.scope.group_by
    if group_by is not None:
        if group_by.preset is not None:
            if group_by.preset not in catalog.GROUP_BY_PRESETS:
                result.add_error(
                    INVALID_GROUP_BY_FIELD,
                    f"preset de group_by invalido: '{group_by.preset}'",
                    token=group_by.preset,
                    suggestion="presets: " + ", ".join(catalog.GROUP_BY_PRESETS),
                )
        for field_name in group_by.fields:
            spec = catalog.FIELDS.get(field_name)
            if spec is None or spec.name not in catalog.GROUP_BY_ALLOWED_FIELDS:
                result.add_error(
                    INVALID_GROUP_BY_FIELD,
                    f"group_by com campo nao permitido: '{field_name}'",
                    token=field_name,
                    suggestion="campos permitidos: " + ", ".join(catalog.GROUP_BY_ALLOWED_FIELDS),
                )

    if ast.scope.dedupe_profile and ast.scope.dedupe_profile not in catalog.DEDUPE_PROFILES:
        result.add_error(
            UNKNOWN_DEDUPE_PROFILE,
            f"perfil de dedupe desconhecido: '{ast.scope.dedupe_profile}'",
            token=ast.scope.dedupe_profile,
            suggestion="perfis: " + ", ".join(catalog.DEDUPE_PROFILES),
        )

    if ast.response.mode not in catalog.RESPONSE_MODES:
        result.add_error(
            INVALID_RESPONSE_MODE,
            f"modo de resposta invalido: '{ast.response.mode}'",
            token=ast.response.mode,
            suggestion="modos: " + ", ".join(catalog.RESPONSE_MODES),
        )
    for field_name, limit in (("max_auto_prefixlen_v4", 32), ("max_auto_prefixlen_v6", 128)):
        value = getattr(ast.response, field_name)
        if value is not None and not (0 <= value <= limit):
            result.add_error(OUT_OF_RANGE, f"{field_name} fora do range (0-{limit}): {value}", token=str(value))
    if ast.response.duration_seconds is not None and ast.response.duration_seconds < 0:
        result.add_error(OUT_OF_RANGE, "duration_seconds nao pode ser negativo")
    if ast.response.min_confidence_for_auto is not None and not (0 <= ast.response.min_confidence_for_auto <= 1):
        result.add_error(OUT_OF_RANGE, "min_confidence_for_auto deve estar entre 0 e 1")

    _check_requires(result, ast.requires)

    computed = is_builder_compatible(ast)
    if computed != ast.builder_compatible:
        result.add_warning(
            "BUILDER_COMPAT_MISMATCH",
            f"builder_compatible estava {ast.builder_compatible}, mas o calculo indica {computed}",
        )
    return result


def validate_text(text: str) -> ValidationResult:
    from .parser import parse

    return validate(parse(text))


def validate_or_raise(ast: RuleAst) -> None:
    """Levanta no primeiro erro (capability tem excecao propria)."""
    result = validate(ast)
    if result.errors:
        issue = result.errors[0]
        error_cls = DslCapabilityError if issue.code in (CAPABILITY_UNAVAILABLE,) else DslSemanticError
        raise error_cls(
            issue.code,
            issue.message,
            line=issue.line,
            column=issue.column,
            token=issue.token,
            suggestion=issue.suggestion,
        )
