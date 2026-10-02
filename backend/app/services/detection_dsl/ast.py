"""AST versionada da DSL de Vetores de Ataque (v1).

A AST representa a REGRA BASE. Template/Binding/Overrides ficam para uma camada
separada futura: BaseRule -> TemplateBinding -> Overrides. Nao ha template_id
aqui.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Union

from . import catalog

OP_AND = "and"
OP_OR = "or"
BOOLEAN_OPS = (OP_AND, OP_OR)


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    value: object = None
    display: str | None = field(default=None, compare=False)
    line: int | None = field(default=None, compare=False)
    column: int | None = field(default=None, compare=False)


@dataclass(frozen=True)
class NotNode:
    child: "BooleanNode"


@dataclass(frozen=True)
class BooleanGroup:
    op: str
    children: tuple["BooleanNode", ...] = ()

    def __post_init__(self) -> None:
        if self.op not in BOOLEAN_OPS:
            raise ValueError(f"operador booleano invalido: {self.op}")
        if len(self.children) < 1:
            raise ValueError("grupo booleano sem filhos")


BooleanNode = Union[Condition, NotNode, BooleanGroup]


@dataclass(frozen=True)
class Triggers:
    warning: BooleanNode | None = None
    critical: BooleanNode | None = None


@dataclass(frozen=True)
class EvidenceItem:
    field: str
    display: str | None = field(default=None, compare=False)
    line: int | None = field(default=None, compare=False)
    column: int | None = field(default=None, compare=False)


@dataclass(frozen=True)
class WindowSpec:
    seconds: int = 60
    display: str | None = field(default=None, compare=False)


@dataclass(frozen=True)
class ExecutionSpec:
    """Janela de execucao.

    Cooldown unico do sistema = cooldown de DETECCAO (intervalo para gerar nova
    anomalia da mesma regra). O motor atual guarda isso como `cooldown_minutes`
    em detection_template_rules e deriva `cooldown_seconds`. Nao duplicamos
    cooldown em window nem em response.
    """

    consecutive: int = 1
    cooldown_seconds: int | None = None
    cooldown_display: str | None = field(default=None, compare=False)


@dataclass(frozen=True)
class GroupBy:
    preset: str | None = None
    fields: tuple[str, ...] = ()

    def is_custom(self) -> bool:
        return self.preset is None and bool(self.fields)


@dataclass(frozen=True)
class ScopeSpec:
    group_by: GroupBy | None = None
    dedupe_profile: str | None = None


@dataclass(frozen=True)
class ResponseSpec:
    mode: str = "detection_only"
    response_profile_id: int | None = None
    connector_id: int | None = None
    require_protected_prefix: bool | None = None
    max_auto_prefixlen_v4: int | None = None
    max_auto_prefixlen_v6: int | None = None
    duration_seconds: int | None = None
    max_active_announcements: int | None = None
    min_confidence_for_auto: float | None = None


@dataclass(frozen=True)
class RuleAst:
    version: int = catalog.AST_VERSION
    name: str = ""
    display_name: str = ""
    enabled: bool = True
    severity: str = "critical"
    match: BooleanNode | None = None
    triggers: Triggers = field(default_factory=Triggers)
    evidence: tuple[EvidenceItem, ...] = ()
    window: WindowSpec | None = None
    execution: ExecutionSpec = field(default_factory=ExecutionSpec)
    scope: ScopeSpec = field(default_factory=ScopeSpec)
    response: ResponseSpec = field(default_factory=ResponseSpec)
    requires: tuple[str, ...] = ()
    builder_compatible: bool = True


def iter_conditions(node: BooleanNode | None):
    """Percorre a arvore devolvendo todas as Condition."""
    if node is None:
        return
    if isinstance(node, Condition):
        yield node
        return
    if isinstance(node, NotNode):
        yield from iter_conditions(node.child)
        return
    if isinstance(node, BooleanGroup):
        for child in node.children:
            yield from iter_conditions(child)


def is_builder_compatible(ast: RuleAst) -> bool:
    """TRUE por padrao; FALSE somente para feature realmente nao representavel.

    group_by.fields custom com campos validos continua compativel. O unico caso
    false nesta fase e NOT aplicado a um grupo composto (negacao de subarvore),
    que o Builder visual ainda nao representa.
    """

    def scan(node: BooleanNode | None) -> bool:
        if node is None:
            return True
        if isinstance(node, NotNode):
            return isinstance(node.child, Condition)
        if isinstance(node, BooleanGroup):
            return all(scan(child) for child in node.children)
        return True

    for node in (ast.match, ast.triggers.warning, ast.triggers.critical):
        if not scan(node):
            return False
    return True


def with_builder_compatibility(ast: RuleAst) -> RuleAst:
    compatible = is_builder_compatible(ast)
    if compatible == ast.builder_compatible:
        return ast
    return RuleAst(
        version=ast.version,
        name=ast.name,
        display_name=ast.display_name,
        enabled=ast.enabled,
        severity=ast.severity,
        match=ast.match,
        triggers=ast.triggers,
        evidence=ast.evidence,
        window=ast.window,
        execution=ast.execution,
        scope=ast.scope,
        response=ast.response,
        requires=ast.requires,
        builder_compatible=compatible,
    )


def semantic_equal(left: RuleAst, right: RuleAst) -> bool:
    """Igualdade semantica (display/posicao ja sao compare=False nos nos)."""
    return left == right
