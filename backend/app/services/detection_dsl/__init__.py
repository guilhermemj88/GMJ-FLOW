"""DSL isolada de Vetores de Ataque (Fase 3A).

Pacote puro (apenas stdlib) com AST versionada, catalogo unico, parser,
serializer e validator. NAO integra com banco, detector, UI ou mitigacao.
"""
from __future__ import annotations

from .ast import (
    BooleanGroup,
    Condition,
    EvidenceItem,
    ExecutionSpec,
    GroupBy,
    NotNode,
    ResponseSpec,
    RuleAst,
    ScopeSpec,
    Triggers,
    WindowSpec,
    is_builder_compatible,
    iter_conditions,
    semantic_equal,
    with_builder_compatibility,
)
from .catalog import (
    AST_VERSION,
    CAPABILITIES,
    DEDUPE_PROFILES,
    EXAMPLES,
    FIELDS,
    GOLDEN_DNS_RULE,
    GOLDEN_NTP_RULE,
    GROUP_BY_ALLOWED_FIELDS,
    GROUP_BY_PRESETS,
    RESPONSE_MODES,
    SECTIONS,
    catalog_json,
)
from .errors import (
    DslCapabilityError,
    DslSemanticError,
    DslSyntaxError,
    RuleDslError,
    ValidationIssue,
    ValidationResult,
)
from .parser import parse, parse_and_validate, tokenize
from .serializer import render_node, serialize
from .units import format_quantity, parse_duration, parse_quantity
from .validator import validate, validate_or_raise, validate_text

__all__ = [
    "AST_VERSION",
    "BooleanGroup",
    "CAPABILITIES",
    "Condition",
    "DEDUPE_PROFILES",
    "DslCapabilityError",
    "DslSemanticError",
    "DslSyntaxError",
    "EXAMPLES",
    "EvidenceItem",
    "ExecutionSpec",
    "FIELDS",
    "GOLDEN_DNS_RULE",
    "GOLDEN_NTP_RULE",
    "GROUP_BY_ALLOWED_FIELDS",
    "GROUP_BY_PRESETS",
    "GroupBy",
    "NotNode",
    "RESPONSE_MODES",
    "ResponseSpec",
    "RuleAst",
    "RuleDslError",
    "SECTIONS",
    "ScopeSpec",
    "Triggers",
    "ValidationIssue",
    "ValidationResult",
    "WindowSpec",
    "catalog_json",
    "format_quantity",
    "is_builder_compatible",
    "iter_conditions",
    "parse",
    "parse_and_validate",
    "parse_duration",
    "parse_quantity",
    "render_node",
    "semantic_equal",
    "serialize",
    "tokenize",
    "validate",
    "validate_or_raise",
    "validate_text",
    "with_builder_compatibility",
]
