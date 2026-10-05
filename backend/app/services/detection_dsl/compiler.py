"""Compilador de expressoes MATCH (DSL) -> fragmento WHERE do ClickHouse.

FASE 2 - Flow Search por expressao. Este modulo e PURO (apenas stdlib + o proprio
pacote): nao importa banco, FastAPI nem o detector. Quem usa fornece um
`FlowSearchDialect` com as funcoes/mapa reais do `flow_raw` (helpers existentes
do backend), mantendo a regra de ouro:

NUNCA concatenar texto do usuario no SQL. Todo valor vira parametro vinculado
(`{nome:Tipo}`) resolvido pelo driver do ClickHouse.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Callable, Mapping

from . import catalog
from .ast import BooleanGroup, Condition, NotNode
from .errors import DslSyntaxError, RuleDslError
from .parser import parse_expression
from .serializer import render_node
from .validator import validate_node

# --- Limites de protecao de custo (nao alteram range/limit legados) ---------
MAX_EXPRESSION_LENGTH = 2000
MAX_AST_DEPTH = 12
MAX_CONDITIONS = 40
MAX_IN_LIST = 64
MAX_REGEX_LENGTH = 200

# Redes internas default para `direction` (inbound = destino interno,
# outbound = origem interna). Sobrescrevivel por variavel de ambiente no
# backend (GMJFLOW_FLOW_INTERNAL_CIDRS).
DEFAULT_INTERNAL_NETWORKS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
    "::1/128",
)

PROTO_NUMBERS: dict[str, int] = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "esp": 50,
    "icmp6": 58,
    "icmpv6": 58,
}

TCP_FLAG_BITS: dict[str, int] = {
    "fin": 0x01,
    "syn": 0x02,
    "rst": 0x04,
    "psh": 0x08,
    "ack": 0x10,
    "urg": 0x20,
    "ece": 0x40,
    "cwr": 0x80,
}

# Campo do dicionario -> (coluna fisica, tipo ClickHouse).
FIELD_COLUMNS: dict[str, tuple[str, str]] = {
    "protocol": ("proto", "UInt8"),
    "src_ip": ("src_ip", "String"),
    "dst_ip": ("dst_ip", "String"),
    "src_cidr": ("src_ip", "String"),
    "dst_cidr": ("dst_ip", "String"),
    "src_port": ("src_port", "UInt16"),
    "dst_port": ("dst_port", "UInt16"),
    "tcp_flags": ("tcp_flags", "UInt16"),
    "sensor": ("sensor", "String"),
    "exporter_ip": ("exporter_ip", "String"),
    "input_if": ("input_if", "UInt32"),
    "output_if": ("output_if", "UInt32"),
    "src_asn": ("src_asn", "UInt32"),
    "dst_asn": ("dst_asn", "UInt32"),
    "bytes": ("bytes", "UInt64"),
    "packets": ("packets", "UInt64"),
    "flow_count": ("flow_count", "UInt64"),
}

# Campos que existem no dicionario (MATCH) mas nao tem coluna no flow_raw.
UNAVAILABLE_FIELDS: dict[str, str] = {
    "sensor_id": "o Flow Search filtra por nome em 'sensor' ou pelo parametro legado sensor_id",
    "icmp_type": "flow_raw nao possui a coluna icmp_type",
    "icmp_code": "flow_raw nao possui a coluna icmp_code",
}

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class CompileError(ValueError):
    """Erro estruturado de compilacao (nunca contem SQL do usuario)."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        field: str | None = None,
        token: str | None = None,
        suggestion: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field
        self.token = token
        self.suggestion = suggestion

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.field:
            data["field"] = self.field
        if self.token:
            data["token"] = self.token
        if self.suggestion:
            data["suggestion"] = self.suggestion
        return data


@dataclass(frozen=True)
class FlowSearchDialect:
    """Ponte entre o dicionario da DSL e o schema fisico do flow_raw.

    `column_types`: colunas existentes em flow_raw (nome -> tipo).
    `ip_param`: converte um IP para a forma armazenada (ex.: `::ffff:` para IPv6).
    `cidr_param`: idem para CIDR.
    `decoder_condition`: condicao SQL segura (sem parametros) para um decoder.
    `internal_networks`: redes usadas por `direction` (inbound/outbound).
    """

    column_types: Mapping[str, str]
    ip_param: Callable[[str], str]
    cidr_param: Callable[[str], str]
    decoder_condition: Callable[[str], str]
    internal_networks: tuple[str, ...] = DEFAULT_INTERNAL_NETWORKS


@dataclass
class CompiledMatch:
    where: str
    params: dict[str, Any]
    canonical_expression: str
    conditions: int
    fields: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "where": self.where,
            "params": self.params,
            "canonical_expression": self.canonical_expression,
            "conditions": self.conditions,
            "fields": list(self.fields),
        }


def count_conditions(node: Any) -> int:
    if node is None:
        return 0
    if isinstance(node, Condition):
        return 1
    if isinstance(node, NotNode):
        return count_conditions(node.child)
    if isinstance(node, BooleanGroup):
        return sum(count_conditions(child) for child in node.children)
    return 0


def ast_depth(node: Any) -> int:
    if node is None:
        return 0
    if isinstance(node, Condition):
        return 1
    if isinstance(node, NotNode):
        return 1 + ast_depth(node.child)
    if isinstance(node, BooleanGroup):
        return 1 + max((ast_depth(child) for child in node.children), default=0)
    return 0


def _json_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    return value


def summarize(node: Any) -> dict[str, Any] | None:
    """AST resumida e serializavel (para preview/validacao na UI)."""
    if node is None:
        return None
    if isinstance(node, Condition):
        return {
            "type": "condition",
            "field": node.field,
            "op": node.op,
            "value": _json_value(node.value),
        }
    if isinstance(node, NotNode):
        return {"type": "not", "child": summarize(node.child)}
    if isinstance(node, BooleanGroup):
        return {"type": node.op, "children": [summarize(child) for child in node.children]}
    return None


class _Compiler:
    def __init__(self, dialect: FlowSearchDialect, prefix: str) -> None:
        self.dialect = dialect
        self.prefix = prefix
        self.params: dict[str, Any] = {}
        self.counter = 0
        self.conditions = 0
        self.fields: list[str] = []

    # -- utilitarios --------------------------------------------------------
    def param(self, value: Any, type_: str) -> str:
        key = f"{self.prefix}_{self.counter}"
        self.counter += 1
        self.params[key] = value
        return f"{{{key}:{type_}}}"

    def column(self, field: str) -> tuple[str, str]:
        if field in UNAVAILABLE_FIELDS:
            raise CompileError(
                "FIELD_NOT_AVAILABLE_IN_FLOW_SEARCH",
                f"campo '{field}' nao esta disponivel no Flow Search",
                field=field,
                suggestion=UNAVAILABLE_FIELDS[field],
            )
        mapping = FIELD_COLUMNS.get(field)
        if mapping is None:
            raise CompileError(
                "FIELD_NOT_AVAILABLE_IN_FLOW_SEARCH",
                f"campo '{field}' nao pode ser compilado para o Flow Search",
                field=field,
            )
        column, type_ = mapping
        if column not in self.dialect.column_types:
            raise CompileError(
                "FIELD_NOT_AVAILABLE_IN_FLOW_SEARCH",
                f"campo '{field}' exige a coluna '{column}', ausente em flow_raw",
                field=field,
            )
        return column, type_

    def array_param(self, values: list[Any], type_: str) -> str:
        return self.param(list(values), f"Array({type_})")

    # -- arvore -------------------------------------------------------------
    def build(self, node: Any, depth: int = 1) -> str:
        if depth > MAX_AST_DEPTH:
            raise CompileError(
                "AST_TOO_DEEP",
                f"expressao excede a profundidade maxima ({MAX_AST_DEPTH})",
                suggestion="simplifique o aninhamento de AND/OR/NOT",
            )
        if isinstance(node, Condition):
            self.conditions += 1
            if self.conditions > MAX_CONDITIONS:
                raise CompileError(
                    "TOO_MANY_CONDITIONS",
                    f"expressao excede o limite de {MAX_CONDITIONS} condicoes",
                )
            self.fields.append(node.field)
            return self.condition(node)
        if isinstance(node, NotNode):
            return f"NOT ({self.build(node.child, depth + 1)})"
        if isinstance(node, BooleanGroup):
            joiner = " AND " if node.op == "and" else " OR "
            parts = [self.build(child, depth + 1) for child in node.children]
            return "(" + joiner.join(parts) + ")"
        raise CompileError("INVALID_AST", f"no booleano invalido: {type(node).__name__}")

    # -- condicoes ----------------------------------------------------------
    def condition(self, node: Condition) -> str:
        field = node.field
        op = node.op
        values = self._values(node)
        if field == "direction":
            return self._enum_membership(op, values, self._direction_atom)
        if field == "decoder":
            return self._enum_membership(op, values, self._decoder_atom)
        if field == "protocol":
            return self._protocol(op, values)
        if field == "tcp_flags":
            return self._tcp_flags(op, values)
        if field == "sensor":
            return self._text(op, values)
        if field in ("src_ip", "dst_ip", "exporter_ip"):
            column, _ = self.column(field)
            return self._ip(op, column, values)
        if field in ("src_cidr", "dst_cidr"):
            column, _ = self.column(field)
            return self._cidr(op, column, values)
        if field == "interface_if_index":
            return self._interface(op, field, values)
        column, type_ = self.column(field)
        return self._numeric(op, column, type_, values)

    @staticmethod
    def _values(node: Condition) -> list[Any]:
        if node.op in (catalog.OP_IN, catalog.OP_NOT_IN, catalog.OP_BETWEEN):
            return list(node.value) if isinstance(node.value, tuple) else [node.value]
        return [node.value]

    # -- atoms ---------------------------------------------------------------
    def _numeric(self, op: str, column: str, type_: str, values: list[Any]) -> str:
        numbers = [int(value) for value in values]
        if op == catalog.OP_BETWEEN:
            low, high = self.param(numbers[0], type_), self.param(numbers[1], type_)
            return f"({column} >= {low} AND {column} <= {high})"
        if op == catalog.OP_IN:
            self._check_in(values)
            return f"{column} IN {self.array_param(numbers, type_)}"
        if op == catalog.OP_NOT_IN:
            self._check_in(values)
            return f"{column} NOT IN {self.array_param(numbers, type_)}"
        if op == catalog.OP_NE:
            return f"{column} != {self.param(numbers[0], type_)}"
        if op == catalog.OP_GT:
            return f"{column} > {self.param(numbers[0], type_)}"
        if op == catalog.OP_GE:
            return f"{column} >= {self.param(numbers[0], type_)}"
        if op == catalog.OP_LT:
            return f"{column} < {self.param(numbers[0], type_)}"
        if op == catalog.OP_LE:
            return f"{column} <= {self.param(numbers[0], type_)}"
        return f"{column} = {self.param(numbers[0], type_)}"

    def _check_in(self, values: list[Any]) -> None:
        if len(values) > MAX_IN_LIST:
            raise CompileError(
                "IN_LIST_TOO_LARGE",
                f"lista IN excede o limite de {MAX_IN_LIST} valores",
            )

    def _text(self, op: str, values: list[Any]) -> str:
        column, _ = self.column("sensor")
        if op == catalog.OP_MATCHES:
            pattern = str(values[0])
            if len(pattern) > MAX_REGEX_LENGTH:
                raise CompileError(
                    "REGEX_TOO_LONG",
                    f"regex excede o limite de {MAX_REGEX_LENGTH} caracteres",
                    field="sensor",
                )
            try:
                re.compile(pattern)
            except re.error as exc:
                raise CompileError(
                    "INVALID_REGEX",
                    f"regex invalida: {exc}",
                    field="sensor",
                ) from exc
            return f"match({column}, {self.param(pattern, 'String')})"
        texts = [str(value) for value in values]
        if op == catalog.OP_IN:
            self._check_in(values)
            return f"{column} IN {self.array_param(texts, 'String')}"
        if op == catalog.OP_NOT_IN:
            self._check_in(values)
            return f"{column} NOT IN {self.array_param(texts, 'String')}"
        if op == catalog.OP_NE:
            return f"{column} != {self.param(texts[0], 'String')}"
        return f"{column} = {self.param(texts[0], 'String')}"

    def _ip(self, op: str, column: str, values: list[Any]) -> str:
        if op == catalog.OP_NE:
            return f"NOT ({self._ip_atom(column, values[0])})"
        if op == catalog.OP_NOT_IN:
            self._check_in(values)
            return "NOT (" + " OR ".join(self._ip_atom(column, value) for value in values) + ")"
        if op == catalog.OP_IN:
            self._check_in(values)
            return "(" + " OR ".join(self._ip_atom(column, value) for value in values) + ")"
        return self._ip_atom(column, values[0])

    def _ip_atom(self, column: str, value: Any) -> str:
        text = str(value).strip()
        if "/" in text:
            return self._cidr_atom(column, text)
        return f"toString({column}) = {self.param(self.dialect.ip_param(text), 'String')}"

    def _cidr(self, op: str, column: str, values: list[Any]) -> str:
        if op == catalog.OP_NE:
            return f"NOT ({self._cidr_atom(column, values[0])})"
        if op == catalog.OP_NOT_IN:
            self._check_in(values)
            return "NOT (" + " OR ".join(self._cidr_atom(column, value) for value in values) + ")"
        if op == catalog.OP_IN:
            self._check_in(values)
            return "(" + " OR ".join(self._cidr_atom(column, value) for value in values) + ")"
        return self._cidr_atom(column, values[0])

    def _cidr_atom(self, column: str, value: Any) -> str:
        network = str(ipaddress.ip_network(str(value), strict=False))
        return (
            f"isIPAddressInRange(toString({column}), "
            f"{self.param(self.dialect.cidr_param(network), 'String')})"
        )

    def _protocol(self, op: str, values: list[Any]) -> str:
        column, type_ = self.column("protocol")
        tokens = [str(value).strip().lower() for value in values]
        if "ip" in tokens:  # "ip" = qualquer protocolo
            if op in (catalog.OP_NE, catalog.OP_NOT_IN):
                return "1 = 0"
            return "1 = 1"
        numbers = []
        for token in tokens:
            if token not in PROTO_NUMBERS:
                raise CompileError(
                    "INVALID_PROTOCOL",
                    f"protocolo sem numero conhecido: '{token}'",
                    field="protocol",
                    token=token,
                )
            numbers.append(PROTO_NUMBERS[token])
        return self._numeric(op, column, type_, numbers)

    def _tcp_flags(self, op: str, values: list[Any]) -> str:
        column, type_ = self.column("tcp_flags")
        mask = self._flag_mask(values[0])
        flags = self.param(mask, type_)
        if op == catalog.OP_NOT_CONTAINS:
            return f"bitAnd({column}, {flags}) = 0"
        return f"bitAnd({column}, {flags}) != 0"

    @staticmethod
    def _flag_mask(value: Any) -> int:
        mask = 0
        raw = str(value).replace("+", ",").replace("|", ",").replace(" ", ",")
        for token in raw.split(","):
            token = token.strip().lower()
            if not token or token in {"null", "none", "0"}:
                continue
            if token not in TCP_FLAG_BITS:
                raise CompileError(
                    "INVALID_FLAG",
                    f"flag TCP desconhecida: '{token}'",
                    field="tcp_flags",
                    token=token,
                    suggestion="flags validas: " + ", ".join(sorted(TCP_FLAG_BITS)),
                )
            mask |= TCP_FLAG_BITS[token]
        return mask

    def _interface(self, op: str, field: str, values: list[Any]) -> str:
        column, type_ = self.column("input_if")
        output_column, _ = self.column("output_if")
        inner = self._numeric(op, column, type_, values)
        mirrored = inner.replace(column, output_column, 1)
        return f"({inner} OR {mirrored})"

    def _enum_membership(
        self,
        op: str,
        values: list[Any],
        atom_builder: Callable[[Any], str],
    ) -> str:
        if op == catalog.OP_NE:
            return f"NOT ({atom_builder(values[0])})"
        if op == catalog.OP_NOT_IN:
            self._check_in(values)
            return "NOT (" + " OR ".join(atom_builder(value) for value in values) + ")"
        if op == catalog.OP_IN:
            self._check_in(values)
            return "(" + " OR ".join(atom_builder(value) for value in values) + ")"
        return atom_builder(values[0])

    def _decoder_atom(self, value: Any) -> str:
        condition = self.dialect.decoder_condition(str(value))
        if not condition:
            condition = "0 = 1"
        return f"({condition})"

    # -- direction ----------------------------------------------------------
    def _internal_atom(self, column: str) -> str:
        parts = [
            f"isIPAddressInRange(toString({column}), "
            f"{self.param(self.dialect.cidr_param(network), 'String')})"
            for network in self.dialect.internal_networks
        ]
        if not parts:
            return "0 = 1"
        return "(" + " OR ".join(parts) + ")"

    def _direction_atom(self, value: Any) -> str:
        canonical = catalog.canonical_direction(str(value)) or str(value)
        if canonical == "inbound":
            return self._internal_atom("dst_ip")
        if canonical == "outbound":
            return self._internal_atom("src_ip")
        if canonical == "both":
            return f"({self._internal_atom('dst_ip')} OR {self._internal_atom('src_ip')})"
        raise CompileError(
            "INVALID_DIRECTION",
            f"direcao invalida: '{value}'",
            field="direction",
            suggestion="use inbound (destino interno), outbound (origem interna) ou both",
        )


def check_limits(text: str) -> None:
    if not str(text or "").strip():
        raise CompileError("EMPTY_EXPRESSION", "expressao vazia")
    if len(text) > MAX_EXPRESSION_LENGTH:
        raise CompileError(
            "EXPRESSION_TOO_LONG",
            f"expressao excede o limite de {MAX_EXPRESSION_LENGTH} caracteres",
        )


def compile_match(
    node: Any,
    dialect: FlowSearchDialect,
    *,
    params_prefix: str = "expr",
) -> CompiledMatch:
    """BooleanNode (secao MATCH) -> fragmento WHERE + parametros vinculados."""
    if node is None:
        raise CompileError("EMPTY_EXPRESSION", "expressao vazia")
    if not _IDENTIFIER_RE.match(params_prefix):
        raise CompileError("INVALID_PREFIX", "prefixo de parametro invalido")
    compiler = _Compiler(dialect, params_prefix)
    where = compiler.build(node)
    return CompiledMatch(
        where=where,
        params=compiler.params,
        canonical_expression=render_node(node),
        conditions=compiler.conditions,
        fields=tuple(sorted(set(compiler.fields))),
    )


def compile_expression(text: str, dialect: FlowSearchDialect) -> CompiledMatch:
    """Texto da expressao (secao MATCH) -> CompiledMatch (parser + validator + compiler)."""
    check_limits(text)
    node = parse_expression(text)
    result = validate_node(node, catalog.SECTION_MATCH)
    if result.errors:
        issue = result.errors[0]
        raise CompileError(
            issue.code,
            issue.message,
            field=issue.token,
            suggestion=issue.suggestion,
        )
    return compile_match(node, dialect)


def check_expression(text: str, dialect: FlowSearchDialect | None = None) -> dict[str, Any]:
    """Validacao/preview (sem executar query). Nunca levanta excecao."""
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    canonical: str | None = None
    node = None
    try:
        check_limits(text)
        node = parse_expression(text)
    except CompileError as exc:
        errors.append(exc.as_dict())
    except RuleDslError as exc:
        errors.append(exc.as_dict())
    except DslSyntaxError as exc:  # pragma: no cover - RuleDslError cobre
        errors.append(exc.as_dict())

    conditions = 0
    fields: list[str] = []
    if node is not None:
        try:
            canonical = render_node(node)
        except Exception:  # pragma: no cover - defensivo
            canonical = None
        conditions = count_conditions(node)
        fields = sorted(
            {condition.field for condition in _iter_conditions(node)}
        )
        result = validate_node(node, catalog.SECTION_MATCH)
        warnings.extend(issue.as_dict() for issue in result.warnings)
        errors.extend(issue.as_dict() for issue in result.errors)
        if not errors:
            try:
                if conditions > MAX_CONDITIONS:
                    raise CompileError(
                        "TOO_MANY_CONDITIONS",
                        f"expressao excede o limite de {MAX_CONDITIONS} condicoes",
                    )
                if ast_depth(node) > MAX_AST_DEPTH:
                    raise CompileError(
                        "AST_TOO_DEEP",
                        f"expressao excede a profundidade maxima ({MAX_AST_DEPTH})",
                    )
                if dialect is not None:
                    compile_match(node, dialect)
            except CompileError as exc:
                errors.append(exc.as_dict())

    return {
        "valid": not errors,
        "canonical_expression": canonical,
        "ast": summarize(node),
        "conditions": conditions,
        "fields": fields,
        "errors": errors,
        "warnings": warnings,
    }


def _iter_conditions(node: Any):
    if node is None:
        return
    if isinstance(node, Condition):
        yield node
        return
    if isinstance(node, NotNode):
        yield from _iter_conditions(node.child)
        return
    if isinstance(node, BooleanGroup):
        for child in node.children:
            yield from _iter_conditions(child)
