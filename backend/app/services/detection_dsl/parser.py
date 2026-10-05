"""Parser real da DSL de Vetores de Ataque -> AST v1."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from . import catalog
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
    with_builder_compatibility,
)
from .errors import (
    CONTAINS_REQUIRES_FLAGS,
    FORBIDDEN_CHARACTER,
    INVALID_ENUM,
    INVALID_LIST,
    INVALID_OPERATOR,
    INVALID_SECTION,
    INVALID_UNIT,
    INVALID_VALUE,
    MISSING_VALUE,
    REGEX_NOT_ALLOWED,
    UNBALANCED_PAREN,
    UNEXPECTED_TOKEN,
    UNKNOWN_FIELD,
    UNKNOWN_SECTION,
    UNTERMINATED_STRING,
    DslSemanticError,
    DslSyntaxError,
)
from .units import parse_duration, parse_quantity

SECTION_KEYWORDS = {
    "MATCH": catalog.SECTION_MATCH,
    "WARNING": catalog.SECTION_WARNING,
    "CRITICAL": catalog.SECTION_CRITICAL,
    "EVIDENCE": catalog.SECTION_EVIDENCE,
    "ADVANCED": catalog.SECTION_ADVANCED,
    "RESPONSE": catalog.SECTION_RESPONSE,
}
HEADER_KEYWORDS = ("RULE", "DISPLAY_NAME", "ENABLED", "SEVERITY")

_ALL_CAPS_RE = re.compile(r"^[A-Z][A-Z_]+$")
_NUMBER_RE = re.compile(r"\d+(?:\.\d+)*[A-Za-z]*")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_+\-]*")
# Literais de rede (IP/CIDR) que o tokenizer numerico padrao nao cobre
# (`10.0.0.0/10`, `2001:db8::1`).
_IPV6_RE = re.compile(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}(?:/\d{1,3})?")
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?")
# Caracteres que nunca pertencem a DSL (evita SQL livre / injection).
_FORBIDDEN_CHARS = {";": ";", "'": "'", "`": "`"}


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int
    column: int


def tokenize(text: str, *, start_line: int = 1) -> list[Token]:
    tokens: list[Token] = []
    line = start_line
    column = 1
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\n":
            line += 1
            column = 1
            index += 1
            continue
        if char in " \t\r":
            column += 1
            index += 1
            continue
        if char == "(":
            tokens.append(Token("lparen", char, line, column))
            index += 1
            column += 1
            continue
        if char == ")":
            tokens.append(Token("rparen", char, line, column))
            index += 1
            column += 1
            continue
        if char == "[":
            tokens.append(Token("lbracket", char, line, column))
            index += 1
            column += 1
            continue
        if char == "]":
            tokens.append(Token("rbracket", char, line, column))
            index += 1
            column += 1
            continue
        if char == ",":
            tokens.append(Token("comma", char, line, column))
            index += 1
            column += 1
            continue
        if char == '"':
            end = index + 1
            while end < length and text[end] != '"':
                end += 1
            if end >= length:
                raise DslSyntaxError(
                    UNTERMINATED_STRING, "string sem aspas de fechamento", line=line, column=column
                )
            tokens.append(Token("string", text[index + 1 : end], line, column))
            column += (end - index) + 1
            index = end + 1
            continue
        if char in "=!<>":
            op = char
            if index + 1 < length and text[index + 1] == "=":
                op += "="
            tokens.append(Token("op", op, line, column))
            column += len(op)
            index += len(op)
            continue
        if char in _FORBIDDEN_CHARS:
            raise DslSyntaxError(
                FORBIDDEN_CHARACTER,
                f"caractere nao permitido: {char!r}",
                line=line,
                column=column,
                token=char,
                suggestion="a DSL aceita apenas expressoes de filtro (sem SQL livre)",
            )
        if char.isdigit() or char == ":":
            ip_match = _IPV6_RE.match(text, index) or _IPV4_RE.match(text, index)
            if ip_match:
                raw = ip_match.group(0)
                tokens.append(Token("value", raw, line, column))
                column += len(raw)
                index += len(raw)
                continue
        number_match = _NUMBER_RE.match(text, index)
        if number_match:
            raw = number_match.group(0)
            tokens.append(Token("number", raw, line, column))
            column += len(raw)
            index += len(raw)
            continue
        ident_match = _IDENT_RE.match(text, index)
        if ident_match:
            raw = ident_match.group(0)
            tokens.append(Token("ident", raw, line, column))
            column += len(raw)
            index += len(raw)
            continue
        raise DslSyntaxError(
            UNEXPECTED_TOKEN, f"caractere inesperado: {char!r}", line=line, column=column, token=char
        )
    tokens.append(Token("eof", "", line, column))
    return tokens


class _ExprParser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Token:
        return self.tokens[self.pos]

    def advance(self) -> Token:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def _is_ident(self, value: str) -> bool:
        token = self.peek()
        return token.kind == "ident" and token.value.upper() == value

    def parse(self):
        node = self.parse_or()
        token = self.peek()
        if token.kind != "eof":
            raise DslSyntaxError(
                UNEXPECTED_TOKEN,
                f"token inesperado: {token.value!r}",
                line=token.line,
                column=token.column,
                token=token.value,
            )
        return node

    def parse_or(self):
        nodes = []
        node = self.parse_and()
        if node is not None:
            nodes.append(node)
        while self._is_ident("OR"):
            self.advance()
            node = self.parse_and()
            if node is not None:
                nodes.append(node)
        return _combine("or", nodes)

    def parse_and(self):
        nodes = []
        node = self.parse_not()
        if node is not None:
            nodes.append(node)
        while self._is_ident("AND"):
            self.advance()
            node = self.parse_not()
            if node is not None:
                nodes.append(node)
        return _combine("and", nodes)

    def parse_not(self):
        if self._is_ident("NOT"):
            self.advance()
            child = self.parse_not()
            if child is None:
                return None
            return NotNode(child)
        return self.parse_primary()

    def parse_primary(self):
        token = self.peek()
        if token.kind == "lparen":
            self.advance()
            node = self.parse_or()
            closing = self.peek()
            if closing.kind != "rparen":
                raise DslSyntaxError(
                    UNBALANCED_PAREN,
                    "parentese aberto sem fechamento",
                    line=token.line,
                    column=token.column,
                    suggestion="feche o grupo com ')'",
                )
            self.advance()
            return node
        if token.kind == "rparen":
            raise DslSyntaxError(
                UNBALANCED_PAREN, "parentese de fechamento sem abertura", line=token.line, column=token.column
            )
        if token.kind != "ident":
            raise DslSyntaxError(
                UNEXPECTED_TOKEN,
                f"esperado campo, encontrado {token.value!r}",
                line=token.line,
                column=token.column,
                token=token.value,
            )
        return self.parse_condition()

    def parse_condition(self):
        field_token = self.advance()
        spec = catalog.resolve_field(field_token.value)
        if spec is None:
            raise DslSemanticError(
                UNKNOWN_FIELD,
                f"campo desconhecido: '{field_token.value}'",
                line=field_token.line,
                column=field_token.column,
                token=field_token.value,
                suggestion="consulte o catalogo de campos (GET /rule-language/catalog)",
            )
        op, op_token = self.parse_operator()
        if self._is_ident("ANY"):
            self.advance()
            if op == catalog.OP_EQ:
                return None  # ANY = ausencia de condicao
            raise DslSemanticError(
                INVALID_VALUE,
                "'any' so e aceito com '=='",
                line=op_token.line,
                column=op_token.column,
                token="any",
            )
        if op not in spec.operators:
            raise self._operator_error(spec, op, op_token)
        value, display = self.parse_value(spec, op)
        return Condition(field=spec.name, op=op, value=value, display=display, line=field_token.line, column=field_token.column)

    def _operator_error(self, spec: catalog.FieldSpec, op: str, op_token: Token) -> DslSemanticError:
        if op == catalog.OP_MATCHES and spec.type != catalog.TYPE_TEXT:
            return DslSemanticError(
                REGEX_NOT_ALLOWED,
                f"regex (MATCHES) so e permitido em campo textual; '{spec.name}' e do tipo {spec.type}",
                line=op_token.line,
                column=op_token.column,
                token=op,
                suggestion="use igualdade/lista no lugar de regex (ex.: sensor matches \"^FIBINET-\")",
            )
        if op in (catalog.OP_CONTAINS, catalog.OP_NOT_CONTAINS) and spec.type != catalog.TYPE_FLAGS:
            return DslSemanticError(
                CONTAINS_REQUIRES_FLAGS,
                f"CONTAINS/NOT CONTAINS so e permitido em campo de flags; '{spec.name}' e do tipo {spec.type}",
                line=op_token.line,
                column=op_token.column,
                token=op,
                suggestion="flags disponiveis: tcp_flags (ex.: tcp_flags contains syn)",
            )
        return DslSemanticError(
            INVALID_OPERATOR,
            f"operador {op!r} nao permitido para o campo '{spec.name}' ({spec.type})",
            line=op_token.line,
            column=op_token.column,
            token=op,
            suggestion="operadores validos: " + ", ".join(spec.operators),
        )

    def parse_operator(self) -> tuple[str, Token]:
        token = self.peek()
        if token.kind == "op":
            self.advance()
            canonical = catalog.canonical_operator(token.value)
            if canonical is None:
                raise DslSyntaxError(
                    UNEXPECTED_TOKEN,
                    f"operador desconhecido: {token.value!r}",
                    line=token.line,
                    column=token.column,
                    token=token.value,
                )
            return canonical, token
        if token.kind == "ident":
            upper = token.value.upper()
            if upper in ("IN", "BETWEEN", "CONTAINS", "MATCHES"):
                self.advance()
                return upper, token
            if upper == "NOT":
                self.advance()
                if self._is_ident("IN"):
                    self.advance()
                    return catalog.OP_NOT_IN, token
                if self._is_ident("CONTAINS"):
                    self.advance()
                    return catalog.OP_NOT_CONTAINS, token
                raise DslSyntaxError(
                    UNEXPECTED_TOKEN,
                    "esperado IN ou CONTAINS depois de NOT",
                    line=token.line,
                    column=token.column,
                    token=token.value,
                )
            raise DslSyntaxError(
                UNEXPECTED_TOKEN,
                f"operador desconhecido: {token.value!r}",
                line=token.line,
                column=token.column,
                token=token.value,
            )
        raise DslSyntaxError(
            UNEXPECTED_TOKEN,
            f"esperado operador, encontrado {token.value!r}",
            line=token.line,
            column=token.column,
            token=token.value,
        )

    def parse_value(self, spec: catalog.FieldSpec, op: str):
        if op == catalog.OP_BETWEEN:
            low, _ = self.parse_single_value(spec)
            if not self._is_ident("AND"):
                token = self.peek()
                raise DslSyntaxError(
                    UNEXPECTED_TOKEN, "BETWEEN exige 'AND' entre os limites", line=token.line, column=token.column
                )
            self.advance()
            high, _ = self.parse_single_value(spec)
            return (low, high), None
        if op in (catalog.OP_IN, catalog.OP_NOT_IN):
            opening = self.peek()
            if opening.kind not in ("lparen", "lbracket"):
                # `src_ip in 100.64.0.0/10` e valido (lista de 1 item).
                value, display = self.parse_single_value(spec)
                return (value,), display
            closing_kind = "rparen" if opening.kind == "lparen" else "rbracket"
            closer = ")" if opening.kind == "lparen" else "]"
            self.advance()
            if self.peek().kind == closing_kind:
                raise DslSemanticError(
                    INVALID_LIST,
                    f"lista vazia em '{spec.name}': informe ao menos um valor",
                    line=opening.line,
                    column=opening.column,
                )
            values = []
            displays = []
            while True:
                value, display = self.parse_single_value(spec)
                values.append(value)
                displays.append(display)
                token = self.peek()
                if token.kind == "comma":
                    self.advance()
                    continue
                if token.kind == closing_kind:
                    self.advance()
                    break
                raise DslSyntaxError(
                    UNEXPECTED_TOKEN,
                    f"esperado ',' ou '{closer}' na lista, encontrado {token.value!r}",
                    line=token.line,
                    column=token.column,
                )
            if not values:
                raise DslSemanticError(
                    INVALID_LIST,
                    f"lista vazia em '{spec.name}': informe ao menos um valor",
                    line=opening.line,
                    column=opening.column,
                )
            display = ", ".join(str(item) for item in displays if item)
            return tuple(values), (display or None)
        value, display = self.parse_single_value(spec)
        return value, display

    def parse_single_value(self, spec: catalog.FieldSpec):
        token = self.peek()
        if token.kind == "eof" or token.kind in ("comma", "rparen", "rbracket"):
            raise DslSyntaxError(
                MISSING_VALUE, "valor ausente", line=token.line, column=token.column, token=token.value
            )
        if spec.type in (catalog.TYPE_METRIC, catalog.TYPE_DERIVED):
            if token.kind != "number":
                raise DslSemanticError(
                    INVALID_UNIT,
                    f"valor de '{spec.name}' deve ser numero com unidade opcional (ex.: 100k)",
                    line=token.line,
                    column=token.column,
                    token=token.value,
                )
            self.advance()
            self._reject_spaced_unit(spec, token)
            value, display = parse_quantity(token.value, line=token.line, column=token.column)
            return value, display
        if spec.type in (catalog.TYPE_PORT, catalog.TYPE_INT):
            if token.kind != "number":
                raise DslSemanticError(
                    INVALID_VALUE,
                    f"valor de '{spec.name}' deve ser inteiro",
                    line=token.line,
                    column=token.column,
                    token=token.value,
                )
            self.advance()
            if not re.match(r"^\d+$", token.value):
                if re.match(r"^\d+(?:\.\d+)*[A-Za-z]+$", token.value):
                    raise DslSemanticError(
                        INVALID_UNIT,
                        f"campo '{spec.name}' nao aceita unidade",
                        line=token.line,
                        column=token.column,
                        token=token.value,
                    )
                raise DslSemanticError(
                    INVALID_VALUE,
                    f"campo '{spec.name}' aceita apenas inteiro",
                    line=token.line,
                    column=token.column,
                    token=token.value,
                )
            self._reject_spaced_unit(spec, token)
            return int(token.value), token.value
        if token.kind not in ("ident", "string", "value"):
            raise DslSemanticError(
                INVALID_VALUE,
                f"valor de '{spec.name}' deve ser texto",
                line=token.line,
                column=token.column,
                token=token.value,
            )
        self.advance()
        raw = token.value
        return self._convert_text_value(spec, raw, token)

    def _reject_spaced_unit(self, spec: catalog.FieldSpec, token: Token) -> None:
        nxt = self.peek()
        if nxt.kind == "ident" and nxt.value in ("k", "K", "M", "G", "T"):
            raise DslSemanticError(
                INVALID_UNIT,
                "unidade nao pode ter espaco",
                line=nxt.line,
                column=nxt.column,
                token=nxt.value,
                suggestion="escreva junto, ex.: 1G",
            )

    def _convert_text_value(self, spec: catalog.FieldSpec, raw: str, token: Token):
        if spec.type == catalog.TYPE_ENUM:
            if spec.name == "direction":
                canonical = catalog.canonical_direction(raw)
            elif spec.name == "decoder":
                canonical = catalog.canonical_decoder(raw)
            elif spec.name == "protocol":
                canonical = catalog.canonical_protocol(raw)
            else:
                canonical = raw
            if canonical is None:
                raise DslSemanticError(
                    INVALID_ENUM,
                    f"valor invalido para '{spec.name}': '{raw}'",
                    line=token.line,
                    column=token.column,
                    token=raw,
                    suggestion="valores validos: " + ", ".join(spec.enum_values),
                )
            return canonical, raw
        if spec.type == catalog.TYPE_IP:
            try:
                return str(ipaddress.ip_address(raw)), raw
            except ValueError:
                # `src_ip in 100.64.0.0/10` e valido: IP aceita rede em IN/NOT IN.
                try:
                    return str(ipaddress.ip_network(raw, strict=False)), raw
                except ValueError as exc:
                    raise DslSemanticError(
                        INVALID_VALUE, f"IP invalido: '{raw}'", line=token.line, column=token.column, token=raw
                    ) from exc
        if spec.type == catalog.TYPE_CIDR:
            try:
                return str(ipaddress.ip_network(raw, strict=False)), raw
            except ValueError as exc:
                raise DslSemanticError(
                    INVALID_VALUE, f"CIDR invalido: '{raw}'", line=token.line, column=token.column, token=raw
                ) from exc
        if spec.type == catalog.TYPE_FLAGS:
            return raw.strip().lower(), raw
        if spec.type == catalog.TYPE_TEXT:
            return raw, raw
        return raw, raw


def _combine(op: str, nodes: list):
    if not nodes:
        return None
    if len(nodes) == 1:
        return nodes[0]
    return BooleanGroup(op=op, children=tuple(nodes))


def _split_sections(text: str):
    header: dict[str, tuple[str, int]] = {}
    sections: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        first, _, remainder = stripped.partition(" ")
        first_upper = first.upper()
        if first_upper in HEADER_KEYWORDS:
            key = "cooldown" if False else first_upper
            header[key] = (remainder.strip(), line_number)
            current = None
            continue
        if first_upper in SECTION_KEYWORDS:
            current = SECTION_KEYWORDS[first_upper]
            if remainder.strip():
                sections.setdefault(current, []).append((line_number, remainder.strip()))
            continue
        if _ALL_CAPS_RE.match(stripped):
            raise DslSyntaxError(
                UNKNOWN_SECTION,
                f"secao desconhecida: '{stripped}'",
                line=line_number,
                suggestion="secoes validas: " + ", ".join(SECTION_KEYWORDS),
            )
        if current is None:
            raise DslSyntaxError(
                UNEXPECTED_TOKEN,
                f"linha fora de secao: '{stripped}'",
                line=line_number,
                token=stripped,
            )
        sections.setdefault(current, []).append((line_number, raw_line.strip()))
    return header, sections


def _parse_boolean(lines: list[tuple[int, str]]):
    if not lines:
        return None
    start_line = lines[0][0]
    block = "\n".join(item[1] for item in lines)
    tokens = tokenize(block, start_line=start_line)
    return _ExprParser(tokens).parse()


def parse_expression(text: str, *, start_line: int = 1):
    """Expressao booleana pura (sem secoes) -> BooleanNode.

    Base reutilizavel para Flow Search (fase 2), que filtra apenas atributos de
    flow e portanto nao tem secoes WARNING/CRITICAL/EVIDENCE.
    """
    if not isinstance(text, str):
        raise DslSyntaxError(UNEXPECTED_TOKEN, "entrada deve ser texto")
    return _ExprParser(tokenize(text, start_line=start_line)).parse()


def _parse_evidence(lines) -> tuple[EvidenceItem, ...]:
    items: list[EvidenceItem] = []
    for line_number, text in lines:
        for part in text.split(","):
            name = part.strip()
            if not name:
                continue
            spec = catalog.resolve_field(name)
            if spec is None:
                raise DslSemanticError(
                    UNKNOWN_FIELD, f"campo de evidence desconhecido: '{name}'", line=line_number, token=name
                )
            items.append(EvidenceItem(field=spec.name, display=name, line=line_number))
    return tuple(items)


def _parse_key_values(lines) -> list[tuple[str, str, int]]:
    pairs = []
    for line_number, text in lines:
        key, sep, value = text.partition("=")
        if not sep:
            raise DslSyntaxError(
                UNEXPECTED_TOKEN, f"linha deve ser 'chave = valor': '{text}'", line=line_number
            )
        pairs.append((key.strip().lower(), value.strip(), line_number))
    return pairs


def _parse_advanced(lines) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value, line_number in _parse_key_values(lines):
        if key == "window":
            seconds, display = parse_duration(value, line=line_number)
            result["window"] = WindowSpec(seconds=seconds, display=display)
        elif key == "consecutive":
            if not re.match(r"^\d+$", value):
                raise DslSemanticError(INVALID_VALUE, f"consecutive invalido: '{value}'", line=line_number)
            result["consecutive"] = int(value)
        elif key in ("cooldown", "cooldown_seconds"):
            seconds, display = parse_duration(value, line=line_number)
            result["cooldown_seconds"] = seconds
            result["cooldown_display"] = display
        elif key == "group_by":
            result["group_by"] = _parse_group_by(value, line_number)
        elif key == "dedupe":
            result["dedupe"] = value
        elif key == "requires":
            result["requires"] = tuple(part.strip() for part in value.split(",") if part.strip())
        else:
            raise DslSyntaxError(
                INVALID_SECTION,
                f"chave desconhecida em ADVANCED: '{key}'",
                line=line_number,
                token=key,
                suggestion="chaves validas: window, consecutive, cooldown, group_by, dedupe, requires",
            )
    return result


def _parse_group_by(value: str, line_number: int) -> GroupBy:
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if not parts:
        raise DslSemanticError(INVALID_VALUE, "group_by vazio", line=line_number)
    if len(parts) == 1 and parts[0] in catalog.GROUP_BY_PRESETS:
        return GroupBy(preset=parts[0])
    fields = []
    for part in parts:
        spec = catalog.resolve_field(part)
        if spec is None:
            raise DslSemanticError(
                UNKNOWN_FIELD,
                f"group_by com campo desconhecido: '{part}'",
                line=line_number,
                token=part,
                suggestion="campos permitidos: " + ", ".join(catalog.GROUP_BY_ALLOWED_FIELDS),
            )
        fields.append(spec.name)
    return GroupBy(preset=None, fields=tuple(fields))


def _parse_response(lines) -> ResponseSpec:
    values: dict[str, object] = {}
    integer_keys = {
        "response_profile_id",
        "connector_id",
        "max_auto_prefixlen_v4",
        "max_auto_prefixlen_v6",
        "duration_seconds",
        "max_active_announcements",
    }
    for key, value, line_number in _parse_key_values(lines):
        if key == "mode":
            values["mode"] = value
        elif key == "require_protected_prefix":
            values["require_protected_prefix"] = value.strip().lower() in ("yes", "true", "1", "sim")
        elif key == "min_confidence_for_auto":
            try:
                values["min_confidence_for_auto"] = float(value)
            except ValueError as exc:
                raise DslSemanticError(
                    INVALID_VALUE, f"min_confidence_for_auto invalido: '{value}'", line=line_number
                ) from exc
        elif key in integer_keys:
            if not re.match(r"^\d+$", value):
                raise DslSemanticError(INVALID_VALUE, f"{key} invalido: '{value}'", line=line_number)
            values[key] = int(value)
        else:
            raise DslSyntaxError(
                INVALID_SECTION,
                f"chave desconhecida em RESPONSE: '{key}'",
                line=line_number,
                token=key,
            )
    return ResponseSpec(**values)


def _parse_header(header: dict[str, tuple[str, int]]) -> dict[str, object]:
    result: dict[str, object] = {}
    if "RULE" in header:
        value, line_number = header["RULE"]
        if not value:
            raise DslSyntaxError(MISSING_VALUE, "RULE exige um nome", line=line_number)
        result["name"] = value.strip().strip('"')
    if "DISPLAY_NAME" in header:
        value, line_number = header["DISPLAY_NAME"]
        if not value:
            raise DslSyntaxError(MISSING_VALUE, "DISPLAY_NAME exige um texto", line=line_number)
        result["display_name"] = value.strip().strip('"')
    if "ENABLED" in header:
        value, line_number = header["ENABLED"]
        lowered = value.strip().lower()
        if lowered in ("yes", "true", "1", "sim"):
            result["enabled"] = True
        elif lowered in ("no", "false", "0", "nao", "não"):
            result["enabled"] = False
        else:
            raise DslSemanticError(INVALID_VALUE, f"ENABLED invalido: '{value}'", line=line_number)
    if "SEVERITY" in header:
        value, line_number = header["SEVERITY"]
        lowered = value.strip().lower()
        if lowered not in ("info", "warning", "critical"):
            raise DslSemanticError(INVALID_ENUM, f"SEVERITY invalido: '{value}'", line=line_number)
        result["severity"] = lowered
    return result


def parse(text: str) -> RuleAst:
    """Texto da DSL -> RuleAst (v1)."""
    if not isinstance(text, str):
        raise DslSyntaxError(UNEXPECTED_TOKEN, "entrada deve ser texto")
    header, sections = _split_sections(text)
    header_values = _parse_header(header)
    advanced = _parse_advanced(sections.get(catalog.SECTION_ADVANCED, []))
    response = _parse_response(sections.get(catalog.SECTION_RESPONSE, []))
    ast = RuleAst(
        version=catalog.AST_VERSION,
        name=str(header_values.get("name", "")),
        display_name=str(header_values.get("display_name", "")),
        enabled=bool(header_values.get("enabled", True)),
        severity=str(header_values.get("severity", "critical")),
        match=_parse_boolean(sections.get(catalog.SECTION_MATCH, [])),
        triggers=Triggers(
            warning=_parse_boolean(sections.get(catalog.SECTION_WARNING, [])),
            critical=_parse_boolean(sections.get(catalog.SECTION_CRITICAL, [])),
        ),
        evidence=_parse_evidence(sections.get(catalog.SECTION_EVIDENCE, [])),
        window=advanced.get("window"),  # type: ignore[arg-type]
        execution=ExecutionSpec(
            consecutive=int(advanced.get("consecutive", 1)),
            cooldown_seconds=advanced.get("cooldown_seconds"),  # type: ignore[arg-type]
            cooldown_display=advanced.get("cooldown_display"),  # type: ignore[arg-type]
        ),
        scope=ScopeSpec(
            group_by=advanced.get("group_by"),  # type: ignore[arg-type]
            dedupe_profile=advanced.get("dedupe"),  # type: ignore[arg-type]
        ),
        response=response,
        requires=tuple(advanced.get("requires", ())),  # type: ignore[arg-type]
    )
    return with_builder_compatibility(ast)


def parse_and_validate(text: str):
    """Conveniencia: parse + validate (import tardio evita ciclo)."""
    from .validator import validate

    ast = parse(text)
    return ast, validate(ast)
