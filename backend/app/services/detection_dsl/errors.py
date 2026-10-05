"""Erros e resultados de validacao da DSL de Vetores de Ataque (Fase 3A)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Codigos estaveis (fonte futura para API/UI).
UNKNOWN_FIELD = "UNKNOWN_FIELD"
INVALID_OPERATOR = "INVALID_OPERATOR"
REGEX_NOT_ALLOWED = "REGEX_NOT_ALLOWED"
CONTAINS_REQUIRES_FLAGS = "CONTAINS_REQUIRES_FLAGS"
INVALID_VALUE = "INVALID_VALUE"
INVALID_UNIT = "INVALID_UNIT"
INVALID_LIST = "INVALID_LIST"
OUT_OF_RANGE = "OUT_OF_RANGE"
INVALID_ENUM = "INVALID_ENUM"
INVALID_RANGE = "INVALID_RANGE"
INVALID_SECTION = "INVALID_SECTION"
FIELD_NOT_ALLOWED_IN_SECTION = "FIELD_NOT_ALLOWED_IN_SECTION"
INVALID_GROUP_BY_FIELD = "INVALID_GROUP_BY_FIELD"
UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
CAPABILITY_EXPERIMENTAL = "CAPABILITY_EXPERIMENTAL"
UNKNOWN_DEDUPE_PROFILE = "UNKNOWN_DEDUPE_PROFILE"
INVALID_RESPONSE_MODE = "INVALID_RESPONSE_MODE"
UNBALANCED_PAREN = "UNBALANCED_PAREN"
UNTERMINATED_STRING = "UNTERMINATED_STRING"
UNEXPECTED_TOKEN = "UNEXPECTED_TOKEN"
FORBIDDEN_CHARACTER = "FORBIDDEN_CHARACTER"
MISSING_VALUE = "MISSING_VALUE"
UNKNOWN_SECTION = "UNKNOWN_SECTION"
UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"


class RuleDslError(Exception):
    """Erro base com code/message/line/column/token/suggestion."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        line: int | None = None,
        column: int | None = None,
        token: str | None = None,
        suggestion: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.line = line
        self.column = column
        self.token = token
        self.suggestion = suggestion

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.line is not None:
            data["line"] = self.line
        if self.column is not None:
            data["column"] = self.column
        if self.token is not None:
            data["token"] = self.token
        if self.suggestion:
            data["suggestion"] = self.suggestion
        return data

    def __str__(self) -> str:
        text = f"{self.code}: {self.message}"
        if self.line is not None:
            where = f"linha {self.line}"
            if self.column is not None:
                where += f", coluna {self.column}"
            text += f" ({where})"
        if self.suggestion:
            text += f" - sugestao: {self.suggestion}"
        return text


class DslSyntaxError(RuleDslError):
    """Erro de sintaxe (tokenizacao/gramatica)."""


class DslSemanticError(RuleDslError):
    """Erro semantico (campo/operador/valor/secao)."""


class DslCapabilityError(RuleDslError):
    """Capability exigida indisponivel."""


@dataclass
class ValidationIssue:
    severity: str  # "error" | "warning"
    code: str
    message: str
    line: int | None = None
    column: int | None = None
    token: str | None = None
    suggestion: str | None = None

    @property
    def is_error(self) -> bool:
        return self.severity == "error"

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }
        if self.line is not None:
            data["line"] = self.line
        if self.column is not None:
            data["column"] = self.column
        if self.token is not None:
            data["token"] = self.token
        if self.suggestion:
            data["suggestion"] = self.suggestion
        return data


@dataclass
class ValidationResult:
    errors: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def add_error(self, code: str, message: str, **kwargs: Any) -> ValidationIssue:
        issue = ValidationIssue(severity="error", code=code, message=message, **kwargs)
        self.errors.append(issue)
        return issue

    def add_warning(self, code: str, message: str, **kwargs: Any) -> ValidationIssue:
        issue = ValidationIssue(severity="warning", code=code, message=message, **kwargs)
        self.warnings.append(issue)
        return issue

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": [issue.as_dict() for issue in self.errors],
            "warnings": [issue.as_dict() for issue in self.warnings],
        }
