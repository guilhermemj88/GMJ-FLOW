"""Unidades decimais de telecom da DSL (k/M/G/T) e duracoes.

Escala decimal (1000), NUNCA binaria (1024). AST guarda o valor normalizado e,
quando veio de texto, tambem o display original (ex.: "1.5G").
"""
from __future__ import annotations

import re
from decimal import Decimal

from .errors import INVALID_UNIT, INVALID_VALUE, DslSemanticError

KILO = Decimal(1000)
MEGA = Decimal(10) ** 6
GIGA = Decimal(10) ** 9
TERA = Decimal(10) ** 12

_UNIT_FACTORS: dict[str, Decimal] = {
    "k": KILO,
    "K": KILO,
    "M": MEGA,
    "G": GIGA,
    "T": TERA,
}
_QUANTITY_RE = re.compile(r"^(\d+(?:\.\d+)?)([kKMGT])?$")

_DURATION_FACTORS: dict[str, Decimal] = {
    "s": Decimal(1),
    "m": Decimal(60),
    "h": Decimal(3600),
    "d": Decimal(86400),
}
_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)([smhd])?$")

UNIT_DOCUMENTATION = (
    {"suffix": "k", "factor": 1000, "description": "quilo (10^3)"},
    {"suffix": "M", "factor": 10 ** 6, "description": "mega (10^6)"},
    {"suffix": "G", "factor": 10 ** 9, "description": "giga (10^9)"},
    {"suffix": "T", "factor": 10 ** 12, "description": "tera (10^12)"},
)


class UnitError(ValueError):
    """Erro interno de conversao (convertido para DslSemanticError na DSL)."""


def normalize_decimal(value: Decimal) -> Decimal:
    """Remove ruido de representacao (1000.000 -> 1000; 1.50 -> 1.5)."""
    if value == value.to_integral_value():
        return value.quantize(Decimal(1))
    return value.normalize()


def parse_quantity(text: str, *, line: int | None = None, column: int | None = None) -> tuple[Decimal, str]:
    """Converte '100k'/'1.5M'/'2G' em Decimal normalizado + display original."""
    raw = str(text).strip()
    match = _QUANTITY_RE.match(raw)
    if not match:
        raise DslSemanticError(
            INVALID_UNIT,
            f"valor com unidade invalida: '{raw}'",
            line=line,
            column=column,
            token=raw,
            suggestion="use k/M/G/T sem espaco, ex.: 500, 100k, 1.5M, 2G, 0.8T",
        )
    number = Decimal(match.group(1))
    suffix = match.group(2)
    value = number * _UNIT_FACTORS[suffix] if suffix else number
    return normalize_decimal(value), raw


def format_quantity(value: Decimal | int) -> str:
    """Formata de volta para unidade amigavel, de forma deterministica."""
    decimal_value = Decimal(value)
    if decimal_value == 0:
        return "0"
    for suffix, factor in (("T", TERA), ("G", GIGA), ("M", MEGA), ("k", KILO)):
        scaled = decimal_value / factor
        if scaled >= 1 and _is_clean(scaled):
            return f"{_plain(scaled)}{suffix}"
    return _plain(decimal_value)


def _is_clean(scaled: Decimal) -> bool:
    return scaled.quantize(Decimal("0.001")) == scaled


def _plain(value: Decimal) -> str:
    return format(value.normalize(), "f")


def parse_duration(text: str, *, line: int | None = None, column: int | None = None) -> tuple[int, str]:
    """Converte '60s'/'5m'/'1h' em segundos inteiros + display original."""
    raw = str(text).strip()
    match = _DURATION_RE.match(raw)
    if not match:
        raise DslSemanticError(
            INVALID_VALUE,
            f"duracao invalida: '{raw}'",
            line=line,
            column=column,
            token=raw,
            suggestion="use s/m/h/d sem espaco, ex.: 60s, 5m, 1h",
        )
    number = Decimal(match.group(1))
    suffix = match.group(2) or "s"
    seconds = number * _DURATION_FACTORS[suffix]
    return int(seconds), raw
