"""Triggers booleanos do detector (DSL TRIGGER -> avaliacao em Python).

Modulo puro (stdlib + detection_dsl, sem banco, ClickHouse ou FastAPI):

- canonicaliza expressoes de trigger WARNING/CRITICAL com a MESMA DSL usada
  pelo Flow Search (`parse_expression` + `validate_node` na secao de trigger);
- avalia a expressao contra o frame multi-metrica devolvido pelo scan do
  detector (bps/pps/flow rate, cardinalidades `unique_*` e `avg_packet_bytes`
  derivado de sum(bytes) / sum(packets)).

Nenhuma expressao do usuario vira SQL: o scan devolve o frame com TODAS as
metricas de uma vez (shared multi-metric frame) e os gatilhos booleanos sao
resolvidos em Python — mesmo principio do Flow Search, que nunca concatena
texto do usuario no SQL.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any

from .detection_dsl import catalog as dsl_catalog
from .detection_dsl import parse_expression, render_node, validate_node
from .detection_dsl.ast import BooleanGroup, Condition, NotNode
from .detection_dsl.errors import RuleDslError

TRIGGER_SECTION = dsl_catalog.SECTION_WARNING

# Campo canonico da DSL (TRIGGER) -> chave do frame do detector.
TRIGGER_FRAME_KEYS: dict[str, str] = {
    "packets_s": "packets_s",
    "bits_s": "bits_s",
    "flows_s": "flows_s",
    "unique_src_ips": "unique_src_ips",
    "unique_dst_ips": "unique_dst_ips",
    "unique_src_ports": "unique_src_ports",
    "unique_dst_ports": "unique_dst_ports",
    "avg_packet_bytes": "avg_packet_bytes",
}


def frame_metrics(row: dict[str, Any]) -> dict[str, float]:
    """Extrai do frame do detector as metricas visiveis ao TRIGGER.

    `avg_packet_bytes` e derivado (sum(bytes)/sum(packets)) quando o frame nao
    traz o campo calculado; nunca e media de medias por flow.
    """
    metrics: dict[str, float] = {}
    for field, key in TRIGGER_FRAME_KEYS.items():
        value = row.get(key)
        if key == "avg_packet_bytes" and value in (None, ""):
            packets = float(row.get("packets") or 0)
            value = (float(row.get("bytes") or 0) / packets) if packets > 0 else 0.0
        try:
            metrics[field] = float(value or 0)
        except (TypeError, ValueError):
            metrics[field] = 0.0
    return metrics


def canonicalize_trigger_expression(text: Any) -> tuple[str, list[dict[str, Any]]]:
    """Valida e canonicaliza uma expressao de trigger da DSL.

    Retorna `(texto_canonico, issues)`. Texto vazio devolve `("", [])`; erro de
    sintaxe/semantica devolve `("", [issue...])` com `code` estavel — nunca
    levanta excecao para o chamador (API tratara como 400).
    """
    raw = str(text or "").strip()
    if not raw:
        return "", []
    try:
        node = parse_expression(raw)
    except RuleDslError as exc:
        return "", [exc.as_dict()]
    result = validate_node(node, TRIGGER_SECTION)
    if result.errors:
        return "", [issue.as_dict() for issue in result.errors]
    return render_node(node), []


def _numeric(value: Any) -> float:
    if isinstance(value, Decimal):
        return float(value)
    return float(value)


def _compare(observed: float, op: str, value: Any) -> bool:
    if op in (dsl_catalog.OP_IN, dsl_catalog.OP_NOT_IN):
        items = value if isinstance(value, tuple) else (value,)
        found = any(observed == _numeric(item) for item in items)
        return found if op == dsl_catalog.OP_IN else not found
    if op == dsl_catalog.OP_BETWEEN:
        low, high = value if isinstance(value, tuple) else (value, value)
        return _numeric(low) <= observed <= _numeric(high)
    target = _numeric(value)
    if op == dsl_catalog.OP_EQ:
        return observed == target
    if op == dsl_catalog.OP_NE:
        return observed != target
    if op == dsl_catalog.OP_GT:
        return observed > target
    if op == dsl_catalog.OP_GE:
        return observed >= target
    if op == dsl_catalog.OP_LT:
        return observed < target
    if op == dsl_catalog.OP_LE:
        return observed <= target
    raise ValueError(f"operador de trigger sem suporte: {op!r}")


def _eval_node(node: Any, metrics: dict[str, float]) -> bool:
    if isinstance(node, Condition):
        field = node.field
        if field not in TRIGGER_FRAME_KEYS:
            raise ValueError(f"campo de trigger desconhecido: {field!r}")
        return _compare(float(metrics.get(field) or 0.0), node.op, node.value)
    if isinstance(node, NotNode):
        return not _eval_node(node.child, metrics)
    if isinstance(node, BooleanGroup):
        if node.op == "and":
            return all(_eval_node(child, metrics) for child in node.children)
        return any(_eval_node(child, metrics) for child in node.children)
    raise TypeError(f"no booleano invalido: {node!r}")


class TriggerEvaluator:
    """Avalia WARNING/CRITICAL de uma regra contra o frame do scan.

    Precedencia: CRITICAL primeiro (um frame critical tambem satisfaz warning
    quando as expressoes foram construidas para isso); devolve
    `"critical" | "warning" | None`.
    """

    def __init__(self, warning_node: Any = None, critical_node: Any = None) -> None:
        self._warning = warning_node
        self._critical = critical_node

    @property
    def active(self) -> bool:
        return self._warning is not None or self._critical is not None

    def evaluate(self, metrics: dict[str, float]) -> str | None:
        if self._critical is not None and _eval_node(self._critical, metrics):
            return "critical"
        if self._warning is not None and _eval_node(self._warning, metrics):
            return "warning"
        return None


_EVALUATOR_CACHE: dict[tuple[str, str], TriggerEvaluator] = {}
_EVALUATOR_CACHE_MAX = 256


def evaluator_for(warning_expr: Any, critical_expr: Any) -> TriggerEvaluator | None:
    """Compila (com cache) o avaliador de uma regra; None quando nao ha trigger.

    As expressoes devem estar canonicas (validadas no save). A compilacao e
    barata; o cache evita re-parse por prefixo dentro do mesmo ciclo.
    """
    warning_text = str(warning_expr or "").strip()
    critical_text = str(critical_expr or "").strip()
    if not warning_text and not critical_text:
        return None
    key = (warning_text, critical_text)
    cached = _EVALUATOR_CACHE.get(key)
    if cached is not None:
        return cached
    evaluator = TriggerEvaluator(
        parse_expression(warning_text) if warning_text else None,
        parse_expression(critical_text) if critical_text else None,
    )
    if len(_EVALUATOR_CACHE) >= _EVALUATOR_CACHE_MAX:
        _EVALUATOR_CACHE.clear()
    _EVALUATOR_CACHE[key] = evaluator
    return evaluator
