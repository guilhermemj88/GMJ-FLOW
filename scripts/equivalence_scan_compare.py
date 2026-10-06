#!/usr/bin/env python3
"""Compara dois dumps de `equivalence_scan_dump.py` (old x new) por regra/prefixo.

    python scripts/equivalence_scan_compare.py equiv_old.json equiv_new.json

Regras da comparacao:
- itens sao ordenados por chave total NORMALIZADA (chaves aditivas do lado new sao
  ignoradas: avg_packet_bytes, evidence, evidence_values, trigger_warning_expr,
  trigger_critical_expr, unique_src_ips ??? e as mesmas chaves dentro de dicts);
- so campos presentes nos dois lados sao comparados;
- campos volateis do ClickHouse (detected_exporter_ip/sensor_name, top_*, e valores
  de agregacao cuja composicao de grupo varia por any()/argMax) divergem tambem
  entre duas execucoes da MESMA imagem ??? use duas rodadas do mesmo lado como piso
  de ruido;
- veredito acionavel: DECISAO considera apenas campos que mudam comportamento
  (matched, severity, thresholds, metric, rule_config, response, mitigacao,
  escopo/identidade da regra). Exit code 0 quando a decisao e os totais batem.
"""
from __future__ import annotations

import json
import sys

ADDITIVE_NESTED_KEYS = {"evidence", "trigger_warning_expr", "trigger_critical_expr"}
ADDITIVE_ITEM_KEYS = {
    "avg_packet_bytes", "evidence", "evidence_values",
    "trigger_warning_expr", "trigger_critical_expr", "unique_src_ips",
}

DECISION_FIELDS = {
    "matched", "severity", "threshold_warning", "threshold_critical", "metric",
    "rule_config", "response", "comparison", "mitigation_mode", "mitigation_enabled",
    "mitigation_reason", "mitigation_basis", "automatic_mitigation_threshold",
    "invalid_scope", "scope_type", "target_role", "direction", "domain",
    "vector", "rule_id", "rule_name", "template_id", "zone_id", "prefix_id", "sensor_id",
    "warning_response_profile_id", "critical_response_profile_id", "fallback_response_profile_id",
}
# Fora do gate de decisao (volateis por composicao de grupo): protocol, src_port,
# dst_port, target_port, detected_exporter_*, top_*, first_seen/last_seen e os
# agregados derivados.


def normalize(value):
    if isinstance(value, dict):
        return {k: v for k, v in value.items() if k not in ADDITIVE_NESTED_KEYS}
    return value


def full_key(item: dict) -> str:
    return json.dumps(
        {k: normalize(v) for k, v in item.items() if k not in ADDITIVE_ITEM_KEYS},
        sort_keys=True,
        default=str,
    )


def key_dump(value) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def load(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


def main() -> int:
    old = load(sys.argv[1])
    new = load(sys.argv[2])
    lhs, rhs = old["rules"], new["rules"]
    problems: list[tuple] = []
    problems_total = [0]
    decision_problems = [0]
    problem_fields: dict[str, int] = {}
    compared_fields: dict[str, int] = {}
    new_only_keys: dict[str, int] = {}
    old_only_keys: dict[str, int] = {}
    if set(lhs) != set(rhs):
        problems.append(("ruleset", "-", "rule-id-sets-differ", sorted(lhs), sorted(rhs)))
    for rid in sorted(lhs, key=int):
        if rid not in rhs:
            continue
        a, b = lhs[rid], rhs[rid]
        if a.get("vector") != b.get("vector"):
            problems.append((rid, "-", "vector", a.get("vector"), b.get("vector")))
        if set(a.get("prefixes", {})) != set(b.get("prefixes", {})):
            problems.append((rid, "-", "prefix-set", sorted(a.get("prefixes", {})), sorted(b.get("prefixes", {}))))
            continue
        for cidr in sorted(a["prefixes"]):
            va, vb = a["prefixes"][cidr], b["prefixes"][cidr]
            if isinstance(va, dict) or isinstance(vb, dict):
                problems.append((rid, cidr, "prefix-error", va if isinstance(va, dict) else "items", vb if isinstance(vb, dict) else "items"))
                continue
            if len(va) != len(vb):
                problems.append((rid, cidr, "item-count", len(va), len(vb)))
                continue
            va = sorted(va, key=full_key)
            vb = sorted(vb, key=full_key)
            for ia, ib in zip(va, vb):
                for field in sorted(set(ia) | set(ib)):
                    if field not in ia or field not in ib:
                        continue
                    compared_fields[field] = compared_fields.get(field, 0) + 1
                    if key_dump(normalize(ia[field])) != key_dump(normalize(ib[field])):
                        problems_total[0] += 1
                        problem_fields[field] = problem_fields.get(field, 0) + 1
                        if field in DECISION_FIELDS:
                            decision_problems[0] += 1
                        if len(problems) < 25:
                            problems.append((rid, cidr, field, ia[field], ib[field]))
                for field in set(ib) - set(ia):
                    new_only_keys[field] = new_only_keys.get(field, 0) + 1
                for field in set(ia) - set(ib):
                    old_only_keys[field] = old_only_keys.get(field, 0) + 1
    totals = {
        "old_items": sum(r["items_total"] for r in lhs.values()),
        "new_items": sum(r["items_total"] for r in rhs.values()),
        "old_matched": sum(r["matched_total"] for r in lhs.values()),
        "new_matched": sum(r["matched_total"] for r in rhs.values()),
        "old_seconds": old.get("total_seconds"),
        "new_seconds": new.get("total_seconds"),
    }
    print("== TOTAIS ==")
    print(json.dumps(totals, indent=1))
    print("== CAMPOS COMPARADOS (contagem de comparacoes) ==")
    print(json.dumps(compared_fields, indent=1, sort_keys=True))
    if old_only_keys:
        print("== CAMPOS SO NO OLD ==")
        print(json.dumps(old_only_keys, indent=1, sort_keys=True))
    if new_only_keys:
        print("== CAMPOS SO NO NEW (aditivos) ==")
        print(json.dumps(new_only_keys, indent=1, sort_keys=True))
    print(f"== PROBLEMAS: {problems_total[0]} (exibindo no maximo 25; decisao: {decision_problems[0]}) ==")
    print("== PROBLEMAS POR CAMPO ==")
    print(json.dumps(dict(sorted(problem_fields.items(), key=lambda kv: -kv[1])), indent=1, sort_keys=True))
    for problem in problems:
        print(" ", problem)
    counts_ok = totals["old_items"] == totals["new_items"] and totals["old_matched"] == totals["new_matched"]
    print("ESTRITO (todos os campos):", "IDENTICO" if problems_total[0] == 0 and counts_ok else "DIVERGENTE")
    ok = decision_problems[0] == 0 and counts_ok
    print("DECISAO (campos de comportamento):", "IDENTICO" if ok else "DIVERGENTE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

