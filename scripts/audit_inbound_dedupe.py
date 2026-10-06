#!/usr/bin/env python3
"""Auditoria de deduplicacao de eventos DNS inbound (Fase 4.1).

Roda o pipeline REAL de avaliacao (`evaluate_detection_template_rule` ->
whitelist -> cooldown -> upsert de anomalia) com ClickHouse MOCKADO e um SQLite
scratch descartavel, para medir QUANTOS eventos independentes um mesmo ataque
gera quando regras antigas (A/B) e um preset novo (C) compartilham o alvo.

Casos padrao: 20 Mbps/4 kpps, 50 Mbps/10 kpps, 85 Mbps/25 kpps, 120 Mbps/50 kpps
(mesmo dst_ip). Le o SQLite de producao apenas em modo leitura (regras 13/14 e
um zone/prefix reais).

    docker run --rm --network gmj-flow_default \
      -v /home/guilherme/GMJ-FLOW/data/backend:/proddata:ro \
      -v /tmp/f41:/work -e GMJFLOW_RUNTIME_DIR=/tmp \
      gmj-flow-backend:latest \
      python /work/audit_inbound_dedupe.py --out /work/dedupe_audit.json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [p for p in ("/app", str(ROOT / "backend")) if os.path.isdir(p)]

import app.main as backend_main  # noqa: E402
from app.services import inbound_vectors  # noqa: E402

UTC = timezone.utc
END = datetime(2026, 10, 6, 16, 0, tzinfo=UTC)

COLUMNS = [
    "src_ip", "dst_ip", "internal_ip", "protocol", "dst_port", "top_dst_port", "top_src_port",
    "bytes", "packets", "flows", "bits_s", "packets_s", "flows_s",
    "unique_dst_ips", "unique_dst_ports", "unique_src_ports", "unique_src_ips",
    "first_seen", "last_seen", "metric_value",
]

CASES = [
    ("20 Mbps / 4 kpps", 20_000_000.0, 4_000.0),
    ("50 Mbps / 10 kpps", 50_000_000.0, 10_000.0),
    ("85 Mbps / 25 kpps", 85_000_000.0, 25_000.0),
    ("120 Mbps / 50 kpps", 120_000_000.0, 50_000.0),
]

ANOMALY_FIELDS = [
    "id", "vector", "severity", "status", "zone_id", "template_id", "rule_id",
    "target_ip", "target_cidr", "scope_type", "protocol", "src_ip", "dst_ip",
    "bits_s", "packets_s", "flows_s", "unique_src_ports", "unique_dst_ips",
    "dedupe_key", "anomaly_source", "source_engine", "source_id", "source_name",
    "message", "first_seen", "last_seen", "source_details_json",
]


class FakeClickHouseResult:
    def __init__(self, columns, rows):
        self.column_names = list(columns)
        self.result_rows = list(rows)


def make_row(target_ip: str, bps: float, pps: float, metric_value: float, window: int = 60):
    packets = int(pps * window)
    payload_bytes = int(bps / 8 * window)
    data = {
        "src_ip": "203.0.113.9",
        "dst_ip": target_ip,
        "internal_ip": target_ip,
        "protocol": "UDP",
        "dst_port": 0,
        "top_dst_port": 0,
        "top_src_port": 53,
        "bytes": payload_bytes,
        "packets": packets,
        "flows": 500,
        "bits_s": bps,
        "packets_s": pps,
        "flows_s": 8.3,
        "unique_dst_ips": 1,
        "unique_dst_ports": 1,
        "unique_src_ports": 1337,
        "unique_src_ips": 2941,
        "first_seen": END,
        "last_seen": END,
        "metric_value": metric_value,
    }
    return tuple(data[name] for name in COLUMNS)


def insert_row(conn, table, row: dict) -> None:
    cols: list[str] = []
    values: list = []
    for entry in conn.execute(f"PRAGMA table_info({table})"):
        name, ctype, notnull, dflt, pk = entry[1], entry[2], entry[3], entry[4], entry[5]
        if name in row:
            cols.append(name)
            values.append(row[name])
        elif notnull and dflt is None and not pk:
            text_type = any(token in (ctype or "").upper() for token in ("TEXT", "CHAR", "CLOB"))
            cols.append(name)
            values.append("" if text_type else 0)
    placeholders = ", ".join("?" for _ in cols)
    conn.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})", values)


def build_rule_c(template_name: str) -> dict:
    preset = inbound_vectors.get_preset("dns_reflection")
    payload = inbound_vectors.preset_rule_payload(preset, multi=False)
    rule = dict(payload)
    rule.update(
        {
            "id": 901,
            "template_id": 1,
            "template_name": template_name,
            "template_active": 1,
            "detection_key": payload.get("group_by", ""),
            "mitigation_mode": "detection_only",
            "mitigation_enabled": 0,
            "enabled": True,
            "sensor_id": None,
            "created_at": "2026-10-06T00:00:00Z",
            "updated_at": "2026-10-06T00:00:00Z",
        }
    )
    return rule


def build_scratch(prod_rules, zone, prefix, template_name):
    db_path = tempfile.mktemp(suffix=".dedupe.db", dir="/tmp")
    os.environ["GMJFLOW_DB_PATH"] = db_path
    backend_main.ensure_sensor_db()
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = OFF")
    for table in ("detection_template_rules", "ip_zone_prefixes", "ip_zones", "detection_templates", "security_anomalies"):
        conn.execute(f"DELETE FROM {table}")
    insert_row(conn, "detection_templates", {
        "id": 1, "name": template_name, "description": "scratch", "active": 1,
        "created_at": "2026-10-06T00:00:00Z", "updated_at": "2026-10-06T00:00:00Z",
    })
    insert_row(conn, "ip_zones", zone)
    insert_row(conn, "ip_zone_prefixes", prefix)
    rules = {
        "A": dict(prod_rules[13]),
        "B": dict(prod_rules[14]),
        "C": build_rule_c(template_name),
    }
    for rule in rules.values():
        rule["template_id"] = 1
        insert_row(conn, "detection_template_rules", rule)
    conn.commit()
    return conn, rules


def run_case(case_name, bps, pps, rules, scratch, target_ip, results_log) -> None:
    scratch.execute("DELETE FROM security_anomalies")
    scratch.commit()
    rule_results = {}
    for label, rule in rules.items():
        metric_value = bps if rule.get("metric") == "bits_s" else pps
        rows = [make_row(target_ip, bps, pps, metric_value)]
        with mock.patch.object(backend_main, "query_clickhouse", side_effect=lambda query, params: FakeClickHouseResult(COLUMNS, rows)), \
                mock.patch.object(backend_main, "clickhouse_sample_rate_expr", return_value="greatest(sample_rate, 1)"):
            res = backend_main.evaluate_detection_template_rule(scratch, dict(rule), END, create_anomalies=True)
        rule_results[label] = {
            "id": rule.get("id"),
            "vector": rule.get("vector"),
            "metric": rule.get("metric"),
            "thresholds": [rule.get("warning_value"), rule.get("critical_value")],
            "trigger_warning_expr": rule.get("trigger_warning_expr") or "",
            "trigger_critical_expr": rule.get("trigger_critical_expr") or "",
            "detection_key": rule.get("detection_key") or "",
            "group_by": rule.get("group_by") or "",
            "matched": res.get("matched"),
            "anomalies_created": res.get("anomalies_created"),
            "skipped_reason": res.get("skipped_reason"),
        }
        print(f"  [{label}] matched={res.get('matched')} created={res.get('anomalies_created')} skip={res.get('skipped_reason')!r}")

    anomalies = [
        {k: dict(row).get(k) for k in ANOMALY_FIELDS}
        for row in scratch.execute("SELECT * FROM security_anomalies ORDER BY id")
    ]
    results_log.append({
        "case": case_name,
        "bps": bps,
        "pps": pps,
        "target_ip": target_ip,
        "rule_results": rule_results,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    })
    print(f"  -> anomalias no security_anomalies (scratch): {len(anomalies)}")
    for item in anomalies:
        print(f"     #{item['id']} {item['vector']} sev={item['severity']} key={item['dedupe_key']}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prod-db", default="/proddata/gmjflow.db")
    ap.add_argument("--out", default="/work/dedupe_audit.json")
    args = ap.parse_args()

    prod = sqlite3.connect(f"file:{args.prod_db}?mode=ro", uri=True, timeout=30)
    prod.row_factory = sqlite3.Row
    rules = {int(r["id"]): dict(r) for r in backend_main.detection_template_rule_rows(prod)}
    pairs = backend_main.detection_rule_zone_prefixes(prod, 1)
    template = prod.execute("SELECT * FROM detection_templates WHERE id = 1").fetchone()
    template_name = template["name"]
    zone_row = prod.execute("SELECT * FROM ip_zones WHERE id = ?", (pairs[0][0]["id"],)).fetchone()
    prefix_row = prod.execute("SELECT * FROM ip_zone_prefixes WHERE id = ?", (pairs[0][1]["id"],)).fetchone()
    zone = {k: zone_row[k] for k in zone_row.keys()}
    prefix = {k: prefix_row[k] for k in prefix_row.keys()}
    prod.close()

    scratch, scratch_rules = build_scratch(rules, zone, prefix, template_name)
    target_ip = str(ipaddress.ip_address(int(ipaddress.ip_network(prefix["cidr"]).network_address) + 10))

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "template": template_name,
        "zone": zone["id"],
        "prefix": prefix["cidr"],
        "pairs_t1": len(pairs),
        "rule_a": {k: scratch_rules["A"].get(k) for k in ("id", "vector", "metric", "warning_value", "critical_value", "comparison", "group_by", "detection_key", "src_port", "protocol", "direction", "domain")},
        "rule_b": {k: scratch_rules["B"].get(k) for k in ("id", "vector", "metric", "warning_value", "critical_value", "comparison", "group_by", "detection_key", "src_port", "protocol", "direction", "domain")},
        "rule_c": {k: scratch_rules["C"].get(k) for k in ("vector", "metric", "group_by", "detection_key", "src_port", "protocol", "direction", "domain", "trigger_warning_expr", "trigger_critical_expr", "evidence", "window_seconds", "response")},
        "cases": [],
    }
    for case_name, bps, pps in CASES:
        print(f"== CASO {case_name} ==")
        run_case(case_name, bps, pps, scratch_rules, scratch, target_ip, report["cases"])

    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=1, default=str)
    print(f"OK -> {args.out}")


if __name__ == "__main__":
    main()

