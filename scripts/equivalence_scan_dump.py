#!/usr/bin/env python3
"""Dump de varredura para equivalencia old x new das regras de deteccao (Fase 4.1).

Executa o caminho real de scan (`query_detection_rule_candidates`) para TODAS as
regras habilitadas na MESMA janela fixa e grava um JSON com os itens compactados
para comparacao posterior por `equivalence_scan_compare.py`.

Importante: o codigo usado e o da IMAGEM (`/app`), nunca o repo montado ??? assim a
mesma invocacao serve para os dois lados (imagem antiga x nova):

    docker run --rm --network gmj-flow_default \
      -v /home/guilherme/GMJ-FLOW/data/backend:/proddata:ro \
      -v /tmp/f41:/work -e GMJFLOW_RUNTIME_DIR=/tmp \
      -e CLICKHOUSE_HOST=clickhouse -e CLICKHOUSE_PORT=8123 \
      -e CLICKHOUSE_USER=default -e CLICKHOUSE_PASSWORD= \
      -e CLICKHOUSE_DATABASE=flowdb \
      gmj-flow-backend:pre-fase4-20261006 \
      python /work/equivalence_scan_dump.py \
        --end-iso 2026-10-06T15:00:00Z --out /work/equiv_old.json

O SQLite de producao e lido SOMENTE em modo leitura via ATTACH; o scan roda sobre
um scratch gravavel (ensure_sensor_db e chamado por sample-rate em old e new).
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [p for p in ("/app", str(ROOT / "backend")) if os.path.isdir(p)]

import app.main as backend_main  # noqa: E402

DROP_KEYS = {"sql", "query", "clickhouse_query", "query_text", "raw_sql", "dsl_expression", "expression", "sql_text"}

COPY_TABLES = [
    "detection_templates",
    "ip_zones",
    "ip_zone_prefixes",
    "detection_template_rules",
    "sensors",
    "sensor_interfaces",
    "network_assets",
    "network_asset_services",
    "threat_network_contexts",
]


def iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def compact_item(item: dict) -> dict:
    out = {}
    for key, value in item.items():
        if key in DROP_KEYS:
            continue
        if isinstance(value, str) and len(value) > 300:
            continue
        out[key] = value
    return out


def build_scratch(prod_db: str, scratch_db: str) -> tuple[sqlite3.Connection, list[str]]:
    if os.path.exists(scratch_db):
        os.remove(scratch_db)
    os.environ["GMJFLOW_DB_PATH"] = scratch_db
    backend_main.ensure_sensor_db()
    conn = sqlite3.connect(scratch_db, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute(f"ATTACH DATABASE '{prod_db}' AS prod")
    for table in reversed(COPY_TABLES):
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone():
            conn.execute(f"DELETE FROM main.{table}")
    copied: list[str] = []
    for table in COPY_TABLES:
        if not conn.execute("SELECT 1 FROM prod.sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone():
            continue
        prod_cols = [r[1] for r in conn.execute(f"PRAGMA prod.table_info({table})")]
        local_cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
        common = [c for c in prod_cols if c in local_cols]
        if not common:
            continue
        cols = ", ".join(common)
        conn.execute(f"INSERT INTO main.{table} ({cols}) SELECT {cols} FROM prod.{table}")
        copied.append(f"{table}({len(common)})")
    conn.commit()
    return conn, copied


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--end-iso", required=True, help="fim da janela fixa (ISO-8601 UTC)")
    ap.add_argument("--out", required=True, help="arquivo JSON de saida")
    ap.add_argument("--prod-db", default="/proddata/gmjflow.db")
    ap.add_argument("--scratch-db", default="/tmp/equivalence_scan_scratch.db")
    ap.add_argument("--limit-rules", default="", help="lista de ids para depuracao, ex.: 13,14")
    args = ap.parse_args()

    end_dt = iso(args.end_iso)
    conn, copied = build_scratch(args.prod_db, args.scratch_db)
    print(f"scratch: {args.scratch_db} copiado: {copied}", flush=True)

    rows = backend_main.detection_template_rule_rows(conn)
    only = {int(x) for x in args.limit_rules.split(",") if x.strip()}
    rows = [r for r in rows if r["enabled"] and (not only or int(r["id"]) in only)]

    zones: dict[int, list] = {}
    for tid in sorted({int(r["template_id"]) for r in rows}):
        zones[tid] = backend_main.detection_rule_zone_prefixes(conn, tid)

    result = {
        "end_iso": args.end_iso,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pairs": {str(t): len(z) for t, z in zones.items()},
        "rules": {},
    }
    total_start = time.perf_counter()
    for raw in rows:
        tid = int(raw["template_id"])
        rule = backend_main.detection_rule_row_to_dict(raw)
        template = {"id": tid, "name": raw.get("template_name") or "", "active": True}
        window = max(1, int(rule.get("window_seconds") or 60))
        start_dt = end_dt - timedelta(seconds=window)
        record = {
            "template_id": tid,
            "vector": rule.get("vector"),
            "metric": rule.get("metric"),
            "window_seconds": window,
            "seconds": 0.0,
            "items_total": 0,
            "matched_total": 0,
            "prefixes": {},
        }
        rule_start = time.perf_counter()
        for zone, prefix in zones[tid]:
            try:
                items = backend_main.query_detection_rule_candidates(
                    zone, template, rule, prefix, start_dt, end_dt, rule.get("sensor_id"), include_unmatched=True
                )
            except Exception as exc:  # noqa: BLE001
                record["prefixes"][prefix["cidr"]] = {"error": f"{type(exc).__name__}: {exc}"}
                continue
            compact = sorted(
                (compact_item(item) for item in items),
                key=lambda i: json.dumps(i, sort_keys=True, default=str),
            )
            record["prefixes"][prefix["cidr"]] = compact
            record["items_total"] += len(compact)
            record["matched_total"] += sum(1 for i in compact if i.get("matched"))
        record["seconds"] = round(time.perf_counter() - rule_start, 3)
        result["rules"][str(rule["id"])] = record
        print(
            f"rule {rule['id']:>3} {str(record['vector'])[:40]:<40} "
            f"items={record['items_total']:>5} matched={record['matched_total']:>3} {record['seconds']:>7.2f}s",
            flush=True,
        )
    result["total_seconds"] = round(time.perf_counter() - total_start, 3)
    with open(args.out, "w") as fh:
        json.dump(result, fh, sort_keys=True, default=str)
    print(f"OK rules={len(result['rules'])} total={result['total_seconds']:.2f}s -> {args.out}")


if __name__ == "__main__":
    main()

