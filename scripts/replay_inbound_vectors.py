#!/usr/bin/env python3
"""Replay historico read-only dos presets inbound/download (Fase 4).

Executa o MESMO caminho do detector (`query_detection_rule_candidates`) para
cada preset x modo (single/multi) x janela (30/60s) sobre buckets FECHADOS
recentes, usando o ClickHouse real em modo SOMENTE LEITURA (SELECT). Nao grava
anomalias, nao toca SQLite e nao altera nada em producao.

Uso (dentro de um container descartavel com a mesma rede do ClickHouse):

    docker run --rm --network gmj-flow_default \
      -v /home/guilherme/GMJ-FLOW:/repo:ro -w /repo \
      -e CLICKHOUSE_HOST=clickhouse -e CLICKHOUSE_PORT=8123 \
      -e CLICKHOUSE_USER=default -e CLICKHOUSE_PASSWORD= \
      -e CLICKHOUSE_DATABASE=flowdb \
      gmj-flow-backend:latest \
      python scripts/replay_inbound_vectors.py \
        --prefixes-file /tmp/inbound_replay_prefixes.json \
        --buckets 4 --window both --modes single,multi --out /tmp/inbound_replay.json

O arquivo de prefixes e gerado no host a partir do SQLite em modo -readonly.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services import inbound_vectors  # noqa: E402
from backend.app import main as backend_main  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay read-only dos presets inbound")
    parser.add_argument("--prefixes-file", required=True, help="JSON: [{prefix_id, cidr, zone_id, zone_name}]")
    parser.add_argument("--presets", default="all", help="'all' ou lista separada por virgula")
    parser.add_argument("--modes", default="single,multi", help="single,multi")
    parser.add_argument("--window", default="both", choices=["30", "60", "both"])
    parser.add_argument("--buckets", type=int, default=4, help="buckets fechados por variante")
    parser.add_argument("--end-offset-seconds", type=int, default=300)
    parser.add_argument("--end-iso", default="", help="ISO UTC; sobrescreve now()-offset (janelas historicas)")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--benchmark-cardinality", action="store_true")
    parser.add_argument("--out", default="")
    return parser.parse_args()


def load_prefixes(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    prefixes: list[dict] = []
    for entry in data:
        prefixes.append(
            {
                "zone": {"id": int(entry["zone_id"]), "name": entry.get("zone_name") or f"zone-{entry['zone_id']}"},
                "prefix": {"id": int(entry["prefix_id"]), "cidr": entry["cidr"]},
            }
        )
    return prefixes


def rule_from_preset(preset: inbound_vectors.InboundVectorPreset, multi: bool, window_seconds: int) -> dict:
    payload = inbound_vectors.preset_rule_payload(preset, multi=multi, window_seconds=window_seconds)
    rule = dict(payload)
    rule.update(
        {
            "id": 900000 + (1 if multi else 0),
            "detection_key": payload.get("group_by", ""),
            "mitigation_mode": "detection_only",
            "mitigation_enabled": 0,
            "enabled": True,
            "sensor_id": None,
        }
    )
    return rule


def floor_to(seconds_epoch: float, window: int) -> datetime:
    epoch = int(seconds_epoch)
    return datetime.fromtimestamp(epoch - (epoch % window), tz=timezone.utc)


def summarize_items(items: list[dict], metric_key: str = "bits_s") -> dict:
    warning = [item for item in items if item.get("matched") and item.get("severity") == "warning"]
    critical = [item for item in items if item.get("matched") and item.get("severity") == "critical"]

    def top(rows: list[dict], count: int = 5) -> list[dict]:
        ordered = sorted(rows, key=lambda item: float(item.get(metric_key) or 0), reverse=True)
        return [
            {
                "target": item.get("dst_ip") or item.get("internal_ip") or item.get("prefix_cidr") or "",
                "bps": round(float(item.get("bits_s") or 0), 2),
                "pps": round(float(item.get("packets_s") or 0), 2),
                "unique_src_ips": int(item.get("unique_src_ips") or 0),
                "unique_dst_ips": int(item.get("unique_dst_ips") or 0),
                "avg_packet_bytes": round(float(item.get("avg_packet_bytes") or 0), 2),
            }
            for item in ordered[:count]
        ]

    return {
        "rows": len(items),
        "warning_matches": len(warning),
        "critical_matches": len(critical),
        "max_bps": max((float(item.get("bits_s") or 0) for item in items), default=0.0),
        "max_pps": max((float(item.get("packets_s") or 0) for item in items), default=0.0),
        "max_unique_dst_ips": max((int(item.get("unique_dst_ips") or 0) for item in items), default=0),
        "max_unique_src_ips": max((int(item.get("unique_src_ips") or 0) for item in items), default=0),
        "top_warning": top(warning),
        "top_critical": top(critical),
    }


def run_replay(args: argparse.Namespace, prefixes: list[dict]) -> dict:
    if args.presets == "all":
        preset_ids = [preset.id for preset in inbound_vectors.list_presets()]
    else:
        preset_ids = [item.strip() for item in args.presets.split(",") if item.strip()]
    modes = [item.strip() for item in args.modes.split(",") if item.strip() and item.strip() in {"single", "multi"}]
    windows = [30, 60] if args.window == "both" else [int(args.window)]

    reference = datetime.now(timezone.utc) - timedelta(seconds=max(0, args.end_offset_seconds))
    if args.end_iso:
        reference = datetime.fromisoformat(args.end_iso.replace("Z", "+00:00"))
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
    cache = backend_main.DetectionScanCache()
    results: list[dict] = []
    for preset_id in preset_ids:
        preset = inbound_vectors.get_preset(preset_id)
        for multi in (False, True):
            if multi and not preset.supports_multi():
                continue
            if (multi and "multi" not in modes) or (not multi and "single" not in modes):
                continue
            for window in windows:
                rule = rule_from_preset(preset, multi, window)
                end_base = floor_to(reference.timestamp(), window)
                for bucket_index in range(max(1, args.buckets)):
                    end_dt = end_base - timedelta(seconds=window * bucket_index)
                    start_dt = end_dt - timedelta(seconds=window)
                    for entry in prefixes:
                        zone = dict(entry["zone"])
                        prefix = dict(entry["prefix"])
                        started = time.monotonic()
                        try:
                            items = backend_main.query_detection_rule_candidates(
                                zone,
                                {"id": 1, "name": "REPLAY-INBOUND", "active": True},
                                rule,
                                prefix,
                                start_dt,
                                end_dt,
                                None,
                                limit=args.limit,
                                include_unmatched=True,
                                query_cache=cache,
                            )
                            error = ""
                        except Exception as exc:  # pragma: no cover - diagnostico
                            items = []
                            error = str(exc)
                        elapsed = time.monotonic() - started
                        summary = summarize_items(items, metric_key=rule.get("metric") or "bits_s")
                        if not summary["rows"] and not error:
                            continue
                        results.append(
                            {
                                "preset": preset.id,
                                "mode": "multi" if multi else "single",
                                "window_seconds": window,
                                "bucket_start": start_dt.isoformat(),
                                "bucket_end": end_dt.isoformat(),
                                "prefix": prefix["cidr"],
                                "zone": zone["name"],
                                "elapsed_s": round(elapsed, 3),
                                "error": error,
                                **summary,
                            }
                        )
                        print(
                            f"[{preset.id} {('multi' if multi else 'single')} {window}s] "
                            f"{prefix['cidr']} {start_dt.strftime('%H:%M')}-{end_dt.strftime('%H:%M')} "
                            f"rows={summary['rows']} warn={summary['warning_matches']} crit={summary['critical_matches']} "
                            f"max_bps={summary['max_bps']:.0f} max_pps={summary['max_pps']:.0f} "
                            f"elapsed={elapsed:.2f}s",
                            flush=True,
                        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reference_end": reference.isoformat(),
        "buckets": args.buckets,
        "results": results,
        "scan_cache": {"queries_executed": cache.misses, "queries_reused": cache.hits, "rows_cached": cache.total_rows},
    }


def benchmark_cardinality(prefixes: list[dict], window: int = 60, buckets: int = 2) -> list[dict]:
    """Compara uniqExact x uniqCombined x uniq no frame real (precisao x custo)."""
    reference = floor_to(time.time() - 300, window)
    entry = prefixes[0] if prefixes else None
    if entry is None:
        return []
    rows = []
    for bucket_index in range(max(1, buckets)):
        end_dt = reference - timedelta(seconds=window * bucket_index)
        start_dt = end_dt - timedelta(seconds=window)
        for function in ("uniqExact", "uniqCombined", "uniq"):
            query = f"""
                SELECT
                    count() AS groups,
                    {function}(unique_src_ip_value) AS src_ips,
                    {function}(unique_dst_ip_value) AS dst_ips
                FROM (
                    SELECT
                        toString(flow_raw.src_ip) AS unique_src_ip_value,
                        toString(flow_raw.dst_ip) AS unique_dst_ip_value
                    FROM flow_raw
                    WHERE flow_time >= {{start:DateTime}} AND flow_time <= {{end:DateTime}}
                      AND proto = 17 AND src_port = 53
                      AND isIPAddressInRange(CAST(toString(flow_raw.dst_ip) AS String), {{prefix_cidr:String}})
                )
            """
            params = {
                "start": start_dt,
                "end": end_dt,
                "prefix_cidr": backend_main.clickhouse_cidr_string_param(entry["prefix"]["cidr"], "cidr"),
            }
            started = time.monotonic()
            try:
                result = backend_main.query_clickhouse(query, params)
                row = backend_main.rows_as_dicts(result)[0]
                rows.append(
                    {
                        "function": function,
                        "prefix": entry["prefix"]["cidr"],
                        "bucket_start": start_dt.isoformat(),
                        "elapsed_s": round(time.monotonic() - started, 4),
                        "src_ips": int(row.get("src_ips") or 0),
                        "dst_ips": int(row.get("dst_ips") or 0),
                    }
                )
            except Exception as exc:  # pragma: no cover - diagnostico
                rows.append({"function": function, "error": str(exc)})
    for row in rows:
        print(f"[bench {row.get('function')}] {row}", flush=True)
    return rows


def main() -> int:
    args = parse_args()
    prefixes = load_prefixes(args.prefixes_file)
    print(f"prefixes={len(prefixes)} presets={args.presets} modes={args.modes} window={args.window}", flush=True)
    payload: dict = {}
    if args.benchmark_cardinality:
        payload["cardinality_benchmark"] = benchmark_cardinality(prefixes)
    payload.update(run_replay(args, prefixes))
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"json salvo em {args.out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
