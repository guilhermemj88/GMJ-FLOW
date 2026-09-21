#!/usr/bin/env python3
"""Offline synthetic benchmark for PMACCT parsing. Never opens ClickHouse."""

from __future__ import annotations

import argparse
import json
import resource
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from collector.pmacct import parse_pmacct as pmacct  # noqa: E402


FIELDS = (
    "src_as",
    "dst_as",
    "in_iface",
    "out_iface",
    "src_host",
    "dst_host",
    "src_port",
    "dst_port",
    "tcpflags",
    "proto",
    "timestamp_start",
    "packets",
    "bytes",
)


def synthetic_lines(count: int) -> list[str]:
    return [
        (
            f"64512,64513,1,2,192.0.2.{index % 250 + 1},"
            f"198.51.100.{index % 250 + 1},{1000 + index % 50000},443,"
            f"0x12,tcp,2026-09-15 12:00:{index % 60:02d},10,{1000 + index}"
        )
        for index in range(count)
    ]


def cpu_seconds() -> float:
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime


def peak_rss_kib() -> int:
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return int(own.ru_maxrss + children.ru_maxrss)


def run_case(batch_size: int, workers: int) -> dict[str, float | int | str]:
    lines = synthetic_lines(batch_size)
    config = pmacct.ParserConfig(
        output_format="csv",
        delimiter=",",
        fallback_fields=FIELDS,
        headers=None,
        sensor="benchmark",
        exporter_ip="203.0.113.1",
        sample_rate=1,
    )
    cpu_started = cpu_seconds()
    wall_started = time.perf_counter()
    with pmacct.ParallelParser(workers) as parser:
        parsed = parser.parse(lines, config)
    wall_seconds = time.perf_counter() - wall_started
    used_cpu_seconds = max(0.0, cpu_seconds() - cpu_started)
    ipc_overhead_estimate = (
        max(
            0.0,
            parsed.parallel_parse_seconds
            - parsed.preparation_seconds
            - parsed.max_chunk_parse_seconds,
        )
        if workers > 1
        else 0.0
    )
    checksum = (
        f"{parsed.rows[0][3]}:{parsed.rows[-1][4]}:{len(parsed.rows)}"
        if parsed.rows
        else "empty"
    )
    return {
        "batch_size": batch_size,
        "workers": workers,
        "rows": len(parsed.rows),
        "wall_seconds": round(wall_seconds, 6),
        "cpu_seconds": round(used_cpu_seconds, 6),
        "rows_per_second": round(len(parsed.rows) / wall_seconds, 2),
        "parallel_parse_seconds": round(parsed.parallel_parse_seconds, 6),
        "worker_cpu_seconds_sum": round(parsed.parse_seconds, 6),
        "preparation_seconds": round(parsed.preparation_seconds, 6),
        "max_chunk_parse_seconds": round(parsed.max_chunk_parse_seconds, 6),
        "ipc_overhead_seconds_estimate": round(ipc_overhead_estimate, 6),
        "peak_rss_kib_approx": peak_rss_kib(),
        "checksum": checksum,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batches", nargs="+", type=int, default=[20000, 50000, 100000])
    parser.add_argument("--workers", nargs="+", type=int, default=[1, 2, 4])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    results = [
        run_case(batch_size, workers)
        for batch_size in args.batches
        for workers in args.workers
    ]
    if args.json:
        print(json.dumps(results, indent=2))
        return
    print(
        "batch workers rows wall_s cpu_s rows_s parallel_s "
        "ipc_est_s peak_rss_kib checksum"
    )
    for item in results:
        print(
            f"{item['batch_size']} {item['workers']} {item['rows']} "
            f"{item['wall_seconds']} {item['cpu_seconds']} "
            f"{item['rows_per_second']} {item['parallel_parse_seconds']} "
            f"{item['ipc_overhead_seconds_estimate']} "
            f"{item['peak_rss_kib_approx']} {item['checksum']}"
        )


if __name__ == "__main__":
    main()
