#!/usr/bin/env python3
"""Benchmark for the P1 Active IOC Hot Set.

Builds synthetic IOC datasets (10k/50k/100k/500k by default) into a temporary
SQLite control plane, then measures:
  - SQLite load time (insertion)
  - snapshot build + atomic swap time (hot set refresh)
  - local lookup latency (hit/miss, median/p95/p99) and throughput
  - approximate RSS delta
  - a SQLite per-lookup reference (10k lookups) for order-of-magnitude
    comparison with the local hot path.

The snapshot is built ONCE per size; lookups never rebuild it (no artificial
per-lookup rebuild).

Usage: python3 scripts/bench_ioc_hotset.py [sizes...]
"""

from __future__ import annotations

import os
import resource
import sqlite3
import sys
import tempfile
import time
from ipaddress import IPv4Address, IPv6Address, ip_address

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.active_ioc_hotset import ActiveIocHotSet  # noqa: E402
from app.services.threat_intelligence import ensure_threat_intel_schema  # noqa: E402

QUERIES = 100_000
WARMUP = 10_000


def pct(values, p):
    s = sorted(values)
    if not s:
        return 0.0
    idx = (len(s) - 1) * p
    lo = int(idx)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (idx - lo)


def rss_kb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def build_dataset(db_path, size):
    conn = sqlite3.connect(db_path)
    ensure_threat_intel_schema(conn)
    conn.execute("UPDATE threat_intel_providers SET enabled = 0")
    conn.execute("UPDATE threat_intel_providers SET enabled = 1 WHERE provider IN ('CEREAL2','FEODO')")
    conn.commit()

    ipv4_base = int(ip_address("11.0.0.0"))
    ipv6_base = int(ip_address("2001:db8::"))
    rows = []
    for i in range(size):
        rows.append(("CEREAL2", "C2", str(ip_address(ipv4_base + i)), "", "c2", "", "[]", 1))
    v6_count = max(1, size // 4)
    for i in range(v6_count):
        rows.append(("FEODO", "BOTNET", str(ip_address(ipv6_base + i)), "", "active_botnet", "Mirai", "[]", 1))
    for i in range(50):
        net = ip_address(ipv4_base + 10_000_000 + i * 256)
        rows.append(("CEREAL2", "NETWORK", "", f"{net}/24", "compromised_host", "", "[]", 1))
    conn.executemany(
        """
        INSERT INTO threat_intel_indicators
            (provider, indicator_type, ip, network, classification, botnet_family, tags_json, active, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, '2026-09-16T00:00:00Z')
        """,
        rows,
    )
    conn.commit()
    conn.close()
    return len(rows)


def run_size(size):
    print(f"--- size={size} ---", flush=True)
    rss_before = rss_kb()
    tmp = tempfile.TemporaryDirectory()
    db_path = os.path.join(tmp.name, "ti.db")
    t0 = time.perf_counter()
    row_count = build_dataset(db_path, size)
    load_s = time.perf_counter() - t0

    factory = _factory(db_path)
    hotset = ActiveIocHotSet(factory, enabled=True)

    t0 = time.perf_counter()
    ok = hotset.refresh()
    build_s = time.perf_counter() - t0
    rss_after = rss_kb()

    ipv4_base = int(ip_address("11.0.0.0"))
    ipv6_base = int(ip_address("2001:db8::"))
    miss_base = int(ip_address("22.0.0.0"))
    hit_ips = [str(ip_address(ipv4_base + (i * 7919) % size)) for i in range(QUERIES // 2)]
    hit_ips += [str(ip_address(ipv6_base + (i * 7919) % max(1, size // 4))) for i in range(QUERIES // 4)]
    miss_ips = [str(ip_address(miss_base + i)) for i in range(QUERIES // 4)]

    # warmup
    for ip in hit_ips[:WARMUP]:
        hotset.lookup(ip)
    for ip in miss_ips[:WARMUP]:
        hotset.lookup(ip)

    hit_lat = []
    miss_lat = []
    t0 = time.perf_counter()
    for ip in hit_ips:
        entry = hotset.lookup(ip)
        if entry is None:  # sanity
            raise SystemExit(f"unexpected miss for {ip}")
    for ip in miss_ips:
        if hotset.lookup(ip) is not None:
            raise SystemExit(f"unexpected hit for {ip}")
    total_s = time.perf_counter() - t0

    # second pass with per-lookup timing
    for ip in hit_ips:
        t = time.perf_counter_ns()
        hotset.lookup(ip)
        hit_lat.append(time.perf_counter_ns() - t)
    for ip in miss_ips:
        t = time.perf_counter_ns()
        hotset.lookup(ip)
        miss_lat.append(time.perf_counter_ns() - t)

    lookups = len(hit_ips) + len(miss_ips)
    print(f"rows={row_count} sqlite_load={load_s:.2f}s build+swap={build_s*1000:.1f}ms ok={ok}")
    print(f"lookups={lookups} throughput={lookups/total_s:,.0f}/s")
    print(f"hit  ns: median={pct(hit_lat,0.5):.0f} p95={pct(hit_lat,0.95):.0f} p99={pct(hit_lat,0.99):.0f}")
    print(f"miss ns: median={pct(miss_lat,0.5):.0f} p95={pct(miss_lat,0.95):.0f} p99={pct(miss_lat,0.99):.0f}")
    print(f"rss_delta={rss_after-rss_before} KB snapshot_exact={hotset.status()['indicator_count_exact']} network={hotset.status()['indicator_count_network']}")

    # separate prefix-lookup benchmark (queries land inside the 50 /24 networks)
    prefix_ips = [str(ip_address(ipv4_base + 10_000_000 + (i * 256) + (i % 100) + 5)) for i in range(50)]
    prefix_queries = [prefix_ips[i % 50] for i in range(100_000)]
    for ip in prefix_queries[:WARMUP]:
        hotset.lookup(ip)
    prefix_lat = []
    for ip in prefix_queries:
        t = time.perf_counter_ns()
        if hotset.lookup(ip) is None:
            raise SystemExit(f"unexpected prefix miss for {ip}")
        prefix_lat.append(time.perf_counter_ns() - t)
    print(f"prefix ns: median={pct(prefix_lat,0.5):.0f} p95={pct(prefix_lat,0.95):.0f} p99={pct(prefix_lat,0.99):.0f}")

    if size <= 10000:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        t = time.perf_counter_ns()
        for ip in hit_ips[:10000]:
            conn.execute(
                "SELECT 1 FROM threat_intel_indicators WHERE active=1 AND ip=? LIMIT 1", (ip,)
            ).fetchall()
        sqlite_us = (time.perf_counter_ns() - t) / 10000 / 1000
        print(f"reference sqlite per-lookup={sqlite_us:.1f}us (local hit median={pct(hit_lat,0.5)/1000:.2f}us)")
        conn.close()
    tmp.cleanup()


def _factory(path):
    def factory():
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return conn
    return factory


def main():
    sizes = [int(arg) for arg in sys.argv[1:]] or [10_000, 50_000, 100_000, 500_000]
    for size in sizes:
        run_size(size)


if __name__ == "__main__":
    main()