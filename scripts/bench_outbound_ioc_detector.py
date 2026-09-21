#!/usr/bin/env python3
"""Benchmark for the P2 outbound IOC shadow detector.

Builds a real ActiveIocHotSet (10k IOCs) over a temporary SQLite control
plane, then runs detector cycles over synthetic FlowObservation batches:
sizes 10k/50k/100k observations; IOC density 0%/1%/10% among destinations;
destination profile repeated (100 unique dst) vs high-cardinality.

Reports cycle latency, observations/sec, unique hotset lookups, candidate
count and RSS delta. No SQLite in the hot path; snapshot built once.
"""

from __future__ import annotations

import os
import resource
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timezone
from ipaddress import ip_address

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.active_ioc_hotset import ActiveIocHotSet  # noqa: E402
from app.services.threat_intelligence import ensure_threat_intel_schema  # noqa: E402
from app.services.network_context import (  # noqa: E402
    CGNAT_PUBLIC,
    CUSTOMER,
    EXTERNAL,
    NetworkContext,
)
from app.services.outbound_ioc_detector import OutboundIocShadowDetector  # noqa: E402
from app.services.behavioral_detection import FlowObservation  # noqa: E402

IOC_COUNT = 10_000
IOC_BASE = int(ip_address("198.51.100.0"))
DST_BASE = int(ip_address("203.0.113.0"))
SRC_BASE = int(ip_address("10.0.0.0"))
NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


class StaticResolver:
    def prepare_resolver(self):
        def resolve(src_ip, dst_ip, *_args, **_kwargs):
            return NetworkContext(
                src_role=CUSTOMER, dst_role=EXTERNAL,
                traffic_direction="OUTBOUND",
            )
        return resolve


def build_hotset(db_path):
    conn = sqlite3.connect(db_path)
    ensure_threat_intel_schema(conn)
    conn.execute("UPDATE threat_intel_providers SET enabled = 1 WHERE provider = 'CEREAL2'")
    conn.executemany(
        "INSERT INTO threat_intel_indicators"
        " (provider, indicator_type, ip, classification, active, updated_at)"
        " VALUES ('CEREAL2','C2',?,'c2',1,'2026-09-16T00:00:00Z')",
        [(str(ip_address(IOC_BASE + i)),) for i in range(IOC_COUNT)],
    )
    conn.commit()
    conn.close()
    hotset = ActiveIocHotSet(_factory(db_path), enabled=True)
    assert hotset.refresh()
    return hotset


def _factory(path):
    def factory():
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return conn
    return factory


def run_case(size, density, repeated):
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    tmp = tempfile.TemporaryDirectory()
    db_path = os.path.join(tmp.name, "ti.db")
    hotset = build_hotset(db_path)
    detector = OutboundIocShadowDetector(
        hotset=hotset, network_context=StaticResolver(), enabled=True
    )

    observations = []
    for i in range(size):
        if repeated:
            dst_index = i % 100
        else:
            dst_index = i
        is_ioc = ((dst_index * 7) % 100) < int(density * 100)
        dst = IOC_BASE + (dst_index % IOC_COUNT) if is_ioc else DST_BASE + (dst_index % 65000)
        observations.append(
            FlowObservation(
                observed_at=NOW, src_ip=str(ip_address(SRC_BASE + (i % 50000))),
                dst_ip=str(ip_address(dst)), src_port=40000 + (i % 20000),
                dst_port=443 if i % 2 else 8443, protocol=6 if i % 3 else 17,
                tcp_flags=0x10, packets=10, bytes=1000, flow_count=1,
                sensor="bench", exporter_ip="192.0.2.1", input_if=10, output_if=20,
            )
        )

    best = None
    for _ in range(3):
        t0 = time.perf_counter()
        result = detector.detect(observations)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        best = elapsed_ms if best is None else min(best, elapsed_ms)
    lookups = result.metrics["unique_destinations_checked"]
    candidates = result.metrics["candidates_total"]
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(
        f"size={size:>6} density={int(density*100):>3}% {'repeated' if repeated else 'cardinal':>9} "
        f"cycle={best:8.1f}ms obs/s={size/(best/1000):>10,.0f} "
        f"unique_dst_lookups={lookups:>6} candidates={candidates:>5} rss_delta={rss_after-rss_before}KB"
    )
    tmp.cleanup()


def main():
    for size in (10_000, 50_000, 100_000):
        for density in (0.0, 0.01, 0.10):
            run_case(size, density, repeated=True)
        run_case(size, 0.01, repeated=False)
        run_case(size, 0.10, repeated=False)


if __name__ == "__main__":
    main()