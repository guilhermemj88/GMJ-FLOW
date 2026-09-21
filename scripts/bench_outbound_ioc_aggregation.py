"""P3 outbound IOC aggregation benchmark (shadow, detect-only).

Reproduces the P3 aggregation claim across four scenarios and an end-to-end
P2 -> P3 pipeline for 100k and 250k flow observations.

Usage: python3 scripts/bench_outbound_ioc_aggregation.py
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.active_ioc_hotset import ActiveIocHotSet  # noqa: E402
from app.services.threat_intelligence import ensure_threat_intel_schema  # noqa: E402
from app.services.network_context import CGNAT_PUBLIC, CUSTOMER  # noqa: E402
from app.services.outbound_ioc_detector import OutboundIocCandidate, OutboundIocShadowDetector  # noqa: E402
from app.services.outbound_ioc_aggregation import OutboundIocAggregator  # noqa: E402
from app.services.behavioral_detection import FlowObservation  # noqa: E402

BASE = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
ISO = BASE.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def make_candidate(src_ip, dst_ip, src_role=CUSTOMER, src_port=40000, dst_port=443, protocol=6):
    return OutboundIocCandidate(
        timestamp=ISO,
        sensor="bench",
        direction="OUTBOUND",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_role=src_role,
        dst_role="EXTERNAL",
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packets=10,
        bytes=1000,
        flow_count=1,
        ioc_matched=True,
        ioc_ip=dst_ip,
        semantic_tier=1,
        signal_class="HIGH_VALUE",
        providers=("CEREAL2",),
        indicator_types=("C2",),
        classifications=("c2",),
        categories=("c2",),
        botnet_family="",
        tags=(),
        network_context={},
        subscriber_resolution_available=False,
    )


def bench_aggregation_scenarios():
    print("== P3 aggregation scenarios (candidates -> aggregator) ==")
    fake_resolver_calls = {"n": 0}

    def fake_resolver(public_ip, src_port, protocol, timestamp):
        fake_resolver_calls["n"] += 1
        return {
            "matched": True,
            "ambiguous": False,
            "private_ip": f"10.99.{int(public_ip.split('.')[3])}.{src_port % 255}",
            "subscriber_id": f"SUB-{public_ip}",
            "confidence": 0.9,
        }

    scenarios = []

    # A. many repeated hits: 100 clients x 100 IOCs
    def scenario_a(n):
        cands = []
        for i in range(n):
            client = f"10.0.{i % 100}.{i % 250}"
            ioc = f"203.0.113.{i % 100}"
            cands.append(make_candidate(client, ioc))
        return cands
    scenarios.append(("A repeated 100x100", scenario_a))

    # B. high cardinality: unique client-IOC pairs
    def scenario_b(n):
        cands = []
        for i in range(n):
            client = f"10.0.{i // 250}.{i % 250}"
            ioc = f"198.51.100.{i % 250}"
            cands.append(make_candidate(client, ioc))
        return cands
    scenarios.append(("B cardinal", scenario_b))

    # C. CGNAT 1% resolution
    def scenario_c(n):
        cands = []
        for i in range(n):
            if i % 100 == 0:
                cands.append(make_candidate("100.64.0.5", f"203.0.113.{i % 100}", src_role=CGNAT_PUBLIC, src_port=1000 + (i % 5)))
            else:
                cands.append(make_candidate(f"10.0.{i % 100}.{i % 250}", f"203.0.113.{i % 100}"))
        return cands
    scenarios.append(("C cgnat 1%", scenario_c))

    # D. CGNAT 10% resolution
    def scenario_d(n):
        cands = []
        for i in range(n):
            if i % 10 == 0:
                cands.append(make_candidate("100.64.0.5", f"203.0.113.{i % 100}", src_role=CGNAT_PUBLIC, src_port=1000 + (i % 20)))
            else:
                cands.append(make_candidate(f"10.0.{i % 100}.{i % 250}", f"203.0.113.{i % 100}"))
        return cands
    scenarios.append(("D cgnat 10%", scenario_d))

    for size in (10000, 50000, 100000):
        for name, gen in scenarios:
            best = None
            for _ in range(3):
                agg = OutboundIocAggregator(
                    enabled=True, window_seconds=300, cgnat_resolver=fake_resolver
                )
                cands = gen(size)
                started = time.perf_counter()
                cycle = agg.ingest(cands, now=BASE)
                elapsed = time.perf_counter() - started
                if best is None or elapsed < best[0]:
                    best = (elapsed, cycle, agg)
            elapsed, cycle, agg = best
            rels_per_sec = len(cycle.relationships) / elapsed if elapsed else 0.0
            print(
                f"size={size:>6} {name:<18} cycle={elapsed*1000:8.1f}ms "
                f"relationships={len(cycle.relationships):>7} rel/s={rels_per_sec:9.0f} "
                f"clients={len(cycle.client_summaries):>7} cgnat_lookups={agg.status()['cgnat_resolution_attempts']} "
                f"cache_hits={agg.status()['cgnat_cache_hits']}"
            )


def ioc_ip(i):
    return "198.51.%d.%d" % (i // 250, i % 250)


def build_hotset(db_path, count):
    conn = sqlite3.connect(db_path)
    ensure_threat_intel_schema(conn)
    conn.execute("UPDATE threat_intel_providers SET enabled = 1 WHERE provider = 'CEREAL2'")
    conn.executemany(
        "INSERT INTO threat_intel_indicators (provider, indicator_type, ip, classification, active, updated_at)"
        " VALUES ('CEREAL2','C2',?, 'c2', 1, '2026-09-16T00:00:00Z')",
        [(ioc_ip(i),) for i in range(count)],
    )
    conn.commit()
    conn.close()


class StaticContext:
    def __init__(self):
        from app.services.network_context import NetworkContext
        self.default = NetworkContext(src_role=CUSTOMER, dst_role="EXTERNAL", traffic_direction="OUTBOUND")

    def prepare_resolver(self):
        def resolve(*a, **k):
            return self.default
        return resolve


def bench_end_to_end():
    print("\n== End-to-end: FlowObservations -> P2 -> P3 ==")
    tmp = tempfile.TemporaryDirectory()
    db_path = os.path.join(tmp.name, "ti.db")
    build_hotset(db_path, 10000)

    def factory():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    hotset = ActiveIocHotSet(factory, enabled=True)
    assert hotset.refresh()
    detector = OutboundIocShadowDetector(
        connection_factory=factory,
        hotset=hotset,
        network_context=StaticContext(),
        enabled=True,
    )
    agg = OutboundIocAggregator(connection_factory=factory, enabled=True, window_seconds=300)

    for n in (100000, 250000):
        observations = [
            FlowObservation(
                observed_at=BASE,
                src_ip=f"10.0.{i % 200}.{i % 250}",
                dst_ip=ioc_ip(i % 10000),
                src_port=40000 + (i % 20000),
                dst_port=443,
                protocol=6 if i % 2 else 17,
                tcp_flags=0x10,
                packets=10,
                bytes=1000,
                flow_count=1,
                sensor="bench",
                exporter_ip="192.0.2.1",
                input_if=10,
                output_if=20,
            )
            for i in range(n)
        ]
        best = None
        for _ in range(3):
            agg2 = OutboundIocAggregator(connection_factory=factory, enabled=True, window_seconds=300)
            started = time.perf_counter()
            det = detector.detect(observations)
            cycle = agg2.ingest(det.candidates, now=BASE)
            elapsed = time.perf_counter() - started
            if best is None or elapsed < best[0]:
                best = (elapsed, det, cycle)
        elapsed, det, cycle = best
        print(
            f"observations={n:>6} p2_candidates={len(det.candidates):>6} "
            f"p3_relationships={len(cycle.relationships):>6} "
            f"p3_clients={len(cycle.client_summaries):>6} "
            f"total={elapsed*1000:8.1f}ms "
            f"p2={det.metrics['cycle_duration_ms']:7.1f}ms "
            f"p3={cycle.metrics['aggregation_cycle_ms']:7.1f}ms"
        )
    tmp.cleanup()


if __name__ == "__main__":
    bench_aggregation_scenarios()
    bench_end_to_end()
