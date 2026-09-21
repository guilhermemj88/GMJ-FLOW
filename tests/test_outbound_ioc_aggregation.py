"""P3 outbound IOC shadow aggregation tests."""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.active_ioc_hotset import ActiveIocHotSet, IocSnapshot  # noqa: E402
from app.services.network_context import CGNAT_PUBLIC, CUSTOMER, EXTERNAL  # noqa: E402
from app.services.outbound_ioc_detector import OutboundIocCandidate  # noqa: E402
from app.services.cgnat_mapping import ensure_cgnat_schema  # noqa: E402
from app.services.outbound_ioc_aggregation import (  # noqa: E402
    AMBIGUOUS,
    ERROR,
    IDENTITY_CGNAT_SUBSCRIBER,
    IDENTITY_CUSTOMER_IP,
    RESOLVED,
    UNRESOLVED,
    OutboundIocAggregator,
    OutboundIocClientSummary,
    OutboundIocRelationship,
)

BASE = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


class TestClock:
    def __init__(self, dt: datetime):
        self.now = dt

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def candidate(
    src_ip="10.0.0.10",
    dst_ip="203.0.113.10",
    src_role=CUSTOMER,
    src_port=40000,
    dst_port=443,
    protocol=6,
    ts=None,
    flow_count=1,
    packets=10,
    bytes_count=1000,
    providers=("CEREAL2",),
    indicator_types=("C2",),
    classifications=("c2",),
    categories=("c2",),
    signal_class="HIGH_VALUE",
    semantic_tier=1,
    botnet_family="",
    sensor="edge",
):
    return OutboundIocCandidate(
        timestamp=ts or iso(BASE),
        sensor=sensor,
        direction="OUTBOUND",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_role=src_role,
        dst_role=EXTERNAL,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packets=packets,
        bytes=bytes_count,
        flow_count=flow_count,
        ioc_matched=True,
        ioc_ip=dst_ip,
        semantic_tier=semantic_tier,
        signal_class=signal_class,
        providers=providers,
        indicator_types=indicator_types,
        classifications=classifications,
        categories=categories,
        botnet_family=botnet_family,
        tags=("shadow",),
        network_context={},
        subscriber_resolution_available=False,
    )


def fake_resolver(mapping, calls):
    def resolve(public_ip, src_port, protocol, timestamp):
        calls.append((public_ip, src_port, protocol, timestamp))
        return mapping.get((public_ip, src_port), {"matched": False, "error": "no_mapping"})
    return resolve


class AggregationTest(unittest.TestCase):
    def setUp(self):
        self.clock = TestClock(BASE)
        self.aggregator = OutboundIocAggregator(
            enabled=True, clock=self.clock, window_seconds=300
        )
        self.calls = []

    def agg(self, *cands, now=None):
        return self.aggregator.ingest(cands, now=now or self.clock())

    # 1. first hit creates relationship
    def test_first_hit_creates_relationship(self):
        cycle = self.agg(candidate())
        self.assertEqual(1, len(cycle.relationships))
        rel = cycle.relationships[0]
        self.assertEqual("10.0.0.10", rel.internal_identity)
        self.assertEqual("203.0.113.10", rel.external_ioc)
        self.assertEqual(1, rel.hit_count)
        self.assertEqual(IDENTITY_CUSTOMER_IP, rel.identity_kind)

    # 2. second hit increments hit_count
    def test_second_hit_increments_hit_count(self):
        self.agg(candidate())
        cycle = self.agg(candidate())
        self.assertEqual(1, len(cycle.relationships))
        self.assertEqual(2, cycle.relationships[0].hit_count)

    # 3. packets/bytes/flows accumulated
    def test_packets_bytes_flows_accumulate(self):
        self.agg(candidate(packets=10, bytes_count=1000, flow_count=2))
        cycle = self.agg(candidate(packets=5, bytes_count=500, flow_count=3))
        rel = cycle.relationships[0]
        self.assertEqual(15, rel.packets)
        self.assertEqual(1500, rel.bytes)
        self.assertEqual(5, rel.flows)
        self.assertEqual(2, rel.hit_count)

    # 4/5. first_seen preserved, last_seen updated
    def test_first_seen_preserved_last_seen_updated(self):
        self.agg(candidate(ts=iso(BASE)))
        later = iso(BASE + timedelta(minutes=1))
        cycle = self.agg(candidate(ts=later))
        rel = cycle.relationships[0]
        self.assertEqual(iso(BASE), rel.first_seen)
        self.assertEqual(later, rel.last_seen)

    # 7. same client + different IOC -> unique_ioc_count increments
    def test_same_client_different_ioc_unique_count(self):
        self.agg(candidate(dst_ip="203.0.113.10"))
        cycle = self.agg(candidate(dst_ip="203.0.113.11"))
        self.assertEqual(2, len(cycle.relationships))
        self.assertEqual(1, len(cycle.client_summaries))
        self.assertEqual(2, cycle.client_summaries[0].unique_ioc_count)
        self.assertEqual(2, cycle.client_summaries[0].total_hits)

    # 8. different clients + same IOC -> separate relationships
    def test_different_clients_same_ioc_separate(self):
        self.agg(candidate(src_ip="10.0.0.10"))
        cycle = self.agg(candidate(src_ip="10.0.0.11"))
        self.assertEqual(2, len(cycle.relationships))
        self.assertEqual(2, len(cycle.client_summaries))

    # 9. multi-provider same IOC -> one flow hit, provider union
    def test_multi_provider_union_one_hit(self):
        self.agg(candidate(providers=("CEREAL2",), classifications=("c2",)))
        cycle = self.agg(
            candidate(
                providers=("FEODO", "GREYNOISE"),
                classifications=("botnet", "malicious"),
                categories=("botnet",),
                indicator_types=("BOTNET",),
            )
        )
        rel = cycle.relationships[0]
        self.assertEqual(2, rel.hit_count)  # one hit per flow, not per provider
        self.assertEqual({"CEREAL2", "FEODO", "GREYNOISE"}, rel.providers)

    # 10. TCP443 aggregates
    def test_tcp443_aggregates(self):
        self.agg(candidate(protocol=6, dst_port=443))
        cycle = self.agg(candidate(protocol=6, dst_port=443))
        self.assertEqual(1, len(cycle.relationships))
        self.assertEqual(2, cycle.relationships[0].hit_count)

    # 11. UDP443 aggregates
    def test_udp443_aggregates(self):
        self.agg(candidate(protocol=17, dst_port=443))
        cycle = self.agg(candidate(protocol=17, dst_port=443))
        self.assertEqual(1, len(cycle.relationships))
        self.assertEqual(2, cycle.relationships[0].hit_count)

    # 12. CDN/GGC context does not suppress (metadata preserved)
    def test_cdn_ggc_context_not_suppressed(self):
        cycle = self.agg(
            candidate(categories=("cdn",), signal_class="LOWER_SIGNAL", semantic_tier=4)
        )
        self.assertEqual(1, len(cycle.relationships))
        self.assertEqual({"cdn"}, cycle.relationships[0].categories)

    # 13. IPv6 aggregation
    def test_ipv6_aggregation(self):
        self.agg(candidate(src_ip="2001:db8:100::10", dst_ip="2001:db8:bad::1"))
        cycle = self.agg(candidate(src_ip="2001:db8:100::10", dst_ip="2001:db8:bad::1"))
        self.assertEqual(1, len(cycle.relationships))
        self.assertEqual("2001:db8:100::10", cycle.relationships[0].internal_identity)

    # 14. relationship expires after 5m
    def test_relationship_expires_after_window(self):
        self.agg(candidate())
        self.assertEqual(1, self.aggregator.status()["active_relationships"])
        self.clock.advance(301)
        cycle = self.agg()
        self.assertEqual(0, len(cycle.relationships))
        self.assertEqual(1, cycle.metrics["expired_relationships"])
        self.assertEqual(0, self.aggregator.status()["active_relationships"])

    # 15. new hit refreshes expiration
    def test_new_hit_refreshes_expiration(self):
        self.agg(candidate(ts=iso(BASE)))
        self.clock.advance(250)
        self.agg(candidate(ts=iso(self.clock())))
        self.clock.advance(250)  # 500s after first, 250s after second
        cycle = self.agg()
        self.assertEqual(1, len(cycle.relationships))

    # 16/17. expired removes IOC from client unique count; no retention
    def test_expired_removes_from_unique_and_no_retention(self):
        self.agg(candidate(dst_ip="203.0.113.10"))
        self.agg(candidate(dst_ip="203.0.113.11"))
        self.clock.advance(301)
        cycle = self.agg()
        self.assertEqual(0, len(cycle.relationships))
        self.assertEqual(0, len(cycle.client_summaries))
        self.assertEqual(0, self.aggregator.status()["unique_ioc_current"])


class CgnatAggregationTest(unittest.TestCase):
    def setUp(self):
        self.clock = TestClock(BASE)
        self.calls = []
        self.aggregator = OutboundIocAggregator(
            enabled=True,
            clock=self.clock,
            window_seconds=300,
            cgnat_resolver=fake_resolver(
                {
                    ("100.64.0.5", 1000): {
                        "matched": True,
                        "ambiguous": False,
                        "private_ip": "10.99.0.1",
                        "subscriber_id": "SUB-1",
                        "subscriber_name": "Alice",
                        "confidence": 0.9,
                        "source_type": "generic",
                        "pool_name": "pool-a",
                    },
                    ("100.64.0.5", 2000): {
                        "matched": True,
                        "ambiguous": False,
                        "private_ip": "10.99.0.2",
                        "subscriber_id": "SUB-2",
                        "confidence": 0.8,
                    },
                },
                self.calls,
            ),
        )

    def cgnat_candidate(self, src_port=1000, ts=None, **kwargs):
        return candidate(
            src_ip="100.64.0.5",
            src_role=CGNAT_PUBLIC,
            src_port=src_port,
            ts=ts,
            **kwargs,
        )

    # 18. CGNAT_PUBLIC IOC hit -> resolver called
    def test_cgnat_hit_resolves(self):
        cycle = self.aggregator.ingest([self.cgnat_candidate()], now=self.clock())
        self.assertEqual(1, len(self.calls))
        rel = cycle.relationships[0]
        self.assertEqual("SUB-1", rel.internal_identity)
        self.assertEqual(IDENTITY_CGNAT_SUBSCRIBER, rel.identity_kind)
        self.assertEqual(RESOLVED, rel.cgnat.status)
        self.assertEqual("SUB-1", rel.cgnat.subscriber_id)
        self.assertEqual("10.99.0.1", rel.cgnat.private_ip)

    # 20. CUSTOMER direct -> resolver NOT called
    def test_customer_not_resolved(self):
        self.aggregator.ingest([candidate(src_role=CUSTOMER)], now=self.clock())
        self.assertEqual(0, len(self.calls))

    # 19. zero candidates -> no resolution, no relationships
    def test_no_candidates_no_resolution(self):
        cycle = self.aggregator.ingest([], now=self.clock())
        self.assertEqual(0, len(self.calls))
        self.assertEqual(0, len(cycle.relationships))

    # 21. resolved subscriber attributed correctly
    def test_resolved_subscriber_attribution(self):
        self.aggregator.ingest([self.cgnat_candidate()], now=self.clock())
        summary = self.aggregator.ingest([], now=self.clock()).client_summaries[0]
        self.assertEqual("SUB-1", summary.internal_identity)

    # 22. unresolved -> public identity preserved
    def test_unresolved_public_identity_preserved(self):
        agg = OutboundIocAggregator(
            enabled=True,
            clock=self.clock,
            cgnat_resolver=lambda *a, **k: {"matched": False, "error": "no_mapping"},
        )
        cycle = agg.ingest([self.cgnat_candidate()], now=self.clock())
        rel = cycle.relationships[0]
        self.assertEqual("100.64.0.5", rel.internal_identity)
        self.assertEqual(UNRESOLVED, rel.cgnat.status)

    # 23. ambiguous -> no arbitrary subscriber selected
    def test_ambiguous_no_arbitrary_subscriber(self):
        agg = OutboundIocAggregator(
            enabled=True,
            clock=self.clock,
            cgnat_resolver=lambda *a, **k: {"matched": True, "ambiguous": True},
        )
        cycle = agg.ingest([self.cgnat_candidate()], now=self.clock())
        rel = cycle.relationships[0]
        self.assertEqual("100.64.0.5", rel.internal_identity)
        self.assertEqual(AMBIGUOUS, rel.cgnat.status)
        self.assertEqual("", rel.cgnat.private_ip)

    # 24. resolver exception -> IOC hit preserved
    def test_resolver_exception_preserves_hit(self):
        def boom(*a, **k):
            raise RuntimeError("sqlite down")
        agg = OutboundIocAggregator(
            enabled=True, clock=self.clock, cgnat_resolver=boom
        )
        cycle = agg.ingest([self.cgnat_candidate()], now=self.clock())
        rel = cycle.relationships[0]
        self.assertEqual(1, len(cycle.relationships))
        self.assertEqual(ERROR, rel.cgnat.status)
        self.assertEqual("100.64.0.5", rel.internal_identity)
        self.assertEqual(1, cycle.metrics["cgnat_resolution_errors"])

    # 25. same mapping repeated -> cache reduces lookups
    def test_cache_reduces_lookups(self):
        self.aggregator.ingest([self.cgnat_candidate()], now=self.clock())
        self.aggregator.ingest([self.cgnat_candidate()], now=self.clock())
        self.aggregator.ingest([self.cgnat_candidate()], now=self.clock())
        self.assertEqual(1, len(self.calls))  # cached after first
        status = self.aggregator.status()
        self.assertEqual(2, status["cgnat_cache_hits"])

    # 26. timestamp used is flow timestamp (not now)
    def test_timestamp_is_flow_timestamp(self):
        flow_ts = iso(BASE + timedelta(minutes=3))
        self.aggregator.ingest([self.cgnat_candidate(ts=flow_ts)], now=self.clock())
        self.assertEqual(1, len(self.calls))
        self.assertEqual(flow_ts, self.calls[0][3])

    # 27. different src_port can resolve different subscriber
    def test_different_ports_resolve_different_subscribers(self):
        self.aggregator.ingest(
            [self.cgnat_candidate(src_port=1000), self.cgnat_candidate(src_port=2000)],
            now=self.clock(),
        )
        cycle = self.aggregator.ingest([], now=self.clock())
        identities = {rel.internal_identity for rel in cycle.relationships}
        self.assertEqual({"SUB-1", "SUB-2"}, identities)


class RealCgnatIntegrationTest(unittest.TestCase):
    def test_real_resolver_end_to_end(self):
        tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(tmp.name, "cgnat.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        ensure_cgnat_schema(conn)
        conn.execute(
            "INSERT INTO cgnat_import_batches"
            " (filename, original_filename, original_content, file_hash, status, created_at)"
            " VALUES ('x','x','','h','active','2026-09-16T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO cgnat_port_mappings"
            " (batch_id, source_type, source_filename, public_ip, private_ip, protocol,"
            "  port_start, port_end, subscriber_id, active, confidence, created_at, updated_at)"
            " VALUES (1,'generic','x','100.64.0.5','10.99.0.1','any',1000,1000,'SUB-1',1,0.9,"
            "  '2026-09-16T00:00:00Z','2026-09-16T00:00:00Z')"
        )
        conn.commit()
        conn.close()

        def factory():
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            return conn

        clock = TestClock(BASE)
        agg = OutboundIocAggregator(
            connection_factory=factory, enabled=True, clock=clock
        )
        cycle = agg.ingest(
            [
                candidate(
                    src_ip="100.64.0.5",
                    src_role=CGNAT_PUBLIC,
                    src_port=1000,
                    protocol=6,
                )
            ],
            now=clock(),
        )
        rel = cycle.relationships[0]
        self.assertEqual(RESOLVED, rel.cgnat.status)
        self.assertEqual("SUB-1", rel.internal_identity)
        self.assertEqual("SUB-1", rel.cgnat.subscriber_id)
        self.assertEqual("10.99.0.1", rel.cgnat.private_ip)
        tmp.cleanup()


class SnapshotFixedPerCycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "ti.db")
        conn = sqlite3.connect(self.db_path)
        from app.services.threat_intelligence import ensure_threat_intel_schema

        ensure_threat_intel_schema(conn)
        conn.execute(
            "UPDATE threat_intel_providers SET enabled = 1 WHERE provider = 'CEREAL2'"
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def _factory(self):
        def factory():
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        return factory

    def _insert(self, ip, active=1):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO threat_intel_indicators"
            " (provider, indicator_type, ip, classification, active, updated_at)"
            " VALUES ('CEREAL2','C2',?, 'c2', ?, '2026-09-16T00:00:00Z')",
            (ip, active),
        )
        conn.commit()
        conn.close()

    # 28. snapshot is a stable reference; lookup_key lock-free and no copy
    def test_snapshot_stable_reference_no_copy(self):
        self._insert("203.0.113.10")
        hotset = ActiveIocHotSet(self._factory(), enabled=True)
        self.assertTrue(hotset.refresh())
        snap_a = hotset.snapshot()
        snap_b = hotset.snapshot()
        self.assertIs(snap_a, snap_b)  # same object: no copy, no lock
        self.assertIsInstance(snap_a, IocSnapshot)
        self.assertEqual(1, snap_a.generation)
        entry = snap_a.lookup_key(int(ip_address("203.0.113.10")))
        self.assertIsNotNone(entry)
        self.assertEqual("203.0.113.10", entry.ip)

    # 29. refresh publishes a new snapshot; the old snapshot stays immutable
    def test_refresh_publishes_new_snapshot_old_immutable(self):
        self._insert("203.0.113.10")
        hotset = ActiveIocHotSet(self._factory(), enabled=True)
        self.assertTrue(hotset.refresh())
        snap_a = hotset.snapshot()
        self._insert("203.0.113.11")
        self.assertTrue(hotset.refresh())
        snap_b = hotset.snapshot()
        self.assertIsNot(snap_a, snap_b)
        # Old snapshot still only knows A.
        key_a = int(ip_address("203.0.113.10"))
        key_b = int(ip_address("203.0.113.11"))
        self.assertIsNotNone(snap_a.lookup_key(key_a))
        self.assertIsNone(snap_a.lookup_key(key_b))
        self.assertIsNotNone(snap_b.lookup_key(key_b))


class TemporalEdgeCaseTest(unittest.TestCase):
    def setUp(self):
        self.clock = TestClock(BASE)

    def test_out_of_order_retrocedes_first_seen_not_last_seen(self):
        agg = OutboundIocAggregator(enabled=True, clock=self.clock, window_seconds=300)
        agg.ingest([candidate(ts=iso(BASE + timedelta(seconds=100)))], now=BASE + timedelta(seconds=100))
        cycle = agg.ingest([candidate(ts=iso(BASE + timedelta(seconds=10)))], now=BASE + timedelta(seconds=110))
        rel = cycle.relationships[0]
        self.assertEqual(iso(BASE + timedelta(seconds=10)), rel.first_seen)
        self.assertEqual(iso(BASE + timedelta(seconds=100)), rel.last_seen)

    def test_future_timestamp_delays_expiration(self):
        agg = OutboundIocAggregator(enabled=True, clock=self.clock, window_seconds=300)
        agg.ingest([candidate(ts=iso(BASE + timedelta(hours=1)))], now=BASE)
        self.clock.advance(3000)
        cycle = agg.ingest([], now=self.clock())
        self.assertEqual(1, len(cycle.relationships))

    def test_expiration_boundary_exact(self):
        for age, expected_active in ((299.999, 1), (300.0, 1), (300.001, 0)):
            clock = TestClock(BASE)
            agg = OutboundIocAggregator(enabled=True, clock=clock, window_seconds=300)
            agg.ingest([candidate()], now=BASE)
            clock.advance(age)
            agg.ingest([], now=clock())
            self.assertEqual(expected_active, agg.status()["active_relationships"], "age=%s" % age)


class EvictionTest(unittest.TestCase):
    def test_cap_respected_with_bounded_admission(self):
        agg = OutboundIocAggregator(enabled=True, clock=TestClock(BASE), window_seconds=300, max_relationships=3)
        cands = [candidate(src_ip="10.0.0.%d" % i, dst_ip="203.0.113.%d" % i) for i in range(10)]
        cycle = agg.ingest(cands, now=BASE)
        self.assertEqual(3, len(cycle.relationships))
        self.assertEqual(3, agg.status()["active_relationships"])
        self.assertGreaterEqual(cycle.metrics["relationships_evicted"] + cycle.metrics["admission_skipped"], 7)

    def test_oldest_first_eviction_with_distinct_timestamps(self):
        agg = OutboundIocAggregator(enabled=True, clock=TestClock(BASE), window_seconds=300, max_relationships=3)
        cands = [
            candidate(src_ip="10.0.0.0", ts=iso(BASE)),
            candidate(src_ip="10.0.0.1", ts=iso(BASE + timedelta(seconds=1))),
            candidate(src_ip="10.0.0.2", ts=iso(BASE + timedelta(seconds=2))),
            candidate(src_ip="10.0.0.3", ts=iso(BASE + timedelta(seconds=3))),
        ]
        cycle = agg.ingest(cands, now=BASE + timedelta(seconds=4))
        identities = {rel.internal_identity for rel in cycle.relationships}
        self.assertEqual({"10.0.0.1", "10.0.0.2", "10.0.0.3"}, identities)

    def test_eviction_updates_client_summary(self):
        agg = OutboundIocAggregator(enabled=True, clock=TestClock(BASE), window_seconds=300, max_relationships=2)
        cands = [candidate(src_ip="10.0.0.10", dst_ip="203.0.113.%d" % i) for i in range(3)]
        cycle = agg.ingest(cands, now=BASE)
        self.assertEqual(2, agg.status()["active_relationships"])
        summary = cycle.client_summaries[0]
        self.assertEqual(2, summary.relationship_count)
        self.assertEqual(2, summary.unique_ioc_count)


class CgnatCacheEdgeTest(unittest.TestCase):
    def test_cache_keys_by_flow_time_bucket(self):
        calls = []
        resolver = fake_resolver({("100.64.0.5", 1000): {"matched": False, "error": "no_mapping"}}, calls)
        agg = OutboundIocAggregator(enabled=True, clock=TestClock(BASE), window_seconds=300, cgnat_resolver=resolver)
        agg.ingest([candidate(src_ip="100.64.0.5", src_role=CGNAT_PUBLIC, src_port=1000, ts=iso(BASE))], now=BASE)
        agg.ingest([candidate(src_ip="100.64.0.5", src_role=CGNAT_PUBLIC, src_port=1000, ts=iso(BASE + timedelta(seconds=400)))], now=BASE + timedelta(seconds=400))
        self.assertEqual(2, len(calls))

    def test_error_not_cached_retries(self):
        calls = []

        def flaky(public_ip, src_port, protocol, timestamp):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("sqlite down")
            return {"matched": False, "error": "no_mapping"}

        agg = OutboundIocAggregator(enabled=True, clock=TestClock(BASE), cgnat_resolver=flaky)
        agg.ingest([candidate(src_ip="100.64.0.5", src_role=CGNAT_PUBLIC, src_port=1000)], now=BASE)
        agg.ingest([candidate(src_ip="100.64.0.5", src_role=CGNAT_PUBLIC, src_port=1000)], now=BASE)
        self.assertEqual(2, len(calls))


class SetTruncationTest(unittest.TestCase):
    def test_set_truncation_deterministic_and_flagged(self):
        agg = OutboundIocAggregator(enabled=True, clock=TestClock(BASE), window_seconds=300, set_limit=2)
        agg.ingest([candidate(providers=("P1",))], now=BASE)
        agg.ingest([candidate(providers=("P2",))], now=BASE)
        cycle = agg.ingest([candidate(providers=("P3",))], now=BASE)
        rel = cycle.relationships[0]
        self.assertTrue(rel.set_truncated)
        self.assertEqual(2, len(rel.providers))
        self.assertEqual({"P1", "P2"}, rel.providers)


class PreparedCgnatResolverEquivalenceTest(unittest.TestCase):
    """Prepared (per-cycle, ensure_schema=False) resolver must match the
    canonical resolve_cgnat_subscriber (ensure_schema=True) exactly."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "cgnat.db")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        ensure_cgnat_schema(conn)
        conn.execute(
            "INSERT INTO cgnat_import_batches (filename, original_filename, original_content, file_hash, status, created_at)"
            " VALUES ('x','x','','h','active','2026-09-16T00:00:00Z')"
        )
        rows = [
            # public, private, protocol, port_start, port_end, subscriber_id, valid_from, valid_until
            ("100.64.0.5", "10.99.0.1", "any", 1000, 1000, "SUB-1", "", ""),
            ("100.64.0.5", "10.99.0.2", "tcp", 2000, 2000, "SUB-2", "", ""),
            ("100.64.0.6", "10.99.1.1", "any", 3000, 4000, "SUB-3", "2026-09-16T00:00:00Z", "2026-09-16T23:59:59Z"),
            ("100.64.0.7", "10.99.2.1", "any", 5000, 5000, "", "", ""),
            ("100.64.0.8", "10.99.3.1", "any", 6000, 6000, "SUB-5", "", ""),
            ("100.64.0.8", "10.99.3.2", "any", 6000, 6000, "SUB-6", "", ""),
        ]
        for public, private, proto, ps, pe, sid, vf, vu in rows:
            conn.execute(
                "INSERT INTO cgnat_port_mappings (batch_id, source_type, source_filename, public_ip, private_ip, protocol, port_start, port_end, subscriber_id, valid_from, valid_until, active, confidence, created_at, updated_at)"
                " VALUES (1,'generic','x',?,?,?,?,?,?,?,?,1,0.9,'2026-09-16T00:00:00Z','2026-09-16T00:00:00Z')",
                (public, private, proto, ps, pe, sid, vf, vu),
            )
        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def _factory(self):
        def factory():
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        return factory

    def _compare(self, public_ip, src_port, protocol, timestamp):
        from app.services.cgnat_mapping import resolve_cgnat_subscriber
        from app.services.outbound_ioc_aggregation import _PreparedCgnatResolver

        conn = self._factory()()
        try:
            original = resolve_cgnat_subscriber(conn, public_ip, src_port, protocol, timestamp)
        finally:
            conn.close()
        prepared = _PreparedCgnatResolver(self._factory())
        try:
            got = prepared.resolve(public_ip, src_port, protocol, timestamp)
        finally:
            prepared.close()
        return original, got

    def test_prepared_matches_original(self):
        cases = [
            ("100.64.0.5", 1000, "tcp", "2026-09-16T12:00:00Z"),   # resolved (any proto)
            ("100.64.0.5", 1000, 6, "2026-09-16T12:00:00Z"),        # int proto -> tcp
            ("100.64.0.5", 2000, "udp", "2026-09-16T12:00:00Z"),    # tcp-only mapping, udp -> no match
            ("100.64.0.6", 3500, "tcp", "2026-09-16T12:00:00Z"),    # inside validity
            ("100.64.0.6", 3500, "tcp", "2026-09-20T12:00:00Z"),    # after validity -> no match
            ("100.64.0.7", 5000, "tcp", "2026-09-16T12:00:00Z"),    # no subscriber_id -> private_ip
            ("100.64.0.8", 6000, "tcp", "2026-09-16T12:00:00Z"),    # ambiguous (two subs same port)
            ("100.64.9.9", 6000, "tcp", "2026-09-16T12:00:00Z"),    # unknown -> unresolved
        ]
        for public_ip, port, proto, ts in cases:
            original, got = self._compare(public_ip, port, proto, ts)
            self.assertEqual(original, got, "mismatch for %s:%s/%s" % (public_ip, port, proto))



if __name__ == "__main__":
    unittest.main()
