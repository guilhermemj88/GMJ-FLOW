"""P2 outbound destination IOC detector shadow tests."""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.active_ioc_hotset import (  # noqa: E402
    ActiveIocHotSet,
    IocEntry,
    ProviderMatch,
)
from app.services.threat_intelligence import ensure_threat_intel_schema  # noqa: E402
from app.services.behavioral_detection import FlowObservation  # noqa: E402
from app.services.network_context import (  # noqa: E402
    CGNAT_PUBLIC,
    CUSTOMER,
    EXTERNAL,
    INFRASTRUCTURE,
    MANAGEMENT,
    NetworkContext,
    NetworkContextEngine,
)
from app.services.outbound_ioc_detector import OutboundIocShadowDetector  # noqa: E402


NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


def flow(
    src_ip="10.0.0.10",
    dst_ip="203.0.113.10",
    src_port=40000,
    dst_port=443,
    protocol=6,
    packets=10,
    bytes_count=1000,
    flow_count=1,
    sensor="edge",
):
    return FlowObservation(
        observed_at=NOW,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        tcp_flags=0x02 if protocol == 6 else 0,
        packets=packets,
        bytes=bytes_count,
        flow_count=flow_count,
        sensor=sensor,
        exporter_ip="192.0.2.1",
        input_if=10,
        output_if=20,
    )


def ioc_entry(
    ip="203.0.113.10",
    evidence=(("CEREAL2", "C2", "c2", "c2", 1),),
    family="",
):
    matches = tuple(
        ProviderMatch(
            provider=provider,
            indicator_type=indicator_type,
            classification=classification,
            category=category,
            tier=tier,
            botnet_family=family,
            tags=("shadow-test",),
        )
        for provider, indicator_type, classification, category, tier in evidence
    )
    return IocEntry(
        ip=ip,
        matches=matches,
        providers=tuple(sorted({item.provider for item in matches})),
        threat_types=tuple(sorted({item.classification for item in matches})),
        categories=tuple(sorted({item.category for item in matches})),
        semantic_tier=min(item.tier for item in matches),
        botnet_family=family,
        tags=("shadow-test",),
    )


class FakeHotSet:
    def __init__(self, entries=None, error=None):
        self.entries = entries or {}
        self.error = error
        self.lookups = []
        self.started = 0
        self.stopped = 0

    def lookup(self, ip):
        self.lookups.append(ip)
        if self.error is not None:
            raise self.error
        return self.entries.get(ip)

    def start(self):
        self.started += 1

    def stop(self):
        self.stopped += 1


class StaticNetworkContext:
    def __init__(self, default=None, contexts=None, error=None):
        self.default = default or NetworkContext(
            src_role=CUSTOMER,
            dst_role=EXTERNAL,
            traffic_direction="OUTBOUND",
        )
        self.contexts = contexts or {}
        self.error = error
        self.prepare_calls = 0
        self.resolve_calls = 0

    def prepare_resolver(self):
        self.prepare_calls += 1
        if self.error is not None:
            raise self.error

        def resolve(src_ip, dst_ip, *_args, **_kwargs):
            self.resolve_calls += 1
            return self.contexts.get((src_ip, dst_ip), self.default)

        return resolve


class OutboundIocDetectorTest(unittest.TestCase):
    def detector(self, entries=None, context=None, enabled=True, hotset=None):
        hotset = hotset or FakeHotSet(entries)
        network = context or StaticNetworkContext()
        detector = OutboundIocShadowDetector(
            hotset=hotset,
            network_context=network,
            enabled=enabled,
        )
        return detector, hotset, network

    def one_candidate(self, entry, observation=None, context=None):
        detector, _, _ = self.detector({entry.ip: entry}, context=context)
        result = detector.detect([observation or flow(dst_ip=entry.ip)])
        self.assertEqual(1, len(result.candidates))
        return result.candidates[0], result

    # 1. Disabled means no context preparation and no hot-set lookup.
    def test_feature_disabled_zero_lookup(self):
        detector, hotset, network = self.detector(
            {"203.0.113.10": ioc_entry()}, enabled=False
        )
        result = detector.detect([flow()])
        self.assertFalse(result.enabled)
        self.assertEqual([], hotset.lookups)
        self.assertEqual(0, network.prepare_calls)
        self.assertEqual(0, detector.status()["cycles"])

    # 2. Benign TCP/443 is checked but produces no candidate.
    def test_customer_to_benign_external_tcp443(self):
        detector, hotset, _ = self.detector({})
        result = detector.detect([flow(dst_port=443, protocol=6)])
        self.assertEqual([], list(result.candidates))
        self.assertEqual(["203.0.113.10"], hotset.lookups)
        self.assertEqual(1, result.metrics["hotset_misses"])

    # 3/4. Neither HTTPS nor QUIC suppresses C2.
    def test_customer_to_c2_tcp443(self):
        candidate, _ = self.one_candidate(ioc_entry())
        self.assertEqual(443, candidate.dst_port)
        self.assertEqual(6, candidate.protocol)
        self.assertIn("c2", candidate.categories)

    def test_customer_to_c2_udp443(self):
        candidate, _ = self.one_candidate(
            ioc_entry(), flow(dst_port=443, protocol=17)
        )
        self.assertEqual(443, candidate.dst_port)
        self.assertEqual(17, candidate.protocol)

    # 5-8. Semantic categories remain distinct.
    def test_botnet_non443_candidate(self):
        entry = ioc_entry(evidence=(("FEODO", "BOTNET", "active_botnet", "botnet", 2),), family="Emotet")
        candidate, result = self.one_candidate(entry, flow(dst_port=8080))
        self.assertIn("botnet", candidate.categories)
        self.assertEqual("Emotet", candidate.botnet_family)
        self.assertEqual(1, result.metrics["botnet_candidates"])

    def test_malware_candidate(self):
        entry = ioc_entry(evidence=(("CEREAL2", "PAYLOAD", "malware_distribution", "malware", 3),))
        candidate, result = self.one_candidate(entry)
        self.assertIn("malware", candidate.categories)
        self.assertEqual(1, result.metrics["malware_candidates"])

    def test_reputation_malicious_candidate(self):
        entry = ioc_entry(evidence=(("GREYNOISE", "IP", "malicious", "reputation_malicious", 4),))
        candidate, result = self.one_candidate(entry)
        self.assertEqual("HIGH_VALUE", candidate.signal_class)
        self.assertEqual(1, result.metrics["reputation_malicious_candidates"])

    def test_scanner_abuse_is_lower_signal(self):
        entry = ioc_entry(evidence=(("BLOCKLIST_DE", "ABUSE", "scanner", "scanner", 4),))
        candidate, result = self.one_candidate(entry)
        self.assertEqual("LOWER_SIGNAL", candidate.signal_class)
        self.assertEqual(1, result.metrics["lower_signal_candidates"])

    # 9-11. Context labels and web ports never erase an IOC hit.
    def test_cdn_expected_service_context_does_not_suppress(self):
        context = StaticNetworkContext(default=NetworkContext(
            src_role=CUSTOMER,
            dst_role=EXTERNAL,
            traffic_direction="OUTBOUND",
            matched_context="CDN_CACHE expected_service",
        ))
        candidate, _ = self.one_candidate(ioc_entry(), context=context)
        self.assertEqual("CDN_CACHE expected_service", candidate.network_context["matched_context"])

    def test_google_ggc_context_does_not_suppress(self):
        context = StaticNetworkContext(default=NetworkContext(
            src_role=CUSTOMER,
            dst_role=EXTERNAL,
            traffic_direction="OUTBOUND",
            matched_context="GOOGLE_GGC",
        ))
        candidate, _ = self.one_candidate(ioc_entry(), context=context)
        self.assertEqual("GOOGLE_GGC", candidate.network_context["matched_context"])

    def test_quic_ioc_remains_candidate(self):
        candidate, _ = self.one_candidate(ioc_entry(), flow(protocol=17, dst_port=443))
        self.assertTrue(candidate.ioc_matched)

    # 12-15. Direction and protected local roles are excluded.
    def test_external_to_customer_is_not_candidate(self):
        context = StaticNetworkContext(default=NetworkContext(
            src_role=EXTERNAL,
            dst_role=CUSTOMER,
            traffic_direction="INBOUND",
        ))
        detector, hotset, _ = self.detector({"10.0.0.10": ioc_entry("10.0.0.10")}, context)
        result = detector.detect([flow(src_ip="203.0.113.10", dst_ip="10.0.0.10")])
        self.assertEqual((), result.candidates)
        self.assertEqual([], hotset.lookups)

    def test_customer_to_customer_is_not_candidate(self):
        context = StaticNetworkContext(default=NetworkContext(
            src_role=CUSTOMER,
            dst_role=CUSTOMER,
            traffic_direction="INTERNAL",
        ))
        detector, hotset, _ = self.detector({"10.0.0.20": ioc_entry("10.0.0.20")}, context)
        result = detector.detect([flow(dst_ip="10.0.0.20")])
        self.assertEqual((), result.candidates)
        self.assertEqual([], hotset.lookups)

    def test_infrastructure_source_is_excluded(self):
        context = StaticNetworkContext(default=NetworkContext(
            src_role=INFRASTRUCTURE,
            dst_role=EXTERNAL,
            traffic_direction="OUTBOUND",
        ))
        detector, hotset, _ = self.detector({"203.0.113.10": ioc_entry()}, context)
        self.assertEqual((), detector.detect([flow()]).candidates)
        self.assertEqual([], hotset.lookups)

    def test_management_source_is_excluded(self):
        context = StaticNetworkContext(default=NetworkContext(
            src_role=MANAGEMENT,
            dst_role=EXTERNAL,
            traffic_direction="OUTBOUND",
        ))
        detector, hotset, _ = self.detector({"203.0.113.10": ioc_entry()}, context)
        self.assertEqual((), detector.detect([flow()]).candidates)
        self.assertEqual([], hotset.lookups)

    # 16. CGNAT is eligible without per-flow subscriber resolution.
    def test_cgnat_public_candidate_preserves_future_resolution_fields(self):
        context = StaticNetworkContext(default=NetworkContext(
            src_role=CGNAT_PUBLIC,
            dst_role=EXTERNAL,
            src_is_cgnat=True,
            traffic_direction="OUTBOUND",
        ))
        candidate, _ = self.one_candidate(
            ioc_entry(), flow(src_ip="100.64.0.10", src_port=45678, protocol=6), context
        )
        self.assertEqual(CGNAT_PUBLIC, candidate.src_role)
        self.assertEqual(45678, candidate.src_port)
        self.assertFalse(candidate.subscriber_resolution_available)

    # 17. IPv6 remains first-class.
    def test_ipv6_customer_to_ipv6_ioc(self):
        entry = ioc_entry("2001:db8:ffff::10")
        candidate, _ = self.one_candidate(
            entry,
            flow(src_ip="2001:db8:1::10", dst_ip=entry.ip),
        )
        self.assertEqual("2001:db8:1::10", candidate.src_ip)
        self.assertEqual(entry.ip, candidate.dst_ip)

    # 18/19. Malformed and unavailable inputs fail safely.
    def test_malformed_destination_is_safe(self):
        detector, hotset, _ = self.detector({})
        result = detector.detect([flow(dst_ip="not-an-ip")])
        self.assertEqual((), result.candidates)
        self.assertEqual([], hotset.lookups)
        self.assertEqual(1, result.metrics["candidate_errors"])

    def test_empty_or_unavailable_hotset_is_safe(self):
        empty, _, _ = self.detector({})
        self.assertEqual((), empty.detect([flow()]).candidates)
        failing_hotset = FakeHotSet(error=RuntimeError("unavailable"))
        failing, _, _ = self.detector(hotset=failing_hotset)
        result = failing.detect([flow()])
        self.assertEqual((), result.candidates)
        self.assertEqual(1, result.metrics["candidate_errors"])

    # 20. Destination lookups are deduplicated per cycle.
    def test_multiple_observations_same_destination_one_lookup(self):
        entry = ioc_entry()
        detector, hotset, _ = self.detector({entry.ip: entry})
        rows = [flow(src_port=40000 + index) for index in range(20)]
        result = detector.detect(rows)
        self.assertEqual([entry.ip], hotset.lookups)
        self.assertEqual(20, len(result.candidates))
        self.assertEqual(1, result.metrics["unique_destinations_checked"])

    def test_multi_provider_evidence_is_preserved(self):
        entry = ioc_entry(evidence=(
            ("CEREAL2", "C2", "c2", "c2", 1),
            ("FEODO", "BOTNET", "active_botnet", "botnet", 2),
            ("GREYNOISE", "IP", "malicious", "reputation_malicious", 4),
        ))
        candidate, result = self.one_candidate(entry)
        self.assertEqual(("CEREAL2", "FEODO", "GREYNOISE"), candidate.providers)
        self.assertEqual(3, len(candidate.classifications))
        self.assertEqual(1, result.metrics["c2_candidates"])
        self.assertEqual(1, result.metrics["botnet_candidates"])
        self.assertEqual(1, result.metrics["reputation_malicious_candidates"])

    def test_multiple_clients_same_ioc_keep_relations(self):
        entry = ioc_entry()
        detector, hotset, _ = self.detector({entry.ip: entry})
        rows = [flow(src_ip=f"10.0.0.{index}") for index in range(1, 4)]
        result = detector.detect(rows)
        self.assertEqual(1, len(hotset.lookups))
        self.assertEqual(3, len(result.candidates))
        self.assertEqual(3, len({item.src_ip for item in result.candidates}))

    def test_same_client_multiple_iocs_keep_relations(self):
        entries = {
            "203.0.113.10": ioc_entry("203.0.113.10"),
            "203.0.113.11": ioc_entry("203.0.113.11"),
            "203.0.113.12": ioc_entry(
                "203.0.113.12",
                (("FEODO", "BOTNET", "active_botnet", "botnet", 2),),
            ),
        }
        detector, _, _ = self.detector(entries)
        result = detector.detect([flow(dst_ip=ip) for ip in entries])
        self.assertEqual(3, len(result.candidates))
        self.assertEqual(set(entries), {item.dst_ip for item in result.candidates})

    def test_identical_flows_are_consolidated_within_cycle(self):
        entry = ioc_entry()
        detector, _, _ = self.detector({entry.ip: entry})
        result = detector.detect([flow(packets=10, bytes_count=100)] * 5)
        self.assertEqual(1, len(result.candidates))
        candidate = result.candidates[0]
        self.assertEqual(50, candidate.packets)
        self.assertEqual(500, candidate.bytes)
        self.assertEqual(5, candidate.flow_count)

    def test_status_is_cumulative_and_cycle_metrics_are_exposed(self):
        entry = ioc_entry()
        detector, _, _ = self.detector({entry.ip: entry})
        first = detector.detect([flow()])
        second = detector.detect([flow(dst_ip="203.0.113.11")])
        status = detector.status()
        self.assertEqual(2, status["cycles"])
        self.assertEqual(2, status["observations_seen"])
        self.assertEqual(1, status["hotset_hits"])
        self.assertEqual(1, status["hotset_misses"])
        self.assertIn("cycle_duration_ms", first.metrics)
        self.assertIn("lookup_duration_ms", second.metrics)
        self.assertFalse(status["truncated"])
        self.assertEqual(0, status["destinations_skipped"])

    def test_hotset_lifecycle_only_starts_when_enabled(self):
        disabled, hotset, _ = self.detector(enabled=False)
        disabled.start()
        disabled.stop()
        self.assertEqual(0, hotset.started)
        self.assertEqual(1, hotset.stopped)
        enabled, hotset2, _ = self.detector(enabled=True)
        enabled.start()
        enabled.stop()
        self.assertEqual(1, hotset2.started)
        self.assertEqual(1, hotset2.stopped)




class _GatedConnection:
    """Blocks the indicators query (2nd execute of a build) until released."""

    def __init__(self, conn, gate):
        self._conn = conn
        self._gate = gate

    def execute(self, sql, params=()):
        self._gate.calls += 1
        if self._gate.calls == 2:
            self._gate.in_build.set()
            if not self._gate.release.wait(timeout=10.0):
                raise sqlite3.OperationalError("build gate timeout")
        return self._conn.execute(sql, params)

    def close(self):
        return self._conn.close()


class _BuildGate:
    def __init__(self, real_factory):
        self._real_factory = real_factory
        self.in_build = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def factory(self):
        return _GatedConnection(self._real_factory(), self)


class DetectorHotSetConcurrencyTest(unittest.TestCase):
    """Detector + hot-set atomic publication: a running detector cycle must
    only ever see a fully built snapshot (never a partial A/B mix)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "ti.db")
        conn = sqlite3.connect(self.db_path)
        ensure_threat_intel_schema(conn)
        conn.execute(
            "UPDATE threat_intel_providers SET enabled = 1 WHERE provider = 'CEREAL2'"
        )
        conn.execute(
            "INSERT INTO threat_intel_indicators"
            " (provider, indicator_type, ip, classification, active, updated_at)"
            " VALUES ('CEREAL2', 'C2', '203.0.113.10', 'c2', 1, '2026-09-16T00:00:00Z')"
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        self._tmp.cleanup()

    def _factory(self):
        def factory():
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        return factory

    def _switch_control_plane_to_b(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE threat_intel_indicators SET active = 0")
        conn.execute(
            "INSERT INTO threat_intel_indicators"
            " (provider, indicator_type, ip, classification, active, updated_at)"
            " VALUES ('CEREAL2', 'C2', '203.0.113.11', 'c2', 1, '2026-09-16T00:00:00Z')"
        )
        conn.commit()
        conn.close()

    def test_detector_reads_valid_snapshot_while_hotset_refreshes(self):
        hotset = ActiveIocHotSet(self._factory(), enabled=True)
        self.assertTrue(hotset.refresh())
        detector = OutboundIocShadowDetector(
            hotset=hotset,
            network_context=StaticNetworkContext(),
            enabled=True,
        )

        # Control plane now contains only 203.0.113.11 (snapshot B source).
        self._switch_control_plane_to_b()

        # Next build is gated: it will block while the detector runs.
        gate = _BuildGate(self._factory())
        hotset._connection_factory = gate.factory
        refresh_thread = threading.Thread(target=hotset.refresh, daemon=True)
        refresh_thread.start()
        self.assertTrue(gate.in_build.wait(timeout=5.0), "build did not start")

        # During the blocked build the detector must see ONLY snapshot A.
        during = detector.detect(
            [flow(dst_ip="203.0.113.10"), flow(dst_ip="203.0.113.11")]
        )
        self.assertEqual(
            {"203.0.113.10"}, {candidate.dst_ip for candidate in during.candidates}
        )

        gate.release.set()
        refresh_thread.join(timeout=10.0)
        self.assertFalse(refresh_thread.is_alive(), "refresh did not finish")

        # After the atomic swap the detector must see ONLY snapshot B.
        after = detector.detect(
            [flow(dst_ip="203.0.113.10"), flow(dst_ip="203.0.113.11")]
        )
        self.assertEqual(
            {"203.0.113.11"}, {candidate.dst_ip for candidate in after.candidates}
        )


class PreparedNetworkContextTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "context.db")
        conn = sqlite3.connect(self.path)
        conn.execute(
            "CREATE TABLE ip_zones (id INTEGER PRIMARY KEY, name TEXT, active INTEGER, subscriber_addressing_mode TEXT)"
        )
        conn.execute(
            "CREATE TABLE ip_zone_prefixes (cidr TEXT, prefix_type TEXT, zone_id INTEGER, active INTEGER)"
        )
        conn.execute(
            "INSERT INTO ip_zones VALUES (1, 'customers-v6', 1, 'direct')"
        )
        conn.execute(
            "INSERT INTO ip_zone_prefixes VALUES ('2001:db8:100::/56', 'client', 1, 1)"
        )
        conn.execute(
            "INSERT INTO ip_zone_prefixes VALUES ('2001:db8:100:1::/64', 'client', 1, 1)"
        )
        conn.execute(
            "INSERT INTO ip_zones VALUES (2, 'cgnat', 1, 'cgnat')"
        )
        conn.execute(
            "INSERT INTO ip_zone_prefixes VALUES ('100.64.0.0/24', 'public_cgnat', 2, 1)"
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def factory(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def test_prepared_resolver_uses_ipv6_longest_prefix_and_no_per_flow_sqlite(self):
        engine = NetworkContextEngine(self.factory)
        resolver = engine.prepare_resolver()
        in_64 = resolver("2001:db8:100:1::10", "2001:4860:4860::8888")
        in_56 = resolver("2001:db8:100:2::10", "2001:4860:4860::8888")
        self.assertEqual("2001:db8:100:1::/64", in_64.src_prefix)
        self.assertEqual("2001:db8:100::/56", in_56.src_prefix)
        self.assertEqual("OUTBOUND", in_64.traffic_direction)
        self.assertEqual(EXTERNAL, in_64.dst_role)

    def test_prepared_resolver_recognizes_cgnat_public(self):
        context = NetworkContextEngine(self.factory).prepare_resolver()(
            "100.64.0.10", "203.0.113.10"
        )
        self.assertEqual(CGNAT_PUBLIC, context.src_role)
        self.assertTrue(context.src_is_cgnat)
        self.assertEqual("OUTBOUND", context.traffic_direction)

    def test_prepared_resolver_v4_longest_prefix_match(self):
        conn = sqlite3.connect(self.path)
        conn.execute("INSERT INTO ip_zones VALUES (3, 'infra-v4', 1, 'direct')")
        conn.execute("INSERT INTO ip_zone_prefixes VALUES ('10.0.0.0/8', 'client', 1, 1)")
        conn.execute("INSERT INTO ip_zone_prefixes VALUES ('10.1.0.0/16', 'infrastructure', 3, 1)")
        conn.commit()
        conn.close()
        resolver = NetworkContextEngine(self.factory).prepare_resolver()
        in_16 = resolver("10.1.2.3", "8.8.8.8")
        in_8 = resolver("10.2.3.4", "8.8.8.8")
        self.assertEqual(INFRASTRUCTURE, in_16.src_role)
        self.assertEqual("10.1.0.0/16", in_16.src_prefix)
        self.assertEqual(CUSTOMER, in_8.src_role)
        self.assertEqual("10.0.0.0/8", in_8.src_prefix)


if __name__ == "__main__":
    unittest.main()

