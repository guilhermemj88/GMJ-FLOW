from __future__ import annotations

import os
import sqlite3
import sys
import unittest
from datetime import datetime, timedelta, timezone


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavioral_detection import (  # noqa: E402
    BOTNET_LIKELY,
    CARPET_BOMBING,
    DISTRIBUTED_SYN_FLOOD,
    DISTRIBUTED_UDP_FLOOD,
    LOW_SLOW_SCAN,
    MULTI_VECTOR_DDOS,
    NETWORK_SWEEP,
    PORT_SCAN_HORIZONTAL,
    PORT_SCAN_VERTICAL,
    SPOOFED_SYN_FLOOD,
    SYN_FLOOD,
    UDP_FLOOD,
    UDP_REFLECTION_SUSPECTED,
    AttackVector,
    BehavioralDetectionEngine,
    CampaignEngine,
    CarpetBombingDetector,
    FlowObservation,
    PortScanDetector,
    SynFloodDetector,
    UdpFloodDetector,
    ensure_behavioral_schema,
)


NOW = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)


def flow(
    source="198.18.0.1",
    destination="203.0.113.10",
    source_port=40000,
    destination_port=443,
    protocol=6,
    flags=0,
    packets=1,
    bytes_count=60,
    seconds_ago=0,
    source_asn=64500,
):
    return FlowObservation(
        observed_at=NOW - timedelta(seconds=seconds_ago),
        src_ip=source,
        dst_ip=destination,
        src_port=source_port,
        dst_port=destination_port,
        protocol=protocol,
        tcp_flags=flags,
        packets=packets,
        bytes=bytes_count,
        flow_count=1,
        src_asn=source_asn,
        sensor="edge",
        exporter_ip="192.0.2.1",
        input_if=10,
    )


class BehavioralDetectorTest(unittest.TestCase):
    def test_normal_traffic_has_no_detection(self):
        rows = [flow(source=f"198.18.0.{index}", destination=f"203.0.113.{index}", packets=2) for index in range(1, 5)]
        self.assertEqual([], PortScanDetector().detect(rows))
        self.assertEqual([], SynFloodDetector().detect(rows))
        self.assertEqual([], UdpFloodDetector().detect(rows))

    def test_vertical_scan(self):
        rows = [flow(destination_port=port, flags=0x02, seconds_ago=port % 8) for port in range(1, 26)]
        vectors = PortScanDetector().detect(rows)
        match = next(item for item in vectors if item.attack_type == PORT_SCAN_VERTICAL)
        self.assertEqual(25, match.features["unique_dst_ports"])
        self.assertEqual(1, match.features["unique_dst_ips"])
        self.assertIn(match.window_seconds, {10, 30, 60, 300})

    def test_horizontal_scan(self):
        rows = [flow(destination=f"203.0.113.{index}", destination_port=22, flags=0x02) for index in range(1, 26)]
        match = next(item for item in PortScanDetector().detect(rows) if item.attack_type == PORT_SCAN_HORIZONTAL)
        self.assertEqual(25, match.features["unique_dst_ips"])
        self.assertEqual(1, match.features["unique_dst_ports"])

    def test_network_sweep(self):
        rows = [flow(destination=f"203.0.113.{index}", destination_port=1000 + index) for index in range(1, 26)]
        self.assertIn(NETWORK_SWEEP, {item.attack_type for item in PortScanDetector().detect(rows)})

    def test_low_slow_scan(self):
        rows = [flow(destination_port=1000 + index, seconds_ago=index * 20) for index in range(1, 13)]
        match = next(item for item in PortScanDetector().detect(rows) if item.attack_type == LOW_SLOW_SCAN)
        self.assertEqual(300, match.window_seconds)
        self.assertLess(match.features["flows_per_second"], 1)

    def test_distributed_syn_flood(self):
        rows = [
            flow(source=f"198.18.1.{index}", destination="203.0.113.55", flags=0x02, packets=100, bytes_count=6000)
            for index in range(1, 26)
        ]
        vectors = SynFloodDetector().detect(rows, lambda *_args: {"matches": []})
        match = next(item for item in vectors if item.target_prefix == "203.0.113.55/32")
        self.assertEqual(DISTRIBUTED_SYN_FLOOD, match.attack_type)
        self.assertEqual(25, match.features["unique_sources"])
        self.assertGreater(match.features["syn_ack_ratio"], 1)

    def test_single_source_syn_flood(self):
        rows = [flow(source="198.18.1.1", destination="203.0.113.54", flags=0x02, packets=1200, bytes_count=72000)]
        match = next(item for item in SynFloodDetector().detect(rows, lambda *_args: {"matches": []}) if item.target_prefix.endswith("/32"))
        self.assertEqual(SYN_FLOOD, match.attack_type)

    def test_spoofed_syn_flood_uses_bogon_and_source_diversity(self):
        rows = [
            flow(source=f"198.18.2.{index}", destination="203.0.113.56", flags=0x02, packets=100, bytes_count=6000)
            for index in range(1, 26)
        ]

        def bogon_lookup(ip, context=None):
            return {"matches": [{"provider": "TEAM_CYMRU", "indicator_type": "BOGON", "classification": "anomalous_source"}]}

        match = next(item for item in SynFloodDetector().detect(rows, bogon_lookup) if item.target_prefix.endswith("/32"))
        self.assertEqual(SPOOFED_SYN_FLOOD, match.attack_type)
        self.assertGreaterEqual(match.features["spoofing_likelihood"], 60)

    def test_distributed_udp_flood(self):
        rows = [
            flow(source=f"198.18.3.{index}", destination="203.0.113.57", protocol=17, source_port=50000 + index, packets=100, bytes_count=10000)
            for index in range(1, 26)
        ]
        match = next(item for item in UdpFloodDetector().detect(rows, lambda *_args: {"matches": []}) if item.target_prefix.endswith("/32"))
        self.assertEqual(DISTRIBUTED_UDP_FLOOD, match.attack_type)

    def test_single_source_udp_flood(self):
        rows = [flow(source="198.18.3.1", destination="203.0.113.58", protocol=17, packets=1200, bytes_count=120000)]
        match = next(item for item in UdpFloodDetector().detect(rows, lambda *_args: {"matches": []}) if item.target_prefix.endswith("/32"))
        self.assertEqual(UDP_FLOOD, match.attack_type)

    def test_udp_reflection_requires_more_than_a_port(self):
        small = [
            flow(source=f"198.18.4.{index}", destination="203.0.113.58", protocol=17, source_port=53, packets=100, bytes_count=10000)
            for index in range(1, 26)
        ]
        small_match = next(item for item in UdpFloodDetector().detect(small, lambda *_args: {"matches": []}) if item.target_prefix.endswith("/32"))
        self.assertEqual(DISTRIBUTED_UDP_FLOOD, small_match.attack_type)
        large = [
            flow(source=f"198.18.5.{index}", destination="203.0.113.59", protocol=17, source_port=53, packets=100, bytes_count=120000)
            for index in range(1, 26)
        ]
        large_match = next(item for item in UdpFloodDetector().detect(large, lambda *_args: {"matches": []}) if item.target_prefix.endswith("/32"))
        self.assertEqual(UDP_REFLECTION_SUSPECTED, large_match.attack_type)
        self.assertTrue(large_match.features["reflection_evidence_satisfied"])

    def test_carpet_bombing_aggregates_below_host_threshold(self):
        rows = [
            flow(source=f"198.18.6.{index}", destination=f"203.0.113.{index}", protocol=17, packets=1200, bytes_count=120000)
            for index in range(1, 13)
        ]
        vectors = CarpetBombingDetector().detect(rows)
        match = next(item for item in vectors if item.attack_type == CARPET_BOMBING)
        self.assertGreaterEqual(match.features["target_hosts"], 8)
        self.assertLess(match.features["max_host_pps"], 100)
        self.assertGreaterEqual(match.features["aggregate_pps"], 200)

    def test_campaign_multi_vector_and_botnet_likely(self):
        def vector(kind, detector, intel=False):
            return AttackVector(
                attack_type=kind,
                detector=detector,
                detector_score=90,
                confidence=0.9,
                first_seen="2026-08-11T11:59:00Z",
                last_seen="2026-08-11T12:00:00Z",
                target_prefix="203.0.113.0/24",
                features={"unique_sources": 30, "packets_per_second": 1000, "bits_per_second": 1000000, "flows_per_second": 100},
                threat_intel={"c2_sources": 0},
            )

        campaign = CampaignEngine(lambda: "GMJ-20260811-ABCDE").correlate(
            [vector(DISTRIBUTED_SYN_FLOOD, "syn"), vector(DISTRIBUTED_UDP_FLOOD, "udp")]
        )[0]
        self.assertEqual(MULTI_VECTOR_DDOS, campaign.classification)
        self.assertRegex(campaign.campaign_id, r"^GMJ-\d{8}-[A-Z0-9]{5}$")
        first = vector(DISTRIBUTED_UDP_FLOOD, "udp")
        second = vector(DISTRIBUTED_UDP_FLOOD, "udp")
        first.threat_intel["c2_sources"] = 3
        botnet = CampaignEngine(lambda: "GMJ-20260811-BOT01").correlate([first, second])[0]
        self.assertEqual(BOTNET_LIKELY, botnet.classification)


class FakeIntelManager:
    def lookup_ip(self, ip, context=None):
        if ip == "10.10.0.10":
            return {"matches": [{"provider": "CEREAL2", "indicator_type": "C2"}], "intel_sources": ["CEREAL2"]}
        return {"matches": [], "intel_sources": []}

    def external_attack_matches(self, *args, **kwargs):
        return []


class BehavioralPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(self.conn)
        self.engine = BehavioralDetectionEngine(lambda: self.conn, FakeIntelManager())

    def tearDown(self):
        self.conn.close()

    def test_compromised_customer_and_internal_history_are_persisted(self):
        rows = []
        for port in range(1, 26):
            rows.append(
                {
                    "flow_time": (NOW - timedelta(seconds=port % 8)).isoformat(),
                    "src_ip": "10.10.0.10",
                    "dst_ip": "198.18.10.20",
                    "src_port": 45000,
                    "dst_port": port,
                    "proto": 6,
                    "tcp_flags": 2,
                    "packets": 1,
                    "bytes": 60,
                }
            )
        vectors, campaigns = self.engine.detect(rows, ["10.10.0.0/24"])
        match = next(item for item in vectors if item.attack_type == PORT_SCAN_VERTICAL)
        self.assertEqual("OUTBOUND", match.direction)
        self.assertGreaterEqual(match.compromised_host_score, 60)
        stats = self.engine.persist(vectors, campaigns)
        self.assertGreater(stats["vectors"], 0)
        history = self.conn.execute("SELECT * FROM gmj_threat_history WHERE entity_key='10.10.0.10'").fetchone()
        self.assertIsNotNone(history)
        self.assertGreaterEqual(history["attacks_seen"], 1)
        self.assertGreaterEqual(self.conn.execute("SELECT COUNT(*) FROM threat_engine_audit").fetchone()[0], 1)

    def test_prefix_baseline_and_internal_recurrence_feed_the_next_detection(self):
        rows = [
            {
                "flow_time": NOW.isoformat(),
                "src_ip": "198.18.20.1",
                "dst_ip": "203.0.113.90",
                "src_port": 45000,
                "dst_port": 443,
                "proto": 6,
                "tcp_flags": 2,
                "packets": 1200,
                "bytes": 72000,
            }
        ]
        first, campaigns = self.engine.detect(rows)
        self.engine.persist(first, campaigns)
        second, _ = self.engine.detect(rows)
        host = next(item for item in second if item.attack_type == SYN_FLOOD and item.target_prefix == "203.0.113.90/32")
        self.assertGreaterEqual(host.features["historical_recurrence"], 1)
        self.assertGreater(host.baseline_deviation, 0)
        baseline = self.conn.execute(
            "SELECT * FROM prefix_behavior_baselines WHERE prefix='203.0.113.90/32' AND protocol='tcp'"
        ).fetchone()
        self.assertIsNotNone(baseline)
        self.assertGreaterEqual(baseline["sample_count"], 1)


if __name__ == "__main__":
    unittest.main()
