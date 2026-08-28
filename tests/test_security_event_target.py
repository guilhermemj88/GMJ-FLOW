"""Tests for outbound destination preservation (Threat Intelligence Map V2.3).

Covers the semantic target owner, the persistence of top destination details,
the recurrence merge (never losing a valid target), and the rule that
multi-target scans never fabricate a single target IP.
"""

from __future__ import annotations

import sqlite3
import unittest

from app.services.behavioral_detection import (
    AttackVector,
    PortScanDetector,
    flow_features,
    FlowObservation,
)
from app.services.security_events import (
    ensure_security_event_schema,
    resolve_event_target,
    upsert_security_event,
    vector_security_payload,
)


def make_flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80, packets=10, flows=1):
    from datetime import datetime, timezone

    return FlowObservation(
        observed_at=datetime.now(timezone.utc),
        src_ip=src_ip, dst_ip=dst_ip, src_port=50000, dst_port=dst_port,
        protocol=6, tcp_flags=0x02, packets=packets, bytes=packets * 40,
        flow_count=flows, src_asn=1, dst_asn=15169, sensor="s", exporter_ip="10.0.0.2",
    )


def make_vector(**overrides) -> AttackVector:
    base = dict(
        attack_type="PORT_SCAN_HORIZONTAL", detector="port_scan", detector_score=80,
        confidence=0.8, first_seen="2026-08-22T09:00:00Z", last_seen="2026-08-22T09:05:00Z",
        src_ip="10.0.0.1", target_ip="", target_prefix="", direction="OUTBOUND",
    )
    base.update(overrides)
    return AttackVector(**base)


class ResolveEventTargetTest(unittest.TestCase):
    def test_single_ip(self):
        result = resolve_event_target("8.8.8.8", "", "OUTBOUND")
        self.assertEqual(result["target_scope"], "single")
        self.assertEqual(result["target_ip"], "8.8.8.8")
        self.assertEqual(result["target_prefix"], "8.8.8.8/32")

    def test_prefix_scope(self):
        result = resolve_event_target("", "45.133.39.0/24", "OUTBOUND")
        self.assertEqual(result["target_scope"], "prefix")
        self.assertEqual(result["target_prefix"], "45.133.39.0/24")

    def test_multi_target_never_fabricates_single_ip(self):
        result = resolve_event_target("", "", "OUTBOUND", {"unique_destinations": 23})
        self.assertEqual(result["target_scope"], "multi")
        self.assertEqual(result["target_ip"], "")
        self.assertEqual(result["target_prefix"], "")

    def test_no_target_scope(self):
        result = resolve_event_target("", "", "INBOUND", {"unique_destinations": 1})
        self.assertEqual(result["target_scope"], "none")


class FlowFeaturesTest(unittest.TestCase):
    def test_top_destination_details_preserved(self):
        flows = [make_flow(dst_ip=f"8.8.8.{i}", dst_port=80) for i in range(1, 6)]
        features = flow_features(flows, 300)
        self.assertIn("top_destination_details", features)
        details = features["top_destination_details"]
        self.assertGreaterEqual(len(details), 5)
        ips = {item["destination_ip"] for item in details}
        self.assertEqual(ips, {f"8.8.8.{i}" for i in range(1, 6)})


class VectorPayloadTest(unittest.TestCase):
    def test_payload_persists_top_destinations_and_target_scope(self):
        vector = make_vector()
        vector.features = {
            "top_destination_details": [
                {"destination_ip": "8.8.8.8", "packets": 20, "bytes": 800, "flows": 20, "pps": 0.1, "share": 100.0},
                {"destination_ip": "1.1.1.1", "packets": 10, "bytes": 400, "flows": 10, "pps": 0.05, "share": 50.0},
            ],
            "unique_destinations": 23,
            "unique_dst_ips": 23,
            "packet_count": 30,
            "packets": 30,
            "byte_count": 1200,
            "bytes": 1200,
            "packets_per_second": 0.1,
            "bits_per_second": 320,
            "flow_count": 30,
            "flows": 30,
            "flows_per_second": 0.1,
            "unique_sources": 1,
            "unique_src_ips": 1,
            "unique_src_ports": 1,
            "unique_dst_ports": 1,
            "unique_source_asns": 1,
            "observation_samples": 30,
            "persistent_windows": 1,
        }
        payload = vector_security_payload(vector)
        import json

        investigation = json.loads(payload["investigation_json"])
        self.assertEqual(investigation["target_scope"], "multi")
        self.assertEqual(len(investigation["top_destinations"]), 2)
        self.assertEqual(investigation["top_destinations"][0]["destination_ip"], "8.8.8.8")


class MergePreservesTargetTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_security_event_schema(self.conn)

    def test_recurrence_keeps_valid_target(self):
        vector = make_vector(target_ip="8.8.8.8", target_prefix="8.8.8.8/32")
        event_id = upsert_security_event(self.conn, vector)
        # Mesma chave (mesmo target): recorrência mantém o target e incrementa.
        vector2 = make_vector(target_ip="8.8.8.8", target_prefix="8.8.8.8/32")
        upsert_security_event(self.conn, vector2)
        row = self.conn.execute(
            "SELECT target_ip, target_prefix, recurrence_count FROM security_events WHERE id=?", (event_id,)
        ).fetchone()
        self.assertEqual(row["target_ip"], "8.8.8.8")
        self.assertEqual(row["target_prefix"], "8.8.8.8/32")
        self.assertEqual(row["recurrence_count"], 2)

    def test_different_target_creates_separate_event(self):
        vector = make_vector(target_ip="8.8.8.8", target_prefix="8.8.8.8/32")
        event_id = upsert_security_event(self.conn, vector)
        vector2 = make_vector(target_ip="9.9.9.9", target_prefix="9.9.9.9/32")
        event_id2 = upsert_security_event(self.conn, vector2)
        self.assertNotEqual(event_id, event_id2)
        row = self.conn.execute("SELECT target_ip FROM security_events WHERE id=?", (event_id,)).fetchone()
        self.assertEqual(row["target_ip"], "8.8.8.8")


class PortScanDetectorTargetTest(unittest.TestCase):
    def test_multi_target_scan_does_not_fabricate_single_ip(self):
        detector = PortScanDetector()
        flows = [make_flow(dst_ip=f"203.0.113.{i}", dst_port=80) for i in range(1, 26)]
        vectors = detector.detect(flows)
        self.assertTrue(vectors)
        horizontal = [v for v in vectors if v.attack_type == "PORT_SCAN_HORIZONTAL"]
        for vector in horizontal:
            # Multi-target scan: nunca inventa um único target_ip.
            if vector.features.get("unique_dst_ips", 0) > 1:
                self.assertEqual(vector.target_ip, "")

    def test_single_target_scan_preserves_ip(self):
        detector = PortScanDetector()
        # Um destino, muitas portas -> vertical scan com target único.
        flows = [make_flow(dst_ip="203.0.113.9", dst_port=p) for p in range(1, 26)]
        vectors = detector.detect(flows)
        vertical = [v for v in vectors if v.attack_type == "PORT_SCAN_VERTICAL"]
        self.assertTrue(vertical)
        for vector in vertical:
            if vector.features.get("unique_dst_ips", 0) == 1:
                self.assertEqual(vector.target_ip, "203.0.113.9")


if __name__ == "__main__":
    unittest.main()
