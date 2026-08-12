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
    CARPET_BOMBING,
    COORDINATED_SCANNING,
    DISTRIBUTED_SYN_FLOOD,
    DISTRIBUTED_UDP_FLOOD,
    LOW_SLOW_SCAN,
    MULTI_VECTOR_DDOS,
    NETWORK_SWEEP,
    PORT_SCAN_HORIZONTAL,
    PORT_SCAN_VERTICAL,
    SCANNING_CAMPAIGN,
    SSH_BRUTE_FORCE,
    AttackVector,
    BehavioralDetectionEngine,
    BehavioralThreatRuntime,
    CampaignEngine,
    CarpetBombingDetector,
    FlowObservation,
    PortScanDetector,
    SshBruteForceDetector,
    UdpFloodDetector,
    ensure_behavioral_schema,
)
from app.services.network_context import NetworkContextEngine  # noqa: E402
from app.services.security_events import (  # noqa: E402
    cleanup_security_events,
    ensure_security_event_schema,
    security_event_row,
    update_security_event_mitigation_status,
    upsert_security_event,
)
from app.services.security_event_ai import analyze_security_event  # noqa: E402


NOW = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)


def flow(
    source: str,
    destination: str,
    *,
    source_port: int = 40000,
    destination_port: int = 443,
    protocol: int = 17,
    flags: int = 0,
    packets: int = 1,
    bytes_count: int = 100,
    seconds_ago: int = 0,
    source_asn: int = 64500,
) -> FlowObservation:
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
        src_asn=source_asn,
        sensor="edge",
        exporter_ip="192.0.2.1",
        input_if=10,
        output_if=20,
    )


class NoIntel:
    def lookup_ip(self, *_args, **_kwargs):
        return {"matches": []}

    def external_attack_matches(self, *_args, **_kwargs):
        return []


class IspRegressionTest(unittest.TestCase):
    def test_case_1_benign_quic_cgnat_is_not_distributed_udp_flood(self):
        rows = [
            flow(
                f"198.51.{index // 254}.{index % 254 + 1}",
                f"203.0.113.{index % 161 + 1}",
                source_port=443,
                destination_port=32768 + index,
                packets=10 if index < 354 else 9,
                bytes_count=12000,
                source_asn=64500 + (index % 330),
                seconds_ago=index % 60,
            )
            for index in range(446)
        ]
        vectors = UdpFloodDetector().detect(rows, lambda *_args: {"matches": []})
        self.assertNotIn(DISTRIBUTED_UDP_FLOOD, {item.attack_type for item in vectors})

    def test_case_2_normal_dns_cardinality_is_not_attack(self):
        rows = [
            flow(
                "8.8.8.8",
                f"203.0.113.{index % 56 + 1}",
                source_port=53,
                destination_port=40000 + index,
                packets=1,
                bytes_count=120,
                seconds_ago=index % 60,
            )
            for index in range(75)
        ]
        self.assertEqual([], UdpFloodDetector().detect(rows, lambda *_args: {"matches": []}))

    def test_case_3_baseline_only_does_not_create_carpet_bombing(self):
        rows = [
            flow("198.51.100.10", f"203.0.113.{index + 1}", packets=1, seconds_ago=index)
            for index in range(9)
        ] + [flow("198.51.100.11", "203.0.113.1", packets=1)]
        baseline = {"203.0.113.0/24": (10 / 60) / 3.7}
        vectors = CarpetBombingDetector().detect(rows, baseline)
        self.assertNotIn(CARPET_BOMBING, {item.attack_type for item in vectors})

    def test_cases_4_to_6_syn_only_scan_shapes(self):
        vertical = [flow("198.51.100.1", "203.0.113.10", protocol=6, flags=2, destination_port=port) for port in range(30)]
        horizontal = [flow("198.51.100.2", f"203.0.113.{index + 1}", protocol=6, flags=2, destination_port=443) for index in range(30)]
        sweep = [flow("198.51.100.3", f"203.0.113.{index + 1}", protocol=6, flags=2, destination_port=1000 + index) for index in range(30)]
        detector = PortScanDetector()
        self.assertIn(PORT_SCAN_VERTICAL, {item.attack_type for item in detector.detect(vertical)})
        self.assertIn(PORT_SCAN_HORIZONTAL, {item.attack_type for item in detector.detect(horizontal)})
        self.assertIn(NETWORK_SWEEP, {item.attack_type for item in detector.detect(sweep)})

    def test_ssh_single_host_many_attempts_is_brute_force(self):
        rows = [
            flow(
                "198.51.100.4", "203.0.113.22", protocol=6, flags=2,
                destination_port=22, packets=5, bytes_count=300, seconds_ago=index * 2,
            )
            for index in range(60)
        ]
        vectors = SshBruteForceDetector().detect(rows, lambda *_args: {"matches": []})
        self.assertEqual(SSH_BRUTE_FORCE, vectors[0].attack_type)
        self.assertEqual(1, vectors[0].features["unique_destinations"])

    def test_ssh_many_hosts_few_attempts_remains_horizontal_scan(self):
        rows = [
            flow(
                "198.51.100.40", f"203.0.113.{index + 1}", protocol=6, flags=2,
                destination_port=22, packets=1, seconds_ago=index,
            )
            for index in range(30)
        ]
        self.assertIn(PORT_SCAN_HORIZONTAL, {item.attack_type for item in PortScanDetector().detect(rows)})
        self.assertEqual([], SshBruteForceDetector().detect(rows, lambda *_args: {"matches": []}))

    def test_ssh_many_hosts_many_attempts_is_one_scan_with_complementary_evidence(self):
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(conn)
        rows = [
            flow(
                "198.51.100.41", f"203.0.113.{host + 1}", protocol=6, flags=2,
                destination_port=22, packets=1, seconds_ago=attempt * 2,
            )
            for host in range(30)
            for attempt in range(30)
        ]
        vectors, _campaigns = BehavioralDetectionEngine(lambda: conn, NoIntel()).detect(
            [item.__dict__ for item in rows]
        )
        self.assertNotIn(SSH_BRUTE_FORCE, {item.attack_type for item in vectors})
        scan = [item for item in vectors if item.attack_type in {PORT_SCAN_HORIZONTAL, NETWORK_SWEEP}]
        self.assertEqual(1, len(scan))
        self.assertEqual(30, scan[0].features["ssh_multi_target_evidence"]["qualifying_targets"])
        self.assertTrue(any("vetores SSH por host suprimidos" in fact for fact in scan[0].evidence))
        conn.close()

    def test_case_8_scan_plus_scan_never_becomes_ddos(self):
        def vector(kind: str, source: str) -> AttackVector:
            return AttackVector(
                attack_type=kind,
                detector="scan",
                detector_score=75,
                confidence=.75,
                first_seen=(NOW - timedelta(minutes=4)).isoformat(),
                last_seen=NOW.isoformat(),
                src_ip=source,
                target_prefix="203.0.113.0/24",
                features={"unique_sources": 1, "packets_per_second": .3, "bits_per_second": 5000, "flows_per_second": .2},
            )

        campaign = CampaignEngine(lambda: "GMJ-20260812-SCAN1").correlate([
            vector(LOW_SLOW_SCAN, "198.51.100.5"),
            vector(PORT_SCAN_VERTICAL, "198.51.100.6"),
        ])[0]
        self.assertIn(campaign.classification, {SCANNING_CAMPAIGN, COORDINATED_SCANNING})
        self.assertNotEqual(MULTI_VECTOR_DDOS, campaign.classification)

    def test_campaign_preserves_observed_asn_diversity(self):
        def flood(kind: str, source: str) -> AttackVector:
            return AttackVector(
                attack_type=kind,
                detector="flood",
                detector_score=90,
                confidence=.9,
                first_seen=(NOW - timedelta(minutes=2)).isoformat(),
                last_seen=NOW.isoformat(),
                src_ip=source,
                target_ip="203.0.113.50",
                target_prefix="203.0.113.0/24",
                features={
                    "unique_sources": 446,
                    "unique_source_asns": 330,
                    "source_asns": list(range(64500, 64600)),
                    "packets_per_second": 150,
                    "bits_per_second": 600_000,
                    "flows_per_second": 25,
                    "persistent_windows": 4,
                },
            )

        campaign = CampaignEngine(lambda: "GMJ-20260812-ASN01").correlate([
            flood(DISTRIBUTED_UDP_FLOOD, "198.51.100.1"),
            flood(DISTRIBUTED_SYN_FLOOD, "198.51.100.2"),
        ])[0]
        self.assertEqual(330, campaign.unique_source_asns)
        self.assertEqual(330, campaign.features["source_asn_diversity"])
        self.assertEqual(100, len(campaign.features["source_asns_sample"]))

    def test_cases_9_and_10_high_volume_detects_even_when_target_is_cgnat(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(self.conn)
        self.conn.executescript(
            """
            CREATE TABLE ip_zones (
                id INTEGER PRIMARY KEY, name TEXT, active INTEGER,
                subscriber_addressing_mode TEXT
            );
            CREATE TABLE ip_zone_prefixes (
                id INTEGER PRIMARY KEY, zone_id INTEGER, cidr TEXT,
                prefix_type TEXT, active INTEGER
            );
            INSERT INTO ip_zones VALUES (1, 'CGNAT', 1, 'cgnat');
            INSERT INTO ip_zone_prefixes VALUES (1, 1, '203.0.113.0/24', 'public_cgnat', 1);
            """
        )
        rows = [
            flow(
                f"198.51.{index // 254}.{index % 254 + 1}", "203.0.113.50",
                source_port=50000 + index, destination_port=443,
                packets=1000, bytes_count=800000,
                seconds_ago=index % 50, source_asn=64500 + index,
            )
            for index in range(40)
        ]
        direct = UdpFloodDetector().detect(rows, lambda *_args: {"matches": []})
        self.assertIn(DISTRIBUTED_UDP_FLOOD, {item.attack_type for item in direct})
        engine = BehavioralDetectionEngine(lambda: self.conn, NoIntel())
        vectors, _ = engine.detect([item.__dict__ for item in rows])
        match = next(item for item in vectors if item.attack_type == DISTRIBUTED_UDP_FLOOD and item.target_ip == "203.0.113.50")
        self.assertEqual("CGNAT_PUBLIC", match.network_context["dst_role"])
        self.assertEqual("INBOUND", match.direction)
        self.assertGreater(match.detector_score, 0)
        self.conn.close()


class CanonicalSecurityEventTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(self.conn)
        ensure_security_event_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def vector(self, pps: float, score: int = 70) -> AttackVector:
        return AttackVector(
            attack_type=PORT_SCAN_VERTICAL,
            detector="port_scan",
            detector_score=score,
            confidence=score / 100,
            first_seen="2026-08-12T11:00:00Z",
            last_seen="2026-08-12T11:01:00Z",
            src_ip="198.51.100.9",
            target_ip="203.0.113.9",
            protocol="tcp",
            direction="INBOUND",
            features={"packet_count": 100, "packets_per_second": pps, "unique_dst_ports": 30},
            network_context={"src_role": "EXTERNAL", "dst_role": "CUSTOMER", "traffic_direction": "INBOUND"},
            evidence=["30 portas TCP SYN sem ACK"],
            score_components={"cardinality": 30, "persistence": 10},
        )

    def test_upsert_is_stable_and_preserves_maximum_metrics(self):
        event_id = upsert_security_event(self.conn, self.vector(10, 70))
        self.assertEqual(event_id, upsert_security_event(self.conn, self.vector(25, 80)))
        row = security_event_row(self.conn.execute("SELECT * FROM security_events WHERE id=?", (event_id,)).fetchone())
        self.assertEqual(2, row["recurrence_count"])
        self.assertEqual(25, row["packets_per_second"])
        self.assertEqual(80, row["detector_score"])

    def test_retention_keeps_investigating_events(self):
        event_id = upsert_security_event(self.conn, self.vector(10))
        old = "2026-01-01T00:00:00Z"
        self.conn.execute("UPDATE security_events SET last_seen=?, status='investigating' WHERE id=?", (old, event_id))
        second = self.vector(11)
        second.src_ip = "198.51.100.10"
        active_id = upsert_security_event(self.conn, second)
        self.conn.execute("UPDATE security_events SET last_seen=? WHERE id=?", (old, active_id))
        removed = cleanup_security_events(self.conn, retention_days=3)
        self.assertEqual(1, removed)
        self.assertIsNotNone(self.conn.execute("SELECT 1 FROM security_events WHERE id=?", (event_id,)).fetchone())

    def test_external_external_direction_is_not_internal(self):
        context = NetworkContextEngine(lambda: self.conn).resolve("198.51.100.1", "203.0.113.1")
        self.assertEqual("EXTERNAL", context.traffic_direction)

    def test_ai_receives_context_is_cached_and_never_executes_mitigation(self):
        event_id = upsert_security_event(self.conn, self.vector(10))
        calls = []

        def executor(_conn, function_key, prompt, **kwargs):
            calls.append((function_key, prompt, kwargs))
            return {
                "ok": True,
                "provider": "Local test",
                "model": "deterministic-test",
                "structured": {
                    "verdict": "SUSPICIOUS",
                    "confidence": 88,
                    "summary": "Evidência requer investigação.",
                    "evidence_for_attack": ["SYN sem ACK"],
                    "evidence_against_attack": ["volume baixo"],
                    "likely_explanation": "scan",
                    "network_context_interpretation": "EXTERNAL para CUSTOMER",
                    "threat_intel_interpretation": "sem confirmação externa",
                    "recommended_action": "monitorar",
                    "mitigation_recommended": False,
                },
            }

        result = analyze_security_event(self.conn, event_id, executor=executor)
        self.assertTrue(result["ok"])
        self.assertFalse(result["analysis"]["mitigation_executed"])
        self.assertIn('"network_context"', calls[0][1])
        cached = analyze_security_event(self.conn, event_id, executor=executor)
        self.assertTrue(cached["cached"])
        self.assertEqual(1, len(calls))
        analyze_security_event(self.conn, event_id, force=True, executor=executor)
        self.assertEqual(2, len(calls))

    def test_material_recurrence_marks_ai_cache_stale_and_preserves_prior_analysis(self):
        event_id = upsert_security_event(self.conn, self.vector(10))
        calls = []

        def executor(_conn, _function_key, _prompt, **_kwargs):
            calls.append("analysis")
            return {
                "ok": True,
                "provider": "Local test",
                "model": "deterministic-test",
                "structured": {
                    "verdict": "SUSPICIOUS",
                    "confidence": 80,
                    "summary": f"analysis-{len(calls)}",
                    "evidence_for_attack": ["SYN sem ACK"],
                    "evidence_against_attack": ["volume baixo"],
                    "likely_explanation": "scan",
                    "network_context_interpretation": "EXTERNAL para CUSTOMER",
                    "threat_intel_interpretation": "sem confirmação externa",
                    "recommended_action": "monitorar",
                    "mitigation_recommended": False,
                },
            }

        first = analyze_security_event(self.conn, event_id, executor=executor)
        changed = self.vector(25, 85)
        changed.last_seen = "2026-08-12T11:02:00Z"
        changed.evidence.append("nova recorrência com cardinalidade maior")
        self.assertEqual(event_id, upsert_security_event(self.conn, changed))
        stale = security_event_row(self.conn.execute("SELECT * FROM security_events WHERE id=?", (event_id,)).fetchone())
        self.assertEqual("stale", stale["ai_analysis_status"])
        self.assertEqual(first["analysis"], stale["ai_analysis"])
        self.assertIsNotNone(stale["ai_analysis_stale_at"])
        refreshed = analyze_security_event(self.conn, event_id, executor=executor)
        self.assertFalse(refreshed["cached"])
        self.assertEqual("analysis-2", refreshed["analysis"]["summary"])
        self.assertEqual(2, len(calls))
        audit = self.conn.execute(
            "SELECT groq_result_json, reason FROM threat_engine_audit WHERE event_type='AI_ANALYSIS_INVALIDATED'"
        ).fetchone()
        self.assertIsNotNone(audit)
        self.assertIn("analysis-1", audit["groq_result_json"])
        self.assertIn("last_seen", audit["reason"])

    def test_mitigation_status_tracks_policy_lifecycle_without_executing_flowspec(self):
        vector = self.vector(10)
        event_id = upsert_security_event(self.conn, vector)
        for status in ("shadow", "requested", "executed", "failed", "expired", "not_executed"):
            changed = update_security_event_mitigation_status(
                self.conn,
                vector,
                status,
                decision_source="POLICY_TEST",
            )
            self.assertEqual(1, changed)
            row = self.conn.execute(
                "SELECT mitigation_status, decision_source, updated_at FROM security_events WHERE id=?",
                (event_id,),
            ).fetchone()
            self.assertEqual(status, row["mitigation_status"])
            self.assertEqual("POLICY_TEST", row["decision_source"])
            self.assertTrue(row["updated_at"])

    def test_operational_mitigation_results_map_to_canonical_states(self):
        expected = {
            "dry_run": "shadow",
            "queued": "requested",
            "advertised": "executed",
            "failed": "failed",
            "rejected_by_policy": "failed",
            "withdrawn": "expired",
            "expired": "expired",
        }
        for operational, canonical in expected.items():
            self.assertEqual(
                canonical,
                BehavioralThreatRuntime.mitigation_status_from_result({"status": operational}),
            )


class StableCampaignPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(self.conn)
        ensure_security_event_schema(self.conn)
        self.engine = BehavioralDetectionEngine(lambda: self.conn, NoIntel())

    def tearDown(self):
        self.conn.close()

    @staticmethod
    def vectors(target_prefix: str, *, first_seen: str, last_seen: str, pps: float) -> list[AttackVector]:
        return [
            AttackVector(
                attack_type=kind,
                detector="port_scan",
                detector_score=80,
                confidence=.8,
                first_seen=first_seen,
                last_seen=last_seen,
                src_ip=f"198.51.100.{index + 60}",
                target_prefix=target_prefix,
                direction="INBOUND",
                protocol="tcp",
                network_context={"src_role": "EXTERNAL", "dst_role": "CUSTOMER"},
                features={
                    "unique_sources": 1,
                    "packets_per_second": pps,
                    "bits_per_second": pps * 800,
                    "flows_per_second": pps / 2,
                },
            )
            for index, kind in enumerate((LOW_SLOW_SCAN, PORT_SCAN_VERTICAL))
        ]

    def test_equivalent_consecutive_campaigns_have_stable_key_and_upsert(self):
        first = CampaignEngine().correlate(self.vectors(
            "203.0.113.0/24",
            first_seen="2026-08-12T10:00:00Z",
            last_seen="2026-08-12T10:01:00Z",
            pps=5,
        ))[0]
        second = CampaignEngine().correlate(self.vectors(
            "203.0.113.0/24",
            first_seen="2026-08-12T10:02:00Z",
            last_seen="2026-08-12T10:03:00Z",
            pps=9,
        ))[0]
        self.assertEqual(first.campaign_key, second.campaign_key)
        self.assertEqual(first.campaign_id, second.campaign_id)
        self.engine.persist([], [first])
        self.engine.persist([], [second])
        rows = self.conn.execute("SELECT * FROM threat_campaigns").fetchall()
        self.assertEqual(1, len(rows))
        self.assertEqual(2, rows[0]["recurrence_count"])
        self.assertEqual("2026-08-12T10:00:00Z", rows[0]["first_seen"])
        self.assertEqual("2026-08-12T10:03:00Z", rows[0]["last_seen"])
        self.assertEqual(18, rows[0]["packets_per_second"])

    def test_semantically_different_campaign_gets_a_new_key(self):
        first = CampaignEngine().correlate(self.vectors(
            "203.0.113.0/24", first_seen="2026-08-12T10:00:00Z",
            last_seen="2026-08-12T10:01:00Z", pps=5,
        ))[0]
        other = CampaignEngine().correlate(self.vectors(
            "203.0.114.0/24", first_seen="2026-08-12T10:02:00Z",
            last_seen="2026-08-12T10:03:00Z", pps=5,
        ))[0]
        self.assertNotEqual(first.campaign_key, other.campaign_key)
        self.assertNotEqual(first.campaign_id, other.campaign_id)

    def test_existing_campaign_is_progressively_keyed_and_reused(self):
        first = CampaignEngine().correlate(self.vectors(
            "203.0.113.0/24", first_seen="2026-08-12T10:00:00Z",
            last_seen="2026-08-12T10:01:00Z", pps=5,
        ))[0]
        self.conn.execute(
            """
            INSERT INTO threat_campaigns (
                campaign_id, campaign_key, target_prefix, classification, coordination_score,
                unique_sources, unique_source_asns, packets_per_second, bits_per_second,
                flows_per_second, first_seen, last_seen, feature_json, threat_intel_json,
                intel_sources_json, decision_source, created_at, updated_at
            ) VALUES (?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', '[]', 'GMJ_FLOW', ?, ?)
            """,
            (
                "GMJ-LEGACY-001", first.target_prefix, first.classification,
                first.coordination_score, first.unique_sources, first.unique_source_asns,
                first.packets_per_second, first.bits_per_second, first.flows_per_second,
                first.first_seen, first.last_seen,
                '{"attack_types":["LOW_SLOW_SCAN","PORT_SCAN_VERTICAL"]}',
                first.first_seen, first.last_seen,
            ),
        )
        ensure_behavioral_schema(self.conn)
        migrated = self.conn.execute(
            "SELECT campaign_key FROM threat_campaigns WHERE campaign_id='GMJ-LEGACY-001'"
        ).fetchone()
        self.assertEqual(first.campaign_key, migrated["campaign_key"])
        later = CampaignEngine().correlate(self.vectors(
            "203.0.113.0/24", first_seen="2026-08-12T10:02:00Z",
            last_seen="2026-08-12T10:03:00Z", pps=7,
        ))[0]
        self.engine.persist([], [later])
        rows = self.conn.execute("SELECT campaign_id, recurrence_count FROM threat_campaigns").fetchall()
        self.assertEqual(1, len(rows))
        self.assertEqual("GMJ-LEGACY-001", rows[0]["campaign_id"])
        self.assertEqual(2, rows[0]["recurrence_count"])


if __name__ == "__main__":
    unittest.main()
