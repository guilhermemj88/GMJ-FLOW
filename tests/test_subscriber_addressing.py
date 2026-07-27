import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_dns_single_flow_outbound import backend_main


class SubscriberAddressingResolutionTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tempdir.name) / "gmjflow.db")
        self.env_patch = mock.patch.dict(
            os.environ,
            {"GMJFLOW_DB_PATH": self.db_path},
            clear=False,
        )
        self.ready_patch = mock.patch.object(backend_main, "SENSOR_DB_READY", False)
        self.hash_patch = mock.patch.object(backend_main, "hash_password", return_value="test-hash")
        self.env_patch.start()
        self.ready_patch.start()
        self.hash_patch.start()
        backend_main.ensure_sensor_db()
        self.conn = backend_main.sqlite_connection()

    def tearDown(self):
        self.conn.close()
        self.hash_patch.stop()
        self.ready_patch.stop()
        self.env_patch.stop()
        self.tempdir.cleanup()

    def add_zone(self, mode, cidr, prefix_type="client"):
        now = "2026-07-27T12:00:00Z"
        cursor = self.conn.execute(
            """
            INSERT INTO ip_zones (
                name, description, active, subscriber_addressing_mode,
                created_at, updated_at
            )
            VALUES (?, '', 1, ?, ?, ?)
            """,
            ("Zone " + mode, mode, now, now),
        )
        zone_id = int(cursor.lastrowid)
        self.conn.execute(
            """
            INSERT INTO ip_zone_prefixes (
                zone_id, cidr, name, description, prefix_type, active,
                created_at, updated_at
            )
            VALUES (?, ?, ?, '', ?, 1, ?, ?)
            """,
            (zone_id, cidr, prefix_type, prefix_type, now, now),
        )
        self.conn.commit()
        return zone_id

    def add_prefix(self, zone_id, cidr, prefix_type):
        now = "2026-07-27T12:00:00Z"
        self.conn.execute(
            """
            INSERT INTO ip_zone_prefixes (
                zone_id, cidr, name, description, prefix_type, active,
                created_at, updated_at
            )
            VALUES (?, ?, ?, '', ?, 1, ?, ?)
            """,
            (zone_id, cidr, prefix_type, prefix_type, now, now),
        )
        self.conn.commit()

    def add_active_mapping(
        self,
        public_ip,
        private_ip,
        port_start=1000,
        port_end=1999,
        batch_id=None,
    ):
        now = "2026-07-27T12:00:00Z"
        if batch_id is None:
            cursor = self.conn.execute(
                """
                INSERT INTO cgnat_import_batches (
                    filename, original_filename, file_hash, status, confidence,
                    created_at, approved_at, activated_at
                )
                VALUES (?, ?, ?, 'active', 1, ?, ?, ?)
                """,
                (
                    "mapping.txt",
                    "mapping.txt",
                    "hash-" + public_ip + "-" + private_ip,
                    now,
                    now,
                    now,
                ),
            )
            batch_id = int(cursor.lastrowid)
        self.conn.execute(
            """
            INSERT INTO cgnat_port_mappings (
                batch_id, source_type, source_filename, device_name, pool_name,
                public_ip, private_ip, protocol, port_start, port_end,
                active, confidence, created_at, updated_at
            )
            VALUES (?, 'a10', 'mapping.txt', 'cgnat-1', 'pool-1',
                    ?, ?, 'udp', ?, ?, 1, 1, ?, ?)
            """,
            (batch_id, public_ip, private_ip, port_start, port_end, now, now),
        )
        self.conn.commit()
        return batch_id

    @staticmethod
    def event(zone_id, source_ip, source_port=1500):
        return {
            "id": 2521,
            "zone_id": zone_id,
            "vector_name": backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
            "attack_vector_name": backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
            "direction": "transmits",
            "severity": "critical",
            "classification": "attack",
            "confidence_label": "high",
            "protocol": "udp",
            "top_src_ip": source_ip,
            "top_src_port": source_port,
            "top_dst_ip": "73.73.73.74",
            "top_dst_port": 53,
            "observed_value": 9_400.0,
            "unique_src_ips": 1,
            "unique_dst_ips": 1,
            "unique_conversations": 1,
            "last_seen_at": "2026-07-27T12:00:00Z",
            "source_details": {
                "classification": "attack",
                "deterministic_confidence_label": "high",
                "unique_src_ips": 1,
                "unique_destinations": 1,
                "unique_conversations": 1,
                "automatic_mitigation_threshold": 5_000.0,
                "detection": {
                    "triggered_severity": "critical",
                    "automatic_mitigation_threshold": 5_000.0,
                    "current": {
                        "last_value": 9_400.0,
                        "automatic_mitigation_threshold": 5_000.0,
                    },
                },
            },
        }

    @staticmethod
    def dns_candidate(event):
        return {
            "attack_vector_name": backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
            "candidate_role": "automatic_destination_dns",
            "protocol": "udp",
            "dst_port": "53",
            "dst_cidr": "73.73.73.74/32",
            "dst_prefix": "73.73.73.74/32",
            "target_prefix": "73.73.73.74/32",
            "mitigation_scope": backend_main.DNS_SINGLE_FLOW_MITIGATION_SCOPE,
            "public_ip": event.get("public_ip"),
            "public_port": event.get("public_port"),
            "private_ip": event.get("private_ip"),
            "mapped_port_start": event.get("mapped_port_start"),
            "mapped_port_end": event.get("mapped_port_end"),
            "cgnat_matched": event.get("cgnat_matched"),
            "cgnat_ambiguous": event.get("cgnat_ambiguous"),
            "cgnat_batch_id": event.get("cgnat_batch_id"),
            "cgnat_mapping_active": event.get("cgnat_mapping_active"),
            "unique_private_subscribers": event.get("unique_private_subscribers"),
            "unique_sources": event.get("unique_sources"),
            "unique_destinations": event.get("unique_destinations"),
            "unique_conversations": event.get("unique_conversations"),
            "subscriber_addressing_resolution": event.get("subscriber_addressing_resolution"),
            "effective_subscriber_addressing_mode": event.get("effective_subscriber_addressing_mode"),
            "cgnat_gate": event.get("cgnat_gate"),
            "top_flow": {
                "src_ip": event.get("top_src_ip"),
                "src_port": event.get("top_src_port"),
                "dst_ip": "73.73.73.74",
                "dst_port": 53,
                "packets_s": 9_400.0,
                "protocol": "udp",
            },
            "raw_payload": {"anomaly": event},
        }

    def dns_gate(self, event):
        return backend_main.dns_single_flow_automatic_policy_gate(
            self.dns_candidate(event),
            whitelist_hits=[],
            whitelist_consulted=True,
        )

    def test_existing_zone_default_is_conservative_cgnat(self):
        now = "2026-07-27T12:00:00Z"
        cursor = self.conn.execute(
            """
            INSERT INTO ip_zones (name, description, active, created_at, updated_at)
            VALUES ('Legacy', '', 1, ?, ?)
            """,
            (now, now),
        )
        zone = backend_main.fetch_ip_zone(self.conn, int(cursor.lastrowid))
        self.assertEqual(zone["subscriber_addressing_mode"], "cgnat")
        preserved = backend_main.normalize_ip_zone_payload(
            self.conn,
            backend_main.IpZonePayload(name="Legacy renamed"),
            "direct_public",
        )
        self.assertEqual(preserved["subscriber_addressing_mode"], "direct_public")

    def test_direct_public_skips_cgnat_and_authorizes_real_dns_case(self):
        zone_id = self.add_zone("direct_public", "179.189.83.0/24")
        enriched = backend_main.enrich_anomaly_event_with_cgnat(
            self.conn,
            self.event(zone_id, "179.189.83.212", 32297),
        )
        resolution = enriched["subscriber_addressing_resolution"]
        self.assertEqual(resolution["configured_mode"], "direct_public")
        self.assertEqual(resolution["effective_mode"], "direct_public")
        self.assertTrue(resolution["direct_public_authorized"])
        self.assertFalse(resolution["cgnat_lookup_required"])
        self.assertFalse(resolution["cgnat_lookup_performed"])
        self.assertEqual(enriched["cgnat_gate"], "not_applicable")
        self.assertEqual(enriched["cgnat_mapping_status"], "not_applicable")
        self.assertIn("IPv4 publico direto", enriched["cgnat_mapping_message"])
        self.assertNotIn("cgnat_mitigation_block_reason", enriched)
        gate = self.dns_gate(enriched)
        self.assertTrue(gate["allowed"])
        self.assertEqual(gate["cgnat_gate"], "not_applicable")

    def test_cgnat_requires_active_unambiguous_fixed_nat_mapping(self):
        zone_id = self.add_zone("cgnat", "203.0.113.0/24", "public_cgnat")
        missing = backend_main.enrich_anomaly_event_with_cgnat(
            self.conn,
            self.event(zone_id, "203.0.113.10"),
        )
        self.assertEqual(missing["cgnat_mitigation_block_reason"], "cgnat_subscriber_not_resolved")
        self.assertEqual(self.dns_gate(missing)["reason"], "cgnat_subscriber_not_resolved")

        batch_id = self.add_active_mapping("203.0.113.10", "100.64.0.1")
        matched = backend_main.enrich_anomaly_event_with_cgnat(
            self.conn,
            self.event(zone_id, "203.0.113.10"),
        )
        self.assertTrue(matched["cgnat_matched"])
        self.assertEqual(matched["private_ip"], "100.64.0.1")
        self.assertEqual(matched["unique_private_subscribers"], 1)
        self.assertTrue(self.dns_gate(matched)["allowed"])

        multiple_subscribers = dict(matched)
        multiple_subscribers["unique_private_subscribers"] = 2
        self.assertEqual(
            self.dns_gate(multiple_subscribers)["reason"],
            "cgnat_subscriber_not_unique",
        )

        self.conn.execute(
            "UPDATE cgnat_import_batches SET status = 'approved' WHERE id = ?",
            (batch_id,),
        )
        self.conn.commit()
        inactive_batch = backend_main.enrich_anomaly_event_with_cgnat(
            self.conn,
            self.event(zone_id, "203.0.113.10"),
        )
        self.assertFalse(inactive_batch["cgnat_matched"])
        self.assertEqual(
            self.dns_gate(inactive_batch)["reason"],
            "cgnat_subscriber_not_resolved",
        )
        self.conn.execute(
            "UPDATE cgnat_import_batches SET status = 'active' WHERE id = ?",
            (batch_id,),
        )
        self.conn.commit()

        outside_port = backend_main.enrich_anomaly_event_with_cgnat(
            self.conn,
            self.event(zone_id, "203.0.113.10", 2500),
        )
        self.assertFalse(outside_port["cgnat_matched"])
        self.assertEqual(self.dns_gate(outside_port)["reason"], "cgnat_subscriber_not_resolved")

        self.add_active_mapping(
            "203.0.113.10",
            "100.64.0.2",
            batch_id=batch_id,
        )
        ambiguous = backend_main.enrich_anomaly_event_with_cgnat(
            self.conn,
            self.event(zone_id, "203.0.113.10"),
        )
        self.assertTrue(ambiguous["cgnat_ambiguous"])
        self.assertEqual(ambiguous["unique_private_subscribers"], 0)
        self.assertEqual(self.dns_gate(ambiguous)["reason"], "cgnat_mapping_ambiguous")

    def test_mixed_selects_gate_from_explicit_cgnat_prefix(self):
        zone_id = self.add_zone("mixed", "179.189.83.0/24", "client")
        self.add_prefix(zone_id, "203.0.113.0/24", "public_cgnat")
        direct = backend_main.enrich_anomaly_event_with_cgnat(
            self.conn,
            self.event(zone_id, "179.189.83.212"),
        )
        self.assertEqual(direct["effective_subscriber_addressing_mode"], "direct_public")
        self.assertTrue(self.dns_gate(direct)["allowed"])

        cgnat = backend_main.enrich_anomaly_event_with_cgnat(
            self.conn,
            self.event(zone_id, "203.0.113.10"),
        )
        self.assertEqual(cgnat["effective_subscriber_addressing_mode"], "cgnat")
        self.assertEqual(cgnat["cgnat_mitigation_block_reason"], "cgnat_subscriber_not_resolved")

    def test_auto_uses_explicit_evidence_and_blocks_real_doubt(self):
        zone_id = self.add_zone("auto", "179.189.83.0/24", "client")
        self.add_prefix(zone_id, "203.0.113.0/24", "public_cgnat")
        self.add_active_mapping("203.0.113.10", "100.64.0.10")

        direct = backend_main.enrich_anomaly_event_with_cgnat(
            self.conn,
            self.event(zone_id, "179.189.83.212"),
        )
        self.assertEqual(direct["subscriber_addressing_resolution"]["reason"], "auto_direct_zone_prefix")
        self.assertTrue(self.dns_gate(direct)["allowed"])

        cgnat = backend_main.enrich_anomaly_event_with_cgnat(
            self.conn,
            self.event(zone_id, "203.0.113.10"),
        )
        self.assertEqual(cgnat["effective_subscriber_addressing_mode"], "cgnat")
        self.assertTrue(cgnat["cgnat_matched"])
        self.assertTrue(self.dns_gate(cgnat)["allowed"])

        unresolved = backend_main.enrich_anomaly_event_with_cgnat(
            self.conn,
            self.event(zone_id, "198.51.100.99"),
        )
        self.assertEqual(unresolved["effective_subscriber_addressing_mode"], "unresolved")
        self.assertTrue(unresolved["subscriber_addressing_resolution"]["ambiguity"])
        self.assertEqual(
            self.dns_gate(unresolved)["reason"],
            "auto_subscriber_addressing_not_determined",
        )

    def test_frontend_exposes_zone_mode_and_addressing_audit(self):
        html = (Path(__file__).resolve().parents[1] / "frontend" / "index.html").read_text(
            encoding="utf-8"
        )
        self.assertIn('id="ipZoneSubscriberAddressingMode"', html)
        for mode in ("direct_public", "cgnat", "mixed", "auto"):
            self.assertIn('value="' + mode + '"', html)
        self.assertIn("Cliente com IPv4 público direto", html)
        self.assertIn("Gates não aplicáveis", html)
        self.assertIn("Endereçamento do assinante", html)


if __name__ == "__main__":
    unittest.main()
