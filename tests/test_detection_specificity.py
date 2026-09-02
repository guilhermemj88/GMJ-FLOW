import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from tests.test_collector_apply_static import backend_main as main


ROOT = Path(__file__).resolve().parents[1]


def rule_spec(
    protocol="ALL",
    dst_port="any",
    src_port="any",
    direction="transmits",
    domain="internal_ip",
    group_by="",
    src_cidr="",
    dst_cidr="",
    input_if="",
    output_if="",
):
    return {
        "protocol": protocol,
        "dst_port": dst_port,
        "src_port": src_port,
        "direction": direction,
        "domain": domain,
        "group_by": group_by,
        "detection_key": "",
        "src_cidr": src_cidr,
        "dst_cidr": dst_cidr,
        "input_if": input_if,
        "output_if": output_if,
    }


def candidate(
    rule_id=1,
    vector="V",
    specificity_score=0,
    severity="warning",
    warning=5000,
    critical=None,
    src_ip="45.5.248.196",
    dst_ip="195.136.19.76",
    dst_port=0,
    protocol="udp",
    display_name="",
    first_seen="2026-09-01T12:00:00Z",
):
    return {
        "rule_id": rule_id,
        "rule_name": vector,
        "vector": vector,
        "display_name": display_name,
        "specificity_score": specificity_score,
        "specificity_components": {},
        "severity": severity,
        "threshold_warning": warning,
        "threshold_critical": critical,
        "zone_id": 1,
        "template_id": 1,
        "prefix_id": 1,
        "prefix_cidr": "45.5.248.0/24",
        "src_ip": src_ip,
        "internal_ip": src_ip,
        "dst_ip": dst_ip,
        "top_dst_ip": dst_ip,
        "top_dst_port": dst_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "rule_config": {"window_seconds": 60},
        "first_seen": first_seen,
        "last_seen": first_seen,
    }


def full_candidate(vector, rule_id, display_name, dst_port, warning, critical, profile_id=None, mitigation_mode="detection_only"):
    observed_at = "2026-09-01T12:00:00Z"
    return {
        "matched": True,
        "zone_id": 7,
        "zone_name": "Clientes",
        "template_id": 8,
        "template_name": "CLIENTES-PUBLICOS-DEFAULT",
        "sensor_id": None,
        "rule_id": rule_id,
        "rule_name": vector,
        "display_name": display_name,
        "rule_config": {
            "dst_port": "53" if dst_port == 53 else "any",
            "group_by": "src_ip,dst_ip,dst_port,proto",
            "window_seconds": 60,
            "consecutive_windows": 1,
            "direction": "transmits",
            "protocol": "DNS" if "DNS" in vector else "UDP",
        },
        "prefix_id": 11,
        "prefix_cidr": "45.5.248.0/24",
        "domain": "internal_ip",
        "direction": "transmits",
        "vector": vector,
        "severity": "warning",
        "src_ip": "45.5.248.196",
        "dst_ip": "195.136.19.76",
        "internal_ip": "45.5.248.196",
        "target_ip": "45.5.248.196",
        "target_cidr": "45.5.248.196/32",
        "target_role": "src_ip",
        "scope_type": "internal_ip_32",
        "invalid_scope": False,
        "protocol": "udp",
        "src_port": None,
        "target_port": dst_port,
        "top_src_ip": "45.5.248.196",
        "top_src_port": 2811,
        "top_dst_ip": "195.136.19.76",
        "top_dst_port": dst_port,
        "dst_port": dst_port,
        "top_packets": 3537000,
        "top_bytes": 282960000,
        "mitigation_basis": "dns_outbound_destination" if "DNS" in vector else "dst_ip,dst_port,protocol",
        "mitigation_reason": "Possivel abuso DNS outbound." if "DNS" in vector else "",
        "packets_s": 58950.0,
        "bits_s": 7000000.0,
        "flows": 3,
        "flows_s": 0.05,
        "packets": 3537000,
        "bytes": 282960000,
        "unique_dst_ips": 1,
        "unique_dst_ports": 1,
        "unique_src_ports": 1,
        "first_seen": observed_at,
        "last_seen": observed_at,
        "threshold_warning": warning,
        "threshold_critical": critical,
        "automatic_mitigation_threshold": critical if critical is not None else warning,
        "warning_response_profile_id": profile_id,
        "critical_response_profile_id": profile_id,
        "fallback_response_profile_id": profile_id,
        "mitigation_mode": mitigation_mode,
        "mitigation_enabled": mitigation_mode == "response_profile",
        "metric": "packets_s",
        "comparison": "over",
        "metric_value": 58950.0,
        "response": "RESPONSE_PROFILE" if mitigation_mode == "response_profile" else "DETECTION_ONLY",
    }


class DetectionSpecificityUnitTest(unittest.TestCase):
    def test_specificity_scores_rank_dns_above_generic_udp(self):
        dns = main.detection_rule_specificity(
            rule_spec(protocol="DNS", dst_port="53", direction="transmits", domain="internal_ip", group_by="src_ip,dst_ip,dst_port,proto")
        )
        udp = main.detection_rule_specificity(
            rule_spec(protocol="UDP", dst_port="any", direction="transmits", domain="internal_ip")
        )
        self.assertGreater(dns["score"], udp["score"])
        self.assertEqual(100, dns["components"]["fixed_port"]["score"])
        self.assertEqual(60, dns["components"]["protocol"]["score"])
        self.assertEqual("application", dns["components"]["protocol"]["kind"])
        self.assertEqual(40, udp["components"]["protocol"]["score"])
        self.assertEqual("transport", udp["components"]["protocol"]["kind"])

    def test_protocol_alias_dns_specializes_udp(self):
        self.assertTrue(main.detection_protocol_specializes("DNS", "UDP"))
        self.assertTrue(main.detection_protocol_specializes("DNS", "ALL"))
        self.assertTrue(main.detection_protocol_specializes("UDP", "UDP"))
        self.assertFalse(main.detection_protocol_specializes("UDP", "DNS"))
        self.assertFalse(main.detection_protocol_specializes("ALL", "DNS"))

    def test_selection_prefers_dns_when_udp53_and_udp_generic_both_match(self):
        dns = candidate(rule_id=2, vector="DNS_INTERNAL_IP_TO_DST_HIGH_PPS", specificity_score=250, warning=5000, dst_port=53, display_name="DNS alto por destino")
        udp = candidate(rule_id=1, vector="PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", specificity_score=110, warning=50000, dst_port=53, display_name="UDP alto por destino")
        selection = main.select_most_specific_detection_candidate([udp, dns])
        self.assertEqual("DNS_INTERNAL_IP_TO_DST_HIGH_PPS", selection["selected"]["vector"])
        self.assertEqual(["PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS"], [item["vector"] for item in selection["suppressed"]])
        self.assertEqual(2, len(selection["matched_rules"]))
        self.assertEqual(1, len(selection["suppressed_rules"]))
        self.assertIn("suppressed", selection["selection_reason"])

    def test_selection_uses_udp_generic_when_port_is_not_dns(self):
        udp = candidate(rule_id=1, vector="PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", specificity_score=110, warning=50000, dst_port=9044)
        selection = main.select_most_specific_detection_candidate([udp])
        self.assertEqual("PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", selection["selected"]["vector"])
        self.assertEqual([], selection["suppressed"])
        self.assertEqual("only_matching_rule", selection["selection_reason"])

    def test_selection_falls_back_to_generic_when_specific_does_not_match(self):
        # Only the generic matched; the specific rule is absent from the group.
        udp = candidate(rule_id=1, vector="PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", specificity_score=110, warning=50000, dst_port=53)
        selection = main.select_most_specific_detection_candidate([udp])
        self.assertEqual("PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", selection["selected"]["vector"])

    def test_tie_break_uses_lower_threshold_then_lower_rule_id(self):
        left = candidate(rule_id=10, vector="A", specificity_score=200, warning=5000)
        right = candidate(rule_id=5, vector="B", specificity_score=200, warning=9000)
        selection = main.select_most_specific_detection_candidate([right, left])
        self.assertEqual("A", selection["selected"]["vector"])

        equal_a = candidate(rule_id=7, vector="A", specificity_score=200, warning=5000)
        equal_b = candidate(rule_id=3, vector="B", specificity_score=200, warning=5000)
        selection = main.select_most_specific_detection_candidate([equal_a, equal_b])
        self.assertEqual("B", selection["selected"]["vector"])


class DetectionSpecificityDbTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "gmjflow.db")
        self.environment = mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": self.db_path}, clear=False)
        self.ready = mock.patch.object(main, "SENSOR_DB_READY", False)
        self.password = mock.patch.object(main, "hash_password", return_value="test-hash")
        self.environment.start()
        self.ready.start()
        self.password.start()
        main.ensure_sensor_db()

    def tearDown(self):
        self.password.stop()
        self.ready.stop()
        self.environment.stop()
        self.tmpdir.cleanup()

    def _seed_template(self, dns_warning=5000, udp_warning=50000):
        now = "2026-09-01T12:00:00Z"
        with main.sqlite_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO detection_templates (name, description, active, created_at, updated_at) VALUES ('SPEC', '', 1, ?, ?)",
                (now, now),
            )
            template_id = int(cursor.lastrowid)
            zone_id = int(conn.execute(
                "INSERT INTO ip_zones (name, description, active, detection_template_id, created_at, updated_at) VALUES ('Clientes', '', 1, ?, ?, ?)",
                (template_id, now, now),
            ).lastrowid)
            prefix_id = int(conn.execute(
                "INSERT INTO ip_zone_prefixes (zone_id, cidr, name, description, prefix_type, active, created_at, updated_at) VALUES (?, '45.5.248.0/24', '', '', 'client', 1, ?, ?)",
                (zone_id, now, now),
            ).lastrowid)

            def insert_rule(vector, display_name, protocol, dst_port, warning, critical, mitigation_mode, profile_id=None):
                mitigation_enabled = 1 if mitigation_mode == "response_profile" else 0
                cursor = conn.execute(
                    """
                    INSERT INTO detection_template_rules (
                        template_id, vector, display_name, domain, direction, protocol, metric, comparison,
                        warning_value, critical_value, window_seconds, consecutive_windows, cooldown_minutes,
                        cooldown_seconds, enabled, response, dst_port, src_port, detection_key, group_by,
                        mitigation_mode, mitigation_enabled, use_global_whitelist, bypass_whitelist,
                        warning_response_profile_id, critical_response_profile_id, fallback_response_profile_id,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, 'internal_ip', 'transmits', ?, 'packets_s', 'over', ?, ?, 60, 1, 0, 0,
                              1, 'DETECTION_ONLY', ?, 'any', '', 'src_ip,dst_ip,dst_port,proto', ?, ?, 0, 1,
                              ?, ?, ?, ?, ?)
                    """,
                    (
                        template_id, vector, display_name, protocol, warning, critical,
                        dst_port, mitigation_mode, mitigation_enabled,
                        profile_id, profile_id, profile_id, now, now,
                    ),
                )
                return int(cursor.lastrowid)

            dns_rule_id = insert_rule(
                "DNS_INTERNAL_IP_TO_DST_HIGH_PPS", "DNS alto por destino", "DNS", "53",
                dns_warning, max(dns_warning, 15000), "response_profile", profile_id=42,
            )
            udp_rule_id = insert_rule(
                "PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", "UDP alto por destino", "UDP", "any",
                udp_warning, max(udp_warning, 120000), "detection_only",
            )
            conn.commit()
        return template_id, zone_id, prefix_id, dns_rule_id, udp_rule_id

    def _rule_rows(self, template_id):
        with main.sqlite_connection() as conn:
            rows = conn.execute(
                """
                SELECT r.*, t.name AS template_name, t.active AS template_active
                FROM detection_template_rules r
                JOIN detection_templates t ON t.id = r.template_id
                WHERE r.template_id = ?
                ORDER BY r.id
                """,
                (template_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def _run_with(self, template_id, end_dt, fake_candidates):
        def fake_query(zone, template, rule, prefix, start_dt, end_dt, sensor_id, limit=1000, include_unmatched=False):
            return fake_candidates(rule)

        rows = self._rule_rows(template_id)
        with main.sqlite_connection() as conn:
            with mock.patch.object(main, "query_detection_rule_candidates", side_effect=fake_query):
                results, anomalies_created = main.run_detection_template_rules_with_specificity(
                    conn, rows, end_dt, create_anomalies=True
                )
            conn.commit()
        return results, anomalies_created

    def test_same_target_window_creates_only_dns_anomaly(self):
        template_id, zone_id, prefix_id, dns_rule_id, udp_rule_id = self._seed_template()
        end_dt = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        dns = full_candidate("DNS_INTERNAL_IP_TO_DST_HIGH_PPS", dns_rule_id, "DNS alto por destino", 53, 5000, 15000, profile_id=42, mitigation_mode="response_profile")
        udp = full_candidate("PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", udp_rule_id, "UDP alto por destino", 53, 50000, 120000)

        def fake_candidates(rule):
            if rule.get("vector") == "DNS_INTERNAL_IP_TO_DST_HIGH_PPS":
                return [dict(dns)]
            return [dict(udp)]

        results, created = self._run_with(template_id, end_dt, fake_candidates)

        with main.sqlite_connection() as conn:
            events = conn.execute("SELECT * FROM anomaly_events").fetchall()
            security = conn.execute("SELECT * FROM security_anomalies").fetchall()
        self.assertEqual(1, len(events))
        self.assertEqual(0, len(security))
        self.assertEqual("DNS_INTERNAL_IP_TO_DST_HIGH_PPS", events[0]["vector_name"])
        self.assertEqual("DNS alto por destino", events[0]["source_name"])
        self.assertEqual(1, created)
        # The generic rule must be reported as suppressed.
        suppressed = [result for result in results if result["rule_name"] == "PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS"]
        self.assertTrue(suppressed)
        self.assertTrue(suppressed[0]["skipped_reason"].startswith("suppressed_by_specific_rule"))

    def test_selection_metadata_is_recorded_in_details(self):
        template_id, zone_id, prefix_id, dns_rule_id, udp_rule_id = self._seed_template()
        end_dt = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        dns = full_candidate("DNS_INTERNAL_IP_TO_DST_HIGH_PPS", dns_rule_id, "DNS alto por destino", 53, 5000, 15000, profile_id=42, mitigation_mode="response_profile")
        udp = full_candidate("PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", udp_rule_id, "UDP alto por destino", 53, 50000, 120000)

        def fake_candidates(rule):
            return [dict(dns)] if rule.get("vector") == "DNS_INTERNAL_IP_TO_DST_HIGH_PPS" else [dict(udp)]

        self._run_with(template_id, end_dt, fake_candidates)

        with main.sqlite_connection() as conn:
            row = conn.execute("SELECT source_details_json FROM anomaly_events ORDER BY id DESC LIMIT 1").fetchone()
        details = main.bgp_json_loads(row["source_details_json"], {})
        selection = details.get("selection") or {}
        self.assertEqual("DNS_INTERNAL_IP_TO_DST_HIGH_PPS", (selection.get("selected_rule") or {}).get("vector"))
        self.assertEqual(["PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS"], [item.get("vector") for item in selection.get("suppressed_rules") or []])
        self.assertEqual(2, len(selection.get("matched_rules") or []))
        self.assertIn("specificity_score", selection)
        self.assertIn("selection_reason", selection)

    def test_generic_fires_alone_when_specific_below_threshold(self):
        # DNS threshold above observed value; only UDP generic matches.
        template_id, zone_id, prefix_id, dns_rule_id, udp_rule_id = self._seed_template(dns_warning=100000, udp_warning=5000)
        end_dt = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        dns = full_candidate("DNS_INTERNAL_IP_TO_DST_HIGH_PPS", dns_rule_id, "DNS alto por destino", 53, 100000, 150000, profile_id=42, mitigation_mode="response_profile")
        dns["matched"] = False
        udp = full_candidate("PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", udp_rule_id, "UDP alto por destino", 53, 5000, 120000)

        def fake_candidates(rule):
            return [dict(dns)] if rule.get("vector") == "DNS_INTERNAL_IP_TO_DST_HIGH_PPS" else [dict(udp)]

        results, created = self._run_with(template_id, end_dt, fake_candidates)

        with main.sqlite_connection() as conn:
            events = conn.execute("SELECT * FROM anomaly_events").fetchall()
            security = conn.execute("SELECT * FROM security_anomalies").fetchall()
        self.assertEqual(0, len(events))
        self.assertEqual(1, len(security))
        self.assertEqual("PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", security[0]["vector"])
        self.assertEqual(1, created)

    def test_existing_generic_is_promoted_when_dns_evidence_appears(self):
        template_id, zone_id, prefix_id, dns_rule_id, udp_rule_id = self._seed_template()
        end_dt = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        udp = full_candidate("PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", udp_rule_id, "UDP alto por destino", 53, 50000, 120000)
        dns = full_candidate("DNS_INTERNAL_IP_TO_DST_HIGH_PPS", dns_rule_id, "DNS alto por destino", 53, 5000, 15000, profile_id=42, mitigation_mode="response_profile")

        # Simulate a previous run where only the generic matched. Age the row so
        # the rule cooldown does not suppress re-evaluation in this run.
        with main.sqlite_connection() as conn:
            self.assertEqual("created", main.upsert_security_anomaly(conn, udp))
            conn.execute(
                "UPDATE security_anomalies SET updated_at = '2026-08-01T00:00:00Z' WHERE vector = 'PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS'"
            )
            generic = conn.execute(
                "SELECT * FROM security_anomalies WHERE vector = 'PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS'"
            ).fetchone()
            conn.commit()
        self.assertEqual("active", generic["status"])

        def fake_candidates(rule):
            return [dict(dns)] if rule.get("vector") == "DNS_INTERNAL_IP_TO_DST_HIGH_PPS" else [dict(udp)]

        self._run_with(template_id, end_dt, fake_candidates)

        with main.sqlite_connection() as conn:
            generic_after = conn.execute(
                "SELECT * FROM security_anomalies WHERE vector = 'PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS'"
            ).fetchone()
            events = conn.execute("SELECT * FROM anomaly_events").fetchall()
        self.assertEqual("ended", generic_after["status"])
        details = main.bgp_json_loads(generic_after["source_details_json"], {})
        self.assertEqual("DNS_INTERNAL_IP_TO_DST_HIGH_PPS", (details.get("reclassified_to") or {}).get("vector"))
        self.assertTrue(details.get("reclassification_history"))
        self.assertEqual(1, len(events))
        self.assertEqual("DNS_INTERNAL_IP_TO_DST_HIGH_PPS", events[0]["vector_name"])

    def test_mitigation_uses_selected_rule_response_profile(self):
        template_id, zone_id, prefix_id, dns_rule_id, udp_rule_id = self._seed_template()
        end_dt = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        dns = full_candidate("DNS_INTERNAL_IP_TO_DST_HIGH_PPS", dns_rule_id, "DNS alto por destino", 53, 5000, 15000, profile_id=42, mitigation_mode="response_profile")
        udp = full_candidate("PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", udp_rule_id, "UDP alto por destino", 53, 50000, 120000)

        def fake_candidates(rule):
            return [dict(dns)] if rule.get("vector") == "DNS_INTERNAL_IP_TO_DST_HIGH_PPS" else [dict(udp)]

        self._run_with(template_id, end_dt, fake_candidates)

        with main.sqlite_connection() as conn:
            event = conn.execute("SELECT response_profile_id FROM anomaly_events ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(42, event["response_profile_id"])
