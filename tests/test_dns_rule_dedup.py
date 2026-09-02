import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_collector_apply_static import backend_main as main


ROOT = Path(__file__).resolve().parents[1]


class DnsRuleDedupTest(unittest.TestCase):
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

    def _rules(self, conn):
        return conn.execute(
            "SELECT * FROM detection_template_rules WHERE lower(vector) = 'dns_internal_ip_to_dst_high_pps' ORDER BY id"
        ).fetchall()

    def test_1_fresh_db_has_single_active_rule(self):
        with main.sqlite_connection() as conn:
            rows = self._rules(conn)
        self.assertEqual(len(rows), 1)
        self.assertTrue(main.sqlite_bool(rows[0]["enabled"]))

    def test_2_rule_has_official_response_profiles(self):
        with main.sqlite_connection() as conn:
            row = self._rules(conn)[0]
            profile = conn.execute(
                "SELECT id, name FROM bgp_response_profiles WHERE name = 'FLOWSPEC_AUTO_BLOCK_DST_DNS'"
            ).fetchone()
        self.assertEqual(row["critical_response_profile_id"], profile["id"])
        self.assertEqual(row["warning_response_profile_id"], profile["id"])
        self.assertEqual(row["fallback_response_profile_id"], profile["id"])
        self.assertEqual(row["mitigation_mode"], "response_profile")
        self.assertEqual(row["mitigation_enabled"], 1)
        self.assertEqual(row["dst_port"], "53")

    def test_3_ensure_is_idempotent(self):
        with mock.patch.object(main, "hash_password", return_value="test-hash"):
            main.SENSOR_DB_READY = False
            main.ensure_sensor_db()
            main.SENSOR_DB_READY = False
            main.ensure_sensor_db()
        with main.sqlite_connection() as conn:
            rows = self._rules(conn)
        self.assertEqual(len(rows), 1)

    def test_4_legacy_duplicate_is_superseded_not_deleted(self):
        now = main.utc_now_iso()
        with main.sqlite_connection() as conn:
            canonical = self._rules(conn)[0]
            template_id = int(canonical["template_id"])
            conn.execute(
                """
                INSERT INTO detection_template_rules (
                    template_id, vector, display_name, domain, direction, protocol, metric, comparison,
                    warning_value, critical_value, window_seconds, consecutive_windows, cooldown_minutes,
                    enabled, response, dst_port, created_at, updated_at
                )
                VALUES (?, 'DNS_INTERNAL_IP_TO_DST_HIGH_PPS', 'DNS alto por destino', 'internal_ip',
                        'transmits', 'DNS', 'packets_s', 'over', 5000, 15000, 60, 1, 5,
                        1, 'DETECTION_ONLY', 'any', ?, ?)
                """,
                (template_id, now, now),
            )
            conn.commit()
            duplicate_id = int(conn.execute(
                "SELECT id FROM detection_template_rules WHERE lower(vector)='dns_internal_ip_to_dst_high_pps' ORDER BY id DESC LIMIT 1"
            ).fetchone()["id"])
            main.deduplicate_dns_internal_ip_to_dst_rules(conn)
            conn.commit()
            rows = self._rules(conn)

        self.assertEqual(len(rows), 2, "A duplicata não deve ser deletada, apenas desabilitada")
        by_id = {int(row["id"]): row for row in rows}
        canonical_after = by_id[int(canonical["id"])]
        duplicate_after = by_id[duplicate_id]
        self.assertTrue(main.sqlite_bool(canonical_after["enabled"]))
        self.assertFalse(main.sqlite_bool(duplicate_after["enabled"]))
        self.assertEqual(duplicate_after["notes"], f"superseded_by_rule_id={int(canonical['id'])}")

    def test_5_detection_loop_sees_single_enabled_rule(self):
        with main.sqlite_connection() as conn:
            rows = main.detection_template_rule_rows(conn)
        matches = [
            row for row in rows
            if clean_upper(row.get("vector")) == "DNS_INTERNAL_IP_TO_DST_HIGH_PPS"
        ]
        self.assertEqual(len(matches), 1)
        self.assertTrue(main.sqlite_bool(matches[0].get("enabled")))

    def test_6_mitigation_profile_resolves_to_dns_auto_block(self):
        with main.sqlite_connection() as conn:
            row = self._rules(conn)[0]
            profile = main.fetch_bgp_profile(conn, int(row["critical_response_profile_id"]))
        self.assertEqual(profile["name"], "FLOWSPEC_AUTO_BLOCK_DST_DNS")
        self.assertEqual(profile["mitigation_target_mode"], "sensor_origin")

    def test_8_no_real_flowspec_announced(self):
        # Guardrail: a migração/deduplicação nunca pode tocar o pipe ExaBGP real.
        with mock.patch.object(main, "exabgp_write_pipe", side_effect=AssertionError("FIFO real nao pode ser escrito")) as pipe:
            with main.sqlite_connection() as conn:
                main.deduplicate_dns_internal_ip_to_dst_rules(conn)
                conn.commit()
        pipe.assert_not_called()


def clean_upper(value):
    return (value or "").strip().upper()


class DnsSpecificityRegressionTest(unittest.TestCase):
    def test_dns_rule_specificity_beats_generic_udp(self):
        dns = main.detection_rule_specificity(
            {
                "protocol": "DNS",
                "dst_port": "53",
                "src_port": "any",
                "direction": "transmits",
                "domain": "internal_ip",
                "group_by": "src_ip,dst_ip,dst_port,proto",
            }
        )
        udp = main.detection_rule_specificity(
            {
                "protocol": "UDP",
                "dst_port": "any",
                "src_port": "any",
                "direction": "transmits",
                "domain": "internal_ip",
            }
        )
        self.assertGreater(dns["score"], udp["score"])
