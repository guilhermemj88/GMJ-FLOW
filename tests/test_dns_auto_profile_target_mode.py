import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_collector_apply_static import backend_main as main


ROOT = Path(__file__).resolve().parents[1]


def _now():
    return main.utc_now_iso()


class DnsAutoProfileSeedTest(unittest.TestCase):
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

    def _profile(self, conn):
        return conn.execute(
            "SELECT * FROM bgp_response_profiles WHERE name = 'FLOWSPEC_AUTO_BLOCK_DST_DNS'"
        ).fetchone()

    def test_A_fresh_db_profile_is_sensor_origin_with_null_connector_and_hour_ttl(self):
        with main.sqlite_connection() as conn:
            profile = self._profile(conn)
        self.assertIsNotNone(profile)
        self.assertEqual(profile["mitigation_target_mode"], "sensor_origin")
        self.assertIsNone(profile["connector_id"])
        self.assertEqual(profile["default_duration_seconds"], 3600)
        self.assertEqual(profile["max_duration_seconds"], 3600)
        self.assertEqual(profile["initial_lease_seconds"], 3600)
        self.assertEqual(profile["recurrence_lease_seconds"], 86400)
        self.assertEqual(profile["recurrence_renewal_enabled"], 1)

    def test_B_legacy_fixed_connector_null_connector_migrates_to_sensor_origin(self):
        with main.sqlite_connection() as conn:
            conn.execute(
                """
                UPDATE bgp_response_profiles
                SET mitigation_target_mode = 'fixed_connector',
                    connector_id = NULL,
                    default_duration_seconds = 3600,
                    max_duration_seconds = 3600,
                    initial_lease_seconds = NULL,
                    recurrence_lease_seconds = NULL,
                    recurrence_renewal_enabled = 0
                WHERE name = 'FLOWSPEC_AUTO_BLOCK_DST_DNS'
                """
            )
            main.migrate_dns_auto_block_profile(conn)
            conn.commit()
            profile = self._profile(conn)
        self.assertEqual(profile["mitigation_target_mode"], "sensor_origin")
        self.assertIsNone(profile["connector_id"])
        self.assertEqual(profile["default_duration_seconds"], 3600)
        self.assertEqual(profile["initial_lease_seconds"], 3600)
        self.assertEqual(profile["recurrence_lease_seconds"], 86400)
        self.assertEqual(profile["recurrence_renewal_enabled"], 1)

    def test_C_explicit_connector_profile_is_not_modified(self):
        with main.sqlite_connection() as conn:
            conn.execute(
                """
                INSERT INTO bgp_connectors (name, role, backend_type, mode, enabled, is_active, created_at, updated_at)
                VALUES ('BGP-VNT-BORDA', 'flowspec_mitigation', 'exabgp', 'manual_approval', 1, 1, ?, ?)
                """,
                (_now(), _now()),
            )
            connector_id = conn.execute("SELECT id FROM bgp_connectors ORDER BY id DESC LIMIT 1").fetchone()["id"]
            conn.execute(
                """
                UPDATE bgp_response_profiles
                SET mitigation_target_mode = 'fixed_connector',
                    connector_id = ?,
                    default_duration_seconds = 3600,
                    initial_lease_seconds = 3600,
                    recurrence_lease_seconds = 86400,
                    recurrence_renewal_enabled = 1
                WHERE name = 'FLOWSPEC_AUTO_BLOCK_DST_DNS'
                """,
                (connector_id,),
            )
            main.migrate_dns_auto_block_profile(conn)
            conn.commit()
            profile = self._profile(conn)
        self.assertEqual(profile["mitigation_target_mode"], "fixed_connector")
        self.assertEqual(profile["connector_id"], connector_id)


class DnsAutoProfileResolutionTest(unittest.TestCase):
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

    def _insert_sensor(self, conn, sensor_id, name):
        conn.execute(
            "INSERT INTO sensors (id, name, exporter_ip, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (sensor_id, name, f"192.0.2.{sensor_id}", _now(), _now()),
        )

    def _insert_connector(self, conn, name, sensor_id):
        return int(conn.execute(
            """
            INSERT INTO bgp_connectors (
                name, role, backend_type, mode, enabled, is_active, sensor_id,
                exabgp_pipe_in, created_at, updated_at
            )
            VALUES (?, 'flowspec_mitigation', 'exabgp', 'manual_approval', 1, 1, ?,
                    '/run/exabgp/exabgp.in', ?, ?)
            """,
            (name, sensor_id, _now(), _now()),
        ).lastrowid)

    def _profile(self, conn):
        return main.fetch_bgp_profile(
            conn,
            int(conn.execute(
                "SELECT id FROM bgp_response_profiles WHERE name = 'FLOWSPEC_AUTO_BLOCK_DST_DNS'"
            ).fetchone()["id"]),
        )

    def _resolve(self, sensor_id):
        with main.sqlite_connection() as conn:
            profile = self._profile(conn)
            candidate = {
                "sensor_id": sensor_id,
                "raw_payload": {"anomaly": {"sensor_id": sensor_id}},
            }
            resolved = main.resolve_mitigation_target_connectors(conn, candidate, profile)
        return resolved, candidate

    def test_D_fibinet_sensor_resolves_fibinet_connector(self):
        with main.sqlite_connection() as conn:
            self._insert_sensor(conn, 1, "Fibinet")
            self._insert_connector(conn, "BGP-FIBINET-BORDA", 1)
            conn.commit()
        resolved, candidate = self._resolve(1)
        self.assertEqual([item["name"] for item in resolved], ["BGP-FIBINET-BORDA"])
        self.assertEqual(candidate["connector_resolution_method"], "sensor")

    def test_E_gm_sensor_resolves_gm_connector(self):
        with main.sqlite_connection() as conn:
            self._insert_sensor(conn, 4, "GM")
            self._insert_connector(conn, "BGP-GM-BORDA", 4)
            conn.commit()
        resolved, candidate = self._resolve(4)
        self.assertEqual([item["name"] for item in resolved], ["BGP-GM-BORDA"])
        self.assertEqual(candidate["connector_resolution_method"], "sensor")

    def test_F_implantar_sensor_resolves_implantar_connector(self):
        with main.sqlite_connection() as conn:
            self._insert_sensor(conn, 7, "IMPLANTAR")
            self._insert_connector(conn, "BGP-IMPLANTAR-BORDA", 7)
            conn.commit()
        resolved, candidate = self._resolve(7)
        self.assertEqual([item["name"] for item in resolved], ["BGP-IMPLANTAR-BORDA"])
        self.assertEqual(candidate["connector_resolution_method"], "sensor")

    def test_G_sensor_without_connector_falls_back_controlled(self):
        with main.sqlite_connection() as conn:
            self._insert_sensor(conn, 99, "sem-connector")
            conn.commit()
        resolved, candidate = self._resolve(99)
        self.assertEqual(resolved, [])
        self.assertEqual(candidate["connector_resolution_error"], "no_active_flowspec_connectors")

    def test_H_two_connectors_same_sensor_is_ambiguous(self):
        with main.sqlite_connection() as conn:
            self._insert_sensor(conn, 1, "Fibinet")
            self._insert_connector(conn, "BGP-FIBINET-BORDA", 1)
            self._insert_connector(conn, "BGP-FIBINET-BORDA-2", 1)
            conn.commit()
        resolved, candidate = self._resolve(1)
        self.assertEqual(len(resolved), 2)
        self.assertEqual(candidate["connector_resolution_error"], "ambiguous_connector_resolution")


class DnsAutoProfileEvaluatedTest(unittest.TestCase):
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

    def _seed_context(self, with_connector):
        now = _now()
        with main.sqlite_connection() as conn:
            profile_id = int(conn.execute(
                "SELECT id FROM bgp_response_profiles WHERE name = 'FLOWSPEC_AUTO_BLOCK_DST_DNS'"
            ).fetchone()["id"])
            conn.execute(
                "INSERT INTO sensors (id, name, exporter_ip, created_at, updated_at) VALUES (9, 'Fibinet', '192.0.2.9', ?, ?)",
                (now, now),
            )
            if with_connector:
                conn.execute(
                    """
                    INSERT INTO bgp_connectors (
                        name, role, backend_type, mode, enabled, is_active, sensor_id,
                        exabgp_pipe_in, created_at, updated_at
                    )
                    VALUES ('BGP-FIBINET-BORDA', 'flowspec_mitigation', 'exabgp', 'manual_approval', 1, 1, 9,
                            '/run/exabgp/exabgp.in', ?, ?)
                    """,
                    (now, now),
                )
            conn.execute(
                "INSERT INTO bgp_protected_prefixes (cidr, name, enabled, block_rtbh, block_flowspec, created_at, updated_at) "
                "VALUES ('45.5.248.0/24', 'Fibinet clientes', 1, 1, 1, ?, ?)",
                (now, now),
            )
            conn.execute(
                "INSERT INTO ip_zones (id, name, connector_id, subscriber_addressing_mode, active, created_at, updated_at) "
                "VALUES (1, 'Clientes', NULL, 'direct_public', 1, ?, ?)",
                (now, now),
            )
            conn.execute(
                "INSERT INTO ip_zone_prefixes (zone_id, cidr, name, active, created_at, updated_at) VALUES (1, '45.5.248.0/24', 'Fibinet clientes', 1, ?, ?)",
                (now, now),
            )
            template_id = conn.execute(
                "INSERT INTO detection_templates (name, description, active, created_at, updated_at) VALUES ('DNS', '', 1, ?, ?)",
                (now, now),
            ).lastrowid
            conn.execute(
                """
                INSERT INTO detection_template_rules (
                    template_id, vector, display_name, domain, direction, protocol, metric, comparison,
                    warning_value, critical_value, window_seconds, consecutive_windows, cooldown_minutes,
                    enabled, response, critical_response_profile_id, mitigation_mode, mitigation_enabled,
                    created_at, updated_at
                )
                VALUES (?, 'DNS_QUERY_OUTBOUND_CLIENT', 'DNS outbound por cliente', 'internal_ip',
                        'transmits', 'DNS', 'packets_s', 'over', 5000, 15000, 60, 1, 5,
                        1, 'DETECTION_ONLY', ?, 'response_profile', 1, ?, ?)
                """,
                (template_id, profile_id, now, now),
            )
            event_id = int(conn.execute(
                """
                INSERT INTO anomaly_events (
                    id, sensor_id, target_ip, target_cidr, target_role, zone_id, zone_name,
                    vector_name, scope_type, direction, decoder, severity, metric_unit,
                    threshold_value, observed_value, peak_value, started_at, last_seen_at,
                    estimated_bytes, estimated_packets, flow_count, summary, dedupe_key,
                    created_at, updated_at, top_src_ip, top_dst_ip, top_src_port, top_dst_port,
                    top_packets, top_bytes, protocol
                )
                VALUES (140, 9, '45.5.248.205', '45.5.248.205/32', 'src_ip', 1, 'Clientes',
                        'DNS_QUERY_OUTBOUND_CLIENT', 'internal_ip_32', 'transmits', 'DNS', 'critical',
                        'packets_s', 10000, 13000, 13000, ?, ?, 1000000, 13000, 1,
                        'DNS outbound alto', 'dns-query-140', ?, ?, '45.5.248.205', '103.100.169.200',
                        62129, 53, 13000, 1000000, 'udp')
                """,
                (now, now, now, now),
            ).lastrowid)
            conn.execute(
                """
                INSERT INTO anomaly_event_flows (
                    anomaly_event_id, flow_time, sensor, exporter_ip, src_ip, dst_ip,
                    src_port, dst_port, proto, bytes, packets, flow_count
                )
                VALUES (?, ?, 'sensor-9', '192.0.2.9', '45.5.248.205', '103.100.169.200', 62129, 53, 17, 1000000, 13000, 1)
                """,
                (event_id, now),
            )
            conn.commit()
        return event_id

    def test_I_auto_allowed_only_when_connector_resolved(self):
        event_id = self._seed_context(with_connector=True)
        evaluated = main.evaluated_mitigation_candidates(event_id)
        self.assertTrue(evaluated["candidates"])
        resolved = evaluated["candidates"][0]
        self.assertTrue(resolved["allow_auto"])
        self.assertFalse(resolved["requires_connector_selection"])
        self.assertEqual(resolved["connector_resolution_mode"], "sensor_origin")
        self.assertEqual(resolved["resolved_connector_name"], "BGP-FIBINET-BORDA")
        self.assertEqual(resolved["resolution_reason"], "anomaly_sensor_connector")

    def test_I_unresolved_connector_not_auto_allowed(self):
        event_id = self._seed_context(with_connector=False)
        evaluated = main.evaluated_mitigation_candidates(event_id)
        unresolved = evaluated["candidates"][0]
        self.assertFalse(unresolved["allow_auto"])
        self.assertFalse(unresolved["auto_allowed"])
        self.assertIn("connector", (unresolved.get("resolution_error") or ""))

    def test_J_proposal_uses_resolved_connector_without_manual_selection(self):
        event_id = self._seed_context(with_connector=True)
        evaluated = main.evaluated_mitigation_candidates(event_id)
        candidate = evaluated["candidates"][0]
        self.assertFalse(candidate["requires_connector_selection"])
        self.assertIsNotNone(candidate["selected_connector_id"])
        self.assertEqual(candidate["resolved_connector_id"], candidate["selected_connector_id"])
        self.assertIn("sensor_origin", candidate["connector_resolution_mode"])
        self.assertEqual(candidate["connector_name"], "BGP-FIBINET-BORDA")
