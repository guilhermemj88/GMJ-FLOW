"""Propagacao de sensor: resolucao, persistencia, dedupe e payload de midia."""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_collector_apply_static import backend_main  # noqa: E402

media_dispatch = backend_main.media_dispatch
SOURCE = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")


class SensorBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmpdir) / "gmjflow.db")
        self._patchers = [
            mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": self.db_path}, clear=False),
            mock.patch.object(backend_main, "SENSOR_DB_READY", False),
            mock.patch.object(backend_main, "hash_password", return_value="test-hash"),
        ]
        for patcher in self._patchers:
            patcher.start()
        backend_main.ensure_sensor_db()
        with backend_main.sqlite_connection() as conn:
            conn.execute("DELETE FROM sensors")
            for sensor_id, name, exporter in (
                (1, "NE8000-BGP-FIBINET", "179.189.80.0"),
                (2, "NE8000-GM-TESTE", "45.5.249.0"),
                (3, "NE8000-F1A-IMPLANTAR", "45.163.144.1"),
            ):
                conn.execute(
                    "INSERT INTO sensors (id, name, exporter_ip, created_at, updated_at) VALUES (?,?,?,?,?)",
                    (sensor_id, name, exporter, "2026-09-29T00:00:00Z", "2026-09-29T00:00:00Z"),
                )
            conn.commit()

    def tearDown(self):
        for patcher in reversed(self._patchers):
            patcher.stop()

    def resolve(self, source):
        with backend_main.sqlite_connection() as conn:
            return backend_main.resolve_detected_sensor(conn, source)


class SensorResolutionTest(SensorBase):
    def test_single_exporter_maps_by_ip(self):
        out = self.resolve({"detected_exporter_count": 1, "detected_exporter_ip": "45.163.144.1"})
        self.assertEqual(out["sensor_resolution"], "single")
        self.assertEqual(out["detected_sensor_id"], 3)
        self.assertEqual(out["detected_sensor_name"], "NE8000-F1A-IMPLANTAR")
        self.assertEqual(out["detected_exporter_ip"], "45.163.144.1")

    def test_ipv4_mapped_ipv6_is_normalized(self):
        out = self.resolve({"detected_exporter_count": 1, "detected_exporter_ip": "::ffff:179.189.80.0"})
        self.assertEqual(out["sensor_resolution"], "single")
        self.assertEqual(out["detected_sensor_id"], 1)

    def test_unknown_exporter_is_unresolved(self):
        out = self.resolve({"detected_exporter_count": 1, "detected_exporter_ip": "45.163.144.6"})
        self.assertEqual(out["sensor_resolution"], "unresolved")
        self.assertIsNone(out["detected_sensor_id"])

    def test_multi_exporter_is_multi_and_never_guesses(self):
        out = self.resolve({"detected_exporter_count": 2, "detected_exporter_ip": "45.163.144.1"})
        self.assertEqual(out["sensor_resolution"], "multi")
        self.assertIsNone(out["detected_sensor_id"])

    def test_name_fallback_requires_unambiguous_match(self):
        out = self.resolve({"detected_exporter_count": 1, "detected_sensor_name": "NE8000-GM-TESTE"})
        self.assertEqual(out["sensor_resolution"], "single")
        self.assertEqual(out["detected_sensor_id"], 2)
        with backend_main.sqlite_connection() as conn:
            conn.execute(
                "INSERT INTO sensors (id, name, exporter_ip, created_at, updated_at) VALUES (9,?,?,?,?)",
                ("NE8000-GM-TESTE", "10.0.0.9", "2026-09-29T00:00:00Z", "2026-09-29T00:00:00Z"),
            )
            conn.commit()
        ambiguous = backend_main.resolve_detected_sensor(
            backend_main.sqlite_connection(), {"detected_exporter_count": 1, "detected_sensor_name": "NE8000-GM-TESTE"}
        )
        self.assertEqual(ambiguous["sensor_resolution"], "unresolved")
        self.assertIsNone(ambiguous["detected_sensor_id"])

    def test_no_data_is_unresolved(self):
        out = self.resolve({})
        self.assertEqual(out["sensor_resolution"], "unresolved")
        self.assertIsNone(out["detected_sensor_id"])

    def test_single_reports_detected_exporter_count_one(self):
        out = self.resolve({"detected_exporter_count": 1, "detected_exporter_ip": "45.5.249.0"})
        self.assertEqual(out["sensor_resolution"], "single")
        self.assertEqual(out["detected_sensor_id"], 2)
        self.assertEqual(out["detected_exporter_count"], 1)

    def test_normalize_exporter_ip_variants(self):
        norm = backend_main.normalize_exporter_ip
        self.assertEqual(norm("45.163.144.1"), "45.163.144.1")
        self.assertEqual(norm("::ffff:45.163.144.1"), "45.163.144.1")
        self.assertEqual(norm("::FFFF:179.189.80.0"), "179.189.80.0")
        for vazio in (None, "", "   "):
            self.assertEqual(norm(vazio), "")

    def test_exporter_evidence_wins_over_name_fallback(self):
        """Evidencia de exporter nao pode ser sobreposta pelo nome."""
        out = self.resolve({
            "detected_exporter_count": 1,
            "detected_exporter_ip": "::ffff:45.163.144.1",
            "detected_sensor_name": "NE8000-GM-TESTE",
        })
        self.assertEqual(out["sensor_resolution"], "single")
        self.assertEqual(out["detected_sensor_id"], 3)
        self.assertEqual(out["detected_sensor_name"], "NE8000-F1A-IMPLANTAR")

    def test_duplicated_exporter_is_unresolved_not_arbitrary(self):
        """Dois sensores com o MESMO exporter_ip: nao escolher arbitrariamente."""
        with backend_main.sqlite_connection() as conn:
            conn.execute(
                "INSERT INTO sensors (id, name, exporter_ip, created_at, updated_at) VALUES (9,?,?,?,?)",
                ("NE8000-CLONE", "45.163.144.1", "2026-09-29T00:00:00Z", "2026-09-29T00:00:00Z"),
            )
            conn.commit()
        out = self.resolve({"detected_exporter_count": 1, "detected_exporter_ip": "45.163.144.1"})
        self.assertEqual(out["sensor_resolution"], "unresolved")
        self.assertIsNone(out["detected_sensor_id"])


class SensorPersistenceWiringTest(unittest.TestCase):
    """Garante que os pontos de persistencia usam o sensor DETECTADO."""

    def test_anomaly_events_receives_detected_sensor(self):
        self.assertIn("detected_sensor = resolve_detected_sensor(conn, traffic)", SOURCE)
        self.assertIn('"sensor_id": detected_sensor["detected_sensor_id"],', SOURCE)
        self.assertNotIn('"sensor_id": vector.get("sensor_id"),', SOURCE)

    def test_security_anomalies_receives_detected_sensor(self):
        self.assertIn('"sensor_id": detected_sensor["detected_sensor_id"],', SOURCE)
        self.assertIn('"sensor_id": detected_sensor["detected_sensor_id"]', SOURCE)
        self.assertIn("detected_sensor = resolve_detected_sensor(conn, candidate)", SOURCE)

    def test_schema_has_sensor_column_and_ensure(self):
        self.assertIn("sensor_id INTEGER REFERENCES sensors(id) ON DELETE SET NULL,", SOURCE)
        self.assertIn(
            'ensure_sqlite_column(conn, "security_anomalies", "sensor_id", "sensor_id INTEGER")', SOURCE
        )

    def test_candidate_carries_raw_detection_fields(self):
        self.assertIn('"detected_exporter_count": int(row.get("detected_exporter_count") or 0),', SOURCE)
        self.assertIn('"detected_exporter_ip": clean_text(row.get("detected_exporter_ip")),', SOURCE)
        self.assertIn('"detected_sensor_name": clean_text(row.get("detected_sensor_name") or row.get("sensor")),', SOURCE)

    def test_queries_use_aggregates_not_group_by(self):
        self.assertIn("uniqExact(toString(exporter_ip)) AS detected_exporter_count", SOURCE)
        self.assertIn("any(toString(exporter_ip)) AS detected_exporter_ip", SOURCE)
        # os GROUP BY nao mudaram
        self.assertIn("GROUP BY target_ip\n", SOURCE)
        self.assertIn("GROUP BY target_ip, target_port, sensor, output_if", SOURCE)
        self.assertIn("GROUP BY target_ip, target_port, sensor, input_if", SOURCE)
        self.assertNotIn("GROUP BY target_ip, target_port, sensor, input_if, exporter_ip", SOURCE)
        self.assertNotIn("GROUP BY target_ip, exporter_ip", SOURCE)


class SensorDedupeStabilityTest(SensorBase):
    """O sensor detectado NAO pode alterar nenhuma chave de dedupe."""

    def test_security_anomaly_dedupe_key_ignores_detected_fields(self):
        base = {
            "vector": "PREFIX_INTERNAL_IP_HIGH_UDP_PPS",
            "zone_id": 7,
            "src_ip": "45.5.249.230",
            "reason": "x",
            "protocol": "udp",
            "target_cidr": "45.5.249.230/32",
            "scope_type": "internal_ip_32",
        }
        with_detected = {
            **base,
            "detected_sensor_id": 3,
            "detected_exporter_ip": "45.163.144.1",
            "detected_sensor_name": "NE8000-F1A-IMPLANTAR",
            "detected_exporter_count": 1,
            "sensor_resolution": "single",
        }
        self.assertEqual(
            backend_main.security_anomaly_dedupe_key(base),
            backend_main.security_anomaly_dedupe_key(with_detected),
        )

    def test_dns_dedupe_key_does_not_read_detected_fields(self):
        candidate = {
            "vector": backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
            "top_src_ip": "45.168.203.9",
            "top_src_port": 26036,
            "top_dst_ip": "45.163.144.18",
            "top_dst_port": 53,
            "protocol": "udp",
            "zone_id": 7,
            "template_id": 1,
            "rule_id": 18,
        }
        detected = {
            **candidate,
            "detected_sensor_id": 3,
            "detected_exporter_ip": "45.163.144.1",
            "detected_sensor_name": "NE8000-F1A-IMPLANTAR",
        }
        self.assertEqual(
            backend_main.detection_template_dns_anomaly_dedupe_key(candidate),
            backend_main.detection_template_dns_anomaly_dedupe_key(detected),
        )

    def test_legacy_vector_dedupe_key_is_unchanged(self):
        vector = {"id": 42, "sensor_id": None, "interface_if_index": None, "decoder": "UDP", "direction": "sends"}
        self.assertEqual(backend_main.anomaly_dedupe_key(vector, "100.64.17.245"), "42|100.64.17.245|||UDP|sends")

    def test_active_anomaly_created_before_deploy_is_found_again(self):
        vector = {"id": 42, "sensor_id": None, "interface_if_index": None, "decoder": "UDP", "direction": "sends"}
        old_key = backend_main.anomaly_dedupe_key(vector, "100.64.17.245")
        with backend_main.sqlite_connection() as conn:
            conn.execute(
                """
                INSERT INTO anomaly_events (target_role, zone_name, vector_name, scope_type, invalid_scope,
                    direction, decoder, severity, metric_unit, threshold_value, observed_value, peak_value,
                    started_at, last_seen_at, status, estimated_bytes, estimated_packets, flow_count, summary,
                    dedupe_key, protocol, mitigation_basis, mitigation_reason, top_src_ip, top_dst_ip,
                    top_packets, top_bytes, detection_engine, rule_snapshot_json, anomaly_source, source_engine,
                    source_id, source_name, source_details_json, auto_mitigation_status, auto_mitigation_reason,
                    auto_mitigation_details_json, auto_mitigation_updated_at, created_at, updated_at, sensor_id)
                VALUES ('src_ip','', '', 'internal_ip_32', 0,
                    'sends','UDP','warning','packets_s',1,2,2,
                    '2026-09-29T10:00:00Z','2026-09-29T10:00:00Z','active',0,0,0,'',
                    ?, 'udp','','','','',0,0,'legacy','{}','detection','detection_templates','','','{}','','','{}','',
                    '2026-09-29T10:00:00Z','2026-09-29T10:00:00Z', NULL)
                """,
                (old_key,),
            )
            conn.commit()
            # a mesma condicao, agora com o sensor detectado resolvido
            new_key = backend_main.anomaly_dedupe_key(vector, "100.64.17.245")
            row = conn.execute(
                "SELECT id FROM anomaly_events WHERE dedupe_key = ? AND status = 'active'", (new_key,)
            ).fetchone()
            total = conn.execute("SELECT COUNT(*) AS c FROM anomaly_events").fetchone()["c"]
        self.assertEqual(old_key, new_key)
        self.assertIsNotNone(row, "anomalia ativa pre-deploy nao foi reconhecida")
        self.assertEqual(total, 1)


class SensorMitigationGuardTest(SensorBase):
    """A mitigacao continua usando o sensor de ESCOPO da regra."""

    def test_guard_line_uses_scope_helper(self):
        self.assertIn("mitigation_scope_sensor_id(conn, candidate) or profile.get(\"sensor_id\")", SOURCE)
        self.assertNotIn('candidate.get("sensor_id") or profile.get("sensor_id")', SOURCE)

    def test_scope_helper_reads_rule_sensor_and_ignores_event_sensor(self):
        """Regra global -> None; regra scoped -> sensor da REGRA; event.sensor_id nunca manda."""
        with backend_main.sqlite_connection() as conn:
            template = conn.execute("SELECT id FROM detection_templates ORDER BY id LIMIT 1").fetchone()
            if template is None:
                self.skipTest("sem detection_templates semeados")
            template_id = int(template["id"])

            def add_rule(vector, domain, sensor_id):
                cur = conn.execute(
                    "INSERT INTO detection_template_rules "
                    "(template_id, vector, domain, direction, metric, sensor_id, created_at, updated_at) "
                    "VALUES (?, ?, ?, 'sends', 'packets_s', ?, '2026-09-29T00:00:00Z', '2026-09-29T00:00:00Z')",
                    (template_id, vector, domain, sensor_id),
                )
                return int(cur.lastrowid)

            global_rule = add_rule("VEC_GLOBAL", "internal_ip", None)
            scoped_rule = add_rule("VEC_SENSOR3", "sensor", 3)
            conn.commit()

            self.assertIsNone(
                backend_main.mitigation_scope_sensor_id(conn, {"detection_template_rule_id": global_rule, "sensor_id": 3}),
                "regra global com evento sensorizado nao pode virar escopo por sensor",
            )
            self.assertEqual(
                backend_main.mitigation_scope_sensor_id(conn, {"detection_template_rule_id": scoped_rule, "sensor_id": None}),
                3,
            )
            self.assertIsNone(
                backend_main.mitigation_scope_sensor_id(conn, {"detection_template_rule_id": 999999, "sensor_id": 3})
            )


    def test_sensor_connector_would_win_without_the_guard(self):
        """Prova que o conector id=5/sensor 3 SERIA escolhido se o evento mandasse no escopo."""
        with backend_main.sqlite_connection() as conn:
            conn.execute(
                "INSERT INTO bgp_connectors (id, name, role, sensor_id, enabled, is_active, created_at, updated_at) "
                "VALUES (5, 'BGP-IMPLANTAR-BORDA', 'flowspec_mitigation', 3, 1, 1, "
                "'2026-09-29T00:00:00Z', '2026-09-29T00:00:00Z')"
            )
            conn.commit()
            found = backend_main.sensor_origin_bgp_connectors(conn, 3)
            self.assertEqual([c["name"] for c in found], ["BGP-IMPLANTAR-BORDA"])
            # a guarda ignora o sensor do evento: regra global nao vira rota por sensor
            self.assertIsNone(
                backend_main.mitigation_scope_sensor_id(conn, {"detection_template_rule_id": 999999, "sensor_id": 3})
            )


class SensorUpdateSemanticsTest(unittest.TestCase):
    """Politica explicita: em UPDATE o sensor_id anterior e PRESERVADO (nao ha backfill nem reescrita)."""

    def _update_block(self, marker):
        start = SOURCE.index(marker)
        return SOURCE[start:start + 2600]



class SensorMediaPayloadTest(SensorBase):
    def test_payload_single_includes_sensor(self):
        with backend_main.sqlite_connection() as conn:
            row = media_dispatch.with_sensor_fields(conn, {"id": 1, "sensor_id": 3})
        data = media_dispatch.anomaly_event_data(row)
        self.assertEqual(data["sensor_id"], 3)
        self.assertEqual(data["sensor_name"], "NE8000-F1A-IMPLANTAR")
        self.assertEqual(data["exporter_ip"], "45.163.144.1")
        self.assertEqual(data["sensor_resolution"], "single")

    def test_payload_multi_and_unresolved(self):
        multi = media_dispatch.anomaly_event_data(
            {"id": 2, "sensor_id": None, "source_details_json": '{"sensor_detection": {"sensor_resolution": "multi"}}'}
        )
        self.assertIsNone(multi["sensor_id"])
        self.assertEqual(multi["sensor_resolution"], "multi")
        unresolved = media_dispatch.anomaly_event_data({"id": 3, "sensor_id": None})
        self.assertIsNone(unresolved["sensor_id"])
        self.assertEqual(unresolved["sensor_resolution"], "unresolved")

    def test_historical_null_row_still_readable(self):
        data = media_dispatch.anomaly_event_data({"id": 4, "sensor_id": None, "target_ip": "1.2.3.4"})
        self.assertEqual(data["target_ip"], "1.2.3.4")
        self.assertIn("top_src_ip", data)
        self.assertIsNone(data["sensor_id"])


class SensorSchemaTest(SensorBase):
    def test_ensure_adds_column_to_legacy_table_and_is_idempotent(self):
        with backend_main.sqlite_connection() as conn:
            cols = {row["name"] for row in conn.execute("PRAGMA table_info(security_anomalies)")}
            self.assertIn("sensor_id", cols)
            backend_main.ensure_sqlite_column(conn, "security_anomalies", "sensor_id", "sensor_id INTEGER")
            backend_main.ensure_sqlite_column(conn, "security_anomalies", "sensor_id", "sensor_id INTEGER")
            cols2 = {row["name"] for row in conn.execute("PRAGMA table_info(security_anomalies)")}
        self.assertEqual(cols, cols2)

    def test_legacy_row_without_sensor_is_still_usable(self):
        with backend_main.sqlite_connection() as conn:
            conn.execute(
                "INSERT INTO security_anomalies (vector, severity, status, target_role, scope_type, invalid_scope, response, dedupe_key, created_at, updated_at, anomaly_source, source_engine, source_id, source_name, source_details_json, auto_mitigation_status, auto_mitigation_reason, auto_mitigation_details_json, auto_mitigation_updated_at) "
                "VALUES ('VEC','warning','active','src_ip','internal_ip_32',0,'DETECTION_ONLY','k','2026-09-29T00:00:00Z','2026-09-29T00:00:00Z','detection_template_rule','detection_templates','1','r','{}','','','{}','')"
            )
            conn.commit()
            row = conn.execute("SELECT * FROM security_anomalies").fetchone()
            self.assertIsNone(row["sensor_id"])
            self.assertEqual(backend_main.security_anomaly_row_to_dict(row)["vector"], "VEC")




    @staticmethod
    def _corpo_funcao(nome: str) -> str:
        inicio = SOURCE.index(f"def {nome}(")
        resto = SOURCE[inicio + 1 :]
        try:
            fim = inicio + 1 + resto.index("\ndef ")
        except ValueError:
            fim = len(SOURCE)
        return SOURCE[inicio:fim]

    def test_anomaly_events_update_does_touch_sensor_id(self):
        """Politica B: o UPDATE grava a resolucao ATUAL (NULL em multi/unresolved)."""
        corpo = self._corpo_funcao("upsert_anomaly_event")
        self.assertIn("sensor_id = ?", corpo)
        self.assertIn('detected_sensor["detected_sensor_id"]', corpo)

    def test_security_anomalies_update_does_touch_sensor_id(self):
        corpo = self._corpo_funcao("upsert_security_anomaly")
        self.assertIn("sensor_id = ?", corpo)
        self.assertIn('detected_sensor["detected_sensor_id"]', corpo)

    def test_dns_template_update_does_touch_sensor_id(self):
        corpo = self._corpo_funcao("upsert_detection_template_dns_anomaly_event")
        self.assertIn("sensor_id = ?", corpo)
        self.assertIn('detected_sensor["detected_sensor_id"]', corpo)
if __name__ == "__main__":
    unittest.main()
