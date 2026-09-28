"""Bloco 2 / Estrategia C — evidencia de distribuicao nos eventos UDP legacy.

Comprova que:
1. o trigger continua PPS-only (a cardinalidade NAO entra no HAVING dos detectores inbound);
2. a cardinalidade e classificacao/evidencia (`distribution_evidence`), nunca gate;
3. mitigacao/policy/severity nao mudam;
4. anomalias antigas (sem os novos campos) continuam serializando.
"""
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from tests.test_collector_apply_static import backend_main


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")

DOWNLOAD_VECTOR = "UDP_DOWNLOAD_SAME_DST_PORT_TO_CLIENT"
UPLOAD_MANY_VECTOR = "UDP_UPLOAD_MANY_CLIENTS_SAME_DST_PORT"


def download_vector(**overrides):
    vector = {
        "id": 8,
        "name": DOWNLOAD_VECTOR,
        "display_name": "UDP download same destino port",
        "domain_type": "internal_ip",
        "target_cidr": "",
        "sensor_id": None,
        "interface_if_index": None,
        "direction": "receives",
        "decoder": "UDP",
        "threshold_unit": "packets_s",
        "threshold_value": 100000,
        "severity": "warning",
        "response_action": "alert_only",
    }
    vector.update(overrides)
    return vector


def download_traffic(**overrides):
    traffic = {
        "target_ip": "45.168.201.213",
        "target_cidr": "45.168.201.213/32",
        "target_role": "dst_ip",
        "scope_type": "internal_dst_ip_port",
        "invalid_scope": False,
        "packets_s": 128100.0,
        "bits_s": 994_000_000.0,
        "total_bytes": 7_000_000_000,
        "total_packets": 7_686_000,
        "flow_count": 11,
        "protocol": "udp",
        "sensor": "NE8000-F1A-IMPLANTAR",
        "input_if": 90,
        "output_if": 0,
        "target_port": 27507,
        "zone_id": 7,
        "zone_name": "IMPLANTAR",
        "unique_src_ips": 1,
        "unique_dst_ips": 1,
        "unique_dst_ports": 1,
        "threshold_value": 100000.0,
        "mitigation_basis": "aggregated_dst_port",
        "mitigation_reason": "UDP inbound agregado por cliente e destination-port.",
        "top_src_ip": "203.0.113.9",
        "top_dst_ip": "45.168.201.213",
        "top_src_port": 33333,
        "top_dst_port": 27507,
        "top_packets": 7_686_000,
        "top_bytes": 7_000_000_000,
        "first_seen_at": "2026-08-31T05:47:00Z",
        "last_seen_at": "2026-08-31T05:47:49Z",
    }
    traffic.update(overrides)
    return traffic


class DistributionEvidenceTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmpdir) / "gmjflow.db")
        self.start = datetime(2026, 8, 31, 5, 47, tzinfo=timezone.utc)
        self._patchers = [
            mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": self.db_path}, clear=False),
            mock.patch.object(backend_main, "SENSOR_DB_READY", False),
            mock.patch.object(backend_main, "hash_password", return_value="test-hash"),
            mock.patch.object(backend_main, "save_anomaly_flow_samples", return_value=None),
        ]
        for patcher in self._patchers:
            patcher.start()
        backend_main.ensure_sensor_db()

    def tearDown(self):
        for patcher in reversed(self._patchers):
            patcher.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _upsert(self, vector, traffic, minutes=1, expect="created"):
        with backend_main.sqlite_connection() as conn:
            action = backend_main.upsert_anomaly_event(
                conn,
                vector,
                traffic,
                self.start,
                self.start + timedelta(minutes=minutes),
            )
            row = conn.execute(
                "SELECT * FROM anomaly_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            event = backend_main.anomaly_event_row_to_dict(row)
            raw = backend_main.bgp_json_loads(row["source_details_json"], {})
        self.assertEqual(action, expect)
        return event, raw

    # CASO A/B/C/D + single/multi -------------------------------------------------
    def test_single_source_keeps_pps_trigger_and_classifies_single_source(self):
        event, raw = self._upsert(download_vector(), download_traffic(unique_src_ips=1))
        self.assertTrue(event["trigger_condition"]["passed"])
        self.assertEqual(event["trigger_condition"]["threshold"], 100000.0)
        self.assertEqual(event["trigger_condition"]["observed_value"], 128100.0)
        evidence = raw["distribution_evidence"]
        self.assertEqual(evidence["unique_src_ips_observed"], 1)
        self.assertEqual(evidence["attack_shape"], "single-source")
        self.assertFalse(evidence["used_for_trigger"])
        self.assertEqual(evidence["threshold_role"], "classification_only")

    def test_multi_source_keeps_pps_trigger_and_classifies_multi_source(self):
        event, raw = self._upsert(
            download_vector(),
            download_traffic(unique_src_ips=34, top_packets=200_000, total_packets=7_686_000),
        )
        self.assertTrue(event["trigger_condition"]["passed"])
        evidence = raw["distribution_evidence"]
        self.assertEqual(evidence["unique_src_ips_observed"], 34)
        self.assertEqual(evidence["attack_shape"], "multi-source")
        self.assertFalse(evidence["used_for_trigger"])
        self.assertEqual(evidence["semantic_threshold"], 3)

    def test_cardinality_below_semantic_threshold_still_fires_by_pps(self):
        _, raw = self._upsert(download_vector(), download_traffic(unique_src_ips=2))
        self.assertEqual(raw["distribution_evidence"]["unique_src_ips_observed"], 2)
        self.assertNotEqual(raw["distribution_evidence"]["attack_shape"], "multi-source")

    def test_exact_single_source_is_classified_even_without_concentration_data(self):
        # cardinalidade exata do agregado: 1 origem e um fato, nao depende do share medido
        _, raw = self._upsert(
            download_vector(),
            download_traffic(unique_src_ips=1, top_packets=0, total_packets=0),
        )
        self.assertEqual(raw["distribution_evidence"]["attack_shape"], "single-source")
        self.assertFalse(raw["distribution_evidence"]["used_for_trigger"])

    def test_cardinality_above_semantic_threshold_does_not_change_detection(self):
        # o detector segue disparando por PPS; apenas a classificacao muda
        with backend_main.sqlite_connection() as conn:
            rows = conn.execute("SELECT COUNT(*) AS n FROM anomaly_events").fetchone()
        self.assertEqual(int(rows["n"]), 0)
        event, raw = self._upsert(download_vector(), download_traffic(unique_src_ips=250))
        self.assertTrue(event["trigger_condition"]["passed"])
        self.assertEqual(raw["distribution_evidence"]["attack_shape"], "multi-source")

    def test_trigger_condition_is_pps_only_for_inbound(self):
        _, raw = self._upsert(download_vector(), download_traffic(unique_src_ips=19))
        detection = raw["detection"]
        self.assertEqual(
            set(detection["trigger_condition"].keys()),
            {"metric", "comparison", "observed_value", "threshold", "passed"},
        )
        self.assertEqual(detection["trigger_condition"]["metric"], "packets_per_second")
        self.assertEqual(detection["trigger_condition"]["comparison"], "over")
        # cardinalidade NAO aparece como condicao de trigger nos vetores inbound
        self.assertEqual(detection["conditions_passed"], [])
        self.assertNotIn("unique_src_ips", detection["trigger_condition"])

    # Vetor de upload (cardinalidade E condicao do HAVING) ------------------------
    def test_upload_many_clients_exposes_cardinality_as_real_trigger_condition(self):
        vector = download_vector(
            id=6,
            name=UPLOAD_MANY_VECTOR,
            direction="sends",
            display_name="UDP upload many clients same destino port",
        )
        traffic = download_traffic(
            unique_src_ips=19,
            unique_dst_ips=1,
            unique_dst_ports=1,
            unique_src_ips_threshold=3,
            scope_type="external_dst_ip_port",
            target_role="dst_ip",
        )
        _, raw = self._upsert(vector, traffic)
        conditions = raw["detection"]["conditions_passed"]
        self.assertEqual(len(conditions), 1)
        self.assertEqual(conditions[0]["condition"], "unique_src_ips")
        self.assertEqual(conditions[0]["threshold"], 3)
        self.assertEqual(conditions[0]["observed_value"], 19)
        self.assertTrue(conditions[0]["passed"])
        self.assertTrue(raw["distribution_evidence"]["used_for_trigger"])

    # Compatibilidade / guardrails -------------------------------------------------
    def test_legacy_anomaly_without_new_fields_still_serializes(self):
        legacy_details = {"attack_vector_id": 8, "vector_name": DOWNLOAD_VECTOR, "display_name": "UDP"}
        with backend_main.sqlite_connection() as conn:
            conn.execute(
                """
                INSERT INTO anomaly_events (
                    attack_vector_id, target_ip, target_cidr, target_role, target_port, protocol,
                    vector_name, scope_type, invalid_scope, direction, decoder, severity, metric_unit,
                    threshold_value, observed_value, peak_value, started_at, last_seen_at, status,
                    estimated_bytes, estimated_packets, flow_count, summary, dedupe_key,
                    anomaly_source, source_engine, source_id, source_name, source_details_json,
                    created_at, updated_at
                )
                VALUES (
                    8, '45.168.201.213', '45.168.201.213/32', 'dst_ip', 27507, 'udp',
                    ?, 'internal_dst_ip_port', 0, 'receives', 'UDP', 'warning', 'packets_s',
                    100000, 108000, 108000, ?, ?, 'ended',
                    1, 1, 1, 'legacy', 'legacy-key',
                    'legacy_attack_vector', 'legacy_detector', '8', 'UDP', ?,
                    ?, ?
                )
                """,
                (
                    DOWNLOAD_VECTOR,
                    backend_main.iso(self.start),
                    backend_main.iso(self.start),
                    backend_main.json.dumps(legacy_details, sort_keys=True),
                    backend_main.iso(self.start),
                    backend_main.iso(self.start),
                ),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM anomaly_events ORDER BY id DESC LIMIT 1").fetchone()
            event = backend_main.anomaly_event_row_to_dict(row)
        self.assertEqual(event["vector_name"], DOWNLOAD_VECTOR)
        self.assertFalse(event.get("trigger_condition"))
        self.assertNotIn("distribution_evidence", event["source_details"])

    def test_mitigation_identity_and_fields_unchanged_by_evidence(self):
        _, raw_enriched = self._upsert(download_vector(), download_traffic(unique_src_ips=34))
        plain_details = {
            "attack_vector_id": 8,
            "vector_name": DOWNLOAD_VECTOR,
            "display_name": "UDP download same destino port",
        }
        with backend_main.sqlite_connection() as conn:
            row = conn.execute("SELECT * FROM anomaly_events ORDER BY id DESC LIMIT 1").fetchone()
            item = dict(row)
        before = dict(item, source_details_json=backend_main.json.dumps(plain_details, sort_keys=True))
        after = dict(item, source_details_json=backend_main.json.dumps(raw_enriched, sort_keys=True))
        candidate_before = backend_main.base_mitigation_candidate(
            backend_main.anomaly_event_row_to_dict(before), DOWNLOAD_VECTOR, "motivo", 0.75
        )
        candidate_after = backend_main.base_mitigation_candidate(
            backend_main.anomaly_event_row_to_dict(after), DOWNLOAD_VECTOR, "motivo", 0.75
        )
        self.assertEqual(
            backend_main.mitigation_key_for_candidate(candidate_before),
            backend_main.mitigation_key_for_candidate(candidate_after),
        )
        for key in ("mitigation_basis", "mitigation_reason", "attack_vector_name", "dst_cidr", "dst_port", "action"):
            self.assertEqual(candidate_before.get(key), candidate_after.get(key), key)
        # nenhum campo de elegibilidade de mitigacao automatica e gravado
        self.assertNotIn("automatic_mitigation_threshold", raw_enriched)
        self.assertNotIn("automatic_mitigation_threshold", raw_enriched["detection"])
        # o gate deterministico de DNS nao se aplica a este vetor
        gate = backend_main.dns_single_flow_automatic_policy_gate(candidate_after)
        self.assertFalse(gate["applies"])
        self.assertTrue(gate["allowed"])

    def test_sampling_observation_is_explicit_and_not_multiplied(self):
        _, raw = self._upsert(download_vector(), download_traffic(unique_src_ips=34))
        sampling = raw["distribution_evidence"]["sampling"]
        self.assertTrue(sampling["cardinality_is_sampled"])
        self.assertEqual(sampling["direction"], "input")
        self.assertIn("nao e o total real de origens", sampling["note"])
        # cardinalidade observada e o valor cru do agregado (nunca x sample-rate)
        self.assertEqual(raw["distribution_evidence"]["unique_src_ips_observed"], 34)

    # Estatico: o vetor de upload expoe o threshold de cardinalidade usado --------
    def test_upload_query_exposes_cardinality_threshold(self):
        self.assertIn('"unique_src_ips_threshold": unique_src_ips_threshold', SOURCE)
        self.assertIn(
            "unique_src_ips_threshold = critical_unique if severity == \"critical\" else warning_unique",
            SOURCE,
        )
        self.assertIn("DISTRIBUTION_SEMANTIC_MULTI_SOURCE_MIN = 3", SOURCE)

    def test_inbound_having_still_pps_only(self):
        """O HAVING dos detectores inbound continua sem cardinalidade."""
        inbound = SOURCE.split("def query_udp_download_to_client(")[1].split("\ndef ")[0]
        self.assertIn("HAVING packets_s >= {float(warning_pps)}", inbound)
        self.assertNotIn("unique_src_ips >=", inbound)
        upload = SOURCE.split("def query_udp_many_internal_to_same_dst_port(")[1].split("\ndef ")[0]
        self.assertIn("AND unique_src_ips >= {int(warning_unique)}", upload)


if __name__ == "__main__":
    unittest.main()
