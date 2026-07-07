import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from tests.test_collector_apply_static import backend_main


def mitigation_config() -> dict:
    return {
        "enabled": True,
        "provider": "ollama",
        "base_url": "http://ollama:11434",
        "selected_model": "qwen2.5:3b-instruct",
        "selected_profile": "recommended",
        "timeout_seconds": 2,
        "max_top_flows": 10,
        "max_context_chars": 12000,
        "num_predict": 160,
        "keep_alive": "30m",
        "allow_auto": False,
        "require_policy_validation": True,
    }


def mitigation_payload(vector: str = "DNS_INTERNAL_IP_HIGH_BITS") -> dict:
    return {
        "anomaly": {
            "id": 24,
            "target_ip": "186.232.172.245",
            "target_cidr": "186.232.172.245/32",
            "vector_name": vector,
            "protocol": "udp",
            "peak_value": 1200,
            "metric_unit": "packets_s",
        },
        "candidates": [
            {
                "candidate_index": 0,
                "action": "discard",
                "risk": "low",
                "target_prefix": "186.232.172.245/32",
                "allow_auto": False,
                "manual_approval_required": True,
                "apply_enabled": False,
            }
        ],
    }


def create_bgp_connector_profile():
    now = backend_main.utc_now_iso()
    conn = backend_main.sqlite_connection()
    connector_id = conn.execute(
        """
        INSERT INTO bgp_connectors (
            name, role, backend_type, mode, max_active_rules, max_duration_seconds,
            enabled, is_active, created_at, updated_at
        )
        VALUES ('BGP-NE40-VNT', 'flowspec_mitigation', 'exabgp', 'manual_approval', 50, 3600, 1, 1, ?, ?)
        """,
        (now, now),
    ).lastrowid
    profile_id = conn.execute(
        """
        INSERT INTO bgp_response_profiles (
            name, enabled, response_type, connector_id, approval_mode, action, default_action,
            target_selector, protocol_selector, dst_port_selector, require_protocol_or_port,
            max_duration_seconds, default_duration_seconds, created_at, updated_at
        )
        VALUES ('FLOWSPEC-DNS', 1, 'flowspec', ?, 'manual_approval', 'discard', 'discard',
                'dst_ip', 'fixed', 'fixed', 1, 3600, 900, ?, ?)
        """,
        (connector_id, now, now),
    ).lastrowid
    conn.commit()
    connector = backend_main.fetch_bgp_connector(conn, int(connector_id))
    profile = backend_main.fetch_bgp_profile(conn, int(profile_id))
    conn.close()
    return connector, profile


class FakeClickHouseResult:
    def __init__(self, rows):
        self.column_names = [
            "flow_time",
            "sensor",
            "exporter_ip",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "proto",
            "input_if",
            "output_if",
            "packets",
            "bytes",
            "flow_count",
            "first_seen",
            "last_seen",
            "bits_s",
            "packets_s",
        ]
        self.result_rows = rows


class AiMitigationRefactorTest(unittest.TestCase):
    def test_prompt_is_compact_safe_and_uses_existing_candidates_only(self):
        prompt = backend_main.build_mitigation_ai_prompt(mitigation_payload())
        self.assertIn("Escolha somente um candidate_index existente", prompt)
        self.assertIn("Nao crie FlowSpec", prompt)
        self.assertIn("allow_auto deve ser false", prompt)
        self.assertIn('"playbook":', prompt)
        self.assertNotIn('"related_flows"', prompt)

    def test_normalize_requires_existing_candidate_and_forces_manual_review(self):
        payload = mitigation_payload()
        result = backend_main.normalize_mitigation_ai_response(
            json.dumps(
                {
                    "recommended_candidate_index": 0,
                    "confidence": "high",
                    "risk": "low",
                    "classification": "dns_abuse_outbound",
                    "reason": "Revisar candidato existente.",
                    "operator_summary": "Revisao manual do cliente.",
                    "allow_auto": True,
                }
            ),
            payload,
        )
        self.assertEqual(result["recommended_candidate_index"], 0)
        self.assertEqual(result["confidence_label"], "high")
        self.assertFalse(result["allow_auto"])
        self.assertTrue(result["manual_approval_required"])
        self.assertFalse(result["mitigation_allowed"])
        self.assertEqual(result["recommended_action"], "manual_review")

        with self.assertRaises(ValueError):
            backend_main.normalize_mitigation_ai_response('{"recommended_candidate_index": 9}', payload)

    def test_deterministic_fallback_selects_safe_candidate_and_never_allows_auto(self):
        payload = mitigation_payload("udp_flood_outbound")
        result = backend_main.deterministic_mitigation_fallback(payload, "timeout")
        self.assertEqual(result["recommended_candidate_index"], 0)
        self.assertFalse(result["allow_auto"])
        self.assertTrue(result["manual_approval_required"])
        self.assertEqual(result["recommended_action"], "manual_review")
        self.assertEqual(result["classification"], "udp_flood_outbound")
        self.assertEqual(result["reason"], "Fallback deterministico: IA local falhou ou excedeu timeout.")

    def test_deterministic_fallback_does_not_select_analysis_only_candidate(self):
        payload = mitigation_payload("DNS_INTERNAL_IP_HIGH_BITS")
        payload["candidates"][0].update(
            {
                "mitigation_mode": "analysis_only",
                "never_announce": True,
                "action": "discard",
                "manual_approval_required": True,
                "allow_auto": False,
                "risk": "medium",
            }
        )
        result = backend_main.deterministic_mitigation_fallback(payload, "invalid json")
        self.assertIsNone(result["recommended_candidate_index"])
        self.assertEqual(result["recommended_action"], "alert_only")
        self.assertEqual(result["risk"], "none")
        self.assertFalse(result["allow_auto"])
        self.assertTrue(result["manual_approval_required"])
        self.assertIn("sem candidato", result["reason"])

    def test_call_ollama_mitigation_ai_uses_num_predict_without_format_json(self):
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"response":"{\\"recommended_candidate_index\\":0}"}'

        def fake_urlopen(request, timeout):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return FakeResponse()

        with mock.patch.object(backend_main.urllib.request, "urlopen", side_effect=fake_urlopen):
            response = backend_main.call_ollama_mitigation_ai({**mitigation_config(), "num_predict": 96}, "prompt")

        self.assertIn("recommended_candidate_index", response)
        self.assertEqual(captured["body"]["options"]["num_predict"], 96)
        self.assertNotIn("format", captured["body"])
        self.assertEqual(captured["timeout"], 2)

    def test_persisted_analysis_saves_fallback_when_ollama_fails(self):
        tmpdir = tempfile.mkdtemp()
        try:
            db_path = str(Path(tmpdir) / "gmjflow.db")
            with mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": db_path}, clear=False), \
                 mock.patch.object(backend_main, "SENSOR_DB_READY", False), \
                 mock.patch.object(backend_main, "hash_password", return_value="test-hash"), \
                 mock.patch.object(backend_main, "call_ollama_mitigation_ai", side_effect=TimeoutError("timed out")):
                backend_main.ensure_sensor_db()
                result = backend_main.anomaly_ai_analysis_result(
                    24,
                    mitigation_config(),
                    persist=True,
                    request_payload=mitigation_payload(),
                    endpoint="persisted",
                )

                self.assertEqual(result["anomaly_id"], 24)
                self.assertEqual(result["recommended_candidate_index"], 0)
                self.assertFalse(result["allow_auto"])
                self.assertTrue(result["manual_approval_required"])
                self.assertIn("Fallback deterministico", result["reason"])
                self.assertIn("timed out", result["error_message"])

                with backend_main.sqlite_connection() as conn:
                    row = conn.execute("SELECT COUNT(*) AS total FROM ai_mitigation_analysis WHERE anomaly_id = 24").fetchone()
                self.assertEqual(int(row["total"]), 1)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_ai_timeout_fallback_creates_pending_approval_without_pipe_write(self):
        tmpdir = tempfile.mkdtemp()
        try:
            db_path = str(Path(tmpdir) / "gmjflow.db")
            with mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": db_path}, clear=False), \
                 mock.patch.object(backend_main, "SENSOR_DB_READY", False), \
                 mock.patch.object(backend_main, "hash_password", return_value="test-hash"):
                backend_main.ensure_sensor_db()
                connector, profile = create_bgp_connector_profile()
                payload = {
                    "anomaly": {
                        "id": 64,
                        "target_ip": "186.232.163.237",
                        "target_cidr": "186.232.163.237/32",
                        "vector_name": "DNS_INTERNAL_IP_HIGH_BITS",
                        "metric_unit": "bits_s",
                        "peak_value": 120_000_000,
                    },
                    "candidates": [
                        {
                            "candidate_index": 0,
                            "connector_id": connector["id"],
                            "response_profile_id": profile["id"],
                            "response_type": "flowspec",
                            "action": "discard",
                            "dst_prefix": "92.38.143.209/32",
                            "protocol": "udp",
                            "dst_port": "53",
                            "duration_seconds": 900,
                            "manual_approval_required": True,
                            "allow_auto": False,
                        }
                    ],
                }
                pipe_calls = []
                with mock.patch.object(backend_main, "call_ollama_mitigation_ai", side_effect=TimeoutError("timed out")), \
                     mock.patch.object(backend_main, "exabgp_write_pipe", side_effect=lambda _connector, command: pipe_calls.append(command)):
                    result = backend_main.anomaly_ai_analysis_result(
                        64,
                        mitigation_config(),
                        persist=True,
                        request_payload=payload,
                        endpoint="persisted",
                    )

                self.assertEqual(result["anomaly_id"], 64)
                self.assertEqual(result["recommended_candidate_index"], 0)
                self.assertEqual(result["pending_approval"]["status"], "pending_approval")
                self.assertEqual(pipe_calls, [])
                with backend_main.sqlite_connection() as conn:
                    row = conn.execute("SELECT * FROM bgp_announcements WHERE anomaly_id = 64").fetchone()
                self.assertEqual(row["status"], "pending_approval")
                self.assertEqual(row["connector_id"], connector["id"])
                self.assertEqual(row["response_profile_id"], profile["id"])
                self.assertEqual(row["route_type"], "flowspec")
                self.assertEqual(row["response_type"], "flowspec")
                self.assertEqual(row["action"], "discard")
                self.assertEqual(row["dst_prefix"], "92.38.143.209/32")
                self.assertEqual(row["protocol"], "udp")
                self.assertEqual(row["dst_port"], "53")
                self.assertIn("announce flow route", row["announce_command"])
                self.assertIn("withdraw flow route", row["withdraw_command"])
                self.assertIn('"dst_prefix"', row["match_json"])
                self.assertIn('"action"', row["then_json"])
                self.assertEqual(row["policy_decision"], "require_manual_approval")
                self.assertTrue(row["created_at"])
                self.assertTrue(row["updated_at"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_ai_pending_approval_failure_returns_controlled_error(self):
        tmpdir = tempfile.mkdtemp()
        try:
            db_path = str(Path(tmpdir) / "gmjflow.db")
            with mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": db_path}, clear=False), \
                 mock.patch.object(backend_main, "SENSOR_DB_READY", False), \
                 mock.patch.object(backend_main, "hash_password", return_value="test-hash"):
                backend_main.ensure_sensor_db()
                connector, profile = create_bgp_connector_profile()
                payload = {
                    "anomaly": {"id": 65, "target_ip": "186.232.163.237", "vector_name": "DNS_INTERNAL_IP_HIGH_BITS", "metric_unit": "bits_s", "peak_value": 120_000_000},
                    "candidates": [{
                        "candidate_index": 0,
                        "connector_id": connector["id"],
                        "response_profile_id": profile["id"],
                        "response_type": "flowspec",
                        "action": "discard",
                        "dst_prefix": "92.38.143.209/32",
                        "protocol": "udp",
                        "dst_port": "53",
                        "duration_seconds": 900,
                        "manual_approval_required": True,
                        "allow_auto": False,
                    }],
                }
                with mock.patch.object(backend_main, "call_ollama_mitigation_ai", side_effect=TimeoutError("timed out")), \
                     mock.patch.object(backend_main, "insert_bgp_mitigation_announcement", side_effect=sqlite3.OperationalError("42 values for 44 columns")):
                    result = backend_main.anomaly_ai_analysis_result(
                        65,
                        mitigation_config(),
                        persist=True,
                        request_payload=payload,
                        endpoint="persisted",
                    )
                self.assertEqual(result["anomaly_id"], 65)
                self.assertIn("pending_approval_error", result)
                self.assertIn("42 values for 44 columns", result["pending_approval_error"])
                with backend_main.sqlite_connection() as conn:
                    ai_total = conn.execute("SELECT COUNT(*) AS total FROM ai_mitigation_analysis WHERE anomaly_id = 65").fetchone()["total"]
                    bgp_total = conn.execute("SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = 65").fetchone()["total"]
                self.assertEqual(int(ai_total), 1)
                self.assertEqual(int(bgp_total), 0)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_bgp_mitigation_insert_uses_balanced_dynamic_columns(self):
        source = Path(backend_main.__file__).read_text(encoding="utf-8")
        function_source = source[source.find("def insert_bgp_mitigation_announcement"):source.find("def active_mitigation_exists")]
        self.assertIn("columns = [", function_source)
        self.assertIn("values = [", function_source)
        self.assertIn("if len(columns) != len(values):", function_source)
        self.assertIn('placeholders = ", ".join("?" for _ in columns)', function_source)

    def test_dns_internal_src_ip_related_flows_use_src_ip_udp53_without_dst_ip(self):
        calls = []
        flow_time = datetime(2026, 1, 1, 12, 4, tzinfo=timezone.utc)
        row = (
            flow_time,
            "sensor-a",
            "::ffff:192.0.2.10",
            "::ffff:186.232.175.250",
            41000,
            "::ffff:45.228.1.10",
            53,
            17,
            10,
            20,
            248952,
            282_000_000,
            123,
            flow_time,
            flow_time,
            6_266_666.67,
            5532.27,
        )

        def fake_query_clickhouse(query, params):
            calls.append((query, dict(params)))
            return FakeClickHouseResult([row])

        event = {
            "id": 25,
            "vector_name": "DNS_INTERNAL_IP_HIGH_BITS",
            "target_ip": "186.232.175.250",
            "target_role": "src_ip",
            "protocol": "DNS",
            "direction": "transmits",
            "status": "active",
            "started_at": "2026-01-01T12:00:00Z",
            "last_seen_at": "2026-01-01T12:05:00Z",
        }
        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse):
            enrichment = backend_main.enrich_anomaly_with_flows(event, range_margin_seconds=120, limit=50)

        self.assertEqual(len(enrichment["flows"]), 1)
        flow = enrichment["flows"][0]
        self.assertEqual(flow["src_ip"], "186.232.175.250")
        self.assertEqual(flow["dst_port"], 53)
        self.assertEqual(flow["proto"], 17)
        self.assertEqual(flow["protocol"], "UDP")
        self.assertEqual(flow["bytes"], 282_000_000)
        self.assertEqual(flow["packets"], 248952)
        self.assertEqual(flow["exporter_ip"], "192.0.2.10")
        self.assertEqual(flow["input_if"], 10)
        self.assertEqual(flow["output_if"], 20)
        self.assertEqual(enrichment["flow_evidence"]["evidence_status"], "complete")
        self.assertEqual(len(enrichment["mitigation_candidates"]), 1)
        candidate = enrichment["mitigation_candidates"][0]
        self.assertEqual(candidate["profile"], "FLOWSPEC_BLOCK_DST_DNS")
        self.assertEqual(candidate["dst_prefix"], "45.228.1.10/32")
        self.assertEqual(candidate["protocol"], "udp")
        self.assertEqual(candidate["dst_port"], "53")
        self.assertTrue(candidate["manual_approval_required"])
        self.assertFalse(candidate["allow_auto"])
        self.assertTrue(candidate["manual_only"])
        self.assertIn("announce flow route", candidate["rendered_command_preview"])
        self.assertEqual(calls[0][1]["target_ip_plain"], "186.232.175.250")
        self.assertIn("toString(src_ip)", calls[0][0])
        self.assertIn("endsWith(toString(src_ip), {target_ip_plain:String})", calls[0][0])
        self.assertIn("dst_port = 53", calls[0][0])
        self.assertIn("ORDER BY packets_s DESC, bits_s DESC, packets DESC, bytes DESC", calls[0][0])
        self.assertNotIn("toString(dst_ip) = {target_ip", calls[0][0])

    def test_dns_aggregate_without_dst_ip_has_no_candidate_or_pending(self):
        tmpdir = tempfile.mkdtemp()
        try:
            db_path = str(Path(tmpdir) / "gmjflow.db")
            with mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": db_path}, clear=False), \
                 mock.patch.object(backend_main, "SENSOR_DB_READY", False), \
                 mock.patch.object(backend_main, "hash_password", return_value="test-hash"):
                backend_main.ensure_sensor_db()
                create_bgp_connector_profile()
                payload = {
                    "anomaly": {
                        "id": 66,
                        "target_ip": "186.232.169.225",
                        "vector_name": "DNS_INTERNAL_IP_HIGH_PPS",
                        "protocol": "DNS",
                        "metric_unit": "packets_s",
                        "peak_value": 22_076.1,
                    },
                    "related_flows": [
                        {
                            "src_ip": "186.232.169.225",
                            "protocol": "DNS",
                            "packets_s": 22076.1,
                            "bits_s": 12639636.0,
                        }
                    ],
                    "candidates": [],
                }
                with mock.patch.object(backend_main, "call_ollama_mitigation_ai", side_effect=TimeoutError("timed out")):
                    result = backend_main.anomaly_ai_analysis_result(
                        66,
                        mitigation_config(),
                        persist=True,
                        request_payload=payload,
                        endpoint="persisted",
                    )
                self.assertIsNone(result["recommended_candidate_index"])
                self.assertEqual(result["candidate_count"], 0)
                self.assertEqual(result["recommended_action"], "alert_only")
                self.assertNotIn("pending_approval", result)
                self.assertIn("Nao foi criada sugestao de FlowSpec", result["operator_summary"])
                with backend_main.sqlite_connection() as conn:
                    total = conn.execute("SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = 66").fetchone()["total"]
                self.assertEqual(int(total), 0)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_dns_related_flows_fallback_to_udp_when_udp53_empty(self):
        calls = []
        flow_time = datetime(2026, 1, 1, 12, 4, tzinfo=timezone.utc)
        udp_row = (
            flow_time,
            "sensor-a",
            "::ffff:192.0.2.10",
            "::ffff:186.232.175.250",
            41000,
            "::ffff:45.228.1.11",
            5353,
            17,
            10,
            20,
            10,
            1000,
            1,
            flow_time,
            flow_time,
            22.2,
            0.2,
        )

        def fake_query_clickhouse(query, params):
            calls.append((query, dict(params)))
            return FakeClickHouseResult([] if len(calls) == 1 else [udp_row])

        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse):
            enrichment = backend_main.enrich_anomaly_with_flows(
                {
                    "vector_name": "DNS_INTERNAL_IP_HIGH_BITS",
                    "target_ip": "186.232.175.250",
                    "target_role": "src_ip",
                    "protocol": "DNS",
                    "direction": "transmits",
                    "started_at": "2026-01-01T12:00:00Z",
                    "last_seen_at": "2026-01-01T12:05:00Z",
                },
                limit=50,
            )

        self.assertEqual(len(calls), 2)
        self.assertIn("dst_port = 53", calls[0][0])
        self.assertNotIn("dst_port = 53", calls[1][0])
        self.assertEqual(len(enrichment["flows"]), 1)
        self.assertEqual(enrichment["flows"][0]["dst_port"], 5353)

    def test_anomaly_detail_reuses_flow_enrichment_for_related_flows(self):
        source = Path(backend_main.__file__).read_text(encoding="utf-8")
        detail_source = source[source.find('def anomaly_detail(request: Request, event_id: int):'):source.find('def anomaly_pdf_response')]
        self.assertIn("conversations_from_flow_evidence(enrichment.get(\"flow_evidence\"))", detail_source)
        self.assertIn("flows = enriched_flows", detail_source)


if __name__ == "__main__":
    unittest.main()
