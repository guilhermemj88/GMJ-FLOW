import json
import os
import shutil
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

    def test_deterministic_fallback_points_to_single_manual_review_candidate(self):
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
        self.assertEqual(result["recommended_candidate_index"], 0)
        self.assertEqual(result["recommended_action"], "manual_review")
        self.assertEqual(result["risk"], "medium")
        self.assertFalse(result["allow_auto"])
        self.assertTrue(result["manual_approval_required"])

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
        self.assertEqual(calls[0][1]["target_ip_plain"], "186.232.175.250")
        self.assertIn("toString(src_ip)", calls[0][0])
        self.assertIn("endsWith(toString(src_ip), {target_ip_plain:String})", calls[0][0])
        self.assertIn("dst_port = 53", calls[0][0])
        self.assertNotIn("toString(dst_ip) = {target_ip", calls[0][0])

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


if __name__ == "__main__":
    unittest.main()
