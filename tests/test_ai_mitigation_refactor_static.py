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
        VALUES ('FLOWSPEC_BLOCK_DST_DNS', 1, 'flowspec', ?, 'manual_approval', 'discard', 'discard',
                'dst_ip', 'fixed', 'fixed', 1, 3600, 900, ?, ?)
        """,
        (connector_id, now, now),
    ).lastrowid
    conn.commit()
    connector = backend_main.fetch_bgp_connector(conn, int(connector_id))
    profile = backend_main.fetch_bgp_profile(conn, int(profile_id))
    conn.close()
    return connector, profile


def response_profile_fixture(**overrides) -> dict:
    base = {
        "id": 1,
        "name": "FLOWSPEC_BLOCK_DST_DNS",
        "description": "",
        "enabled": 1,
        "response_type": "flowspec",
        "connector_id": 10,
        "connector_name": "BGP-FIBINET-BORDA",
        "connector_enabled": 1,
        "connector_active": 1,
        "approval_mode": "manual_approval",
        "action": "discard",
        "default_action": "discard",
        "target_selector": "dst_ip",
        "protocol_selector": "udp",
        "fixed_protocol": "",
        "src_port_selector": "any",
        "src_port_value": "",
        "dst_port_selector": "fixed",
        "dst_port_value": "53",
        "tcp_flags_selector": "any",
        "tcp_flags_value": "",
        "rate_limit_bps": None,
        "rate_limit_value_raw": "",
        "rate_limit_unit": "",
        "default_rate_limit_bps": None,
        "default_rate_limit_raw": "",
        "max_rate_limit_bps": None,
        "min_rate_limit_bps": None,
        "bgp_community": "",
        "action_metadata": "",
        "use_global_whitelist": 1,
        "extra_whitelist_ids": "[]",
        "bypass_whitelist": 0,
        "redirect_target": "",
        "next_hop": "",
        "community": "",
        "large_community": "",
        "require_protocol_or_port": 1,
        "require_protected_prefix": 1,
        "allow_wide_prefix": 0,
        "max_prefixlen_v4": 32,
        "max_prefixlen_v6": 128,
        "max_duration_seconds": 3600,
        "default_duration_seconds": 900,
        "notes": "",
        "used_by_rules_count": 0,
        "used_by_rules_raw": "",
        "created_at": "2026-07-08T00:00:00Z",
        "updated_at": "2026-07-08T00:00:00Z",
    }
    base.update(overrides)
    return backend_main.bgp_response_profile_row_to_dict(base)


class FakeClickHouseResult:
    def __init__(self, rows):
        self.column_names = [
            "sensor",
            "exporter_ip",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "proto",
            "input_if",
            "output_if",
            "raw_packets",
            "raw_bytes",
            "sample_rate",
            "packets",
            "bytes",
            "flow_count",
            "first_flow_time",
            "last_flow_time",
            "bits_s",
            "packets_s",
        ]
        self.result_rows = rows


class AiMitigationRefactorTest(unittest.TestCase):
    def assert_safe_flow_aggregation_query(self, query: str):
        for forbidden in (
            "sum(bytes) AS bytes",
            "sum(packets) AS packets",
            "sum(bytes) *",
            "sum(packets) /",
            "sum(packets *",
            "sum(bytes *",
        ):
            self.assertNotIn(forbidden, query)
        self.assertIn("raw_packets", query)
        self.assertIn("raw_bytes", query)
        self.assertIn("sample_rate", query)
        self.assertIn("raw_packets * sample_rate AS packets", query)
        self.assertIn("raw_bytes * sample_rate AS bytes", query)
        self.assertIn("total_flow_count AS flow_count", query)

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

    def test_dns_flow_query_builders_do_not_use_aggregate_flow_time_alias(self):
        query = backend_main.anomaly_flow_query(
            [
                "flow_time >= {start:DateTime}",
                "flow_time <= {end:DateTime}",
                "toString(src_ip) = {target_ip_plain:String}",
                "proto = 17",
            ],
            dns_dst_port_filter=True,
        )
        self.assertNotIn("AS flow_time", query)
        self.assertNotIn("max(flow_time) AS flow_time", query)
        self.assertIn("min(flow_time) AS first_flow_time", query)
        self.assertIn("max(flow_time) AS last_flow_time", query)
        where_clause = query.split("WHERE", 1)[1].split("GROUP BY", 1)[0]
        self.assertNotIn("max(", where_clause)
        self.assertNotIn("first_flow_time", where_clause)
        self.assertNotIn("last_flow_time", where_clause)

        schema = {
            "flow_time": "DateTime64(3)",
            "src_ip": "IPv6",
            "dst_ip": "IPv6",
            "src_port": "UInt16",
            "dst_port": "UInt16",
            "proto": "UInt8",
            "packets": "UInt64",
            "bytes": "UInt64",
            "flow_count": "UInt64",
        }
        dynamic_query = backend_main.dynamic_anomaly_flow_query(
            [
                "flow_time >= {start:DateTime}",
                "flow_time <= {end:DateTime}",
                "toString(src_ip) = {target_ip_plain:String}",
                "proto = 17",
            ],
            dns_dst_port_filter=True,
            schema=schema,
        )
        self.assertNotIn("AS flow_time", dynamic_query)
        self.assertNotIn("max(flow_time) AS flow_time", dynamic_query)
        self.assertIn("min(flow_time) AS first_flow_time", dynamic_query)
        self.assertIn("max(flow_time) AS last_flow_time", dynamic_query)
        dynamic_where = dynamic_query.split("WHERE", 1)[1].split("GROUP BY", 1)[0]
        self.assertNotIn("max(", dynamic_where)
        self.assertNotIn("first_flow_time", dynamic_where)
        self.assertNotIn("last_flow_time", dynamic_where)

    def test_ai_payload_preserves_enrichment_attempts(self):
        payload = backend_main.compact_ai_payload_for_model(
            {
                "anomaly": {"id": 64, "target_ip": "186.232.169.225"},
                "flow_evidence": {
                    "evidence_status": "complete",
                    "enrichment_attempts": [{"label": "standard_dns_udp53", "rows": 1}],
                    "related_flows": [
                        {
                            "src_ip": "186.232.169.225",
                            "dst_ip": "92.38.143.209",
                            "dst_port": 53,
                            "proto": 17,
                            "protocol": "UDP",
                            "packets": 1_332_224,
                            "raw_packets": 2602,
                            "sample_rate": 512,
                            "packets_s": 22203.73,
                        }
                    ],
                },
                "candidates": [],
            },
            5000,
        )
        self.assertEqual(payload["flow_evidence"]["enrichment_attempts"][0]["label"], "standard_dns_udp53")
        self.assertEqual(len(payload["related_flows"]), 1)
        self.assertEqual(payload["related_flows"][0]["dst_ip"], "92.38.143.209")
        self.assertEqual(payload["related_flows"][0]["packets_s"], 22203.73)
        self.assertEqual(payload["related_flows"][0]["raw_packets"], 2602)
        self.assertEqual(payload["related_flows"][0]["sample_rate"], 512)

    def test_dns_internal_src_ip_related_flows_use_src_ip_udp53_without_dst_ip(self):
        calls = []
        flow_time = datetime(2026, 1, 1, 12, 4, tzinfo=timezone.utc)
        row = (
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
            1,
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
        self.assertEqual(flow["raw_packets"], 248952)
        self.assertEqual(flow["sample_rate"], 1)
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
        self.assertIn("protocol =udp;", candidate["rendered_command_preview"])
        self.assertEqual(calls[0][1]["target_ip_plain"], "186.232.175.250")
        self.assertIn("toString(src_ip)", calls[0][0])
        self.assertIn("endsWith(toString(src_ip), {target_ip_plain:String})", calls[0][0])
        self.assertIn("dst_port = 53", calls[0][0])
        self.assertIn("sum(packets) AS raw_packets", calls[0][0])
        self.assertIn("sum(bytes) AS raw_bytes", calls[0][0])
        self.assertIn("AS sample_rate", calls[0][0])
        self.assertIn("raw_packets * sample_rate AS packets", calls[0][0])
        self.assertIn("raw_bytes * sample_rate AS bytes", calls[0][0])
        self.assertIn("round((raw_packets * sample_rate) / 60, 2) AS packets_s", calls[0][0])
        self.assertIn("sum(flow_count) AS total_flow_count", calls[0][0])
        self.assertIn("ORDER BY packets DESC, bytes DESC", calls[0][0])
        self.assert_safe_flow_aggregation_query(calls[0][0])
        self.assertNotIn("toString(dst_ip) = {target_ip", calls[0][0])

    def test_dns_enrichment_uses_adaptive_flow_raw_schema_aliases(self):
        calls = []
        flow_time = datetime(2026, 1, 1, 12, 4, tzinfo=timezone.utc)

        class Result:
            def __init__(self, columns, rows):
                self.column_names = columns
                self.result_rows = rows

        schema_columns = [
            ("timestamp", "DateTime"),
            ("sensor_name", "String"),
            ("router_ip", "IPv6"),
            ("src_addr", "IPv6"),
            ("l4_src_port", "UInt16"),
            ("dst_addr", "IPv6"),
            ("l4_dst_port", "UInt16"),
            ("protocol", "String"),
            ("ingress_if", "UInt32"),
            ("egress_if", "UInt32"),
            ("pkts", "UInt64"),
            ("octets", "UInt64"),
            ("records", "UInt64"),
            ("sample_rate", "UInt32"),
        ]
        row = (
            "sensor-a",
            "::ffff:192.0.2.10",
            "::ffff:186.232.169.225",
            53001,
            "::ffff:92.38.143.209",
            53,
            17,
            10,
            20,
            2602,
            190_160,
            512,
            1_332_224,
            97_361_920,
            321,
            flow_time,
            flow_time,
            12_981_589.33,
            22_203.73,
        )

        def fake_query_clickhouse(query, params=None):
            calls.append((query, dict(params or {})))
            if "DESCRIBE TABLE flow_raw" in query:
                return Result(["name", "type"], schema_columns)
            if "max(flow_time)" in query or "toString(src_ip)" in query:
                raise Exception("Unknown identifier flow_time")
            self.assertIn("timestamp >= {start:DateTime}", query)
            self.assertIn("toString(src_addr)", query)
            self.assertIn("toString(dst_addr)", query)
            self.assertIn("l4_dst_port = 53", query)
            self.assertIn("lower(toString(protocol))", query)
            self.assertIn("sum(pkts) AS raw_packets", query)
            self.assertIn("sum(octets) AS raw_bytes", query)
            self.assertIn("max(greatest(sample_rate, 1)) AS sample_rate", query)
            self.assertIn("raw_packets * sample_rate AS packets", query)
            self.assertIn("raw_bytes * sample_rate AS bytes", query)
            self.assertIn("round((raw_packets * sample_rate) / 60, 2) AS packets_s", query)
            self.assertIn("sum(records) AS total_flow_count", query)
            self.assertIn("ORDER BY packets DESC, bytes DESC", query)
            self.assert_safe_flow_aggregation_query(query)
            return Result(
                [
                    "sensor",
                    "exporter_ip",
                    "src_ip",
                    "src_port",
                    "dst_ip",
                    "dst_port",
                    "proto",
                    "input_if",
                    "output_if",
                    "raw_packets",
                    "raw_bytes",
                    "sample_rate",
                    "packets",
                    "bytes",
                    "flow_count",
                    "first_flow_time",
                    "last_flow_time",
                    "bits_s",
                    "packets_s",
                ],
                [row],
            )

        event = {
            "id": 64,
            "vector_name": "DNS_INTERNAL_IP_HIGH_PPS",
            "target_ip": "186.232.169.225",
            "target_role": "src_ip",
            "protocol": "DNS",
            "direction": "transmits",
            "started_at": "2026-01-01T12:00:00Z",
            "last_seen_at": "2026-01-01T12:05:00Z",
        }
        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse):
            enrichment = backend_main.enrich_anomaly_with_flows(event, range_margin_seconds=120, limit=50)

        self.assertEqual(enrichment["flow_evidence"]["evidence_status"], "complete")
        self.assertEqual(enrichment["flow_evidence"]["unique_dst_ips"], 1)
        self.assertEqual(enrichment["flow_evidence"]["dominant_dst_port"], 53)
        self.assertEqual(enrichment["flow_evidence"]["dominant_protocol"], "UDP")
        self.assertEqual(enrichment["flow_evidence"]["enrichment_attempts"][-1]["schema_mode"], "adaptive")
        flow = enrichment["flows"][0]
        self.assertEqual(flow["src_ip"], "186.232.169.225")
        self.assertEqual(flow["src_port"], 53001)
        self.assertEqual(flow["dst_ip"], "92.38.143.209")
        self.assertEqual(flow["dst_port"], 53)
        self.assertEqual(flow["proto"], 17)
        self.assertEqual(flow["protocol"], "UDP")
        self.assertEqual(flow["packets"], 1332224)
        self.assertEqual(flow["raw_packets"], 2602)
        self.assertEqual(flow["sample_rate"], 512)
        self.assertEqual(flow["packets_s"], 22203.73)
        self.assertEqual(flow["bits_s"], 12981589.33)
        self.assertEqual(enrichment["mitigation_candidates"][0]["dst_prefix"], "92.38.143.209/32")
        self.assertEqual(enrichment["mitigation_candidates"][0]["profile"], "FLOWSPEC_BLOCK_DST_DNS")
        self.assertFalse(enrichment["mitigation_candidates"][0]["allow_auto"])
        self.assertEqual(enrichment["mitigation_candidates"][0].get("src_port") or "", "")
        self.assertEqual(enrichment["mitigation_candidates"][0].get("src_prefix") or "", "")
        self.assertNotIn("source ", enrichment["mitigation_candidates"][0]["rendered_command_preview"])
        self.assertNotIn("source-port", enrichment["mitigation_candidates"][0]["rendered_command_preview"])
        self.assertIn("destination-port =53;", enrichment["mitigation_candidates"][0]["rendered_command_preview"])
        self.assertTrue(enrichment["mitigation_candidates"][0]["manual_approval_required"])

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

    def test_dns_outbound_source_only_candidate_does_not_create_pending(self):
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
                        "id": 67,
                        "target_ip": "186.232.169.225",
                        "target_cidr": "186.232.169.225/32",
                        "vector_name": "DNS_INTERNAL_IP_HIGH_PPS",
                        "protocol": "DNS",
                        "metric_unit": "packets_s",
                        "peak_value": 22_076.1,
                    },
                    "candidates": [{
                        "candidate_index": 0,
                        "connector_id": connector["id"],
                        "response_profile_id": profile["id"],
                        "profile": "FLOWSPEC_BLOCK_SRC_DNS",
                        "response_type": "flowspec",
                        "action": "discard",
                        "src_prefix": "186.232.169.225/32",
                        "target_prefix": "186.232.169.225/32",
                        "protocol": "udp",
                        "dst_port": "53",
                        "duration_seconds": 900,
                        "manual_approval_required": True,
                        "allow_auto": False,
                    }],
                }
                with mock.patch.object(backend_main, "call_ollama_mitigation_ai", side_effect=TimeoutError("timed out")):
                    result = backend_main.anomaly_ai_analysis_result(
                        67,
                        mitigation_config(),
                        persist=True,
                        request_payload=payload,
                        endpoint="persisted",
                    )
                self.assertIsNone(result["recommended_candidate_index"])
                self.assertEqual(result["recommended_action"], "alert_only")
                self.assertEqual(result["candidate_count"], 1)
                self.assertNotIn("pending_approval", result)
                with backend_main.sqlite_connection() as conn:
                    total = conn.execute("SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = 67").fetchone()["total"]
                self.assertEqual(int(total), 0)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_dns_outbound_src_dns_profile_is_rejected_at_pending_persistence(self):
        tmpdir = tempfile.mkdtemp()
        try:
            db_path = str(Path(tmpdir) / "gmjflow.db")
            with mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": db_path}, clear=False), \
                 mock.patch.object(backend_main, "SENSOR_DB_READY", False), \
                 mock.patch.object(backend_main, "hash_password", return_value="test-hash"):
                backend_main.ensure_sensor_db()
                connector, profile = create_bgp_connector_profile()
                with backend_main.sqlite_connection() as conn:
                    conn.execute("UPDATE bgp_response_profiles SET name = 'FLOWSPEC_BLOCK_SRC_DNS' WHERE id = ?", (profile["id"],))
                    conn.commit()
                payload = {
                    "anomaly": {
                        "id": 68,
                        "target_ip": "186.232.169.225",
                        "target_cidr": "186.232.169.225/32",
                        "vector_name": "DNS_INTERNAL_IP_HIGH_BITS",
                        "protocol": "DNS",
                        "metric_unit": "bits_s",
                        "peak_value": 120_000_000,
                    },
                    "candidates": [{
                        "candidate_index": 0,
                        "connector_id": connector["id"],
                        "response_profile_id": profile["id"],
                        "response_type": "flowspec",
                        "action": "discard",
                        "dst_prefix": "92.38.143.209/32",
                        "target_prefix": "92.38.143.209/32",
                        "protocol": "udp",
                        "dst_port": "53",
                        "duration_seconds": 900,
                        "manual_approval_required": True,
                        "allow_auto": False,
                    }],
                }
                with mock.patch.object(backend_main, "call_ollama_mitigation_ai", side_effect=TimeoutError("timed out")):
                    result = backend_main.anomaly_ai_analysis_result(
                        68,
                        mitigation_config(),
                        persist=True,
                        request_payload=payload,
                        endpoint="persisted",
                    )
                self.assertEqual(result["recommended_candidate_index"], 0)
                self.assertIn("pending_approval_error", result)
                self.assertIn("dns_outbound_cannot_use_flowspec_block_src_dns", result["pending_approval_error"])
                self.assertNotIn("pending_approval", result)
                with backend_main.sqlite_connection() as conn:
                    total = conn.execute("SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = 68").fetchone()["total"]
                self.assertEqual(int(total), 0)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_dns_outbound_candidate_policy_rejects_source_only_and_src_profile(self):
        source_only = {
            "template": "dns_udp_abuse_outbound",
            "profile": "FLOWSPEC_BLOCK_DST_DNS",
            "response_type": "flowspec",
            "action": "discard",
            "src_prefix": "186.232.169.225/32",
            "protocol": "udp",
            "dst_port": "53",
            "manual_approval_required": True,
            "allow_auto": False,
        }
        ok, reason = backend_main.validate_dns_outbound_pending_candidate(
            source_only,
            {"vector_name": "DNS_INTERNAL_IP_HIGH_PPS", "target_ip": "186.232.169.225"},
            {"classification": "dns_abuse_outbound"},
            {"name": "FLOWSPEC_BLOCK_DST_DNS"},
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "dns_outbound_requires_external_dst_prefix")
        self.assertFalse(backend_main.mitigation_candidate_can_create_pending(source_only))
        rendered = backend_main.render_exabgp_flowspec_command("announce", source_only)
        self.assertNotIn("source ", rendered)
        self.assertNotIn("source-port", rendered)
        self.assertIn("protocol =udp;", rendered)
        self.assertIn("destination-port =53;", rendered)
        self.assertNotIn("destination ", rendered)

        src_profile = {
            **source_only,
            "src_prefix": "",
            "dst_prefix": "92.38.143.209/32",
            "target_prefix": "92.38.143.209/32",
            "profile": "FLOWSPEC_BLOCK_SRC_DNS",
        }
        ok, reason = backend_main.validate_dns_outbound_pending_candidate(
            src_profile,
            {"vector_name": "DNS_INTERNAL_IP_HIGH_PPS"},
            {"classification": "dns_abuse_outbound"},
            {"name": "FLOWSPEC_BLOCK_SRC_DNS"},
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "dns_outbound_cannot_use_flowspec_block_src_dns")
        self.assertFalse(backend_main.mitigation_candidate_can_create_pending(src_profile))

    def test_dns_outbound_dst_dns_candidate_omits_source_port_from_preview_and_pending(self):
        tmpdir = tempfile.mkdtemp()
        try:
            db_path = str(Path(tmpdir) / "gmjflow.db")
            with mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": db_path}, clear=False), \
                 mock.patch.object(backend_main, "SENSOR_DB_READY", False), \
                 mock.patch.object(backend_main, "hash_password", return_value="test-hash"):
                backend_main.ensure_sensor_db()
                connector, profile = create_bgp_connector_profile()
                candidate = {
                    "candidate_index": 0,
                    "connector_id": connector["id"],
                    "response_profile_id": profile["id"],
                    "profile": "FLOWSPEC_BLOCK_DST_DNS",
                    "response_profile_name": "FLOWSPEC_BLOCK_DST_DNS",
                    "response_type": "flowspec",
                    "action": "discard",
                    "src_prefix": "186.232.169.225/32",
                    "src_port": "23311",
                    "dst_prefix": "202.181.139.255/32",
                    "target_prefix": "202.181.139.255/32",
                    "protocol": "udp",
                    "dst_port": "53",
                    "duration_seconds": 900,
                    "manual_approval_required": True,
                    "allow_auto": False,
                    "template": "dns_udp_abuse_outbound",
                }
                expected = "announce flow route { match { destination 202.181.139.255/32; protocol =udp; destination-port =53; } then { discard; } }"
                rendered = backend_main.render_exabgp_flowspec_command("announce", candidate)
                self.assertEqual(rendered, expected)
                self.assertNotIn("source-port", rendered)
                self.assertNotIn("source ", rendered)
                payload = {
                    "anomaly": {
                        "id": 69,
                        "target_ip": "186.232.169.225",
                        "target_cidr": "186.232.169.225/32",
                        "vector_name": "DNS_INTERNAL_IP_HIGH_PPS",
                        "protocol": "DNS",
                        "metric_unit": "packets_s",
                        "peak_value": 22_247.1,
                    },
                    "candidates": [candidate],
                }
                with mock.patch.object(backend_main, "call_ollama_mitigation_ai", side_effect=TimeoutError("timed out")):
                    result = backend_main.anomaly_ai_analysis_result(
                        69,
                        mitigation_config(),
                        persist=True,
                        request_payload=payload,
                        endpoint="persisted",
                    )
                self.assertIn("pending_approval", result)
                self.assertNotIn("source-port", result.get("rendered_command_preview") or "")
                pending = result["pending_approval"]
                self.assertEqual(pending["announce_command"], expected)
                self.assertEqual(pending.get("src_port") or "", "")
                self.assertEqual(pending.get("src_prefix") or "", "")
                self.assertNotIn("source-port", pending["announce_command"])
                self.assertNotIn("source ", pending["announce_command"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_dns_outbound_valid_candidate_uses_dst_profile_and_external_dst_prefix(self):
        candidate = {
            "template": "dns_udp_abuse_outbound",
            "profile": "FLOWSPEC_BLOCK_DST_DNS",
            "response_type": "flowspec",
            "action": "discard",
            "dst_prefix": "92.38.143.209/32",
            "target_prefix": "92.38.143.209/32",
            "protocol": "udp",
            "src_port": "23311",
            "src_prefix": "186.232.169.225/32",
            "dst_port": "53",
            "manual_approval_required": True,
            "allow_auto": False,
        }
        ok, reason = backend_main.validate_dns_outbound_pending_candidate(
            candidate,
            {"vector_name": "DNS_INTERNAL_IP_HIGH_PPS", "target_ip": "186.232.169.225"},
            {"classification": "dns_abuse_outbound"},
            {"name": "FLOWSPEC_BLOCK_DST_DNS"},
        )
        self.assertTrue(ok, reason)
        self.assertTrue(backend_main.mitigation_candidate_can_create_pending(candidate))
        rendered = backend_main.render_exabgp_flowspec_command("announce", candidate)
        self.assertIn("destination 92.38.143.209/32;", rendered)
        self.assertIn("protocol =udp;", rendered)
        self.assertIn("destination-port =53;", rendered)
        self.assertNotIn("source-port", rendered)
        self.assertNotIn("source ", rendered)

    def test_dns_related_flows_fallback_to_udp_when_udp53_empty(self):
        calls = []
        flow_time = datetime(2026, 1, 1, 12, 4, tzinfo=timezone.utc)
        udp_row = (
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

    def test_frontend_related_flows_falls_back_to_flow_evidence(self):
        html = Path("frontend/index.html").read_text(encoding="utf-8")
        self.assertIn("detail.flow_evidence.related_flows", html)
        self.assertIn("const evidenceFlows", html)

    def test_safe_destination_profiles_validate_for_dns_udp_and_tcp(self):
        cases = [
            ("FLOWSPEC_BLOCK_DST_DNS", "udp", "fixed", "53", "dst udp/53"),
            ("FLOWSPEC_BLOCK_DST_UDP_PORT", "udp", "anomaly_dst_port", "", "dst udp/<anom_dst_port>"),
            ("FLOWSPEC_BLOCK_DST_TCP_PORT", "tcp", "anomaly_dst_port", "", "dst tcp/<anom_dst_port>"),
        ]
        for name, protocol, dst_selector, dst_value, display_match in cases:
            profile = response_profile_fixture(
                name=name,
                protocol_selector=protocol,
                dst_port_selector=dst_selector,
                dst_port_value=dst_value,
            )
            self.assertEqual(profile["validation_status"], "valid")
            self.assertTrue(profile["is_safe_default"])
            self.assertEqual(profile["display_match"], display_match)
            self.assertEqual(profile["approval_mode"], "manual_approval")
            self.assertNotIn("source-port", profile["rendered_command_preview"])

    def test_unsafe_and_deprecated_profiles_are_classified_explicitly(self):
        src_dns = response_profile_fixture(name="FLOWSPEC_BLOCK_SRC_DNS", target_selector="src_ip")
        self.assertEqual(src_dns["validation_status"], "deprecated")
        self.assertTrue(src_dns["is_deprecated"])
        self.assertFalse(src_dns["is_safe_default"])

        src_port = response_profile_fixture(
            name="FLOWSPEC_BLOCK_DST_UDP_SRC_PORT",
            src_port_selector="anomaly_src_port",
            dst_port_selector="any",
            dst_port_value="",
        )
        self.assertEqual(src_port["validation_status"], "unsafe")
        self.assertTrue(src_port["uses_source_port"])

    def test_flowspec_profile_without_connector_is_invalid_connector(self):
        profile = response_profile_fixture(connector_id=None, connector_name="", connector_enabled=None, connector_active=None)
        self.assertEqual(profile["validation_status"], "invalid_connector")
        self.assertEqual(profile["profile_status"], "invalid_connector")
        self.assertIn("Connector", profile["validation_reason"])


if __name__ == "__main__":
    unittest.main()
