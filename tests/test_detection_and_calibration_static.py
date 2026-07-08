import os
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from tests.test_collector_apply_static import backend_main


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


class FakeClickHouseResult:
    def __init__(self, columns, rows):
        self.column_names = columns
        self.result_rows = rows


def outbound_dst_port_rule(vector="UDP_INTERNAL_IP_DST_HIGH_PPS", protocol="UDP", dst_port="any"):
    return {
        "id": 101,
        "vector": vector,
        "domain": "internal_ip",
        "direction": "transmits",
        "protocol": protocol,
        "metric": "packets_s",
        "comparison": "over",
        "warning_value": 10_000,
        "critical_value": 50_000,
        "window_seconds": 60,
        "consecutive_windows": 1,
        "cooldown_seconds": 0,
        "dst_port": dst_port,
        "src_port": "any",
        "response": "MANUAL_REVIEW",
        "mitigation_mode": "manual_review",
        "enabled": True,
        "group_by": "src_ip,dst_ip,dst_port,proto",
        "use_global_whitelist": False,
        "bypass_whitelist": True,
    }


class DetectionAndCalibrationStaticTest(unittest.TestCase):
    def test_worker_evaluates_detection_template_rules_before_legacy_vectors(self):
        worker = SOURCE[SOURCE.find("def detect_anomalies_once"):SOURCE.find("def anomaly_detection_enabled")]
        self.assertIn("run_detection_template_rules_once(create_anomalies=True)", worker)
        self.assertIn("active_attack_vectors(conn)", worker)

    def test_detection_status_and_run_now_endpoints_exist(self):
        self.assertIn('@app.get("/api/detection/status")', SOURCE)
        self.assertIn('@app.post("/api/detection/run-now")', SOURCE)
        self.assertIn("GMJFLOW_DETECTION_INTERVAL_SECONDS", SOURCE)
        self.assertIn("detection scheduler started", SOURCE)

    def test_detection_template_anomaly_source_fields_are_persisted(self):
        self.assertIn("anomaly_source", SOURCE)
        self.assertIn('"detection_template_rule"', SOURCE)
        self.assertIn('"detection_templates"', SOURCE)
        self.assertIn("source_details_json", SOURCE)
        self.assertIn("rule_config", SOURCE)
        self.assertIn("observed", SOURCE)

    def test_detection_run_reports_cooldown_disabled_whitelist_and_no_flow(self):
        self.assertIn("rule skipped: cooldown", SOURCE)
        self.assertIn("rule skipped: disabled", SOURCE)
        self.assertIn("rule skipped: no zone/prefix match", SOURCE)
        self.assertIn("rule skipped: no flow rows", SOURCE)
        self.assertIn("global_whitelist", SOURCE)

    def test_detection_only_still_creates_anomaly_without_mitigation(self):
        detection_run = SOURCE[SOURCE.find("def evaluate_detection_template_rule"):SOURCE.find("def run_detection_template_rules_once")]
        self.assertIn("upsert_security_anomaly(conn, item)", detection_run)
        self.assertNotIn("rule.get(\"mitigation_mode\")", detection_run)
        self.assertNotIn("apply_mitigation_candidate", detection_run)

    def test_subnet_detection_uses_null_ip_fields_and_prefix_scope(self):
        query_builder = SOURCE[SOURCE.find("def query_detection_rule_candidates"):SOURCE.find("def security_anomaly_dedupe_key")]
        self.assertIn('if grouping == "subnet":', query_builder)
        self.assertIn("src_expr = \"CAST(NULL, 'Nullable(String)')\"", query_builder)
        self.assertIn("dst_expr = \"CAST(NULL, 'Nullable(String)')\"", query_builder)
        self.assertIn("internal_expr = \"CAST(NULL, 'Nullable(String)')\"", query_builder)
        self.assertIn('"target_cidr": prefix["cidr"]', query_builder)
        self.assertIn('"scope_type": "subnet"', query_builder)

    def test_anomaly_threshold_uses_metric_unit_not_pps_default(self):
        self.assertIn("configured_metric = clean_text(rule_config.get(\"metric\")", SOURCE)
        self.assertIn('"metric_unit": metric_unit', SOURCE)
        self.assertIn('"threshold_value": threshold_value', SOURCE)
        self.assertIn("formatMetricValue(event.threshold_value, event.metric_unit)", FRONTEND)

    def test_calibration_does_not_persist_failed_or_zero_confidence_results(self):
        calibration = SOURCE[SOURCE.find("def calibrate_interface_sample_rate"):SOURCE.find("def calibration_detail")]
        self.assertIn("should_persist = confidence > 0 and snmp_ok and flow_ok", calibration)
        self.assertIn("if should_persist:", calibration)
        self.assertIn('"snmp_ok": snmp_ok', calibration)
        self.assertIn('"flow_ok": flow_ok', calibration)
        self.assertIn('"reason": reason', calibration)

    def test_calibration_diagnostics_endpoint_and_ui_controls_exist(self):
        self.assertIn('@app.get("/api/sensors/{sensor_id}/interfaces/{if_index}/calibration-diagnostics")', SOURCE)
        self.assertIn("Testar SNMP", FRONTEND)
        self.assertIn("Testar Flow bruto", FRONTEND)
        self.assertIn("Janela: ultimos 15 min", FRONTEND)
        self.assertIn("calibration-diagnostics?window_minutes=5", FRONTEND)

    def test_detection_port_parser_accepts_exclusions(self):
        cases = {
            "any": "any",
            "53": "53",
            "53,123": "53,123",
            "!53": "!53",
            "!53,123": "!53,123",
        }
        for raw, expected in cases.items():
            self.assertEqual(backend_main.normalize_detection_port_text(raw, "dst_port"), expected)

    def test_outbound_dst_port_exclusion_filters_dns_and_allows_other_udp(self):
        calls = []
        flow_time = datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc)
        columns = [
            "src_ip", "dst_ip", "internal_ip", "protocol", "dst_port", "bytes", "packets", "flows",
            "bits_s", "packets_s", "flows_s", "unique_dst_ips", "unique_dst_ports", "unique_src_ports",
            "first_seen", "last_seen", "metric_value",
        ]
        dns_row = ("186.232.171.235", "8.8.8.8", "186.232.171.235", "UDP", 53, 9_000_000, 900_000, 20, 1_200_000, 15_000, 0.33, 1, 1, 2, flow_time, flow_time, 15_000)
        udp_row = ("186.232.171.235", "34.40.46.199", "186.232.171.235", "UDP", 9044, 9_000_000, 900_000, 20, 1_200_000, 15_000, 0.33, 1, 1, 2, flow_time, flow_time, 15_000)

        query_rows = [[dns_row], [udp_row]]

        def fake_query_clickhouse(query, params):
            calls.append((query, dict(params)))
            self.assertIn("dst_port NOT IN (53)", query)
            rows = query_rows.pop(0)
            if "dst_port NOT IN (53)" in query:
                rows = [row for row in rows if row[4] != 53]
            return FakeClickHouseResult(columns, rows)

        zone = {"id": 1, "name": "CGN"}
        template = {"id": 10, "name": "Outbound abuse", "active": True}
        prefix = {"id": 7, "cidr": "186.232.171.0/24"}
        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse), \
             mock.patch.object(backend_main, "clickhouse_sample_rate_expr", return_value="greatest(sample_rate, 1)"):
            dns_items = backend_main.query_detection_rule_candidates(
                zone, template, outbound_dst_port_rule(dst_port="!53"), prefix, flow_time, flow_time, None
            )
            udp_items = backend_main.query_detection_rule_candidates(
                zone, template, outbound_dst_port_rule(dst_port="!53"), prefix, flow_time, flow_time, None
            )

        self.assertEqual(dns_items, [])
        self.assertEqual(len(udp_items), 1)
        self.assertEqual(udp_items[0]["top_dst_port"], 9044)
        self.assertNotEqual(udp_items[0]["dst_ip"], "8.8.8.8")
        self.assertEqual(len(calls), 2)

    def test_dns_detection_rule_still_matches_udp53(self):
        calls = []
        flow_time = datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc)
        columns = [
            "src_ip", "dst_ip", "internal_ip", "protocol", "dst_port", "bytes", "packets", "flows",
            "bits_s", "packets_s", "flows_s", "unique_dst_ips", "unique_dst_ports", "unique_src_ports",
            "first_seen", "last_seen", "metric_value",
        ]
        dns_row = ("186.232.171.235", "8.8.8.8", "186.232.171.235", "DNS", 0, 9_000_000, 900_000, 20, 1_200_000, 15_000, 0.33, 1, 1, 2, flow_time, flow_time, 15_000)

        def fake_query_clickhouse(query, params):
            calls.append((query, dict(params)))
            return FakeClickHouseResult(columns, [dns_row])

        rule = outbound_dst_port_rule(vector="DNS_INTERNAL_IP_HIGH_PPS", protocol="DNS")
        rule["group_by"] = "src_ip"
        zone = {"id": 1, "name": "CGN"}
        template = {"id": 10, "name": "DNS", "active": True}
        prefix = {"id": 7, "cidr": "186.232.171.0/24"}
        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse), \
             mock.patch.object(backend_main, "clickhouse_sample_rate_expr", return_value="greatest(sample_rate, 1)"):
            items = backend_main.query_detection_rule_candidates(zone, template, rule, prefix, flow_time, flow_time, None)

        self.assertEqual(len(items), 1)
        self.assertIn("src_port = 53 OR dst_port = 53", calls[0][0])
        self.assertNotIn("dst_port NOT IN (53)", calls[0][0])

    def test_outbound_dst_port_rule_creates_one_candidate_per_destination_port(self):
        calls = []
        flow_time = datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc)
        columns = [
            "src_ip", "dst_ip", "internal_ip", "protocol", "dst_port", "bytes", "packets", "flows",
            "bits_s", "packets_s", "flows_s", "unique_dst_ips", "unique_dst_ports", "unique_src_ports",
            "first_seen", "last_seen", "metric_value",
        ]
        rows = [
            ("186.232.171.235", "34.40.46.199", "186.232.171.235", "UDP", 9044, 9_000_000, 900_000, 20, 1_200_000, 15_000, 0.33, 1, 1, 2, flow_time, flow_time, 15_000),
            ("186.232.171.235", "35.1.2.3", "186.232.171.235", "UDP", 9443, 7_200_000, 720_000, 12, 960_000, 12_000, 0.2, 1, 1, 1, flow_time, flow_time, 12_000),
        ]

        def fake_query_clickhouse(query, params):
            calls.append((query, dict(params)))
            return FakeClickHouseResult(columns, rows)

        zone = {"id": 1, "name": "CGN"}
        template = {"id": 10, "name": "Outbound abuse", "active": True}
        prefix = {"id": 7, "cidr": "186.232.171.0/24"}
        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse), \
             mock.patch.object(backend_main, "clickhouse_sample_rate_expr", return_value="greatest(sample_rate, 1)"):
            items = backend_main.query_detection_rule_candidates(
                zone, template, outbound_dst_port_rule(), prefix, flow_time, flow_time, None
            )

        self.assertEqual(len(items), 2)
        self.assertIn("dst_port AS dst_port", calls[0][0])
        self.assertIn("GROUP BY bucket, src_ip, dst_ip, internal_ip, protocol, dst_port", calls[0][0])
        self.assertEqual({(item["src_ip"], item["dst_ip"], item["top_dst_port"]) for item in items}, {
            ("186.232.171.235", "34.40.46.199", 9044),
            ("186.232.171.235", "35.1.2.3", 9443),
        })
        self.assertTrue(all(item["target_ip"] == "186.232.171.235" for item in items))
        self.assertTrue(all(item["mitigation_basis"] == "dst_ip,dst_port,protocol" for item in items))

        tmpdir = tempfile.mkdtemp()
        try:
            db_path = str(Path(tmpdir) / "gmjflow.db")
            with mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": db_path}, clear=False), \
                 mock.patch.object(backend_main, "SENSOR_DB_READY", False), \
                 mock.patch.object(backend_main, "hash_password", return_value="test-hash"):
                backend_main.ensure_sensor_db()
                with backend_main.sqlite_connection() as conn:
                    for item in items:
                        backend_main.upsert_security_anomaly(conn, item)
                    rows_db = conn.execute("SELECT * FROM security_anomalies ORDER BY dst_ip, source_details_json").fetchall()
                self.assertEqual(len(rows_db), 2)
                dedupe = [row["dedupe_key"] for row in rows_db]
                self.assertEqual(len(set(dedupe)), 2)
                converted = [backend_main.security_anomaly_row_to_dict(row) for row in rows_db]
                self.assertEqual({item["top_dst_port"] for item in converted}, {9044, 9443})
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_outbound_dst_port_related_flows_are_exact_destination_port(self):
        calls = []
        flow_time = datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc)
        columns = [
            "sensor", "exporter_ip", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "input_if", "output_if",
            "raw_packets", "raw_bytes", "sample_rate", "packets", "bytes", "flow_count", "first_flow_time", "last_flow_time", "bits_s", "packets_s",
        ]
        row = ("s1", "192.0.2.1", "186.232.171.235", 40000, "34.40.46.199", 9044, 17, 1, 2, 900_000, 9_000_000, 1, 900_000, 9_000_000, 20, flow_time, flow_time, 1_200_000, 15_000)
        dns_row = ("s1", "192.0.2.1", "186.232.171.235", 52706, "8.8.8.8", 53, 17, 1, 2, 9_000_000, 90_000_000, 1, 9_000_000, 90_000_000, 20, flow_time, flow_time, 12_000_000, 150_000)
        quic_row = ("s1", "192.0.2.1", "186.232.171.235", 52707, "35.233.3.154", 443, 17, 1, 2, 8_000_000, 80_000_000, 1, 8_000_000, 80_000_000, 20, flow_time, flow_time, 10_000_000, 130_000)

        def fake_query_clickhouse(query, params):
            calls.append((query, dict(params)))
            return FakeClickHouseResult(columns, [dns_row, quic_row, row])

        event = {
            "id": 501,
            "vector_name": "UDP_INTERNAL_IP_DST_HIGH_PPS",
            "target_ip": "186.232.171.235",
            "target_cidr": "186.232.171.235/32",
            "target_role": "src_ip",
            "top_src_ip": "186.232.171.235",
            "top_dst_ip": "34.40.46.199",
            "top_dst_port": 9044,
            "protocol": "UDP",
            "direction": "transmits",
            "source_details": {"rule_config": {"dst_port": "!53"}},
            "started_at": "2026-07-07T12:00:00Z",
            "last_seen_at": "2026-07-07T12:01:00Z",
        }
        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse):
            enrichment = backend_main.enrich_anomaly_with_flows(event, range_margin_seconds=0, limit=10)

        self.assertEqual(len(enrichment["flows"]), 1)
        self.assertEqual(enrichment["flows"][0]["dst_ip"], "34.40.46.199")
        self.assertEqual(enrichment["flows"][0]["dst_port"], 9044)
        self.assertTrue(all(flow["dst_port"] == 9044 for flow in enrichment["flow_evidence"]["related_flows"]))
        self.assertTrue(all(flow["dst_port"] != 53 for flow in enrichment["flow_evidence"]["related_flows"]))
        self.assertEqual(enrichment["flow_evidence"]["top_conversations"][0]["dst_ip"], "34.40.46.199")
        self.assertEqual(enrichment["flow_evidence"]["top_conversations"][0]["dst_port"], 9044)
        self.assertIn("dst_port = {top_dst_port:UInt16}", calls[0][0])
        self.assertIn("top_dst_ip", calls[0][0])
        self.assertIn("top_src_ip", calls[0][0])
        self.assertIn("dst_port != 53", calls[0][0])
        self.assertEqual(calls[0][1]["top_dst_port"], 9044)

    def test_ip_zone_anomaly_ui_shows_dst_port_and_mitigates_security_item(self):
        self.assertIn("<th>Dst porta</th>", FRONTEND)
        self.assertIn("function securityAnomalyDstPort(item)", FRONTEND)
        self.assertIn("item?.top_dst_port || item?.target_port || details.top_dst_port || details.target_port", FRONTEND)
        self.assertIn("function securityAnomalyDstIp(item)", FRONTEND)
        self.assertIn("item?.dst_ip || details.top_dst_ip", FRONTEND)
        self.assertIn("function securityAnomalyActionId(item)", FRONTEND)
        self.assertIn("security-anomaly-mitigate", FRONTEND)
        self.assertIn('data-anomaly-id="${actionId}"', FRONTEND)
        self.assertIn("openBgpMitigationModal(Number(mitigate.dataset.anomalyId))", FRONTEND)
        self.assertIn('"target_port": int(source_details.get("target_port") or source_details.get("top_dst_port") or 0)', SOURCE)

    def test_outbound_dst_port_udp_and_tcp_candidates_are_destination_only(self):
        for vector, protocol, port, profile in (
            ("UDP_INTERNAL_IP_DST_HIGH_PPS", "UDP", 9044, "FLOWSPEC_BLOCK_DST_UDP_PORT"),
            ("TCP_INTERNAL_IP_DST_HIGH_PPS", "TCP", 443, "FLOWSPEC_BLOCK_DST_TCP_PORT"),
        ):
            event = {
                "vector_name": vector,
                "attack_vector_name": vector,
                "target_ip": "186.232.171.235",
                "top_src_ip": "186.232.171.235",
                "top_dst_ip": "34.40.46.199",
                "top_dst_port": port,
                "protocol": protocol,
                "direction": "transmits",
            }
            candidate = backend_main.outbound_dst_port_candidate(event, 0.8)
            self.assertIsNotNone(candidate)
            self.assertEqual(candidate["profile"], profile)
            self.assertEqual(candidate["dst_prefix"], "34.40.46.199/32")
            self.assertEqual(candidate["protocol"], protocol.lower())
            self.assertEqual(candidate["dst_port"], str(port))
            self.assertEqual(candidate.get("src_prefix") or "", "")
            self.assertEqual(candidate.get("src_port") or "", "")
            self.assertNotIn("source ", candidate["rendered_command_preview"])
            self.assertNotIn("source-port", candidate["rendered_command_preview"])
            self.assertIn(f"destination-port ={port};", candidate["rendered_command_preview"])

        missing = backend_main.outbound_dst_port_candidate({"vector_name": "UDP_INTERNAL_IP_DST_HIGH_PPS", "top_dst_ip": "34.40.46.199", "protocol": "UDP"}, 0.8)
        self.assertIsNone(missing)
        dns_port = backend_main.outbound_dst_port_candidate({
            "vector_name": "UDP_INTERNAL_IP_DST_HIGH_PPS",
            "top_dst_ip": "8.8.8.8",
            "top_dst_port": 53,
            "protocol": "UDP",
            "direction": "transmits",
        }, 0.8)
        self.assertIsNone(dns_port)

    def test_response_profiles_ui_is_compact_and_uses_details_for_preview(self):
        response_profiles_section = FRONTEND[
            FRONTEND.find('<div class="panel-title mb-2">Response Profiles</div>'):
            FRONTEND.find('<div class="panel-title mb-2">Politica de seguranca</div>')
        ]
        self.assertIn('id="bgpProfileFilters"', response_profiles_section)
        self.assertIn('data-filter="valid"', response_profiles_section)
        self.assertIn('data-filter="unsafe"', response_profiles_section)
        self.assertIn("<th>Match</th>", response_profiles_section)
        self.assertIn("<th>Aprovacao</th>", response_profiles_section)
        self.assertNotIn("<th>Preview</th>", response_profiles_section)
        self.assertIn("item.display_match || item.compact_preview", FRONTEND)
        self.assertIn("bgp-profile-details-toggle", FRONTEND)
        self.assertIn("Preview completo", FRONTEND)
        self.assertIn("validation_status", FRONTEND)
        self.assertIn("used_by_rules", FRONTEND)

    def test_anomaly_human_labels_and_fallbacks(self):
        self.assertEqual(backend_main.anomaly_type_label("PREFIX_INTERNAL_IP_HIGH_UDP_PPS_ATTACK"), "UDP flood por IP")
        self.assertEqual(backend_main.anomaly_type_label("DNS_INTERNAL_IP_TO_DST_HIGH_PPS"), "DNS alto por destino")
        self.assertIn("UDP alto", backend_main.anomaly_type_label("PREFIX_INTERNAL_IP_UNKNOWN_HIGH_UDP_PPS"))

    def test_anomaly_main_table_is_compact_and_keeps_technical_names_in_detail(self):
        anomaly_header = FRONTEND[
            FRONTEND.find('<tbody id="anomaliesTable"></tbody>') - 900:
            FRONTEND.find('<tbody id="anomaliesTable"></tbody>')
        ]
        render_source = FRONTEND[
            FRONTEND.find("function renderAnomalyTable"):
            FRONTEND.find("async function loadAnomalies")
        ]
        detail_source = FRONTEND[
            FRONTEND.find("function anomalyScopeHtml"):
            FRONTEND.find("function normalizedAnomalyMetricPoints")
        ]
        self.assertIn("<th>Tipo</th>", anomaly_header)
        self.assertIn("<th>Alvo</th>", anomaly_header)
        self.assertNotIn("Regra/Vetor", anomaly_header)
        self.assertIn("anomalyTypeLabel(event)", render_source)
        self.assertIn("anomalyCompactSummary(event)", render_source)
        self.assertIn("Regra tecnica", detail_source)
        self.assertIn("Vetor tecnico", detail_source)

    def test_anomaly_timeseries_window_expands_zero_duration(self):
        first = datetime(2026, 7, 7, 14, 12, 49, tzinfo=timezone.utc)
        start, end = backend_main.anomaly_timeseries_window({
            "started_at": first.isoformat().replace("+00:00", "Z"),
            "last_seen_at": first.isoformat().replace("+00:00", "Z"),
        })
        self.assertEqual(start, first - timedelta(minutes=15))
        self.assertGreaterEqual((end - first).total_seconds(), 3600)

    def test_general_ip_anomaly_timeseries_uses_flow_raw_without_top_flow_filter(self):
        calls = []
        columns = ["time", "bits_s", "packets_s", "flows_s", "bytes", "packets", "flows"]
        base = datetime(2026, 7, 7, 14, 10, tzinfo=timezone.utc)

        def fake_query_clickhouse(query, params=None):
            calls.append((query, dict(params or {})))
            if "DESCRIBE TABLE flow_raw" in query:
                return FakeClickHouseResult(
                    ["name", "type"],
                    [
                        ("flow_time", "DateTime"),
                        ("src_ip", "IPv6"),
                        ("dst_ip", "IPv6"),
                        ("proto", "UInt8"),
                        ("packets", "UInt64"),
                        ("bytes", "UInt64"),
                        ("sample_rate", "UInt32"),
                        ("flow_count", "UInt64"),
                    ],
                )
            self.assertIn("FROM flow_raw", query)
            self.assertIn("proto = 17", query)
            self.assertNotIn("top_dst_port", query)
            self.assertNotIn("dst_port = {top_dst_port", query)
            self.assertNotIn("protocol =", query)
            return FakeClickHouseResult(columns, [
                (base, 8000.0, 1000.0, 1.0, 60000, 60000, 60),
                (base + timedelta(minutes=1), 16000.0, 2000.0, 1.5, 120000, 120000, 90),
                (base + timedelta(minutes=2), 24000.0, 3000.0, 2.0, 180000, 180000, 120),
            ])

        event = {
            "vector_name": "PREFIX_INTERNAL_IP_HIGH_UDP_PPS_ATTACK",
            "target_ip": "45.5.248.195",
            "target_cidr": "45.5.248.195/32",
            "target_role": "src_ip",
            "direction": "transmits",
            "protocol": "UDP",
            "started_at": "2026-07-07T14:12:49Z",
            "last_seen_at": "2026-07-07T14:12:49Z",
            "top_dst_ip": "213.33.167.222",
            "top_dst_port": 80,
        }
        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse):
            result = backend_main.anomaly_detail_timeseries(event)
        self.assertEqual(result["source"], "flow_raw")
        self.assertEqual(result["scope"], "target_total")
        self.assertEqual(result["points_count"], 3)
        self.assertEqual(result["warning"], "")

    def test_destination_port_timeseries_can_filter_specific_conversation(self):
        queries = []

        def fake_query_clickhouse(query, params=None):
            queries.append(query)
            if "DESCRIBE TABLE flow_raw" in query:
                return FakeClickHouseResult(
                    ["name", "type"],
                    [
                        ("flow_time", "DateTime"),
                        ("src_ip", "IPv6"),
                        ("dst_ip", "IPv6"),
                        ("dst_port", "UInt16"),
                        ("proto", "UInt8"),
                        ("packets", "UInt64"),
                        ("bytes", "UInt64"),
                        ("sample_rate", "UInt32"),
                        ("flow_count", "UInt64"),
                    ],
                )
            return FakeClickHouseResult(["time", "bits_s", "packets_s", "flows_s", "bytes", "packets", "flows"], [])

        event = {
            "vector_name": "UDP_INTERNAL_IP_DST_HIGH_PPS",
            "target_ip": "45.5.248.195",
            "target_role": "src_ip",
            "direction": "transmits",
            "protocol": "UDP",
            "top_dst_ip": "213.33.167.222",
            "top_dst_port": 80,
            "started_at": "2026-07-07T14:12:49Z",
            "last_seen_at": "2026-07-07T14:13:49Z",
        }
        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse):
            backend_main.anomaly_timeseries_flow_raw(event, *backend_main.anomaly_timeseries_window(event))
        flow_query = queries[-1]
        self.assertIn("top_dst_ip", flow_query)
        self.assertIn("dst_port = {top_dst_port:UInt16}", flow_query)

    def test_collector_build_context_uses_host_project_dir(self):
        with mock.patch.dict(os.environ, {"GMJFLOW_PROJECT_DIR": "/opt/gmj-flow"}, clear=False):
            self.assertEqual(
                backend_main.collector_build_context(),
                "/opt/gmj-flow/runtime/collector/pmacct",
            )
            compose = backend_main.compose_for_collectors([{"id": 1, "name": "sensor-1", "listener_port": 9995, "exporter_ip": ""}])
            self.assertIn('context: "/opt/gmj-flow/runtime/collector/pmacct"', compose)
            self.assertNotIn("context: /app/runtime/collector/pmacct", compose)
        with mock.patch.dict(os.environ, {"GMJFLOW_PROJECT_DIR": ""}, clear=False), \
             mock.patch.object(backend_main, "detected_runtime_mount_source", return_value=""):
            self.assertEqual(backend_main.collector_build_context(), str(Path("runtime") / "collector" / "pmacct"))
        self.assertNotEqual(backend_main.collector_build_context(), "/app/runtime/collector/pmacct")


if __name__ == "__main__":
    unittest.main()
