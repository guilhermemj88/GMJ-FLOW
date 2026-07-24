import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from tests.test_collector_apply_static import backend_main


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


class FakeClickHouseResult:
    def __init__(self, columns, rows):
        self.column_names = columns
        self.result_rows = rows


def dns_single_flow_rule():
    return {
        "id": 501,
        "vector": backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
        "display_name": "Ataque DNS por fluxo único",
        "domain": "internal_ip",
        "direction": "transmits",
        "protocol": "UDP",
        "metric": "packets_s",
        "comparison": "over",
        "warning_value": 5_000,
        "critical_value": 5_000,
        "window_seconds": 60,
        "consecutive_windows": 1,
        "cooldown_seconds": 0,
        "src_port": "any",
        "dst_port": "53",
        "response": "DETECTION_ONLY",
        "mitigation_mode": "detection_only",
        "mitigation_enabled": False,
        "enabled": True,
        "detection_key": "src_ip,src_port,dst_ip,dst_port,protocol",
        "group_by": "src_ip,src_port,dst_ip,dst_port,protocol",
        "use_global_whitelist": True,
        "bypass_whitelist": False,
    }


DNS_COLUMNS = [
    "src_ip",
    "src_port",
    "dst_ip",
    "internal_ip",
    "protocol",
    "dst_port",
    "top_dst_port",
    "top_src_port",
    "bytes",
    "packets",
    "flows",
    "bits_s",
    "packets_s",
    "flows_s",
    "unique_dst_ips",
    "unique_dst_ports",
    "unique_src_ports",
    "first_seen",
    "last_seen",
    "metric_value",
]


def dns_row(pps, src_port=2811, dst_port=53, protocol="UDP", flow_time=None):
    observed_at = flow_time or datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
    packets = int(float(pps) * 60)
    return (
        "45.5.248.196",
        src_port,
        "195.136.19.76",
        "45.5.248.196",
        protocol,
        dst_port,
        dst_port,
        src_port,
        packets * 80,
        packets,
        1,
        pps * 640,
        pps,
        1 / 60,
        1,
        1,
        1,
        observed_at,
        observed_at,
        pps,
    )


def persisted_candidate(observed_at, pps=5_000, src_port=2811):
    packets = int(pps * 60)
    return {
        "zone_id": 7,
        "zone_name": "Clientes",
        "template_id": 8,
        "template_name": "CLIENTES-PUBLICOS-DEFAULT",
        "sensor_id": 9,
        "rule_id": 10,
        "rule_name": backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
        "display_name": "Ataque DNS por fluxo único",
        "rule_config": dns_single_flow_rule(),
        "prefix_id": 11,
        "prefix_cidr": "45.5.248.0/24",
        "domain": "internal_ip",
        "direction": "transmits",
        "vector": backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
        "severity": "critical",
        "src_ip": "45.5.248.196",
        "dst_ip": "195.136.19.76",
        "internal_ip": "45.5.248.196",
        "target_ip": "45.5.248.196",
        "target_cidr": "45.5.248.196/32",
        "target_role": "src_ip",
        "scope_type": "internal_ip_32",
        "invalid_scope": False,
        "protocol": "udp",
        "src_port": src_port,
        "target_port": 53,
        "top_src_ip": "45.5.248.196",
        "top_src_port": src_port,
        "top_dst_ip": "195.136.19.76",
        "top_dst_port": 53,
        "top_packets": packets,
        "top_bytes": packets * 80,
        "mitigation_basis": "dns_outbound_conversation",
        "mitigation_reason": "Conversa UDP/53 unica acima de 5 Kpps; classificacao deterministica critical.",
        "packets_s": float(pps),
        "bits_s": float(pps * 640),
        "flows": 1,
        "flows_s": round(1 / 60, 2),
        "packets": packets,
        "bytes": packets * 80,
        "unique_dst_ips": 1,
        "unique_dst_ports": 1,
        "unique_src_ports": 1,
        "first_seen": observed_at,
        "last_seen": observed_at,
        "threshold_warning": 5_000.0,
        "threshold_critical": 5_000.0,
        "automatic_mitigation_threshold": 5_000.0,
        "metric": "packets_s",
        "comparison": "over",
        "metric_value": float(pps),
        "matched": True,
        "response": "DETECTION_ONLY",
    }


class DnsSingleFlowOutboundTest(unittest.TestCase):
    def query_items(self, rows, rule=None):
        captured = {}

        def fake_query(query, params):
            captured["query"] = query
            captured["params"] = dict(params)
            return FakeClickHouseResult(DNS_COLUMNS, rows)

        flow_time = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query), mock.patch.object(
            backend_main,
            "clickhouse_sample_rate_expr",
            return_value="greatest(toFloat64(sample_rate), 1.0)",
        ):
            items = backend_main.query_detection_rule_candidates(
                {"id": 7, "name": "Clientes"},
                {"id": 8, "name": "CLIENTES-PUBLICOS-DEFAULT", "active": True},
                rule or dns_single_flow_rule(),
                {"id": 11, "cidr": "45.5.248.0/24"},
                flow_time - timedelta(seconds=60),
                flow_time,
                None,
            )
        return items, captured

    def test_threshold_protocol_port_and_real_conversation_grouping(self):
        below, captured = self.query_items([dns_row(4_999)])
        exact, _ = self.query_items([dns_row(5_000)])
        high, _ = self.query_items([dns_row(11_000)])
        tcp, _ = self.query_items([dns_row(11_000, protocol="TCP")])
        wrong_port, _ = self.query_items([dns_row(11_000, dst_port=54)])

        self.assertEqual(below, [])
        self.assertEqual(len(exact), 1)
        self.assertEqual(exact[0]["severity"], "critical")
        self.assertEqual(exact[0]["metric_value"], 5_000)
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0]["severity"], "critical")
        self.assertEqual(high[0]["packets_s"], 11_000)
        self.assertEqual(tcp, [])
        self.assertEqual(wrong_port, [])

        query = captured["query"]
        self.assertIn("toUInt16(src_port) AS src_port", query)
        self.assertIn("GROUP BY bucket, src_ip, src_port, dst_ip, dst_port, protocol", query)
        self.assertIn("src_port AS top_src_port", query)
        self.assertIn("SELECT\n            src_ip,\n            src_port,", query)
        self.assertNotIn("argMax(src_port, packet_value * multiplier) AS top_src_port", query)
        self.assertIn("proto = 17", query)
        self.assertIn("dst_port = 53", query)

    def test_source_ports_are_not_summed_and_only_matching_conversation_fires(self):
        split, _ = self.query_items([dns_row(3_000, 2000), dns_row(3_000, 3000)])
        one_attack, _ = self.query_items([dns_row(6_000, 2000), dns_row(1_000, 3000)])

        self.assertEqual(split, [])
        self.assertEqual(len(one_attack), 1)
        self.assertEqual(one_attack[0]["top_src_port"], 2000)
        self.assertEqual(one_attack[0]["src_port"], 2000)
        self.assertEqual(one_attack[0]["packets_s"], 6_000)

    def test_detection_key_alone_enables_real_source_port_grouping(self):
        key_only_rule = dns_single_flow_rule()
        key_only_rule["group_by"] = ""
        items, captured = self.query_items([dns_row(6_000, 2811)], key_only_rule)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["src_port"], 2811)
        self.assertIn("GROUP BY bucket, src_ip, src_port, dst_ip, dst_port, protocol", captured["query"])
        self.assertNotIn("argMax(src_port, packet_value * multiplier) AS top_src_port", captured["query"])

    def test_legacy_dns_grouping_still_uses_argmax_for_source_port(self):
        legacy_rule = dns_single_flow_rule()
        legacy_rule.update(
            {
                "vector": "DNS_INTERNAL_IP_TO_DST_HIGH_PPS",
                "critical_value": 15_000,
                "detection_key": "DNS_INTERNAL_IP_TO_DST_HIGH_PPS",
                "group_by": "src_ip,dst_ip,dst_port,proto",
                "protocol": "DNS",
            }
        )
        items, captured = self.query_items([dns_row(6_000)], legacy_rule)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["severity"], "warning")
        self.assertIn("GROUP BY bucket, src_ip, dst_ip, internal_ip, protocol, dst_port", captured["query"])
        self.assertIn("argMax(src_port, packet_value * multiplier) AS top_src_port", captured["query"])
        self.assertNotIn("GROUP BY bucket, src_ip, src_port", captured["query"])

    def test_official_rule_grouping_dedup_temporal_gate_and_history(self):
        tmpdir = tempfile.mkdtemp()
        db_path = str(Path(tmpdir) / "gmjflow.db")
        try:
            with mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": db_path}, clear=False), mock.patch.object(
                backend_main, "SENSOR_DB_READY", False
            ), mock.patch.object(backend_main, "hash_password", return_value="test-hash"):
                backend_main.ensure_sensor_db()
                first_at = "2026-07-24T12:00:00Z"
                second_at = "2026-07-24T12:01:00Z"
                with backend_main.sqlite_connection() as conn:
                    rule = conn.execute(
                        """
                        SELECT *
                        FROM detection_template_rules
                        WHERE upper(vector) = ?
                        ORDER BY id
                        LIMIT 1
                        """,
                        (backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,),
                    ).fetchone()
                    self.assertIsNotNone(rule)
                    self.assertEqual(rule["display_name"], "Ataque DNS por fluxo único")
                    self.assertEqual(rule["domain"], "internal_ip")
                    self.assertEqual(rule["direction"], "transmits")
                    self.assertEqual(rule["protocol"], "UDP")
                    self.assertEqual(rule["metric"], "packets_s")
                    self.assertEqual(rule["warning_value"], 5_000)
                    self.assertEqual(rule["critical_value"], 5_000)
                    self.assertEqual(rule["detection_key"], "src_ip,src_port,dst_ip,dst_port,protocol")
                    self.assertEqual(rule["group_by"], "src_ip,src_port,dst_ip,dst_port,protocol")
                    self.assertEqual(rule["src_port"], "any")
                    self.assertEqual(rule["dst_port"], "53")
                    self.assertEqual(rule["response"], "DETECTION_ONLY")
                    self.assertEqual(rule["mitigation_mode"], "detection_only")
                    self.assertEqual(rule["mitigation_enabled"], 0)

                    first = persisted_candidate(first_at, 5_000, 2811)
                    first.update(
                        {
                            "zone_id": None,
                            "sensor_id": None,
                            "template_id": int(rule["template_id"]),
                            "rule_id": int(rule["id"]),
                        }
                    )
                    self.assertEqual(backend_main.upsert_detection_template_dns_anomaly_event(conn, first), "created")
                    row = conn.execute(
                        "SELECT * FROM anomaly_events WHERE vector_name = ?",
                        (backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,),
                    ).fetchone()
                    event_id = int(row["id"])
                    event = backend_main.anomaly_event_row_to_dict(row)
                    self.assertEqual(event["severity"], "critical")
                    self.assertEqual(event["classification"], "attack")
                    self.assertEqual(event["confidence_label"], "high")
                    self.assertEqual(event["timeseries_points"], 1)
                    self.assertEqual(event["critical_threshold"], 5_000)
                    gate = backend_main.detection_automatic_policy_gate(event)
                    self.assertFalse(gate["allowed"])
                    self.assertEqual(gate["reason"], "insufficient_time_series_evidence")

                    conn.commit()
                with mock.patch.object(backend_main, "exabgp_write_pipe") as fifo_write:
                    backend_main.process_anomaly_mitigation()
                    fifo_write.assert_not_called()
                with backend_main.sqlite_connection() as conn:
                    one_point = conn.execute("SELECT * FROM anomaly_events WHERE id = ?", (event_id,)).fetchone()
                    self.assertEqual(one_point["auto_mitigation_status"], "not_applied")
                    self.assertEqual(one_point["auto_mitigation_reason"], "insufficient_time_series_evidence")
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) AS count FROM bgp_announcements WHERE anomaly_id = ?",
                            (event_id,),
                        ).fetchone()["count"],
                        0,
                    )

                    second = persisted_candidate(second_at, 11_000, 2811)
                    second.update(
                        {
                            "zone_id": None,
                            "sensor_id": None,
                            "template_id": int(rule["template_id"]),
                            "rule_id": int(rule["id"]),
                        }
                    )
                    self.assertEqual(backend_main.upsert_detection_template_dns_anomaly_event(conn, second), "updated")
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) AS count FROM anomaly_events WHERE vector_name = ? AND top_src_port = 2811",
                            (backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,),
                        ).fetchone()["count"],
                        1,
                    )
                    updated = conn.execute("SELECT * FROM anomaly_events WHERE id = ?", (event_id,)).fetchone()
                    event = backend_main.anomaly_event_row_to_dict(updated)
                    self.assertEqual(event["observed_value"], 11_000)
                    self.assertEqual(event["peak_value"], 11_000)
                    self.assertEqual(event["timeseries_points"], 2)
                    self.assertEqual(event["started_at"], first_at)
                    self.assertEqual(event["last_seen_at"], second_at)
                    self.assertGreater(event["estimated_packets"], int(11_000 * 60))
                    self.assertGreater(event["estimated_bytes"], 0)
                    self.assertEqual(event["flow_count"], 2)
                    self.assertEqual(event["top_src_port"], 2811)
                    self.assertEqual(event["top_dst_port"], 53)

                    context = backend_main.fetch_anomaly_mitigation_context(conn, event_id)
                    candidate = backend_main.dns_single_flow_manual_candidate(conn, context["event"], context["flows"], 0.99)
                    self.assertIsNotNone(candidate)
                    self.assertEqual(candidate["src_cidr"], "45.5.248.196/32")
                    self.assertEqual(candidate["dst_cidr"], "195.136.19.76/32")
                    self.assertEqual(candidate["protocol"], "udp")
                    self.assertEqual(candidate["dst_port"], "53")
                    self.assertEqual(candidate["src_port"], "")
                    self.assertEqual(candidate["top_flow"]["src_port"], 2811)
                    proposal = backend_main.deterministic_automatic_proposal_state(conn, candidate)
                    self.assertFalse(proposal["eligible"])
                    self.assertEqual(proposal["reason"], "profile_not_automatic")

                    other = persisted_candidate(second_at, 6_000, 3000)
                    other.update(
                        {
                            "zone_id": None,
                            "sensor_id": None,
                            "template_id": int(rule["template_id"]),
                            "rule_id": int(rule["id"]),
                        }
                    )
                    self.assertEqual(backend_main.upsert_detection_template_dns_anomaly_event(conn, other), "created")
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) AS count FROM anomaly_events WHERE vector_name = ?",
                            (backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,),
                        ).fetchone()["count"],
                        2,
                    )

                    conn.execute(
                        "UPDATE anomaly_events SET status = 'ended', ended_at = ? WHERE id = ?",
                        ("2026-07-24T12:02:00Z", event_id),
                    )
                    ended = backend_main.anomaly_event_row_to_dict(
                        conn.execute("SELECT * FROM anomaly_events WHERE id = ?", (event_id,)).fetchone()
                    )
                    self.assertEqual(ended["status"], "ended")
                    self.assertEqual(ended["severity"], "critical")
                    self.assertEqual(ended["critical_threshold"], 5_000)
                    self.assertEqual(ended["peak_value"], 11_000)
                    self.assertEqual(ended["top_flow"]["src_port"], 2811)
                    conn.commit()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_ai_cannot_supply_a_warning_severity_for_deterministic_event(self):
        payload = {
            "analysis_mode": "informational",
            "anomaly": {
                "vector_name": backend_main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
                "severity": "critical",
                "classification": "attack",
            },
            "candidates": [],
        }
        with self.assertRaises(ValueError):
            backend_main.normalize_mitigation_ai_response(
                {
                    "apply_mitigation": False,
                    "reason": "tentativa de rebaixamento",
                    "severity": "warning",
                    "classification": "normal",
                },
                payload,
            )
        self.assertEqual(payload["anomaly"]["severity"], "critical")
        self.assertEqual(payload["anomaly"]["classification"], "attack")
        prompt = backend_main.build_mitigation_ai_prompt(payload)
        self.assertIn("never_change_deterministic_severity_or_classification", prompt)

    def test_frontend_saves_reopens_labels_and_draws_only_critical_threshold(self):
        self.assertIn(
            '<option value="src_ip,src_port,dst_ip,dst_port,protocol">Conversa completa</option>',
            FRONTEND,
        )
        self.assertIn("IP origem + porta origem + IP destino + porta destino + protocolo", FRONTEND)
        self.assertIn("group_by: selectValue('detectionRuleGroupBy')", FRONTEND)
        self.assertIn("setValue('detectionRuleGroupBy', rule?.group_by || rule?.detection_key || '')", FRONTEND)
        self.assertIn("Ataque DNS por fluxo único", FRONTEND)
        self.assertIn("isDnsSingleFlowOutbound(event)", FRONTEND)
        self.assertIn("...(!isDnsSingleFlowOutbound(event) ? [{ name: 'Warning'", FRONTEND)
        self.assertIn("{ name: 'Critical', value: event.critical_threshold", FRONTEND)
        self.assertIn("['Porta de origem'", FRONTEND)
        self.assertIn("['PPS observado'", FRONTEND)
        self.assertIn("['Estado da mitigação'", FRONTEND)


if __name__ == "__main__":
    unittest.main()
