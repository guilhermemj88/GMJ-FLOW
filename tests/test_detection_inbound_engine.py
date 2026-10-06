"""Testes do motor de vetores inbound (Fase 4) — integracao com app.main.

Exercita `query_detection_rule_candidates` com ClickHouse mockado para provar:
triggers booleanos (OR/AND composto), cardinalidades (unique_src_ips),
avg_packet_bytes, single target (dst_ip) x multi-target (prefix/subnet),
protocolos TCP com flags (SYN sem ACK, SYN+ACK, ACK sem SYN) e a ausencia de
regressao no caminho legado das 28 regras atuais.
"""
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services import detection_triggers, inbound_vectors  # noqa: E402
from tests.test_collector_apply_static import backend_main  # noqa: E402

NOW = datetime(2026, 10, 6, 16, 0, tzinfo=timezone.utc)

COLUMNS = [
    "src_ip", "dst_ip", "internal_ip", "protocol", "dst_port", "top_dst_port", "top_src_port",
    "bytes", "packets", "flows", "bits_s", "packets_s", "flows_s",
    "unique_dst_ips", "unique_dst_ports", "unique_src_ports", "unique_src_ips",
    "first_seen", "last_seen", "metric_value",
]

DEFAULTS = {
    "src_ip": "203.0.113.9",
    "dst_ip": "189.5.0.10",
    "internal_ip": "189.5.0.10",
    "protocol": "UDP",
    "dst_port": 0,
    "top_dst_port": 0,
    "top_src_port": 53,
    "bytes": 400_000_000,
    "packets": 400_000,
    "flows": 500,
    "bits_s": 16_000_000.0,
    "packets_s": 4_000.0,
    "flows_s": 20.0,
    "unique_dst_ips": 1,
    "unique_dst_ports": 1,
    "unique_src_ports": 1337,
    "unique_src_ips": 2941,
    "first_seen": NOW,
    "last_seen": NOW,
    "metric_value": 16_000_000.0,
}


def make_row(**overrides):
    data = {**DEFAULTS, **overrides}
    return tuple(data[name] for name in COLUMNS)


class FakeClickHouseResult:
    def __init__(self, columns, rows):
        self.column_names = list(columns)
        self.result_rows = list(rows)


def rule_from_preset(preset_id: str, multi: bool = False, **overrides):
    preset = inbound_vectors.get_preset(preset_id)
    payload = inbound_vectors.preset_rule_payload(preset, multi=multi)
    rule = dict(payload)
    rule.update(
        {
            "id": 901,
            "detection_key": payload.get("group_by", ""),
            "mitigation_mode": "detection_only",
            "mitigation_enabled": 0,
            "enabled": True,
            "sensor_id": None,
        }
    )
    rule.update(overrides)
    return rule


def legacy_rule(**overrides):
    rule = {
        "id": 42,
        "vector": "LEGACY_PREFIX_UDP_PPS",
        "display_name": "Legacy",
        "domain": "internal_ip",
        "direction": "receives",
        "protocol": "UDP",
        "metric": "packets_s",
        "comparison": "over",
        "warning_value": 10_000.0,
        "critical_value": 50_000.0,
        "window_seconds": 60,
        "group_by": "dst_ip",
        "detection_key": "dst_ip",
        "src_port": "any",
        "dst_port": "any",
        "trigger_warning_expr": "",
        "trigger_critical_expr": "",
        "evidence": "",
        "response": "DETECTION_ONLY",
        "mitigation_mode": "detection_only",
        "mitigation_enabled": 0,
        "enabled": True,
        "sensor_id": None,
    }
    rule.update(overrides)
    return rule


def run_rule(rule, rows, prefix=None):
    calls = []

    def fake_query_clickhouse(query, params):
        calls.append((query, dict(params)))
        return FakeClickHouseResult(COLUMNS, rows)

    zone = {"id": 1, "name": "ZONA-TESTE"}
    template = {"id": 1, "name": "TPL-TESTE", "active": True}
    prefix = prefix or {"id": 7, "cidr": "189.5.0.0/24"}
    with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse), mock.patch.object(
        backend_main, "clickhouse_sample_rate_expr", return_value="greatest(sample_rate, 1)"
    ):
        items = backend_main.query_detection_rule_candidates(
            zone, template, rule, prefix, NOW, NOW, None, include_unmatched=True
        )
    return items, calls


class TriggerEngineTest(unittest.TestCase):
    def test_detection_triggers_identity_with_main_binding(self):
        self.assertIs(backend_main.detection_triggers, detection_triggers)

    def test_dns_reflection_single_matches_warning_and_critical(self):
        rule = rule_from_preset("dns_reflection")
        rows = [
            make_row(bits_s=16_000_000.0, packets_s=4_000.0, metric_value=16_000_000.0),
            make_row(bits_s=31_000_000.0, packets_s=5_000.0, metric_value=31_000_000.0),
            make_row(bits_s=10_000_000.0, packets_s=1_000.0, metric_value=10_000_000.0),
        ]
        items, calls = run_rule(rule, rows)
        self.assertEqual([item["matched"] for item in items], [True, True, False])
        self.assertEqual([item["severity"] for item in items[:2]], ["warning", "critical"])
        self.assertEqual(items[0]["avg_packet_bytes"], 1000.0)
        self.assertEqual(items[0]["unique_src_ips"], 2941)
        sql = calls[0][0]
        self.assertIn("uniqExact(unique_src_ip_value)", sql)
        self.assertIn("toString(flow_raw.src_ip) AS unique_src_ip_value", sql)
        self.assertIn("toString(flow_raw.dst_ip) AS dst_ip", sql)

    def test_dns_reflection_band_split_leaves_legacy_warning_band_to_legacy_rules(self):
        rule = rule_from_preset("dns_reflection")
        rows = [
            make_row(bits_s=85_000_000.0, packets_s=5_000.0, metric_value=85_000_000.0),
            make_row(bits_s=80_000_000.0, packets_s=1_000.0, metric_value=80_000_000.0),
            make_row(bits_s=50_000_000.0, packets_s=25_000.0, metric_value=50_000_000.0),
            make_row(bits_s=20_000_000.0, packets_s=4_000.0, metric_value=20_000_000.0),
        ]
        items, _ = run_rule(rule, rows)
        self.assertEqual([item["matched"] for item in items], [False, True, False, True])
        self.assertEqual(items[1]["severity"], "critical")
        self.assertEqual(items[3]["severity"], "warning")

    def test_legacy_dns_amp_over_comparison_is_strict(self):
        self.assertFalse(backend_main.comparison_matches(80_000_000.0, 80_000_000.0, "over"))
        self.assertTrue(backend_main.comparison_matches(80_000_001.0, 80_000_000.0, "over"))
        self.assertFalse(backend_main.comparison_matches(20_000.0, 20_000.0, "over"))
        self.assertTrue(backend_main.comparison_matches(20_001.0, 20_000.0, "over"))
        self.assertFalse(backend_main.comparison_matches(100_000_000.0, 100_000_000.0, "over"))
        self.assertTrue(backend_main.comparison_matches(100_000_001.0, 100_000_000.0, "over"))
        self.assertFalse(backend_main.comparison_matches(40_000.0, 40_000.0, "over"))
        self.assertTrue(backend_main.comparison_matches(40_001.0, 40_000.0, "over"))

    def test_dns_reflection_multi_target_carpet_bombing(self):
        rule = rule_from_preset("dns_reflection", multi=True)
        rows = [
            make_row(bits_s=60_000_000.0, unique_dst_ips=5, metric_value=60_000_000.0),
            make_row(bits_s=60_000_000.0, unique_dst_ips=8, metric_value=60_000_000.0),
            make_row(bits_s=110_000_000.0, unique_dst_ips=16, metric_value=110_000_000.0),
        ]
        items, calls = run_rule(rule, rows)
        self.assertEqual([item["matched"] for item in items], [False, True, True])
        self.assertEqual([item["severity"] for item in items[1:]], ["warning", "critical"])
        sql = calls[0][0]
        self.assertIn("uniqExact(unique_dst_ip_value)", sql)
        self.assertIn("uniqExact(unique_src_ip_value)", sql)
        self.assertIn("GROUP BY bucket, src_ip, dst_ip, internal_ip, protocol", sql)
        self.assertIn("CAST(NULL, 'Nullable(String)')", sql)

    def test_unique_src_ips_trigger(self):
        rule = rule_from_preset("dns_reflection", trigger_warning_expr="unique_src_ips >= 3000", trigger_critical_expr="")
        rows = [make_row(unique_src_ips=2941), make_row(unique_src_ips=3100)]
        items, _ = run_rule(rule, rows)
        self.assertEqual([item["matched"] for item in items], [False, True])
        self.assertEqual(items[1]["severity"], "warning")

    def test_avg_packet_bytes_trigger_uses_sum_ratio(self):
        rule = rule_from_preset(
            "dns_reflection",
            trigger_warning_expr="avg_packet_bytes >= 400",
            trigger_critical_expr="avg_packet_bytes >= 1200",
        )
        rows = [
            make_row(bytes=200_000, packets=400, metric_value=200_000.0),
            make_row(bytes=600_000, packets=400, metric_value=600_000.0),
            make_row(bytes=120_000, packets=400, metric_value=120_000.0),
        ]
        items, _ = run_rule(rule, rows)
        self.assertEqual([item["matched"] for item in items], [True, True, False])
        self.assertEqual([item["severity"] for item in items[:2]], ["warning", "critical"])
        self.assertEqual(items[0]["avg_packet_bytes"], 500.0)

    def test_evidence_values_snapshot(self):
        rule = rule_from_preset("dns_reflection")
        items, _ = run_rule(rule, [make_row()])
        evidence = items[0]["evidence_values"]
        self.assertEqual(evidence["bits_s"], 16_000_000.0)
        self.assertEqual(evidence["packets_s"], 4_000.0)
        self.assertEqual(evidence["avg_packet_bytes"], 1000.0)
        self.assertEqual(evidence["unique_src_ips"], 2941)

    def test_tcp_syn_flood_preset_uses_flags_and_pps(self):
        rule = rule_from_preset("tcp_syn_flood")
        self.assertEqual(rule["protocol"], "TCP+SYN-NO-ACK")
        rows = [
            make_row(packets_s=60_000.0, metric_value=60_000.0),
            make_row(packets_s=160_000.0, metric_value=160_000.0),
            make_row(packets_s=40_000.0, metric_value=40_000.0),
        ]
        items, calls = run_rule(rule, rows)
        self.assertEqual([item["matched"] for item in items], [True, True, False])
        self.assertEqual([item["severity"] for item in items[:2]], ["warning", "critical"])
        sql = calls[0][0]
        self.assertIn("proto = 6", sql)
        self.assertIn("bitAnd(tcp_flags, 2) != 0 AND bitAnd(tcp_flags, 16) = 0", sql)

    def test_ack_flood_preset_uses_ack_without_syn(self):
        rule = rule_from_preset("tcp_ack_flood")
        _, calls = run_rule(rule, [make_row(packets_s=120_000.0, metric_value=120_000.0)])
        sql = calls[0][0]
        self.assertIn("bitAnd(tcp_flags, 16) != 0 AND bitAnd(tcp_flags, 2) = 0", sql)

    def test_legacy_rule_path_is_unchanged(self):
        rule = legacy_rule()
        rows = [
            make_row(packets_s=15_000.0, metric_value=15_000.0),
            make_row(packets_s=60_000.0, metric_value=60_000.0),
            make_row(packets_s=5_000.0, metric_value=5_000.0),
        ]
        items, calls = run_rule(rule, rows)
        self.assertEqual([item["matched"] for item in items], [True, True, False])
        self.assertEqual([item["severity"] for item in items[:2]], ["warning", "critical"])
        self.assertEqual(items[0]["trigger_warning_expr"], "")
        sql = calls[0][0]
        self.assertIn("toUInt64(1) AS unique_dst_ips", sql)

    def test_no_expression_trigger_keeps_zero_threshold_guard(self):
        rule = legacy_rule(warning_value=0.0, critical_value=0.0)
        items, calls = run_rule(rule, [make_row()])
        self.assertEqual(items, [])
        self.assertEqual(calls, [])


class ProtocolConditionTest(unittest.TestCase):
    def test_new_tcp_flags_conditions(self):
        expected = {
            "TCP+SYN-NO-ACK": "bitAnd(tcp_flags, 2) != 0 AND bitAnd(tcp_flags, 16) = 0",
            "TCP+SYNACK": "bitAnd(tcp_flags, 2) != 0 AND bitAnd(tcp_flags, 16) != 0",
            "TCP+ACK-NO-SYN": "bitAnd(tcp_flags, 16) != 0 AND bitAnd(tcp_flags, 2) = 0",
            "TCP+ACK": "bitAnd(tcp_flags, 16) != 0",
            "TCP+RST": "bitAnd(tcp_flags, 4) != 0",
            "TCP+NULL": "tcp_flags = 0",
            "TCP+ALL": "proto = 6",
        }
        for protocol, fragment in expected.items():
            self.assertIn(protocol, backend_main.DETECTION_PROTOCOLS, protocol)
            self.assertIn(fragment, backend_main.detection_protocol_condition(protocol), protocol)

    def test_legacy_tcp_syn_condition_unchanged(self):
        self.assertEqual(
            backend_main.detection_protocol_condition("TCP+SYN"),
            "proto = 6 AND bitAnd(tcp_flags, 2) != 0",
        )

    def test_new_metrics_available(self):
        self.assertIn("unique_src_ips", backend_main.DETECTION_METRICS)
        self.assertIn("avg_packet_bytes", backend_main.DETECTION_METRICS)
        self.assertEqual(backend_main.metric_expression_for_detection("unique_src_ips"), "unique_src_ips")
        self.assertEqual(
            backend_main.metric_expression_for_detection("avg_packet_bytes"),
            "if(packets > 0, bytes / packets, 0)",
        )


class SavePathValidationTest(unittest.TestCase):
    def _normalize(self, payload: dict):
        model = backend_main.DetectionRulePayload(**payload)
        return backend_main.normalize_detection_rule_payload(model)

    def test_single_payload_canonicalizes_trigger(self):
        payload = dict(inbound_vectors.preset_rule_payload(inbound_vectors.get_preset("dns_reflection")))
        data = self._normalize(payload)
        self.assertEqual(
            data["trigger_warning_expr"],
            "(bps >= 15M OR pps >= 3k) AND NOT (bps > 80M OR pps > 20k)",
        )
        self.assertEqual(
            data["trigger_critical_expr"],
            "(bps >= 30M OR pps >= 8k) AND NOT (bps > 80M OR pps > 20k)",
        )
        self.assertEqual(data["evidence"], "bits_s,packets_s,flows_s,avg_packet_bytes,unique_src_ips,unique_src_ports,unique_dst_ips")
        self.assertEqual(data["metric"], "bits_s")
        self.assertEqual(data["direction"], "receives")

    def test_multi_payload_canonicalizes_carpet_trigger(self):
        payload = dict(
            inbound_vectors.preset_rule_payload(inbound_vectors.get_preset("dns_reflection"), multi=True)
        )
        data = self._normalize(payload)
        self.assertEqual(
            data["trigger_warning_expr"],
            "(bps >= 50M OR pps >= 10k) AND unique_dst_ips >= 8",
        )
        self.assertEqual(data["domain"], "subnet")
        self.assertEqual(data["group_by"], "")

    def test_all_preset_payloads_pass_save_validation(self):
        for preset, multi in inbound_vectors.iter_preset_variants():
            payload = dict(inbound_vectors.preset_rule_payload(preset, multi=multi))
            data = self._normalize(payload)
            canonical, issues = detection_triggers.canonicalize_trigger_expression(data["trigger_warning_expr"])
            self.assertEqual(issues, [], f"{preset.id}")
            self.assertEqual(canonical, data["trigger_warning_expr"])

    def test_invalid_trigger_expression_rejected_with_code(self):
        payload = dict(inbound_vectors.preset_rule_payload(inbound_vectors.get_preset("dns_reflection")))
        payload["trigger_warning_expr"] = "src_ip == 1.2.3.4"
        with self.assertRaises(Exception) as caught:
            self._normalize(payload)
        exc = caught.exception
        self.assertEqual(getattr(exc, "status_code", None), 400)
        detail = getattr(exc, "detail", {})
        self.assertEqual(detail.get("code"), "INVALID_TRIGGER_EXPRESSION")
        self.assertEqual(detail["errors"][0]["code"], "FIELD_NOT_ALLOWED_IN_SECTION")

    def test_trigger_without_numeric_values_is_accepted(self):
        payload = dict(inbound_vectors.preset_rule_payload(inbound_vectors.get_preset("dns_reflection")))
        payload["warning_value"] = None
        payload["critical_value"] = None
        data = self._normalize(payload)
        self.assertEqual(
            data["trigger_warning_expr"],
            "(bps >= 15M OR pps >= 3k) AND NOT (bps > 80M OR pps > 20k)",
        )

    def test_no_trigger_and_no_values_is_rejected(self):
        payload = dict(inbound_vectors.preset_rule_payload(inbound_vectors.get_preset("dns_reflection")))
        payload["warning_value"] = None
        payload["critical_value"] = None
        payload["trigger_warning_expr"] = ""
        payload["trigger_critical_expr"] = ""
        with self.assertRaises(Exception) as caught:
            self._normalize(payload)
        self.assertEqual(getattr(caught.exception, "status_code", None), 400)

    def test_evidence_aliases_are_canonicalized(self):
        payload = dict(inbound_vectors.preset_rule_payload(inbound_vectors.get_preset("dns_reflection")))
        payload["evidence"] = "bps,pps,flows,avg_packet_bytes"
        data = self._normalize(payload)
        self.assertEqual(data["evidence"], "bits_s,packets_s,flows_s,avg_packet_bytes")

    def test_invalid_evidence_rejected(self):
        payload = dict(inbound_vectors.preset_rule_payload(inbound_vectors.get_preset("dns_reflection")))
        payload["evidence"] = "banana"
        with self.assertRaises(Exception) as caught:
            self._normalize(payload)
        self.assertEqual(getattr(caught.exception, "status_code", None), 400)


if __name__ == "__main__":
    unittest.main()
