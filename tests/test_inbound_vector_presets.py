"""Testes do catalogo de presets inbound/download (Fase 4).

Valida: 11 presets na ordem canonica (A..K), triggers DSL canonicalizaveis,
modos single/multi justificados, thresholds default do plano (DNS 15M/3k,
DNS Query Flood 5k, carpet 50M/10k + unique_dst_ips >= 8), EVIDENCE valida,
payloads DESABILITADOS e independencia total das 2 regras DNS inbound produtivas.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services import detection_dsl, detection_triggers, inbound_vectors  # noqa: E402

ENGINE_METRICS = {
    "packets_s", "bits_s", "flows_s", "flows", "unique_src_ips",
    "unique_dst_ips", "unique_src_ports", "unique_dst_ports", "avg_packet_bytes",
}
PRODUCTION_DNS_RULES = {"DNS_AMP_INBOUND_HIGH_BITS", "DNS_AMP_INBOUND_HIGH_PPS"}

EXPECTED_ORDER = (
    "dns_reflection",
    "dns_query_flood",
    "ntp_reflection",
    "ssdp_reflection",
    "cldap_reflection",
    "memcached_amplification",
    "udp_flood",
    "tcp_syn_flood",
    "tcp_synack_flood",
    "tcp_ack_flood",
    "icmp_flood",
)


class PresetCatalogTest(unittest.TestCase):
    def test_eleven_presets_in_plan_order(self):
        presets = inbound_vectors.list_presets()
        self.assertEqual(len(presets), 11)
        self.assertEqual(tuple(preset.id for preset in presets), EXPECTED_ORDER)

    def test_vector_names_do_not_collide_with_production_rules(self):
        for preset in inbound_vectors.list_presets():
            for name in (preset.vector_name(False), preset.vector_name(True)):
                self.assertNotIn(name, PRODUCTION_DNS_RULES)

    def test_presets_never_reference_legacy_dns_amp_rules(self):
        source = Path(inbound_vectors.__file__).read_text(encoding="utf-8")
        self.assertNotIn("DNS_AMP_INBOUND", source)

    def test_every_trigger_expression_canonicalizes(self):
        for preset, multi in inbound_vectors.iter_preset_variants():
            for expr in (
                preset.warning_multi_expr if multi else preset.warning_expr,
                preset.critical_multi_expr if multi else preset.critical_expr,
            ):
                canonical, issues = detection_triggers.canonicalize_trigger_expression(expr)
                self.assertEqual(issues, [], f"{preset.id} multi={multi}: {issue_text(issues)}")
                self.assertTrue(canonical)

    def test_payloads_are_disabled_and_use_engine_metrics(self):
        for preset, multi in inbound_vectors.iter_preset_variants():
            payload = inbound_vectors.preset_rule_payload(preset, multi=multi)
            self.assertFalse(payload["enabled"])
            self.assertIn(payload["metric"], ENGINE_METRICS)
            self.assertEqual(payload["direction"], "receives")
            self.assertIn(payload["domain"], {"internal_ip", "subnet"})
            if multi:
                self.assertEqual(payload["domain"], "subnet")
            else:
                self.assertEqual(payload["domain"], "internal_ip")
                self.assertEqual(payload["group_by"], "dst_ip")
            canonical, issues = detection_triggers.canonicalize_trigger_expression(payload["trigger_warning_expr"])
            self.assertEqual(issues, [])
            self.assertEqual(canonical, payload["trigger_warning_expr"])

    def test_evidence_fields_are_valid_dsl_evidence(self):
        for preset in inbound_vectors.list_presets():
            self.assertTrue(preset.evidence, preset.id)
            for field_name in preset.evidence:
                spec = detection_dsl.FIELDS.get(field_name)
                self.assertIsNotNone(spec, f"{preset.id}: {field_name}")
                self.assertIn(detection_dsl.SECTION_EVIDENCE, spec.sections)

    def test_dns_reflection_defaults_match_plan(self):
        preset = inbound_vectors.get_preset("dns_reflection")
        self.assertEqual(preset.warning_expr, "bps >= 15M OR pps >= 3k")
        self.assertEqual(preset.critical_expr, "bps >= 30M OR pps >= 8k")
        self.assertEqual(preset.warning_multi_expr, "(bps >= 50M OR pps >= 10k) AND unique_dst_ips >= 8")
        self.assertEqual(preset.critical_multi_expr, "(bps >= 100M OR pps >= 20k) AND unique_dst_ips >= 16")

    def test_dns_query_flood_defaults_match_plan(self):
        preset = inbound_vectors.get_preset("dns_query_flood")
        self.assertEqual(preset.warning_expr, "bps >= 15M OR pps >= 5k")
        self.assertEqual(preset.critical_expr, "bps >= 30M OR pps >= 10k")
        self.assertFalse(preset.supports_multi())

    def test_multi_mode_is_justified_per_preset(self):
        for preset in inbound_vectors.list_presets():
            if preset.supports_multi():
                self.assertTrue(preset.multi_mode_note, preset.id)
            else:
                self.assertTrue(preset.multi_mode_note, preset.id)

    def test_reflection_ports_registry(self):
        self.assertEqual(inbound_vectors.REFLECTION_PORTS, (19, 53, 123, 137, 389, 1900, 3702, 5353, 11211))

    def test_preset_dsl_text_contains_all_sections(self):
        preset = inbound_vectors.get_preset("dns_reflection")
        text = inbound_vectors.preset_dsl_text(preset)
        for section in ("MATCH", "WARNING", "CRITICAL", "EVIDENCE", "ADVANCED"):
            self.assertIn(section, text)
        self.assertIn("direction == inbound", text)
        multi_text = inbound_vectors.preset_dsl_text(preset, multi=True)
        self.assertIn("unique_dst_ips >= 8", multi_text)

    def test_multi_payload_rejected_for_presets_without_multi(self):
        preset = inbound_vectors.get_preset("dns_query_flood")
        with self.assertRaises(ValueError):
            inbound_vectors.preset_rule_payload(preset, multi=True)


def issue_text(issues) -> str:
    return "; ".join(f"{issue.get('code')}: {issue.get('message')}" for issue in issues)


if __name__ == "__main__":
    unittest.main()
