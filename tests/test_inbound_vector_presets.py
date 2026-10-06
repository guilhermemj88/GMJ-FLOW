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
        self.assertEqual(
            preset.warning_expr,
            "(bps >= 15M OR pps >= 3k) AND NOT (bps > 80M OR pps > 20k)",
        )
        self.assertEqual(
            preset.critical_expr,
            "(bps >= 30M OR pps >= 8k) AND NOT (bps > 80M OR pps > 20k)",
        )
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


def legacy_dns_amp_severities(bps: float, pps: float) -> tuple[str, ...]:
    """Faixas reais das 2 regras legadas DNS_AMP_INBOUND (comparison=over => estritamente maior)."""
    severities: list[str] = []
    if bps > 80_000_000.0:
        severities.append("BITS-warning")
    if bps > 100_000_000.0:
        severities.append("BITS-critical")
    if pps > 20_000.0:
        severities.append("PPS-warning")
    if pps > 40_000.0:
        severities.append("PPS-critical")
    return tuple(severities)


DNS_BAND_SPLIT_BOUNDARY_CASES = (
    # caso, bps, pps, severidade esperada do preset band-split, legados esperados
    ("10 Mbps / 1 kpps", 10_000_000.0, 1_000.0, None, ()),
    ("15 Mbps / 3 kpps", 15_000_000.0, 3_000.0, "warning", ()),
    ("20 Mbps / 4 kpps", 20_000_000.0, 4_000.0, "warning", ()),
    ("29 Mbps / 7 kpps", 29_000_000.0, 7_000.0, "warning", ()),
    ("30 Mbps / 8 kpps", 30_000_000.0, 8_000.0, "critical", ()),
    ("50 Mbps / 10 kpps", 50_000_000.0, 10_000.0, "critical", ()),
    ("79 Mbps / 19 kpps", 79_000_000.0, 19_000.0, "critical", ()),
    ("85 Mbps / 5 kpps", 85_000_000.0, 5_000.0, None, ("BITS-warning",)),
    ("50 Mbps / 25 kpps", 50_000_000.0, 25_000.0, None, ("PPS-warning",)),
    ("85 Mbps / 25 kpps", 85_000_000.0, 25_000.0, None, ("BITS-warning", "PPS-warning")),
    (
        "120 Mbps / 50 kpps",
        120_000_000.0,
        50_000.0,
        None,
        ("BITS-warning", "BITS-critical", "PPS-warning", "PPS-critical"),
    ),
    ("exato 80 Mbps / 1 kpps", 80_000_000.0, 1_000.0, "critical", ()),
    ("80 Mbps + 1 / 1 kpps", 80_000_001.0, 1_000.0, None, ("BITS-warning",)),
    ("exato 20 kpps / 1 Mbps", 1_000_000.0, 20_000.0, "critical", ()),
    ("20 kpps + 1 / 1 Mbps", 1_000_000.0, 20_001.0, None, ("PPS-warning",)),
    ("exato 100 Mbps / 1 kpps", 100_000_000.0, 1_000.0, None, ("BITS-warning",)),
    ("100 Mbps + 1 / 1 kpps", 100_000_001.0, 1_000.0, None, ("BITS-warning", "BITS-critical")),
    ("exato 40 kpps / 1 Mbps", 1_000_000.0, 40_000.0, None, ("PPS-warning",)),
    ("40 kpps + 1 / 1 Mbps", 1_000_000.0, 40_001.0, None, ("PPS-warning", "PPS-critical")),
)


class DnsReflectionBandSplitTest(unittest.TestCase):
    """Fase 4.2: o preset single cobre a faixa sensivel e cede a faixa dos legados."""

    def band_evaluator(self):
        preset = inbound_vectors.get_preset("dns_reflection")
        evaluator = detection_triggers.evaluator_for(preset.warning_expr, preset.critical_expr)
        self.assertIsNotNone(evaluator)
        return evaluator

    def band_severity(self, evaluator, bps: float, pps: float):
        return evaluator.evaluate(detection_triggers.frame_metrics({"bits_s": bps, "packets_s": pps}))

    def test_dns_reflection_single_uses_band_split_expressions(self):
        preset = inbound_vectors.get_preset("dns_reflection")
        expected_warning = "(bps >= 15M OR pps >= 3k) AND NOT (bps > 80M OR pps > 20k)"
        expected_critical = "(bps >= 30M OR pps >= 8k) AND NOT (bps > 80M OR pps > 20k)"
        self.assertEqual(preset.warning_expr, expected_warning)
        self.assertEqual(preset.critical_expr, expected_critical)
        payload = inbound_vectors.preset_rule_payload(preset)
        canonical_warning, warning_issues = detection_triggers.canonicalize_trigger_expression(
            payload["trigger_warning_expr"]
        )
        canonical_critical, critical_issues = detection_triggers.canonicalize_trigger_expression(
            payload["trigger_critical_expr"]
        )
        self.assertEqual(warning_issues, [])
        self.assertEqual(critical_issues, [])
        self.assertEqual(canonical_warning, expected_warning)
        self.assertEqual(canonical_critical, expected_critical)

    def test_boundary_matrix_matches_plan(self):
        evaluator = self.band_evaluator()
        for name, bps, pps, expected_band, expected_legacy in DNS_BAND_SPLIT_BOUNDARY_CASES:
            with self.subTest(case=name):
                self.assertEqual(self.band_severity(evaluator, bps, pps), expected_band)
                self.assertEqual(legacy_dns_amp_severities(bps, pps), expected_legacy)

    def test_no_overlap_and_no_gap_between_band_split_and_legacy_rules(self):
        evaluator = self.band_evaluator()
        base = detection_triggers.evaluator_for("bps >= 15M OR pps >= 3k", "bps >= 30M OR pps >= 8k")
        self.assertIsNotNone(base)
        bps_points = (79_000_000.0, 80_000_000.0, 80_000_001.0, 99_999_999.0, 100_000_000.0, 100_000_001.0, 120_000_000.0)
        pps_points = (19_999.0, 20_000.0, 20_001.0, 39_999.0, 40_000.0, 40_001.0, 50_000.0)
        checked = 0
        for bps in bps_points:
            for pps in pps_points:
                metrics = detection_triggers.frame_metrics({"bits_s": bps, "packets_s": pps})
                band = evaluator.evaluate(metrics)
                base_severity = base.evaluate(metrics)
                legacy = legacy_dns_amp_severities(bps, pps)
                checked += 1
                self.assertFalse(band is not None and legacy, f"overlap novo x legado em bps={bps} pps={pps}")
                self.assertFalse(
                    base_severity is not None and band is None and not legacy,
                    f"gap do band-split em bps={bps} pps={pps}",
                )
        self.assertEqual(checked, len(bps_points) * len(pps_points))

    def test_exact_legacy_boundaries_follow_strict_over_operator(self):
        evaluator = self.band_evaluator()
        self.assertEqual(
            self.band_severity(evaluator, 80_000_000.0, 1_000.0),
            "critical",
        )
        self.assertEqual(
            self.band_severity(evaluator, 1_000_000.0, 20_000.0),
            "critical",
        )
        self.assertIsNone(self.band_severity(evaluator, 80_000_001.0, 1_000.0))
        self.assertIsNone(self.band_severity(evaluator, 1_000_000.0, 20_001.0))


def issue_text(issues) -> str:
    return "; ".join(f"{issue.get('code')}: {issue.get('message')}" for issue in issues)


if __name__ == "__main__":
    unittest.main()
