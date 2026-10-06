"""Testes do motor de triggers booleanos do detector (Fase 4).

Cobrem: canonicalizacao DSL, avaliacao OR/AND/NOT, unidades k/M/G, aliases
(pps/bps/flows), cardinalidades, avg_packet_bytes derivado e erros estruturados.
Modulo puro (stdlib + detection_dsl) — nao precisa de banco nem ClickHouse.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services import detection_triggers  # noqa: E402


def _eval(warning: str = "", critical: str = "", **metrics):
    evaluator = detection_triggers.evaluator_for(warning, critical)
    assert evaluator is not None
    return evaluator.evaluate(detection_triggers.frame_metrics(metrics))


class CanonicalizationTest(unittest.TestCase):
    def test_canonical_keeps_metric_units(self):
        canonical, issues = detection_triggers.canonicalize_trigger_expression("bps >= 15M OR pps >= 3k")
        self.assertEqual(issues, [])
        self.assertEqual(canonical, "bps >= 15M OR pps >= 3k")

    def test_canonical_composite_with_parentheses(self):
        text = "(bps >= 50M OR pps >= 10k) AND unique_dst_ips >= 8"
        canonical, issues = detection_triggers.canonicalize_trigger_expression(text)
        self.assertEqual(issues, [])
        self.assertEqual(canonical, text)

    def test_canonical_is_idempotent(self):
        canonical, _ = detection_triggers.canonicalize_trigger_expression(
            "(bps >= 50M OR pps >= 10k) AND unique_dst_ips >= 8"
        )
        again, issues = detection_triggers.canonicalize_trigger_expression(canonical)
        self.assertEqual(issues, [])
        self.assertEqual(again, canonical)

    def test_aliases_are_canonicalized(self):
        canonical, issues = detection_triggers.canonicalize_trigger_expression("flows >= 10")
        self.assertEqual(issues, [])
        self.assertEqual(canonical, "flows >= 10")

    def test_empty_expression_is_noop(self):
        self.assertEqual(detection_triggers.canonicalize_trigger_expression(""), ("", []))
        self.assertEqual(detection_triggers.canonicalize_trigger_expression(None), ("", []))
        self.assertIsNone(detection_triggers.evaluator_for("", ""))

    def test_match_field_is_rejected_in_trigger(self):
        canonical, issues = detection_triggers.canonicalize_trigger_expression("src_ip == 1.2.3.4")
        self.assertEqual(canonical, "")
        self.assertEqual([issue["code"] for issue in issues], ["FIELD_NOT_ALLOWED_IN_SECTION"])

    def test_syntax_error_is_reported_as_issue(self):
        canonical, issues = detection_triggers.canonicalize_trigger_expression("bps >>> 15M")
        self.assertEqual(canonical, "")
        self.assertTrue(issues)
        self.assertIn("code", issues[0])

    def test_avg_packet_bytes_allowed_as_trigger(self):
        canonical, issues = detection_triggers.canonicalize_trigger_expression("avg_packet_bytes >= 1000")
        self.assertEqual(issues, [])
        self.assertEqual(canonical, "avg_packet_bytes >= 1000")


class EvaluationTest(unittest.TestCase):
    def test_or_warning_boundaries(self):
        expr = "bps >= 15M OR pps >= 3k"
        self.assertIsNone(_eval(expr, "", bits_s=14_999_999, packets_s=2_999))
        self.assertEqual(_eval(expr, "", bits_s=15_000_000, packets_s=0), "warning")
        self.assertEqual(_eval(expr, "", bits_s=0, packets_s=3_000), "warning")

    def test_critical_precedence(self):
        warning = "bps >= 15M OR pps >= 3k"
        critical = "bps >= 30M OR pps >= 8k"
        self.assertEqual(_eval(warning, critical, bits_s=15_000_000), "warning")
        self.assertEqual(_eval(warning, critical, bits_s=30_000_000), "critical")
        self.assertEqual(_eval(warning, critical, packets_s=8_000), "critical")

    def test_composite_and_or(self):
        warning = "(bps >= 50M OR pps >= 10k) AND unique_dst_ips >= 8"
        self.assertIsNone(_eval(warning, "", bits_s=60_000_000, unique_dst_ips=7))
        self.assertIsNone(_eval(warning, "", bits_s=49_000_000, packets_s=9_000, unique_dst_ips=16))
        self.assertEqual(_eval(warning, "", bits_s=60_000_000, unique_dst_ips=8), "warning")
        self.assertEqual(_eval(warning, "", packets_s=11_000, unique_dst_ips=9), "warning")

    def test_unique_src_ips_metric(self):
        self.assertEqual(_eval("unique_src_ips >= 500", "", unique_src_ips=500), "warning")
        self.assertIsNone(_eval("unique_src_ips >= 500", "", unique_src_ips=499))

    def test_not_node(self):
        self.assertEqual(
            _eval("NOT unique_dst_ips >= 3", "", unique_dst_ips=2),
            "warning",
        )

    def test_avg_packet_bytes_derived_from_bytes_and_packets(self):
        evaluator = detection_triggers.evaluator_for("avg_packet_bytes >= 400", "")
        assert evaluator is not None
        frame = {"bytes": 200_000, "packets": 400}
        self.assertEqual(evaluator.evaluate(detection_triggers.frame_metrics(frame)), "warning")
        frame = {"bytes": 100_000, "packets": 400}
        self.assertIsNone(evaluator.evaluate(detection_triggers.frame_metrics(frame)))

    def test_avg_packet_bytes_zero_packets_is_zero(self):
        metrics = detection_triggers.frame_metrics({"bytes": 1000, "packets": 0})
        self.assertEqual(metrics["avg_packet_bytes"], 0.0)

    def test_in_list_and_between(self):
        self.assertEqual(_eval("pps IN [3000, 5000]", "", packets_s=5_000), "warning")
        self.assertIsNone(_eval("pps IN [3000, 5000]", "", packets_s=4_000))
        self.assertEqual(_eval("pps BETWEEN 3k AND 5k", "", packets_s=4_000), "warning")

    def test_frame_metrics_defaults_missing_to_zero(self):
        metrics = detection_triggers.frame_metrics({})
        for field in detection_triggers.TRIGGER_FRAME_KEYS:
            self.assertEqual(metrics[field], 0.0)


if __name__ == "__main__":
    unittest.main()
