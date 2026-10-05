"""Golden tests (DNS/NTP), round-trip AST e builder compatibility (Fase 3A)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services.detection_dsl import (  # noqa: E402
    BooleanGroup,
    Condition,
    GOLDEN_DNS_RULE,
    GOLDEN_NTP_RULE,
    NotNode,
    is_builder_compatible,
    iter_conditions,
    parse,
    semantic_equal,
    serialize,
    validate,
)


def _conditions(node):
    return {condition.field: condition for condition in iter_conditions(node)}


class GoldenDnsRuleTest(unittest.TestCase):
    def test_ast_of_dns_golden_rule(self):
        ast = parse(GOLDEN_DNS_RULE)
        self.assertIsInstance(ast.match, BooleanGroup)
        self.assertEqual(ast.match.op, "and")
        self.assertEqual(len(ast.match.children), 5)
        match = _conditions(ast.match)
        self.assertEqual(match["protocol"].value, "udp")
        self.assertEqual(match["direction"].value, "inbound")
        self.assertEqual(match["decoder"].value, "DNS")
        self.assertEqual(int(match["src_port"].value), 53)
        self.assertEqual(match["dst_port"].op, ">=")
        self.assertEqual(int(match["dst_port"].value), 1024)

        self.assertIsInstance(ast.triggers.warning, BooleanGroup)
        self.assertEqual(ast.triggers.warning.op, "or")
        warning = _conditions(ast.triggers.warning)
        self.assertEqual(int(warning["packets_s"].value), 100_000)
        self.assertEqual(int(warning["bits_s"].value), 1_000_000_000)

        critical = _conditions(ast.triggers.critical)
        self.assertEqual(int(critical["packets_s"].value), 200_000)
        self.assertEqual(int(critical["bits_s"].value), 2_000_000_000)

        self.assertEqual([item.field for item in ast.evidence], ["unique_src_ips", "avg_packet_bytes", "flows_s"])
        self.assertEqual(ast.window.seconds, 60)
        self.assertEqual(ast.execution.consecutive, 1)
        self.assertEqual(ast.scope.group_by.preset, "target_port")
        self.assertEqual(ast.scope.dedupe_profile, "anomaly_event_default")
        self.assertEqual(ast.response.mode, "manual_approval")
        self.assertTrue(ast.builder_compatible)

    def test_dns_rule_is_valid(self):
        result = validate(parse(GOLDEN_DNS_RULE))
        self.assertTrue(result.ok, result.as_dict())

    def test_dns_roundtrip_is_semantically_stable(self):
        first = parse(GOLDEN_DNS_RULE)
        text = serialize(first)
        second = parse(text)
        self.assertTrue(semantic_equal(first, second))
        self.assertEqual(serialize(second), text)

    def test_dns_serialized_text_has_no_legacy_forms(self):
        text = serialize(parse(GOLDEN_DNS_RULE))
        self.assertNotIn("receives", text)
        self.assertNotIn("= any", text)
        self.assertIn("direction == inbound", text)
        self.assertIn("pps >= 100k", text)
        self.assertIn("bps >= 1G", text)


class GoldenNtpRuleTest(unittest.TestCase):
    def test_ntp_ast(self):
        ast = parse(GOLDEN_NTP_RULE)
        match = _conditions(ast.match)
        self.assertEqual(match["decoder"].value, "NTP")
        self.assertEqual(int(match["src_port"].value), 123)
        self.assertTrue(validate(ast).ok)

    def test_ntp_roundtrip(self):
        first = parse(GOLDEN_NTP_RULE)
        second = parse(serialize(first))
        self.assertTrue(semantic_equal(first, second))
        self.assertIn("decoder == NTP", serialize(second))
        self.assertIn("src_port == 123", serialize(second))


class GroupByRoundtripTest(unittest.TestCase):
    def test_custom_fields_roundtrip(self):
        ast = parse("ADVANCED\ngroup_by = src_ip, dst_ip, dst_port, protocol\n")
        again = parse(serialize(ast))
        self.assertTrue(semantic_equal(ast, again))
        self.assertEqual(again.scope.group_by.fields, ("src_ip", "dst_ip", "dst_port", "protocol"))
        self.assertTrue(again.builder_compatible)

    def test_preset_roundtrip(self):
        ast = parse("ADVANCED\ngroup_by = conversation\n")
        again = parse(serialize(ast))
        self.assertEqual(again.scope.group_by.preset, "conversation")


class BuilderCompatibilityTest(unittest.TestCase):
    def test_normal_rule_is_compatible(self):
        ast = parse(GOLDEN_DNS_RULE)
        self.assertTrue(is_builder_compatible(ast))

    def test_not_over_single_condition_is_compatible(self):
        ast = parse("WARNING\nNOT pps >= 1\n")
        self.assertTrue(is_builder_compatible(ast))

    def test_not_over_composite_is_not_compatible(self):
        ast = parse("WARNING\nNOT (pps >= 1 AND bps >= 2)\n")
        self.assertFalse(is_builder_compatible(ast))
        self.assertFalse(ast.builder_compatible)


if __name__ == "__main__":
    unittest.main()
