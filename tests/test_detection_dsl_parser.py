"""Testes do parser: aliases, ANY, booleanos e seções (Fase 3A)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services.detection_dsl import (  # noqa: E402
    BooleanGroup,
    Condition,
    DslSemanticError,
    DslSyntaxError,
    NotNode,
    parse,
    serialize,
)


def _match_condition(text, field):
    ast = parse(text)
    for condition in _iter(ast.match):
        if condition.field == field:
            return condition
    raise AssertionError(f"campo {field} nao encontrado")


def _iter(node):
    if node is None:
        return
    if isinstance(node, Condition):
        yield node
    elif isinstance(node, NotNode):
        yield from _iter(node.child)
    elif isinstance(node, BooleanGroup):
        for child in node.children:
            yield from _iter(child)


class DirectionAliasTest(unittest.TestCase):
    def test_inbound_aliases(self):
        for alias in ("receives", "download", "in", "entrando", "inbound"):
            condition = _match_condition(f"MATCH\ndirection = {alias}\n", "direction")
            self.assertEqual(condition.value, "inbound", alias)

    def test_outbound_aliases(self):
        for alias in ("sends", "transmits", "upload", "out", "saindo", "outbound"):
            condition = _match_condition(f"MATCH\ndirection = {alias}\n", "direction")
            self.assertEqual(condition.value, "outbound", alias)

    def test_serializer_never_writes_legacy_direction(self):
        ast = parse("MATCH\ndirection = transmits\n")
        text = serialize(ast)
        self.assertIn("direction = outbound", text)
        self.assertNotIn("transmits", text)
        self.assertNotIn("receives", text)


class MetricAliasTest(unittest.TestCase):
    def test_metric_aliases_map_to_canonical(self):
        ast = parse("WARNING\npps >= 100k OR bps >= 1G OR flows >= 10\n")
        fields = {condition.field for condition in _iter(ast.triggers.warning)}
        self.assertEqual(fields, {"packets_s", "bits_s", "flows_s"})

    def test_serializer_writes_friendly_metric_names(self):
        ast = parse("WARNING\npackets_s >= 100k\n")
        self.assertIn("pps >= 100k", serialize(ast))


class AnySemanticsTest(unittest.TestCase):
    def test_any_removes_condition(self):
        ast = parse("MATCH\nsrc_port = any\n")
        self.assertIsNone(ast.match)

    def test_any_inside_group_is_dropped(self):
        ast = parse("MATCH\nprotocol = udp AND src_port = any\n")
        self.assertIsInstance(ast.match, Condition)
        self.assertEqual(ast.match.field, "protocol")

    def test_serializer_never_writes_any(self):
        ast = parse("MATCH\nprotocol = udp AND src_port = any\n")
        self.assertNotIn("any", serialize(ast))


class BooleanParsingTest(unittest.TestCase):
    def test_and_binds_tighter_than_or(self):
        ast = parse("WARNING\npps >= 1 OR bps >= 2 AND flows >= 3\n")
        node = ast.triggers.warning
        self.assertIsInstance(node, BooleanGroup)
        self.assertEqual(node.op, "or")
        self.assertEqual(len(node.children), 2)
        self.assertIsInstance(node.children[1], BooleanGroup)
        self.assertEqual(node.children[1].op, "and")

    def test_parentheses_override_precedence(self):
        ast = parse("WARNING\n(pps >= 1 OR bps >= 2) AND flows >= 3\n")
        node = ast.triggers.warning
        self.assertIsInstance(node, BooleanGroup)
        self.assertEqual(node.op, "and")
        self.assertIsInstance(node.children[0], BooleanGroup)
        self.assertEqual(node.children[0].op, "or")

    def test_not(self):
        ast = parse("WARNING\nNOT (pps >= 1 AND bps >= 2)\n")
        node = ast.triggers.warning
        self.assertIsInstance(node, NotNode)
        self.assertIsInstance(node.child, BooleanGroup)

    def test_nested_groups(self):
        ast = parse("WARNING\n(pps >= 1 OR (bps >= 2 AND flows >= 3))\n")
        node = ast.triggers.warning
        self.assertIsInstance(node, BooleanGroup)
        self.assertEqual(node.op, "or")
        self.assertIsInstance(node.children[1], BooleanGroup)


class SectionParsingTest(unittest.TestCase):
    def test_full_sections(self):
        ast = parse(
            "RULE dns_reflection\n"
            'DISPLAY_NAME "DNS Reflection"\n'
            "SEVERITY warning\n"
            "\nMATCH\nprotocol = udp\n"
            "\nEVIDENCE\nunique_src, avg_packet_bytes, flows\n"
            "\nADVANCED\nwindow = 5m\nconsecutive = 2\ngroup_by = src_ip, dst_port\ndedupe = dns_single_flow\nrequires = conversation_grouping\n"
            "\nRESPONSE\nmode = auto\nmax_auto_prefixlen_v4 = 32\n"
        )
        self.assertEqual(ast.name, "dns_reflection")
        self.assertEqual(ast.display_name, "DNS Reflection")
        self.assertEqual(ast.severity, "warning")
        self.assertEqual(ast.window.seconds, 300)
        self.assertEqual(ast.execution.consecutive, 2)
        self.assertEqual(ast.scope.group_by.fields, ("src_ip", "dst_port"))
        self.assertEqual(ast.scope.dedupe_profile, "dns_single_flow")
        self.assertEqual(ast.requires, ("conversation_grouping",))
        self.assertEqual(ast.response.mode, "auto")
        self.assertEqual(ast.response.max_auto_prefixlen_v4, 32)

    def test_unknown_field_is_semantic_error(self):
        with self.assertRaises(DslSemanticError) as ctx:
            parse("MATCH\navg_pkt >= 1\n")
        self.assertEqual(ctx.exception.code, "UNKNOWN_FIELD")
        self.assertIsNotNone(ctx.exception.line)

    def test_unknown_section_is_syntax_error(self):
        with self.assertRaises(DslSyntaxError) as ctx:
            parse("NOPE\nfield = 1\n")
        self.assertEqual(ctx.exception.code, "UNKNOWN_SECTION")

    def test_unterminated_string(self):
        with self.assertRaises(DslSyntaxError) as ctx:
            parse('MATCH\ndecoder = "DNS\n')
        self.assertEqual(ctx.exception.code, "UNTERMINATED_STRING")


if __name__ == "__main__":
    unittest.main()
