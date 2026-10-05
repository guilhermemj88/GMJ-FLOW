"""Testes de erro/capability do validator (Fase 3A)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services.detection_dsl import (  # noqa: E402
    DslSemanticError,
    DslSyntaxError,
    parse,
    parse_and_validate,
    validate,
    validate_text,
)


def _codes(result):
    return [issue.code for issue in result.errors]


def _warning_codes(result):
    return [issue.code for issue in result.warnings]


class ParserErrorCodeTest(unittest.TestCase):
    def test_avg_pkt_unknown_field(self):
        with self.assertRaises(DslSemanticError) as ctx:
            parse("WARNING\navg_pkt >= 1\n")
        self.assertEqual(ctx.exception.code, "UNKNOWN_FIELD")

    def test_operator_incompatible_with_enum(self):
        with self.assertRaises(DslSemanticError) as ctx:
            parse("MATCH\nprotocol >= udp\n")
        self.assertEqual(ctx.exception.code, "INVALID_OPERATOR")

    def test_invalid_unit(self):
        with self.assertRaises(DslSemanticError) as ctx:
            parse("WARNING\nbps >= 1GG\n")
        self.assertEqual(ctx.exception.code, "INVALID_UNIT")

    def test_invalid_protocol_value(self):
        with self.assertRaises(DslSemanticError) as ctx:
            parse("MATCH\nprotocol = udp2\n")
        self.assertEqual(ctx.exception.code, "INVALID_ENUM")

    def test_invalid_direction_value(self):
        with self.assertRaises(DslSemanticError) as ctx:
            parse("MATCH\ndirection = receive\n")
        self.assertEqual(ctx.exception.code, "INVALID_ENUM")


class SemanticValidationTest(unittest.TestCase):
    def test_port_out_of_range(self):
        ast, result = parse_and_validate("MATCH\ndst_port = 70000\n")
        self.assertFalse(result.ok)
        self.assertIn("OUT_OF_RANGE", _codes(result))

    def test_port_negative_rejected(self):
        # '-' nao e um token valido de valor: rejeitado na sintaxe.
        with self.assertRaises(DslSyntaxError):
            validate_text("MATCH\ndst_port = -1\n")

    def test_between_inverted(self):
        ast, result = parse_and_validate("MATCH\ndst_port BETWEEN 65535 AND 1024\n")
        self.assertFalse(result.ok)
        self.assertIn("INVALID_RANGE", _codes(result))

    def test_between_valid(self):
        ast, result = parse_and_validate("MATCH\ndst_port BETWEEN 1024 AND 65535\n")
        self.assertTrue(result.ok, result.as_dict())

    def test_port_list_valid(self):
        ast, result = parse_and_validate("MATCH\nsrc_port IN (53, 123, 1900)\n")
        self.assertTrue(result.ok, result.as_dict())

    def test_port_list_with_invalid_value(self):
        ast, result = parse_and_validate("MATCH\nsrc_port IN (53, 70000)\n")
        self.assertFalse(result.ok)
        self.assertIn("OUT_OF_RANGE", _codes(result))

    def test_avg_packet_bytes_not_allowed_in_trigger(self):
        ast, result = parse_and_validate("WARNING\navg_packet_bytes >= 100\n")
        self.assertFalse(result.ok)
        self.assertIn("FIELD_NOT_ALLOWED_IN_SECTION", _codes(result))

    def test_bytes_not_allowed_in_trigger(self):
        ast, result = parse_and_validate("WARNING\nbytes >= 100\n")
        self.assertFalse(result.ok)
        self.assertIn("FIELD_NOT_ALLOWED_IN_SECTION", _codes(result))

    def test_group_by_invalid_field(self):
        ast, result = parse_and_validate("ADVANCED\ngroup_by = pps\n")
        self.assertFalse(result.ok)
        self.assertIn("INVALID_GROUP_BY_FIELD", _codes(result))

    def test_group_by_custom_valid_fields_are_builder_compatible(self):
        ast, result = parse_and_validate("ADVANCED\ngroup_by = src_ip, dst_ip, dst_port, protocol\n")
        self.assertTrue(result.ok, result.as_dict())
        self.assertTrue(ast.builder_compatible)
        self.assertEqual(ast.scope.group_by.fields, ("src_ip", "dst_ip", "dst_port", "protocol"))

    def test_unknown_dedupe_profile(self):
        ast, result = parse_and_validate("ADVANCED\ndedupe = nope\n")
        self.assertFalse(result.ok)
        self.assertIn("UNKNOWN_DEDUPE_PROFILE", _codes(result))

    def test_invalid_response_mode(self):
        ast, result = parse_and_validate("RESPONSE\nmode = friday\n")
        self.assertFalse(result.ok)
        self.assertIn("INVALID_RESPONSE_MODE", _codes(result))


class CapabilityValidationTest(unittest.TestCase):
    def test_tcp_flags_experimental_warning(self):
        ast, result = parse_and_validate("MATCH\ntcp_flags contains syn\n")
        self.assertTrue(result.ok, result.as_dict())
        self.assertIn("CAPABILITY_EXPERIMENTAL", _warning_codes(result))

    def test_required_capability_unavailable(self):
        ast, result = parse_and_validate("ADVANCED\nrequires = flowspec_dns_block\n")
        self.assertFalse(result.ok)
        self.assertIn("CAPABILITY_UNAVAILABLE", _codes(result))

    def test_required_capability_unknown(self):
        ast, result = parse_and_validate("ADVANCED\nrequires = teleport\n")
        self.assertFalse(result.ok)
        self.assertIn("UNKNOWN_CAPABILITY", _codes(result))

    def test_supported_field_capability_has_no_warning(self):
        ast, result = parse_and_validate("EVIDENCE\navg_packet_bytes\n")
        self.assertTrue(result.ok, result.as_dict())
        self.assertEqual(_warning_codes(result), [])


if __name__ == "__main__":
    unittest.main()
