"""Testes da FASE 1 da DSL: vocabulario canonico, dicionario e base do Flow Search."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services.detection_dsl import (  # noqa: E402
    Condition,
    DslSemanticError,
    DslSyntaxError,
    FIELDS,
    GOLDEN_DNS_RULE,
    INVALID_EXAMPLES,
    OPERATORS_BY_TYPE,
    OP_EQ,
    VALID_EXAMPLES,
    canonical_direction,
    canonical_operator,
    catalog_json,
    iter_conditions,
    parse,
    parse_expression,
    resolve_field,
    semantic_equal,
    serialize,
    validate_expression,
    validate_text,
)

MAIN_PY = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")


def _first_condition(node):
    for condition in iter_conditions(node):
        return condition
    raise AssertionError("nenhuma condicao encontrada")


class CanonicalVocabularyTest(unittest.TestCase):
    def test_operator_aliases_normalize_to_canonical(self):
        for raw in ("=", "==", "eq", "EQ"):
            self.assertEqual(canonical_operator(raw), OP_EQ, raw)
        self.assertEqual(canonical_operator("<"), "<")
        self.assertEqual(canonical_operator("not in"), "NOT IN")
        self.assertEqual(canonical_operator("not contains"), "NOT CONTAINS")
        self.assertIsNone(canonical_operator("banana"))

    def test_proto_alias_resolves_to_protocol(self):
        spec = resolve_field("proto")
        self.assertIsNotNone(spec)
        self.assertEqual(spec.name, "protocol")
        self.assertEqual(spec.display_name, "proto")
        self.assertEqual(canonical_operator("=="), OP_EQ)

    def test_direction_aliases_are_canonicalized(self):
        self.assertEqual(canonical_direction("receives"), "inbound")
        self.assertEqual(canonical_direction("transmits"), "outbound")
        self.assertEqual(canonical_direction("sends"), "outbound")
        condition = _first_condition(parse_expression("direction == sends"))
        self.assertEqual(condition.value, "outbound")

    def test_metric_and_evidence_aliases(self):
        self.assertEqual(resolve_field("pps").name, "packets_s")
        self.assertEqual(resolve_field("bps").name, "bits_s")
        self.assertEqual(resolve_field("flows").name, "flows_s")
        self.assertEqual(resolve_field("unique_src").name, "unique_src_ips")
        self.assertEqual(resolve_field("unique_dst_ports").name, "unique_dst_ports")


class OperatorByTypeTest(unittest.TestCase):
    def test_port_rejects_regex_and_metric_ops(self):
        with self.assertRaises(DslSemanticError) as ctx:
            parse_expression('src_port matches "^53$"')
        self.assertEqual(ctx.exception.code, "REGEX_NOT_ALLOWED")
        with self.assertRaises(DslSemanticError) as ctx:
            parse_expression("dst_port contains 1")
        self.assertEqual(ctx.exception.code, "CONTAINS_REQUIRES_FLAGS")

    def test_flags_reject_comparison(self):
        with self.assertRaises(DslSemanticError) as ctx:
            parse_expression("tcp_flags > 10")
        self.assertEqual(ctx.exception.code, "INVALID_OPERATOR")

    def test_flags_accept_contains_only(self):
        expression = "proto == tcp and tcp_flags contains syn and tcp_flags not contains rst"
        result = validate_expression(expression)
        self.assertTrue(result.ok, result.as_dict())
        fields = {condition.field for condition in iter_conditions(parse_expression(expression))}
        self.assertEqual(fields, {"protocol", "tcp_flags"})

    def test_numeric_ops_allowed_for_ports(self):
        for expression in ("dst_port >= 1024", "dst_port between 1024 and 65535", "src_port in [53, 123]"):
            self.assertTrue(validate_expression(expression).ok, expression)

    def test_ip_and_cidr_literals(self):
        condition = _first_condition(parse_expression("src_ip == 2001:db8::1"))
        self.assertEqual(condition.value, "2001:db8::1")
        cidr = _first_condition(parse_expression("src_ip in 100.64.0.0/10"))
        self.assertEqual(cidr.value, ("100.64.0.0/10",))
        multi = _first_condition(parse_expression("src_ip in [10.0.0.0/8, 192.168.0.0/16]"))
        self.assertEqual(multi.value, ("10.0.0.0/8", "192.168.0.0/16"))

    def test_empty_list_is_rejected(self):
        with self.assertRaises(DslSemanticError) as ctx:
            parse_expression("src_port in []")
        self.assertEqual(ctx.exception.code, "INVALID_LIST")


class RegexSecurityTest(unittest.TestCase):
    def test_regex_allowed_on_text_sensor(self):
        result = validate_expression('sensor matches "^FIBINET-"')
        self.assertTrue(result.ok, result.as_dict())

    def test_invalid_regex_reported(self):
        result = validate_expression('sensor matches "([unclosed"')
        self.assertFalse(result.ok)
        self.assertEqual([issue.code for issue in result.errors], ["INVALID_VALUE"])

    def test_sql_injection_is_rejected(self):
        with self.assertRaises(DslSyntaxError) as ctx:
            parse_expression("proto == udp; DROP TABLE flow_raw")
        self.assertEqual(ctx.exception.code, "FORBIDDEN_CHARACTER")
        self.assertIsNotNone(ctx.exception.suggestion)

    def test_unknown_field_is_rejected(self):
        with self.assertRaises(DslSemanticError) as ctx:
            parse_expression("unknown_field == 1")
        self.assertEqual(ctx.exception.code, "UNKNOWN_FIELD")


class SectionSeparationTest(unittest.TestCase):
    def test_raw_flow_field_not_allowed_in_trigger(self):
        result = validate_text("WARNING\nsrc_ip == 10.0.0.1\n")
        self.assertFalse(result.ok)
        self.assertIn("FIELD_NOT_ALLOWED_IN_SECTION", [issue.code for issue in result.errors])

    def test_aggregated_metric_not_allowed_in_match(self):
        result = validate_text("MATCH\npps >= 100k\n")
        self.assertFalse(result.ok)
        self.assertIn("FIELD_NOT_ALLOWED_IN_SECTION", [issue.code for issue in result.errors])

    def test_trigger_accepts_aggregated_metrics(self):
        result = validate_text("WARNING\npps >= 100k and unique_src_ips >= 500\n")
        self.assertTrue(result.ok, result.as_dict())

    def test_evidence_accepts_lists_and_metrics(self):
        result = validate_text("EVIDENCE\ntop_src_ips, top_dst_ports, avg_packet_bytes, pps\n")
        self.assertTrue(result.ok, result.as_dict())


class GroupByTest(unittest.TestCase):
    def test_allowed_fields(self):
        result = validate_text("ADVANCED\ngroup_by = dst_ip,src_port,proto\n")
        self.assertTrue(result.ok, result.as_dict())

    def test_interface_preset(self):
        ast = parse("ADVANCED\ngroup_by = interface\n")
        again = parse(serialize(ast))
        self.assertEqual(again.scope.group_by.preset, "interface")

    def test_forbidden_field(self):
        result = validate_text("ADVANCED\ngroup_by = tcp_flags\n")
        self.assertFalse(result.ok)
        self.assertIn("INVALID_GROUP_BY_FIELD", [issue.code for issue in result.errors])


class ExamplesAndRoundTripTest(unittest.TestCase):
    def test_valid_examples_parse_and_validate(self):
        for expression in VALID_EXAMPLES:
            result = validate_expression(expression)
            self.assertTrue(result.ok, f"{expression!r}: {result.as_dict()}")

    def test_invalid_examples_fail_with_expected_code(self):
        for item in INVALID_EXAMPLES:
            expression = item["expression"]
            expected = item["code"]
            with self.assertRaises((DslSemanticError, DslSyntaxError)) as ctx:
                validate_expression(expression)
            self.assertEqual(ctx.exception.code, expected, expression)

    def test_serializer_uses_canonical_form(self):
        text = serialize(parse(GOLDEN_DNS_RULE))
        self.assertIn("proto == udp", text)
        self.assertIn("direction == inbound", text)
        self.assertIn("src_port == 53", text)
        self.assertIn("pps >= 100k", text)
        match_block = text.split("\n\n")[0]
        self.assertNotIn(" = ", match_block)

    def test_list_round_trip(self):
        ast = parse_expression("src_port in [53,123,1900,11211]")
        self.assertIsInstance(ast, Condition)

    def test_golden_rule_round_trip(self):
        first = parse(GOLDEN_DNS_RULE)
        text = serialize(first)
        second = parse(text)
        self.assertTrue(semantic_equal(first, second))
        self.assertEqual(serialize(second), text)


class CatalogDictionaryTest(unittest.TestCase):
    def test_catalog_required_dictionary_keys(self):
        data = catalog_json()
        json.dumps(data)
        self.assertEqual(data["language"], "gmjflow-rule-language")
        for key in ("fields", "operators", "operators_by_type", "group_by", "sections", "examples"):
            self.assertIn(key, data, key)

    def test_every_field_declares_dictionary_metadata(self):
        for item in catalog_json()["fields"]:
            for key in (
                "name", "aliases", "label", "description", "type", "origin",
                "operators", "unit", "enum_values", "examples", "match_allowed",
                "group_by_allowed", "trigger_allowed", "evidence_allowed",
                "capability", "clickhouse", "exporter_reliability", "status",
            ):
                self.assertIn(key, item, f"{item['name']}:{key}")
            self.assertIsInstance(item["match_allowed"], bool)

    def test_priority_fields_present(self):
        for name in (
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "tcp_flags",
            "direction", "sensor", "sensor_id", "exporter_ip", "input_if",
            "output_if", "src_asn", "dst_asn", "bytes", "packets", "flow_count",
            "packets_s", "bits_s", "flows_s", "unique_src_ips", "unique_dst_ips",
            "unique_src_ports", "unique_dst_ports", "top_src_ips", "top_dst_ips",
        ):
            self.assertIn(name, FIELDS, name)

    def test_operators_by_type_complete(self):
        for type_ in ("int", "port", "metric", "enum", "ip", "cidr", "flags", "text"):
            self.assertIn(type_, OPERATORS_BY_TYPE)
        self.assertEqual(OPERATORS_BY_TYPE["flags"], ("CONTAINS", "NOT CONTAINS"))
        self.assertEqual(OPERATORS_BY_TYPE["text"], ("==", "!=", "MATCHES"))


class CatalogEndpointStaticTest(unittest.TestCase):
    def test_endpoint_route_is_declared(self):
        self.assertIn('@app.get("/api/rule-language/catalog")', MAIN_PY)
        self.assertIn("catalog_json()", MAIN_PY)
        self.assertIn("from app.services import detection_dsl", MAIN_PY)


if __name__ == "__main__":
    unittest.main()
