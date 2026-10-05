"""Testes do compilador MATCH -> ClickHouse (Fase 2 - Flow Search por expressao)."""
import ipaddress
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

MAIN_PY = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")

from app.services.detection_dsl import (  # noqa: E402
    DEFAULT_INTERNAL_NETWORKS,
    MAX_AST_DEPTH,
    MAX_CONDITIONS,
    MAX_IN_LIST,
    MAX_REGEX_LENGTH,
    CompileError,
    FlowSearchDialect,
    check_expression,
    compile_expression,
    compile_match,
    field_flow_search_availability,
    parse_expression,
)

# Schema real de flowdb.flow_raw (somente colunas usadas pelo Flow Search).
FLOW_RAW_COLUMNS = {
    "flow_time": "DateTime64(3, 'UTC')",
    "sensor": "LowCardinality(String)",
    "exporter_ip": "IPv6",
    "src_ip": "IPv6",
    "dst_ip": "IPv6",
    "src_port": "UInt16",
    "dst_port": "UInt16",
    "proto": "UInt8",
    "tcp_flags": "UInt16",
    "input_if": "UInt32",
    "output_if": "UInt32",
    "bytes": "UInt64",
    "packets": "UInt64",
    "flow_count": "UInt64",
    "src_asn": "UInt32",
    "dst_asn": "UInt32",
}


def _ip_param(value: str) -> str:
    parsed = ipaddress.ip_address(value)
    if isinstance(parsed, ipaddress.IPv4Address):
        return f"::ffff:{parsed}"
    return str(parsed)


def _cidr_param(value: str) -> str:
    network = ipaddress.ip_network(value, strict=False)
    if network.version == 4:
        return f"::ffff:{network.network_address}/{96 + network.prefixlen}"
    return str(network)


def _decoder_condition(decoder: str) -> str:
    return {
        "DNS": "proto IN (6, 17) AND (src_port = 53 OR dst_port = 53)",
        "NTP": "proto = 17 AND (src_port = 123 OR dst_port = 123)",
        "TCP": "proto = 6",
        "TCP+SYN": "proto = 6 AND bitAnd(tcp_flags, 2) != 0",
        "UDP": "proto = 17",
        "ICMP": "proto IN (1, 58)",
    }.get(decoder.upper(), "0 = 1")


def dialect() -> FlowSearchDialect:
    return FlowSearchDialect(
        column_types=FLOW_RAW_COLUMNS,
        ip_param=_ip_param,
        cidr_param=_cidr_param,
        decoder_condition=_decoder_condition,
    )


def compile_text(text: str):
    return compile_expression(text, dialect())


class BasicCompileTest(unittest.TestCase):
    def test_equality_uses_bound_params(self):
        compiled = compile_text("proto == udp and src_port == 53")
        self.assertEqual(compiled.conditions, 2)
        self.assertEqual(compiled.params, {"expr_0": 17, "expr_1": 53})
        self.assertIn("proto = {expr_0:UInt8}", compiled.where)
        self.assertIn("src_port = {expr_1:UInt16}", compiled.where)
        self.assertNotIn("udp", compiled.where)

    def test_legacy_equality_alias_is_canonicalized(self):
        compiled = compile_text("proto = udp and src_port = 53")
        self.assertEqual(compiled.params, {"expr_0": 17, "expr_1": 53})
        self.assertIn("==", compiled.canonical_expression)
        self.assertIn("proto == udp", compiled.canonical_expression)

    def test_inequality(self):
        compiled = compile_text("proto != udp")
        self.assertEqual(compiled.where, "proto != {expr_0:UInt8}")
        self.assertEqual(compiled.params, {"expr_0": 17})

    def test_in_and_not_in(self):
        compiled = compile_text("src_port in [53,123,1900]")
        self.assertEqual(compiled.where, "src_port IN {expr_0:Array(UInt16)}")
        self.assertEqual(compiled.params, {"expr_0": [53, 123, 1900]})
        negated = compile_text("src_port not in [53,123]")
        self.assertEqual(negated.where, "src_port NOT IN {expr_0:Array(UInt16)}")

    def test_between(self):
        compiled = compile_text("dst_port between 1024 and 65535")
        self.assertEqual(
            compiled.where,
            "(dst_port >= {expr_0:UInt16} AND dst_port <= {expr_1:UInt16})",
        )
        self.assertEqual(compiled.params, {"expr_0": 1024, "expr_1": 65535})

    def test_numeric_fields_use_uint64_params(self):
        compiled = compile_text("bytes >= 1000000 and packets <= 2000")
        self.assertEqual(compiled.params, {"expr_0": 1_000_000, "expr_1": 2_000})
        self.assertIn("bytes >= {expr_0:UInt64}", compiled.where)
        self.assertIn("packets <= {expr_1:UInt64}", compiled.where)

    def test_cidr_and_ip(self):
        cidr = compile_text("src_ip in 100.64.0.0/10")
        self.assertIn("isIPAddressInRange(toString(src_ip), {expr_0:String})", cidr.where)
        self.assertEqual(cidr.params, {"expr_0": "::ffff:100.64.0.0/106"})
        single = compile_text("src_ip == 10.0.0.1")
        self.assertEqual(single.where, "toString(src_ip) = {expr_0:String}")
        self.assertEqual(single.params, {"expr_0": "::ffff:10.0.0.1"})

    def test_src_cidr_field(self):
        compiled = compile_text("src_cidr == 192.168.0.0/16")
        self.assertIn("isIPAddressInRange(toString(src_ip), {expr_0:String})", compiled.where)
        self.assertEqual(compiled.params, {"expr_0": "::ffff:192.168.0.0/112"})


class DirectionCompileTest(unittest.TestCase):
    def test_inbound_uses_destination(self):
        compiled = compile_text("direction == inbound")
        self.assertIn("toString(dst_ip)", compiled.where)
        self.assertNotIn("toString(src_ip)", compiled.where)
        self.assertEqual(len(compiled.params), len(DEFAULT_INTERNAL_NETWORKS))

    def test_outbound_uses_source(self):
        compiled = compile_text("direction == outbound")
        self.assertIn("toString(src_ip)", compiled.where)
        self.assertNotIn("toString(dst_ip)", compiled.where)

    def test_alias_receives_is_inbound(self):
        self.assertEqual(
            compile_text("direction == receives").where,
            compile_text("direction == inbound").where,
        )

    def test_alias_transmits_is_outbound(self):
        self.assertEqual(
            compile_text("direction == transmits").where,
            compile_text("direction == outbound").where,
        )

    def test_both_uses_both_columns(self):
        compiled = compile_text("direction == both")
        self.assertIn("toString(dst_ip)", compiled.where)
        self.assertIn("toString(src_ip)", compiled.where)

    def test_direction_not_in(self):
        compiled = compile_text("direction not in [inbound, both]")
        self.assertTrue(compiled.where.startswith("NOT ("))


class FlagsAndTextTest(unittest.TestCase):
    def test_tcp_flags_contains(self):
        compiled = compile_text("tcp_flags contains syn")
        self.assertEqual(compiled.where, "bitAnd(tcp_flags, {expr_0:UInt16}) != 0")
        self.assertEqual(compiled.params, {"expr_0": 0x02})

    def test_tcp_flags_multiple_bits(self):
        compiled = compile_text("tcp_flags contains syn+ack")
        self.assertEqual(compiled.params, {"expr_0": 0x12})

    def test_tcp_flags_not_contains(self):
        compiled = compile_text("tcp_flags not contains rst")
        self.assertEqual(compiled.where, "bitAnd(tcp_flags, {expr_0:UInt16}) = 0")
        self.assertEqual(compiled.params, {"expr_0": 0x04})

    def test_sensor_equality_and_matches(self):
        equal = compile_text("sensor == SENSOR-BHE-F1A")
        self.assertEqual(equal.where, "sensor = {expr_0:String}")
        self.assertEqual(equal.params, {"expr_0": "SENSOR-BHE-F1A"})
        matches = compile_text('sensor matches "^FIBINET-"')
        self.assertEqual(matches.where, "match(sensor, {expr_0:String})")
        self.assertEqual(matches.params, {"expr_0": "^FIBINET-"})
        self.assertNotIn("FIBINET", matches.where)

    def test_sensor_inequality(self):
        compiled = compile_text("sensor != FIBINET-A")
        self.assertEqual(compiled.where, "sensor != {expr_0:String}")
        self.assertEqual(compiled.params, {"expr_0": "FIBINET-A"})


class BooleanTreeTest(unittest.TestCase):
    def test_and_or_precedence(self):
        compiled = compile_text("proto == udp or proto == tcp and src_port == 53")
        self.assertTrue(compiled.where.startswith("("))
        self.assertIn(" OR ", compiled.where)
        self.assertIn(" AND ", compiled.where)

    def test_parentheses_and_not(self):
        compiled = compile_text("not (proto == udp and src_port == 53)")
        self.assertTrue(compiled.where.startswith("NOT (("))
        self.assertEqual(compiled.conditions, 2)

    def test_decoder_and_protocol_together(self):
        compiled = compile_text("decoder == DNS and direction == inbound")
        self.assertIn("(src_port = 53 OR dst_port = 53)", compiled.where)
        self.assertIn("toString(dst_ip)", compiled.where)

    def test_interface_checks_both_columns(self):
        compiled = compile_text("interface_if_index == 12")
        self.assertEqual(
            compiled.where,
            "(input_if = {expr_0:UInt32} OR output_if = {expr_0:UInt32})",
        )


class CheckExpressionTest(unittest.TestCase):
    def test_valid_expression_reports_ast_and_canonical(self):
        result = check_expression("proto = udp and src_port == 53", dialect())
        self.assertTrue(result["valid"])
        self.assertEqual(result["canonical_expression"], "proto == udp AND src_port == 53")
        self.assertEqual(result["conditions"], 2)
        self.assertEqual(result["fields"], ["protocol", "src_port"])
        self.assertEqual(result["ast"]["type"], "and")
        self.assertEqual(result["errors"], [])

    def test_sql_injection_is_reported(self):
        result = check_expression("proto == udp; DROP TABLE flow_raw", dialect())
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "FORBIDDEN_CHARACTER")

    def test_trigger_metric_rejected_in_flow_search(self):
        result = check_expression("pps >= 100k", dialect())
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "FIELD_NOT_ALLOWED_IN_SECTION")

    def test_field_without_column_is_reported(self):
        result = check_expression("sensor_id == 2", dialect())
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "FIELD_NOT_AVAILABLE_IN_FLOW_SEARCH")

    def test_empty_expression(self):
        result = check_expression("   ", dialect())
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "EMPTY_EXPRESSION")


class ComplexityLimitsTest(unittest.TestCase):
    def test_too_many_conditions(self):
        expression = " and ".join(["proto == udp"] * (MAX_CONDITIONS + 5))
        with self.assertRaises(CompileError) as ctx:
            compile_text(expression)
        self.assertEqual(ctx.exception.code, "TOO_MANY_CONDITIONS")

    def test_ast_too_deep(self):
        expression = " ".join(["not"] * (MAX_AST_DEPTH + 3)) + " proto == udp"
        result = check_expression(expression, dialect())
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "AST_TOO_DEEP")

    def test_in_list_too_large(self):
        values = ",".join(str(port) for port in range(1, MAX_IN_LIST + 6))
        with self.assertRaises(CompileError) as ctx:
            compile_text(f"src_port in [{values}]")
        self.assertEqual(ctx.exception.code, "IN_LIST_TOO_LARGE")

    def test_regex_too_long(self):
        pattern = "^" + ("a" * (MAX_REGEX_LENGTH + 5))
        result = check_expression(f'sensor matches "{pattern}"', dialect())
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "REGEX_TOO_LONG")

    def test_expression_too_long(self):
        expression = "proto == udp and " * 400 + "proto == udp"
        result = check_expression(expression, dialect())
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "EXPRESSION_TOO_LONG")


class CompileMatchTest(unittest.TestCase):
    def test_compile_match_from_parsed_node(self):
        node = parse_expression("proto == udp")
        compiled = compile_match(node, dialect(), params_prefix="f")
        self.assertEqual(compiled.params, {"f_0": 17})
        self.assertEqual(compiled.fields, ("protocol",))


class FlowSearchWiringStaticTest(unittest.TestCase):
    def assert_in_main(self, needle: str) -> None:
        self.assertTrue(needle in MAIN_PY, f"nao encontrado em main.py: {needle}")

    def test_search_accepts_expression_additively(self):
        self.assert_in_main("expression: str | None = None")
        self.assert_in_main("def search_flows_payload(")
        self.assert_in_main("compile_flow_search_expression(expression)")

    def test_validate_endpoint_declared(self):
        self.assert_in_main('@app.get("/api/flows/expression/validate")')
        self.assert_in_main("detection_dsl.check_expression(")

    def test_expression_is_combined_with_legacy_filters(self):
        self.assert_in_main("flow_search_internal_networks")
        self.assert_in_main("GMJFLOW_FLOW_INTERNAL_CIDRS")


class FieldAvailabilityTest(unittest.TestCase):
    def test_available_fields_and_specials(self):
        availability = field_flow_search_availability(FLOW_RAW_COLUMNS)
        for name in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "tcp_flags", "sensor", "bytes", "direction", "decoder", "interface_if_index"):
            self.assertTrue(availability[name], name)
        for name in ("sensor_id", "icmp_type", "icmp_code", "packets_s", "bits_s", "avg_packet_bytes"):
            self.assertFalse(availability[name], name)

    def test_missing_column_marks_field_unavailable(self):
        availability = field_flow_search_availability({"src_ip": "IPv6"})
        self.assertTrue(availability["src_ip"])
        self.assertFalse(availability["dst_ip"])
        self.assertFalse(availability["interface_if_index"])


if __name__ == "__main__":
    unittest.main()
