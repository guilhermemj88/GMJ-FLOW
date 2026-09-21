from __future__ import annotations

import os
import sqlite3
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import app.main as main  # noqa: E402
from app.services import flow_codecs as codecs_service  # noqa: E402


INDEX_HTML_PATH = os.path.join(ROOT, "frontend", "index.html")
MAIN_PATH = os.path.join(ROOT, "backend", "app", "main.py")


def _read_asset(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _seeded_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    codecs_service.ensure_flow_codecs_schema(conn)
    codecs_service.seed_builtin_flow_codecs(conn)
    return conn


def _flow(protocol: str, source_port: int, destination_port: int) -> dict:
    return {
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
    }


def _groups(matches: list[dict]) -> set[str]:
    return {codecs_service.codec_service_group(item["name"]) for item in matches}


class CodecRegistryClassificationTest(unittest.TestCase):
    """O grafico stacked usa a classificacao canonica da aba Codecs."""

    @classmethod
    def setUpClass(cls):
        cls.conn = _seeded_connection()
        active = codecs_service.list_flow_codecs(cls.conn, active_only=True)
        cls.every_active = active
        cls.codecs = codecs_service.order_flow_codecs(
            [item for item in active if codecs_service.codec_is_aggregate_classifiable(item)]
        )
        cls.names = {item["name"] for item in cls.codecs}

    def test_registry_exposes_builtin_codecs(self):
        self.assertTrue(self.every_active)
        self.assertTrue(all(int(item.get("builtin", 0)) == 1 for item in self.every_active))

    def test_only_aggregate_classifiable_codecs_are_used(self):
        skipped = [
            item["name"] for item in self.every_active
            if not codecs_service.codec_is_aggregate_classifiable(item)
        ]
        self.assertTrue(all(name not in self.names for name in skipped))

    def test_tcp_to_port_80_is_http(self):
        matches = codecs_service.classify_flow_codecs(_flow("TCP", 40123, 80), self.codecs)
        self.assertIn("HTTP", _groups(matches))

    def test_tcp_from_port_80_is_http(self):
        matches = codecs_service.classify_flow_codecs(_flow("TCP", 80, 40123), self.codecs)
        self.assertIn("HTTP", _groups(matches))

    def test_tcp_to_port_443_is_https(self):
        matches = codecs_service.classify_flow_codecs(_flow("TCP", 51000, 443), self.codecs)
        self.assertIn("HTTPS", _groups(matches))

    def test_tcp_from_port_443_is_https(self):
        matches = codecs_service.classify_flow_codecs(_flow("TCP", 443, 51000), self.codecs)
        self.assertIn("HTTPS", _groups(matches))

    def test_udp_to_port_443_is_quic(self):
        matches = codecs_service.classify_flow_codecs(_flow("UDP", 51000, 443), self.codecs)
        self.assertIn("QUIC", _groups(matches))

    def test_udp_from_port_443_is_quic(self):
        matches = codecs_service.classify_flow_codecs(_flow("UDP", 443, 51000), self.codecs)
        self.assertIn("QUIC", _groups(matches))

    def test_udp_to_port_53_is_dns(self):
        matches = codecs_service.classify_flow_codecs(_flow("UDP", 51000, 53), self.codecs)
        self.assertIn("DNS", _groups(matches))

    def test_unmatched_tcp_has_no_codec_but_keeps_protocol(self):
        matches = codecs_service.classify_flow_codecs(_flow("TCP", 51000, 65535), self.codecs)
        groups = _groups(matches)
        for known in ("HTTP", "HTTPS", "DNS", "NTP", "QUIC", "SSDP", "SNMP", "MEMCACHED", "CLDAP", "CHARGEN"):
            self.assertNotIn(known, groups)

    def test_classification_is_protocol_aware(self):
        # porta 443 em TCP nao pode casar codecs UDP (QUIC) e vice-versa
        tcp_groups = _groups(codecs_service.classify_flow_codecs(_flow("TCP", 51000, 443), self.codecs))
        udp_groups = _groups(codecs_service.classify_flow_codecs(_flow("UDP", 51000, 443), self.codecs))
        self.assertIn("HTTPS", tcp_groups)
        self.assertNotIn("HTTPS", udp_groups)
        self.assertIn("QUIC", udp_groups)
        self.assertNotIn("QUIC", tcp_groups)


class CodecPrecedenceTest(unittest.TestCase):
    """Ordem canonica: prioridade DESC, especificidade DESC, id ASC."""

    def test_sort_key_prefers_higher_priority(self):
        generic = {"name": "GENERIC", "id": 1, "specificity_priority": 0, "protocol": "ANY"}
        specific = {"name": "SPECIFIC", "id": 2, "specificity_priority": 50, "protocol": "TCP", "destination_port": 443}
        ordered = codecs_service.order_flow_codecs([generic, specific])
        self.assertEqual([item["name"] for item in ordered], ["SPECIFIC", "GENERIC"])

    def test_sort_key_prefers_specificity_on_same_priority(self):
        wide = {"name": "WIDE", "id": 1, "specificity_priority": 10, "protocol": "TCP"}
        narrow = {"name": "NARROW", "id": 2, "specificity_priority": 10, "protocol": "TCP", "destination_port": 443}
        ordered = codecs_service.order_flow_codecs([wide, narrow])
        self.assertEqual([item["name"] for item in ordered], ["NARROW", "WIDE"])

    def test_first_match_wins_without_duplicate_count(self):
        # dois codecs casam o mesmo fluxo: apenas o primeiro (canonico) define o label
        generic = {"name": "TCP_ANY", "id": 1, "specificity_priority": 0, "protocol": "TCP", "active": 1}
        specific = {
            "name": "HTTPS_CLIENT", "id": 2, "specificity_priority": 50,
            "protocol": "TCP", "destination_port": 443, "active": 1,
        }
        ordered = codecs_service.order_flow_codecs([generic, specific])
        matches = codecs_service.classify_flow_codecs(_flow("TCP", 51000, 443), ordered)
        self.assertGreaterEqual(len(matches), 2)
        self.assertEqual(codecs_service.codec_service_group(matches[0]["name"]), "HTTPS")


class ServiceGroupLabelTest(unittest.TestCase):
    """CLIENT/RETURN/QUERY/RESPONSE consolidam no mesmo servico."""

    def test_client_and_return_share_group(self):
        self.assertEqual(
            codecs_service.codec_service_group("HTTPS_CLIENT"),
            codecs_service.codec_service_group("HTTPS_RETURN"),
        )

    def test_dns_variants_share_group(self):
        self.assertEqual(
            codecs_service.codec_service_group("DNS_QUERY_UDP"),
            codecs_service.codec_service_group("DNS_RESPONSE_UDP"),
        )

    def test_single_token_name_is_preserved(self):
        self.assertEqual(codecs_service.codec_service_group("MEMCACHED"), "MEMCACHED")

    def test_group_of_role_only_name_is_preserved(self):
        self.assertEqual(codecs_service.codec_service_group("UDP"), "UDP")

    def test_empty_group_is_empty(self):
        self.assertEqual(codecs_service.codec_service_group(""), "")


class ServiceExpressionTest(unittest.TestCase):
    """Expressao multiIf parametrizada: sem valores concatenados."""

    @classmethod
    def setUpClass(cls):
        conn = _seeded_connection()
        active = codecs_service.list_flow_codecs(conn, active_only=True)
        cls.codecs = codecs_service.order_flow_codecs(
            [item for item in active if codecs_service.codec_is_aggregate_classifiable(item)]
        )
        cls.params: dict = {}
        cls.expr = main._directional_service_label_expr(cls.codecs, cls.params)

    def test_expression_is_multibranch_multif(self):
        self.assertTrue(self.expr.startswith("multiIf("))

    def test_expression_uses_one_parameter_per_codec(self):
        labels = [key for key in self.params if key.startswith("dslv_label_")]
        self.assertEqual(len(labels), len(self.codecs))

    def test_values_are_parameters_not_literals(self):
        for item in self.codecs:
            group = codecs_service.codec_service_group(item["name"])
            self.assertNotIn(f"'{group}'", self.expr)

    def test_ports_are_parameters(self):
        self.assertIn("{dslv_dst_0:UInt16}", self.expr)
        self.assertIn("{dslv_proto_0:UInt8}", self.expr)

    def test_fallback_keeps_unclassified_visible(self):
        self.assertIn("TCP OTHER", main._DIRECTIONAL_SERVICE_FALLBACK_EXPR)
        self.assertIn("UDP OTHER", main._DIRECTIONAL_SERVICE_FALLBACK_EXPR)
        self.assertIn("GRE", main._DIRECTIONAL_SERVICE_FALLBACK_EXPR)
        self.assertIn("ESP", main._DIRECTIONAL_SERVICE_FALLBACK_EXPR)

    def test_expression_counts_all_configured_codecs(self):
        self.assertEqual(self.expr.count("multiIf("), 2)  # principal + fallback


class StackedSeriesTest(unittest.TestCase):
    """Series empilhadas preservam throughput total e direcao."""

    rows = [
        {"ts": "t1", "service_label": "HTTPS", "flow_direction": "download", "bps": 100.0},
        {"ts": "t1", "service_label": "QUIC", "flow_direction": "download", "bps": 60.0},
        {"ts": "t1", "service_label": "DNS", "flow_direction": "download", "bps": 5.0},
        {"ts": "t1", "service_label": "HTTPS", "flow_direction": "upload", "bps": 40.0},
        {"ts": "t1", "service_label": "DNS", "flow_direction": "upload", "bps": 3.0},
    ]

    def _totals(self, series):
        return {item["label"]: item["points"][0]["value"] for item in series}

    def test_total_sums_both_directions(self):
        series = main._directional_stacked_series(
            self.rows, "total", key_field="service_label",
            color_resolver=main._directional_service_color,
        )
        totals = self._totals(series)
        self.assertAlmostEqual(totals["HTTPS"], 140.0)
        self.assertAlmostEqual(totals["QUIC"], 60.0)
        self.assertAlmostEqual(totals["DNS"], 8.0)

    def test_download_and_upload_split(self):
        download = self._totals(main._directional_stacked_series(
            self.rows, "download", key_field="service_label",
            color_resolver=main._directional_service_color,
        ))
        upload = self._totals(main._directional_stacked_series(
            self.rows, "upload", key_field="service_label",
            color_resolver=main._directional_service_color,
        ))
        self.assertAlmostEqual(download["HTTPS"], 100.0)
        self.assertAlmostEqual(upload["HTTPS"], 40.0)
        self.assertAlmostEqual(upload["DNS"], 3.0)

    def test_top_n_switch_to_other_keeps_total(self):
        series = main._directional_stacked_series(
            self.rows, "total", key_field="service_label",
            color_resolver=main._directional_service_color,
            selected_labels={"HTTPS"},
        )
        totals = self._totals(series)
        self.assertAlmostEqual(totals["HTTPS"], 140.0)
        self.assertAlmostEqual(totals[main._DIRECTIONAL_OTHER_LABEL], 68.0)
        self.assertAlmostEqual(sum(totals.values()), 208.0)

    def test_top_labels_uses_total_throughput(self):
        selected = main._directional_top_labels(self.rows, "service_label", 2)
        self.assertEqual(selected, {"HTTPS", "QUIC"})

    def test_colors_are_stable_per_label(self):
        first = main._directional_service_color("HTTPS")
        second = main._directional_service_color("HTTPS")
        self.assertEqual(first, second)
        self.assertEqual(first, main._DIRECTIONAL_SERVICE_COLORS["HTTPS"])

    def test_series_are_ordered_by_canonical_protocol_order(self):
        rows = [
            {"ts": "t1", "label": "OTHER", "flow_direction": "download", "bps": 1.0},
            {"ts": "t1", "label": "TCP", "flow_direction": "download", "bps": 9.0},
            {"ts": "t1", "label": "UDP", "flow_direction": "download", "bps": 5.0},
        ]
        series = main._directional_protocol_series(rows, "total")
        self.assertEqual([item["label"] for item in series], ["TCP", "UDP", "OTHER"])


class DirectionalQueryStaticTest(unittest.TestCase):
    """A serie de servico usa a mesma base direcional e projeta as portas."""

    @classmethod
    def setUpClass(cls):
        cls.source = _read_asset(MAIN_PATH)

    def test_dimensions_include_ports(self):
        self.assertIn('"src_ip", "dst_ip", "proto", "src_port", "dst_port",', self.source)

    def test_series_query_groups_by_protocol_and_service(self):
        self.assertIn("GROUP BY ts, proto_label, service_label", self.source)

    def test_series_query_applies_edge_filters(self):
        self.assertIn("WHERE {rated_where} AND {download_filter}", self.source)
        self.assertIn("WHERE {rated_where} AND {upload_filter}", self.source)

    def test_payload_exposes_service_timeseries(self):
        self.assertIn('"service_timeseries": service_timeseries', self.source)
        self.assertIn('"service_timeseries": {"total": [], "download": [], "upload": []}', self.source)

    def test_rankings_are_untouched(self):
        for branch in (
            'asn_branch("external_asn_download", "download", "src_asn"',
            'asn_branch("external_asn_upload", "upload", "dst_asn"',
            'ip_branch("local_ip_download", "download", "dst_ip")',
            'ip_branch("local_ip_upload", "upload", "src_ip")',
        ):
            self.assertIn(branch, self.source)


class StackedFrontendStaticTest(unittest.TestCase):
    """Frontend empilhado por servico com toggle Servicos/Protocolos."""

    @classmethod
    def setUpClass(cls):
        cls.html = _read_asset(INDEX_HTML_PATH)

    def test_series_are_stacked(self):
        self.assertIn("stack: 'traffic'", self.html)
        self.assertIn("areaStyle: { color: hexToRgba(color, 0.72), opacity: 1 }", self.html)

    def test_series_mode_toggle_exists(self):
        self.assertIn('data-series-group="service"', self.html)
        self.assertIn('data-series-group="protocol"', self.html)
        self.assertIn("directionalSeriesMode", self.html)

    def test_mode_switch_is_wired(self):
        self.assertIn("document.querySelectorAll('.directional-series-toggle button')", self.html)
        self.assertIn("directionalSeriesMode = button.dataset.seriesGroup || 'service'", self.html)

    def test_frontend_reads_both_timeseries(self):
        self.assertIn("service_timeseries", self.html)
        self.assertIn("protocol_timeseries", self.html)

    def test_titles_and_meta_describe_current_mode(self):
        self.assertIn('id="protocolSectionTitle"', self.html)
        self.assertIn("Tráfego por Serviço", self.html)
        self.assertIn("por serviço (codecs)", self.html)

    def test_empty_state_keeps_no_infinite_loading(self):
        self.assertIn("if (!items.length || !items.some(item => (item.points || []).length))", self.html)
        self.assertIn("Sem dados de serviço no período", self.html)

    def test_tooltip_percentage_is_kept_for_stacked_reading(self):
        self.assertIn("value / bucketTotal * 100", self.html)

    def test_direction_toggle_is_preserved(self):
        for direction in ("total", "download", "upload"):
            self.assertIn(f'data-protocol-direction="{direction}"', self.html)


if __name__ == "__main__":
    unittest.main()
