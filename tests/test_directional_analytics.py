from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import app.main as main  # noqa: E402
from app.services import network_context  # noqa: E402


INDEX_HTML_PATH = os.path.join(ROOT, "frontend", "index.html")
MAIN_PATH = os.path.join(ROOT, "backend", "app", "main.py")


def _read_asset(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


class DirectionRuleTest(unittest.TestCase):
    """Regra canonica de direcao por prefixo monitorado (NetworkContext)."""

    def test_external_to_monitored_is_download(self):
        self.assertEqual(
            network_context._direction(network_context.EXTERNAL, network_context.CUSTOMER),
            "INBOUND",
        )

    def test_monitored_to_external_is_upload(self):
        self.assertEqual(
            network_context._direction(network_context.CUSTOMER, network_context.EXTERNAL),
            "OUTBOUND",
        )

    def test_monitored_to_monitored_is_ignored(self):
        self.assertEqual(
            network_context._direction(network_context.CUSTOMER, network_context.CUSTOMER),
            "INTERNAL",
        )

    def test_external_to_external_is_ignored(self):
        self.assertEqual(
            network_context._direction(network_context.EXTERNAL, network_context.EXTERNAL),
            "EXTERNAL",
        )

    def test_sql_edge_filters_follow_the_same_rule(self):
        params: dict = {}
        src_filter, dst_filter = main.cidr_membership_filters_for_clickhouse(
            ["192.0.2.0/24"], params, "t"
        )
        upload_filter, download_filter, both_filter = main.zone_edge_filters(
            src_filter, dst_filter
        )
        # download: dst pertence E src nao pertence
        self.assertIn("dst_ip", download_filter)
        self.assertIn("src_ip", download_filter)
        self.assertIn("NOT", download_filter)
        # upload: src pertence E dst nao pertence
        self.assertIn("src_ip", upload_filter)
        self.assertIn("dst_ip", upload_filter)
        self.assertIn("NOT", upload_filter)
        # both cobre as duas direcoes e exclui interno/externo puro
        self.assertIn("OR", both_filter)


class ProtocolSeriesTest(unittest.TestCase):
    """Grafico por protocolo respeita Total/Download/Upload (requisito 8)."""

    def setUp(self):
        self.rows = [
            {"ts": "2026-09-21T12:00:00+00:00", "label": "TCP", "flow_direction": "download", "bps": 100.0},
            {"ts": "2026-09-21T12:00:00+00:00", "label": "UDP", "flow_direction": "download", "bps": 50.0},
            {"ts": "2026-09-21T12:00:00+00:00", "label": "TCP", "flow_direction": "upload", "bps": 30.0},
            {"ts": "2026-09-21T12:00:00+00:00", "label": "ESP", "flow_direction": "upload", "bps": 5.0},
        ]

    @staticmethod
    def _by_label(series):
        return {item["label"]: item["points"][0]["value"] for item in series}

    def test_total_sums_both_directions(self):
        values = self._by_label(main._directional_protocol_series(self.rows, "total"))
        self.assertAlmostEqual(values["TCP"], 130.0)
        self.assertAlmostEqual(values["UDP"], 50.0)
        self.assertAlmostEqual(values["ESP"], 5.0)

    def test_download_keeps_only_download(self):
        values = self._by_label(main._directional_protocol_series(self.rows, "download"))
        self.assertAlmostEqual(values["TCP"], 100.0)
        self.assertAlmostEqual(values["UDP"], 50.0)
        self.assertNotIn("ESP", values)

    def test_upload_keeps_only_upload(self):
        values = self._by_label(main._directional_protocol_series(self.rows, "upload"))
        self.assertAlmostEqual(values["TCP"], 30.0)
        self.assertAlmostEqual(values["ESP"], 5.0)
        self.assertNotIn("UDP", values)


class MonitoredAsnTest(unittest.TestCase):
    """ASN interno (dono do bloco monitorado) nunca e listado como externo."""

    def test_monitored_asn_numbers_derives_owner_asn(self):
        with mock.patch.object(
            main,
            "resolve_asn_for_ip",
            return_value={"asn": 268568, "as_name": "FIBINET", "country": "BR", "prefix": "192.0.2.0/24", "source": "local_prefix_db"},
        ):
            numbers = main.monitored_asn_numbers(["192.0.2.0/24"])
        self.assertIn(268568, numbers)

    def test_payload_excludes_monitored_asns_statically(self):
        main_source = _read_asset(MAIN_PATH)
        self.assertIn("item[\"asn_number\"] not in monitored_asns", main_source)


class EmptyPayloadTest(unittest.TestCase):
    """Sem blocos monitorados o endpoint nao executa ClickHouse e sinaliza vazio."""

    def test_payload_without_monitored_prefixes_is_empty(self):
        payload = main.directional_analytics_payload(60)
        self.assertEqual(payload["query_source"], "none")
        self.assertEqual(payload["monitored_prefixes"], 0)
        self.assertEqual(payload["protocol_timeseries"], {"total": [], "download": [], "upload": []})
        self.assertEqual(payload["external_asn_download"]["items"], [])
        self.assertEqual(payload["external_asn_upload"]["items"], [])
        self.assertEqual(payload["local_ip_download"]["items"], [])
        self.assertEqual(payload["local_ip_upload"]["items"], [])


class FrontendStaticTest(unittest.TestCase):
    """Widgets usam a API real e preservam a composicao default/custom."""

    @classmethod
    def setUpClass(cls):
        cls.html = _read_asset(INDEX_HTML_PATH)

    def test_widgets_consume_real_api_endpoint(self):
        self.assertIn("/api/dashboard/directional-analytics", self.html)

    def test_markup_contains_directional_sections(self):
        for section_id in (
            "dashboardProtocolSection",
            "dashboardExternalAsnSection",
            "dashboardLocalIpSection",
        ):
            self.assertIn(f'id="{section_id}"', self.html)

    def test_markup_contains_ranking_tables(self):
        for table_id in (
            "externalAsnDownloadTable",
            "externalAsnUploadTable",
            "localIpDownloadTable",
            "localIpUploadTable",
        ):
            self.assertIn(f'id="{table_id}"', self.html)

    def test_protocol_toggle_has_three_directions(self):
        for direction in ("total", "download", "upload"):
            self.assertIn(f'data-protocol-direction="{direction}"', self.html)

    def test_operational_composition_includes_new_sections(self):
        self.assertIn(":not(#dashboardProtocolSection)", self.html)
        self.assertIn(":not(#dashboardExternalAsnSection)", self.html)
        self.assertIn(":not(#dashboardLocalIpSection)", self.html)

    def test_custom_composition_keeps_configurable_grid_only(self):
        # O modo custom continua exibindo apenas o grid configuravel + prefixo + alerta.
        self.assertIn(
            "#view-dashboard.dashboard-engine-active:not(.dashboard-operational) > section:not(#configurableDashboardGrid)",
            self.html,
        )

    def test_existing_overview_sections_not_removed(self):
        for section_id in ("dashboardTopInterfacesSection", "dashboardSecondaryAnalyticsSection"):
            self.assertIn(f'id="{section_id}"', self.html)

    def test_empty_state_does_not_leave_infinite_loading(self):
        self.assertIn("Sem dados direcionais no período.", self.html)
        self.assertIn("Nenhum bloco monitorado configurado.", self.html)

    def test_direction_rule_uses_src_asn_for_download_and_dst_asn_for_upload(self):
        main_source = _read_asset(MAIN_PATH)
        self.assertIn('asn_branch("external_asn_download", "download", "src_asn"', main_source)
        self.assertIn('asn_branch("external_asn_upload", "upload", "dst_asn"', main_source)

    def test_local_ip_download_groups_dst_and_upload_groups_src(self):
        main_source = _read_asset(MAIN_PATH)
        self.assertIn('ip_branch("local_ip_download", "download", "dst_ip")', main_source)
        self.assertIn('ip_branch("local_ip_upload", "upload", "src_ip")', main_source)


if __name__ == "__main__":
    unittest.main()
