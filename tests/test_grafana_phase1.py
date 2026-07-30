from __future__ import annotations

import copy
import json
import unittest

from backend.app.services.grafana_api import (
    GRAFANA_METRICS,
    canonical_ranking,
    validate_ranking_request,
    validate_timeseries_request,
)
from backend.app.services.grafana_exporter import (
    dashboard_from_grafana_export,
    export_dashboard,
)
from backend.app.services.dashboard_widgets import validate_widget_definition
from tests.test_grafana_exporter import sample_dashboard


FROM = "2026-07-29T10:00:00Z"
TO = "2026-07-29T11:00:00Z"


def prefix_dashboard() -> dict:
    dashboard = sample_dashboard()
    dashboard.update(
        {
            "revision": 7,
            "layout_version": 7,
            "global_filters": [
                {"field": "sensor", "operator": "eq", "value": 4},
                {"field": "interface", "operator": "eq", "value": 11},
                {"field": "protocol", "operator": "eq", "value": "udp"},
                {"field": "direction", "operator": "eq", "value": "upload"},
                {"field": "zone", "operator": "eq", "value": 7},
            ],
            "prefix_filter": {
                "enabled": True,
                "cidr": "186.232.160.0/20",
                "address_family": "ipv4",
                "match_side": "either",
            },
            "prefix_grouping": {
                "enabled": True,
                "ipv4_prefix_length": 24,
                "ipv6_prefix_length": 56,
                "side": "destination",
                "top_n": 20,
            },
        }
    )
    dashboard["widgets"][0]["config"].update(
        {
            "metric": "bps",
            "group_by": "dst_prefix",
            "api_token": "must-not-leak",
            "headers": {"Authorization": "Bearer must-not-leak"},
        }
    )
    dashboard["widgets"][3]["config"].update(
        {
            "dimension": "dst_prefix",
            "limit": 20,
        }
    )
    return dashboard


def target_bodies(exported: dict) -> list[dict]:
    return [
        json.loads(panel["targets"][0]["url_options"]["data"])
        for panel in exported["dashboard"]["panels"]
    ]


class GrafanaPhase1ExportTest(unittest.TestCase):
    def test_fixed_export_preserves_layout_and_saved_prefix_filter(self):
        source = prefix_dashboard()
        snapshot = copy.deepcopy(source)
        exported = export_dashboard(
            source,
            include_saved_filters=True,
            make_filters_editable=False,
            include_variables=True,
        )
        self.assertEqual(source, snapshot)
        self.assertEqual(exported["dashboard"]["templating"]["list"], [])
        self.assertEqual(
            exported["dashboard"]["panels"][0]["gridPos"],
            {"x": 0, "y": 0, "w": 8, "h": 6},
        )
        for body in target_bodies(exported):
            self.assertEqual(body["from"], "$__isoFrom()")
            self.assertEqual(body["to"], "$__isoTo()")
            self.assertEqual(
                body["prefix_filter"]["cidr"],
                "186.232.160.0/20",
            )
            self.assertEqual(body["filters"]["sensor_ids"], [4])
            self.assertEqual(body["filters"]["interfaces"], [11])
            self.assertEqual(body["filters"]["protocols"], ["udp"])
            self.assertEqual(body["filters"]["direction"], "upload")
            self.assertEqual(body["zone"], 7)

    def test_editable_export_has_required_variables_and_placeholders(self):
        exported = export_dashboard(
            prefix_dashboard(),
            make_filters_editable=True,
            include_variables=True,
            include_prefixes=True,
        )
        variables = {
            item["name"]: item
            for item in exported["dashboard"]["templating"]["list"]
        }
        self.assertEqual(
            set(variables),
            {
                "prefix",
                "prefix_group",
                "prefix_length",
                "ipv6_prefix_length",
                "match_side",
                "address_family",
                "sensor",
                "interface",
                "direction",
                "zone",
                "top_n",
            },
        )
        bodies = target_bodies(exported)
        self.assertEqual(variables["sensor"]["current"]["value"], "4")
        self.assertEqual(variables["interface"]["current"]["value"], "11")
        self.assertEqual(variables["zone"]["current"]["value"], "7")
        self.assertTrue(
            all(body["prefix_filter"]["cidr"] == "${prefix}" for body in bodies)
        )
        self.assertTrue(
            all(
                body["sensor"] == "${sensor}"
                and body["interface"] == "${interface}"
                and body["direction"] == "${direction}"
                and body["zone"] == "${zone}"
                for body in bodies
            )
        )
        self.assertTrue(
            all(
                body["prefix_grouping"]["ipv4_prefix_length"]
                == "${prefix_length}"
                for body in bodies
            )
        )
        ranking = next(body for body in bodies if "top_n" in body)
        self.assertEqual(ranking["top_n"], "${top_n}")

    def test_export_options_metadata_and_secret_scrubbing(self):
        exported = export_dashboard(
            prefix_dashboard(),
            grafana_version="12.1",
            datasource_uid="gmj-api",
            datasource_type="yesoreyeram-infinity-datasource",
            folder_uid="network-observability",
            dashboard_title="Fluxos por prefixo",
            dashboard_uid="fluxos-prefixo",
            refresh="1m",
            default_from="now-6h",
            default_to="now",
        )
        dashboard = exported["dashboard"]
        self.assertEqual(dashboard["title"], "Fluxos por prefixo")
        self.assertEqual(dashboard["uid"], "fluxos-prefixo")
        self.assertEqual(dashboard["refresh"], "1m")
        self.assertEqual(dashboard["time"], {"from": "now-6h", "to": "now"})
        self.assertEqual(exported["folderUid"], "network-observability")
        self.assertEqual(dashboard["gmj_flow"]["source"], "gmj-flow")
        self.assertEqual(dashboard["gmj_flow"]["schema_version"], 1)
        self.assertEqual(dashboard["gmj_flow"]["dashboard_revision"], 7)
        serialized = json.dumps(exported).lower()
        self.assertNotIn("must-not-leak", serialized)
        self.assertNotIn("authorization", serialized)
        self.assertNotIn("api_token", serialized)
        self.assertFalse(exported["meta"]["credentials_included"])

    def test_only_authentic_untampered_gmj_exports_can_be_reimported(self):
        exported = export_dashboard(prefix_dashboard())
        definition = dashboard_from_grafana_export(exported)
        self.assertEqual(definition["name"], "Observabilidade")
        self.assertEqual(
            definition["prefix_filter"]["cidr"],
            "186.232.160.0/20",
        )
        self.assertEqual(len(definition["widgets"]), 11)
        self.assertNotIn("id", definition["widgets"][0])

        with self.assertRaisesRegex(ValueError, "somente dashboards"):
            dashboard_from_grafana_export(
                {"dashboard": {"title": "Grafana arbitrário"}}
            )

        tampered = copy.deepcopy(exported)
        tampered["dashboard"]["panels"][0]["title"] = "Alterado"
        with self.assertRaisesRegex(ValueError, "assinatura estrutural"):
            dashboard_from_grafana_export(tampered)

    def test_prefix_widget_aliases_export_the_matching_public_metric(self):
        aliases = {
            "traffic_by_prefix_bps": "traffic_by_prefix_bps",
            "traffic_by_prefix_pps": "traffic_by_prefix_pps",
            "top_source_prefixes": "top_source_prefixes",
            "top_destination_prefixes": "top_destination_prefixes",
            "prefix_timeseries": "prefix_timeseries",
            "top_ports_by_prefix": "top_ports_by_prefix",
            "top_protocols_by_prefix": "top_protocols_by_prefix",
            "prefix_table": "top_destination_prefixes",
            "prefix_distribution": "top_destination_prefixes",
        }
        dashboard = prefix_dashboard()
        dashboard["widgets"] = [
            validate_widget_definition(
                {
                    "title": alias,
                    "type": alias,
                    "category": "traffic",
                    "config": {},
                    "visualization": {},
                    "grid": {
                        "x": index % 3 * 4,
                        "y": index // 3 * 6,
                        "w": 4,
                        "h": 6,
                    },
                }
            )
            for index, alias in enumerate(aliases)
        ]
        exported = export_dashboard(dashboard)
        metrics = [
            body["metric"]
            for body in target_bodies(exported)
        ]
        self.assertEqual(metrics, list(aliases.values()))


class GrafanaPrefixContractTest(unittest.TestCase):
    def test_prefix_metrics_are_registered_with_correct_dimensions(self):
        expected = {
            "traffic_by_prefix_bps": "timeseries",
            "traffic_by_prefix_pps": "timeseries",
            "prefix_timeseries": "timeseries",
            "top_source_prefixes": "ranking",
            "top_destination_prefixes": "ranking",
            "top_ports_by_prefix": "ranking",
            "top_protocols_by_prefix": "ranking",
        }
        self.assertEqual(
            {metric: GRAFANA_METRICS[metric]["kind"] for metric in expected},
            expected,
        )
        self.assertEqual(
            GRAFANA_METRICS["top_source_prefixes"]["dimensions"],
            ["source_prefix"],
        )
        self.assertEqual(
            GRAFANA_METRICS["top_destination_prefixes"]["dimensions"],
            ["destination_prefix"],
        )

    def test_timeseries_and_ranking_accept_ipv4_ipv6_prefix_context(self):
        timeseries = validate_timeseries_request(
            {
                "metric": "traffic_by_prefix_bps",
                "from": FROM,
                "to": TO,
                "group_by": ["dst_prefix"],
                "prefix_filter": {
                    "cidr": "2001:db8:1200::/48",
                    "address_family": "ipv6",
                    "match_side": "destination",
                },
                "prefix_grouping": {
                    "enabled": True,
                    "ipv4_prefix_length": 24,
                    "ipv6_prefix_length": 56,
                    "side": "destination",
                },
            }
        )
        self.assertEqual(
            timeseries["prefix_filter"]["cidr"],
            "2001:db8:1200::/48",
        )
        self.assertEqual(
            timeseries["prefix_grouping"]["ipv6_prefix_length"],
            56,
        )

        ranking = validate_ranking_request(
            {
                "metric": "top_ports_by_prefix",
                "from": FROM,
                "to": TO,
                "top_n": 25,
                "filters": {
                    "direction": "download",
                    "protocols": ["tcp"],
                },
                "prefix_filter": {
                    "start_ip": "192.0.2.10",
                    "end_ip": "192.0.2.30",
                    "address_family": "ipv4",
                    "match_side": "either",
                },
            }
        )
        self.assertEqual(ranking["top_n"], 25)
        self.assertEqual(ranking["filters"]["protocols"], ["tcp"])
        self.assertEqual(ranking["prefix_filter"]["start_ip"], "192.0.2.10")

    def test_editable_scalar_variables_accept_all_or_positive_ids(self):
        editable = validate_timeseries_request(
            {
                "metric": "traffic_bps",
                "from": FROM,
                "to": TO,
                "sensor": "all",
                "interface": "all",
                "zone": "all",
                "direction": "upload",
            }
        )
        self.assertEqual(editable["filters"]["sensor_ids"], [])
        self.assertEqual(editable["filters"]["interfaces"], [])
        self.assertEqual(editable["filters"]["direction"], "upload")
        self.assertIsNone(editable["zone_id"])

        fixed = validate_ranking_request(
            {
                "metric": "top_protocols",
                "from": FROM,
                "to": TO,
                "sensor": "4",
                "interface": "11",
                "zone": "7",
            }
        )
        self.assertEqual(fixed["filters"]["sensor_ids"], [4])
        self.assertEqual(fixed["filters"]["interfaces"], [11])
        self.assertEqual(fixed["zone_id"], 7)

    def test_prefix_rankings_keep_cidr_port_and_protocol_labels(self):
        cases = (
            (
                "top_source_prefixes",
                {"prefix": "192.0.2.17/24", "value": 30},
                "192.0.2.0/24",
            ),
            (
                "top_destination_prefixes",
                {"key": "2001:db8:1200::/56", "value": 20},
                "2001:db8:1200::/56",
            ),
            (
                "top_ports_by_prefix",
                {"port": 53, "protocol": "udp", "value": 10},
                "udp/53",
            ),
            (
                "top_protocols_by_prefix",
                {"proto": 58, "value": 5},
                "IPv6-ICMP",
            ),
        )
        for metric, item, expected_label in cases:
            request = validate_ranking_request(
                {
                    "metric": metric,
                    "from": FROM,
                    "to": TO,
                }
            )
            result = canonical_ranking(
                {"items": [item], "source": "raw"},
                request,
                "prefix-contract",
            )
            self.assertEqual(result["items"][0]["label"], expected_label)
            self.assertEqual(result["items"][0]["percent"], 100.0)


if __name__ == "__main__":
    unittest.main()
