from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from backend.app.services.grafana_api import (
    GRAFANA_ANOMALY_FIELDS,
    GRAFANA_CGNAT_FIELDS,
    GRAFANA_RANKING_QUERY_PLANS,
    GrafanaApiError,
    authenticate,
    canonical_active_anomalies,
    canonical_anomaly_item,
    canonical_bgp_status_item,
    canonical_mitigation_item,
    canonical_ranking,
    canonical_timeseries,
    catalog,
    filter_anomaly_history,
    is_grafana_api_path,
    mitigation_is_active,
    service_document,
    validate_mitigation_filters,
    validate_ranking_request,
    validate_timeseries_request,
)


BASE_ENV = {
    "GMJ_FLOW_GRAFANA_TOKEN": "test-grafana-token",
    "GMJ_FLOW_GRAFANA_PREVIOUS_TOKEN": "",
    "GMJ_FLOW_GRAFANA_SCOPES": (
        "grafana:data:read,grafana:dashboard:export"
    ),
    "GMJ_FLOW_GRAFANA_RATE_LIMIT_PER_MINUTE": "9999",
}


class GrafanaAuthenticationTest(unittest.TestCase):
    def test_dedicated_auth_namespace_does_not_capture_session_export(self):
        self.assertTrue(is_grafana_api_path("/api/v1/grafana"))
        self.assertTrue(is_grafana_api_path("/api/v1/grafana/health"))
        self.assertTrue(
            is_grafana_api_path("/api/v1/grafana/query/timeseries")
        )
        self.assertFalse(
            is_grafana_api_path("/api/dashboards/42/grafana-export")
        )
        self.assertFalse(is_grafana_api_path("/api/dashboard/series"))

    def test_missing_token_is_rejected(self):
        with patch.dict(os.environ, BASE_ENV, clear=False):
            with self.assertRaises(GrafanaApiError) as missing:
                authenticate(None, "grafana:data:read")
        self.assertEqual(missing.exception.status_code, 401)
        self.assertEqual(missing.exception.error, "grafana_token_required")

    def test_valid_token_returns_scopes_without_secret(self):
        with patch.dict(os.environ, BASE_ENV, clear=False):
            result = authenticate(
                "Bearer test-grafana-token",
                "grafana:data:read",
                request_correlation_id="contract-test",
            )
        self.assertEqual(result["correlation_id"], "contract-test")
        self.assertIn("grafana:data:read", result["scopes"])
        self.assertNotIn("test-grafana-token", str(result))

    def test_valid_read_token_allows_200_save_and_test_response(self):
        with patch.dict(os.environ, BASE_ENV, clear=False):
            context = authenticate(
                "Bearer test-grafana-token",
                "grafana:data:read",
            )
        response = {
            "status_code": 200,
            "body": service_document("2026-07-29T12:00:00Z"),
            "correlation_id": context["correlation_id"],
        }
        self.assertEqual(response["status_code"], 200)
        self.assertEqual(response["body"]["status"], "ok")

    def test_invalid_token_and_missing_scope_are_structured(self):
        with patch.dict(os.environ, BASE_ENV, clear=False):
            with self.assertRaises(GrafanaApiError) as invalid:
                authenticate("Bearer wrong", "grafana:data:read")
            with self.assertRaises(GrafanaApiError) as scope:
                authenticate(
                    "Bearer test-grafana-token",
                    "grafana:dashboard:publish",
                )
        self.assertEqual(invalid.exception.status_code, 401)
        self.assertEqual(invalid.exception.error, "grafana_token_invalid")
        self.assertEqual(scope.exception.status_code, 403)
        self.assertEqual(scope.exception.error, "grafana_scope_insufficient")

    def test_data_routes_reject_token_without_data_read_scope(self):
        env = {
            **BASE_ENV,
            "GMJ_FLOW_GRAFANA_SCOPES": "grafana:dashboard:export",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(GrafanaApiError) as caught:
                authenticate(
                    "Bearer test-grafana-token",
                    "grafana:data:read",
                )
        self.assertEqual(caught.exception.status_code, 403)
        self.assertEqual(
            caught.exception.error,
            "grafana_scope_insufficient",
        )

    def test_bearer_token_is_not_written_to_auth_log(self):
        with patch.dict(os.environ, BASE_ENV, clear=False):
            with self.assertLogs("gmj-flow.grafana", level="INFO") as logs:
                authenticate(
                    "Bearer test-grafana-token",
                    "grafana:data:read",
                    request_correlation_id="log-contract-test",
                )
        self.assertNotIn("test-grafana-token", "\n".join(logs.output))


class GrafanaRequestValidationTest(unittest.TestCase):
    def test_catalog_is_stable_and_whitelisted(self):
        result = catalog()
        self.assertEqual(result["api_version"], "v1")
        self.assertEqual(
            {item["id"] for item in result["metrics"]},
            {
                "traffic_bps",
                "traffic_pps",
                "top_download_origins",
                "top_upload_destinations",
                "top_protocols",
                "top_source_ips",
                "top_destination_ips",
                "top_ports",
                "top_tcp_flags",
            },
        )
        ranking_metrics = {
            item["id"]: item
            for item in result["metrics"]
            if item["kind"] == "ranking"
        }
        self.assertEqual(
            ranking_metrics["top_source_ips"]["dimensions"],
            ["source_ip"],
        )
        self.assertEqual(
            ranking_metrics["top_destination_ips"]["dimensions"],
            ["destination_ip"],
        )
        self.assertEqual(
            ranking_metrics["top_ports"]["dimensions"],
            ["protocol", "port"],
        )
        self.assertEqual(ranking_metrics["top_tcp_flags"]["unit"], "pps")
        self.assertEqual(
            set(result["ranking_calculations"]),
            {
                "last",
                "last_not_null",
                "mean",
                "max",
                "min",
                "total",
                "rate",
            },
        )
        self.assertEqual(
            set(GRAFANA_RANKING_QUERY_PLANS),
            set(ranking_metrics),
        )
        self.assertEqual(
            GRAFANA_RANKING_QUERY_PLANS["top_upload_destinations"],
            {
                "dimension": "dst_asn",
                "direction": "upload",
                "metric": "bps",
            },
        )
        self.assertEqual(
            GRAFANA_RANKING_QUERY_PLANS["top_download_origins"],
            {
                "dimension": "src_asn",
                "direction": "download",
                "metric": "bps",
            },
        )
        self.assertEqual(
            GRAFANA_RANKING_QUERY_PLANS["top_ports"]["dimension"],
            "dst_port",
        )
        self.assertEqual(
            GRAFANA_RANKING_QUERY_PLANS["top_tcp_flags"]["metric"],
            "pps",
        )
        self.assertEqual(
            {item["id"] for item in result["datasets"]},
            {
                "anomalies_active",
                "anomalies_history",
                "mitigations",
                "mitigations_active",
                "bgp_status",
            },
        )
        self.assertTrue(
            {
                "cgnat_private_ip",
                "cgnat_public_ip",
                "cgnat_public_port",
                "cgnat_pool",
                "cgnat_device",
            }
            <= set(result["resource_fields"])
        )

    def test_save_and_test_document_lists_read_endpoints(self):
        result = service_document("2026-07-29T12:00:00Z")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["service"], "gmj-flow-grafana-api")
        self.assertEqual(result["api_version"], "v1")
        self.assertEqual(result["timestamp"], "2026-07-29T12:00:00Z")
        self.assertEqual(
            result["endpoints"]["anomalies_active"],
            "/api/v1/grafana/anomalies/active",
        )
        self.assertEqual(
            result["endpoints"]["bgp_status"],
            "/api/v1/grafana/bgp/status",
        )
        self.assertEqual(
            result["endpoints"]["mitigations_active"],
            "/api/v1/grafana/mitigations/active",
        )

    def test_timeseries_applies_max_points_to_interval(self):
        request = validate_timeseries_request(
            {
                "metric": "traffic_bps",
                "from": "2026-07-28T10:00:00Z",
                "to": "2026-07-28T11:00:00Z",
                "interval_ms": 1000,
                "max_data_points": 60,
                "filters": {"direction": "both"},
                "group_by": ["direction"],
                "calculation": "rate",
                "timezone": "UTC",
            }
        )
        self.assertEqual(request["interval_ms"], 60000)
        self.assertFalse(request["include_partial_bucket"])

    def test_rejects_large_filter_fanout_and_non_utc_timezone(self):
        payload = {
            "metric": "traffic_bps",
            "from": "2026-07-28T10:00:00Z",
            "to": "2026-07-28T10:10:00Z",
            "filters": {"protocols": ["tcp", "udp"]},
            "group_by": ["direction"],
            "calculation": "rate",
        }
        with self.assertRaises(GrafanaApiError) as filters:
            validate_timeseries_request(payload)
        self.assertEqual(filters.exception.error, "filter_limit_exceeded")
        with self.assertRaises(GrafanaApiError) as timezone:
            validate_timeseries_request(
                {
                    **payload,
                    "filters": {},
                    "timezone": "America/Sao_Paulo",
                }
            )
        self.assertEqual(timezone.exception.error, "timezone_not_allowed")

    def test_ranking_rejects_timeseries_metric(self):
        with self.assertRaises(GrafanaApiError) as caught:
            validate_ranking_request(
                {
                    "metric": "traffic_bps",
                    "from": "2026-07-28T10:00:00Z",
                    "to": "2026-07-28T10:10:00Z",
                }
            )
        self.assertEqual(caught.exception.error, "metric_not_allowed")

    def test_all_top_n_metrics_accept_filters_and_calculations(self):
        metrics = {
            "top_upload_destinations",
            "top_download_origins",
            "top_source_ips",
            "top_destination_ips",
            "top_ports",
            "top_protocols",
            "top_tcp_flags",
        }
        for metric in metrics:
            for calculation in (
                "last",
                "last_not_null",
                "mean",
                "max",
                "min",
                "total",
                "rate",
            ):
                request = validate_ranking_request(
                    {
                        "metric": metric,
                        "from": "2026-07-28T10:00:00Z",
                        "to": "2026-07-28T10:10:00Z",
                        "direction": "upload",
                        "sensor": 4,
                        "interface": 11,
                        "protocol": "udp",
                        "top_n": 100,
                        "calculation": calculation,
                    }
                )
                self.assertEqual(request["filters"]["direction"], "upload")
                self.assertEqual(request["filters"]["sensor_ids"], [4])
                self.assertEqual(request["filters"]["interfaces"], [11])
                self.assertEqual(request["filters"]["protocols"], ["udp"])
                self.assertEqual(request["top_n"], 100)
                self.assertEqual(
                    int((request["end"] - request["start"]).total_seconds()),
                    600,
                )

    def test_ranking_validates_direction_top_n_and_filter_conflicts(self):
        base = {
            "metric": "top_source_ips",
            "from": "2026-07-28T10:00:00Z",
            "to": "2026-07-28T10:10:00Z",
        }
        self.assertEqual(
            validate_ranking_request({**base, "top_n": 1})["top_n"],
            1,
        )
        self.assertEqual(
            validate_ranking_request(
                {**base, "direction": "download"}
            )["filters"]["direction"],
            "download",
        )
        for top_n in (0, 101):
            with self.assertRaises(GrafanaApiError) as caught:
                validate_ranking_request({**base, "top_n": top_n})
            self.assertEqual(caught.exception.error, "top_n_not_allowed")
        with self.assertRaises(GrafanaApiError) as direction:
            validate_ranking_request({**base, "direction": "sideways"})
        self.assertEqual(direction.exception.error, "filter_not_allowed")
        with self.assertRaises(GrafanaApiError) as conflict:
            validate_ranking_request(
                {
                    **base,
                    "protocol": "udp",
                    "filters": {"protocols": ["tcp"]},
                }
            )
        self.assertEqual(conflict.exception.error, "filter_not_allowed")


class GrafanaCanonicalResponseTest(unittest.TestCase):
    def test_timeseries_is_positive_sorted_and_deduplicated(self):
        request = validate_timeseries_request(
            {
                "metric": "traffic_bps",
                "from": "2026-07-28T10:00:00Z",
                "to": "2026-07-28T10:10:00Z",
                "filters": {},
                "group_by": ["direction"],
                "calculation": "rate",
            }
        )
        result = canonical_timeseries(
            {
                "source": "aggregate",
                "series": [
                    {
                        "name": "Upload",
                        "direction": "upload",
                        "points": [
                            {
                                "ts": "2026-07-28T10:01:00Z",
                                "value": -20,
                            },
                            {
                                "ts": "2026-07-28T10:00:00Z",
                                "value": 10,
                            },
                            {
                                "ts": "2026-07-28T10:00:00Z",
                                "value": 12,
                            },
                        ],
                    }
                ],
            },
            request,
            "canonical-test",
        )
        points = result["series"][0]["points"]
        self.assertEqual(len(points), 2)
        self.assertLess(points[0]["timestamp"], points[1]["timestamp"])
        self.assertEqual(points[0]["value"], 12)
        self.assertEqual(points[1]["value"], 20)
        self.assertFalse(result["meta"]["include_partial_bucket"])

    def test_timeseries_preserves_null_without_converting_it_to_zero(self):
        request = validate_timeseries_request(
            {
                "metric": "traffic_pps",
                "from": "2026-07-28T10:00:00Z",
                "to": "2026-07-28T10:10:00Z",
                "filters": {},
                "group_by": ["direction"],
                "calculation": "rate",
            }
        )
        result = canonical_timeseries(
            {
                "series": [
                    {
                        "name": "Download",
                        "direction": "download",
                        "points": [
                            {
                                "ts": "2026-07-28T10:00:00Z",
                                "value": None,
                            },
                            {
                                "ts": "2026-07-28T10:01:00Z",
                                "value": 0,
                            },
                        ],
                    }
                ]
            },
            request,
            "null-test",
        )
        self.assertIsNone(result["series"][0]["points"][0]["value"])
        self.assertEqual(result["series"][0]["points"][1]["value"], 0)

    def test_ranking_table_contract(self):
        request = validate_ranking_request(
            {
                "metric": "top_protocols",
                "from": "2026-07-28T10:00:00Z",
                "to": "2026-07-28T10:10:00Z",
                "format": "table",
            }
        )
        result = canonical_ranking(
            {
                "items": [
                    {"key": "tcp", "value": 80, "percentage": 80},
                    {"key": "udp", "value": 20, "percentage": 20},
                ]
            },
            request,
            "ranking-test",
        )
        self.assertEqual(
            [column["name"] for column in result["columns"]],
            [
                "rank",
                "label",
                "value",
                "percent",
            ],
        )
        self.assertEqual(result["rows"][0], [1, "TCP", 80.0, 80.0])
        self.assertEqual(result["meta"]["metric"], "top_protocols")
        self.assertEqual(result["meta"]["total"], 100.0)

    def test_asn_ranking_exposes_network_and_country_contract(self):
        request = validate_ranking_request(
            {
                "metric": "top_upload_destinations",
                "from": "2026-07-28T10:00:00Z",
                "to": "2026-07-28T10:10:00Z",
            }
        )
        result = canonical_ranking(
            {
                "total": 1000,
                "timestamp": "2026-07-28T10:10:00Z",
                "items": [
                    {
                        "key": "AS263009",
                        "label": "AS263009 — Nome da rede",
                        "value": 790,
                        "packets_s": 18,
                        "percentage": 79,
                        "metadata": {
                            "asn": 263009,
                            "as_name": "Nome da rede",
                            "org_name": "Organizacao",
                            "country": "BR",
                            "country_code": "BR",
                            "country_name": "Brazil",
                            "password": "must-not-leak",
                            "announce_command": "must-not-leak",
                        },
                    }
                ],
            },
            request,
            "asn-ranking",
        )
        item = result["items"][0]
        self.assertEqual(item["asn"], 263009)
        self.assertEqual(item["asn_name"], "Nome da rede")
        self.assertEqual(item["country_code"], "BR")
        self.assertEqual(item["country_name"], "Brazil")
        self.assertEqual(item["bps"], 790)
        self.assertEqual(item["pps"], 18)
        self.assertEqual(item["percentage"], 100)
        self.assertEqual(result["total"], 790)
        self.assertEqual(result["timestamp"], "2026-07-28T10:10:00Z")
        self.assertNotIn("must-not-leak", str(result))

    def test_ports_use_protocol_and_destination_port_display(self):
        request = validate_ranking_request(
            {
                "metric": "top_ports",
                "from": "2026-07-28T10:00:00Z",
                "to": "2026-07-28T10:10:00Z",
            }
        )
        result = canonical_ranking(
            {
                "items": [
                    {
                        "key": "UDP/443",
                        "value": 250,
                        "bits_s": 250,
                        "packets_s": 25,
                        "port": 443,
                        "protocol": "UDP",
                    }
                ]
            },
            request,
            "port-ranking",
        )
        item = result["items"][0]
        self.assertEqual(item["key"], "udp/443")
        self.assertEqual(item["display_name"], "udp/443")
        self.assertEqual(item["protocol"], "UDP")
        self.assertEqual(item["port"], 443)

    def test_tcp_flags_are_normalized_and_keep_pps_packets(self):
        request = validate_ranking_request(
            {
                "metric": "top_tcp_flags",
                "from": "2026-07-28T10:00:00Z",
                "to": "2026-07-28T10:10:00Z",
            }
        )
        result = canonical_ranking(
            {
                "items": [
                    {
                        "key": "",
                        "label": "NONE",
                        "value": 80,
                        "packets": 800,
                    },
                    {
                        "key": "ACK,SYN,PSH",
                        "label": "ACK,SYN,PSH",
                        "value": 20,
                        "packets": 200,
                    },
                ]
            },
            request,
            "flags-ranking",
        )
        self.assertEqual(result["items"][0]["tcp_flags"], "NONE")
        self.assertEqual(result["items"][0]["pps"], 80)
        self.assertEqual(result["items"][0]["packets"], 800)
        self.assertEqual(result["items"][1]["tcp_flags"], "SYN,PSH,ACK")
        self.assertEqual(result["items"][1]["percentage"], 20)

    def test_all_rankings_use_their_own_dimension_and_returned_value_total(self):
        cases = {
            "top_source_ips": (
                [
                    {"ip": "192.0.2.10", "key": "wrong", "value": 3},
                    {"ip": "2001:db8::10", "key": "wrong", "value": 1},
                ],
                ["192.0.2.10", "2001:db8::10"],
            ),
            "top_destination_ips": (
                [
                    {"ip": "198.51.100.20", "key": "wrong", "value": 3},
                    {"ip": "2001:db8:1::20", "key": "wrong", "value": 1},
                ],
                ["198.51.100.20", "2001:db8:1::20"],
            ),
            "top_ports": (
                [
                    {
                        "key": "192.0.2.10",
                        "protocol": "tcp",
                        "port": 443,
                        "value": 3,
                    },
                    {
                        "key": "2001:db8::10",
                        "protocol": "udp",
                        "port": 53,
                        "value": 1,
                    },
                ],
                ["tcp/443", "udp/53"],
            ),
            "top_protocols": (
                [
                    {"key": "192.0.2.10", "proto": 6, "value": 3},
                    {"key": "2001:db8::10", "proto": 58, "value": 1},
                ],
                ["TCP", "IPv6-ICMP"],
            ),
            "top_tcp_flags": (
                [
                    {"key": "192.0.2.10", "flags": 18, "value": 3},
                    {"key": "2001:db8::10", "flags": 17, "value": 1},
                ],
                ["SYN,ACK", "FIN,ACK"],
            ),
            "top_upload_destinations": (
                [
                    {
                        "key": "192.0.2.10",
                        "asn_number": 64500,
                        "description": "Destino SA",
                        "country": "BR",
                        "value": 3,
                    },
                    {
                        "key": "2001:db8::10",
                        "asn_number": 64501,
                        "description": "Transit Inc",
                        "country": "US",
                        "value": 1,
                    },
                ],
                [
                    "AS64500 — Destino SA (BR)",
                    "AS64501 — Transit Inc (US)",
                ],
            ),
            "top_download_origins": (
                [
                    {
                        "key": "192.0.2.10",
                        "asn_number": 64510,
                        "description": "Origem SA",
                        "country": "BR",
                        "value": 3,
                    },
                    {
                        "key": "2001:db8::10",
                        "asn_number": 64511,
                        "description": "Origin Inc",
                        "country": "US",
                        "value": 1,
                    },
                ],
                [
                    "AS64510 — Origem SA (BR)",
                    "AS64511 — Origin Inc (US)",
                ],
            ),
        }
        for metric, (items, expected_labels) in cases.items():
            with self.subTest(metric=metric):
                request = validate_ranking_request(
                    {
                        "metric": metric,
                        "from": "2026-07-28T10:00:00Z",
                        "to": "2026-07-28T10:10:00Z",
                    }
                )
                result = canonical_ranking(
                    {
                        "total": 999999,
                        "items": [
                            {**item, "percentage": 999}
                            for item in items
                        ],
                    },
                    request,
                    "dimension-contract",
                )
                self.assertEqual(
                    [item["label"] for item in result["items"]],
                    expected_labels,
                )
                self.assertEqual(result["total"], 4)
                percentages = [
                    item["percentage"] for item in result["items"]
                ]
                self.assertEqual(percentages, [75.0, 25.0])
                self.assertTrue(
                    all(0 <= percentage <= 100 for percentage in percentages)
                )
                self.assertLessEqual(sum(percentages), 100.0)

    def test_ports_protocols_and_flags_never_use_an_ip_fallback(self):
        for metric in ("top_ports", "top_protocols", "top_tcp_flags"):
            with self.subTest(metric=metric):
                request = validate_ranking_request(
                    {
                        "metric": metric,
                        "from": "2026-07-28T10:00:00Z",
                        "to": "2026-07-28T10:10:00Z",
                    }
                )
                result = canonical_ranking(
                    {
                        "items": [
                            {
                                "key": "192.0.2.55",
                                "label": "192.0.2.55",
                                "value": 100,
                            }
                        ]
                    },
                    request,
                    "no-ip-fallback",
                )
                self.assertEqual(result["items"], [])
                self.assertEqual(result["total"], 0)

    def test_empty_ranking_is_jsonpath_safe_and_has_no_secrets(self):
        request = validate_ranking_request(
            {
                "metric": "top_destination_ips",
                "from": "2026-07-28T10:00:00Z",
                "to": "2026-07-28T10:10:00Z",
            }
        )
        result = canonical_ranking({}, request, "empty-ranking")
        self.assertEqual(result["items"], [])
        self.assertEqual(result["total"], 0)
        serialized = str(result).lower()
        for secret in (
            "bearer",
            "password",
            "announce_command",
            "withdraw_command",
        ):
            self.assertNotIn(secret, serialized)


class GrafanaResourceResponseTest(unittest.TestCase):
    def setUp(self):
        self.history = [
            {
                "id": 11,
                "status": "ended",
                "severity": "critical",
                "display_name": "DNS flood",
                "top_src_ip": "198.51.100.10",
                "top_dst_ip": "203.0.113.20",
                "top_src_port": 53000,
                "top_dst_port": 53,
                "protocol": "udp",
                "metric_unit": "bits_s",
                "observed_value": 8000,
                "estimated_bytes": 12000,
                "estimated_packets": 250,
                "started_at": "2026-07-29T10:00:00Z",
                "last_seen_at": "2026-07-29T10:10:00Z",
                "mitigation_state": "announcement_applied",
            },
            {
                "id": 12,
                "status": "closed",
                "severity": "warning",
                "summary": "Port scan",
                "top_src_ip": "192.0.2.15",
                "top_dst_ip": "203.0.113.30",
                "decoder": "tcp",
                "metric_unit": "packets_s",
                "observed_value": 75,
                "started_at": "2026-07-29T11:00:00Z",
                "last_seen_at": "2026-07-29T11:02:00Z",
            },
        ]

    def test_active_anomaly_contract_has_only_documented_fields(self):
        active = {**self.history[0], "status": "active"}
        result = canonical_active_anomalies([active, self.history[1]])
        self.assertEqual(len(result), 1)
        self.assertEqual(tuple(result[0]), GRAFANA_ANOMALY_FIELDS)
        self.assertEqual(result[0]["bps"], 8000)
        self.assertEqual(result[0]["pps"], 0)
        self.assertEqual(result[0]["duration_seconds"], 600)
        self.assertEqual(
            result[0]["mitigation_status"],
            "announcement_applied",
        )

    def test_history_filters_time_status_severity_and_search(self):
        items, total = filter_anomaly_history(
            self.history,
            from_value="2026-07-29T09:55:00Z",
            to_value="2026-07-29T10:30:00Z",
            status="ended",
            severity="critical",
            search="198.51.100.10",
        )
        self.assertEqual(total, 1)
        self.assertEqual([item["id"] for item in items], [11])

    def test_history_paginates_after_sorting_and_caps_limit(self):
        items, total = filter_anomaly_history(
            self.history,
            limit=10000,
            offset=1,
        )
        self.assertEqual(total, 2)
        self.assertEqual([item["id"] for item in items], [11])

    def test_history_rejects_inverted_time_range(self):
        with self.assertRaises(GrafanaApiError) as caught:
            filter_anomaly_history(
                self.history,
                from_value="2026-07-29T12:00:00Z",
                to_value="2026-07-29T11:00:00Z",
            )
        self.assertEqual(caught.exception.status_code, 400)

    def test_resolved_cgnat_exposes_private_ip_from_detail_contract(self):
        event = {
            **self.history[0],
            "cgnat_matched": True,
            "cgnat_ambiguous": False,
            "cgnat_lookup_performed": True,
            "effective_subscriber_addressing_mode": "cgnat",
            "private_ip": "100.64.17.186",
            "public_ip": "186.232.173.250",
            "public_port": 23922,
            "mapped_port_start": 22528,
            "mapped_port_end": 24575,
            "cgnat_pool_name": "POOL-OUTSIDE",
            "cgnat_device_name": "A10-VNT",
            "cgnat_source_type": "a10",
            "cgnat_mapping_source": "internal-router-dump.txt",
            "cgnat_confidence": 0.98,
        }
        result = canonical_anomaly_item(event)
        self.assertTrue(result["cgnat_applicable"])
        self.assertTrue(result["cgnat_resolved"])
        self.assertEqual(result["cgnat_private_ip"], "100.64.17.186")
        self.assertEqual(result["cgnat_public_ip"], "186.232.173.250")
        self.assertEqual(result["cgnat_public_port"], 23922)
        self.assertEqual(result["cgnat_port_range"], "22528-24575")
        self.assertEqual(result["cgnat_vendor"], "A10")
        self.assertEqual(result["cgnat_mapping_source"], "a10")
        self.assertNotIn("internal-router-dump.txt", str(result))

    def test_anomaly_without_cgnat_has_null_cgnat_fields(self):
        result = canonical_anomaly_item(self.history[1])
        self.assertFalse(result["cgnat_applicable"])
        self.assertFalse(result["cgnat_resolved"])
        for field in GRAFANA_CGNAT_FIELDS:
            if field not in {"cgnat_applicable", "cgnat_resolved"}:
                self.assertIsNone(result[field])

    def test_active_mitigation_contract_and_remaining_ttl(self):
        now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
        mitigation = canonical_mitigation_item(
            {
                "id": 91,
                "anomaly_id": 1669,
                "status": "advertised",
                "requested_mode": "automatic",
                "connector_id": 2,
                "connector_name": "BGP-NE40-VNT",
                "connector_backend": "exabgp",
                "connector_mode": "auto",
                "attack_vector_name": "DNS_SINGLE_FLOW_OUTBOUND",
                "protocol": "udp",
                "dst_port": "53",
                "dst_prefix": "102.218.215.26/32",
                "advertised_at": "2026-07-29T11:55:00Z",
                "expires_at": "2026-07-29T12:10:00Z",
                "duration_seconds": 900,
                "_cgnat_event": {
                    "cgnat_matched": True,
                    "cgnat_lookup_performed": True,
                    "effective_subscriber_addressing_mode": "cgnat",
                    "private_ip": "100.64.17.186",
                    "public_ip": "186.232.173.250",
                    "public_port": 23922,
                    "mapped_port_start": 22528,
                    "mapped_port_end": 24575,
                    "cgnat_pool_name": "POOL-OUTSIDE",
                    "cgnat_device_name": "A10-VNT",
                    "cgnat_source_type": "a10",
                    "cgnat_confidence": 1,
                    "top_dst_ip": "102.218.215.26",
                    "top_dst_port": 53,
                    "protocol": "udp",
                },
            },
            now=now,
        )
        self.assertEqual(mitigation["action"], "announce")
        self.assertEqual(mitigation["mode"], "automatic")
        self.assertEqual(mitigation["connector_mode"], "automatic")
        self.assertEqual(mitigation["source_ip"], "186.232.173.250")
        self.assertEqual(mitigation["destination_ip"], "102.218.215.26")
        self.assertEqual(mitigation["remaining_seconds"], 600)
        self.assertEqual(mitigation["cgnat_private_ip"], "100.64.17.186")

    def test_active_mitigation_states_exclude_expired_and_simulation(self):
        now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
        self.assertTrue(
            mitigation_is_active(
                {"status": "sent", "expires_at": None},
                now=now,
            )
        )
        self.assertFalse(
            mitigation_is_active(
                {"status": "expired"},
                now=now,
            )
        )
        self.assertFalse(
            mitigation_is_active(
                {
                    "status": "advertised",
                    "expires_at": "2026-07-29T11:59:59Z",
                },
                now=now,
            )
        )
        self.assertFalse(
            mitigation_is_active(
                {
                    "status": "active",
                    "confirmation_level": "simulation_only",
                },
                now=now,
            )
        )

    def test_mitigation_filters_and_pagination_are_validated(self):
        result = validate_mitigation_filters(
            active_only=True,
            anomaly_id=1669,
            status="Advertised",
            connector_id=2,
            from_value="2026-07-29T10:00:00Z",
            to_value="2026-07-29T12:00:00Z",
            limit=5000,
            offset=25,
        )
        self.assertTrue(result["active_only"])
        self.assertEqual(result["anomaly_id"], 1669)
        self.assertEqual(result["status"], "advertised")
        self.assertEqual(result["connector_id"], 2)
        self.assertEqual(result["limit"], 1000)
        self.assertEqual(result["offset"], 25)

    def test_read_only_resource_rows_are_flat_and_omit_secrets(self):
        mitigation = canonical_mitigation_item(
            {
                "id": 4,
                "anomaly_id": 11,
                "status": "active",
                "announce_command": "secret announce command",
                "withdraw_command": "secret withdraw command",
                "router_password": "secret password",
                "raw_payload": {"token": "secret bearer token"},
                "updated_at": "2026-07-29T12:00:00Z",
            }
        )
        bgp = canonical_bgp_status_item(
            {
                "id": 2,
                "name": "edge-1",
                "enabled": True,
                "is_active": True,
                "router_password": "secret",
                "bgp_state": "established",
            }
        )
        serialized = str(mitigation)
        for secret in (
            "secret announce command",
            "secret withdraw command",
            "secret password",
            "secret bearer token",
        ):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("router_password", bgp)
        self.assertTrue(
            all(
                not isinstance(value, (dict, list))
                for value in (*mitigation.values(), *bgp.values())
            )
        )

    def test_single_anomaly_canonicalization_preserves_utc_timestamps(self):
        result = canonical_anomaly_item(self.history[0])
        self.assertEqual(result["started_at"], "2026-07-29T10:00:00Z")
        self.assertEqual(result["last_seen_at"], "2026-07-29T10:10:00Z")


if __name__ == "__main__":
    unittest.main()
