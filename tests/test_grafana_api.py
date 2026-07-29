from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from backend.app.services.grafana_api import (
    GRAFANA_ANOMALY_FIELDS,
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
    service_document,
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
            },
        )
        self.assertEqual(
            {item["id"] for item in result["datasets"]},
            {
                "anomalies_active",
                "anomalies_history",
                "mitigations",
                "bgp_status",
            },
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
            ["rank", "label", "value", "percent"],
        )
        self.assertEqual(result["rows"][0], [1, "tcp", 80.0, 80.0])


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

    def test_read_only_resource_rows_are_flat_and_omit_secrets(self):
        mitigation = canonical_mitigation_item(
            {
                "id": 4,
                "anomaly_id": 11,
                "status": "active",
                "command": "secret router command",
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
        self.assertNotIn("command", mitigation)
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
