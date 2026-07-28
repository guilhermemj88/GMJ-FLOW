from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from backend.app.services.grafana_api import (
    GrafanaApiError,
    authenticate,
    canonical_ranking,
    canonical_timeseries,
    catalog,
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


if __name__ == "__main__":
    unittest.main()

