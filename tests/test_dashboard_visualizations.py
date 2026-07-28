from __future__ import annotations

import copy
import unittest

from backend.app.services.dashboard_visualizations import (
    infer_visualization_kind,
    normalize_field_config,
    normalize_visualization_config,
    visualization_choices,
)
from backend.app.services.dashboard_widgets import validate_widget_definition


class DashboardVisualizationContractTest(unittest.TestCase):
    def test_ranking_payload_has_all_compatible_visualizations(self):
        self.assertEqual(
            set(visualization_choices("ranking_snapshot")),
            {
                "table",
                "horizontal_bar",
                "vertical_bar",
                "pie",
                "donut",
                "bar_gauge",
                "stat",
            },
        )

    def test_legacy_bar_normalizes_without_changing_data_kind(self):
        config, visualization = normalize_visualization_config(
            "top_n",
            {
                "metric": "bps",
                "dimension": "src_asn",
                "visualization": "bar",
            },
            {"type": "bar"},
        )
        self.assertEqual(config["data_kind"], "ranking_snapshot")
        self.assertEqual(config["visualization_kind"], "vertical_bar")
        self.assertEqual(visualization["visualization_kind"], "vertical_bar")

    def test_old_widget_migration_is_idempotent(self):
        source = {
            "title": "Tráfego",
            "type": "timeseries",
            "category": "traffic",
            "config": {
                "metric": "bps",
                "direction": "both",
                "group_by": "total",
                "aggregation": "sum",
                "resolution_seconds": 0,
            },
            "visualization": {"type": "line"},
            "grid": {"x": 0, "y": 0, "w": 6, "h": 6},
            "refresh_interval_seconds": 30,
        }
        first = validate_widget_definition(copy.deepcopy(source))
        second = validate_widget_definition(copy.deepcopy(first))
        self.assertEqual(first, second)
        self.assertEqual(first["config"]["calculation"], "last_not_null")
        self.assertEqual(
            first["config"]["legend_calculation"],
            "last_not_null",
        )

    def test_field_config_normalizes_bounds_nulls_and_overrides(self):
        normalized = normalize_field_config(
            {
                "defaults": {
                    "unit": "bps",
                    "decimals": 3,
                    "min": 100,
                    "max": -100,
                    "null_value": "connected",
                    "color": {
                        "mode": "fixed",
                        "fixedColor": "#ABCDEF",
                    },
                },
                "overrides": [
                    {
                        "matcher": {
                            "type": "direction",
                            "value": "upload",
                        },
                        "properties": {
                            "negative_y": True,
                            "color": "#112233",
                        },
                    }
                ],
            },
            "bps",
        )
        self.assertEqual(normalized["defaults"]["min"], -100)
        self.assertEqual(normalized["defaults"]["max"], 100)
        self.assertEqual(normalized["defaults"]["null_value"], "connected")
        self.assertEqual(
            normalized["defaults"]["color"]["fixedColor"],
            "#abcdef",
        )
        self.assertTrue(
            normalized["overrides"][0]["properties"]["negative_y"]
        )

    def test_inference_rejects_incompatible_visualization(self):
        result = infer_visualization_kind(
            "timeseries",
            {"visualization_kind": "pie"},
            {"type": "pie"},
        )
        self.assertIn(result, visualization_choices("timeseries"))
        self.assertNotEqual(result, "pie")


if __name__ == "__main__":
    unittest.main()

