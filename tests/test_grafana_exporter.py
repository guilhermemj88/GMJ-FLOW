from __future__ import annotations

import copy
import json
import unittest

from backend.app.services.grafana_exporter import export_dashboard


def sample_dashboard() -> dict:
    visualizations = [
        ("line", "timeseries"),
        ("area", "timeseries"),
        ("time_bars", "timeseries"),
        ("horizontal_bar", "top_n"),
        ("vertical_bar", "top_n"),
        ("pie", "top_n"),
        ("donut", "top_n"),
        ("bar_gauge", "top_n"),
        ("stat", "top_n"),
        ("table", "top_n"),
    ]
    widgets = []
    for index, (visualization, widget_type) in enumerate(visualizations):
        ranking = widget_type == "top_n"
        widgets.append(
            {
                "id": index + 1,
                "title": visualization,
                "type": widget_type,
                "config": {
                    "metric": "bps",
                    "direction": "both",
                    "dimension": "protocol" if ranking else None,
                    "limit": 10,
                    "group_by": "total",
                    "visualization_kind": visualization,
                    "traffic_orientation": (
                        "split_zero" if visualization == "line" else "positive_both"
                    ),
                    "legend_calculation": "last_not_null",
                    "field_config": {
                        "defaults": {
                            "unit": "bps",
                            "decimals": 2,
                        },
                        "overrides": [
                            {
                                "matcher": {
                                    "type": "direction",
                                    "value": "download",
                                },
                                "properties": {"color": "#00aa00"},
                            }
                        ],
                    },
                },
                "visualization": {"type": visualization},
                "grid": {
                    "x": index % 3 * 4,
                    "y": index // 3 * 6,
                    "w": 4,
                    "h": 6,
                },
                "hidden": False,
            }
        )
    widgets.append(
        {
            **copy.deepcopy(widgets[0]),
            "id": 99,
            "title": "hidden",
            "hidden": True,
        }
    )
    return {
        "id": 42,
        "name": "Observabilidade",
        "description": "Dashboard de teste",
        "refresh_interval_seconds": 30,
        "time_range": {"minutes": 15},
        "widgets": widgets,
    }


class GrafanaExporterTest(unittest.TestCase):
    def test_export_is_deterministic_and_has_no_credentials(self):
        first = export_dashboard(sample_dashboard())
        second = export_dashboard(sample_dashboard())
        self.assertEqual(first, second)
        self.assertEqual(
            first["meta"]["export_hash"],
            second["meta"]["export_hash"],
        )
        serialized = json.dumps(first)
        self.assertNotIn("Authorization", serialized)
        self.assertNotIn("Bearer ", serialized)
        self.assertFalse(first["meta"]["credentials_included"])

    def test_maps_all_supported_panel_types_and_exact_grid(self):
        exported = export_dashboard(sample_dashboard())
        panels = exported["dashboard"]["panels"]
        self.assertEqual(len(panels), 10)
        self.assertEqual(
            {panel["type"] for panel in panels},
            {
                "timeseries",
                "barchart",
                "piechart",
                "bargauge",
                "stat",
                "table",
            },
        )
        self.assertEqual(
            panels[0]["gridPos"],
            {"x": 0, "y": 0, "w": 8, "h": 6},
        )
        self.assertEqual(
            panels[1]["gridPos"],
            {"x": 8, "y": 0, "w": 8, "h": 6},
        )

    def test_split_zero_is_visual_only(self):
        exported = export_dashboard(sample_dashboard())
        panel = exported["dashboard"]["panels"][0]
        upload_override = next(
            override
            for override in panel["fieldConfig"]["overrides"]
            if any(
                prop.get("value") == "negative-Y"
                for prop in override["properties"]
            )
        )
        self.assertIn("upload", upload_override["matcher"]["options"])
        target_body = json.loads(
            panel["targets"][0]["url_options"]["data"]
        )
        self.assertNotIn("negative", json.dumps(target_body).lower())
        self.assertEqual(
            target_body["from"],
            "${__timeFrom:date:iso}",
        )
        self.assertEqual(
            panel["targets"][0]["root_selector"],
            "$.rows",
        )
        self.assertEqual(
            panel["targets"][0]["columns"][0]["type"],
            "timestamp_epoch",
        )

    def test_hidden_widgets_are_opt_in(self):
        dashboard = sample_dashboard()
        self.assertEqual(
            len(export_dashboard(dashboard)["dashboard"]["panels"]),
            10,
        )
        self.assertEqual(
            len(
                export_dashboard(
                    dashboard,
                    include_hidden=True,
                )["dashboard"]["panels"]
            ),
            11,
        )

    def test_unsupported_visual_option_returns_structured_warning(self):
        dashboard = sample_dashboard()
        dashboard["widgets"][0]["config"]["appearance"] = {
            "custom_gradient": "linear-gradient(red, blue)"
        }
        warning = export_dashboard(dashboard)["meta"]["warnings"][0]
        self.assertEqual(warning["widget_id"], 1)
        self.assertEqual(warning["field"], "appearance.custom_gradient")
        self.assertIn("Grafana", warning["message"])


if __name__ == "__main__":
    unittest.main()
