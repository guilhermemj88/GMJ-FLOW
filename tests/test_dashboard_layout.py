from __future__ import annotations

import copy
import random
import sqlite3
import unittest
from pathlib import Path

from backend.app.services.dashboard_layout import (
    compact_layout_vertically,
    layout_signature,
    move_item_and_push,
    normalize_grid_item,
    rectangles_overlap,
    repair_dashboard_layout,
    resize_item_and_push,
    resolve_collisions,
    validate_layout,
)
from backend.app.services.dashboard_widgets import (
    COLLAPSED_GRID_HEIGHT,
    DASHBOARD_SCHEMA_VERSION,
    DashboardLayoutVersionConflict,
    GENERAL_WIDGETS,
    create_dashboard,
    ensure_dashboard_schema,
    get_dashboard,
    persist_dashboard_layout,
    repair_dashboard_widgets,
    widget_layout_constraints,
)


ROOT = Path(__file__).resolve().parents[1]
LAYOUT_JS = (ROOT / "frontend" / "dashboard-layout.js").read_text(
    encoding="utf-8"
)
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


def assert_no_overlap(
    case: unittest.TestCase,
    items: list[dict],
) -> None:
    visible = [item for item in items if not item.get("hidden")]
    for index, left in enumerate(visible):
        for right in visible[index + 1 :]:
            case.assertFalse(
                rectangles_overlap(left, right),
                "%s overlaps %s" % (left["id"], right["id"]),
            )


class DashboardLayoutPureEngineTest(unittest.TestCase):
    def test_touching_edges_do_not_collide(self):
        self.assertFalse(
            rectangles_overlap(
                {"x": 0, "y": 0, "w": 6, "h": 4},
                {"x": 6, "y": 0, "w": 6, "h": 4},
            )
        )
        self.assertFalse(
            rectangles_overlap(
                {"x": 0, "y": 0, "w": 6, "h": 4},
                {"x": 0, "y": 4, "w": 6, "h": 4},
            )
        )

    def test_partial_intersection_collides(self):
        self.assertTrue(
            rectangles_overlap(
                {"x": 0, "y": 0, "w": 6, "h": 6},
                {"x": 4, "y": 5, "w": 6, "h": 4},
            )
        )

    def test_larger_widget_pushes_below_in_cascade(self):
        items = [
            {"id": "A", "x": 0, "y": 0, "w": 6, "h": 6},
            {"id": "B", "x": 0, "y": 6, "w": 6, "h": 5},
            {"id": "C", "x": 0, "y": 11, "w": 6, "h": 4},
        ]
        repaired = resize_item_and_push(items, "A", 6, 9)
        by_id = {item["id"]: item for item in repaired}
        self.assertEqual(by_id["A"]["y"], 0)
        self.assertEqual(by_id["A"]["h"], 9)
        self.assertEqual(by_id["B"]["y"], 9)
        self.assertEqual(by_id["C"]["y"], 14)
        assert_no_overlap(self, repaired)

    def test_one_widget_pushes_partial_columns_deterministically(self):
        broken = [
            {"id": "A", "x": 0, "y": 0, "w": 6, "h": 8},
            {"id": "B", "x": 0, "y": 6, "w": 4, "h": 6},
            {"id": "C", "x": 4, "y": 6, "w": 4, "h": 6},
            {"id": "D", "x": 8, "y": 6, "w": 4, "h": 6},
        ]
        repaired = repair_dashboard_layout(broken)
        by_id = {item["id"]: item for item in repaired}
        self.assertEqual(by_id["A"]["y"], 0)
        self.assertGreaterEqual(by_id["B"]["y"], 8)
        self.assertGreaterEqual(by_id["C"]["y"], 8)
        self.assertGreaterEqual(by_id["D"]["y"], 8)
        self.assertEqual(
            layout_signature(repaired),
            layout_signature(repair_dashboard_layout(repaired)),
        )
        assert_no_overlap(self, repaired)

    def test_separate_columns_are_not_pushed(self):
        items = [
            {"id": "A", "x": 0, "y": 0, "w": 4, "h": 8},
            {"id": "B", "x": 6, "y": 0, "w": 4, "h": 5},
        ]
        moved = resize_item_and_push(items, "A", 4, 10)
        by_id = {item["id"]: item for item in moved}
        self.assertEqual(by_id["B"]["y"], 0)

    def test_grafana_style_resize_only_pushes_intersecting_columns(self):
        items = [
            {"id": "A", "x": 0, "y": 0, "w": 6, "h": 8},
            {"id": "B", "x": 6, "y": 0, "w": 6, "h": 8},
            {"id": "C", "x": 0, "y": 8, "w": 4, "h": 6},
            {"id": "D", "x": 4, "y": 8, "w": 4, "h": 6},
            {"id": "E", "x": 8, "y": 8, "w": 4, "h": 6},
        ]
        resized = resize_item_and_push(items, "A", 6, 12)
        by_id = {item["id"]: item for item in resized}
        self.assertEqual((by_id["A"]["y"], by_id["A"]["h"]), (0, 12))
        self.assertEqual(by_id["B"]["y"], 0)
        self.assertEqual(by_id["C"]["y"], 12)
        self.assertEqual(by_id["D"]["y"], 12)
        self.assertEqual(by_id["E"]["y"], 8)
        assert_no_overlap(self, resized)

    def test_compaction_removes_gaps_without_collisions(self):
        compacted = compact_layout_vertically(
            [
                {"id": 1, "x": 0, "y": 4, "w": 6, "h": 3},
                {"id": 2, "x": 0, "y": 12, "w": 6, "h": 3},
                {"id": 3, "x": 6, "y": 9, "w": 6, "h": 2},
            ]
        )
        by_id = {item["id"]: item for item in compacted}
        self.assertEqual(by_id[1]["y"], 0)
        self.assertEqual(by_id[2]["y"], 3)
        self.assertEqual(by_id[3]["y"], 0)
        assert_no_overlap(self, compacted)

    def test_normalization_respects_bounds_and_is_idempotent(self):
        normalized = normalize_grid_item(
            {
                "id": 1,
                "x": -9,
                "y": -4,
                "w": 99,
                "h": 0,
                "min_w": 3,
                "min_h": 2,
                "max_w": 8,
                "max_h": 10,
            }
        )
        self.assertEqual(normalized["x"], 0)
        self.assertEqual(normalized["y"], 0)
        self.assertEqual(normalized["w"], 8)
        self.assertEqual(normalized["h"], 2)
        self.assertLessEqual(normalized["x"] + normalized["w"], 12)
        self.assertEqual(normalized, normalize_grid_item(normalized))

    def test_move_into_occupied_area_keeps_active_widget(self):
        items = [
            {"id": 1, "x": 0, "y": 0, "w": 6, "h": 5},
            {"id": 2, "x": 6, "y": 0, "w": 6, "h": 5},
        ]
        moved = move_item_and_push(items, 2, 0, 0)
        by_id = {item["id"]: item for item in moved}
        self.assertEqual((by_id[2]["x"], by_id[2]["y"]), (0, 0))
        self.assertEqual(by_id[1]["y"], 5)

    def test_duplicate_reappear_expand_and_delete_are_valid(self):
        base = [
            {"id": 1, "x": 0, "y": 0, "w": 6, "h": 6},
            {"id": 2, "x": 0, "y": 6, "w": 6, "h": 4},
        ]
        duplicated = repair_dashboard_layout(
            base
            + [{"id": 3, "x": 0, "y": 6, "w": 6, "h": 4}],
            3,
        )
        assert_no_overlap(self, duplicated)

        hidden = copy.deepcopy(base)
        hidden[0]["hidden"] = True
        compacted = repair_dashboard_layout(hidden)
        self.assertEqual(
            next(item for item in compacted if item["id"] == 2)["y"],
            0,
        )
        reappeared_input = copy.deepcopy(compacted)
        reappeared = next(
            item for item in reappeared_input if item["id"] == 1
        )
        reappeared["hidden"] = False
        shown = repair_dashboard_layout(reappeared_input, 1)
        assert_no_overlap(self, shown)

        collapsed = [
            {"id": 1, "x": 0, "y": 0, "w": 6, "h": 2},
            {"id": 2, "x": 0, "y": 2, "w": 6, "h": 4},
        ]
        expanded = resize_item_and_push(collapsed, 1, 6, 8)
        self.assertEqual(
            next(item for item in expanded if item["id"] == 2)["y"],
            8,
        )

        after_delete = compact_layout_vertically(
            [item for item in expanded if item["id"] != 1]
        )
        self.assertEqual(after_delete[0]["y"], 0)

    def test_validation_checks_every_visible_pair(self):
        invalid = [
            {"id": 1, "x": 0, "y": 0, "w": 6, "h": 6},
            {"id": 2, "x": 2, "y": 2, "w": 6, "h": 6},
        ]
        self.assertFalse(validate_layout(invalid)["valid"])
        repaired = resolve_collisions(invalid, 1)
        self.assertTrue(validate_layout(repaired)["valid"])

    def test_randomized_repair_is_deterministic_and_idempotent(self):
        generator = random.Random(20260727)
        for case in range(150):
            items = [
                {
                    "id": identifier,
                    "x": generator.randint(-2, 12),
                    "y": generator.randint(-3, 30),
                    "w": generator.randint(2, 6),
                    "h": generator.randint(2, 10),
                    "min_w": 1,
                    "min_h": 1,
                    "max_w": 12,
                    "max_h": 12,
                }
                for identifier in range(1, generator.randint(2, 12))
            ]
            first = repair_dashboard_layout(items)
            second = repair_dashboard_layout(copy.deepcopy(items))
            third = repair_dashboard_layout(first)
            self.assertEqual(
                layout_signature(first),
                layout_signature(second),
                "non-deterministic case %s" % case,
            )
            self.assertEqual(
                layout_signature(first),
                layout_signature(third),
                "non-idempotent case %s" % case,
            )
            self.assertTrue(validate_layout(first)["valid"])


class DashboardLayoutPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)"
        )
        self.conn.execute(
            "INSERT INTO users (id, username) VALUES (1, 'operator')"
        )
        ensure_dashboard_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_broken_persisted_layout_is_repaired_once(self):
        dashboard = create_dashboard(
            self.conn,
            {
                "name": "Quebrado",
                "is_default": False,
                "is_shared": False,
                "refresh_interval_seconds": 30,
            },
            1,
            widgets=copy.deepcopy(GENERAL_WIDGETS[:3]),
        )
        widget_ids = [item["id"] for item in dashboard["widgets"]]
        self.conn.execute(
            """
            UPDATE dashboard_widgets
            SET grid_x = 0, grid_y = 0, grid_w = 6, grid_h = 8
            WHERE id IN (?, ?, ?)
            """,
            tuple(widget_ids),
        )
        self.assertTrue(
            repair_dashboard_widgets(
                self.conn,
                dashboard["id"],
                widget_ids[0],
            )
        )
        repaired = get_dashboard(self.conn, dashboard["id"])
        self.assertFalse(repaired["layout_repaired"])
        self.assertEqual(
            repaired["layout_version"],
            DASHBOARD_SCHEMA_VERSION + 1,
        )
        assert_no_overlap(
            self,
            [
                {"id": item["id"], **item["grid"], "hidden": item["hidden"]}
                for item in repaired["widgets"]
            ],
        )
        signature = [
            (item["id"], item["grid"])
            for item in repaired["widgets"]
        ]
        self.assertFalse(
            repair_dashboard_widgets(self.conn, dashboard["id"])
        )
        again = get_dashboard(self.conn, dashboard["id"])
        self.assertEqual(
            signature,
            [(item["id"], item["grid"]) for item in again["widgets"]],
        )

    def test_default_sizes_and_collapsed_schema_are_additive(self):
        expected = {
            "timeseries": (6, 8, 5, 6),
            "recent_events": (12, 7, 6, 5),
            "status_list": (4, 5, 3, 4),
            "kpi": (3, 3, 2, 2),
        }
        for widget_type, values in expected.items():
            constraints = widget_layout_constraints(
                {
                    "type": widget_type,
                    "config": {},
                    "visualization": {"type": "table"},
                }
            )
            self.assertEqual(
                (
                    constraints["default_w"],
                    constraints["default_h"],
                    constraints["min_w"],
                    constraints["min_h"],
                ),
                values,
            )
        columns = {
            row["name"]
            for row in self.conn.execute(
                "PRAGMA table_info(dashboard_widgets)"
            ).fetchall()
        }
        self.assertIn("expanded_grid_h", columns)
        self.assertIn("collapsed_grid_h", columns)
        self.assertIn("height_mode", columns)
        self.assertEqual(COLLAPSED_GRID_HEIGHT, 2)

    def test_full_layout_commit_is_atomic_versioned_and_idempotent(self):
        dashboard = create_dashboard(
            self.conn,
            {
                "name": "Transacional",
                "is_default": False,
                "is_shared": False,
                "refresh_interval_seconds": 30,
            },
            1,
            widgets=copy.deepcopy(GENERAL_WIDGETS[:3]),
        )
        current_version = dashboard["layout_version"]
        widgets = [
            {"id": item["id"], "grid": dict(item["grid"])}
            for item in dashboard["widgets"]
        ]
        widgets[0]["grid"]["h"] = 12
        result = persist_dashboard_layout(
            self.conn,
            dashboard["id"],
            widgets,
            layout_version=current_version,
            active_widget_id=widgets[0]["id"],
            idempotency_key="resize-1",
        )
        self.assertEqual(result["layout_version"], current_version + 1)
        self.assertFalse(result["idempotent_replay"])
        self.assertEqual(result["idempotency_key"], "resize-1")
        self.conn.commit()
        replay = persist_dashboard_layout(
            self.conn,
            dashboard["id"],
            result["widgets"],
            layout_version=current_version,
            active_widget_id=widgets[0]["id"],
            idempotency_key="resize-1",
        )
        self.assertTrue(replay["idempotent_replay"])
        with self.assertRaises(DashboardLayoutVersionConflict):
            stale = copy.deepcopy(result["widgets"])
            stale[0]["grid"]["w"] -= 1
            persist_dashboard_layout(
                self.conn,
                dashboard["id"],
                stale,
                layout_version=current_version,
                active_widget_id=stale[0]["id"],
            )

    def test_custom_layout_preserves_free_slots_and_echoes_interaction(self):
        dashboard = create_dashboard(
            self.conn,
            {
                "name": "Custom",
                "is_default": False,
                "is_shared": False,
                "layout_mode": "custom",
                "compact_mode": "none",
                "refresh_interval_seconds": 30,
            },
            1,
            widgets=copy.deepcopy(GENERAL_WIDGETS[:2]),
        )
        widgets = [
            {"id": item["id"], "grid": dict(item["grid"])}
            for item in dashboard["widgets"]
        ]
        active_id = widgets[0]["id"]
        widgets[0]["grid"].update({"x": 8, "y": 20, "w": 4})
        result = persist_dashboard_layout(
            self.conn,
            dashboard["id"],
            widgets,
            base_revision=dashboard["layout_version"],
            active_widget_id=active_id,
            interaction_id="drag-contract-1",
            compact_mode="none",
        )
        by_id = {
            item["id"]: item["grid"]
            for item in result["widgets"]
        }
        self.assertEqual(by_id[active_id]["y"], 20)
        self.assertEqual(result["revision"], dashboard["layout_version"] + 1)
        self.assertEqual(result["interaction_id"], "drag-contract-1")
        self.assertEqual(result["compact_mode"], "none")

    def test_full_layout_commit_rejects_missing_widget_without_partial_write(self):
        dashboard = create_dashboard(
            self.conn,
            {
                "name": "Rollback",
                "is_default": False,
                "is_shared": False,
                "refresh_interval_seconds": 30,
            },
            1,
            widgets=copy.deepcopy(GENERAL_WIDGETS[:2]),
        )
        before = [
            (item["id"], dict(item["grid"]))
            for item in dashboard["widgets"]
        ]
        with self.assertRaises(ValueError):
            persist_dashboard_layout(
                self.conn,
                dashboard["id"],
                [
                    {
                        "id": dashboard["widgets"][0]["id"],
                        "grid": {"x": 0, "y": 0, "w": 6, "h": 10},
                    }
                ],
                layout_version=dashboard["layout_version"],
            )
        after = get_dashboard(self.conn, dashboard["id"])
        self.assertEqual(
            before,
            [(item["id"], item["grid"]) for item in after["widgets"]],
        )


class DashboardLayoutFrontendContractTest(unittest.TestCase):
    def test_javascript_exports_pure_engine_contract(self):
        for name in (
            "normalizeGridItem",
            "rectanglesOverlap",
            "itemsOverlap",
            "findCollisions",
            "moveItemAndPush",
            "resizeItemAndPush",
            "calculateResizePreview",
            "calculateMovePreview",
            "resolveLayoutDuringInteraction",
            "commitLayoutInteraction",
            "rollbackLayoutInteraction",
            "pushItemDown",
            "resolveCollisions",
            "compactLayoutVertically",
            "repairDashboardLayout",
            "validateLayout",
            "sortLayout",
        ):
            self.assertIn("function %s(" % name, LAYOUT_JS)
            self.assertIn(name, LAYOUT_JS[LAYOUT_JS.find("return Object.freeze"):])
        self.assertIn("MAX_LAYOUT_ITERATIONS", LAYOUT_JS)
        self.assertIn("current.y + current.h", LAYOUT_JS)

    def test_dom_uses_single_grid_height_and_contained_content(self):
        for token in (
            "--dashboard-grid-row-height: 48px",
            "--dashboard-grid-gap: 12px",
            "grid-auto-rows: var(--dashboard-grid-row-height)",
            "calculateGridPixelHeight",
            "overflow: hidden",
            "configurable-dashboard-widget-body .table-wrap",
            "ResizeObserver",
            "configurableWidgetResizeObservers",
        ):
            self.assertIn(token, FRONTEND)
        self.assertIn("height: auto !important", FRONTEND)

    def test_interactions_use_push_engine_and_fullscreen_is_not_persisted(self):
        self.assertIn("GMJDashboardLayout.moveItemAndPush(", FRONTEND)
        self.assertIn("GMJDashboardLayout.resizeItemAndPush(", FRONTEND)
        self.assertIn("repairConfigurableDashboardClientLayout", FRONTEND)
        fullscreen_branch = FRONTEND[
            FRONTEND.find("target.closest('.configurable-widget-fullscreen')"):
            FRONTEND.find("target.closest('.configurable-widget-hide')")
        ]
        self.assertIn("classList.toggle('fullscreen-widget')", fullscreen_branch)
        self.assertNotIn("apiRequest(", fullscreen_branch)


if __name__ == "__main__":
    unittest.main()
