from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

# The 10-second aggregate modules transitively import the ClickHouse driver,
# which may not be installed in a bare local venv. The consumer tests mock
# query_clickhouse anyway, so stub the driver when absent (never used for real).
import types as _types  # noqa: E402
if "clickhouse_connect" not in sys.modules:
    _clickhouse_connect = _types.ModuleType("clickhouse_connect")
    _clickhouse_connect.get_client = lambda *a, **k: None
    sys.modules["clickhouse_connect"] = _clickhouse_connect

from app.services.behavior_flow_table import (  # noqa: E402
    BEHAVIOR_FLOW_TABLE_DEFAULT,
    BEHAVIOR_FLOW_TABLE_FALLBACK,
    behavior_flow_table,
)


class BehaviorFlowTableConfigTest(unittest.TestCase):
    def test_default_uses_v2(self):
        with mock.patch.dict(os.environ, {"GMJFLOW_BEHAVIOR_FLOW_TABLE": ""}):
            self.assertEqual("behavior_flow_10s_v2", behavior_flow_table())

    def test_env_v1_uses_v1(self):
        with mock.patch.dict(os.environ, {"GMJFLOW_BEHAVIOR_FLOW_TABLE": "behavior_flow_10s"}):
            self.assertEqual("behavior_flow_10s", behavior_flow_table())

    def test_env_v2_uses_v2(self):
        with mock.patch.dict(os.environ, {"GMJFLOW_BEHAVIOR_FLOW_TABLE": "behavior_flow_10s_v2"}):
            self.assertEqual("behavior_flow_10s_v2", behavior_flow_table())

    def test_invalid_env_falls_back_safe(self):
        for bad in ("evil; DROP TABLE behavior_flow_10s", "behavior_flow_10s_v3", "SELECT 1", "behavior_flow_10s "):
            with mock.patch.dict(os.environ, {"GMJFLOW_BEHAVIOR_FLOW_TABLE": bad}):
                self.assertEqual(BEHAVIOR_FLOW_TABLE_FALLBACK, behavior_flow_table())

    def test_allowlist_constants(self):
        self.assertEqual("behavior_flow_10s_v2", BEHAVIOR_FLOW_TABLE_DEFAULT)
        self.assertEqual("behavior_flow_10s", BEHAVIOR_FLOW_TABLE_FALLBACK)


class BehaviorFlowTableConsumerTest(unittest.TestCase):
    def _capture_detection_sql(self, table):
        import app.services.behavioral_detection as bd

        captured = {}

        def fake_query(sql, params=None):
            captured["sql"] = sql
            return []

        with mock.patch("app.services.behavioral_detection.behavior_flow_table", return_value=table):
            with mock.patch("app.services.clickhouse.query_clickhouse", side_effect=fake_query):
                bd.fetch_recent_observations()
        return captured["sql"]

    def _capture_candidates_sql(self, table):
        import app.services.behavioral_candidates as bc

        captured = {}

        def fake_query(sql, params=None):
            captured["sql"] = sql
            return []

        with mock.patch("app.services.behavioral_candidates.behavior_flow_table", return_value=table):
            with mock.patch("app.services.behavioral_candidates.query_clickhouse", side_effect=fake_query):
                bc.scan_candidates()
        return captured["sql"]

    def test_fetch_recent_observations_uses_selected_table(self):
        sql = self._capture_detection_sql("behavior_flow_10s_v2")
        self.assertIn("FROM behavior_flow_10s_v2", sql)
        self.assertNotIn("FROM behavior_flow_10s\n", sql)

    def test_candidates_use_selected_table(self):
        sql = self._capture_candidates_sql("behavior_flow_10s_v2")
        self.assertIn("FROM behavior_flow_10s_v2", sql)

    def test_no_productive_reader_hardcoded_v1(self):
        import inspect

        import app.services.behavioral_candidates as bc
        import app.services.behavioral_detection as bd

        det_src = inspect.getsource(bd.fetch_recent_observations)
        cand_src = inspect.getsource(bc._run)
        self.assertIn("behavior_flow_table()", det_src)
        self.assertIn("behavior_flow_table()", cand_src)


if __name__ == "__main__":
    unittest.main()
