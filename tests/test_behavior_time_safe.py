from __future__ import annotations

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavioral_detection import behavioral_clickhouse_schema_statements  # noqa: E402


def _norm(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


class BehaviorTimeSafeDdlTest(unittest.TestCase):
    """Phase 5E: canonical DDL must keep behavior_flow_10s_v2 time-safe.

    These are static (string-level) checks: they verify the repo's canonical
    ClickHouse DDL reproduces behavior_flow_10s EXACTLY except for the
    `WHERE time_classification = 'VALID_TIME'` guard in the V2 MV. They do not
    require a running ClickHouse.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.statements = behavioral_clickhouse_schema_statements()

    def _find(self, needle: str) -> str:
        for statement in self.statements:
            if needle in statement:
                return statement
        self.fail(f"statement containing {needle!r} not found")
        return ""

    def test_v2_mv_filters_valid_time(self) -> None:
        v2 = self._find("mv_flow_raw_to_behavior_10s_v2")
        self.assertIn("time_classification = 'VALID_TIME'", v2)

    def test_v1_mv_does_not_filter(self) -> None:
        # V1 keeps legacy semantics (no temporal filter) until future cutover.
        v1 = self._find("mv_flow_raw_to_behavior_10s TO behavior_flow_10s")
        self.assertNotIn("time_classification", v1)

    def test_v1_v2_mv_aggregation_parity(self) -> None:
        v1 = self._find("mv_flow_raw_to_behavior_10s TO behavior_flow_10s")
        v2 = self._find("mv_flow_raw_to_behavior_10s_v2")
        v1_select = re.search(r"AS\s+SELECT(.*?)FROM\s+flow_raw", v1, re.S)
        v2_select = re.search(r"AS\s+SELECT(.*?)FROM\s+flow_raw", v2, re.S)
        self.assertIsNotNone(v1_select)
        self.assertIsNotNone(v2_select)
        self.assertEqual(_norm(v1_select.group(1)), _norm(v2_select.group(1)))
        v1_group = re.search(r"GROUP BY(.*?)(?:;|$)", v1, re.S)
        v2_group = re.search(r"GROUP BY(.*?)(?:;|$)", v2, re.S)
        self.assertIsNotNone(v1_group)
        self.assertIsNotNone(v2_group)
        self.assertEqual(_norm(v1_group.group(1)), _norm(v2_group.group(1)))

    def test_v1_v2_table_schema_parity(self) -> None:
        v1 = self._find("CREATE TABLE IF NOT EXISTS behavior_flow_10s ")
        v2 = self._find("CREATE TABLE IF NOT EXISTS behavior_flow_10s_v2 ")
        # The whole CREATE TABLE statement must be identical except the name.
        v1_norm = v1.replace("behavior_flow_10s ", "behavior_flow_10s_x ")
        v2_norm = v2.replace("behavior_flow_10s_v2 ", "behavior_flow_10s_x ")
        self.assertEqual(_norm(v1_norm), _norm(v2_norm))
        self.assertIn("SummingMergeTree((bytes, packets, flows))", v2)
        self.assertIn("INTERVAL 24 HOUR DELETE", v2)

    def test_v1_v2_order_by_parity(self) -> None:
        v1 = self._find("CREATE TABLE IF NOT EXISTS behavior_flow_10s ")
        v2 = self._find("CREATE TABLE IF NOT EXISTS behavior_flow_10s_v2 ")
        v1_order = re.search(r"ORDER BY\s+\((.*?)\)", v1, re.S)
        v2_order = re.search(r"ORDER BY\s+\((.*?)\)", v2, re.S)
        self.assertIsNotNone(v1_order)
        self.assertIsNotNone(v2_order)
        self.assertEqual(_norm(v1_order.group(1)), _norm(v2_order.group(1)))

    def test_v2_mv_where_between_from_and_group_by(self) -> None:
        v2 = self._find("mv_flow_raw_to_behavior_10s_v2")
        self.assertLess(v2.index("FROM flow_raw"), v2.index("time_classification = 'VALID_TIME'"))
        self.assertLess(v2.index("time_classification = 'VALID_TIME'"), v2.index("GROUP BY"))


if __name__ == "__main__":
    unittest.main()
