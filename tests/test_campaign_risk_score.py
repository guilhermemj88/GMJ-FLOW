from __future__ import annotations

import json
import os
import sqlite3
import sys
import types
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

try:
    import fastapi  # noqa: F401
except ImportError:
    fastapi_stub = types.ModuleType("fastapi")

    class APIRouter:
        def __init__(self, *args, **kwargs):
            pass

        def get(self, *args, **kwargs):
            return lambda function: function

    sys.modules["fastapi"] = fastapi_stub
    fastapi_stub.APIRouter = APIRouter
    fastapi_stub.FastAPI = APIRouter

from app.api import threat_engine as api  # noqa: E402
from app.services.behavioral_detection import ensure_behavioral_schema, campaign_row  # noqa: E402
from app.services.campaign_investigation import get_campaign_investigation  # noqa: E402
from app.services.campaign_score import (  # noqa: E402
    COORDINATION_MAX,
    RECURRENCE_MAX,
    _band_for,
    calculate_campaign_risk_score,
    campaign_risk_from_context,
)
from app.services.security_events import ensure_security_event_schema  # noqa: E402


def _context(signals=None):
    return {"signals": signals or {}}


def _all_signals_true():
    return _context({
        "strong_traffic_deviation": True,
        "threat_intel_reinforced_by_context": True,
        "security_event_correlated": True,
    })


class CampaignRiskScorePureTest(unittest.TestCase):
    def test_no_signal_is_zero(self) -> None:
        result = calculate_campaign_risk_score(
            coordination_score=0,
            recurrence_count=1,
            context_evaluation=_context(),
            persistence_satisfied=False,
        )
        self.assertEqual(0, result["score"])
        self.assertEqual("informational", result["band"])
        self.assertTrue(result["advisory_only"])
        self.assertEqual(0, sum(result["components"].values()))

    def test_all_signals_max_is_100(self) -> None:
        result = calculate_campaign_risk_score(
            coordination_score=100,
            recurrence_count=10,
            context_evaluation=_all_signals_true(),
            persistence_satisfied=True,
        )
        self.assertEqual(100, result["score"])
        self.assertEqual("critical", result["band"])
        self.assertTrue(result["advisory_only"])

    def test_recurrence_cap(self) -> None:
        first = calculate_campaign_risk_score(coordination_score=0, recurrence_count=1)
        self.assertEqual(0, first["components"]["recurrence"])
        second = calculate_campaign_risk_score(coordination_score=0, recurrence_count=2)
        self.assertEqual(3, second["components"]["recurrence"])
        capped = calculate_campaign_risk_score(coordination_score=0, recurrence_count=999)
        self.assertEqual(RECURRENCE_MAX, capped["components"]["recurrence"])

    def test_coordination_normalization(self) -> None:
        self.assertEqual(COORDINATION_MAX, calculate_campaign_risk_score(coordination_score=100)["components"]["coordination"])
        self.assertEqual(0, calculate_campaign_risk_score(coordination_score=0)["components"]["coordination"])
        self.assertEqual(10, calculate_campaign_risk_score(coordination_score=40)["components"]["coordination"])
        self.assertEqual(17, calculate_campaign_risk_score(coordination_score=71)["components"]["coordination"])

    def test_each_component_isolated(self) -> None:
        cases = [
            ("traffic_deviation", calculate_campaign_risk_score(
                coordination_score=0, recurrence_count=1,
                context_evaluation=_context({"strong_traffic_deviation": True}),
                persistence_satisfied=False,
            ), 20),
            ("threat_intel", calculate_campaign_risk_score(
                coordination_score=0, recurrence_count=1,
                context_evaluation=_context({"threat_intel_reinforced_by_context": True}),
                persistence_satisfied=False,
            ), 15),
            ("security_events", calculate_campaign_risk_score(
                coordination_score=0, recurrence_count=1,
                context_evaluation=_context({"security_event_correlated": True}),
                persistence_satisfied=False,
            ), 15),
            ("persistence", calculate_campaign_risk_score(
                coordination_score=0, recurrence_count=1, persistence_satisfied=True,
            ), 10),
        ]
        for name, result, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(expected, result["components"][name])
                self.assertEqual(expected, result["score"])

    def test_clamp_0_100(self) -> None:
        result = calculate_campaign_risk_score(
            coordination_score=9999,
            recurrence_count=9999,
            context_evaluation=_all_signals_true(),
            persistence_satisfied=True,
        )
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_bands_boundaries(self) -> None:
        expected = [
            (0, "informational"), (39, "informational"),
            (40, "suspicious"), (59, "suspicious"),
            (60, "needs_review"), (74, "needs_review"),
            (75, "elevated"), (84, "elevated"),
            (85, "critical"), (100, "critical"),
        ]
        for score, band in expected:
            with self.subTest(score=score):
                self.assertEqual(band, _band_for(score))

    def test_components_sum_equals_score(self) -> None:
        samples = [
            dict(coordination_score=71, recurrence_count=3, context_evaluation=_context({
                "strong_traffic_deviation": False,
                "threat_intel_reinforced_by_context": True,
                "security_event_correlated": False,
            }), persistence_satisfied=True),
            dict(coordination_score=0, recurrence_count=1, context_evaluation=_context(), persistence_satisfied=False),
            dict(coordination_score=100, recurrence_count=6, context_evaluation=_all_signals_true(), persistence_satisfied=True),
            dict(coordination_score=52, recurrence_count=4, context_evaluation=_context({
                "strong_traffic_deviation": True,
                "threat_intel_reinforced_by_context": False,
                "security_event_correlated": True,
            }), persistence_satisfied=False),
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                result = calculate_campaign_risk_score(**sample)
                self.assertEqual(result["score"], sum(result["components"].values()))

    def test_advisory_only_always_true(self) -> None:
        for _ in range(5):
            self.assertTrue(calculate_campaign_risk_score(coordination_score=0)["advisory_only"])


class CampaignRiskSchemaTest(unittest.TestCase):
    def test_schema_is_idempotent(self) -> None:
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            ensure_behavioral_schema(conn)
            ensure_behavioral_schema(conn)
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(threat_campaigns)").fetchall()
            }
            for column in ("campaign_risk_score", "campaign_risk_band", "campaign_risk_components_json"):
                self.assertIn(column, columns)
        finally:
            conn.close()

    def test_campaign_row_decodes_risk_fields(self) -> None:
        row = {
            "campaign_id": "GMJ-C-TEST",
            "feature_json": "{}",
            "threat_intel_json": "{}",
            "intel_sources_json": "[]",
            "campaign_risk_score": 48,
            "campaign_risk_band": "suspicious",
            "campaign_risk_components_json": json.dumps({"coordination": 17, "recurrence": 6}),
        }
        item = campaign_row(row)
        self.assertEqual(48, item["campaign_risk_score"])
        self.assertEqual("suspicious", item["campaign_risk_band"])
        self.assertEqual({"coordination": 17, "recurrence": 6}, item["campaign_risk_components"])
        self.assertNotIn("campaign_risk_components_json", item)


class CampaignRiskIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(self.conn)
        ensure_security_event_schema(self.conn)
        self.conn.executescript(
            """
            CREATE TABLE asn_info (
                asn INTEGER PRIMARY KEY, as_name TEXT NOT NULL DEFAULT '',
                org_name TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '', raw_json TEXT NOT NULL DEFAULT '',
                first_seen_at TEXT, updated_at TEXT, expires_at TEXT,
                last_error TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE asn_resolution_queue (
                ip TEXT PRIMARY KEY, asn INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'queued'
            );
            """
        )
        self.previous_factory = api.BEHAVIORAL_THREAT_RUNTIME.connection_factory
        api.BEHAVIORAL_THREAT_RUNTIME.connection_factory = lambda: self.conn
        self._insert_campaign()
        self.conn.commit()

    def tearDown(self) -> None:
        api.BEHAVIORAL_THREAT_RUNTIME.connection_factory = self.previous_factory
        self.conn.close()

    def _insert_campaign(self) -> None:
        features = {
            "attack_family": "SCAN_FAMILY",
            "concurrent_sources": 4,
            "source_asn_diversity": 2,
            "persistence_satisfied": True,
            "target_correlation": True,
            "attack_types": ["PORT_SCAN_HORIZONTAL"],
        }
        self.conn.execute(
            """
            INSERT INTO threat_campaigns (
                campaign_id, campaign_key, target_prefix, classification, coordination_score,
                unique_sources, unique_source_asns, packets_per_second, bits_per_second,
                flows_per_second, first_seen, last_seen, feature_json, threat_intel_json,
                intel_sources_json, decision_source, status, recurrence_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "GMJ-C-RISK", "key-risk", "179.189.82.0/24", "SCANNING_CAMPAIGN", 71,
                4, 2, 500.0, 4_000_000.0, 5.0,
                "2026-08-12T10:00:00Z", "2026-08-12T10:05:00Z",
                json.dumps(features), "{}", "[]",
                "GMJ_FLOW", "active", 3, "2026-08-12T10:00:00Z", "2026-08-12T10:05:00Z",
            ),
        )

    def test_get_campaign_investigation_exposes_risk_fields(self) -> None:
        payload = get_campaign_investigation(self.conn, "GMJ-C-RISK")
        self.assertIsNotNone(payload)
        campaign = payload["campaign"]
        for field in ("campaign_risk_score", "campaign_risk_band", "campaign_risk_components"):
            self.assertIn(field, campaign)
        self.assertEqual(sum(campaign["campaign_risk_components"].values()), campaign["campaign_risk_score"])

    def test_list_campaigns_exposes_risk_fields(self) -> None:
        items = api.list_campaigns(limit=100)["items"]
        self.assertEqual(1, len(items))
        campaign = items[0]
        for field in ("campaign_risk_score", "campaign_risk_band", "campaign_risk_components"):
            self.assertIn(field, campaign)
        self.assertIsInstance(campaign["campaign_risk_components"], dict)


class CampaignRiskFromContextTest(unittest.TestCase):
    def test_reads_persistence_from_features(self) -> None:
        campaign = {
            "coordination_score": 80,
            "recurrence_count": 2,
            "features": {"persistence_satisfied": True},
        }
        result = campaign_risk_from_context(campaign, _context({"security_event_correlated": True}))
        self.assertEqual(10, result["components"]["persistence"])
        self.assertEqual(15, result["components"]["security_events"])
        self.assertEqual(20, result["components"]["coordination"])


if __name__ == "__main__":
    unittest.main()
