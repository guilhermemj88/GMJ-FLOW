from __future__ import annotations

import json
import os
import sqlite3
import sys
import unittest
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.threat_intelligence import (  # noqa: E402
    BLOCKLIST_DE,
    CEREAL2,
    GREYNOISE,
    ThreatIntelManager,
    ensure_threat_intel_schema,
    semantic_category,
    semantic_tier,
    utc_now_iso,
)


def metadata(primary_source, **extra):
    base = {"primary_source": primary_source, "aggregator_source": None}
    base.update(extra)
    return base


class ConsolidatedIocsTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.factory = lambda: self.conn
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()
        ensure_threat_intel_schema(self.conn)
        self.conn.commit()

    def tearDown(self):
        self.env.stop()
        self.conn.close()

    def insert(self, provider, ip, classification, meta=None, last_seen=None):
        self.conn.execute(
            """
            INSERT INTO threat_intel_indicators (
                provider, indicator_type, ip, network, classification, first_seen,
                last_seen, botnet_family, tags_json, metadata_json, sync_token, active, updated_at
            ) VALUES (?, 'IP', ?, '', ?, NULL, ?, '', '[]', ?, 'sync', 1, ?)
            """,
            (
                provider, ip, classification, last_seen,
                json.dumps(meta or {}), utc_now_iso(),
            ),
        )
        self.conn.commit()

    def test_semantic_profile_keeps_greynoise_malicious_separate(self):
        self.assertEqual((4, "reputation_malicious"), (semantic_tier("malicious"), semantic_category("malicious")))
        self.assertEqual((4, "abuse"), (semantic_tier("reported_attack_source"), semantic_category("reported_attack_source")))
        self.assertEqual((1, "c2"), (semantic_tier("c2"), semantic_category("c2")))
        self.assertEqual((1, "c2"), (semantic_tier("botnet_cc"), semantic_category("botnet_cc")))
        self.assertEqual((5, "unknown"), (semantic_tier("suspicious"), semantic_category("suspicious")))
        self.assertEqual((5, "benign"), (semantic_tier("benign"), semantic_category("benign")))

    def test_priority_and_primary_source(self):
        # Same IP: C2 (Cereal2) wins over abuse (Blocklist.de).
        self.insert(CEREAL2, "45.1.2.3", "c2", metadata(CEREAL2))
        self.insert(BLOCKLIST_DE, "45.1.2.3", "reported_attack_source", metadata(BLOCKLIST_DE))
        manager = ThreatIntelManager(self.factory)
        result = manager.consolidated_iocs()
        self.assertEqual(1, result["total"])
        item = result["items"][0]
        self.assertEqual("45.1.2.3", item["ip"])
        self.assertEqual(1, item["priority"])
        self.assertEqual("c2", item["category"])
        self.assertEqual(CEREAL2, item["primary_source"])
        self.assertEqual(2, item["independent_sources"])
        self.assertEqual(2, item["evidence_count"])

    def test_independent_sources_uses_primary_source_not_provider(self):
        # CINS direct + FireHOL mirroring CINS = ONE independent source.
        self.insert("CINS", "45.1.2.4", "scanner", metadata("CINS"))
        self.insert("FIREHOL", "45.1.2.4", "scanner", metadata("CINS", aggregator_source="FIREHOL"))
        manager = ThreatIntelManager(self.factory)
        result = manager.consolidated_iocs()
        item = result["items"][0]
        self.assertEqual(1, item["independent_sources"])
        self.assertEqual(2, item["evidence_count"])

    def test_greynoise_malicious_category_is_isolated(self):
        self.insert(GREYNOISE, "45.1.2.5", "malicious", metadata(GREYNOISE))
        manager = ThreatIntelManager(self.factory)
        item = manager.consolidated_iocs()["items"][0]
        self.assertEqual(4, item["priority"])
        self.assertEqual("reputation_malicious", item["category"])
        self.assertEqual(GREYNOISE, item["primary_source"])

    def test_filter_by_tier_and_category(self):
        self.insert(CEREAL2, "45.1.2.3", "c2", metadata(CEREAL2))
        self.insert(BLOCKLIST_DE, "45.1.2.9", "reported_attack_source", metadata(BLOCKLIST_DE))
        manager = ThreatIntelManager(self.factory)
        self.assertEqual(1, manager.consolidated_iocs(tier="1")["total"])
        self.assertEqual(1, manager.consolidated_iocs(category="abuse")["total"])
        self.assertEqual(1, manager.consolidated_iocs(provider="BLOCKLIST_DE")["total"])

    def test_consolidated_ioc_returns_all_evidence(self):
        self.insert(CEREAL2, "45.1.2.6", "c2", metadata(CEREAL2, confidence_original=90), last_seen="2026-08-31T10:00:00Z")
        self.insert(BLOCKLIST_DE, "45.1.2.6", "reported_attack_source", metadata(BLOCKLIST_DE))
        manager = ThreatIntelManager(self.factory)
        detail = manager.consolidated_ioc("45.1.2.6")
        summary = detail["summary"]
        self.assertTrue(summary["found"])
        self.assertEqual(1, summary["priority"])
        self.assertEqual("c2", summary["category"])
        self.assertEqual(CEREAL2, summary["primary_source"])
        self.assertEqual(90, summary["confidence"])
        self.assertEqual(2, summary["independent_sources"])
        self.assertEqual(2, len(detail["evidence"]))
        classifications = {e["classification"] for e in detail["evidence"]}
        self.assertEqual({"c2", "reported_attack_source"}, classifications)


if __name__ == "__main__":
    unittest.main()
