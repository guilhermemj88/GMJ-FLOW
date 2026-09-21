from __future__ import annotations

import os
import sqlite3
import sys
import unittest
import urllib.error
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.threat_intelligence import (  # noqa: E402
    ACTIVE,
    BLOCKLIST_DE,
    DEGRADED,
    ERROR,
    ThreatIntelManager,
    ensure_threat_intel_schema,
)


class FakeResponse:
    def __init__(self, payload: bytes, status: int = 200, headers: dict | None = None):
        self.payload = payload
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


def feed_body(count: int = 10, include_ipv6: bool = False) -> bytes:
    lines = ["# Blocklist.de unit-test", ""]
    for index in range(count):
        lines.append(f"198.51.100.{index + 1}")
    if include_ipv6:
        lines.append("2001:db8::dead")
    return ("\n".join(lines)).encode("utf-8")


class BlocklistDeTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.factory = lambda: self.conn
        self.env = mock.patch.dict(
            os.environ,
            {
                "GMJFLOW_THREAT_INTEL_BLOCKLIST_DE_ENABLED": "true",
                "GMJFLOW_BLOCKLIST_DE_MIN_RECORDS": "10",
            },
            clear=False,
        )
        self.env.start()
        ensure_threat_intel_schema(self.conn)
        self.conn.commit()

    def tearDown(self):
        self.env.stop()
        self.conn.close()

    def _active_rows(self):
        return self.conn.execute(
            "SELECT ip, classification, metadata_json, active FROM threat_intel_indicators WHERE provider=? ORDER BY ip",
            (BLOCKLIST_DE,),
        ).fetchall()

    def test_sync_persists_ips_with_original_semantics(self):
        manager = ThreatIntelManager(self.factory, lambda *_a, **_k: FakeResponse(feed_body(20, include_ipv6=True)))
        result = manager.sync(BLOCKLIST_DE)
        self.assertEqual(ACTIVE, result["status"])
        self.assertEqual(21, result["items_processed"])
        rows = self._active_rows()
        self.assertEqual(21, len(rows))
        self.assertIn("2001:db8::dead", {row["ip"] for row in rows})
        sample = next(row for row in rows if row["ip"] == "198.51.100.1")
        self.assertEqual("reported_attack_source", sample["classification"])
        import json
        metadata = json.loads(sample["metadata_json"])
        self.assertEqual(BLOCKLIST_DE, metadata["primary_source"])
        self.assertIsNone(metadata["aggregator_source"])
        self.assertEqual("reported_attack_source", metadata["classification_original"])
        self.assertEqual("abuse", metadata["category"])
        self.assertIsNone(metadata["service"])
        self.assertIsNotNone(metadata["expires_at"])
        self.assertIsNotNone(metadata["retrieved_at"])

    def test_comment_and_empty_lines_ignored(self):
        lines = ["# header", ""]
        for index in range(12):
            lines.append(f"203.0.113.{index + 1}")
        lines.append("")
        body = ("\n".join(lines)).encode("utf-8")
        manager = ThreatIntelManager(self.factory, lambda *_a, **_k: FakeResponse(body))
        result = manager.sync(BLOCKLIST_DE)
        self.assertEqual(ACTIVE, result["status"])
        self.assertEqual(12, result["items_processed"])

    def test_html_response_preserves_previous_snapshot(self):
        good = feed_body(20)
        manager = ThreatIntelManager(self.factory, lambda *_a, **_k: FakeResponse(good))
        self.assertEqual(ACTIVE, manager.sync(BLOCKLIST_DE)["status"])
        self.assertEqual(20, len(self._active_rows()))

        manager_html = ThreatIntelManager(self.factory, lambda *_a, **_k: FakeResponse(b"<html><body>Forbidden</body></html>"))
        result = manager_html.sync(BLOCKLIST_DE)
        self.assertEqual(DEGRADED, result["status"])
        self.assertEqual(20, len(self._active_rows()))

    def test_abrupt_reduction_preserves_previous_snapshot(self):
        manager = ThreatIntelManager(self.factory, lambda *_a, **_k: FakeResponse(feed_body(100)))
        self.assertEqual(ACTIVE, manager.sync(BLOCKLIST_DE)["status"])
        self.assertEqual(100, len(self._active_rows()))

        manager_small = ThreatIntelManager(self.factory, lambda *_a, **_k: FakeResponse(feed_body(40)))
        result = manager_small.sync(BLOCKLIST_DE)
        self.assertEqual(DEGRADED, result["status"])
        self.assertEqual(100, len(self._active_rows()))

    def test_timeout_raises_offline_without_write(self):
        def opener(request, timeout=0):
            raise urllib.error.URLError("network down")

        manager = ThreatIntelManager(self.factory, opener)
        result = manager.sync(BLOCKLIST_DE)
        self.assertEqual(ERROR, result["status"])
        self.assertEqual(0, len(self._active_rows()))

    def test_not_modified_skips_write_and_keeps_active(self):
        calls = {"n": 0}

        def opener(request, timeout=0):
            calls["n"] += 1
            if calls["n"] == 1:
                return FakeResponse(feed_body(20))
            raise urllib.error.HTTPError(request.full_url, 304, "Not Modified", None, None)

        manager = ThreatIntelManager(self.factory, opener)
        self.assertEqual(ACTIVE, manager.sync(BLOCKLIST_DE)["status"])
        self.assertEqual(20, len(self._active_rows()))
        second = manager.sync(BLOCKLIST_DE)
        self.assertEqual(ACTIVE, second["status"])
        self.assertEqual(0, second["items_processed"])
        self.assertEqual(20, len(self._active_rows()))

    def test_ioc_absent_from_next_feed_becomes_inactive(self):
        calls = {"n": 0}

        def opener(request, timeout=0):
            calls["n"] += 1
            if calls["n"] == 1:
                return FakeResponse(feed_body(20))
            return FakeResponse(feed_body(12))

        manager = ThreatIntelManager(self.factory, opener)
        manager.sync(BLOCKLIST_DE)
        manager.sync(BLOCKLIST_DE)
        active = [row["ip"] for row in self._active_rows() if row["active"]]
        self.assertEqual(12, len(active))
        inactive = [row["ip"] for row in self._active_rows() if not row["active"]]
        self.assertEqual(8, len(inactive))

    def test_write_duration_is_recorded(self):
        manager = ThreatIntelManager(self.factory, lambda *_a, **_k: FakeResponse(feed_body(200)))
        manager.sync(BLOCKLIST_DE)
        row = self.conn.execute(
            "SELECT config_json FROM threat_intel_providers WHERE provider=?", (BLOCKLIST_DE,)
        ).fetchone()
        import json
        config = json.loads(row["config_json"])
        self.assertIn("last_write_duration_ms", config)
        self.assertGreaterEqual(config["last_write_duration_ms"], 0)


if __name__ == "__main__":
    unittest.main()
