from __future__ import annotations

import os
import sqlite3
import sys
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

# The behavior modules transitively import the ClickHouse driver; stub it in a
# bare venv (never used for real in these tests).
if "clickhouse_connect" not in sys.modules:
    _cc = types.ModuleType("clickhouse_connect")
    _cc.get_client = lambda *a, **k: None
    sys.modules["clickhouse_connect"] = _cc

from app.services.behavior_baseline import (  # noqa: E402
    BOOTSTRAP,
    ELIGIBLE,
    QUARANTINED,
    REJECTED,
    TRUSTED,
    safe_learning_decision,
)
from app.services.behavioral_detection import (  # noqa: E402
    _record_safe_learning_audit_v2,
)


def _decision(**overrides):
    base = dict(
        baseline_state=TRUSTED,
        ema_pps=100.0,
        mad_pps=10.0,
        window_pps=105.0,
        confirmed_attack=False,
        strong_detector_signal=False,
        quarantined_until="",
        now_iso="2026-08-29T20:00:00Z",
        robust_stats_ready=True,
    )
    base.update(overrides)
    return safe_learning_decision(**base)


class SafeLearningGuardrailTest(unittest.TestCase):
    def test_normal_traffic_would_learn(self):
        d = _decision()
        self.assertTrue(d["should_update"])
        self.assertEqual(ELIGIBLE, d["classification"])
        self.assertEqual("normal", d["reason"])

    def test_confirmed_attack_blocked(self):
        d = _decision(confirmed_attack=True)
        self.assertFalse(d["should_update"])
        self.assertEqual("confirmed_attack", d["reason"])

    def test_critical_blocked(self):
        # CRITICAL severity is mapped to confirmed_attack=True by the caller.
        d = _decision(confirmed_attack=True)
        self.assertEqual(REJECTED, d["classification"])
        self.assertFalse(d["should_update"])

    def test_network_sweep_blocked(self):
        d = _decision(strong_detector_signal=True, robust_stats_ready=False)
        self.assertFalse(d["should_update"])
        self.assertEqual("detector_signal", d["reason"])

    def test_carpet_bombing_blocked(self):
        d = _decision(strong_detector_signal=True, robust_stats_ready=False)
        self.assertEqual(REJECTED, d["classification"])

    def test_udp_flood_blocked(self):
        d = _decision(strong_detector_signal=True, robust_stats_ready=False)
        self.assertFalse(d["should_update"])

    def test_bootstrap_strong_signal_blocked(self):
        d = _decision(baseline_state=BOOTSTRAP, strong_detector_signal=True)
        self.assertFalse(d["should_update"])
        self.assertEqual("bootstrap_strong_signal", d["reason"])

    def test_protected_range_blocked(self):
        d = _decision(protected_or_internal=True)
        self.assertFalse(d["should_update"])
        self.assertEqual("protected_or_internal", d["reason"])

    def test_internal_range_blocked(self):
        d = _decision(protected_or_internal=True)
        self.assertEqual(REJECTED, d["classification"])

    def test_known_malicious_campaign_blocked(self):
        d = _decision(campaign_blocked=True)
        self.assertFalse(d["should_update"])
        self.assertEqual("campaign_rejected", d["reason"])

    def test_guardrails_override_robust_stats(self):
        for kw in ({"campaign_blocked": True}, {"protected_or_internal": True}, {"confirmed_attack": True}):
            d = _decision(robust_stats_ready=True, **kw)
            self.assertFalse(d["should_update"])

    def test_future_quarantine_frozen_does_not_learn(self):
        d = _decision(quarantined_until="2026-08-29T20:15:00Z", now_iso="2026-08-29T20:00:00Z")
        self.assertFalse(d["should_update"])
        self.assertEqual("quarantine_frozen", d["reason"])


V2_DDL = """
CREATE TABLE behavior_safe_learning_shadow_audit_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hour_bucket TEXT NOT NULL,
    protocol TEXT NOT NULL,
    classification TEXT NOT NULL,
    reason TEXT NOT NULL,
    policy_version TEXT NOT NULL DEFAULT 'safe_learning_shadow_v2',
    evaluation_count INTEGER NOT NULL DEFAULT 0,
    would_learn_count INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0,
    quarantined_count INTEGER NOT NULL DEFAULT 0,
    confirmed_attack_count INTEGER NOT NULL DEFAULT 0,
    strong_detector_signal_count INTEGER NOT NULL DEFAULT 0,
    protected_or_internal_count INTEGER NOT NULL DEFAULT 0,
    campaign_blocked_count INTEGER NOT NULL DEFAULT 0,
    robust_z_min REAL,
    robust_z_max REAL,
    robust_z_sum REAL,
    robust_z_count INTEGER NOT NULL DEFAULT 0,
    baseline_state TEXT NOT NULL DEFAULT '',
    sample_prefix TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(hour_bucket, protocol, classification, reason)
);
"""


class SafeLearningAuditV2AggregationTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript(V2_DDL)

    def tearDown(self):
        self.conn.close()

    def _record(self, prefix="10.0.0.0/24", classification=QUARANTINED, reason="robust_z", **kw):
        base = dict(
            now_iso="2026-08-29T20:05:00Z",
            prefix=prefix,
            protocol="tcp",
            classification=classification,
            reason=reason,
            safe_would_update=False,
            confirmed_attack=False,
            strong_signal=False,
            protected_or_internal=False,
            campaign_blocked=False,
            audit_z=2.5,
            baseline_state=TRUSTED,
        )
        base.update(kw)
        _record_safe_learning_audit_v2(self.conn, **base)

    def test_repeated_quarantine_aggregates_single_row(self):
        for _ in range(10):
            self._record()
        n = self.conn.execute("SELECT COUNT(*) FROM behavior_safe_learning_shadow_audit_v2").fetchone()[0]
        self.assertEqual(1, n)
        row = self.conn.execute("SELECT evaluation_count, quarantined_count FROM behavior_safe_learning_shadow_audit_v2").fetchone()
        self.assertEqual(10, row[0])
        self.assertEqual(10, row[1])

    def test_repeated_eligible_aggregates(self):
        for _ in range(5):
            self._record(classification=ELIGIBLE, reason="quarantine_frozen")
        n = self.conn.execute("SELECT COUNT(*) FROM behavior_safe_learning_shadow_audit_v2").fetchone()[0]
        self.assertEqual(1, n)
        row = self.conn.execute("SELECT evaluation_count FROM behavior_safe_learning_shadow_audit_v2").fetchone()
        self.assertEqual(5, row[0])

    def test_state_change_creates_new_row(self):
        self._record(reason="robust_z")
        self._record(reason="quarantine_extended")
        self._record(classification=ELIGIBLE, reason="normal")
        n = self.conn.execute("SELECT COUNT(*) FROM behavior_safe_learning_shadow_audit_v2").fetchone()[0]
        self.assertEqual(3, n)

    def test_different_hour_new_row(self):
        self._record(now_iso="2026-08-29T20:05:00Z")
        self._record(now_iso="2026-08-29T21:05:00Z")
        n = self.conn.execute("SELECT COUNT(*) FROM behavior_safe_learning_shadow_audit_v2").fetchone()[0]
        self.assertEqual(2, n)

    def test_robust_z_aggregation(self):
        self._record(audit_z=2.0)
        self._record(audit_z=4.0)
        row = self.conn.execute("SELECT robust_z_min, robust_z_max, robust_z_sum, robust_z_count FROM behavior_safe_learning_shadow_audit_v2").fetchone()
        self.assertEqual(2.0, row[0])
        self.assertEqual(4.0, row[1])
        self.assertEqual(6.0, row[2])
        self.assertEqual(2, row[3])

    def test_different_prefixes_same_meta_aggregate(self):
        # The v2 key deliberately excludes target_prefix (which fans each target
        # into 9 prefix lengths); same-meta rows must collapse to one bucket.
        self._record(prefix="10.0.0.0/24", reason="robust_z")
        self._record(prefix="10.0.0.0/32", reason="robust_z")
        self._record(prefix="192.0.2.0/24", reason="robust_z")
        n = self.conn.execute("SELECT COUNT(*) FROM behavior_safe_learning_shadow_audit_v2").fetchone()[0]
        self.assertEqual(1, n)
        row = self.conn.execute("SELECT evaluation_count, sample_prefix FROM behavior_safe_learning_shadow_audit_v2").fetchone()
        self.assertEqual(3, row[0])
        self.assertEqual("192.0.2.0/24", row[1])

    def test_guardrail_counts_aggregate(self):
        self._record(classification=REJECTED, reason="campaign_rejected", campaign_blocked=True)
        self._record(classification=REJECTED, reason="campaign_rejected", campaign_blocked=True)
        self._record(classification=REJECTED, reason="protected_or_internal", protected_or_internal=True)
        n = self.conn.execute("SELECT COUNT(*) FROM behavior_safe_learning_shadow_audit_v2").fetchone()[0]
        self.assertEqual(2, n)
        row = self.conn.execute("SELECT campaign_blocked_count FROM behavior_safe_learning_shadow_audit_v2 WHERE reason='campaign_rejected'").fetchone()
        self.assertEqual(2, row[0])


if __name__ == "__main__":
    unittest.main()
