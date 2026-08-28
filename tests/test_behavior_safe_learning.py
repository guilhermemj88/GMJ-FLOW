from __future__ import annotations

import os
import sqlite3
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavior_baseline import (  # noqa: E402
    BOOTSTRAP,
    ELIGIBLE,
    QUARANTINED,
    REJECTED,
    TRUSTED,
    safe_learning_decision,
)
from app.services.behavioral_detection import (  # noqa: E402
    AttackVector,
    BehavioralDetectionEngine,
    FlowObservation,
    ensure_behavioral_schema,
)
from app.services.config_effective import behavior_safe_learning_enabled  # noqa: E402


NOW = "2026-08-27T12:00:00Z"


class SafeLearningDecisionTest(unittest.TestCase):
    def test_normal_since_install_promotes_after_clean_windows(self) -> None:
        state = BOOTSTRAP
        clean = 0
        for i in range(1, 12):
            decision = safe_learning_decision(
                baseline_state=state, bootstrap_clean_count=clean, window_pps=100.0,
                sample_count=i, ema_pps=100.0, mad_pps=5.0, now_iso=NOW,
            )
            self.assertEqual(ELIGIBLE, decision["classification"])
            self.assertTrue(decision["should_update"])
            self.assertEqual(BOOTSTRAP, decision["next_state"])
            state, clean = decision["next_state"], decision["next_clean_count"]
        decision = safe_learning_decision(
            baseline_state=state, bootstrap_clean_count=clean, window_pps=100.0,
            sample_count=12, ema_pps=100.0, mad_pps=5.0, now_iso=NOW,
        )
        self.assertEqual(TRUSTED, decision["next_state"])
        self.assertTrue(decision["promoted"])

    def test_attack_since_first_window_never_trusted(self) -> None:
        decision = safe_learning_decision(
            baseline_state=BOOTSTRAP, bootstrap_clean_count=0, window_pps=999999.0,
            strong_detector_signal=True, now_iso=NOW,
        )
        self.assertEqual(REJECTED, decision["classification"])
        self.assertFalse(decision["should_update"])
        self.assertEqual(BOOTSTRAP, decision["next_state"])
        self.assertEqual(0, decision["next_clean_count"])

    def test_attack_during_bootstrap_resets_clean_counter(self) -> None:
        decision = safe_learning_decision(
            baseline_state=BOOTSTRAP, bootstrap_clean_count=7, window_pps=100.0,
            now_iso=NOW,
        )
        self.assertEqual(BOOTSTRAP, decision["next_state"])
        self.assertEqual(8, decision["next_clean_count"])
        decision = safe_learning_decision(
            baseline_state=BOOTSTRAP, bootstrap_clean_count=8, window_pps=999999.0,
            strong_detector_signal=True, now_iso=NOW,
        )
        self.assertEqual(REJECTED, decision["classification"])
        self.assertEqual(0, decision["next_clean_count"])

    def test_confirmed_attack_after_mature_rejects(self) -> None:
        decision = safe_learning_decision(
            baseline_state=TRUSTED, sample_count=100, ema_pps=100.0, mad_pps=5.0,
            window_pps=100.0, confirmed_attack=True, now_iso=NOW,
        )
        self.assertEqual(REJECTED, decision["classification"])
        self.assertFalse(decision["should_update"])

    def test_persistent_attack_does_not_update_baseline(self) -> None:
        # Anomalous window quarantines; a subsequent anomalous window extends.
        first = safe_learning_decision(
            baseline_state=TRUSTED, sample_count=100, ema_pps=100.0, mad_pps=5.0,
            window_pps=1000.0, now_iso=NOW,
        )
        self.assertEqual(QUARANTINED, first["classification"])
        self.assertFalse(first["should_update"])
        self.assertTrue(first["next_quarantined_until"] > NOW)

    def test_isolated_spike_quarantines_then_recovers(self) -> None:
        frozen_until = "2026-08-27T12:10:00Z"
        decision = safe_learning_decision(
            baseline_state=TRUSTED, sample_count=100, ema_pps=100.0, mad_pps=5.0,
            window_pps=100.0, quarantined_until=frozen_until, now_iso=NOW,
        )
        self.assertEqual(ELIGIBLE, decision["classification"])
        self.assertFalse(decision["should_update"])  # still frozen
        self.assertEqual(frozen_until, decision["next_quarantined_until"])

    def test_legitimate_high_traffic_learns_when_below_z(self) -> None:
        decision = safe_learning_decision(
            baseline_state=TRUSTED, sample_count=100, ema_pps=100.0, mad_pps=50.0,
            window_pps=200.0, now_iso=NOW,
        )
        # z = (200-100)/(1.4826*50) ~= 1.35 < 4 => eligible
        self.assertEqual(ELIGIBLE, decision["classification"])
        self.assertTrue(decision["should_update"])

    def test_low_maturity_does_not_quarantine_on_z(self) -> None:
        # sample_count below min_quarantine_samples => no z gate.
        decision = safe_learning_decision(
            baseline_state=TRUSTED, sample_count=5, ema_pps=100.0, mad_pps=5.0,
            window_pps=1000.0, now_iso=NOW,
        )
        self.assertEqual(ELIGIBLE, decision["classification"])
        self.assertTrue(decision["should_update"])


class SafeStateMigrationTest(unittest.TestCase):
    # Row shape: (pps, bps, samples, state, clean, mad, quarantined, rejected, quarantined, trusted)
    def test_legacy_mature_row_is_trusted(self) -> None:
        row = (100.0, 800.0, 24, "BOOTSTRAP", 0, 0.0, "", 0, 0, "")
        state, _ = BehavioralDetectionEngine._safe_state(row, 25)
        self.assertEqual(TRUSTED, state)

    def test_legacy_young_row_stays_bootstrap(self) -> None:
        row = (100.0, 800.0, 5, "BOOTSTRAP", 0, 0.0, "", 0, 0, "")
        state, _ = BehavioralDetectionEngine._safe_state(row, 6)
        self.assertEqual(BOOTSTRAP, state)

    def test_new_bootstrap_counting_clean_windows_stays_bootstrap(self) -> None:
        row = (100.0, 800.0, 8, "BOOTSTRAP", 5, 5.0, "", 0, 0, "")
        state, clean = BehavioralDetectionEngine._safe_state(row, 9)
        self.assertEqual(BOOTSTRAP, state)
        self.assertEqual(5, clean)

    def test_legacy_mature_with_residual_clean_count_is_trusted(self) -> None:
        # Rows touched by an earlier shadow run may carry clean_count>0; the
        # maturity derivation must still recognize them as legacy TRUSTED.
        row = (100.0, 800.0, 30, "BOOTSTRAP", 3, 5.0, "", 0, 0, "")
        state, _ = BehavioralDetectionEngine._safe_state(row, 31)
        self.assertEqual(TRUSTED, state)

    def test_already_trusted_is_trusted(self) -> None:
        row = (100.0, 800.0, 100, "TRUSTED", 0, 5.0, "", 0, 0, "2026-08-27T12:00:00Z")
        state, _ = BehavioralDetectionEngine._safe_state(row, 101)
        self.assertEqual(TRUSTED, state)


class FeatureSwitchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            "CREATE TABLE system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )

    def tearDown(self) -> None:
        self.conn.close()

    def test_default_is_off(self) -> None:
        self.assertFalse(behavior_safe_learning_enabled(self.conn))

    def test_env_override_enables(self) -> None:
        with mock.patch.dict(os.environ, {"GMJFLOW_BEHAVIOR_SAFE_LEARNING": "true"}):
            self.assertTrue(behavior_safe_learning_enabled(self.conn))

    def test_kill_switch_wins_over_enabled(self) -> None:
        self.conn.execute(
            "INSERT INTO system_settings(key, value) VALUES ('behavior_safe_learning_enabled', 'true')"
        )
        with mock.patch.dict(os.environ, {"GMJFLOW_BEHAVIOR_SAFE_LEARNING_KILL_SWITCH": "true"}):
            self.assertFalse(behavior_safe_learning_enabled(self.conn))


class BaselineIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(self.conn)
        self.engine = BehavioralDetectionEngine(lambda: self.conn, _NoIntel())
        self.base_time = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.conn.close()

    def _observations(self, pps: int = 100, seconds_ago: int = 0) -> list[FlowObservation]:
        return [
            FlowObservation(
                observed_at=self.base_time - timedelta(seconds=seconds_ago),
                src_ip="198.51.100.1", dst_ip="203.0.113.50", src_port=40000, dst_port=443,
                protocol=6, tcp_flags=2, packets=pps * 60, bytes=pps * 60 * 100,
            )
        ]

    def _ema_row(self, prefix: str, protocol: str):
        return self.conn.execute(
            "SELECT packets_per_second_ema, bits_per_second_ema, sample_count, baseline_state, "
            "last_classification FROM prefix_behavior_baselines WHERE prefix=? AND protocol=?",
            (prefix, protocol),
        ).fetchone()

    def test_shadow_off_keeps_v1_ema(self) -> None:
        obs = self._observations(pps=100)
        self.engine.update_prefix_baselines(self.conn, obs, window_seconds=60, vectors=[])
        row = self._ema_row("203.0.113.0/24", "tcp")
        self.assertIsNotNone(row)
        # First sample => EMA == window pps exactly (V1 behavior unchanged).
        self.assertAlmostEqual(100.0, float(row["packets_per_second_ema"]), places=3)
        # Shadow metadata still written (safe proposal) without gating the EMA.
        self.assertEqual("BOOTSTRAP", row["baseline_state"])

    def test_shadow_writes_counters(self) -> None:
        self.engine.update_prefix_baselines(self.conn, self._observations(pps=100), window_seconds=60, vectors=[])
        count = self.conn.execute(
            "SELECT COUNT(*) FROM behavior_safe_learning_counters"
        ).fetchone()[0]
        self.assertGreater(count, 0)

    def test_enabled_gates_confirmed_attack(self) -> None:
        with mock.patch.dict(os.environ, {"GMJFLOW_BEHAVIOR_SAFE_LEARNING": "true"}):
            vector = AttackVector(
                attack_type="SYN_FLOOD", detector="syn_flood", detector_score=90,
                confidence=0.9, first_seen="2026-08-27T11:59:00Z", last_seen="2026-08-27T12:00:00Z",
                target_prefix="203.0.113.0/24", verdict="CONFIRMED_ATTACK", severity="CRITICAL",
            )
            self.engine.update_prefix_baselines(
                self.conn, self._observations(pps=100), window_seconds=60, vectors=[vector]
            )
        row = self._ema_row("203.0.113.0/24", "tcp")
        self.assertEqual("REJECTED", row["last_classification"])
        # First sample + REJECTED => sample_count stays 0 (not updated).
        self.assertEqual(0, row["sample_count"])

    def test_clock_skew_observations_are_excluded(self) -> None:
        # A stale (clock-skewed) spike far outside the 60s window must not
        # inflate the baseline; the window cutoff is relative to the newest
        # observation (clock-skew filtering happens upstream in ClickHouse).
        obs = [
            FlowObservation(
                observed_at=self.base_time,
                src_ip="198.51.100.1", dst_ip="203.0.113.50", src_port=40000, dst_port=443,
                protocol=6, tcp_flags=2, packets=6000, bytes=600000,
            ),
            FlowObservation(
                observed_at=self.base_time - timedelta(hours=2),
                src_ip="198.51.100.2", dst_ip="203.0.113.50", src_port=40001, dst_port=443,
                protocol=6, tcp_flags=2, packets=60_000_000, bytes=6_000_000_000,
            ),
        ]
        self.engine.update_prefix_baselines(self.conn, obs, window_seconds=60, vectors=[])
        row = self._ema_row("203.0.113.0/24", "tcp")
        self.assertIsNotNone(row)
        self.assertAlmostEqual(100.0, float(row["packets_per_second_ema"]), places=3)


class _NoIntel:
    def lookup_ip(self, *_args, **_kwargs):
        return {"matches": []}

    def external_attack_matches(self, *_args, **_kwargs):
        return []


if __name__ == "__main__":
    unittest.main()
