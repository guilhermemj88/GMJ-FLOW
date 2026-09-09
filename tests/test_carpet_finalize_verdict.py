"""Regression: `finalize_vector` must preserve the Carpet semantic classification.

Bug: `BehavioralDetectionEngine` re-finalizes vectors after correlation, and the
generic `finalize_vector` recomputed verdict/severity purely from
`detector_score`, overriding the Carpet detector's
EXPECTED_DISTRIBUTED_TRAFFIC (INFO/LOW) and SUSPICIOUS_DISTRIBUTED_TRAFFIC
(SUSPICIOUS/MEDIUM) classification.
"""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavioral_detection import (  # noqa: E402
    CARPET_BOMBING,
    EXPECTED_DISTRIBUTED_TRAFFIC,
    SUSPICIOUS_DISTRIBUTED_TRAFFIC,
    SYN_FLOOD,
    AttackVector,
    finalize_vector,
)
from app.services.threat_contracts import detector_verdict  # noqa: E402


def _carpet_vector(classification: str, score: int = 54, persistent_windows: int = 5) -> AttackVector:
    return AttackVector(
        attack_type=CARPET_BOMBING,
        detector="prefix_carpet_bombing",
        detector_score=score,
        confidence=score / 100.0,
        first_seen="2026-01-01T00:00:00Z",
        last_seen="2026-01-01T00:01:00Z",
        target_prefix="45.168.200.0/22",
        features={
            "traffic_classification": classification,
            "persistent_windows": persistent_windows,
        },
    )


class CarpetFinalizeVerdictTest(unittest.TestCase):
    def test_expected_traffic_is_info_low_and_idempotent(self):
        # Sanity: with this score + persistence the generic verdict would
        # promote the vector (this is exactly the bug being regressed).
        self.assertEqual("SUSPICIOUS", detector_verdict(54, persistent_windows=5))
        vector = _carpet_vector(EXPECTED_DISTRIBUTED_TRAFFIC)
        finalize_vector(vector)
        self.assertEqual("INFO", vector.verdict)
        self.assertEqual("LOW", vector.severity)
        # A second finalize (engine post-processing) must not change it.
        finalize_vector(vector)
        self.assertEqual("INFO", vector.verdict)
        self.assertEqual("LOW", vector.severity)

    def test_suspicious_traffic_is_suspicious_medium_and_idempotent(self):
        vector = _carpet_vector(SUSPICIOUS_DISTRIBUTED_TRAFFIC)
        finalize_vector(vector)
        finalize_vector(vector)
        self.assertEqual("SUSPICIOUS", vector.verdict)
        self.assertEqual("MEDIUM", vector.severity)

    def test_confirmed_attack_keeps_score_based_verdict(self):
        vector = _carpet_vector("CONFIRMED_ATTACK", score=95, persistent_windows=5)
        finalize_vector(vector)
        self.assertEqual("CONFIRMED_ATTACK", vector.verdict)
        self.assertEqual("CRITICAL", vector.severity)

    def test_non_carpet_vector_is_unaffected(self):
        vector = AttackVector(
            attack_type=SYN_FLOOD,
            detector="syn_flood",
            detector_score=54,
            confidence=0.54,
            first_seen="2026-01-01T00:00:00Z",
            last_seen="2026-01-01T00:01:00Z",
            target_ip="203.0.113.10",
            features={"persistent_windows": 5},
        )
        finalize_vector(vector)
        # Generic path untouched for non-CARPET vectors.
        self.assertEqual("SUSPICIOUS", vector.verdict)
        self.assertEqual("LOW", vector.severity)


if __name__ == "__main__":
    unittest.main()
