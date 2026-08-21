from __future__ import annotations

import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.threat_score import threat_score_payload  # noqa: E402


class ThreatScoreTest(unittest.TestCase):
    def base_event(self, **overrides):
        event = {
            "severity": "HIGH",
            "attack_type": "NETWORK_SWEEP",
            "direction": "INBOUND",
            "src_role": "EXTERNAL",
            "dst_role": "CUSTOMER",
            "recurrence_count": 4,
            "unique_destinations": 20,
            "unique_dst_ports": 1,
            "baseline_deviation": 3,
            "detector_score": 87,
            "investigation": {"tcp_flags": [{"flags": 2, "packets": 100}]},
        }
        event.update(overrides)
        return event

    def test_high_score_external_inbound_would_block_in_shadow(self):
        score = threat_score_payload(
            self.base_event(severity="CRITICAL"),
            history={"historical_recurrence": 6, "prior_mitigations": 0},
        )
        self.assertGreaterEqual(score["score"], 85)
        self.assertEqual("auto_mitigation_eligible", score["band"])
        self.assertEqual("shadow", score["mode"])
        self.assertEqual("WOULD_BLOCK", score["shadow_decision"])
        self.assertFalse(score["mitigation_executed"])
        labels = " ".join(component["label"] for component in score["components"])
        self.assertIn("network_sweep", labels)
        self.assertIn("recorrência", labels)
        self.assertIn("20+ destinos", labels)
        self.assertIn("origem externa", labels)
        self.assertIn("histórico", labels)

    def test_cgnat_or_outbound_never_blocks(self):
        event = self.base_event(direction="OUTBOUND", src_role="CGNAT_PUBLIC", dst_role="EXTERNAL")
        score = threat_score_payload(event)
        self.assertEqual("WOULD_NOT_BLOCK", score["shadow_decision"])
        self.assertFalse(score["mitigation_executed"])

    def test_critical_alone_does_not_imply_block(self):
        # Critical severity but low technical evidence and internal source.
        event = self.base_event(
            severity="CRITICAL", attack_type="LOW_SLOW_SCAN", recurrence_count=1,
            unique_destinations=3, baseline_deviation=0, detector_score=45,
            src_role="CUSTOMER", direction="OUTBOUND",
        )
        score = threat_score_payload(event)
        self.assertEqual("WOULD_NOT_BLOCK", score["shadow_decision"])

    def test_bands_are_exhaustive(self):
        cases = [(0, "informational"), (40, "suspicious"), (60, "needs_review"),
                 (75, "mitigation_candidate"), (85, "auto_mitigation_eligible"), (100, "auto_mitigation_eligible")]
        for detector_score, band in cases:
            score = threat_score_payload(self.base_event(severity="LOW", attack_type="OTHER",
                                                          recurrence_count=0, unique_destinations=0,
                                                          baseline_deviation=0, detector_score=detector_score,
                                                          direction="UNKNOWN", src_role="UNKNOWN",
                                                          investigation={}))
            # Without any component the score falls back to detector_score.
            self.assertEqual(band, score["band"], f"detector_score={detector_score}")


if __name__ == "__main__":
    unittest.main()
