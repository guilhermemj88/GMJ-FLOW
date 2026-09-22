from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.peak_handoff import handoff_peak_event


def entry(verdict, handoff_recommended=True):
    return {
        "threat": {
            "verdict": verdict,
            "handoff_recommended": handoff_recommended,
            "reasons": ["strong_ioc"],
            "ioc_hit_count": 1,
        },
        "peak": {"metric": "both"},
        "evidence": {"deltas": {"pps_delta_pct": 200}},
    }


class PeakHandoffTest(unittest.TestCase):
    def test_normal_peak_does_not_handoff(self):
        result = handoff_peak_event(None, 1, entry("normal", handoff_recommended=False))
        self.assertEqual(result["status"], "no_handoff")

    def test_suspicious_peak_handoff_pending_without_callback(self):
        result = handoff_peak_event(None, 1, entry("suspicious"))
        self.assertEqual(result["status"], "handoff_pending")
        self.assertEqual(result["payload"]["verdict"], "suspicious")

    def test_suspicious_peak_handoff_uses_existing_callback(self):
        calls = []

        def create_event(conn, payload):
            calls.append(payload)
            return {"security_event_id": 99}

        result = handoff_peak_event(None, 1, entry("suspicious"), create_event=create_event)
        self.assertEqual(result["status"], "handed_off")
        self.assertEqual(result["created"], {"security_event_id": 99})
        self.assertEqual(calls[0]["event_id"], 1)

    def test_handoff_never_calls_mitigation(self):
        source = Path(__file__).resolve().parents[1].joinpath("backend", "app", "services", "peak_handoff.py").read_text(encoding="utf-8")
        for forbidden in (
            "from app.services.mitigation",
            "from app.services.transit_rtbh",
            "from app.services.mitigation_validator",
            "generate_mitigation_candidates",
            "validate_mitigation_decision",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
