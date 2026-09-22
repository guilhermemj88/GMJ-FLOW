from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

ROOT = Path(__file__).resolve().parents[1]


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


class PeakHunterRefactorContractTest(unittest.TestCase):
    """Static contracts that prove there is ONE operational Peak Hunter."""

    def test_evidence_never_uses_flow_raw(self):
        source = read("backend/app/services/peak_evidence.py")
        self.assertNotIn("FROM flow_raw", source)
        self.assertIn("flow_dashboard_", source)

    def test_runner_never_uses_flow_raw(self):
        runner = read("backend/app/services/peak_hunter_auto.py")
        self.assertNotIn("FROM flow_raw", runner)

    def test_runner_never_calls_legacy_or_mitigation(self):
        runner = read("backend/app/services/peak_hunter_auto.py")
        for forbidden in (
            "analyze_peak_hunter",
            "generate_mitigation_candidates",
            "build_peak_hunter_response_profile_draft",
            "build_peak_hunter_detection_rule_draft",
            "build_peak_hunter_playbook_draft",
            "build_peak_hunter_attack_vector_draft",
            "export_peak_analysis_dataset",
            "classify_dominant_group",
            "validate_mitigation_decision",
            "load_playbook",
        ):
            self.assertNotIn(forbidden, runner, forbidden)

    def test_evidence_queries_are_time_bounded(self):
        source = read("backend/app/services/peak_evidence.py")
        self.assertIn("minute >= {{start:DateTime}}", source)
        self.assertIn("minute < {{end:DateTime}}", source)

    def test_ui_lists_persisted_events(self):
        html = read("frontend/index.html")
        self.assertIn("/api/peak-hunter/events", html)
        self.assertIn("renderPeakHunterEvents", html)
        self.assertIn("loadPeakHunterEvents", html)

    def test_ui_legacy_tabs_are_labelled(self):
        html = read("frontend/index.html")
        self.assertIn("Histórico (legacy)", html)
        self.assertIn("Automação (legacy)", html)

    def test_detection_is_pure_no_io(self):
        source = read("backend/app/services/peak_detection.py")
        for forbidden in ("flow_raw", "clickhouse", "sqlite", "http"):
            self.assertNotIn(forbidden, source)

    def test_handoff_does_not_import_mitigation(self):
        source = read("backend/app/services/peak_handoff.py")
        for forbidden in (
            "from app.services.mitigation",
            "from app.services.transit_rtbh",
            "generate_mitigation_candidates",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
