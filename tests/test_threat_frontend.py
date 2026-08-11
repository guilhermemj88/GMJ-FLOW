from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ThreatFrontendStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        cls.script = (ROOT / "frontend" / "threat-intelligence.js").read_text(encoding="utf-8")
        cls.style = (ROOT / "frontend" / "threat-intelligence.css").read_text(encoding="utf-8")

    def test_navigation_view_and_permission_are_wired(self) -> None:
        self.assertIn('data-nav-view="threat-intelligence"', self.html)
        self.assertIn('id="view-threat-intelligence"', self.html)
        self.assertIn("'threat-intelligence': 'anomalies.view'", self.html)
        self.assertIn("window.loadThreatIntelligenceWorkspace?.()", self.html)

    def test_current_map_component_is_reused(self) -> None:
        self.assertIn("new root.GeoFlowMap", self.script)
        self.assertIn("id=\"threatGlobalMap\"", self.html)

    def test_provider_secrets_are_not_rendered(self) -> None:
        self.assertNotIn("GREYNOISE_API_KEY", self.script)
        self.assertNotIn("api_key", self.script.lower())
        self.assertIn("credential_configured", self.script)

    def test_text_badges_exist_in_addition_to_colors(self) -> None:
        for label in ("GMJ-FLOW", "External Threat Intel", "Manual", "Allowlist/Exception"):
            self.assertIn(label, self.html)
        self.assertIn("threat-source-badge", self.style)


if __name__ == "__main__":
    unittest.main()
