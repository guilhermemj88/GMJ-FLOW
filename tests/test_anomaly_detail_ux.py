from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AnomalyDetailUxStaticTest(unittest.TestCase):
    """Guards the anomaly detail UX pass 2 (frontend-only, no backend)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        cls.style = (ROOT / "frontend" / "threat-intelligence.css").read_text(encoding="utf-8")

    def test_empty_field_filter_exists(self) -> None:
        self.assertIn("isSemanticEmpty", self.html)

    def test_threshold_card_resolves_from_detection(self) -> None:
        # The card must fall back to source_details_json.detection.trigger_threshold,
        # same chain as the technical details section, instead of a stale 0 value.
        self.assertIn("cardTriggerThreshold", self.html)
        self.assertIn("detailDetection.trigger_threshold", self.html)

    def test_addressing_context_has_dedicated_collapsible_block(self) -> None:
        self.assertIn("Contexto de endereçamento / CGNAT", self.html)

    def test_source_origin_renamed_to_detection_source(self) -> None:
        self.assertIn("Fonte da detecção", self.html)
        self.assertNotIn("['Origem', anomalySourceLabel", self.html)

    def test_decision_lead_block_present(self) -> None:
        self.assertIn("Mitigação automática", self.html)
        self.assertIn("ux-decision", self.style)

    def test_flows_table_has_compact_columns(self) -> None:
        self.assertIn("<th>Conversa</th>", self.html)
        self.assertIn("<th>Proto</th>", self.html)
        self.assertNotIn('<th class="text-end">Src porta</th>', self.html)
        self.assertNotIn('<th class="text-end">Dst porta</th>', self.html)
        self.assertIn("flow-conversation", self.html)
        self.assertIn("flow-secondary", self.html)


if __name__ == "__main__":
    unittest.main()
