"""P5.0 UI: transport semantics badge helper + wiring static tests."""
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class P5TransportSemanticsUiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (ROOT / "frontend" / "threat-intelligence.js").read_text(encoding="utf-8")
        cls.style = (ROOT / "frontend" / "threat-intelligence.css").read_text(encoding="utf-8")

    def test_semantic_label_mapping_is_centralized(self) -> None:
        self.assertIn("const TRANSPORT_SEMANTIC_LABELS = Object.freeze({", self.script)
        self.assertIn("HTTPS_SERVER_RESPONSE: 'HTTPS Server Response'", self.script)
        self.assertIn("HTTPS_CLIENT_INITIATION: 'HTTPS Client Initiation'", self.script)
        self.assertIn("HTTPS_SOURCE_SYN: 'HTTPS Source SYN'", self.script)
        self.assertIn("HTTPS_BIDIRECTIONAL_ESTABLISHED: 'HTTPS Established'", self.script)
        self.assertIn("HTTPS_AMBIGUOUS: 'HTTPS / TCP 443'", self.script)
        self.assertIn("QUIC_UDP_443: 'QUIC / UDP 443'", self.script)

    def test_display_helper_returns_null_for_missing_or_non_https(self) -> None:
        self.assertIn("function getTransportSemanticDisplay(investigation)", self.script)
        self.assertIn("if (!role) return null;", self.script)
        self.assertIn("if (roleUpper === 'NON_HTTPS') return null;", self.script)

    def test_conflict_prevented_with_threat_confidence(self) -> None:
        self.assertIn("Transport confidence:", self.script)

    def test_c2_overlay_and_reason_labels_present(self) -> None:
        self.assertIn("C2 over HTTPS", self.script)
        self.assertIn("'Source port 443'", self.script)
        self.assertIn("'ACK dominant'", self.script)
        self.assertIn("'Inbound server direction'", self.script)
        self.assertIn("'UDP port 443'", self.script)

    def test_badge_wired_in_attack_vector_list(self) -> None:
        self.assertIn("${renderTransportSemanticBadge(item.investigation)}", self.script)

    def test_badge_wired_in_investigation_drawer_ports_section(self) -> None:
        self.assertIn(
            '<section id="security-event-ports"><h3>Portas e protocolos</h3>${renderTransportSemanticBadge(investigation)}',
            self.script,
        )

    def test_attack_type_remains_primary_in_list(self) -> None:
        self.assertIn("<td><strong>${esc(item.attack_type)}</strong>${renderTransportSemanticBadge(item.investigation)}", self.script)

    def test_css_badge_styles_present(self) -> None:
        self.assertIn(".transport-semantic-badge", self.style)
        self.assertIn(".transport-semantic-c2", self.style)
        self.assertIn(".transport-semantic-confidence", self.style)

    def test_unknown_enum_graceful_fallback(self) -> None:
        self.assertIn("function humanizeTransportEnum(value)", self.script)
        self.assertIn("TRANSPORT_SEMANTIC_LABELS[roleUpper] || humanizeTransportEnum(role)", self.script)


if __name__ == "__main__":
    unittest.main()
