from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = REPO_ROOT / "frontend" / "index.html"
MAIN_PATH = REPO_ROOT / "backend" / "app" / "main.py"


class MitigationViewSectionsStaticTest(unittest.TestCase):
    """A tela de Mitigação segue a estrutura especificada.

    Ordem esperada: AGORA / Estado operacional, EVENTOS RECENTES,
    SAÚDE DA AUTOMAÇÃO e CONFIGURAÇÃO (IA, perfis, políticas de porta,
    prefixos protegidos e controles manuais).
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")
        cls.main = MAIN_PATH.read_text(encoding="utf-8")

    def test_sections_present(self) -> None:
        for marker in (
            'id="mitigationNowPanel"',
            'id="mitigationRecentEventsPanel"',
            'id="mitigationAutomationHealthPanel"',
        ):
            self.assertIn(marker, self.html)

    def test_section_order(self) -> None:
        markers = [
            'id="mitigationNowPanel"',
            'id="mitigationRecentEventsPanel"',
            'id="mitigationAutomationHealthPanel"',
            "Configuração</h2>",
            'id="rtbhPanel"',
        ]
        positions = [self.html.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions), "ordem das seções da Mitigação divergente")

    def test_now_panel_fields(self) -> None:
        section = self.html.split('id="mitigationNowPanel"', 1)[1].split("</section>", 1)[0]
        for marker in (
            "Agora / Estado operacional",
            'id="mitigationNowSummary"',
            'id="mitigationNowCards"',
        ):
            self.assertIn(marker, section)
        for marker in (
            "Alvo <code>",
            "Ataque/vetor:",
            "Ação aplicada:",
            "Conector:",
            "Início:",
            "Expira:",
            "mitigation-now-detail",
            "bgp-ann-withdraw",
        ):
            self.assertIn(marker, self.html, f"campo obrigatório do painel AGORA ausente: {marker}")

    def test_recent_events_counters(self) -> None:
        for marker in (
            'id="mitigationRecentMitigated"',
            'id="mitigationRecentCorrelated"',
            'id="mitigationRecentBlocked"',
            'id="mitigationRecentFailed"',
            'id="mitigationRecentEnded"',
        ):
            self.assertIn(marker, self.html)

    def test_automation_health_panel(self) -> None:
        for marker in (
            'id="mitigationHealthBgp"',
            'id="mitigationHealthFlowspec"',
            'id="mitigationHealthOrchestrator"',
            'id="mitigationHealthProfiles"',
            'id="mitigationHealthFailures"',
        ):
            self.assertIn(marker, self.html)

    def test_configuration_groups_controls(self) -> None:
        config_index = self.html.index("Configuração</h2>")
        for marker in (
            "IA para mitigação",
            "Perfis de resposta",
            "Politica de seguranca",
            "Prefixos Protegidos",
            "Controles manuais (teste manual / laboratório)",
        ):
            self.assertGreater(
                self.html.index(marker),
                config_index,
                f"{marker} deveria estar dentro do bloco CONFIGURAÇÃO",
            )

    def test_moved_tables_appear_once(self) -> None:
        for anchor in (
            "automaticMitigationExecutionsTable",
            "bgpPendingSuggestionsTable",
            "bgpInFlightAnnouncementsTable",
            "bgpActiveAnnouncementsTable",
            "bgpFailedAnnouncementsTable",
            "bgpHistoryAnnouncementsTable",
        ):
            self.assertEqual(self.html.count(f'id="{anchor}"'), 1, f"{anchor} deve aparecer exatamente uma vez")

    def test_render_functions_present(self) -> None:
        for name in (
            "function renderMitigationNow()",
            "function renderMitigationRecentEvents()",
            "function renderMitigationAutomationHealth(",
            "function openBgpAnnouncementDetail(",
            "function formatRemainingWindow(",
            "function mitigationConnectorConfirmation(",
        ):
            self.assertIn(name, self.html)
        for hook in (
            "renderMitigationNow();",
            "renderMitigationRecentEvents();",
            "renderMitigationAutomationHealth(mitigationAutomationHealthPayload);",
        ):
            self.assertIn(hook, self.html)

    def test_detail_modal_present(self) -> None:
        self.assertIn('id="bgpAnnouncementDetailModal"', self.html)
        self.assertIn('id="bgpAnnouncementDetailBody"', self.html)
        self.assertIn("openModal('bgpAnnouncementDetailModal')", self.html)

    def test_health_endpoint_contract(self) -> None:
        self.assertIn("/api/mitigation/automation/health", self.html)
        self.assertIn('@app.get("/api/mitigation/automation/health")', self.main)
        self.assertIn("def mitigation_automation_health(request: Request):", self.main)
        self.assertIn("AUTOMATIC_MITIGATION_THREAD", self.main)
        self.assertIn('sqlite_table_exists(conn, "automatic_mitigation_jobs")', self.main)


if __name__ == "__main__":
    unittest.main()
