"""Contratos estáticos da página de Codecs no frontend (GMJ-FLOW).

Verifica navegação, página, funções e semântica da porta 443 sem precisar de
navegador. Segue o padrão dos demais testes estáticos de frontend.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


def _section(marker: str, end_marker: str = "</section>") -> str:
    start = HTML.index(marker)
    end = HTML.index(end_marker, start)
    return HTML[start:end]


class CodecsPageStaticTest(unittest.TestCase):
    def test_nav_button_points_to_codecs_view(self):
        self.assertIn('id="codecsNavButton" type="button" data-nav-view="codecs" data-required-permission="settings.view"', HTML)
        self.assertIn('<i data-lucide="tags"></i><span>Codecs</span>', HTML)

    def test_codecs_view_section_exists(self):
        self.assertIn('id="view-codecs" class="app-view"', HTML)

    def test_show_view_handles_codecs(self):
        show_view = HTML.split("function showView(", 1)[1]
        self.assertIn("view === 'codecs'", show_view)
        self.assertIn("loadCodecsWorkspace()", show_view)

    def test_permission_maps_codecs_to_settings(self):
        requirements = HTML.split("function requiredPermissionForView(", 1)[1].split("}", 1)[0]
        self.assertIn("codecs: 'settings.view'", requirements)

    def test_required_functions_exist(self):
        for token in (
            "async function loadCodecsWorkspace()",
            "function renderCodecsTable(",
            "function openCodecEditor(",
            "async function saveCodec()",
            "async function handleCodecAction(",
            "async function runCodecTest()",
            "function codecPortLabel(",
        ):
            self.assertIn(token, HTML)

    def test_port_any_rendering(self):
        self.assertIn("function codecPortLabel(value)", HTML)
        # 0, null e vazio devem exibir ANY.
        self.assertIn("num <= 0) return 'ANY'", HTML)

    def test_builtin_custom_badges(self):
        self.assertIn("<span class=\"badge-soft ok\">BUILTIN</span>", HTML)
        self.assertIn("<span class=\"badge-soft warn\">CUSTOM</span>", HTML)

    def test_delete_builtin_is_blocked_in_ui(self):
        self.assertIn("Codecs builtin não podem ser excluídos.", HTML)

    def test_codec_tester_calls_test_endpoint(self):
        self.assertIn("'/api/flow-codecs/test'", HTML)
        self.assertIn("codec(s) correspondente(s), em ordem de prioridade", HTML)

    def test_https_and_quic_client_return_shown_distinct(self):
        self.assertIn("<strong>HTTPS_CLIENT</strong> (TCP dst 443)", HTML)
        self.assertIn("<strong>HTTPS_RETURN</strong> (TCP src 443)", HTML)
        self.assertIn("<strong>QUIC_CLIENT</strong> (UDP dst 443)", HTML)
        self.assertIn("<strong>QUIC_RETURN</strong> (UDP src 443)", HTML)

    def test_no_copy_claims_443_is_trusted_or_whitelist(self):
        for forbidden in (
            "443 é confiável",
            "443 confiável",
            "443 = whitelist",
            "443 é whitelist",
            "porta 443 é segura",
        ):
            self.assertNotIn(forbidden, HTML)
        # A página deixa explícito que codec não é whitelist/autorização.
        self.assertIn("Codec match ≠ whitelist", HTML)
        self.assertIn("Codec match ≠ autorização", HTML)
        self.assertIn("Porta 443 sozinha é evidência fraca (hint)", HTML)

    def test_editor_exposes_all_fields(self):
        editor = _section('id="codecEditorDrawer"', "</aside>")
        for field in (
            'id="codecEditorName"',
            'id="codecEditorDisplayName"',
            'id="codecEditorDescription"',
            'id="codecEditorProtocol"',
            'id="codecEditorSourcePort"',
            'id="codecEditorDestinationPort"',
            'id="codecEditorDirection"',
            'id="codecEditorTcpFlags"',
            'id="codecEditorIcmpType"',
            'id="codecEditorIcmpCode"',
            'id="codecEditorSourceRole"',
            'id="codecEditorDestinationRole"',
            'id="codecEditorProvider"',
            'id="codecEditorPriority"',
            'id="codecEditorExclusiveGroup"',
            'id="codecEditorConsumeTraffic"',
            'id="codecEditorActive"',
        ):
            self.assertIn(field, editor)


if __name__ == "__main__":
    unittest.main()
