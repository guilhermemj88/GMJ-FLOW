from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SecondaryAnalyticsStaticTest(unittest.TestCase):
    """Guards Fase 5 Secondary Analytics (Top Protocolos, Top ASN origem, resumo Flows)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

    def test_section_after_top_interfaces_before_legacy_grid(self) -> None:
        self.assertIn('class="dashboard-overview-chrome" id="dashboardSecondaryAnalyticsSection"', self.html)
        top = self.html.index('id="dashboardTopInterfacesSection"')
        secondary = self.html.index('id="dashboardSecondaryAnalyticsSection"')
        legacy = self.html.index('data-dashboard-legacy-fallback="top-rankings"')
        self.assertLess(top, secondary)
        self.assertLess(secondary, legacy)

    def test_top_protocolos_uses_throughput_and_share(self) -> None:
        self.assertIn('id="secondaryProtocolsTable"', self.html)
        self.assertIn("function renderSecondaryProtocols(items)", self.html)
        # share calculado por throughput (bps), nao por contagem de registros
        self.assertIn("const total = rows.reduce((sum, item) => sum + (Number(item.bps) || 0), 0);", self.html)
        self.assertIn("const share = bps / total * 100", self.html)
        self.assertIn("escapeHtml(item.proto)", self.html)
        # reusa a ShareBar existente
        self.assertIn('class="share-bar"', self.html)

    def test_top_asn_origin_removed_from_default_overview(self) -> None:
        # O card "Top ASN de origem" era redundante: duplicava o painel
        # "Destinos do Upload" (mesmo payload asnSrc) e o widget
        # "Top ASN Externo · Upload". Saiu do overview default; a fonte de dados
        # (asnSrcTable) segue viva e a API nao foi alterada.
        self.assertNotIn('id="secondaryAsnTable"', self.html)
        self.assertNotIn("Top ASN de origem", self.html)
        self.assertNotIn("renderSecondaryAsnSrc", self.html)
        self.assertIn('id="asnSrcTable"', self.html)
        self.assertIn("renderAsnWidget(chart, tableId, statusId, payload);", self.html)

    def test_asn_names_from_real_source_only(self) -> None:
        self.assertIn("asnDisplayName(item)", self.html)
        self.assertIn("asnCode(item)", self.html)
        # o widget de ASN exibe o codigo e usa o nome real como descricao/tooltip
        self.assertIn("escapeHtml(asnCode(item))", self.html)
        self.assertIn('title="${escapeHtml(asnDisplayName(item))}"', self.html)

    def test_flows_summary_and_navigation(self) -> None:
        self.assertIn('id="secondaryFlowsSummary"', self.html)
        self.assertIn('id="secondaryFlowsLink"', self.html)
        self.assertIn('onclick="showView(\'flows\')"', self.html)
        # métricas reais derivadas do payload de protocolos (flows + packets_s)
        self.assertIn("function renderSecondaryFlowsSummary(protocolItems)", self.html)
        self.assertIn("Number(item.flows)", self.html)
        self.assertIn("Number(item.packets_s)", self.html)

    def test_flows_navigation_is_permission_aware(self) -> None:
        # navega pelo mecanismo showView, que aplica requiredPermissionForView
        self.assertIn('data-nav-view="flows" data-required-permission="dashboard.view"', self.html)

    def test_no_new_requests_in_secondary_render(self) -> None:
        start = self.html.index("function renderSecondaryProtocols")
        end = self.html.index("let alertsRows = [];")
        block = self.html[start:end]
        self.assertNotIn("fetchJSON(", block)
        self.assertNotIn("apiRequest(", block)
        self.assertNotIn("loadAllInterfaces(", block)

    def test_empty_and_error_states(self) -> None:
        self.assertIn("Sem dados de protocolo.", self.html)
        self.assertIn("renderTableMessage('secondaryProtocolsTable'", self.html)
        # o widget de ranking publica o mesmo vazio para tabela e grafico
        self.assertIn("emptyLabel: 'Sem dados de protocolo.'", self.html)

    def test_legacy_top_rankings_superseded(self) -> None:
        # grade legada permanece no DOM (migração/tests) mas nunca mais é exibida
        self.assertIn("fallback.hidden = true;", self.html)
        self.assertIn("fallback.setAttribute('aria-hidden', 'true');", self.html)

    def test_top_clients_zones_deferred(self) -> None:
        # adiado nesta fase para evitar N+1/agregação duplicada
        self.assertNotIn("secondaryClients", self.html)
        self.assertNotIn("Top Clientes", self.html)

    def test_css_uses_theme_tokens_only(self) -> None:
        marker = "/* ---- Secondary Analytics (Fase 5) ---- */"
        start = self.html.index(marker)
        end = self.html.index("</style>", start)
        block = self.html[start:end]
        for token in ("var(--muted)", "var(--line)", "var(--font-mono)"):
            self.assertIn(token, block)
        # nenhuma paleta hardcoded no bloco novo
        self.assertNotIn("#", block)


if __name__ == "__main__":
    unittest.main()
