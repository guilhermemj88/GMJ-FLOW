import re
import unittest
from collections import Counter, defaultdict
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


def function_source(name, next_name=None):
    start = HTML.index(f"function {name}(")
    if next_name:
        end = HTML.index(f"function {next_name}(", start)
    else:
        match = re.search(r"\n    (?:async )?function \w+\(", HTML[start + 1 :])
        end = start + 1 + match.start() if match else len(HTML)
    return HTML[start:end]


class OwnershipParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.ids_by_view = defaultdict(set)
        self.section_stack = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        element_id = attrs.get("id")
        if tag == "section":
            self.section_stack.append(element_id)
        if element_id:
            self.ids.append(element_id)
            owner = next((item for item in reversed(self.section_stack) if item and item.startswith("view-")), None)
            if owner:
                self.ids_by_view[owner].add(element_id)

    def handle_endtag(self, tag):
        if tag == "section" and self.section_stack:
            self.section_stack.pop()


class FrontendAiNavigationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = OwnershipParser()
        cls.parser.feed(HTML)

    def test_ai_page_menu_tabs_and_ids_exist(self):
        ai_ids = self.parser.ids_by_view["view-ai"]
        for element_id in (
            "aiOverviewPanel",
            "aiProvidersPanel",
            "aiModelsPanel",
            "aiRoutingPanel",
            "aiPromptsPanel",
            "aiTestsPanel",
            "aiHistoryPanel",
            "aiProvidersTable",
            "aiRoutesTable",
            "aiPlaygroundPrompt",
            "aiHistoryTable",
        ):
            self.assertIn(element_id, ai_ids)
        self.assertIn('id="aiNavButton" type="button" data-nav-view="ai"', HTML)
        for tab in ("overview", "providers", "models", "routing", "prompts", "tests", "history"):
            self.assertIn(f'data-ai-tab="{tab}"', HTML)

    def test_ai_forms_were_removed_from_mitigation_and_system(self):
        mitigation = self.parser.ids_by_view["view-mitigation"]
        system = self.parser.ids_by_view["view-system"]
        for removed in (
            "aiEnabled", "aiProvider", "aiBaseUrl", "aiProfile", "aiModel", "aiTimeout",
            "aiTopFlows", "aiContextChars", "saveAiMitigationButton", "testAiMitigationButton",
        ):
            self.assertNotIn(removed, mitigation)
            self.assertNotIn(f'id="{removed}"', HTML)
        for removed in (
            "systemAiEnabled", "systemAiProvider", "systemAiBaseUrl", "systemAiModel",
            "systemAiTimeout", "systemAiContextChars", "systemAiKeepAlive", "systemAiSaveButton",
            "systemAiPullButton", "systemAiTestButton",
        ):
            self.assertNotIn(removed, system)
            self.assertNotIn(f'id="{removed}"', HTML)
        self.assertIn("mitigationAiState", mitigation)
        self.assertIn("configureMitigationAiButton", mitigation)
        self.assertIn("systemOllamaState", system)
        self.assertIn("manageAiModelsButton", system)

    def test_summary_links_open_the_expected_ai_sections(self):
        self.assertIn("pendingAiRouteFunction = 'mitigation_analysis'; showView('ai'); showAiTab('routing')", HTML)
        self.assertIn("showView('ai'); showAiTab('models')", HTML)

    def test_canonical_route_and_legacy_aliases(self):
        source = function_source("canonicalNavigationView", "viewFromLocationHash")
        self.assertIn("['ai-settings', 'local-ai', 'mitigation-ai']", source)
        self.assertIn("return 'ai'", source)
        self.assertIn("window.history.replaceState(null, '', `#${view}`)", HTML)

    def test_html_ids_are_unique(self):
        duplicates = [element_id for element_id, count in Counter(self.parser.ids).items() if count > 1]
        self.assertEqual([], duplicates)

    def test_ai_data_is_loaded_only_when_ai_view_is_active(self):
        start = HTML.index("function showView(")
        end = HTML.index("document.querySelectorAll('.side-nav button[data-nav-view]')", start)
        source = HTML[start:end]
        self.assertIn("view === 'ai'", source)
        self.assertIn("loadAiWorkspace().catch", source)
        self.assertNotIn("method: 'POST'", source)
        workspace = function_source("loadAiWorkspace", "loadMitigationAiSummary")
        self.assertIn("if (activeView !== 'ai') return", workspace)
        for forbidden in ("/api/bgp/", "/api/anomalies/", "method: 'POST'", "FlowSpec", "FIFO"):
            self.assertNotIn(forbidden, workspace)

    def test_navigation_does_not_create_ai_polling_timers(self):
        start = HTML.index("function showView(")
        end = HTML.index("document.querySelectorAll('.side-nav button[data-nav-view]')", start)
        source = HTML[start:end]
        ai_branch = source[source.index("view === 'ai'") : source.index("view === 'system'")]
        self.assertNotIn("setTimeout", ai_branch)
        self.assertNotIn("setInterval", ai_branch)
        scheduler = function_source("scheduleAiModelPullStatus", "pollAiModelPullStatus")
        self.assertIn("clearTimeout(aiModelPullPollTimer)", scheduler)
        self.assertIn("if (activeView !== 'ai'", scheduler)
        self.assertEqual(1, HTML.count("getElementById('refreshAiButton').addEventListener"))

    def test_opening_ai_and_playground_have_no_mitigation_side_effects(self):
        playground = function_source("runAiPlayground", "cancelAiPlayground")
        self.assertIn("/api/ai/playground", playground)
        for forbidden in ("/api/bgp/", "/api/anomalies/", "FlowSpec", "exabgp", "FIFO", "runBgp", "mitigation"):
            self.assertNotIn(forbidden, playground)

    def test_credentials_are_redacted_from_request_error_preview(self):
        source = function_source("requestBodyPreview", "apiDetailMessage")
        for key in ("api[_-]?key", "authorization", "credential", "secret", "token"):
            self.assertIn(key, source)
        self.assertIn("[REDACTED]", source)

    def test_operator_mutations_are_hidden_and_safety_notice_is_visible(self):
        self.assertIn("document.querySelectorAll('.ai-admin-control')", HTML)
        self.assertIn("A IA fornece análise e recomendação. A execução é controlada pelas políticas determinísticas do GMJ-FLOW.", HTML)
        self.assertIn("Não altera anomalias, não envia FlowSpec, não escreve em FIFO e não executa mitigação.", HTML)


if __name__ == "__main__":
    unittest.main()
