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


class ViewOwnershipParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.all_ids = []
        self.ids_by_view = defaultdict(set)
        self.section_stack = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        element_id = attrs.get("id")
        if tag == "section":
            self.section_stack.append(element_id)
        if element_id:
            self.all_ids.append(element_id)
            owner = next(
                (section_id for section_id in reversed(self.section_stack) if section_id and section_id.startswith("view-")),
                None,
            )
            if owner:
                self.ids_by_view[owner].add(element_id)

    def handle_startendtag(self, tag, attrs):
        element_id = dict(attrs).get("id")
        if element_id:
            self.all_ids.append(element_id)
            owner = next(
                (section_id for section_id in reversed(self.section_stack) if section_id and section_id.startswith("view-")),
                None,
            )
            if owner:
                self.ids_by_view[owner].add(element_id)

    def handle_endtag(self, tag):
        if tag == "section" and self.section_stack:
            self.section_stack.pop()


class FrontendNavigationMapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = ViewOwnershipParser()
        cls.parser.feed(HTML)

    def test_html_ids_are_unique(self):
        duplicates = [element_id for element_id, count in Counter(self.parser.all_ids).items() if count > 1]
        self.assertEqual([], duplicates)

    def test_bgp_connectors_contains_only_connector_workspace(self):
        bgp_ids = self.parser.ids_by_view["view-bgp-connectors"]
        for element_id in (
            "bgpConnectorsStatus",
            "bgpInfrastructurePanel",
            "bgpPeerStatusRows",
            "bgpConnectorEditorPanel",
            "bgpConnectorsTable",
        ):
            self.assertIn(element_id, bgp_ids)
        for element_id in (
            "globalMapPanel",
            "globalMapChart",
            "mapSrcAsn",
            "mapDstAsn",
            "mapSrcCidr",
            "mapDstCidr",
            "mapSeverity",
            "mapVector",
            "mapAnomalyStatus",
        ):
            self.assertNotIn(element_id, bgp_ids)
        self.assertNotIn("organizeBgpPageSections", HTML)
        self.assertNotIn("bgpInfrastructureMount", HTML)

    def test_map_page_owns_filters_metrics_map_and_tables(self):
        map_ids = self.parser.ids_by_view["view-global-map"]
        for element_id in (
            "globalMapPanel",
            "mapSrcAsn",
            "mapDstAsn",
            "mapSrcCidr",
            "mapDstCidr",
            "mapSeverity",
            "mapVector",
            "mapAnomalyStatus",
            "mapTotalBits",
            "mapTotalPackets",
            "mapActiveCountries",
            "mapActiveRoutes",
            "globalMapChart",
            "globalMapRoutesTable",
            "globalMapMissingTable",
        ):
            self.assertIn(element_id, map_ids)
        self.assertIn('id="globalMapNavButton" type="button" data-nav-view="global-map"', HTML)
        self.assertIn("<span>Mapa Global</span>", HTML)

    def test_map_has_loading_empty_and_error_states(self):
        for message in (
            "Carregando dados geográficos...",
            "Nenhuma rota encontrada apos aplicar os filtros",
            "Erro ao carregar dados geográficos. Tente atualizar novamente.",
        ):
            self.assertIn(message, HTML)

    def test_map_routes_use_global_map_as_canonical_and_preserve_aliases(self):
        source = function_source("canonicalNavigationView", "viewFromLocationHash")
        self.assertIn("['map', 'geo', 'traffic-map', 'network-map']", source)
        self.assertIn("return 'global-map'", source)
        self.assertIn("window.history.replaceState(null, '', `#${view}`)", HTML)

    def test_navigation_covers_mitigation_connectors_and_map_without_actions(self):
        start = HTML.index("function showView(")
        end = HTML.index("document.querySelectorAll('.side-nav button[data-nav-view]')", start)
        source = HTML[start:end]
        for view in ("mitigation", "bgp-connectors", "global-map"):
            self.assertIn(f"view === '{view}'", source)
        self.assertIn("loadMitigationView().catch", source)
        self.assertIn("loadBgpConnectorsView().catch", source)
        self.assertIn("loadGlobalMapView().catch", source)
        for forbidden in ("apiRequest(", "method: 'POST'", "runBgpDryRun", "updateBgpAnnouncement"):
            self.assertNotIn(forbidden, source)

    def test_map_is_initialized_and_requested_only_while_active(self):
        init_source = function_source("ensureLeafletMap", "clearLeafletMap")
        load_source = function_source("loadGlobalMap", "dashboardLayout")
        view_source = function_source("loadGlobalMapView", "debounceGlobalMapLoad")
        self.assertIn("if (activeView !== 'global-map') return false", init_source)
        self.assertIn("if (activeView !== 'global-map') return", load_source)
        self.assertIn("if (controller.signal.aborted || activeView !== 'global-map') return", load_source)
        self.assertIn("await loadGlobalMap({ force: true })", view_source)
        self.assertNotIn("ensureLeafletMap", view_source)
        self.assertEqual(1, HTML.count("'/api/geo/flows'"))
        self.assertEqual(1, HTML.count("'/api/geo/anomalies'"))

    def test_leaving_map_cancels_requests_and_timers(self):
        abort_source = function_source("abortMapRequest", "deactivateGlobalMapView")
        deactivate_source = function_source("deactivateGlobalMapView", "loadGlobalMapView")
        self.assertIn("mapAbortController.abort()", abort_source)
        self.assertIn("clearTimeout(mapDebounceTimer)", abort_source)
        self.assertIn("clearTimeout(mapResizeTimer)", abort_source)
        self.assertIn("mapViewActivation += 1", deactivate_source)
        self.assertIn("abortMapRequest()", deactivate_source)

    def test_connector_checks_do_not_load_map_or_send_flowspec(self):
        all_checks = function_source("checkBgpConnectorStatusesNow", "loadBgpConnectorsView")
        self.assertIn("/check-router`, { method: 'POST' }", all_checks)
        for forbidden in ("/api/geo/", "/announcements", "runBgpDryRun", "updateBgpAnnouncement"):
            self.assertNotIn(forbidden, all_checks)

    def test_opening_map_does_not_execute_mitigation(self):
        source = function_source("loadGlobalMapView", "debounceGlobalMapLoad")
        for forbidden in ("/api/bgp/", "mitigation", "FlowSpec", "method: 'POST'"):
            self.assertNotIn(forbidden, source)

    def test_map_listeners_are_registered_once(self):
        for element_id in ("applyMapFiltersButton", "clearMapFiltersButton", "fitMapButton", "refreshMapButton"):
            marker = f"getElementById('{element_id}').addEventListener"
            self.assertEqual(1, HTML.count(marker), marker)


if __name__ == "__main__":
    unittest.main()
