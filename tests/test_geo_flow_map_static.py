import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
COMPONENT = HTML.split("/* GeoFlowMap component:start */", 1)[1].split("/* GeoFlowMap component:end */", 1)[0]
STYLES = HTML.split("/* GeoFlowMap styles:start */", 1)[1].split("/* GeoFlowMap styles:end */", 1)[0]
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")


class GeoFlowMapComponentTest(unittest.TestCase):
    def test_component_has_reusable_public_contract(self):
        self.assertIn("class GeoFlowMap", COMPONENT)
        for method in (
            "static normalizePayload(payload)",
            "static hasCoordinates(edge)",
            "static metricValue(edge, metric, mode)",
            "setMode(mode, options = {})",
            "setGroupBy(groupBy, options = {})",
            "setData(payload, options = {})",
            "setLoading(message =",
            "setError(message =",
            "fit()",
            "resize()",
            "destroy()",
        ):
            self.assertIn(method, COMPONENT)
        self.assertIn("root.GeoFlowMap = exported.GeoFlowMap", COMPONENT)

    def test_modes_map_to_existing_api_filters(self):
        for source in (
            "flows: Object.freeze({ metric: 'flows', direction: 'both' })",
            "download: Object.freeze({ metric: 'bits_s', direction: 'download' })",
            "upload: Object.freeze({ metric: 'bits_s', direction: 'upload' })",
            "total: Object.freeze({ metric: 'bits_s', direction: 'both' })",
        ):
            self.assertIn(source, COMPONENT)
        for label in ("Fluxos", "Download", "Upload", "Total"):
            self.assertIn(label, COMPONENT)

    def test_rendering_supports_dark_routes_markers_labels_ranking_and_navigation(self):
        self.assertIn("basemaps.cartocdn.com/dark_all", COMPONENT)
        self.assertIn("curvedRoutePoints(edge)", COMPONENT)
        self.assertIn("globalThis.L.polyline(points", COMPONENT)
        self.assertIn("globalThis.L.circleMarker", COMPONENT)
        self.assertIn("geo-flow-rate-marker", COMPONENT)
        self.assertIn("data-geo-ranking", COMPONENT)
        self.assertIn("zoomControl: true", COMPONENT)
        self.assertIn("worldCopyJump: true", COMPONENT)
        self.assertIn("this.map.fitBounds", COMPONENT)
        self.assertIn(".geo-flow-map .geo-flow-route.is-animated", STYLES)
        self.assertIn(".geo-flow-map__ranking", STYLES)
        self.assertIn("--geo-bg: var(--map-background, #07111f)", STYLES)

    def test_normalizer_keeps_current_geo_payload_fields(self):
        for field in (
            "src_lat",
            "src_lon",
            "dst_lat",
            "dst_lon",
            "bits_s",
            "packets_s",
            "flows",
            "top_protocol",
            "top_asn_src",
            "top_asn_dst",
        ):
            self.assertIn(field, COMPONENT)
        self.assertIn("Array.isArray(source.edges)", COMPONENT)
        self.assertIn("Array.isArray(source.items)", COMPONENT)

    def test_country_city_and_legacy_grouping_options_are_available(self):
        for option in (
            '<option value="city">Cidade</option>',
            '<option value="country">País</option>',
            '<option value="asn">ASN</option>',
            '<option value="ip">IP/CIDR</option>',
        ):
            self.assertIn(option, COMPONENT)


class GeoFlowMapIntegrationTest(unittest.TestCase):
    def test_component_is_delivered_by_existing_single_file_frontend(self):
        self.assertIn('id="geo-flow-map-styles"', HTML)
        self.assertIn('id="geo-flow-map-component"', HTML)
        self.assertNotIn('/assets/geo-flow-map.css', HTML)
        self.assertNotIn('/assets/geo-flow-map.js', HTML)
        self.assertNotIn("./frontend/assets:/usr/share/nginx/html/assets:ro", COMPOSE)

    def test_dashboard_and_global_page_use_same_component(self):
        self.assertIn('id="dashboardGeoFlowMap"', HTML)
        self.assertIn('id="globalMapChart"', HTML)
        self.assertIn("dashboardGeoFlowMap = new GeoFlowMap", HTML)
        self.assertIn("globalGeoFlowMap = new GeoFlowMap", HTML)
        self.assertEqual(2, HTML.count("new GeoFlowMap"))
        self.assertNotIn("L.map('globalMapChart'", HTML)

    def test_global_filters_remain_in_api_query(self):
        for query_mapping in (
            "query.set('range_minutes'",
            "query.set('direction'",
            "query.set('metric'",
            "query.set('group_by'",
            "query.set('top_n'",
            "query.set('sensor_id'",
            "query.set('interface_id'",
            "query.set('zone_id'",
            "query.set('proto'",
            "query.set('asn_src'",
            "query.set('asn_dst'",
            "query.set('src_cidr'",
            "query.set('dst_cidr'",
            "query.set('severity'",
            "query.set('vector'",
            "query.set('status'",
        ):
            self.assertIn(query_mapping, HTML)

    def test_dashboard_geo_request_is_lazy_and_uses_current_dashboard_filters(self):
        self.assertIn("if (isDashboardWidgetVisible('global-summary'))", HTML)
        self.assertIn("fetchJSON(GEO_FLOW_ENDPOINT, dashboardGeoParams(), requestOptions)", HTML)
        self.assertIn("dashboardParams({ includeSensorId: true, includeInterfaceId: true })", HTML)

    def test_global_integration_preserves_loading_empty_and_error_states(self):
        self.assertIn("globalGeoFlowMap.setLoading(loadingMessage)", HTML)
        self.assertIn("renderGeoFlowMap(payload)", HTML)
        self.assertIn("globalGeoFlowMap.setError('Erro ao carregar dados geográficos. Tente atualizar novamente.')", HTML)
        self.assertIn("Nenhuma rota encontrada apos aplicar os filtros", HTML)


if __name__ == "__main__":
    unittest.main()
