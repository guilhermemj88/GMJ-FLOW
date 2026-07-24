import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
BACKEND = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")


def function_source(name, next_name=None):
    start = HTML.index(f"function {name}(")
    if next_name:
        end = HTML.index(f"function {next_name}(", start)
    else:
        match = re.search(r"\n    (?:async )?function \w+\(", HTML[start + 1 :])
        end = start + 1 + match.start() if match else len(HTML)
    return HTML[start:end]


class GlobalMapQuickPeriodTest(unittest.TestCase):
    def test_required_quick_periods_and_custom_option_exist(self):
        select_start = HTML.index('id="mapRangeMinutes"')
        select_end = HTML.index("</select>", select_start)
        select = HTML[select_start:select_end]
        for value, label in (
            ("60", "1 hora"),
            ("360", "6 horas"),
            ("1440", "24 horas"),
            ("10080", "7 dias"),
            ("43200", "30 dias"),
            ("custom", "Customizado..."),
        ):
            self.assertIn(f'<option value="{value}"', select)
            self.assertIn(label, select)

    def test_map_custom_range_has_separate_date_and_time_inputs(self):
        for element_id, input_type in (
            ("customStartDate", "date"),
            ("customStartClock", "time"),
            ("customEndDate", "date"),
            ("customEndClock", "time"),
        ):
            self.assertIn(f'id="{element_id}" type="{input_type}"', HTML)

    def test_map_range_is_registered_with_existing_range_state(self):
        self.assertIn("map: { start: '', end: '', previous: '30' }", HTML)
        self.assertIn("if (target === 'map') return 'mapRangeMinutes'", function_source("rangeSelectId", "splitLocalDateTime"))


class GlobalMapCustomPeriodValidationTest(unittest.TestCase):
    def test_start_must_precede_end(self):
        source = function_source("validateCustomRange", "browserTimeZoneLabel")
        self.assertIn("if (startDate >= endDate)", source)
        self.assertIn("O início precisa ser menor que o fim.", source)

    def test_future_start_and_end_are_rejected(self):
        source = function_source("validateCustomRange", "browserTimeZoneLabel")
        self.assertIn("startDate.getTime() > now.getTime() + futureToleranceMs", source)
        self.assertIn("endDate.getTime() > now.getTime() + futureToleranceMs", source)
        self.assertIn("O início não pode estar no futuro.", source)
        self.assertIn("O fim não pode estar no futuro.", source)

    def test_maximum_range_is_configurable_and_not_silently_truncated(self):
        self.assertIn('<meta name="gmj-map-max-range-days" content="180">', HTML)
        source = function_source("validateCustomRange", "browserTimeZoneLabel")
        self.assertIn("MAP_MAX_CUSTOM_RANGE_DAYS * 86400000", source)
        self.assertIn("O intervalo máximo configurado para o mapa", source)
        self.assertNotIn("Math.min(durationMs", source)
        geo_start = BACKEND.index('@app.get("/api/geo/flows")')
        geo_end = BACKEND.index("\ndef top_dimension(", geo_start)
        geo_source = BACKEND[geo_start:geo_end]
        self.assertNotIn("range_seconds(start_dt, end_dt) > 360 * 60", geo_source)

    def test_invalid_range_stops_before_request(self):
        source = function_source("loadGlobalMap", "dashboardLayout")
        validation_position = source.index("validateCustomRange('map'")
        request_position = source.index("apiRequest(")
        self.assertLess(validation_position, request_position)
        self.assertIn("Período inválido:", source)
        self.assertIn("return;", source[validation_position:request_position])


class GlobalMapCustomPeriodQueryTest(unittest.TestCase):
    def test_custom_range_sends_explicit_utc_timestamps(self):
        append_source = function_source("appendRangeParams", "dashboardParams")
        self.assertIn("query.set('start_time', dateTimeLocalToApi(custom.start))", append_source)
        self.assertIn("query.set('end_time', dateTimeLocalToApi(custom.end))", append_source)
        map_source = function_source("mapParams", "apiUrl")
        self.assertIn("appendRangeParams(query, 'mapRangeMinutes', 'map')", map_source)

    def test_browser_timezone_is_respected_and_displayed(self):
        converter = function_source("dateTimeLocalToApi", "appendRangeParams")
        self.assertIn("new Date(value).toISOString()", converter)
        timezone = function_source("browserTimeZoneLabel", "formatMapPeriodDate")
        self.assertIn("Intl.DateTimeFormat().resolvedOptions().timeZone", timezone)
        display = function_source("updateMapAppliedPeriod", "isLongMapRange")
        self.assertIn("browserTimeZoneLabel()", display)

    def test_existing_filters_remain_in_map_query(self):
        source = function_source("mapParams", "apiUrl")
        for fragment in (
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
            self.assertIn(fragment, source)

    def test_map_ranking_and_tables_share_the_same_payload(self):
        source = function_source("renderGlobalMap", "abortMapRequest")
        self.assertIn("renderGeoFlowMap(payload)", source)
        self.assertIn("renderGlobalMapTables(edges, metric)", source)
        component = function_source("renderGeoFlowMap", "mapRouteRow")
        self.assertIn("globalGeoFlowMap.setData(payload", component)

    def test_editing_custom_fields_does_not_issue_requests(self):
        for element_id in ("customStartDate", "customStartClock", "customEndDate", "customEndClock"):
            self.assertNotIn(f"getElementById('{element_id}').addEventListener", HTML)
        marker = "getElementById('mapRangeMinutes').addEventListener"
        self.assertEqual(1, HTML.count(marker))
        self.assertIn("handleRangeSelectChange('map')", HTML)

    def test_long_queries_have_explicit_loading_feedback(self):
        source = function_source("loadGlobalMap", "dashboardLayout")
        self.assertIn("isLongMapRange()", source)
        self.assertIn("Consultando um período extenso", source)
        self.assertIn("globalGeoFlowMap.setLoading(loadingMessage)", source)

    def test_effective_backend_period_is_shown_after_success(self):
        source = function_source("loadGlobalMap", "dashboardLayout")
        render_position = source.index("renderGlobalMap(payload)")
        period_position = source.index("updateMapAppliedPeriod(payload)")
        self.assertLess(render_position, period_position)
        self.assertIn('id="mapAppliedPeriod"', HTML)


if __name__ == "__main__":
    unittest.main()
