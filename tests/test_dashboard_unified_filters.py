from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
PREFIX_CONTROLS = (ROOT / "frontend" / "dashboard-prefix-controls.js").read_text(encoding="utf-8")
BACKEND = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")

FILTER_KINDS = ("sensors", "interfaces", "protocols", "services")
FILTER_TABS = ("network", "collection", "traffic", "advanced")


def block(start_marker: str, end_marker: str) -> str:
    start = FRONTEND.index(start_marker)
    end = FRONTEND.index(end_marker, start)
    return FRONTEND[start:end]


def dashboard_controls_block() -> str:
    return block('<div class="dashboard-controls">', '<section class="dashboard-alert-chrome"')


def filters_panel_block() -> str:
    return block('<section id="dashboardPrefixControls"', '<section id="configurableDashboardGrid"')


def js_block(start_marker: str, end_marker: str) -> str:
    start = FRONTEND.index(start_marker)
    end = FRONTEND.index(end_marker, start)
    return FRONTEND[start:end]


class HeaderIsCleanTest(unittest.TestCase):
    """Filtros de conteudo sairam do topo do dashboard."""

    def test_sensor_left_the_header(self) -> None:
        self.assertNotIn('id="sensor"', FRONTEND)
        self.assertNotIn('id="sensor"', dashboard_controls_block())

    def test_interface_left_the_header(self) -> None:
        self.assertNotIn('id="interface"', FRONTEND)
        self.assertNotIn('id="interface"', dashboard_controls_block())

    def test_client_group_left_the_header(self) -> None:
        self.assertNotIn('id="dashboardZone"', dashboard_controls_block())
        self.assertIn('id="dashboardZone"', filters_panel_block())

    def test_zone_direction_left_the_header(self) -> None:
        self.assertNotIn('id="dashboardZoneDirection"', dashboard_controls_block())
        self.assertIn('id="dashboardZoneDirection"', filters_panel_block())

    def test_series_mode_left_the_header(self) -> None:
        self.assertNotIn('id="dashboardSeriesMode"', dashboard_controls_block())
        self.assertIn('id="dashboardSeriesMode"', filters_panel_block())

    def test_header_keeps_operational_controls(self) -> None:
        controls = dashboard_controls_block()
        for marker in (
            'id="dashboardSelector"',
            'id="newDashboardButton"',
            'id="dashboardManagerButton"',
            'id="rangeMinutes"',
            'id="dashboardSeriesLimit"',
            'id="dashboardRefreshInterval"',
            'id="refresh"',
            'id="editDashboardButton"',
            'id="resetDashboardButton"',
        ):
            self.assertIn(marker, controls)


class UnifiedFiltersPanelTest(unittest.TestCase):
    """Painel unico FILTROS DO DASHBOARD com grupos conceituais."""

    def test_panel_is_renamed(self) -> None:
        panel = filters_panel_block()
        self.assertIn("<div class=\"panel-title\">Filtros do Dashboard</div>", panel)
        self.assertNotIn("Filtro de IPs / Prefixos", panel)

    def test_groups_are_declared(self) -> None:
        panel = filters_panel_block()
        for tab in FILTER_TABS:
            self.assertIn(f'data-filter-tab="{tab}"', panel)
            self.assertIn(f'data-filter-group="{tab}"', panel)

    def test_network_fields_are_preserved(self) -> None:
        panel = filters_panel_block()
        for element_id in (
            "dashboardPrefixFilterType",
            "dashboardPrefixFamily",
            "dashboardPrefixSaved",
            "dashboardPrefixSubnet",
            "dashboardPrefixCidr",
            "dashboardPrefixStart",
            "dashboardPrefixEnd",
            "dashboardPrefixMatchSide",
            "dashboardPrefixIpv4Length",
            "dashboardPrefixIpv6Length",
        ):
            self.assertIn(f'id="{element_id}"', panel)

    def test_custom_ip_field_exists(self) -> None:
        self.assertIn('id="dashboardFilterIp"', filters_panel_block())

    def test_traffic_group_fields_exist(self) -> None:
        panel = filters_panel_block()
        for element_id in (
            "dashboardFilterDirection",
            "dashboardFilterProtocolList",
            "dashboardFilterServiceList",
            "dashboardFilterSrcPort",
            "dashboardFilterDstPort",
        ):
            self.assertIn(f'id="{element_id}"', panel)

    def test_actions_are_preserved(self) -> None:
        panel = filters_panel_block()
        for element_id in (
            "applyDashboardPrefixFilter",
            "saveDashboardPrefixFilter",
            "clearDashboardPrefixFilter",
            "collapseDashboardPrefixFilter",
        ):
            self.assertIn(f'id="{element_id}"', panel)


class MultiselectTest(unittest.TestCase):
    """Multiselects de sensores, interfaces, protocolos e servicos."""

    def test_multiselect_containers_exist(self) -> None:
        panel = filters_panel_block()
        for element_id in (
            "dashboardFilterSensorList",
            "dashboardFilterInterfaceList",
            "dashboardFilterProtocolList",
            "dashboardFilterServiceList",
        ):
            self.assertIn(f'id="{element_id}"', panel)

    def test_state_normalizes_multi_values(self) -> None:
        block_text = js_block("function normalizeDashboardFilterValues(", "function dashboardFilterValues(")
        self.assertIn("Array.isArray(values) ? values : []", block_text)
        self.assertIn("if (kind === 'sensors' || kind === 'interfaces')", block_text)

    def test_toggle_updates_the_shared_state(self) -> None:
        block_text = js_block("function toggleDashboardFilterValue(", "function dashboardFilterChipEntries(")
        self.assertIn("setDashboardFilterValues(kind, next);", block_text)

    def test_protocol_options_include_required_protocols(self) -> None:
        block_text = js_block("const DASHBOARD_FILTER_PROTOCOL_OPTIONS", "const DASHBOARD_FILTER_SERVICE_OPTIONS")
        for token in ("['tcp', 'TCP']", "['udp', 'UDP']", "['icmp', 'ICMP']", "['gre', 'GRE']", "['esp', 'ESP']", "['other', 'Outros']"):
            self.assertIn(token, block_text)

    def test_service_options_use_canonical_codecs(self) -> None:
        block_text = js_block("const DASHBOARD_FILTER_SERVICE_OPTIONS", "const DASHBOARD_FILTER_MULTISELECT_KINDS")
        for token in ("'HTTPS'", "'HTTP'", "'DNS'", "'QUIC'", "'NTP'", "'SIP'"):
            self.assertIn(token, block_text)

    def test_interface_options_follow_selected_sensors(self) -> None:
        block_text = js_block("async function loadDashboardInterfaces(", "async function loadDashboardSensors(")
        self.assertIn("const sensorIds = selectedDashboardSensors();", block_text)
        self.assertIn("/api/sensors/${current}/interfaces", block_text)
        self.assertIn("dashboard_sensor_id: sensorId", block_text)

    def test_clearing_sensors_drops_orphan_interfaces(self) -> None:
        block_text = js_block("function setDashboardFilterValues(", "function toggleDashboardFilterValue(")
        self.assertIn("dashboardFilterState.interfaces = dashboardFilterState.interfaces.filter", block_text)
        self.assertIn("loadDashboardInterfaces()", block_text)


class QueryWiringTest(unittest.TestCase):
    """Filtros chegam ao backend pelo estado unificado, sem N+1."""

    def test_dashboard_params_include_multi_scope(self) -> None:
        block_text = js_block("function dashboardParams(", "function dashboardSeriesParams(")
        self.assertIn("query.set('sensor_ids', sensors.join(','));", block_text)
        self.assertIn("query.set('interface_ids', interfaces.join(','));", block_text)
        self.assertIn("appendDashboardFilterQuery(query);", block_text)

    def test_filter_query_carries_traffic_filters(self) -> None:
        block_text = js_block("function appendDashboardFilterQuery(", "function appendDashboardPrefixQuery(")
        for token in (
            "query.set('protocols', values.protocols.join(','));",
            "query.set('services', values.services.join(','));",
            "query.set('ip', values.ip);",
            "query.set('src_port', values.srcPort);",
            "query.set('dst_port', values.dstPort);",
        ):
            self.assertIn(token, block_text)

    def test_prefix_filter_is_shared_with_the_overview(self) -> None:
        block_text = js_block("function appendDashboardPrefixQuery(", "function dashboardFiltersToGlobalFilters(")
        for token in (
            "query.set('prefix_enabled', String(enabled));",
            "query.set('prefix_cidr', filter.cidr);",
            "query.set('prefix_match_side', filter.match_side || 'either');",
        ):
            self.assertIn(token, block_text)

    def test_series_params_respect_direction(self) -> None:
        block_text = js_block("function dashboardSeriesParams(", "function dashboardGeoParams(")
        self.assertIn("query.set('direction', dashboardFilterQueryValues().direction || 'both');", block_text)

    def test_widget_context_receives_unified_filters(self) -> None:
        block_text = js_block("function configurableDashboardContext()", "function configurableWidgetQueryContext(")
        for token in ("sensor_ids: selectedDashboardSensors(),", "interface_ids: selectedDashboardInterfaces(),", "protocols: dashboardFilterValues('protocols'),", "services: dashboardFilterValues('services'),"):
            self.assertIn(token, block_text)

    def test_frontend_sends_no_new_endpoint(self) -> None:
        self.assertNotIn("/api/dashboard/filters", FRONTEND)
        for endpoint in ("/api/tops/src-ip", "/api/dashboard/series", "/api/dashboard/directional-analytics"):
            self.assertIn(endpoint, FRONTEND)

    def test_backend_accepts_multi_scope_params(self) -> None:
        for token in (
            "sensor_ids: str | None = None,",
            "interface_ids: str | None = None,",
            "protocols: str | None = None,",
            "services: str | None = None,",
        ):
            self.assertIn(token, BACKEND)
        self.assertIn('filters.append("toString(exporter_ip) IN {sensor_exporter_ips:Array(String)}")', BACKEND)
        self.assertIn('"proto IN {protocol_list:Array(UInt8)}"', BACKEND)
        self.assertIn("DASHBOARD_SERVICE_FILTERS", BACKEND)


class ChipsAndTemporaryStateTest(unittest.TestCase):
    """Chips resumem apenas filtros ativos e o estado temporario e preservado."""

    def test_chips_only_list_active_filters(self) -> None:
        block_text = js_block("function dashboardFilterChipEntries()", "function cleanFilterText(")
        self.assertIn("if (directionValue !== 'both')", block_text)
        self.assertIn("const ipValue = cleanFilterText", block_text)
        self.assertNotIn("Todos os sensores", block_text)

    def test_chips_hide_when_empty(self) -> None:
        block_text = js_block("function renderDashboardFilterChips()", "function removeDashboardFilterChip(")
        self.assertIn("container.hidden = true;", block_text)
        self.assertIn("data-filter-chip", block_text)

    def test_chips_are_collapsed_state_friendly(self) -> None:
        panel = filters_panel_block()
        self.assertIn('id="dashboardFilterChips"', panel)
        self.assertIn("dashboard-filter-chips", panel)

    def test_temporary_state_is_persisted(self) -> None:
        self.assertIn("DASHBOARD_FILTER_TEMP_KEY", FRONTEND)
        self.assertIn("sessionStorage.setItem(DASHBOARD_FILTER_TEMP_KEY", FRONTEND)

    def test_temporary_state_restore_keeps_inputs(self) -> None:
        block_text = js_block("function restoreDashboardFilterTemporaryState()", "function activateDashboardFilterTab(")
        for token in ("saved.sensors", "saved.interfaces", "saved.protocols", "saved.services", "dashboardFilterDirection", "dashboardFilterIp"):
            self.assertIn(token, block_text)

    def test_panel_collapse_does_not_query_backend(self) -> None:
        self.assertNotIn("fetch", PREFIX_CONTROLS)
        self.assertNotIn("apiRequest", PREFIX_CONTROLS)
        self.assertIn("setCollapsed", PREFIX_CONTROLS)

    def test_panel_interactions_do_not_call_api(self) -> None:
        for start, end in (
            ("function initDashboardFiltersPanel()", "function selectedDashboardSensors()"),
            ("function renderDashboardFilterPanel()", "function dashboardFilterQueryValues()"),
            ("function renderDashboardFilterChips()", "function removeDashboardFilterChip("),
            ("function activateDashboardFilterTab(", "function initDashboardFiltersPanel()"),
        ):
            block_text = js_block(start, end)
            self.assertNotIn("apiRequest(", block_text, start)
            self.assertNotIn("fetchJSON(", block_text, start)

    def test_apply_updates_dashboard_and_refreshes_once(self) -> None:
        block_text = js_block("async function applyConfigurablePrefixFilter(", "async function clearConfigurablePrefixFilter(")
        self.assertIn("persistDashboardFilterTemporaryState();", block_text)
        self.assertEqual(block_text.count("await refreshConfigurableDashboard();"), 1)


class PersistenceAndCompatibilityTest(unittest.TestCase):
    """Salvar no dashboard e compatibilidade com dashboards antigos."""

    def test_save_persists_global_filters(self) -> None:
        block_text = js_block("async function applyConfigurablePrefixFilter(", "async function clearConfigurablePrefixFilter(")
        self.assertIn("global_filters: dashboardFiltersToGlobalFilters()", block_text)
        self.assertIn("prefix_filter: { ...filter, temporary: false },", block_text)

    def test_global_filters_use_supported_fields(self) -> None:
        block_text = js_block("function dashboardFiltersToGlobalFilters()", "function applyDashboardFilterStateFromGlobalFilters(")
        for token in ("field: 'sensor'", "field: 'interface'", "field: 'protocol'", "operator: 'in'"):
            self.assertIn(token, block_text)

    def test_legacy_dashboards_restore_filters(self) -> None:
        self.assertIn("applyDashboardFilterStateFromGlobalFilters(dashboard.global_filters || []);", FRONTEND)
        self.assertIn("configurableDashboard?.prefix_filter", FRONTEND)

    def test_clear_resets_every_filter(self) -> None:
        block_text = js_block("async function clearConfigurablePrefixFilter()", "function configurableDashboardContext()")
        self.assertIn("dashboardFilterState = emptyDashboardFilterState();", block_text)
        self.assertIn("sessionStorage.removeItem(DASHBOARD_FILTER_TEMP_KEY)", block_text)
        self.assertIn("renderDashboardFilterPanel();", block_text)

    def test_backend_scope_resolution_is_shared(self) -> None:
        self.assertIn("def resolve_scope_ids(", BACKEND)
        self.assertIn("def raw_flow_where_multi(", BACKEND)
        self.assertIn("def dashboard_prefix_filter_params(", BACKEND)


if __name__ == "__main__":
    unittest.main()
