from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class InterfaceDrawerStaticTest(unittest.TestCase):
    """Guards Fase 4 Investigation (Interface Drawer + Interfaces view, real data only)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")

    def test_interface_key_is_sensor_id_plus_if_index(self) -> None:
        # identidade da interface = sensor_id + if_index (seguro entre sensores)
        self.assertIn('data-interface-sensor="${escapeHtml(item.sensor_id)}"', self.html)
        self.assertIn('data-interface-ifindex="${escapeHtml(item.if_index)}"', self.html)
        self.assertIn("Number(entry.sensor_id) === interfaceDrawerState.sensorId", self.html)
        self.assertIn("Number(entry.if_index) === interfaceDrawerState.ifIndex", self.html)

    def test_top_interfaces_row_opens_drawer(self) -> None:
        self.assertIn(".interfaces-row[data-interface-sensor][data-interface-ifindex]", self.html)
        self.assertIn("openInterfaceDrawer(row.dataset.interfaceSensor, row.dataset.interfaceIfindex, row)", self.html)

    def test_drawer_close_via_button_backdrop_and_escape(self) -> None:
        self.assertIn('id="interfaceDrawerClose"', self.html)
        self.assertIn('id="interfaceDrawerBackdrop"', self.html)
        self.assertIn("close.addEventListener('click', closeInterfaceDrawer)", self.html)
        self.assertIn("backdrop.addEventListener('click', closeInterfaceDrawer)", self.html)
        self.assertIn("event.key === 'Escape' && interfaceDrawerState.open", self.html)

    def test_drawer_loading_and_error_states(self) -> None:
        self.assertIn("Interface não encontrada ou sensor indisponível.", self.html)
        self.assertIn("Falha ao carregar a interface.", self.html)
        self.assertIn("Falha ao carregar tráfego.", self.html)
        self.assertIn("Sem histórico de tráfego para esta interface.", self.html)

    def test_no_n_plus_1_interface_batching(self) -> None:
        # busca por sensor (Promise.all), nunca por interface; cache de 20s
        self.assertIn("Promise.all(sensors.map(", self.html)
        self.assertIn("allInterfacesCacheAt", self.html)
        self.assertIn("20000", self.html)

    def test_utilization_semantics_neutral_warning_critical(self) -> None:
        self.assertIn("function interfaceUtilization(item)", self.html)
        self.assertIn("function utilizationTone(utilization)", self.html)
        self.assertIn("utilization >= 85", self.html)
        self.assertIn("utilization >= 65", self.html)
        self.assertIn("return 'neutral'", self.html)
        self.assertIn("return 'warning'", self.html)
        self.assertIn("return 'critical'", self.html)
        # verde/ok e reservado ao status-dot; utilizacao nunca afirma 'ok'
        self.assertIn(".status-dot.ok {", self.html)

    def test_no_fabricated_error_discard_crc_fields(self) -> None:
        for field in ("if_in_errors", "if_out_errors", "if_in_discards", "if_out_discards", "if_in_crc", "if_admin_status"):
            self.assertNotIn(field, self.html)

    def test_interfaces_view_uses_real_snmp_data(self) -> None:
        self.assertIn('id="view-interfaces"', self.html)
        self.assertIn('id="interfacesViewTable"', self.html)
        self.assertIn('id="interfacesSensor"', self.html)
        self.assertIn('id="refreshInterfacesButton"', self.html)
        self.assertIn("function renderInterfacesViewTable()", self.html)
        self.assertIn("const all = await loadAllInterfaces();", self.html)
        self.assertIn("function loadInterfacesView()", self.html)
        self.assertIn("function renderInterfacesSensorSelect()", self.html)

    def test_drawer_tabs_overview_traffic_only(self) -> None:
        self.assertIn('data-interface-tab="overview"', self.html)
        self.assertIn('data-interface-tab="traffic"', self.html)
        self.assertNotIn('data-interface-tab="errors"', self.html)

    def test_permissions_preserved(self) -> None:
        self.assertIn("interfaces: 'sensors.view'", self.html)
        self.assertIn('id="interfacesNavButton"', self.html)
        self.assertIn('data-nav-view="interfaces" data-required-permission="sensors.view"', self.html)

    def test_drawer_css_uses_theme_tokens(self) -> None:
        # CSS da Fase 4 usa tokens semanticos (tema operator incluido)
        self.assertIn(".interface-drawer {", self.html)
        self.assertIn("background: var(--surface);", self.html)
        self.assertIn("border-left: 1px solid var(--line-strong);", self.html)
        self.assertIn("border-bottom-color: var(--accent);", self.html)


if __name__ == "__main__":
    unittest.main()
