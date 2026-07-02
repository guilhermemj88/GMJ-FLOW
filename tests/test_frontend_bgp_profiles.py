import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


class FrontendBgpProfilesTest(unittest.TestCase):
    def test_loads_connectors_from_bgp_connectors_endpoint(self):
        self.assertIn("apiRequest('/api/bgp/connectors')", HTML)

    def test_profile_payload_uses_numeric_connector_id(self):
        self.assertIn("connector_id: selectValue('bgpProfileConnector') ? Number(selectValue('bgpProfileConnector')) : null", HTML)
        self.assertNotIn("connector_id: selectValue('bgpProfileConnector', item.connector_name", HTML)

    def test_edit_profile_selects_connector_id(self):
        self.assertIn("setValue('bgpProfileConnector', item.connector_id || '')", HTML)

    def test_save_success_keeps_profile_selected_and_visible(self):
        self.assertIn("Profile salvo com sucesso", HTML)
        self.assertIn("editBgpProfile(saved.id)", HTML)

    def test_save_error_shows_backend_message_and_payload(self):
        self.assertIn("Erro ao salvar Response Profile", HTML)
        self.assertIn("Payload enviado:", HTML)
        self.assertIn("showBgpProfileSaveError(error, payload)", HTML)

    def test_new_profile_defaults_are_safe_dns_flowspec(self):
        self.assertIn("setValue('bgpProfileTarget', 'dst_ip')", HTML)
        self.assertIn("setValue('bgpProfileProtocol', 'udp')", HTML)
        self.assertIn("setValue('bgpProfileDstPortSelector', 'fixed')", HTML)
        self.assertIn("setValue('bgpProfileDstPortValue', '53')", HTML)
        self.assertIn("setValue('bgpProfileMaxDuration', 3600)", HTML)

    def test_manual_flowspec_uses_manual_endpoint_and_logs_payload(self):
        self.assertIn("/manual-flowspec/dry-run", HTML)
        self.assertIn("console.log('[manual-flowspec] payload', payload)", HTML)

    def test_manual_flowspec_blocks_port_without_protocol(self):
        self.assertIn("Protocolo e obrigatorio quando porta e informada.", HTML)
        self.assertIn("if ((srcPort || dstPort) && !protocol)", HTML)


if __name__ == "__main__":
    unittest.main()
