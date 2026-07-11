import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


class FrontendBgpProfilesTest(unittest.TestCase):
    def test_loads_connectors_from_bgp_connectors_endpoint(self):
        self.assertIn("apiRequest('/api/bgp/connectors')", HTML)

    def test_profile_payload_uses_numeric_connector_id(self):
        self.assertIn("connector_id: targetMode === 'fixed_connector' && selectValue('bgpProfileConnector') ? Number(selectValue('bgpProfileConnector')) : null", HTML)
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

    def test_manual_flowspec_dry_run_selection_does_not_send_announce_action(self):
        self.assertIn("const selectedAction = selectValue('bgpDryAction', 'dry_run');", HTML)
        self.assertIn("const action = requestedAction === 'dry_run' ? 'dry_run' : selectedAction;", HTML)
        self.assertIn("Confirmação ANUNCIAR obrigatoria para anunciar agora.", HTML)

    def test_manual_flowspec_blocks_port_without_protocol(self):
        self.assertIn("Protocolo e obrigatorio quando porta e informada.", HTML)
        self.assertIn("if ((srcPort || dstPort) && !protocol)", HTML)

    def test_ai_recommendation_does_not_render_null_candidate_as_one(self):
        self.assertIn("candidateText = Number.isInteger(Number(candidateIndex))", HTML)
        self.assertIn(": 'sem candidato'", HTML)
        self.assertIn("aiCandidateIndex !== null", HTML)

    def test_dns_source_only_candidate_is_not_actionable_in_ui(self):
        self.assertIn("dnsSourceOnly", HTML)
        self.assertIn("dnsWithoutDestination", HTML)
        self.assertIn("FLOWSPEC_BLOCK_SRC_DNS", HTML)
        self.assertIn("policy.decision === 'deny' || dnsWithoutDestination", HTML)

    def test_traffic_learning_modal_and_tooltips_exist(self):
        self.assertIn("Aprender com o tráfego", HTML)
        self.assertIn('id="trafficLearningModal"', HTML)
        self.assertIn("openTrafficLearningModal", HTML)
        self.assertIn("/learn-from-traffic", HTML)
        self.assertIn("installHelpTooltips", HTML)
        self.assertIn("Janela de cálculo em segundos", HTML)
        self.assertIn("Duração interna no GMJ-FLOW", HTML)

    def test_traffic_learning_fill_and_save_actions_are_explicit(self):
        self.assertIn("Preencher regra atual", HTML)
        self.assertIn("Aplicar e salvar regra", HTML)
        self.assertIn("function applyTrafficLearningToRule(draftOnly = false)", HTML)
        self.assertIn("Sugestao aplicada ao formulario. Clique em Salvar regra para persistir.", HTML)
        self.assertIn("highlightTrafficLearnedFields", HTML)
        self.assertIn("closeModal('trafficLearningModal')", HTML)
        self.assertIn("function saveTrafficLearningRule", HTML)
        self.assertIn("const saved = await saveDetectionRule()", HTML)
        self.assertIn("Lista de regras atualizada", HTML)
        self.assertIn("Falha ao salvar regra aprendida", HTML)
        self.assertIn("trafficLearnSaveButton", HTML)
        self.assertIn("setValue('detectionRuleMitigationMode', 'manual_review')", HTML)
        self.assertIn("setBoolSelect('detectionRuleMitigationEnabled', false)", HTML)

    def test_detection_rule_profile_selects_load_response_profiles_endpoint(self):
        self.assertIn("apiRequest('/api/bgp/response-profiles')", HTML)
        self.assertIn("function bgpResponseProfilesFromPayload(payload)", HTML)
        self.assertIn("if (Array.isArray(payload)) return payload", HTML)
        self.assertIn("if (Array.isArray(payload?.items)) return payload.items", HTML)
        self.assertIn("if (Array.isArray(payload?.profiles)) return payload.profiles", HTML)
        self.assertIn("Falha ao carregar Response Profiles", HTML)

    def test_detection_rule_profile_selects_preserve_existing_rule_ids(self):
        self.assertIn("detectionRuleWarningProfile: rule?.warning_response_profile_id", HTML)
        self.assertIn("detectionRuleCriticalProfile: rule?.critical_response_profile_id", HTML)
        self.assertIn("detectionRuleFallbackProfile: rule?.fallback_response_profile_id", HTML)
        self.assertIn("renderBgpSelects(profileSelections)", HTML)
        self.assertIn("applyDetectionRuleProfileSelections(profileSelections)", HTML)
        self.assertIn("ensureDetectionRuleProfileOptions(profileSelections)", HTML)
        self.assertIn("function bgpProfileEnabled(item = {})", HTML)
        self.assertIn(".filter(item => bgpProfileEnabled(item) || String(item.id) === String(selected))", HTML)
        self.assertIn(".map(item => [item.id, item.name])", HTML)

    def test_detection_rule_profile_save_preserves_selected_ids(self):
        self.assertIn("const warningProfileId = responseProfileMode && selectValue('detectionRuleWarningProfile')", HTML)
        self.assertIn("const criticalProfileId = responseProfileMode && selectValue('detectionRuleCriticalProfile')", HTML)
        self.assertIn("const fallbackProfileId = responseProfileMode && selectValue('detectionRuleFallbackProfile')", HTML)
        self.assertIn("warning_response_profile_id: warningProfileId", HTML)
        self.assertIn("critical_response_profile_id: criticalProfileId", HTML)
        self.assertIn("fallback_response_profile_id: fallbackProfileId", HTML)


if __name__ == "__main__":
    unittest.main()
