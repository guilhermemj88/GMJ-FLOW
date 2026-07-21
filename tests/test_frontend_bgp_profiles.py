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

    def test_ops_summary_polling_updates_anomaly_badge_every_five_seconds(self):
        self.assertIn("function refreshOpsSummary()", HTML)
        self.assertIn("apiRequest('/api/ops/summary')", HTML)
        self.assertIn("renderAnomalyBadge({", HTML)
        self.assertIn("active_count: summary.active_anomalies", HTML)
        self.assertIn("setInterval(() =>", HTML)
        self.assertIn("}, 5000)", HTML)
        self.assertIn("if (opsSummaryRefreshTimer) return;", HTML)
        self.assertIn("clearInterval(opsSummaryRefreshTimer)", HTML)

    def test_mitigation_nav_badge_and_summary_cards_use_advertised_announcements(self):
        self.assertIn('id="bgpNavBadge"', HTML)
        self.assertIn("function renderMitigationBadge(summary)", HTML)
        self.assertIn("summary.active_bgp_announcements", HTML)
        self.assertIn('id="bgpSummaryActive"', HTML)
        self.assertIn('id="bgpSummaryPending"', HTML)
        self.assertIn('id="bgpSummaryFailed"', HTML)
        self.assertIn('id="bgpSummaryExpiredToday"', HTML)
        self.assertIn("function bgpAnnouncementIsOperationalActive(item)", HTML)
        active_start = HTML.index("function bgpAnnouncementIsOperationalActive(item)")
        active_end = HTML.index("function bgpAnnouncementIsInFlight(item)", active_start)
        active_source = HTML[active_start:active_end]
        self.assertIn("return String(item?.status || '').toLowerCase() === 'advertised'", active_source)
        self.assertNotIn("'active'", active_source)
        self.assertNotIn("'announced'", active_source)
        self.assertIn("bgpAnnouncements.filter(item => bgpAnnouncementIsOperationalActive(item))", HTML)

    def test_bgp_actions_refresh_summary_immediately(self):
        self.assertIn("await refreshOpsSummary();", HTML)
        self.assertIn("async function updateBgpAnnouncement(id, action)", HTML)
        self.assertIn("async function applyBgpMitigationCandidate(index, mode)", HTML)
        self.assertIn("async function applyBgpMitigationDnsTargets(index, mode, selectedOnly = false)", HTML)

    def test_dry_run_connector_is_visually_clear(self):
        self.assertIn("(item.backend || item.backend_type) === 'dry_run' ? 'off' : 'ok'", HTML)
        self.assertIn("item.mode === 'dry_run' ? 'off' : 'ok'", HTML)
        self.assertIn("const statusInfo = bgpAnnouncementStatusInfo(item);", HTML)
        self.assertIn("statusInfo.code === 'advertised' ? 'FlowSpec anunciado com confirmação operacional local' : statusInfo.note", HTML)

    def test_bgp_workspace_distinguishes_delivery_and_operational_states(self):
        for technical, label in (
            ("pending_approval", "Aguardando aprovação"),
            ("queued", "Na fila de envio"),
            ("sent", "Enviado ao ExaBGP"),
            ("advertised", "FlowSpec ativo"),
            ("peer_down", "Peer BGP indisponível"),
            ("failed", "Falhou"),
            ("dry_run", "Simulação"),
            ("withdrawn", "Retirado"),
            ("expired", "Expirado"),
            ("deduplicated", "Resposta já existente"),
        ):
            self.assertIn(f"{technical}: {{", HTML)
            self.assertIn(f"label: '{label}'", HTML)

    def test_sent_and_peer_down_are_not_presented_as_advertised(self):
        self.assertIn("label: 'Enviado ao ExaBGP'", HTML)
        self.assertIn("Comando entregue ao ExaBGP; peer e rota ainda não confirmados.", HTML)
        self.assertIn("label: 'Peer BGP indisponível'", HTML)
        self.assertIn("Não enviado porque o peer estava indisponível.", HTML)
        self.assertIn("['queued', 'sent', 'peer_down', 'active', 'announced', 'failed_withdraw']", HTML)
        self.assertIn('id="bgpInFlightAnnouncementsTable"', HTML)

    def test_elapsed_ttl_and_durable_intents_are_not_presented_as_completed_withdrawals(self):
        status_start = HTML.index("function bgpAnnouncementStatusCode")
        status_end = HTML.index("function bgpAnnouncementStatusInfo", status_start)
        self.assertNotIn("return 'expired'", HTML[status_start:status_end])
        self.assertIn("label: 'FlowSpec ativo · retirada atrasada'", HTML)
        self.assertIn("label: 'Entrega em andamento'", HTML)
        self.assertIn("label: 'Retirada pendente'", HTML)
        self.assertIn("confirmationLevel === 'withdraw_requested'", HTML)
        self.assertIn("confirmationLevel === 'delivery_attempted'", HTML)

    def test_failed_withdraw_remains_actionable_for_retry(self):
        actions_start = HTML.index("function bgpInFlightActions")
        actions_end = HTML.index("function renderBgpAnnouncements", actions_start)
        actions_source = HTML[actions_start:actions_end]
        self.assertIn("'failed_withdraw'", actions_source)
        self.assertIn("details.send_claim_token", actions_source)
        self.assertIn("'withdraw_requested'", actions_source)
        self.assertIn("bgp-ann-withdraw", actions_source)

    def test_legacy_active_and_announced_are_sent_without_confirmation(self):
        for legacy_status in ("active", "announced"):
            self.assertIn(f"{legacy_status}: {{", HTML)
        self.assertGreaterEqual(HTML.count("label: 'Enviado (legado, sem confirmação)'"), 2)
        self.assertIn("Registro legado; peer e instalação da rota não confirmados.", HTML)
        self.assertIn("['Envio registrado (legado)', legacyAnnouncementAt]", HTML)
        self.assertIn("bgpAnnouncementIsInFlight(item)", HTML)

    def test_bgp_details_explain_confirmation_and_internal_ttl(self):
        self.assertIn("function bgpAnnouncementStatusBadge(item)", HTML)
        self.assertIn("Nível de confirmação: ${escapeHtml(info.confirmation)}", HTML)
        self.assertIn("O TTL é controlado internamente pelo GMJ-FLOW e, isoladamente, não confirma anúncio ao peer.", HTML)
        self.assertNotIn("TTL interno do GMJ-FLOW. Não é enviado ao BGP.", HTML)
        self.assertNotIn("TTL e interno do GMJ-FLOW. Nao e enviado ao BGP.", HTML)

    def test_in_flight_rows_preserve_reject_and_withdraw_actions(self):
        handler_start = HTML.index("document.getElementById('bgpInFlightAnnouncementsTable').addEventListener")
        handler_end = HTML.index("document.getElementById('bgpPendingSuggestionsTable').addEventListener", handler_start)
        handler_source = HTML[handler_start:handler_end]
        self.assertIn(".bgp-ann-reject", handler_source)
        self.assertIn("updateBgpAnnouncement(reject.dataset.id, 'reject')", handler_source)
        self.assertIn(".bgp-ann-withdraw", handler_source)
        self.assertIn("updateBgpAnnouncement(withdraw.dataset.id, 'withdraw')", handler_source)

    def test_anomaly_active_and_history_table_has_response_before_actions(self):
        table_start = HTML.index('<table class="table table-sm table-hover align-middle mb-0 anomaly-table">')
        table_end = HTML.index('</table>', table_start)
        table_source = HTML[table_start:table_end]
        self.assertEqual(table_source.count('<col class="anomaly-col-'), 10)
        self.assertLess(table_source.index('<col class="anomaly-col-response">'), table_source.index('<col class="anomaly-col-actions">'))
        self.assertLess(table_source.index('<th>Resposta</th>'), table_source.index('<th>Ações</th>'))
        self.assertIn('id="anomalyTabActive"', HTML)
        self.assertIn('id="anomalyTabHistory"', HTML)
        self.assertIn('<tr><td colspan="10" class="text-muted">Sem anomalias</td></tr>', HTML)

    def test_anomaly_response_has_complete_operator_status_map(self):
        map_start = HTML.index("const ANOMALY_RESPONSE_STATUS_PRESENTATION")
        map_end = HTML.index("const ANOMALY_RESPONSE_REFRESH_FIELDS", map_start)
        map_source = HTML[map_start:map_end]
        for technical, label in (
            ("pending_approval", "Aguardando aprovação"),
            ("queued", "Na fila de envio"),
            ("sent", "Enviado ao ExaBGP"),
            ("advertised", "FlowSpec ativo"),
            ("peer_down", "Peer BGP indisponível"),
            ("dry_run", "Dry-run"),
            ("deduplicated", "Duplicado"),
            ("not_applied", "Não aplicado"),
            ("rejected", "Rejeitado"),
            ("rejected_by_policy", "Bloqueado por política"),
            ("failed", "Falhou"),
            ("withdrawn", "Aplicado e retirado"),
            ("expired", "Expirado"),
            ("applied", "Aplicado sem confirmação"),
        ):
            self.assertIn(f"{technical}: {{", map_source)
            self.assertIn(f"label: '{label}'", map_source)
        self.assertIn("label: 'Sem resposta'", map_source)

    def test_anomaly_response_marks_only_operational_advertised_as_active(self):
        operational_start = HTML.index("function anomalyResponseAnnouncementIsOperational")
        operational_end = HTML.index("function anomalyResponseAnnouncementStatusCode", operational_start)
        operational_source = HTML[operational_start:operational_end]
        self.assertIn("!== 'advertised'", operational_source)
        self.assertIn("announcement.legacy_unconfirmed === true", operational_source)
        self.assertIn("announcement.operationally_active === true", operational_source)
        status_start = HTML.index("function anomalyResponseStatusCode")
        status_end = HTML.index("function anomalyResponseStatusInfo", status_start)
        status_source = HTML[status_start:status_end]
        self.assertIn("if (!primary) return 'applied'", status_source)
        self.assertIn("['active', 'announced', 'applied'].includes(primaryStatus)", status_source)
        self.assertIn("anomalyResponseAnnouncementStatusCode({ ...primary, status: 'advertised' })", status_source)

    def test_anomaly_response_legacy_states_never_claim_active_flowspec(self):
        map_start = HTML.index("const ANOMALY_RESPONSE_STATUS_PRESENTATION")
        map_end = HTML.index("const ANOMALY_RESPONSE_REFRESH_FIELDS", map_start)
        map_source = HTML[map_start:map_end]
        self.assertGreaterEqual(map_source.count("label: 'Enviado (legado, sem confirmação)'"), 2)
        self.assertIn("active: {", map_source)
        self.assertIn("announced: {", map_source)
        self.assertIn("applied: {", map_source)
        self.assertIn("label: 'Aplicado sem confirmação'", map_source)

    def test_anomaly_response_consumes_backend_summary_and_attempt_contract(self):
        for field in (
            "response_status",
            "response_reason",
            "response_updated_at",
            "response_announcement",
            "response_announcements",
        ):
            self.assertIn(field, HTML)
        self.assertIn("function anomalyResponseEventFromPayload", HTML)
        self.assertIn("ANOMALY_RESPONSE_REFRESH_FIELDS.forEach", HTML)

    def test_anomaly_response_detail_omits_empty_fields_and_lists_every_attempt(self):
        self.assertIn("function anomalyResponseHasValue(value)", HTML)
        self.assertIn("if (!anomalyResponseHasValue(displayValue)) return '';", HTML)
        self.assertIn("Todas as tentativas (${attempts.length})", HTML)
        self.assertIn("attempts.map((announcement, index) => anomalyResponseAttemptHtml", HTML)
        for label in (
            "Estado do peer",
            "Origem interna",
            "Destino / prefixo",
            "Última tentativa",
            "Último erro",
            "ID do anúncio",
            "Nível de confirmação",
        ):
            self.assertIn(f"anomalyResponseDetailField('{label}'", HTML)
        self.assertIn('id="anomalyResponseModal"', HTML)
        self.assertIn("const internalOrigin = announcement.origin_ip", HTML)
        self.assertIn("announcement.response_origin", HTML)

    def test_anomaly_response_translates_confirmation_levels_from_backend(self):
        for technical, label in (
            ("registered", "Apenas registrado"),
            ("approved", "Aprovado"),
            ("delivered_to_exabgp", "Enviado ao ExaBGP"),
            ("peer_established", "Peer estabelecido"),
            ("peer_established_announce_requested", "Anúncio solicitado com peer estabelecido (confirmação local)"),
            ("peer_unavailable", "Peer indisponível; não enviado"),
            ("simulation_only", "Somente simulação"),
        ):
            self.assertIn(f"{technical}: '{label}'", HTML)
        self.assertIn("anomalyResponseConfirmationText(confirmation, info.confirmation)", HTML)
        self.assertIn("delivery_attempted: 'Tentativa de entrega registrada; resultado ainda incerto'", HTML)
        self.assertIn("withdraw_requested: 'Retirada solicitada; entrega ainda não confirmada'", HTML)

    def test_anomaly_response_primary_fallback_uses_required_priority(self):
        priority_start = HTML.index("function anomalyResponseAttemptPriority")
        priority_end = HTML.index("function anomalyResponseStatusCode", priority_start)
        priority_source = HTML[priority_start:priority_end]
        self.assertIn("if (status === 'advertised') return 0", priority_source)
        self.assertIn("if (['sent', 'queued'].includes(status)) return 1", priority_source)
        self.assertIn("if (status === 'pending_approval') return 2", priority_source)
        self.assertIn("event.response_announcement", priority_source)
        self.assertIn("anomalyResponseAttemptTimestamp(right) - anomalyResponseAttemptTimestamp(left)", priority_source)

    def test_anomaly_response_refresh_is_single_list_request_and_row_patch(self):
        refresh_start = HTML.index("async function refreshAnomalyResponseRows")
        refresh_end = HTML.index("function anomalyActionId", refresh_start)
        refresh_source = HTML[refresh_start:refresh_end]
        self.assertIn("anomalyActiveTab === 'active' ? '/api/anomalies/active' : '/api/anomalies/history'", refresh_source)
        self.assertIn("mergeAnomalyResponseFields(item, fresh)", refresh_source)
        self.assertIn("patchAnomalyResponseCell(merged)", refresh_source)
        self.assertNotIn("loadAnomalies(", refresh_source)
        self.assertNotIn("loadAnomalyDashboard(", refresh_source)
        self.assertIn("'auto_mitigation_details'", HTML)
        self.assertNotIn("'auto_mitigation_details_json'", HTML)

    def test_anomaly_response_can_select_a_standalone_outcome_and_keeps_visible_security_id(self):
        primary_start = HTML.index("function anomalyPrimaryResponseAnnouncement")
        primary_end = HTML.index("function anomalyResponseStatusCode", primary_start)
        primary_source = HTML[primary_start:primary_end]
        self.assertIn("Object.prototype.hasOwnProperty.call(event, 'response_announcement')", primary_source)
        self.assertIn("? event.response_announcement", primary_source)
        self.assertIn("const outcomeDetails = event.auto_mitigation_details", HTML)
        self.assertIn("const anomalyId = Number(event.id || 0) || anomalyActionId(event)", HTML)
        self.assertIn("[event.id, anomalyActionId(event)].some", HTML)

    def test_anomaly_response_refresh_avoids_security_and_regular_id_collision(self):
        lookup_start = HTML.index("function anomalyResponseIsSecurityItem")
        lookup_end = HTML.index("function anomalyResponseConfirmationText", lookup_start)
        lookup_source = HTML[lookup_start:lookup_end]
        self.assertIn("['security_anomaly', 'security_anomalies'].includes(source)", lookup_source)
        self.assertIn("if (actionId) keys.push(`action:${actionId}`)", lookup_source)
        self.assertIn("if (rowId && !anomalyResponseIsSecurityItem(event)) keys.push(`row:${rowId}`)", lookup_source)
        self.assertIn("return !anomalyResponseIsSecurityItem(event) && Number(event.id || 0) === targetId", lookup_source)
        refresh_start = HTML.index("async function refreshAnomalyResponseRows")
        refresh_end = HTML.index("function anomalyActionId", refresh_start)
        refresh_source = HTML[refresh_start:refresh_end]
        self.assertIn("const freshByKey = new Map()", refresh_source)
        self.assertIn("anomalyResponseLookupKeys(item).forEach(key => freshByKey.set(key, item))", refresh_source)
        self.assertNotIn("freshById", refresh_source)
        self.assertIn("return Number(event?.action_id || event?.security_anomaly_id || event?.id || 0)", HTML)
        self.assertIn('<tr data-anomaly-row-id="${actionId}">', HTML)
        self.assertIn("if (!event.action_id && Number(requestedId) < 0) event.action_id = Number(requestedId)", HTML)
        self.assertIn("anomalyItems.findIndex(item => anomalyResponseMatchesId(item, targetId))", HTML)

    def test_bgp_mutations_refresh_anomaly_response_even_after_failure(self):
        apply_start = HTML.index("async function applyBgpMitigationCandidate")
        reject_start = HTML.index("async function rejectBgpMitigationCandidate", apply_start)
        dns_start = HTML.index("async function applyBgpMitigationDnsTargets", reject_start)
        update_start = HTML.index("async function updateBgpAnnouncement", dns_start)
        update_end = HTML.index("function unitLabel", update_start)
        apply_source = HTML[apply_start:reject_start]
        reject_source = HTML[reject_start:dns_start]
        dns_source = HTML[dns_start:update_start]
        update_source = HTML[update_start:update_end]
        for source in (apply_source, reject_source, dns_source, update_source):
            self.assertIn("finally", source)
            self.assertIn("refreshAnomalyResponseRows", source)
        for source in (apply_source, dns_source, update_source):
            self.assertLess(source.index("refreshAnomalyResponseRows"), source.index("loadBgpView"))
        self.assertIn("openAnomalyResponseDetail(Number(response.dataset.anomalyId))", HTML)

    def test_anomaly_response_column_preserves_all_existing_action_buttons(self):
        render_start = HTML.index("function renderAnomalyTable(items)")
        render_end = HTML.index("async function loadAnomalies", render_start)
        render_source = HTML[render_start:render_end]
        self.assertLess(render_source.index('class="anomaly-response-cell"'), render_source.index('class="anomaly-actions"'))
        for action_class in ("anomaly-detail", "anomaly-mitigate", "anomaly-ack", "anomaly-close"):
            self.assertIn(action_class, render_source)

    def test_bgp_status_uses_existing_global_polling_without_another_interval(self):
        refresh_start = HTML.index("async function refreshOpsSummary()")
        refresh_end = HTML.index("function startOpsSummaryPolling()", refresh_start)
        refresh_source = HTML[refresh_start:refresh_end]
        self.assertIn("await refreshBgpConnectorStatuses()", refresh_source)
        self.assertIn("document.getElementById('view-bgp')?.classList.contains('active')", refresh_source)
        self.assertIn("if (bgpStatusesRefreshInFlight) return", HTML)
        self.assertEqual(HTML.count("opsSummaryRefreshTimer = setInterval"), 1)

    def test_bgp_manual_check_and_disabled_labels_use_persisted_status(self):
        self.assertIn("function checkBgpConnectorStatusesNow()", HTML)
        self.assertIn("/check-router`, { method: 'POST' }", HTML)
        self.assertIn("/status`).catch", HTML)
        self.assertIn("VERIFICACAO DESABILITADA", HTML)
        self.assertIn("checkBgpConnectorStatusesNow().catch", HTML)

    def test_zone_connector_mapping_and_not_applied_reason_are_visible(self):
        self.assertIn('id="ipZoneConnector"', HTML)
        self.assertIn("connector_id: connectorId ? Number(connectorId) : null", HTML)
        self.assertIn("candidate.automatic_not_applied_reason || candidate.connector_resolution_error", HTML)
        self.assertIn("event.auto_mitigation_reason || '-'", HTML)

    def test_manual_mitigation_modal_title_depends_on_resolved_connector_mode(self):
        self.assertIn('id="bgpMitigationModalTitle" class="view-title">Avaliar mitigação BGP</h2>', HTML)
        self.assertIn("function updateBgpMitigationModalTitle(candidates)", HTML)
        self.assertIn("candidate.connector_dry_run === true", HTML)
        self.assertIn("? 'Dry-run BGP'", HTML)
        self.assertIn("? 'Proposta de FlowSpec'", HTML)
        self.assertIn(": 'Avaliar mitigação BGP'", HTML)

    def test_manual_mitigation_decisions_have_operator_friendly_labels(self):
        for technical, label in (
            ("allow_auto", "Elegível para resposta automática"),
            ("require_manual_approval", "Aguardando aprovação"),
            ("deny", "Não permitido"),
            ("dry_run", "Simulação"),
            ("rejected_by_policy", "Bloqueado por política"),
        ):
            self.assertIn(f"{technical}: '{label}'", HTML)
        self.assertIn("mitigationDecisionLabel(code)", HTML)

    def test_manual_mitigation_renders_connector_selector_and_recalculates_only(self):
        self.assertIn("candidate.eligible_connectors", HTML)
        self.assertIn("candidate.requires_connector_selection", HTML)
        self.assertIn("bgp-mitigation-connector", HTML)
        self.assertIn("Selecione o conector para recalcular", HTML)
        self.assertIn("nenhum anúncio é enviado", HTML)
        self.assertIn("const evaluationPayload = selectedConnectorId ? { connector_id: selectedConnectorId } : {};", HTML)
        self.assertIn("body: JSON.stringify(evaluationPayload)", HTML)
        self.assertIn("runBgpAnomalyDryRun(connectorId, false)", HTML)
        self.assertIn("uniqueMitigationConnectorForRecalculation", HTML)
        self.assertIn("Conector único #${automaticConnectorId} selecionado. Recalculando proposta...", HTML)

    def test_evaluation_and_modal_open_do_not_load_or_apply_bgp_workspace(self):
        open_start = HTML.index("async function openBgpMitigationModal")
        open_end = HTML.index("const MITIGATION_DECISION_LABELS", open_start)
        self.assertNotIn("loadBgpView", HTML[open_start:open_end])
        evaluation_start = HTML.index("async function runBgpAnomalyDryRun")
        evaluation_end = HTML.index("async function applyBgpMitigationCandidate", evaluation_start)
        evaluation_source = HTML[evaluation_start:evaluation_end]
        self.assertIn("/mitigation/evaluate", evaluation_source)
        self.assertNotIn("/mitigation/apply", evaluation_source)
        self.assertNotIn("loadBgpView", evaluation_source)

    def test_manual_mitigation_actions_follow_backend_capabilities(self):
        self.assertIn("candidate.actionable", HTML)
        self.assertIn("candidate.can_submit_approval", HTML)
        self.assertIn("candidate.can_announce_now", HTML)
        self.assertIn("Não elegível para mitigação", HTML)
        self.assertIn("Enviar para aprovação", HTML)
        self.assertIn("Aprovar e anunciar", HTML)
        self.assertIn("<span>Rejeitar</span>", HTML)

    def test_equivalent_manual_mitigation_is_visible_and_not_actionable(self):
        self.assertIn("candidate.equivalent_announcement", HTML)
        self.assertIn("Resposta equivalente já ativa", HTML)
        self.assertIn("Abrir detalhes${announcement.id", HTML)
        self.assertIn("!equivalentAnnouncement", HTML)

    def test_manual_apply_includes_selected_connector(self):
        self.assertIn("const connectorId = mitigationCandidateConnectorId(candidate);", HTML)
        self.assertIn("const payload = { candidate_index: Number(index), mode, connector_id: connectorId };", HTML)
        self.assertIn("connector_id: connectorId, selected_dns_target_ips: selectedIps", HTML)

    def test_manual_rejection_is_persisted_by_backend(self):
        self.assertIn("async function rejectBgpMitigationCandidate(index)", HTML)
        self.assertIn("reason: 'rejected_by_operator'", HTML)
        self.assertIn("/mitigation/reject", HTML)
        self.assertIn("rejection_persisted: true", HTML)
        self.assertIn("rejectBgpMitigationCandidate(Number(reject.dataset.index))", HTML)


if __name__ == "__main__":
    unittest.main()
