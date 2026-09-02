"""Testes A-G para o gate de mitigação automática de anomalias CRITICAL.

Requisitos (Tarefa 5):
- CRITICAL configurada para resposta automática pode aplicar na 1ª janela.
- WARNING continua exigindo evidência temporal.
- Whitelist / connector unresolved / ExaBGP unverified/down bloqueiam.
- Caminho completo chega à função de anúncio com pipe/BGP 100% mockados.
- Nenhum anúncio real é enviado durante a suíte.
"""

import unittest
from unittest import mock

from tests.test_collector_apply_static import backend_main as main


def critical_auto_candidate(value=20000, severity="critical"):
    return {
        "template_id": 1,
        "template_name": "CLIENTES-PUBLICOS-DEFAULT",
        "rule_id": 10,
        "rule_name": "DNS_INTERNAL_IP_TO_DST_HIGH_PPS",
        "vector": "DNS_INTERNAL_IP_TO_DST_HIGH_PPS",
        "attack_vector_name": "DNS_INTERNAL_IP_TO_DST_HIGH_PPS",
        "severity": severity,
        "metric": "packets_s",
        "metric_value": value,
        "packets_s": value,
        "comparison": "over",
        "threshold_warning": 5000,
        "threshold_critical": 15000,
        "automatic_mitigation_threshold": 15000,
        "direction": "transmits",
        "protocol": "udp",
        "dst_port": "53",
        "src_ip": "179.189.83.212",
        "dst_ip": "99.231.171.212",
        "top_dst_port": 53,
        "first_seen": "2026-07-24T12:00:00Z",
        "last_seen": "2026-07-24T12:00:00Z",
        "rule_config": {
            "direction": "transmits",
            "protocol": "DNS",
            "dst_port": "53",
            "comparison": "over",
            "window_seconds": 60,
            "consecutive_windows": 1,
            "mitigation_mode": "response_profile",
        },
    }


def event_with_state(state, severity="critical", observed=20000):
    return {
        "id": 2142,
        "severity": severity,
        "observed_value": observed,
        "source_details_json": {
            "rule_config": {
                "consecutive_windows": 1,
                "mitigation_mode": "response_profile",
            },
            "detection": state,
        },
    }


class CriticalAutoMitigationTest(unittest.TestCase):
    def setUp(self):
        # Guarda de segurança (requisito G): qualquer tentativa de escrever no
        # pipe ExaBGP real faz o teste falhar imediatamente.
        self._pipe_guard = mock.patch.object(
            main,
            "exabgp_write_pipe",
            side_effect=AssertionError("Teste tentou escrever no pipe ExaBGP real."),
        )
        self.pipe_guard_mock = self._pipe_guard.start()
        self.addCleanup(self._pipe_guard.stop)

    # A) critical + automatic + connector ready + primeira janela => permitida.
    def test_critical_auto_first_window_allows_automatic(self):
        state = main.build_detection_threshold_state(critical_auto_candidate())
        evidence = state["temporal_evidence"]

        self.assertTrue(evidence["time_series_gate_bypassed_for_critical"])
        self.assertEqual(1, evidence["required_points"])
        self.assertEqual(1, evidence["time_series_required_windows"])
        self.assertEqual(1, evidence["time_series_observed_windows"])
        self.assertEqual("bypassed_critical_auto_single_window", evidence["time_series_reason"])
        self.assertTrue(evidence["sufficient_for_automatic"])
        self.assertTrue(evidence["instant_critical_allowed"])

        gate = main.detection_automatic_policy_gate(event_with_state(state))
        self.assertTrue(gate["allowed"])
        self.assertNotIn("insufficient_time_series_evidence", gate["reasons"])
        self.assertEqual("bypassed_critical_auto_single_window", gate["time_series_reason"])
        self.assertTrue(gate["time_series_gate_bypassed_for_critical"])

    # A2) explicit consecutive_windows > 1 para critical deve ser respeitado.
    def test_critical_explicit_multiple_windows_are_respected(self):
        candidate = critical_auto_candidate()
        candidate["rule_config"]["consecutive_windows"] = 3
        state = main.build_detection_threshold_state(candidate)
        evidence = state["temporal_evidence"]

        self.assertFalse(evidence["time_series_gate_bypassed_for_critical"])
        self.assertEqual(3, evidence["required_points"])
        self.assertFalse(evidence["sufficient_for_automatic"])

        gate = main.detection_automatic_policy_gate(event_with_state(state))
        self.assertFalse(gate["allowed"])
        self.assertIn("insufficient_time_series_evidence", gate["reasons"])

    # B) warning + apenas uma janela => aguarda evidência.
    def test_warning_single_window_waits_for_evidence(self):
        state = main.build_detection_threshold_state(
            critical_auto_candidate(value=7000, severity="warning")
        )
        gate = main.detection_automatic_policy_gate(
            event_with_state(state, severity="warning", observed=7000)
        )

        self.assertFalse(gate["allowed"])
        self.assertIn("insufficient_time_series_evidence", gate["reasons"])
        self.assertFalse(gate["time_series_gate_bypassed_for_critical"])
        self.assertEqual("insufficient_time_series_evidence", gate["time_series_reason"])

    # C) critical + whitelist fail => não aplica (bloqueador whitelist).
    def test_whitelist_failure_is_reported_as_blocker(self):
        blockers = main.automatic_mitigation_blockers(
            {
                "automatic_gate": {
                    "applies": True,
                    "allowed": True,
                    "reasons": [],
                    "time_series_reason": "sufficient_time_series_evidence",
                },
                "policy": {"decision": "require_manual_approval", "reasons": [], "warnings": ["whitelist_match"]},
                "readiness": {"ready": True, "reason": "exabgp_ready"},
                "validation": {"errors": []},
                "preview_connector": {"id": 1, "name": "BGP-FIBINET-BORDA", "backend_type": "exabgp", "mode": "auto"},
                "requires_connector_selection": False,
                "resolution_reason": "anomaly_sensor_connector",
                "cooldown_allowed": True,
                "whitelist_hits": [{"id": 1}],
            }
        )
        by_key = {blocker["key"]: blocker for blocker in blockers}

        self.assertEqual("FAILED", by_key["whitelist"]["status"])
        self.assertEqual("whitelist_match", by_key["whitelist"]["reason"])
        self.assertEqual("PASSED", by_key["exabgp_readiness"]["status"])
        self.assertEqual("PASSED", by_key["connector"]["status"])
        self.assertEqual("PASSED", by_key["time_series"]["status"])

    # D) critical + connector unresolved => não aplica (bloqueador connector).
    def test_connector_unresolved_is_reported_as_blocker(self):
        blockers = main.automatic_mitigation_blockers(
            {
                "automatic_gate": {
                    "applies": True,
                    "allowed": True,
                    "reasons": [],
                    "time_series_reason": "sufficient_time_series_evidence",
                },
                "policy": {"decision": "deny", "reasons": [], "warnings": []},
                "readiness": {"ready": True, "reason": "exabgp_ready"},
                "validation": {"errors": []},
                "preview_connector": None,
                "requires_connector_selection": False,
                "resolution_reason": "connector_unresolved",
                "cooldown_allowed": True,
                "whitelist_hits": [],
            }
        )
        by_key = {blocker["key"]: blocker for blocker in blockers}

        self.assertEqual("FAILED", by_key["connector"]["status"])
        self.assertEqual("connector_unresolved", by_key["connector"]["reason"])

    # E) critical + ExaBGP unverified/down => não aplica (bloqueador readiness).
    def test_exabgp_unverified_blocks_readiness(self):
        status = {
            "bgp_state": "not_verified",
            "flowspec_state": "not_verified",
            "service": {"active": False, "check_possible": False},
            "listener": {"listening": False},
            "session": {"tcp_established": False},
            "pipes": {"ok": True, "is_fifo": True, "reader_active": True},
            "passive_listen_enabled": False,
            "checks": {
                "service_ok": False,
                "listener_ok": True,
                "bgp_ok": False,
                "flowspec_ok": False,
                "pipe_ok": True,
                "close_wait_ok": True,
            },
        }
        readiness = main.evaluate_bgp_connector_readiness(status)
        self.assertFalse(readiness["ready"])
        self.assertIn("exabgp_service_unverified", readiness["reasons"])

        blockers = main.automatic_mitigation_blockers(
            {
                "automatic_gate": {
                    "applies": True,
                    "allowed": True,
                    "reasons": [],
                    "time_series_reason": "sufficient_time_series_evidence",
                },
                "policy": {"decision": "allow_auto", "reasons": ["AUTO_ALLOWED"], "warnings": []},
                "readiness": readiness,
                "validation": {"errors": []},
                "preview_connector": {"id": 1, "name": "BGP-FIBINET-BORDA", "backend_type": "exabgp", "mode": "auto"},
                "requires_connector_selection": False,
                "resolution_reason": "anomaly_sensor_connector",
                "cooldown_allowed": True,
                "whitelist_hits": [],
            }
        )
        by_key = {blocker["key"]: blocker for blocker in blockers}
        self.assertEqual("FAILED", by_key["exabgp_readiness"]["status"])
        self.assertIn("exabgp_service_unverified", by_key["exabgp_readiness"]["reason"])

    # E2) serviço inverificável, mas BGP estabelecido => não é "unverified".
    def test_service_uncheckable_but_bgp_established_is_not_unverified(self):
        status = {
            "bgp_state": "established",
            "flowspec_state": "not_verified",
            "service": {"active": False, "check_possible": False},
            "listener": {"listening": False},
            "session": {"tcp_established": True},
            "pipes": {"ok": True, "is_fifo": True, "reader_active": True},
            "passive_listen_enabled": False,
            "checks": {
                "service_ok": False,
                "listener_ok": True,
                "bgp_ok": True,
                "flowspec_ok": False,
                "pipe_ok": True,
                "close_wait_ok": True,
            },
        }
        readiness = main.evaluate_bgp_connector_readiness(status)
        self.assertNotIn("exabgp_service_unverified", readiness["reasons"])
        self.assertTrue(readiness["checks"]["service_ok"])
        # FlowSpec ainda não verificado => readiness global permanece bloqueada.
        self.assertFalse(readiness["ready"])
        self.assertIn("flowspec_not_verified", readiness["reasons"])

    # F) critical + tudo válido => caminho chega à função de anúncio com
    #    BGP/pipe 100% mockados (nenhuma escrita real).
    def test_critical_all_valid_reaches_announce(self):
        candidate = {
            "mitigation_mode": "automatic",
            "response_profile_id": 7,
            "attack_vector_name": "DNS_INTERNAL_IP_TO_DST_HIGH_PPS",
            "cooldown_seconds": 0,
        }
        connector = {
            "id": 1,
            "name": "BGP-FIBINET-BORDA",
            "backend_type": "exabgp",
            "mode": "auto",
            "enabled": True,
            "is_active": True,
        }
        profile = {"id": 7, "name": "FLOWSPEC_AUTO_BLOCK_DST_DNS", "approval_mode": "auto"}
        ready = {"ready": True, "reason": "", "reasons": [], "checks": {"service_ok": True}}

        with mock.patch.object(
            main,
            "detection_automatic_policy_gate",
            return_value={
                "applies": True,
                "allowed": True,
                "reason": "",
                "reasons": [],
                "analysis_mode": "automatic_authorization",
                "mitigation_state": "candidate_generated",
                "time_series_reason": "bypassed_critical_auto_single_window",
                "time_series_gate_bypassed_for_critical": True,
            },
        ) as gate, mock.patch.object(main, "fetch_bgp_profile", return_value=profile), mock.patch.object(
            main, "resolve_mitigation_target_connectors", return_value=[connector]
        ), mock.patch.object(
            main,
            "policy_for_candidate",
            return_value={"decision": "allow_auto", "reasons": ["AUTO_ALLOWED"], "warnings": []},
        ), mock.patch.object(
            main, "validate_mitigation_candidate", return_value={"errors": [], "warnings": []}
        ), mock.patch.object(
            main,
            "render_exabgp_flowspec_command",
            side_effect=lambda mode, _c: (
                "announce flow route { ... }" if mode == "announce" else "withdraw flow route { ... }"
            ),
        ), mock.patch.object(
            main, "equivalent_mitigation_announcement", return_value=None
        ), mock.patch.object(main, "cooldown_allows_mitigation", return_value=True), mock.patch.object(
            main, "check_bgp_connector_readiness", return_value=ready
        ) as readiness:
            result = main.deterministic_automatic_proposal_state(None, candidate)

        self.assertTrue(result["auto_allowed"])
        self.assertTrue(result["eligible"])
        self.assertTrue(result["eligible_for_automatic"])
        self.assertEqual("automatic_authorization", result["analysis_mode"])
        self.assertEqual("candidate_generated", result["mitigation_state"])
        self.assertIn("announce flow route", result["command"])
        self.assertEqual(ready, result["readiness"])
        readiness.assert_called_once()
        gate.assert_called_once()
        # O pipe real jamais é escrito: o guard de setUp falharia o teste.

    # G) nenhum anúncio real é enviado durante a suíte.
    def test_no_real_announce_during_suite(self):
        self.assertEqual(0, self.pipe_guard_mock.call_count)


if __name__ == "__main__":
    unittest.main()
