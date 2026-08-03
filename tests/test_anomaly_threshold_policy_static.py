import os
import shutil
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ai_integration_stub = types.ModuleType("app.services.ai_integration")
ai_integration_stub.AI_FUNCTIONS = {}
ai_integration_stub.AI_PROVIDER_TYPES = set()
ai_integration_stub.MITIGATION_SCHEMA = {}
for function_name in (
    "audit_ai_action",
    "ai_audit_history",
    "ai_history",
    "ai_overview",
    "central_ai_effective_config",
    "compose_ai_http_headers",
    "delete_ai_provider",
    "duplicate_ai_provider",
    "ensure_ai_schema",
    "execute_ai_playground",
    "execute_ai_route",
    "get_ai_provider",
    "global_ai_settings",
    "list_ai_prompts",
    "list_ai_providers",
    "list_ai_routes",
    "list_provider_models",
    "prompt_versions",
    "refresh_provider_models",
    "render_prompt",
    "restore_prompt_version",
    "save_ai_prompt",
    "save_ai_provider",
    "save_ai_route",
    "sanitize_ai_content",
    "sanitize_error",
    "test_ai_provider",
    "toggle_ai_provider",
    "update_global_ai_settings",
):
    setattr(ai_integration_stub, function_name, lambda *args, **kwargs: {})
sys.modules.setdefault("app.services.ai_integration", ai_integration_stub)

from tests.test_collector_apply_static import backend_main as main


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


def detection_candidate(
    value=7000,
    severity="warning",
    warning=5000,
    critical=15000,
    automatic=None,
    first_seen="2026-07-24T12:00:00Z",
    last_seen="2026-07-24T12:00:00Z",
):
    return {
        "template_id": 1,
        "template_name": "CLIENTES-PUBLICOS-DEFAULT",
        "rule_id": 10,
        "rule_name": "DNS_ABUSE_OUTBOUND",
        "vector": "DNS_ABUSE_OUTBOUND",
        "severity": severity,
        "metric": "packets_s",
        "metric_value": value,
        "packets_s": value,
        "comparison": "over",
        "threshold_warning": warning,
        "threshold_critical": critical,
        "automatic_mitigation_threshold": automatic,
        "direction": "transmits",
        "protocol": "udp",
        "prefix_cidr": "179.189.83.0/24",
        "src_ip": "179.189.83.212",
        "internal_ip": "179.189.83.212",
        "dst_ip": "99.231.171.212",
        "top_dst_port": 53,
        "target_port": 53,
        "whitelist_status": "no_match",
        "first_seen": first_seen,
        "last_seen": last_seen,
        "rule_config": {
            "direction": "transmits",
            "protocol": "DNS",
            "dst_port": "53",
            "comparison": "over",
            "window_seconds": 60,
            "consecutive_windows": 1,
        },
    }


def event_with_detection(state, severity=None, observed=None):
    current = state.get("current") or {}
    return {
        "id": 2142,
        "severity": severity or current.get("severity") or state.get("triggered_severity"),
        "observed_value": observed if observed is not None else current.get("last_value"),
        "source_details_json": {
            "rule_config": {
                "consecutive_windows": 1,
                "allow_warning_auto": False,
            },
            "detection": state,
        },
    }


class AnomalyThresholdPolicyTest(unittest.TestCase):
    def test_warning_snapshot_uses_real_trigger_not_critical_threshold(self):
        state = main.build_detection_threshold_state(detection_candidate())

        self.assertEqual(5000.0, state["warning_threshold"])
        self.assertEqual(15000.0, state["critical_threshold"])
        self.assertEqual(15000.0, state["automatic_mitigation_threshold"])
        self.assertEqual(5000.0, state["trigger_threshold"])
        self.assertEqual(7000.0, state["trigger_value"])
        self.assertEqual("warning", state["triggered_severity"])
        self.assertEqual("packets_per_second", state["canonical_unit"])
        self.assertTrue(state["trigger_condition"]["passed"])

    def test_pps_values_are_compared_canonically_and_only_formatted_as_kpps(self):
        state = main.build_detection_threshold_state(detection_candidate())

        self.assertEqual(7000.0, state["trigger_value"])
        self.assertEqual(5000.0, state["trigger_threshold"])
        self.assertEqual(15000.0, state["critical_threshold"])
        self.assertEqual("7.0 Kpps", main.format_metric(state["trigger_value"], "packets_s"))
        self.assertEqual("15 Kpps", main.format_metric(state["critical_threshold"], "packets_s"))

    def test_critical_snapshot_uses_critical_trigger(self):
        state = main.build_detection_threshold_state(
            detection_candidate(value=16000, severity="critical")
        )

        self.assertEqual(15000.0, state["trigger_threshold"])
        self.assertEqual(16000.0, state["trigger_value"])
        self.assertEqual("critical", state["triggered_severity"])

    def test_explicit_automatic_threshold_can_differ_from_severity_thresholds(self):
        state = main.build_detection_threshold_state(
            detection_candidate(automatic=12000)
        )

        self.assertEqual(5000.0, state["warning_threshold"])
        self.assertEqual(15000.0, state["critical_threshold"])
        self.assertEqual(12000.0, state["automatic_mitigation_threshold"])

    def test_threshold_history_trigger_last_and_peak_are_independent(self):
        first = main.build_detection_threshold_state(detection_candidate())
        second = main.build_detection_threshold_state(
            detection_candidate(
                value=20000,
                severity="critical",
                warning=6000,
                critical=18000,
                first_seen="2026-07-24T12:01:00Z",
                last_seen="2026-07-24T12:01:00Z",
            ),
            {"detection": first},
        )
        third = main.build_detection_threshold_state(
            detection_candidate(
                value=9000,
                severity="warning",
                warning=6000,
                critical=18000,
                first_seen="2026-07-24T12:02:00Z",
                last_seen="2026-07-24T12:02:00Z",
            ),
            {"detection": second},
        )

        self.assertEqual(7000.0, third["trigger_value"])
        self.assertEqual(5000.0, third["trigger_threshold"])
        self.assertEqual(9000.0, third["current"]["last_value"])
        self.assertEqual(20000.0, third["current"]["peak_value"])
        self.assertEqual(first["threshold_version"], third["threshold_version"])
        self.assertGreaterEqual(len(third["threshold_history"]), 2)

    def test_additional_conditions_are_persisted(self):
        state = main.build_detection_threshold_state(detection_candidate())
        conditions = {item["condition"]: item for item in state["conditions_passed"]}

        self.assertTrue(conditions["zone_prefix_membership"]["passed"])
        self.assertEqual(53, conditions["destination_port"]["actual"])
        self.assertEqual("no_match", conditions["global_whitelist"]["actual"])

    def test_dns_event_persists_trigger_snapshot_and_keeps_it_after_threshold_change(self):
        tmpdir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(tmpdir, "gmjflow.db")
            with mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": db_path}, clear=False), \
                    mock.patch.object(main, "SENSOR_DB_READY", False), \
                    mock.patch.object(main, "hash_password", return_value="test-hash"):
                main.ensure_sensor_db()
                with main.sqlite_connection() as conn:
                    first = detection_candidate()
                    self.assertEqual(
                        "created",
                        main.upsert_detection_template_dns_anomaly_event(conn, first),
                    )
                    conn.commit()
                    row = conn.execute(
                        "SELECT * FROM anomaly_events ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                    event = main.anomaly_event_row_to_dict(row)

                    self.assertEqual(5000.0, event["threshold_value"])
                    self.assertEqual(5000.0, event["trigger_threshold"])
                    self.assertEqual(15000.0, event["critical_threshold"])
                    self.assertEqual("packets_per_second", event["canonical_unit"])

                    changed = detection_candidate(
                        value=9000,
                        warning=6000,
                        critical=18000,
                        first_seen="2026-07-24T12:01:00Z",
                        last_seen="2026-07-24T12:01:00Z",
                    )
                    self.assertEqual(
                        "updated",
                        main.upsert_detection_template_dns_anomaly_event(conn, changed),
                    )
                    conn.commit()
                    row = conn.execute(
                        "SELECT * FROM anomaly_events ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                    event = main.anomaly_event_row_to_dict(row)

                    self.assertEqual(5000.0, event["trigger_threshold"])
                    self.assertEqual(7000.0, event["trigger_value"])
                    self.assertEqual(6000.0, event["configured_thresholds_current"]["warning_threshold"])
                    self.assertEqual(9000.0, event["last_value"])
                    self.assertGreaterEqual(len(event["threshold_history"]), 2)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_warning_profile_never_falls_through_to_critical_profile(self):
        warning = detection_candidate()
        warning.update(
            {
                "warning_response_profile_id": None,
                "critical_response_profile_id": 22,
                "fallback_response_profile_id": None,
            }
        )
        critical = dict(warning, severity="critical")

        self.assertIsNone(main.detection_response_profile_id(warning))
        self.assertEqual(22, main.detection_response_profile_id(critical))

    def test_warning_gate_has_deterministic_priority_and_stops_before_connector(self):
        state = main.build_detection_threshold_state(detection_candidate())
        candidate = {
            "mitigation_mode": "automatic",
            "raw_payload": {"anomaly": event_with_detection(state)},
        }

        with mock.patch.object(main, "fetch_bgp_profile") as fetch_profile, \
                mock.patch.object(main, "resolve_mitigation_target_connectors") as resolve_connector:
            result = main.deterministic_automatic_proposal_state(None, candidate)

        self.assertFalse(result["auto_allowed"])
        self.assertFalse(result["eligible"])
        self.assertEqual("warning_manual_only", result["reason"])
        self.assertIn("below_automatic_mitigation_threshold", result["reasons"])
        self.assertIn("insufficient_time_series_evidence", result["reasons"])
        self.assertEqual("informational", result["analysis_mode"])
        fetch_profile.assert_not_called()
        resolve_connector.assert_not_called()

    def test_only_one_point_blocks_critical_automatic_by_default(self):
        state = main.build_detection_threshold_state(
            detection_candidate(value=20000, severity="critical")
        )
        gate = main.detection_automatic_policy_gate(
            event_with_detection(state, severity="critical", observed=20000)
        )

        self.assertFalse(gate["allowed"])
        self.assertEqual("insufficient_time_series_evidence", gate["reason"])

    def test_two_points_allow_critical_to_continue_to_later_gates(self):
        first = main.build_detection_threshold_state(
            detection_candidate(value=20000, severity="critical")
        )
        second = main.build_detection_threshold_state(
            detection_candidate(
                value=21000,
                severity="critical",
                first_seen="2026-07-24T12:01:00Z",
                last_seen="2026-07-24T12:01:00Z",
            ),
            {"detection": first},
        )
        gate = main.detection_automatic_policy_gate(
            event_with_detection(second, severity="critical", observed=21000)
        )

        self.assertTrue(gate["allowed"])
        self.assertEqual("automatic_authorization", gate["analysis_mode"])

    def test_critical_positive_ai_advances_to_automatic_and_negative_ai_does_not(self):
        proposal = {"auto_allowed": True, "eligible": True}
        config = {"allow_auto": True}
        approved = {
            "id": 9,
            "apply_mitigation": True,
            "status": "success",
            "error_message": "",
        }

        self.assertEqual(
            "automatic",
            main.automatic_mitigation_execution_mode(proposal, config, approved),
        )
        self.assertEqual(
            "manual_approval",
            main.automatic_mitigation_execution_mode(
                proposal,
                config,
                {**approved, "apply_mitigation": False},
            ),
        )

    def test_informational_ai_cannot_become_automatic_authorization(self):
        response = main.normalize_mitigation_ai_response(
            {"apply_mitigation": True, "reason": "modelo aprovou"},
            {"analysis_mode": "informational"},
        )

        self.assertFalse(response["apply_mitigation"])
        self.assertIn("Analise informativa", response["reason"])

    def test_informational_ai_payload_preserves_threshold_evidence_and_safe_candidate(self):
        payload = main.compact_ai_payload_for_model(
            {
                "analysis_mode": "informational",
                "anomaly": {
                    **event_with_detection(
                        main.build_detection_threshold_state(detection_candidate())
                    ),
                    "triggered_severity": "warning",
                    "trigger_value": 7000,
                    "trigger_threshold": 5000,
                    "warning_threshold": 5000,
                    "critical_threshold": 15000,
                    "automatic_mitigation_threshold": 15000,
                    "timeseries_points": 1,
                    "evidence_duration_seconds": 0,
                    "estimated_bytes": 480_000_000,
                },
                "candidates": [
                    {
                        "dst_cidr": "99.231.171.212/32",
                        "protocol": "udp",
                        "dst_port": "53",
                        "mitigation_state": "informational_candidate",
                    }
                ],
                "security_rules": {
                    "analysis_mode": "informational",
                    "analysis_only_never_apply": True,
                },
            },
            12000,
        )

        self.assertEqual("informational", payload["analysis_mode"])
        self.assertEqual(5000, payload["anomaly"]["trigger_threshold"])
        self.assertEqual(15000, payload["anomaly"]["critical_threshold"])
        self.assertEqual(1, payload["anomaly"]["timeseries_points"])
        self.assertEqual("99.231.171.212/32", payload["candidates"][0]["dst_cidr"])
        self.assertEqual("53", payload["candidates"][0]["dst_port"])

    def test_active_summary_ignores_ended_closed_and_rejected(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE anomaly_events (severity TEXT, status TEXT)")
        conn.executemany(
            "INSERT INTO anomaly_events (severity, status) VALUES (?, ?)",
            [
                ("warning", "active"),
                ("warning", "active"),
                ("critical", "active"),
                ("critical", "ended"),
                ("warning", "closed"),
                ("critical", "rejected"),
            ],
        )
        with mock.patch.object(main, "consolidated_security_anomaly_groups", return_value=[]):
            summary = main.active_anomalies_summary(conn)

        self.assertEqual(3, summary["active_total"])
        self.assertEqual(2, summary["active_warning"])
        self.assertEqual(1, summary["active_critical"])
        self.assertEqual(summary["active_total"], summary["active_count"])
        conn.close()

    def test_mitigation_states_are_explicit(self):
        self.assertEqual(
            "informational_candidate",
            main.mitigation_state_from_status("informational_candidate"),
        )
        self.assertEqual(
            "announcement_pending",
            main.mitigation_state_from_status("pending_approval"),
        )
        self.assertEqual(
            "announcement_applied",
            main.mitigation_state_from_status("advertised"),
        )
        self.assertEqual("ended", main.mitigation_state_from_status("", "ended"))

    def test_worker_gate_precedes_ai_and_persists_no_announcement_evidence(self):
        worker = SOURCE[
            SOURCE.index("def process_anomaly_mitigation")
            : SOURCE.index("MANUAL_FLOWSPEC_ANNOUNCEMENT_COLUMNS")
        ]
        gate_position = worker.index("event_automatic_gate = detection_automatic_policy_gate")
        proposal_position = worker.index("proposal_states:")

        self.assertLess(gate_position, proposal_position)
        self.assertIn('"ai_called": False', worker)
        self.assertIn('"fifo_written": False', worker)
        self.assertIn('"announcement_pending": False', worker)
        self.assertIn('"informational_candidate"', worker)

    def test_safe_dns_destination_and_source_only_guard_remain_unchanged(self):
        dns = SOURCE[
            SOURCE.index("def dns_outbound_candidates")
            : SOURCE.index("def fetch_anomaly_mitigation_context")
        ]

        self.assertIn('"dst_cidr": cidr_from_ip_or_cidr(dst_ip)', dns)
        self.assertIn('"dst_port": "53"', dns)
        self.assertIn('"never_announce": True', dns)
        self.assertIn('"mitigation_mode": "analysis_only"', dns)


class AnomalySeverityUiStaticTest(unittest.TestCase):
    def test_semantic_tokens_cover_all_themes(self):
        self.assertGreaterEqual(HTML.count("--warning:"), 3)
        self.assertGreaterEqual(HTML.count("--danger:"), 3)
        self.assertGreaterEqual(HTML.count("--info:"), 3)
        self.assertGreaterEqual(HTML.count("--success:"), 3)
        self.assertIn(".badge-soft.severity-warning", HTML)
        self.assertIn(".badge-soft.severity-critical", HTML)
        self.assertIn(".badge-soft.severity-info", HTML)

    def test_list_detail_response_and_mitigation_use_semantic_badges(self):
        self.assertIn("${severityBadgeClass(event.severity)}", HTML)
        self.assertIn('id="anomalyDetailSeverity"', HTML)
        self.assertIn("severityBadgeClass(event.triggered_severity || event.severity)", HTML)
        self.assertIn("Candidato informativo:", HTML)
        self.assertIn("Elegível para automático", HTML)
        self.assertIn("mitigationStateInfo(event.mitigation_state", HTML)
        self.assertIn("color: [anomalySeverityColor(", HTML)

    def test_detail_shows_separate_threshold_and_evidence_fields(self):
        for label in (
            "Severidade disparada",
            "Valor que disparou",
            "Threshold warning",
            "Threshold critical",
            "Threshold automático",
            "Threshold do gatilho",
            "Fonte threshold",
            "Evidência temporal",
            "Condições adicionais",
        ):
            self.assertIn(label, HTML)

    def test_nav_has_total_warning_critical_and_accessible_tooltip(self):
        for identifier in (
            "anomalyNavBadge",
            "anomalyNavWarningBadge",
            "anomalyNavCriticalBadge",
        ):
            self.assertIn(identifier, HTML)
        self.assertIn("anomalias ativas:", HTML)
        self.assertIn("button.setAttribute('aria-label'", HTML)
        self.assertIn("warningBadge.hidden = warningCount <= 0", HTML)
        self.assertIn("criticalBadge.hidden = criticalCount <= 0", HTML)

    def test_cards_and_menu_share_the_existing_ops_summary_poll(self):
        self.assertEqual(1, HTML.count("apiRequest('/api/ops/summary', { cache: 'no-store' })"))
        self.assertNotIn("apiRequest('/api/anomalies/summary')", HTML)
        self.assertIn("setText('anomalyActiveCount'", HTML)
        self.assertIn("setText('anomalyCriticalCount'", HTML)
        self.assertIn("setText('anomalyWarningCount'", HTML)
        self.assertIn("active_total:", HTML)
        self.assertIn("active_critical:", HTML)
        self.assertIn("active_warning:", HTML)

    def test_anomaly_cards_use_semantic_severity_accents(self):
        self.assertIn("anomaly-active-metric", HTML)
        self.assertIn("anomaly-warning-metric", HTML)
        self.assertIn("anomaly-critical-metric", HTML)


if __name__ == "__main__":
    unittest.main()
