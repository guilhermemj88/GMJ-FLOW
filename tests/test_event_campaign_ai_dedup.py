from __future__ import annotations

import json
import os
import sqlite3
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavioral_detection import AttackVector, ensure_behavioral_schema  # noqa: E402
from app.services.campaign_ai import analyze_campaign, resolve_campaign_ai_for_event  # noqa: E402
from app.services.security_events import ensure_security_event_schema, upsert_security_event  # noqa: E402
from app.services.security_event_ai import analyze_security_event, get_security_event_analysis  # noqa: E402


def _campaign_structured(summary: str = "Análise de campanha de teste.") -> dict:
    return {
        "summary": summary,
        "confidence": "MEDIUM",
        "assessment": "SUSPICIOUS",
        "why_detected": ["scan distribuído"],
        "important_sources": ["198.51.100.1"],
        "threat_intelligence_findings": [],
        "possible_false_positive_factors": [],
        "recommended_checks": [],
        "recommended_actions": [],
        "mitigation_advisory": "monitorar",
        "limitations": [],
    }


def _event_structured(summary: str = "Análise de evento de teste.") -> dict:
    return {
        "summary": summary,
        "confidence": "LOW",
        "assessment": "SUSPICIOUS",
        "why_detected": ["SYN sem ACK"],
        "important_sources": ["198.51.100.9"],
        "threat_intelligence_findings": [],
        "possible_false_positive_factors": [],
        "recommended_checks": [],
        "recommended_actions": [],
        "mitigation_advisory": "monitorar",
        "limitations": [],
    }


class EventCampaignAiDedupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(self.conn)
        ensure_security_event_schema(self.conn)
        self.conn.commit()

    def tearDown(self) -> None:
        self.conn.close()

    def _campaign(self, campaign_id: str = "GMJ-C-DEDUP") -> str:
        self.conn.execute(
            """
            INSERT INTO threat_campaigns (
                campaign_id, campaign_key, target_prefix, classification, coordination_score,
                unique_sources, unique_source_asns, packets_per_second, bits_per_second,
                flows_per_second, first_seen, last_seen, feature_json, threat_intel_json,
                intel_sources_json, decision_source, status, recurrence_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                campaign_id, f"key-{campaign_id}", "203.0.113.0/24", "SCANNING_CAMPAIGN", 40,
                4, 2, 100.0, 800000.0, 5.0,
                "2026-08-12T10:00:00Z", "2026-08-12T10:05:00Z",
                json.dumps({"attack_family": "SCAN_FAMILY", "concurrent_sources": 4, "attack_types": ["PORT_SCAN_HORIZONTAL"]}),
                "{}", "[]", "GMJ_FLOW", "active", 1,
                "2026-08-12T10:00:00Z", "2026-08-12T10:05:00Z",
            ),
        )
        self.conn.commit()
        return campaign_id

    def _event(self, campaign_id: str = "") -> int:
        vector = AttackVector(
            attack_type="PORT_SCAN_VERTICAL",
            detector="port_scan",
            detector_score=70,
            confidence=0.7,
            first_seen="2026-08-12T11:00:00Z",
            last_seen="2026-08-12T11:01:00Z",
            src_ip="198.51.100.9",
            target_ip="203.0.113.9",
            protocol="tcp",
            direction="INBOUND",
            features={"packet_count": 100, "packets_per_second": 10, "unique_dst_ports": 30},
            network_context={"src_role": "EXTERNAL", "dst_role": "CUSTOMER", "traffic_direction": "INBOUND"},
            evidence=["30 portas TCP SYN sem ACK"],
            score_components={"cardinality": 30, "persistence": 10},
        )
        event_id = upsert_security_event(self.conn, vector)
        if campaign_id:
            self.conn.execute("UPDATE security_events SET campaign_id=? WHERE id=?", (campaign_id, event_id))
        self.conn.commit()
        return event_id

    def _valid_campaign_analysis(self, campaign_id: str, calls: list[str]) -> dict:
        def executor(_conn, _function_key, _prompt, **_kwargs):
            calls.append("campaign")
            return {"ok": True, "provider": "Local test", "model": "m", "structured": _campaign_structured()}
        return analyze_campaign(self.conn, campaign_id, executor=executor)

    def _event_executor(self, calls: list[str]):
        def executor(_conn, _function_key, _prompt, **_kwargs):
            calls.append("event")
            return {"ok": True, "provider": "Local test", "model": "m", "structured": _event_structured()}
        return executor

    def test_event_without_campaign_uses_event_ai(self) -> None:
        event_id = self._event()
        calls: list[str] = []
        result = analyze_security_event(self.conn, event_id, executor=self._event_executor(calls))
        self.assertTrue(result["ok"])
        self.assertEqual("event", result["analysis_source"])
        self.assertFalse(result["inherited_from_campaign"])
        self.assertEqual(["event"], calls)

    def test_event_with_campaign_without_ai_uses_event_ai(self) -> None:
        campaign_id = self._campaign()
        event_id = self._event(campaign_id)
        calls: list[str] = []
        result = analyze_security_event(self.conn, event_id, executor=self._event_executor(calls))
        self.assertTrue(result["ok"])
        self.assertEqual("event", result["analysis_source"])
        self.assertFalse(result["inherited_from_campaign"])
        self.assertEqual(["event"], calls)

    def test_event_with_valid_campaign_ai_inherits_without_provider_call(self) -> None:
        campaign_id = self._campaign()
        event_id = self._event(campaign_id)
        campaign_calls: list[str] = []
        self._valid_campaign_analysis(campaign_id, campaign_calls)
        event_calls: list[str] = []
        result = analyze_security_event(self.conn, event_id, executor=self._event_executor(event_calls))
        self.assertTrue(result["ok"])
        self.assertTrue(result["cached"])
        self.assertEqual("campaign", result["analysis_source"])
        self.assertTrue(result["inherited_from_campaign"])
        self.assertEqual(campaign_id, result["campaign_id"])
        self.assertEqual([], event_calls)  # provider NÃO chamado

    def test_campaign_ai_stale_does_not_inherit(self) -> None:
        campaign_id = self._campaign()
        event_id = self._event(campaign_id)
        calls: list[str] = []
        self._valid_campaign_analysis(campaign_id, calls)
        # Alteração material torna a análise da campanha stale.
        self.conn.execute("UPDATE threat_campaigns SET recurrence_count = recurrence_count + 1 WHERE campaign_id=?", (campaign_id,))
        self.conn.commit()
        resolution = resolve_campaign_ai_for_event(self.conn, campaign_id)
        self.assertTrue(resolution["available"])
        self.assertTrue(resolution["stale"])
        self.assertFalse(resolution["valid"])
        event_calls: list[str] = []
        result = analyze_security_event(self.conn, event_id, executor=self._event_executor(event_calls))
        self.assertEqual("event", result["analysis_source"])
        self.assertEqual(["event"], event_calls)

    def test_force_always_runs_event_ai(self) -> None:
        campaign_id = self._campaign()
        event_id = self._event(campaign_id)
        calls: list[str] = []
        self._valid_campaign_analysis(campaign_id, calls)
        event_calls: list[str] = []
        result = analyze_security_event(self.conn, event_id, force=True, executor=self._event_executor(event_calls))
        self.assertEqual("event", result["analysis_source"])
        self.assertFalse(result["inherited_from_campaign"])
        self.assertEqual(["event"], event_calls)

    def test_individual_analysis_available_when_event_has_own_valid_ai(self) -> None:
        campaign_id = self._campaign()
        event_id = self._event(campaign_id)
        # Event AI própria primeiro (válida).
        event_calls: list[str] = []
        analyze_security_event(self.conn, event_id, executor=self._event_executor(event_calls))
        # Depois, campanha com AI válida.
        campaign_calls: list[str] = []
        self._valid_campaign_analysis(campaign_id, campaign_calls)
        payload = get_security_event_analysis(self.conn, event_id)
        self.assertEqual("campaign", payload["analysis_source"])
        self.assertTrue(payload["inherited_from_campaign"])
        self.assertTrue(payload["individual_analysis_available"])
        self.assertIsNotNone(payload["individual_analysis_id"])

    def test_inherited_does_not_write_event_ai_json(self) -> None:
        campaign_id = self._campaign()
        event_id = self._event(campaign_id)
        calls: list[str] = []
        self._valid_campaign_analysis(campaign_id, calls)
        event_calls: list[str] = []
        analyze_security_event(self.conn, event_id, executor=self._event_executor(event_calls))
        row = self.conn.execute(
            "SELECT ai_analysis_json, ai_analysis_status FROM security_events WHERE id=?", (event_id,)
        ).fetchone()
        self.assertIn(row["ai_analysis_json"], ("", "{}"))
        self.assertEqual("not_analyzed", row["ai_analysis_status"])

    def test_campaign_analysis_id_correct(self) -> None:
        campaign_id = self._campaign()
        event_id = self._event(campaign_id)
        calls: list[str] = []
        self._valid_campaign_analysis(campaign_id, calls)
        stored_id = int(self.conn.execute(
            "SELECT id FROM campaign_ai_analyses WHERE campaign_id=? AND status='valid' ORDER BY id DESC LIMIT 1",
            (campaign_id,),
        ).fetchone()[0])
        event_calls: list[str] = []
        result = analyze_security_event(self.conn, event_id, executor=self._event_executor(event_calls))
        self.assertEqual(stored_id, result["campaign_analysis_id"])

    def test_fingerprint_stale_uses_canonical_owner(self) -> None:
        campaign_id = self._campaign()
        calls: list[str] = []
        self._valid_campaign_analysis(campaign_id, calls)
        resolution = resolve_campaign_ai_for_event(self.conn, campaign_id)
        self.assertTrue(resolution["available"])
        self.assertTrue(resolution["valid"])
        self.assertFalse(resolution["stale"])
        self.assertTrue(resolution["analysis_fingerprint"])
        self.assertTrue(resolution["evidence_fingerprint"])

    def test_no_mitigation_and_no_policy(self) -> None:
        campaign_id = self._campaign()
        event_id = self._event(campaign_id)
        calls: list[str] = []
        self._valid_campaign_analysis(campaign_id, calls)
        event_calls: list[str] = []
        result = analyze_security_event(self.conn, event_id, executor=self._event_executor(event_calls))
        self.assertTrue(result["advisory_only"])
        self.assertFalse(result["mitigation_executed"])
        # O caminho de herança nunca toca o Policy Engine: a tabela de decisões
        # sequer é criada (nenhuma decisão/avaliação de mitigação ocorreu).
        policy_table = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='threat_policy_decisions'"
        ).fetchone()
        if policy_table is not None:
            self.assertEqual(0, self.conn.execute("SELECT COUNT(*) FROM threat_policy_decisions").fetchone()[0])
        # Herança registra AI_INHERITED, nunca AI_REQUEST/AI_RESPONSE para o provider.
        request_rows = self.conn.execute(
            "SELECT COUNT(*) FROM threat_engine_audit WHERE event_type='AI_REQUEST' AND detector='security_event_ai'"
        ).fetchone()[0]
        self.assertEqual(0, request_rows)
        inherited_rows = self.conn.execute(
            "SELECT COUNT(*) FROM threat_engine_audit WHERE event_type='AI_INHERITED'"
        ).fetchone()[0]
        self.assertEqual(1, inherited_rows)

    def test_frontend_renders_inherited_controls(self) -> None:
        path = os.path.join(ROOT, "frontend", "threat-intelligence.js")
        with open(path, encoding="utf-8") as handle:
            content = handle.read()
        self.assertIn("Análise da campanha", content)
        self.assertIn("Esta análise foi herdada da campanha correlacionada.", content)
        self.assertIn("Abrir campanha", content)
        self.assertIn("Analisar este evento individualmente", content)
        self.assertIn("analysis_source === 'campaign'", content)


if __name__ == "__main__":
    unittest.main()
