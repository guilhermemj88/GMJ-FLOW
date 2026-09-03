from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.behavioral_detection import (  # noqa: E402
    CARPET_BOMBING,
    EXPECTED_DISTRIBUTED_TRAFFIC,
    PORT_SCAN_VERTICAL,
    SUSPICIOUS_DISTRIBUTED_TRAFFIC,
    SYN_FLOOD,
    TI_INFLUENCE_ADVISORY_ONLY,
    TI_INFLUENCE_NORMAL,
    TI_INFLUENCE_REDUCED,
    UDP_FLOOD,
    AttackVector,
)
from app.services.threat_policy import (  # noqa: E402
    MitigationProposal,
    ThreatAiClassifier,
    ThreatPolicyEngine,
    ThreatSafetyGuard,
    compact_attack_vector,
    ensure_threat_policy_schema,
)


class SqliteFixture:
    def __init__(self) -> None:
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        self.path = handle.name
        handle.close()
        self._connections: list[sqlite3.Connection] = []

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        self._connections.append(conn)
        return conn

    def close(self) -> None:
        # Fechar todas as conexões abertas de forma determinística antes de
        # desvincular o arquivo: no Windows o driver mantém o handle aberto e
        # os.unlink() falha com PermissionError (WinError 32) enquanto qualquer
        # conexão ainda estiver viva.
        for conn in reversed(self._connections):
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._connections.clear()
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


def vector(**overrides) -> AttackVector:
    values = {
        "attack_type": PORT_SCAN_VERTICAL,
        "detector": "port_scan",
        "detector_score": 99,
        "confidence": 0.99,
        "first_seen": "2026-08-11T10:00:00Z",
        "last_seen": "2026-08-11T10:01:00Z",
        "src_ip": "198.51.100.7",
        "target_ip": "203.0.113.20",
        "target_prefix": "203.0.113.20/32",
        "direction": "RECEIVES",
        "baseline_deviation": 5.0,
        "features": {"unique_dst_ports": 80, "recurrence_count": 3},
        "intel_sources": ["GREYNOISE", "CEREAL2"],
        "external_correlation": True,
    }
    values.update(overrides)
    return AttackVector(**values)


class ThreatPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.db = SqliteFixture()
        with self.db.connect() as conn:
            ensure_threat_policy_schema(conn)
            conn.executescript(
                """
                CREATE TABLE detection_whitelist (
                    id INTEGER PRIMARY KEY, name TEXT, active INTEGER,
                    src_cidr TEXT, dst_cidr TEXT
                );
                CREATE TABLE bgp_connectors (
                    id INTEGER PRIMARY KEY, enabled INTEGER, peer_ip TEXT,
                    local_address TEXT, router_mgmt_ip TEXT
                );
                CREATE TABLE sensors (
                    id INTEGER PRIMARY KEY, active INTEGER, exporter_ip TEXT,
                    listener_ip TEXT, snmp_ip TEXT
                );
                CREATE TABLE bgp_protected_prefixes (
                    id INTEGER PRIMARY KEY, enabled INTEGER, cidr TEXT
                );
                CREATE TABLE system_settings (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def tearDown(self) -> None:
        self.db.close()

    def enable_auto_policy(self) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO system_settings (key, value, updated_at) "
                "VALUES ('threat_policy_auto_enabled', 'true', 'now')"
            )
            conn.commit()

    @staticmethod
    def ai(classification: str = PORT_SCAN_VERTICAL, confidence: float = 0.98) -> dict:
        return {
            "ok": True,
            "classification": classification,
            "confidence": confidence,
            "reason": "evidencia agregada consistente",
            "provider_type": "groq",
        }

    def test_compact_vector_never_contains_raw_flows(self) -> None:
        item = vector(features={"unique_dst_ports": 80, "raw_flows": [{"secret": "no"}], "samples": [1, 2]})
        compact = compact_attack_vector(item)
        self.assertNotIn("raw_flows", compact["features"])
        self.assertNotIn("samples", compact["features"])
        self.assertEqual(compact["features"]["unique_dst_ports"], 80)

    def test_groq_timeout_and_invalid_result_never_authorize(self) -> None:
        timeout_classifier = ThreatAiClassifier(self.db.connect, executor=lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("timeout")))
        self.assertFalse(timeout_classifier.classify(vector())["ok"])
        invalid_classifier = ThreatAiClassifier(self.db.connect, executor=lambda *args, **kwargs: {"ok": True, "structured": None})
        invalid = invalid_classifier.classify(vector())
        self.assertFalse(invalid["ok"])
        self.assertEqual(invalid["classification"], "UNKNOWN_ANOMALY")

    def test_external_match_alone_never_authorizes(self) -> None:
        item = vector(detector_score=0, baseline_deviation=0, features={}, intel_sources=["FEODO"], external_correlation=True)
        self.enable_auto_policy()
        decision = ThreatPolicyEngine(self.db.connect).evaluate(item, self.ai())
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.gates["detector_evidence"])

    def test_allowlist_and_infrastructure_are_hard_blocks(self) -> None:
        guard = ThreatSafetyGuard(self.db.connect)
        with self.db.connect() as conn:
            conn.execute("INSERT INTO detection_whitelist VALUES (1, 'trusted scanner', 1, '198.51.100.0/24', NULL)")
            conn.execute("INSERT INTO bgp_connectors VALUES (1, 1, '192.0.2.1', '192.0.2.2', '192.0.2.3')")
            conn.execute("INSERT INTO sensors VALUES (1, 1, '192.0.2.10', '192.0.2.11', '192.0.2.12')")
            conn.commit()
        allowlisted = guard.evaluate(MitigationProposal(action="discard", src_prefix="198.51.100.7/32"))
        peer = guard.evaluate(MitigationProposal(action="discard", src_prefix="192.0.2.1/32"))
        exporter = guard.evaluate(MitigationProposal(action="discard", src_prefix="192.0.2.10/32"))
        self.assertFalse(allowlisted["passed"])
        self.assertFalse(peer["passed"])
        self.assertFalse(exporter["passed"])

    def test_protected_range_is_a_hard_block(self) -> None:
        with self.db.connect() as conn:
            conn.execute("INSERT INTO bgp_protected_prefixes VALUES (1, 1, '203.0.113.0/24')")
            conn.commit()
        result = ThreatSafetyGuard(self.db.connect).evaluate(MitigationProposal(action="discard", dst_prefix="203.0.113.20/32"))
        self.assertFalse(result["passed"])
        self.assertEqual(result["protected_hits"][0]["source"], "bgp_protected_prefix")

    def test_strong_multi_signal_scan_can_pass_only_when_auto_enabled(self) -> None:
        engine = ThreatPolicyEngine(self.db.connect)
        self.enable_auto_policy()
        with patch.dict(
            os.environ,
            {
                "GMJFLOW_THREAT_POLICY_REQUIRE_GROQ": "true",
                "GMJFLOW_THREAT_POLICY_MIN_SCORE": "85",
            },
            clear=False,
        ):
            decision = engine.evaluate(vector(), self.ai())
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.proposal.src_prefix, "198.51.100.7/32")
        self.assertGreater(decision.proposal.ttl_seconds, 0)
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM threat_policy_decisions ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["decision_source"], "GMJ_FLOW")
        self.assertIn("GREYNOISE", row["intel_sources_json"])

    def test_non_groq_provider_cannot_satisfy_required_groq_gate(self) -> None:
        ai = self.ai()
        ai["provider_type"] = "openai"
        self.enable_auto_policy()
        with patch.dict(
            os.environ,
            {"GMJFLOW_THREAT_POLICY_REQUIRE_GROQ": "true"},
            clear=False,
        ):
            decision = ThreatPolicyEngine(self.db.connect).evaluate(vector(), ai)
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.gates["ai_is_groq"])

    def test_udp_port_filter_requires_seventy_percent_concentration(self) -> None:
        engine = ThreatPolicyEngine(self.db.connect)
        weak = vector(
            attack_type=UDP_FLOOD,
            src_ip="",
            features={"destination_port_distribution": {"53": 60, "123": 40}},
            intel_sources=[],
        )
        strong = vector(
            attack_type=UDP_FLOOD,
            src_ip="",
            features={"destination_port_distribution": {"53": 80, "123": 20}},
            intel_sources=[],
        )
        weak_proposal, _ = engine.proposal_for(weak)
        strong_proposal, _ = engine.proposal_for(strong)
        self.assertEqual(weak_proposal.dst_port, "")
        self.assertEqual(strong_proposal.dst_port, "53")

    # ------------------------------------------------------------------
    # TI influence na policy: ADVISORY_ONLY não pode alterar a decisão.
    # ------------------------------------------------------------------
    def _carpet_vector(self, *, with_intel: bool) -> AttackVector:
        base = dict(
            attack_type=CARPET_BOMBING,
            detector="prefix_carpet_bombing",
            detector_score=99,
            confidence=0.99,
            first_seen="2026-08-11T10:00:00Z",
            last_seen="2026-08-11T10:01:00Z",
            target_prefix="203.0.113.0/24",
            direction="RECEIVES",
            baseline_deviation=5.0,
            features={
                "traffic_classification": EXPECTED_DISTRIBUTED_TRAFFIC,
                "reason_codes": ["LIKELY_WEB_RETURN_TRAFFIC"],
                "recurrence_count": 3,
                "persistent_windows": 3,
            },
            intel_sources=[],
            external_correlation=False,
            threat_intel={},
        )
        if with_intel:
            base["intel_sources"] = ["GREYNOISE", "CEREAL2"]
            base["external_correlation"] = True
            base["threat_intel"] = {
                "source_intel": {
                    "matched_source_count": 1,
                    "match_count": 1,
                    "indicator_types": ["IP"],
                    "classifications": ["malicious"],
                    "tags": ["scanner"],
                    "intel_sources": ["GREYNOISE"],
                },
                "target_campaign_intel": {
                    "matches": 1,
                    "observations": [{"provider": "CEREAL2", "method": "coordinated"}],
                    "intel_sources": ["CEREAL2"],
                },
            }
        return AttackVector(**base)

    def test_advisory_only_intel_keeps_policy_decision_identical(self) -> None:
        engine = ThreatPolicyEngine(self.db.connect)
        self.enable_auto_policy()
        no_intel = self._carpet_vector(with_intel=False)
        advisory = self._carpet_vector(with_intel=True)
        with patch.dict(
            os.environ,
            {
                "GMJFLOW_THREAT_POLICY_REQUIRE_RELEVANT_INTEL": "true",
                "GMJFLOW_THREAT_POLICY_REQUIRE_GROQ": "true",
            },
            clear=False,
        ):
            decision_a = engine.evaluate(no_intel, self.ai(CARPET_BOMBING))
            decision_b = engine.evaluate(advisory, self.ai(CARPET_BOMBING))

        # Invariante: mesma evidência, mesmo score, mesma decisão.
        self.assertEqual(no_intel.detector_score, advisory.detector_score)
        self.assertEqual(no_intel.confidence, advisory.confidence)
        self.assertEqual(decision_a.policy_score, decision_b.policy_score)
        self.assertEqual(decision_a.allowed, decision_b.allowed)
        self.assertEqual(
            decision_a.gates["shadow_policy_verdict"],
            decision_b.gates["shadow_policy_verdict"],
        )
        self.assertEqual(
            set(decision_a.non_mitigation_reason.split(", ")),
            set(decision_b.non_mitigation_reason.split(", ")),
        )
        # O IOC permanece, mas a influência é advisory e o bônus aplicado é zero.
        self.assertEqual(TI_INFLUENCE_ADVISORY_ONLY, decision_b.gates["ti_influence"])
        self.assertEqual(0, decision_b.gates["ti_bonus_applied"])
        self.assertGreater(decision_b.gates["ti_bonus_raw"], 0)
        # Sem IOC o gate relevant_threat_intel falha; com IOC ADVISORY_ONLY
        # também deve falhar (não pode satisfazer o gate).
        self.assertFalse(decision_a.gates["relevant_threat_intel"])
        self.assertFalse(decision_b.gates["relevant_threat_intel"])

    def test_reduced_intel_is_capped_in_policy(self) -> None:
        engine = ThreatPolicyEngine(self.db.connect)
        item = vector(
            attack_type=CARPET_BOMBING,
            features={
                "traffic_classification": SUSPICIOUS_DISTRIBUTED_TRAFFIC,
                "recurrence_count": 3,
            },
            intel_sources=["GREYNOISE", "CEREAL2"],
            external_correlation=True,
            threat_intel={
                "source_intel": {"matched_source_count": 1, "intel_sources": ["GREYNOISE"]},
                "target_campaign_intel": {"matches": 1},
            },
        )
        decision = engine.evaluate(item, self.ai(CARPET_BOMBING))
        self.assertEqual(TI_INFLUENCE_REDUCED, decision.gates["ti_influence"])
        self.assertGreater(decision.gates["ti_bonus_raw"], 2)
        self.assertLessEqual(decision.gates["ti_bonus_applied"], 2)

    def test_normal_intel_applied_equals_raw(self) -> None:
        engine = ThreatPolicyEngine(self.db.connect)
        item = vector(
            attack_type=SYN_FLOOD,
            intel_sources=["GREYNOISE"],
            external_correlation=True,
            threat_intel={
                "source_intel": {"matched_source_count": 1, "c2_sources": 1, "intel_sources": ["GREYNOISE"]},
                "target_campaign_intel": {"matches": 1},
            },
        )
        decision = engine.evaluate(item, self.ai(SYN_FLOOD))
        self.assertEqual(TI_INFLUENCE_NORMAL, decision.gates["ti_influence"])
        self.assertEqual(decision.gates["ti_bonus_raw"], decision.gates["ti_bonus_applied"])
        self.assertGreater(decision.gates["ti_bonus_applied"], 0)


if __name__ == "__main__":
    unittest.main()
