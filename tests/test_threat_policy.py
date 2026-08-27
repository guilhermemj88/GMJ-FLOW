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
    PORT_SCAN_VERTICAL,
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


if __name__ == "__main__":
    unittest.main()
