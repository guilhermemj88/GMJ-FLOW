from __future__ import annotations

import os
import sqlite3
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.network_sweep_policy import (  # noqa: E402
    BGP_NOT_READY,
    DESTINATION_INFRASTRUCTURE,
    DETECTOR_SCORE_TOO_LOW,
    EXISTING_MITIGATION,
    INSUFFICIENT_DESTINATIONS,
    NOT_CONFIRMED,
    NOT_CRITICAL,
    NOT_INBOUND,
    RECURRENCE_TOO_LOW,
    SOURCE_NOT_EXTERNAL,
    SOURCE_PROTECTED,
    TARGET_PROTECTED,
    compute_proposed_ttl,
    ensure_network_sweep_shadow_schema,
    evaluate_network_sweep,
    network_sweep_dedup_key,
)


def _candidate(**overrides):
    base = {
        "attack_type": "NETWORK_SWEEP",
        "verdict": "CONFIRMED_ATTACK",
        "severity": "CRITICAL",
        "direction": "INBOUND",
        "src_role": "EXTERNAL",
        "dst_role": "CUSTOMER",
        "src_ip": "203.0.113.50",
        "target_prefix": "186.232.160.0/24",
        "recurrence_count": 3,
        "detector_score": 94,
        "unique_destinations": 34,
        "unique_dst_ports": 12,
        "source_asn": "AS64496",
        "src_is_cgnat": False,
        "campaign_id": "",
    }
    base.update(overrides)
    return base


class NetworkSweepPolicyTest(unittest.TestCase):
    def test_ideal_case_eligible_and_would_mitigate(self) -> None:
        d = evaluate_network_sweep(_candidate(), source_protected=False, target_protected=False,
                                   existing_mitigation=False, bgp_ready=True)
        self.assertTrue(d["eligible"])
        self.assertTrue(d["would_mitigate"])
        self.assertEqual("discard", d["proposed_action"])
        self.assertEqual(2700, d["proposed_ttl"])  # recurrence 3 -> 15+15+15

    def test_likely_verdict_rejected(self) -> None:
        d = evaluate_network_sweep(_candidate(verdict="LIKELY_ATTACK"), bgp_ready=True)
        self.assertFalse(d["eligible"])
        self.assertIn(NOT_CONFIRMED, d["ineligible_reasons"])

    def test_non_critical_severity_rejected(self) -> None:
        for sev in ("HIGH", "MEDIUM", "LOW"):
            d = evaluate_network_sweep(_candidate(severity=sev), bgp_ready=True)
            self.assertFalse(d["eligible"])
            self.assertIn(NOT_CRITICAL, d["ineligible_reasons"])

    def test_outbound_rejected(self) -> None:
        d = evaluate_network_sweep(_candidate(direction="OUTBOUND"), bgp_ready=True)
        self.assertFalse(d["eligible"])
        self.assertIn(NOT_INBOUND, d["ineligible_reasons"])

    def test_internal_rejected(self) -> None:
        d = evaluate_network_sweep(_candidate(direction="INTERNAL"), bgp_ready=True)
        self.assertFalse(d["eligible"])
        self.assertIn(NOT_INBOUND, d["ineligible_reasons"])

    def test_source_customer_or_cgnat_rejected(self) -> None:
        for role in ("CUSTOMER", "CGNAT_PUBLIC", "INFRASTRUCTURE", "MANAGEMENT"):
            d = evaluate_network_sweep(_candidate(src_role=role), bgp_ready=True)
            self.assertFalse(d["eligible"])
            self.assertIn(SOURCE_NOT_EXTERNAL, d["ineligible_reasons"])

    def test_source_protected_rejected(self) -> None:
        d = evaluate_network_sweep(_candidate(), source_protected=True, bgp_ready=True)
        self.assertFalse(d["eligible"])
        self.assertIn(SOURCE_PROTECTED, d["ineligible_reasons"])

    def test_target_protected_rejected(self) -> None:
        d = evaluate_network_sweep(_candidate(), target_protected=True, bgp_ready=True)
        self.assertFalse(d["eligible"])
        self.assertIn(TARGET_PROTECTED, d["ineligible_reasons"])

    def test_destination_infrastructure_rejected(self) -> None:
        d = evaluate_network_sweep(_candidate(dst_role="INFRASTRUCTURE"), bgp_ready=True)
        self.assertFalse(d["eligible"])
        self.assertIn(DESTINATION_INFRASTRUCTURE, d["ineligible_reasons"])

    def test_recurrence_one_without_campaign_rejected(self) -> None:
        d = evaluate_network_sweep(_candidate(recurrence_count=1), bgp_ready=True)
        self.assertFalse(d["eligible"])
        self.assertIn(RECURRENCE_TOO_LOW, d["ineligible_reasons"])

    def test_recurrence_two_eligible(self) -> None:
        d = evaluate_network_sweep(_candidate(recurrence_count=2), bgp_ready=True)
        self.assertTrue(d["eligible"])

    def test_campaign_corroboration_supplies_recurrence(self) -> None:
        campaign = {"campaign_id": "C-1", "classification": "COORDINATED_SCANNING", "coordination_score": 48, "unique_sources": 5}
        d = evaluate_network_sweep(_candidate(recurrence_count=1, campaign_id="C-1"), bgp_ready=True, campaign=campaign)
        self.assertTrue(d["eligible"])
        self.assertEqual("C-1", d["evidence"]["campaign_id"])

    def test_detector_score_89_rejected(self) -> None:
        d = evaluate_network_sweep(_candidate(detector_score=89), bgp_ready=True)
        self.assertFalse(d["eligible"])
        self.assertIn(DETECTOR_SCORE_TOO_LOW, d["ineligible_reasons"])

    def test_unique_destinations_19_rejected(self) -> None:
        d = evaluate_network_sweep(_candidate(unique_destinations=19), bgp_ready=True)
        self.assertFalse(d["eligible"])
        self.assertIn(INSUFFICIENT_DESTINATIONS, d["ineligible_reasons"])

    def test_existing_mitigation_rejected(self) -> None:
        d = evaluate_network_sweep(_candidate(), existing_mitigation=True, bgp_ready=True)
        self.assertFalse(d["eligible"])
        self.assertIn(EXISTING_MITIGATION, d["ineligible_reasons"])

    def test_bgp_not_ready_rejected(self) -> None:
        d = evaluate_network_sweep(_candidate(), bgp_ready=False)
        self.assertFalse(d["eligible"])
        self.assertIn(BGP_NOT_READY, d["ineligible_reasons"])

    def test_ttl_cap(self) -> None:
        self.assertEqual(900, compute_proposed_ttl(1))
        self.assertEqual(1800, compute_proposed_ttl(2))
        self.assertEqual(2700, compute_proposed_ttl(3))
        self.assertEqual(3600, compute_proposed_ttl(4))
        self.assertEqual(3600, compute_proposed_ttl(99))

    def test_ai_fields_ignored(self) -> None:
        # AI payload may claim allow_auto / malicious, but must never change the verdict.
        malicious = _candidate(verdict="LIKELY_ATTACK", ai_recommendation="allow_auto", ai_is_malicious=True)
        base = _candidate(verdict="LIKELY_ATTACK")
        d1 = evaluate_network_sweep(base, bgp_ready=True)
        d2 = evaluate_network_sweep(malicious, bgp_ready=True)
        self.assertEqual(d1["eligible"], d2["eligible"])
        self.assertFalse(d2["eligible"])  # still gated by deterministic verdict

    def test_module_isolation_dns_and_mitigation(self) -> None:
        import inspect
        import app.services.network_sweep_policy as nsp
        source = inspect.getsource(nsp)
        # No import of any execution path, and no DNS/FlowSpec wiring.
        for forbidden in ("from app.services.automatic_mitigation", "import automatic_mitigation",
                          "from app.main", "DNS_SINGLE_FLOW_OUTBOUND", "FLOWSPEC_AUTO_BLOCK_DST_DNS"):
            self.assertNotIn(forbidden, source)
        # No execution-capable functions exposed by the evaluator.
        for name in ("announce", "withdraw", "send_flowspec"):
            self.assertFalse(hasattr(nsp, name), f"module must not expose {name}")

    def test_dedup_key_deterministic(self) -> None:
        a = network_sweep_dedup_key("pub-1", "1", 3)
        b = network_sweep_dedup_key("pub-1", "1", 3)
        c = network_sweep_dedup_key("pub-1", "1", 4)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)


class NetworkSweepShadowAuditTest(unittest.TestCase):
    def test_insert_or_ignore_dedup(self) -> None:
        conn = sqlite3.connect(":memory:")
        ensure_network_sweep_shadow_schema(conn)
        key = network_sweep_dedup_key("pub-9", "9", 2)
        args = ("2026-08-28T00:00:00Z", key, "9", "pub-9", "", "203.0.113.1", "186.232.0.0/24",
                1, 1, "discard", 1800, "[]", "{}", "network_sweep_shadow_v1")
        for _ in range(2):
            conn.execute(
                "INSERT OR IGNORE INTO network_sweep_policy_shadow_audit (created_at, dedup_key, event_id, public_id, "
                "campaign_id, source_ip, target_prefix, eligible, would_mitigate, proposed_action, proposed_ttl, "
                "ineligible_reasons_json, evidence_json, policy_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", args)
        count = conn.execute("SELECT COUNT(*) FROM network_sweep_policy_shadow_audit").fetchone()[0]
        self.assertEqual(1, count)
        conn.close()


if __name__ == "__main__":
    unittest.main()
