"""Logic tests for TI -> RTBH candidate generation (RECOMMEND_ONLY)."""

import os
import sqlite3
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services import transit_rtbh as rtbh  # noqa: E402


def memory_connection():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


def setup_providers(conn, providers, policies):
    rtbh.ensure_transit_rtbh_schema(conn)
    for name, input_if in providers:
        conn.execute(
            """
            INSERT INTO transit_providers (name, input_if, enabled, created_at, updated_at)
            VALUES (?, ?, 1, 'x', 'x')
            """,
            (name, input_if),
        )
    for provider_id, policy in policies.items():
        conn.execute(
            """
            INSERT INTO transit_rtbh_policies (
                provider_id, enabled, standard_communities_json, large_communities_json,
                mode, min_prefix_length, max_prefix_length, min_confidence,
                min_attack_bps, min_duration_seconds, cooldown_seconds,
                allow_auto, require_manual_approval, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'x', 'x')
            """,
            (
                provider_id,
                int(policy.get("enabled", True)),
                rtbh.json_dump(policy.get("standard", [])),
                rtbh.json_dump(policy.get("large", [])),
                policy.get("mode", "MANUAL_APPROVAL"),
                int(policy.get("min_prefix_length", 32)),
                int(policy.get("max_prefix_length", 32)),
                float(policy.get("min_confidence", 0.9)),
                float(policy.get("min_attack_bps", 1e9)),
                int(policy.get("min_duration_seconds", 60)),
                int(policy.get("cooldown_seconds", 3600)),
                int(policy.get("allow_auto", False)),
                int(policy.get("require_manual_approval", True)),
            ),
        )


def carpet_incident(incident_id="inc-1", target="45.163.144.0/22"):
    return {
        "incident_id": incident_id,
        "threat_assessment_id": incident_id,
        "classification": rtbh.CLASSIFICATION_UDP_VOLUMETRIC_CARPET_BOMBING,
        "rtbh_eligible": True,
        "classification_info": {
            "classification": rtbh.CLASSIFICATION_UDP_VOLUMETRIC_CARPET_BOMBING,
            "is_carpet_bombing": True,
            "spoofing_probable": True,
            "random_ports": True,
            "dominant_port": "",
        },
        "target_prefix": target,
        "confidence": 0.99,
        "duration_seconds": 900,
        "observed_bps": 200_000_000.0,
        "observed_pps": 20_000.0,
        "evidence": {},
    }


def uniform_hosts():
    return [
        {"host": f"45.163.145.{host}", "bps": 1_000_000_000.0, "pps": 100.0}
        for host in range(1, 25)
    ]


def concentrated_hosts():
    return [
        {"host": "45.163.145.74", "bps": 60_000_000_000.0, "pps": 5_000.0},
        {"host": "45.163.145.73", "bps": 20_000_000_000.0, "pps": 2_000.0},
        {"host": "45.163.145.75", "bps": 10_000_000.0, "pps": 100.0},
    ]


class CandidateGenerationLogicTests(unittest.TestCase):
    def test_provider_without_community_creates_review_required(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {"standard": [], "large": []}})
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        with mock.patch.dict(os.environ, {"RTBH_EXECUTION_ENABLED": "false"}):
            created = rtbh.generate_rtbh_candidates_from_rows(
                conn, carpet_incident(), concentrated_hosts(), ingress,
                estimate_multiplier=1.0,
            )
        self.assertGreaterEqual(len(created), 1)
        for item in created:
            self.assertEqual(item["status"], rtbh.CANDIDATE_STATUS_REVIEW_REQUIRED)
            self.assertTrue(item["policy_configured"])

    def test_provider_disabled_not_used(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284), ("SEABORN", 220)], {1: {}, 2: {}})
        conn.execute("UPDATE transit_providers SET enabled = 0 WHERE name = 'SEABORN'")
        ingress = [
            {"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0},
            {"input_if": 220, "bps": 50_000_000.0, "pps": 5_000.0},
        ]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn, carpet_incident(), concentrated_hosts(), ingress, estimate_multiplier=1.0
        )
        provider_names = {item["provider_name"] for item in created}
        self.assertIn("CIRION", provider_names)
        self.assertNotIn("SEABORN", provider_names)

    def test_multi_transit_generates_provider_specific_candidates(self):
        conn = memory_connection()
        setup_providers(
            conn,
            [("CIRION", 284), ("SEABORN", 220), ("SEMPRE", 202)],
            {1: {}, 2: {}, 3: {}},
        )
        ingress = [
            {"input_if": 284, "bps": 508_000_000.0, "pps": 50_800.0},
            {"input_if": 220, "bps": 227_000_000.0, "pps": 22_700.0},
            {"input_if": 202, "bps": 222_000_000.0, "pps": 22_200.0},
        ]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn, carpet_incident(), concentrated_hosts(), ingress, estimate_multiplier=1.0
        )
        self.assertEqual(len(created), 6)  # 2 victims x 3 providers
        providers = {item["provider_name"] for item in created}
        self.assertEqual(providers, {"CIRION", "SEABORN", "SEMPRE"})
        cirion = [item for item in created if item["provider_name"] == "CIRION"][0]
        self.assertAlmostEqual(cirion["attack_share_provider"], 0.5308, places=3)

    def test_carpet_bombing_does_not_blackhole_parent_prefix_automatically(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn, carpet_incident(), uniform_hosts(), ingress, estimate_multiplier=1.0
        )
        self.assertEqual(len(created), 1)
        candidate = created[0]
        self.assertEqual(candidate["action_type"], rtbh.ACTION_TYPE_MANUAL_LARGE_PREFIX_RTBH)
        self.assertEqual(candidate["target_prefix"], "45.163.144.0/22")
        self.assertEqual(candidate["collateral_risk"], rtbh.COLLATERAL_CRITICAL)
        self.assertTrue(candidate["no_safe_selective_rtbh_candidate"])
        self.assertTrue(candidate["large_prefix_manual_only"])
        self.assertEqual(candidate["status"], rtbh.CANDIDATE_STATUS_REVIEW_REQUIRED)
        self.assertIn("tornará todo o prefixo indisponível", candidate["reason"])

    def test_selective_victims_create_rtbh_candidates(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn, carpet_incident(), concentrated_hosts(), ingress, estimate_multiplier=1.0
        )
        targets = {item["target_prefix"] for item in created}
        self.assertEqual(targets, {"45.163.145.74/32", "45.163.145.73/32"})
        for item in created:
            self.assertEqual(item["action_type"], rtbh.ACTION_TYPE_RTBH)
            self.assertFalse(item["large_prefix_manual_only"])

    def test_prefix_outside_policy_constraints_skipped(self):
        conn = memory_connection()
        setup_providers(
            conn,
            [("CIRION", 284)],
            {1: {"min_prefix_length": 24, "max_prefix_length": 24}},
        )
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        # Concentrated hosts produce /32 selective victims, outside the
        # provider's [24,24] prefix constraints -> skipped entirely.
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn, carpet_incident(), concentrated_hosts(), ingress, estimate_multiplier=1.0
        )
        self.assertEqual(created, [])

    def test_uniform_attack_offers_manual_large_prefix(self):
        conn = memory_connection()
        setup_providers(
            conn,
            [("CIRION", 284)],
            {1: {"min_prefix_length": 24, "max_prefix_length": 24}},
        )
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        # Uniform spread over a /24: no selective victim; the large prefix
        # offer is created as MANUAL ONLY with collateral CRITICAL.
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            carpet_incident(target="45.163.145.0/24"),
            uniform_hosts(),
            ingress,
            estimate_multiplier=1.0,
        )
        self.assertEqual(len(created), 1)
        candidate = created[0]
        self.assertEqual(candidate["action_type"], rtbh.ACTION_TYPE_MANUAL_LARGE_PREFIX_RTBH)
        self.assertEqual(candidate["collateral_risk"], rtbh.COLLATERAL_CRITICAL)
        self.assertEqual(candidate["status"], rtbh.CANDIDATE_STATUS_REVIEW_REQUIRED)

    def test_ai_cannot_override_policy(self):
        conn = memory_connection()
        setup_providers(
            conn,
            [("CIRION", 284)],
            {1: {"mode": "AUTO", "min_confidence": 0.99, "require_manual_approval": False}},
        )
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        incident = carpet_incident()
        incident["confidence"] = 0.5  # below policy minimum
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn, incident, concentrated_hosts(), ingress, estimate_multiplier=1.0
        )
        self.assertEqual(len(created), 2)
        for item in created:
            self.assertNotEqual(item["status"], rtbh.CANDIDATE_STATUS_EXECUTING)
            self.assertIn(
                item["status"],
                {rtbh.CANDIDATE_STATUS_PROPOSED, rtbh.CANDIDATE_STATUS_REVIEW_REQUIRED},
            )

    def test_dedupe_by_incident_provider_target(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        first = rtbh.generate_rtbh_candidates_from_rows(
            conn, carpet_incident(), concentrated_hosts(), ingress, estimate_multiplier=1.0
        )
        second = rtbh.generate_rtbh_candidates_from_rows(
            conn, carpet_incident(), concentrated_hosts(), ingress, estimate_multiplier=1.0
        )
        self.assertTrue(first)
        self.assertEqual(second, [])
        total = conn.execute("SELECT COUNT(*) FROM rtbh_mitigation_candidates").fetchone()[0]
        self.assertEqual(total, len(first))

    def test_protected_prefix_block_all_skips_candidates(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS bgp_protected_prefixes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cidr TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                block_rtbh INTEGER NOT NULL DEFAULT 1,
                block_auto_rtbh INTEGER NOT NULL DEFAULT 0,
                require_manual_rtbh INTEGER NOT NULL DEFAULT 1,
                block_all_rtbh INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            INSERT INTO bgp_protected_prefixes
                (cidr, enabled, block_rtbh, block_auto_rtbh, require_manual_rtbh, block_all_rtbh)
            VALUES ('45.163.145.74/32', 1, 0, 1, 1, 1)
            """
        )
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn, carpet_incident(), concentrated_hosts(), ingress, estimate_multiplier=1.0
        )
        targets = {item["target_prefix"] for item in created}
        self.assertNotIn("45.163.145.74/32", targets)
        skipped = conn.execute(
            "SELECT COUNT(*) FROM rtbh_candidate_audit WHERE action = 'candidate_skipped_protected_prefix'"
        ).fetchone()[0]
        self.assertGreaterEqual(skipped, 1)

    def test_selective_targets_with_total_bps_prevents_truncated_subset_inflation(self):
        # Uniform carpet bombing: the top-20 subset alone would look
        # "concentrated" (5% each within the subset), but the real share of
        # each /32 against the whole /22 attack is ~0.74%.
        rows = [
            {"host": f"45.163.145.{host}", "bps": 17.0, "pps": 1700.0}
            for host in range(72, 92)
        ]
        inflated = rtbh.selective_targets("45.163.144.0/22", rows)
        self.assertTrue(inflated)  # without total, the subset looks selective
        correct = rtbh.selective_targets("45.163.144.0/22", rows, total_bps=2297.0)
        self.assertEqual(correct, [])

    def test_uniform_attack_with_total_bps_generates_manual_large_prefix_only(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 200_000_000.0, "pps": 20_000.0}]
        hosts = [
            {"host": f"45.163.145.{host}", "bps": 17_000_000.0, "pps": 1700.0}
            for host in range(72, 92)
        ]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            carpet_incident(),
            hosts,
            ingress,
            estimate_multiplier=1.0,
            total_bps=2_297_000_000.0,  # real /22 total >> top subset
        )
        self.assertEqual(len(created), 1)
        self.assertEqual(
            created[0]["action_type"], rtbh.ACTION_TYPE_MANUAL_LARGE_PREFIX_RTBH
        )
        self.assertTrue(created[0]["no_safe_selective_rtbh_candidate"])

    def test_audit_trail_records_creation(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        rtbh.generate_rtbh_candidates_from_rows(
            conn, carpet_incident(), concentrated_hosts(), ingress, estimate_multiplier=1.0
        )
        rows = conn.execute(
            "SELECT * FROM rtbh_candidate_audit ORDER BY id"
        ).fetchall()
        self.assertTrue(rows)
        for row in rows:
            self.assertTrue(row["actor"])
            self.assertTrue(row["action"])
            self.assertTrue(row["created_at"])

    def test_provider_share_threshold_skips_irrelevant_transit(self):
        conn = memory_connection()
        setup_providers(
            conn,
            [("CIRION", 284), ("SEABORN", 220), ("SEMPRE", 202)],
            {1: {}, 2: {}, 3: {}},
        )
        ingress = [
            {"input_if": 284, "bps": 940_000_000.0, "pps": 94_000.0},
            {"input_if": 220, "bps": 50_000_000.0, "pps": 5_000.0},
            {"input_if": 202, "bps": 10_000_000.0, "pps": 1_000.0},  # 1% share
        ]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            carpet_incident(),
            concentrated_hosts(),
            ingress,
            estimate_multiplier=1.0,
            min_provider_share=0.05,
        )
        providers = {item["provider_name"] for item in created}
        self.assertIn("CIRION", providers)
        self.assertIn("SEABORN", providers)
        self.assertNotIn("SEMPRE", providers)

    def test_max_candidates_per_incident_caps(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284), ("SEABORN", 220)], {1: {}, 2: {}})
        hosts = [
            {"host": f"45.163.145.{host}", "bps": 5_000_000_000.0, "pps": 500.0}
            for host in range(10, 22)  # 12 hosts, each ~4-8% share
        ]
        ingress = [
            {"input_if": 284, "bps": 600_000_000.0, "pps": 60_000.0},
            {"input_if": 220, "bps": 400_000_000.0, "pps": 40_000.0},
        ]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            carpet_incident(),
            hosts,
            ingress,
            estimate_multiplier=1.0,
            max_candidates_per_incident=5,
        )
        self.assertLessEqual(len(created), 5)
        total = conn.execute("SELECT COUNT(*) FROM rtbh_mitigation_candidates").fetchone()[0]
        self.assertLessEqual(total, 5)
        skipped = conn.execute(
            "SELECT COUNT(*) FROM rtbh_candidate_audit WHERE action = 'candidate_skipped_cap'"
        ).fetchone()[0]
        self.assertGreaterEqual(skipped, 1)

    def test_scrubbing_recommendation_when_over_local_capacity(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 200_000_000.0, "pps": 20_000.0}]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            carpet_incident(),
            concentrated_hosts(),
            ingress,
            estimate_multiplier=1000.0,  # 200 Gbps estimated
            local_capacity_bps=10_000_000_000.0,  # 10 Gbps local capacity
        )
        scrub = [
            item
            for item in created
            if item["action_type"] == rtbh.ACTION_TYPE_UPSTREAM_SCRUBBING
        ]
        self.assertEqual(len(scrub), 1)
        self.assertEqual(scrub[0]["provider_id"], None)
        self.assertEqual(scrub[0]["status"], rtbh.CANDIDATE_STATUS_REVIEW_REQUIRED)

    def test_dry_run_would_announce_reflects_policy_readiness_not_execution(self):
        conn = memory_connection()
        setup_providers(
            conn,
            [("CIRION", 284)],
            {1: {"standard": ["64512:666"], "mode": "MANUAL_APPROVAL"}},
        )
        with mock.patch.dict(os.environ, {"RTBH_EXECUTION_ENABLED": "false"}):
            result = rtbh.rtbh_dry_run(
                conn,
                {"provider_id": 1, "target_prefix": "45.163.145.74/32", "input_if": 284},
            )
        # Kill switch off: the action WOULD be announced (policy ready) but
        # is never actually announced in this dry-run-only version.
        self.assertTrue(result["would_announce"])
        self.assertFalse(result["actually_announced"])
        self.assertFalse(result["execution_enabled_env"])
        self.assertIn("rtbh_execution_kill_switch_disabled", result["reason"])
        self.assertIn("dry_run_only_version_never_announces", result["reason"])

    def test_dry_run_rejects_policy_without_community(self):
        conn = memory_connection()
        setup_providers(
            conn,
            [("CIRION", 284)],
            {1: {"standard": [], "large": [], "mode": "MANUAL_APPROVAL"}},
        )
        result = rtbh.rtbh_dry_run(
            conn,
            {"provider_id": 1, "target_prefix": "45.163.145.74/32", "input_if": 284},
        )
        self.assertFalse(result["would_announce"])
        self.assertIn("no_communities_configured", result["reason"])

    def test_dry_run_rejects_provider_without_policy(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {})
        result = rtbh.rtbh_dry_run(
            conn,
            {"provider_id": 1, "target_prefix": "45.163.145.74/32", "input_if": 284},
        )
        self.assertFalse(result["would_announce"])
        self.assertFalse(result["policy_configured"])
        self.assertIn("provider_policy_not_configured", result["reason"])


if __name__ == "__main__":
    unittest.main()
