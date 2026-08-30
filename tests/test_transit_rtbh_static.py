"""Static surface checks for the Transit RTBH module (RECOMMEND_ONLY)."""

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


class TransitRtbhStaticTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row

    def tearDown(self):
        self.conn.close()

    def test_module_surface(self):
        for symbol in (
            "ensure_transit_rtbh_schema",
            "valid_standard_community",
            "valid_large_community",
            "validate_community_list",
            "rtbh_execution_enabled_env",
            "rtbh_version_allows_execution",
            "effective_execution_allowed",
            "classify_rtbh_incident",
            "assess_mitigation_suitability",
            "selective_targets",
            "generate_rtbh_candidates_from_rows",
            "rtbh_dry_run",
            "apply_candidate_status",
            "rtbh_report_section",
            "protected_prefix_rtbh_check",
        ):
            self.assertTrue(callable(getattr(rtbh, symbol, None)), symbol)

    def test_kill_switch_defaults_false(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RTBH_EXECUTION_ENABLED", None)
            self.assertFalse(rtbh.rtbh_execution_enabled_env())
            self.assertFalse(rtbh.rtbh_version_allows_execution())
            self.assertFalse(
                rtbh.effective_execution_allowed({"enabled": True, "mode": "AUTO"})
            )

    def test_kill_switch_effective_requires_policy_and_env(self):
        with mock.patch.dict(
            os.environ,
            {"RTBH_EXECUTION_ENABLED": "true"},
        ):
            self.assertTrue(rtbh.rtbh_execution_enabled_env())
            # Policy OFF or not AUTO never allows execution.
            self.assertFalse(
                rtbh.effective_execution_allowed({"enabled": True, "mode": "OFF"})
            )
            self.assertFalse(
                rtbh.effective_execution_allowed({"enabled": False, "mode": "AUTO"})
            )
            self.assertTrue(
                rtbh.effective_execution_allowed({"enabled": True, "mode": "AUTO"})
            )

    def test_statuses_unreachable_in_this_version(self):
        self.assertNotIn(rtbh.CANDIDATE_STATUS_EXECUTING, rtbh.REACHABLE_STATUSES)
        self.assertNotIn(rtbh.CANDIDATE_STATUS_ACTIVE, rtbh.REACHABLE_STATUSES)
        self.assertNotIn(
            rtbh.CANDIDATE_STATUS_WITHDRAW_PENDING, rtbh.REACHABLE_STATUSES
        )
        self.assertNotIn(rtbh.CANDIDATE_STATUS_WITHDRAWN, rtbh.REACHABLE_STATUSES)

    def test_community_validation(self):
        self.assertTrue(rtbh.valid_standard_community("65000:666"))
        self.assertTrue(rtbh.valid_standard_community("4294967295:65535"))
        self.assertTrue(rtbh.valid_large_community("65000:1:666"))
        for invalid in (
            "666",
            "65000:",
            "65000:666:7",
            "a:b",
            "65000:70000",
            "65000:-1",
            "",
            None,
        ):
            self.assertFalse(rtbh.valid_standard_community(invalid), invalid)
        for invalid in ("65000:1", "65000:1:2:3", "a:b:c", "65000:1:-1"):
            self.assertFalse(rtbh.valid_large_community(invalid), invalid)

    def test_validate_community_list_rejects_invalid(self):
        with self.assertRaises(ValueError):
            rtbh.validate_community_list("standard", ["65000:notaport"])
        with self.assertRaises(ValueError):
            rtbh.validate_community_list("large", ["65000:1"])
        with self.assertRaises(ValueError):
            rtbh.validate_community_list("standard", {"not": "list"})
        self.assertEqual(
            rtbh.validate_community_list("standard", ["65000:1", "65000:1"]),
            ["65000:1"],
        )

    def test_classification_udp_volumetric_carpet_bombing(self):
        result = rtbh.classify_rtbh_incident(
            "DISTRIBUTED_UDP_FLOOD",
            {
                "spoofing_likelihood": 80,
                "unique_src_ips": 500,
                "unique_dst_ports": 120,
                "unique_dst_ips": 900,
                "destination_port_distribution": {"1024": 10, "2048": 10, "3333": 10},
            },
        )
        self.assertEqual(
            result["classification"],
            rtbh.CLASSIFICATION_UDP_VOLUMETRIC_CARPET_BOMBING,
        )
        self.assertTrue(result["rtbh_eligible"])
        self.assertTrue(result["spoofing_probable"])

    def test_classification_not_eligible(self):
        result = rtbh.classify_rtbh_incident("SSH_BRUTE_FORCE", {})
        self.assertFalse(result["rtbh_eligible"])

    def test_suitability_spoofing_lowers_source_blocking(self):
        result = rtbh.assess_mitigation_suitability(
            {"spoofing_probable": True, "random_ports": True, "dominant_port": ""}
        )
        self.assertEqual(result["source_blocking_suitability"], "VERY_LOW")
        self.assertEqual(result["asn_blocking_suitability"], "VERY_LOW")
        self.assertEqual(result["port_flowspec_suitability"], "LOW")
        self.assertEqual(result["protocol_flowspec_suitability"], "LOW")
        self.assertEqual(result["source_attribution_confidence"], "LOW")
        self.assertEqual(result["blocklist_value"], "LOW")

    def test_suitability_dominant_port_raises_flowspec(self):
        result = rtbh.assess_mitigation_suitability(
            {"spoofing_probable": False, "random_ports": False, "dominant_port": "53"}
        )
        self.assertEqual(result["port_flowspec_suitability"], "HIGH")

    def test_scrubbing_very_high_over_capacity(self):
        result = rtbh.assess_mitigation_suitability(
            {"spoofing_probable": False, "random_ports": False, "dominant_port": ""},
            exceeds_local_capacity_bps=100_000_000_000,
            observed_bps=150_000_000_000,
        )
        self.assertEqual(result["scrubbing_suitability"], "VERY_HIGH")

    def test_schema_creates_tables(self):
        rtbh.ensure_transit_rtbh_schema(self.conn)
        tables = {
            row[0]
            for row in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        for table in (
            "transit_providers",
            "transit_rtbh_policies",
            "rtbh_mitigation_candidates",
            "rtbh_candidate_audit",
        ):
            self.assertIn(table, tables)

    def test_protected_prefix_check_legacy_compat(self):
        rtbh.ensure_transit_rtbh_schema(self.conn)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS bgp_protected_prefixes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cidr TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                block_rtbh INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        self.conn.execute(
            "INSERT INTO bgp_protected_prefixes (cidr, enabled, block_rtbh) VALUES (?, 1, 1)",
            ("45.163.144.0/22",),
        )
        result = rtbh.protected_prefix_rtbh_check(self.conn, "45.163.145.74/32")
        self.assertTrue(result["matched"])
        self.assertTrue(result["block_all_rtbh"])
        self.assertTrue(result["require_manual_rtbh"])

    def test_protected_prefix_check_three_level(self):
        rtbh.ensure_transit_rtbh_schema(self.conn)
        self.conn.execute(
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
        self.conn.execute(
            """
            INSERT INTO bgp_protected_prefixes
                (cidr, enabled, block_rtbh, block_auto_rtbh, require_manual_rtbh, block_all_rtbh)
            VALUES (?, 1, 0, 1, 1, 0)
            """,
            ("45.163.144.0/22",),
        )
        result = rtbh.protected_prefix_rtbh_check(self.conn, "45.163.145.74/32")
        self.assertTrue(result["matched"])
        self.assertFalse(result["block_all_rtbh"])
        self.assertTrue(result["require_manual_rtbh"])

    def test_selective_targets_concentration(self):
        rows = [
            {"host": "45.163.145.74", "bps": 60_000_000_000, "pps": 5_000},
            {"host": "45.163.145.73", "bps": 20_000_000_000, "pps": 2_000},
            {"host": "45.163.145.75", "bps": 10_000_000, "pps": 100},
            {"host": "8.8.8.8", "bps": 99_000_000_000, "pps": 9_000},
        ]
        targets = rtbh.selective_targets("45.163.144.0/22", rows)
        self.assertEqual([item["prefix"] for item in targets], ["45.163.145.74/32", "45.163.145.73/32"])

    def test_selective_targets_uniform_attack_returns_none(self):
        rows = [
            {"host": f"45.163.145.{host}", "bps": 1_000_000_000, "pps": 100}
            for host in range(1, 25)
        ]
        targets = rtbh.selective_targets("45.163.144.0/22", rows)
        self.assertEqual(targets, [])

    def test_dry_run_never_announces_and_masks_communities(self):
        rtbh.ensure_transit_rtbh_schema(self.conn)
        self.conn.execute(
            """
            INSERT INTO transit_providers (name, input_if, enabled, created_at, updated_at)
            VALUES ('CIRION', 284, 1, 'x', 'x')
            """
        )
        self.conn.execute(
            """
            INSERT INTO transit_rtbh_policies (
                provider_id, enabled, standard_communities_json, large_communities_json,
                mode, created_at, updated_at
            ) VALUES (1, 1, '["65000:666"]', '["65000:1:666"]', 'MANUAL_APPROVAL', 'x', 'x')
            """
        )
        with mock.patch.dict(os.environ, {"RTBH_EXECUTION_ENABLED": "true"}):
            result = rtbh.rtbh_dry_run(
                self.conn,
                {"provider_id": 1, "target_prefix": "45.163.145.74/32", "input_if": 284},
            )
        self.assertFalse(result["actually_announced"])
        self.assertEqual(result["standard_communities"], ["Configured"])
        self.assertEqual(result["large_communities"], ["Configured"])
        self.assertEqual(result["policy_mode"], "MANUAL_APPROVAL")
        self.assertTrue(result["dry_run_only_version"])
        with mock.patch.dict(os.environ, {"RTBH_EXECUTION_ENABLED": "true"}):
            visible = rtbh.rtbh_dry_run(
                self.conn,
                {"provider_id": 1, "target_prefix": "45.163.145.74/32", "input_if": 284},
                include_community_values=True,
            )
        self.assertEqual(visible["standard_communities"], ["65000:666"])

    def test_status_transitions_reject_execution(self):
        rtbh.ensure_transit_rtbh_schema(self.conn)
        self.conn.execute(
            """
            INSERT INTO rtbh_mitigation_candidates (
                incident_id, classification, action_type, target_prefix,
                provider_id, status, created_at, updated_at
            ) VALUES ('inc-1', 'UDP_VOLUMETRIC_CARPET_BOMBING', 'RTBH',
                      '45.163.145.74/32', NULL, 'PROPOSED', 'x', 'x')
            """
        )
        with self.assertRaises(ValueError):
            rtbh.apply_candidate_status(self.conn, 1, "EXECUTING", actor="tester")
        item = rtbh.apply_candidate_status(
            self.conn, 1, "DRY_RUN", actor="tester", reason="dry run"
        )
        self.assertEqual(item["status"], "DRY_RUN")
        self.assertFalse(item["dry_run"].get("actually_announced"))
        with self.assertRaises(ValueError):
            rtbh.apply_candidate_status(self.conn, 1, "ACTIVE", actor="tester")
        audit_rows = self.conn.execute(
            "SELECT * FROM rtbh_candidate_audit ORDER BY id"
        ).fetchall()
        self.assertEqual(len(audit_rows), 1)
        self.assertEqual(audit_rows[0]["old_state"], "PROPOSED")
        self.assertEqual(audit_rows[0]["new_state"], "DRY_RUN")


if __name__ == "__main__":
    unittest.main()
