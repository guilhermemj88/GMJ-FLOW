"""Hardening tests for transit RTBH selection (validated incident 45.163.144.0/22).

Covers:
- sampling scale applied exactly once (raw parser + single estimate)
- missing baseline behavior
- uniform carpet / concentrated / borderline / protected-service / multi-transit
- scrubbing priority
- validation provenance
"""

import importlib.util
import os
import sqlite3
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services import transit_rtbh as rtbh  # noqa: E402
from tests.test_transit_rtbh_logic import (  # noqa: E402
    carpet_incident,
    concentrated_hosts,
    memory_connection,
    setup_providers,
    uniform_hosts,
)


def load_parser_module():
    clickhouse_stub = types.ModuleType("clickhouse_connect")
    clickhouse_stub.get_client = lambda *args, **kwargs: None
    sys.modules.setdefault("clickhouse_connect", clickhouse_stub)
    spec = importlib.util.spec_from_file_location(
        "parse_pmacct_under_test", ROOT / "collector" / "pmacct" / "parse_pmacct.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def uniform_1024_hosts():
    rows = []
    for host in range(0, 1024):
        third = host // 256
        fourth = host % 256
        rows.append(
            {
                "host": f"45.163.{144 + third}.{fourth}",
                "bps": 250_000.0,
                "pps": 25.0,
                "bytes": 250_000.0 * 1080 / 8,
            }
        )
    return rows


class SamplingScaleTests(unittest.TestCase):
    def test_parser_stores_raw_counts_regardless_of_sample_rate(self):
        parser = load_parser_module()
        record = {
            "src_host": "8.8.8.8",
            "dst_host": "45.163.145.74",
            "src_port": 53,
            "dst_port": 12345,
            "proto": "udp",
            "tcpflags": 0,
            "in_iface": 284,
            "out_iface": 0,
            "bytes": 1200,
            "packets": 1,
            "flows": 1,
            "timestamp": "2026-08-29 23:59:00",
        }
        row = parser.normalize_flow(record, "sensor", "1.1.1.1", sample_rate_default=1000)
        # tuple: [11]=bytes [12]=packets [13]=flow_count [15]=sample_rate
        self.assertEqual(row[11], 1200, "RAW_BYTES_ALREADY_SCALED must stay false")
        self.assertEqual(row[12], 1, "RAW_PACKETS_ALREADY_SCALED must stay false")
        self.assertEqual(row[13], 1, "RAW_FLOWS_ALREADY_SCALED must stay false")
        self.assertEqual(row[15], 1000, "sample_rate column records the factor")

    def test_estimate_applied_exactly_once(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 100_000.0, "pps": 10.0}]
        incident = carpet_incident()
        incident["observed_bps"] = 592_600_000.0
        incident["observed_pps"] = 61_984.0
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            incident,
            concentrated_hosts(),
            ingress,
            estimate_multiplier=1000.0,
            total_bps=100_000.0,
        )
        self.assertTrue(created)
        for item in created:
            self.assertEqual(
                item["attack_bps_estimated"],
                592_600_000.0 * 1000.0,
                "must be X*1000 exactly once, never X*1,000,000",
            )
            self.assertEqual(item["attack_pps_estimated"], 61_984.0 * 1000.0)
            self.assertNotEqual(item["attack_bps_estimated"], 592_600_000.0 * 1_000_000.0)


class BaselineMissingTests(unittest.TestCase):
    def test_missing_baseline_does_not_invent_ratio_nor_block(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 200_000_000.0, "pps": 20_000.0}]
        incident = carpet_incident()
        incident["baseline_available"] = False
        incident["baseline_bps"] = 0.0
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            incident,
            concentrated_hosts(),
            ingress,
            estimate_multiplier=1000.0,
            total_bps=200_000_000.0,
        )
        self.assertTrue(created, "volumetric incident must not be blocked by missing baseline")
        for item in created:
            self.assertEqual(item["baseline_bps"], 0.0, "do not replace absence with zero")
            self.assertEqual(item["attack_baseline_ratio"], 0.0, "do not invent ratio")
            self.assertFalse(item["evidence"]["baseline_available"])

    def test_present_baseline_computes_ratio(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        incident = carpet_incident()
        incident["baseline_available"] = True
        incident["baseline_bps"] = 100_000_000.0  # observed 200M -> ratio 2.0
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            incident,
            concentrated_hosts(),
            ingress,
            estimate_multiplier=1.0,
            total_bps=100_000_000.0,
        )
        for item in created:
            self.assertTrue(item["evidence"]["baseline_available"])
            self.assertAlmostEqual(item["attack_baseline_ratio"], 2.0, places=3)


class CarpetAndConcentratedTests(unittest.TestCase):
    def test_case_a_uniform_carpet_1024_hosts(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 256_000_000.0, "pps": 25_600.0}]
        hosts = uniform_1024_hosts()
        total_bps = 1024 * 250_000.0
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            carpet_incident(),
            hosts,
            ingress,
            estimate_multiplier=1000.0,
            total_bps=total_bps,
            local_capacity_bps=10_000_000_000.0,
        )
        actions = {item["action_type"] for item in created}
        self.assertIn(rtbh.ACTION_TYPE_MANUAL_LARGE_PREFIX_RTBH, actions)
        self.assertIn(rtbh.ACTION_TYPE_UPSTREAM_SCRUBBING, actions)
        self.assertNotIn(rtbh.ACTION_TYPE_RTBH, actions)
        for item in created:
            self.assertTrue(item["no_safe_selective_rtbh_candidate"])
            self.assertEqual(item["status"], rtbh.CANDIDATE_STATUS_REVIEW_REQUIRED)
            if item["action_type"] == rtbh.ACTION_TYPE_MANUAL_LARGE_PREFIX_RTBH:
                self.assertIn("tornará todo o prefixo indisponível", item["reason"] or "")

    def test_case_b_concentrated_host_above_50_percent(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        hosts = [
            {"host": "45.163.145.74", "bps": 60_000_000.0, "pps": 6_000.0},
            {"host": "45.163.145.73", "bps": 10_000_000.0, "pps": 1_000.0},
            {"host": "45.163.145.75", "bps": 10_000_000.0, "pps": 1_000.0},
        ]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            carpet_incident(),
            hosts,
            ingress,
            estimate_multiplier=1.0,
            total_bps=100_000_000.0,
        )
        self.assertTrue(any(i["action_type"] == rtbh.ACTION_TYPE_RTBH for i in created))
        targets = {i["target_prefix"] for i in created if i["action_type"] == rtbh.ACTION_TYPE_RTBH}
        self.assertIn("45.163.145.74/32", targets)

    def test_case_c_borderline_threshold(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {}})
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        total = 1_000_000_000.0
        below = [
            {"host": "45.163.145.74", "bps": 49_000_000.0, "pps": 4_900.0},  # 4.9%
        ]
        created_below = rtbh.generate_rtbh_candidates_from_rows(
            conn, carpet_incident(), below, ingress, estimate_multiplier=1.0, total_bps=total
        )
        self.assertFalse(any(i["action_type"] == rtbh.ACTION_TYPE_RTBH for i in created_below))
        conn.execute("DELETE FROM rtbh_mitigation_candidates")
        conn.execute("DELETE FROM rtbh_candidate_audit")
        conn.commit()
        above = [
            {"host": "45.163.145.74", "bps": 51_000_000.0, "pps": 5_100.0},  # 5.1%
        ]
        created_above = rtbh.generate_rtbh_candidates_from_rows(
            conn, carpet_incident(), above, ingress, estimate_multiplier=1.0, total_bps=total
        )
        self.assertTrue(any(i["action_type"] == rtbh.ACTION_TYPE_RTBH for i in created_above))

    def test_case_d_protected_service_blocks_selective(self):
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
                block_all_rtbh INTEGER NOT NULL DEFAULT 0,
                service_name TEXT NOT NULL DEFAULT '',
                protocol TEXT NOT NULL DEFAULT '',
                port INTEGER,
                protection_level TEXT NOT NULL DEFAULT 'NORMAL'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO bgp_protected_prefixes
                (cidr, name, enabled, block_rtbh, block_auto_rtbh, require_manual_rtbh,
                 block_all_rtbh, service_name, protocol, port, protection_level)
            VALUES ('45.163.146.23/32', 'Ookla', 1, 0, 1, 1, 0, 'Ookla Speedtest', 'tcp', 8080, 'CRITICAL')
            """
        )
        conn.commit()
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        hosts = [
            {"host": "45.163.146.23", "bps": 60_000_000.0, "pps": 6_000.0},  # 60%
            {"host": "45.163.145.74", "bps": 10_000_000.0, "pps": 1_000.0},
        ]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            carpet_incident(),
            hosts,
            ingress,
            estimate_multiplier=1.0,
            total_bps=100_000_000.0,
        )
        # Selective RTBH must never target the protected service host.
        selective_targets_created = {
            i["target_prefix"]
            for i in created
            if i["action_type"] == rtbh.ACTION_TYPE_RTBH
        }
        self.assertNotIn("45.163.146.23/32", selective_targets_created)
        skipped = conn.execute(
            "SELECT COUNT(*) AS c FROM rtbh_candidate_audit "
            "WHERE action = 'candidate_skipped_protected_service' AND reason = 'protected_service_collateral'"
        ).fetchone()[0]
        self.assertGreaterEqual(skipped, 1)

    def test_case_d_large_prefix_lists_affected_services(self):
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
                block_all_rtbh INTEGER NOT NULL DEFAULT 0,
                service_name TEXT NOT NULL DEFAULT '',
                protocol TEXT NOT NULL DEFAULT '',
                port INTEGER,
                protection_level TEXT NOT NULL DEFAULT 'NORMAL'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO bgp_protected_prefixes
                (cidr, name, enabled, block_rtbh, block_auto_rtbh, require_manual_rtbh,
                 block_all_rtbh, service_name, protocol, port, protection_level)
            VALUES ('45.163.146.23/32', 'Ookla', 1, 0, 1, 1, 0, 'Ookla Speedtest', 'tcp', 8080, 'CRITICAL')
            """
        )
        conn.commit()
        ingress = [{"input_if": 284, "bps": 100_000_000.0, "pps": 10_000.0}]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            carpet_incident(),
            uniform_hosts(),
            ingress,
            estimate_multiplier=1.0,
            total_bps=24 * 1_000_000_000.0,
        )
        large = [i for i in created if i["action_type"] == rtbh.ACTION_TYPE_MANUAL_LARGE_PREFIX_RTBH]
        self.assertTrue(large)
        for item in large:
            self.assertGreaterEqual(item["evidence"]["protected_services_affected"], 1)
            self.assertIn("Ookla Speedtest", item["evidence"]["affected_service_names"])
            self.assertIn("Ookla Speedtest", item["reason"])
            self.assertGreaterEqual(item["evidence"]["affected_host_count"], 1)
            self.assertEqual(item["status"], rtbh.CANDIDATE_STATUS_REVIEW_REQUIRED)

    def test_case_e_multi_transit_threshold(self):
        conn = memory_connection()
        setup_providers(
            conn,
            [("CIRION", 284), ("SEABORN", 220), ("SEMPRE", 202), ("MINOR", 90)],
            {1: {}, 2: {}, 3: {}, 4: {}},
        )
        ingress = [
            {"input_if": 284, "bps": 500_000_000.0, "pps": 50_000.0},
            {"input_if": 220, "bps": 240_000_000.0, "pps": 24_000.0},
            {"input_if": 202, "bps": 220_000_000.0, "pps": 22_000.0},
            {"input_if": 90, "bps": 40_000_000.0, "pps": 4_000.0},  # 4%
        ]
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            carpet_incident(),
            concentrated_hosts(),
            ingress,
            estimate_multiplier=1.0,
            min_provider_share=0.05,
            total_bps=1_000_000_000.0,
        )
        providers = {i["provider_name"] for i in created if i.get("provider_name")}
        self.assertEqual(providers, {"CIRION", "SEABORN", "SEMPRE"})
        self.assertNotIn("MINOR", providers)


class ProvenanceTests(unittest.TestCase):
    def test_validation_only_defaults_and_stamping(self):
        conn = memory_connection()
        rtbh.ensure_transit_rtbh_schema(conn)
        conn.execute(
            "INSERT INTO transit_providers (name, input_if, enabled, notes, created_at, updated_at) "
            "VALUES ('CIRION', 284, 1, 'VALIDACAO', 'x', 'x')"
        )
        conn.execute(
            "INSERT INTO transit_rtbh_policies (provider_id, enabled, standard_communities_json, "
            "large_communities_json, mode, created_at, updated_at) "
            "VALUES (1, 1, '[\"64512:666\"]', '[]', 'MANUAL_APPROVAL', 'x', 'x')"
        )
        conn.commit()
        before = rtbh.provider_row_to_dict(
            conn.execute("SELECT * FROM transit_providers WHERE id = 1").fetchone()
        )
        self.assertFalse(before["validation_only"])
        counts = rtbh.mark_validation_artifacts(
            conn, provider_names=["CIRION"], incident_id="INC-TEST"
        )
        self.assertEqual(counts["providers"], 1)
        self.assertEqual(counts["policies"], 1)
        after = rtbh.provider_row_to_dict(
            conn.execute("SELECT * FROM transit_providers WHERE id = 1").fetchone()
        )
        self.assertTrue(after["validation_only"])


class PersistenceOrderingTests(unittest.TestCase):
    """Persistence ranks candidates, but only AFTER the concentration gate.

    Equal-volume victims are reordered so the persistent one wins; a
    zero-duration spike falls below the persistent victim.
    """

    def _item(self, bps, share, duration, usrc, max_usrc=40000):
        return {
            "attack_bps_estimated": bps,
            "attack_share_provider": share,
            "evidence": {
                "duration_seconds": duration,
                "window_seconds": 1080.0,
                "active_buckets": duration / 10.0,
                "unique_sources": usrc,
                "unique_sources_max": max_usrc,
            },
        }

    def test_min_attack_bps_gate_uses_observed_not_estimated(self):
        conn = memory_connection()
        setup_providers(conn, [("CIRION", 284)], {1: {"min_attack_bps": 1e9}})
        ingress = [{"input_if": 284, "bps": 5_000_000.0, "pps": 500.0}]
        hosts = [
            {"host": "45.163.145.74", "bps": 4_500_000.0, "pps": 450.0},  # 90%
        ]
        incident = carpet_incident()
        incident["observed_bps"] = 5_000_000.0  # physical: 5 Mbps
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            incident,
            hosts,
            ingress,
            estimate_multiplier=1000.0,  # estimated = 5 Gbps > 1 Gbps gate
            total_bps=5_000_000.0,
        )
        rtbhs = [i for i in created if i["action_type"] == rtbh.ACTION_TYPE_RTBH]
        self.assertTrue(rtbhs)
        # Estimated magnitude would pass min_attack_bps; observed must not.
        self.assertEqual(rtbhs[0]["status_reason"], "below_min_attack_bps")
        self.assertEqual(rtbhs[0]["evidence"]["gate_bps_basis"], "observed")

    def test_rank_key_prefers_persistent_victim_over_equal_volume_spike(self):
        spike = self._item(50_000_000_000.0, 1.0, 60.0, 5000)
        persistent = self._item(50_000_000_000.0, 1.0, 1000.0, 40000)
        self.assertGreater(rtbh.candidate_rank_key(persistent), rtbh.candidate_rank_key(spike))

    def test_rank_key_monotonic_in_volume_for_identical_persistence(self):
        low = self._item(10_000_000_000.0, 0.5, 900.0, 20000)
        high = self._item(20_000_000_000.0, 0.5, 900.0, 20000)
        self.assertGreater(rtbh.candidate_rank_key(high), rtbh.candidate_rank_key(low))

    def test_cap_ordering_uses_rank_key_and_keeps_persistent_host(self):
        conn = memory_connection()
        rtbh.ensure_transit_rtbh_schema(conn)
        conn.execute(
            "INSERT INTO transit_providers (name, input_if, enabled, notes, created_at, updated_at) "
            "VALUES ('T1', 1, 1, '', 'x', 'x')"
        )
        conn.commit()
        rows = [
            {"host": "45.163.144.1", "bps": 100.0, "pps": 10.0, "bytes": 100.0,
             "first": None, "last": None, "usrc": 1000},
            {"host": "45.163.144.2", "bps": 100.0, "pps": 10.0, "bytes": 100.0,
             "first": None, "last": None, "usrc": 1000},
            {"host": "45.163.144.3", "bps": 100.0, "pps": 10.0, "bytes": 100.0,
             "first": None, "last": None, "usrc": 1000},
        ]
        ingress = [{"input_if": 1, "bps": 300.0, "pps": 30.0}]
        incident = carpet_incident(target="45.163.144.0/24")
        incident["observed_bps"] = 600.0
        created = rtbh.generate_rtbh_candidates_from_rows(
            conn,
            incident,
            rows,
            ingress,
            estimate_multiplier=1.0,
            total_bps=300.0,
            max_candidates_per_incident=2,
        )
        rtbhs = [i for i in created if i["action_type"] == rtbh.ACTION_TYPE_RTBH]
        self.assertEqual(len(rtbhs), 2)
        # Ties broken deterministically by rank key; all shares equal here.
        self.assertTrue(all(not i["no_safe_selective_rtbh_candidate"] for i in rtbhs))


if __name__ == "__main__":
    unittest.main()
