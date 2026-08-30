"""Pools CGNAT não determinísticos: modelo, match, contexto e compatibilidade."""

import sqlite3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services import cgnat_mapping as cgnat

MAIN = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


def memory_connection():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


def add_pool(conn, name="POOL-A", prefix="45.168.202.0/24", mode="non_deterministic", active=True, notes=""):
    return cgnat.create_cgnat_pool(
        conn,
        {"name": name, "prefix": prefix, "mode": mode, "active": active, "notes": notes},
    )


class CgnatPoolMatchTests(unittest.TestCase):
    def test_ip_inside_non_deterministic_pool_identified(self):
        conn = memory_connection()
        add_pool(conn)
        result = cgnat.cgnat_pool_match(conn, "45.168.202.10")
        self.assertTrue(result["matched"])
        self.assertTrue(result["is_cgnat"])
        self.assertEqual(result["cgnat_mode"], "non_deterministic")
        self.assertEqual(result["cgnat_pool"], "45.168.202.0/24")
        self.assertEqual(result["pool_size"], 256)
        self.assertFalse(result["subscriber_attribution_available"])

    def test_ip_outside_pool_not_identified(self):
        conn = memory_connection()
        add_pool(conn)
        result = cgnat.cgnat_pool_match(conn, "8.8.8.8")
        self.assertFalse(result["matched"])
        self.assertFalse(result["is_cgnat"])
        self.assertEqual(result["cgnat_pool"], "")

    def test_subnet_equal_to_pool_coverage_100(self):
        conn = memory_connection()
        add_pool(conn)
        context = cgnat.cgnat_pool_overlap_context(conn, "45.168.202.0/24", unique_targets=256)
        self.assertEqual(context["context"], "CGNAT_POOL")
        self.assertEqual(context["pool_size"], 256)
        self.assertEqual(context["cgnat_pool_coverage"], 1.0)
        self.assertEqual(context["overlap"], "equal")

    def test_subset_coverage_correct(self):
        conn = memory_connection()
        add_pool(conn)
        context = cgnat.cgnat_pool_overlap_context(conn, "45.168.202.0/25", unique_targets=64)
        self.assertEqual(context["context"], "CGNAT_POOL")
        self.assertEqual(context["pool_size"], 256)
        self.assertEqual(context["unique_targets_reached"], 64)
        self.assertEqual(context["cgnat_pool_coverage"], 0.25)
        self.assertEqual(context["overlap"], "target_inside_pool")

    def test_overlapping_pools_most_specific_wins(self):
        conn = memory_connection()
        add_pool(conn, name="BROAD", prefix="45.168.0.0/16")
        add_pool(conn, name="SPECIFIC", prefix="45.168.202.0/24")
        result = cgnat.cgnat_pool_match(conn, "45.168.202.77")
        self.assertTrue(result["matched"])
        self.assertEqual(result["cgnat_pool"], "45.168.202.0/24")
        self.assertEqual(result["cgnat_pool_name"], "SPECIFIC")

    def test_inactive_pool_ignored(self):
        conn = memory_connection()
        add_pool(conn, active=False)
        result = cgnat.cgnat_pool_match(conn, "45.168.202.10")
        self.assertFalse(result["matched"])
        listed = cgnat.list_cgnat_pools(conn, include_inactive=True)
        self.assertEqual(len(listed), 1)
        self.assertFalse(listed[0]["active"])

    def test_non_deterministic_never_returns_subscriber_attribution(self):
        conn = memory_connection()
        add_pool(conn)
        result = cgnat.cgnat_pool_match(conn, "45.168.202.200")
        self.assertTrue(result["is_cgnat"])
        self.assertFalse(result["subscriber_attribution_available"])
        for forbidden in ("private_ip", "subscriber_id", "subscriber_name", "public_port", "port_start"):
            self.assertNotIn(forbidden, result)

    def test_deterministic_existing_mapping_still_works(self):
        conn = memory_connection()
        cgnat.ensure_cgnat_schema(conn)
        now = cgnat.utc_now_iso()
        cursor = conn.execute(
            "INSERT INTO cgnat_import_batches (filename, original_filename, file_hash, status, created_at) "
            "VALUES ('m.txt', 'm.txt', 'h1', 'active', ?)",
            (now,),
        )
        batch_id = int(cursor.lastrowid)
        conn.execute(
            "INSERT INTO cgnat_port_mappings (batch_id, source_type, source_filename, public_ip, private_ip, "
            "protocol, port_start, port_end, subscriber_id, active, created_at, updated_at) "
            "VALUES (?, 'mikrotik', 'm.txt', '45.168.202.10', '100.64.0.5', 'any', 1024, 2048, 'SUB-1', 1, ?, ?)",
            (batch_id, now, now),
        )
        conn.commit()
        resolved = cgnat.resolve_cgnat_subscriber(conn, "45.168.202.10", 1500, "tcp")
        self.assertTrue(resolved["matched"])
        self.assertFalse(resolved["ambiguous"])
        self.assertEqual(resolved["private_ip"], "100.64.0.5")

    def test_deterministic_pool_marks_attribution_available(self):
        conn = memory_connection()
        add_pool(conn, mode="deterministic")
        result = cgnat.cgnat_pool_match(conn, "45.168.202.10")
        self.assertTrue(result["is_cgnat"])
        self.assertEqual(result["cgnat_mode"], "deterministic")
        self.assertTrue(result["subscriber_attribution_available"])


class CgnatPoolStaticTests(unittest.TestCase):
    def test_pool_endpoints_exist(self):
        for fragment in (
            '@app.get("/api/cgnat/pools")',
            '@app.post("/api/cgnat/pools")',
            '@app.put("/api/cgnat/pools/{pool_id}")',
            '@app.delete("/api/cgnat/pools/{pool_id}")',
            '@app.get("/api/cgnat/pool-match")',
        ):
            self.assertIn(fragment, MAIN)

    def test_enrichment_exposes_pool_fields_without_inventing_subscriber(self):
        enrichment = MAIN[MAIN.find("def enrich_anomaly_event_with_cgnat"):MAIN.find("def fetch_anomaly_mitigation_context")]
        for key in ('"is_cgnat"', '"cgnat_mode"', '"cgnat_pool"', '"cgnat_pool_name"', '"subscriber_attribution_available"'):
            self.assertIn(key, enrichment)
        self.assertIn('"pool_non_deterministic"', enrichment)
        self.assertIn("atribuição de assinante indisponível", enrichment)
        self.assertIn('"target_is_cgnat"', enrichment)
        self.assertIn('"cgnat_pool_coverage"', enrichment)

    def test_rtbh_context_attached_without_execution_changes(self):
        start = MAIN.find("def generate_rtbh_candidates_from_behavioral_decision")
        end = MAIN.find("\ndef ", start + 10)
        rtbh_generator = MAIN[start:end]
        self.assertIn("cgnat_pool_overlap_context", rtbh_generator)
        self.assertIn('"target_is_cgnat": True', rtbh_generator)
        self.assertIn('"cgnat_pool_coverage"', rtbh_generator)

    def test_ui_pools_section_and_drawer(self):
        self.assertIn("Pools CGNAT", FRONTEND)
        self.assertIn("saveCgnatPoolButton", FRONTEND)
        self.assertIn("cgnatPoolsTable", FRONTEND)
        self.assertIn("loadCgnatPools", FRONTEND)
        self.assertIn("Atribuição de assinante: indisponível", FRONTEND)
        self.assertIn("Contexto do alvo", FRONTEND)
        self.assertIn("% do pool", FRONTEND)


if __name__ == "__main__":
    unittest.main()
