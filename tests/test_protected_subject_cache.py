"""Regression for the cached protected-subject lookup (SQLite Phase 2A).

The behavioral engine's ``update_prefix_baselines`` used to call
``_is_protected_subject(conn, prefix)`` once per prefix, which re-read the same
protection tables (~4-6 SELECTs) for every prefix inside the persist
transaction. This test proves:

- ``load_protected_subject_context`` + ``is_protected_subject_cached`` return
  exactly the same result as the DB-backed ``_is_protected_subject``;
- the protection data is loaded once and the per-prefix lookup is pure (zero
  additional SQLite queries), so the query count no longer grows with N.
"""

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
    _is_protected_subject,
    is_protected_subject_cached,
    load_protected_subject_context,
)


class CountingConnection:
    """Wraps a real connection and counts ``execute`` calls (queries)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self.execute_count = 0

    def execute(self, sql: str, *params):
        self.execute_count += 1
        return self._conn.execute(sql, *params)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE detection_whitelist (src_cidr TEXT, dst_cidr TEXT, active INTEGER)")
    conn.execute("CREATE TABLE bgp_protected_prefixes (cidr TEXT, enabled INTEGER)")
    conn.execute("CREATE TABLE threat_network_contexts (protected_ranges_json TEXT, enabled INTEGER)")
    conn.execute("CREATE TABLE bgp_connectors (peer_ip TEXT, local_address TEXT, router_mgmt_ip TEXT, enabled INTEGER)")
    conn.execute("CREATE TABLE sensors (exporter_ip TEXT, listener_ip TEXT, snmp_ip TEXT, active INTEGER)")
    conn.commit()


def _seed_data(conn: sqlite3.Connection) -> None:
    conn.execute("INSERT INTO detection_whitelist (src_cidr, dst_cidr, active) VALUES ('198.51.100.0/24', '203.0.114.0/24', 1)")
    conn.execute("INSERT INTO bgp_protected_prefixes (cidr, enabled) VALUES ('203.0.115.0/24', 1)")
    conn.execute("INSERT INTO threat_network_contexts (protected_ranges_json, enabled) VALUES ('[\"192.0.2.0/24\"]', 1)")
    conn.execute("INSERT INTO bgp_connectors (peer_ip, local_address, router_mgmt_ip, enabled) VALUES ('203.0.116.1', '203.0.116.2', '203.0.116.3', 1)")
    conn.execute("INSERT INTO sensors (exporter_ip, listener_ip, snmp_ip, active) VALUES ('203.0.117.1', '203.0.117.2', '203.0.117.3', 1)")
    conn.commit()


SUBJECT_CASES = [
    ("203.0.113.10", False),   # public, unprotected
    ("10.0.0.5", True),        # RFC1918
    ("203.0.114.7", True),     # detection_whitelist dst_cidr
    ("198.51.100.7", True),    # detection_whitelist src_cidr
    ("203.0.115.7", True),     # bgp_protected_prefixes
    ("192.0.2.7", True),       # threat_network_contexts
    ("2001:db8::1", False),    # IPv6, unprotected
    ("fc00::1", True),         # IPv6 ULA
    ("203.0.116.1", True),     # exact host (bgp_connectors.peer_ip)
    ("203.0.117.2", True),     # exact host (sensors.listener_ip)
]


class ProtectedSubjectCacheTest(unittest.TestCase):
    def setUp(self) -> None:
        self._old_env = os.environ.get("GMJFLOW_THREAT_PROTECTED_RANGES")
        os.environ["GMJFLOW_THREAT_PROTECTED_RANGES"] = ""

    def tearDown(self) -> None:
        if self._old_env is None:
            os.environ.pop("GMJFLOW_THREAT_PROTECTED_RANGES", None)
        else:
            os.environ["GMJFLOW_THREAT_PROTECTED_RANGES"] = self._old_env

    def _db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        _create_schema(conn)
        _seed_data(conn)
        return conn

    def test_equivalence_between_db_backed_and_cached(self) -> None:
        conn = self._db()
        context = load_protected_subject_context(conn)
        for subject, _expected in SUBJECT_CASES:
            db_backed = _is_protected_subject(conn, subject)
            cached = is_protected_subject_cached(subject, context)
            self.assertEqual(db_backed, cached, f"subject={subject}")

    def test_expected_protection_results(self) -> None:
        conn = self._db()
        context = load_protected_subject_context(conn)
        for subject, expected in SUBJECT_CASES:
            self.assertEqual(expected, is_protected_subject_cached(subject, context), f"subject={subject}")

    def test_common_prefix_not_protected(self) -> None:
        conn = self._db()
        context = load_protected_subject_context(conn)
        self.assertFalse(is_protected_subject_cached("45.168.200.0/22", context))

    def test_optional_table_missing_keeps_semantics(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        # Only create the whitelist — the other tables are absent.
        conn.execute("CREATE TABLE detection_whitelist (src_cidr TEXT, dst_cidr TEXT, active INTEGER)")
        conn.execute("INSERT INTO detection_whitelist (src_cidr, dst_cidr, active) VALUES ('198.51.100.0/24', '203.0.114.0/24', 1)")
        conn.commit()
        context = load_protected_subject_context(conn)
        self.assertTrue(is_protected_subject_cached("203.0.114.7", context))
        self.assertFalse(is_protected_subject_cached("203.0.115.7", context))  # bgp table absent
        self.assertFalse(is_protected_subject_cached("192.0.2.7", context))    # contexts table absent

    def test_queries_do_not_grow_with_prefixes(self) -> None:
        # New path: load once, then N pure lookups (zero new queries).
        conn = self._db()
        counting = CountingConnection(conn)
        context = load_protected_subject_context(counting)
        load_queries = counting.execute_count
        for i in range(1000):
            is_protected_subject_cached(f"203.0.113.{i % 250 + 1}", context)
        self.assertEqual(load_queries, counting.execute_count,
                         "cached lookups must not issue any SQLite query")

        # Contrast with the DB-backed path: it grows with N.
        conn2 = self._db()
        counting2 = CountingConnection(conn2)
        before = counting2.execute_count
        for i in range(200):
            _is_protected_subject(counting2, f"203.0.113.{i % 250 + 1}")
        after = counting2.execute_count
        self.assertGreater(after - before, 200,
                           "DB-backed path issues multiple queries per subject")


if __name__ == "__main__":
    unittest.main()
