"""Regressão de vazamento de conexões SQLite (FD) e concorrência sem lock.

O ``sqlite3.Connection`` nativo faz commit/rollback no ``__exit__`` mas NÃO
fecha a conexão. ``AutoCloseConnection`` preserva commit/rollback e fecha,
evitando o acúmulo de file descriptors que causava
``sqlite3.OperationalError: database is locked`` em workers recorrentes.
"""

import os
import sqlite3
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services.sqlite_managed import AutoCloseConnection, open_managed

MAIN = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
RTBH_API = (ROOT / "backend" / "app" / "api" / "rtbh.py").read_text(encoding="utf-8")
THREAT_INTEL = (ROOT / "backend" / "app" / "services" / "threat_intelligence.py").read_text(encoding="utf-8")
CLICKHOUSE_SVC = (ROOT / "backend" / "app" / "services" / "clickhouse.py").read_text(encoding="utf-8")
NETWORK_CONTEXT = (ROOT / "backend" / "app" / "services" / "network_context.py").read_text(encoding="utf-8")


class ManagedConnectionTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmpdir = tempfile.mkdtemp()
        self.path = str(Path(self.tmpdir) / "gmjflow-test.db")

    def _init_wal(self):
        conn = open_managed(self.path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT)")
        conn.close()

    def test_with_block_closes_connection(self):
        self._init_wal()
        reference = []
        with open_managed(self.path) as conn:
            reference.append(conn)
            conn.execute("SELECT 1")
        with self.assertRaises(sqlite3.ProgrammingError):
            reference[0].execute("SELECT 1")

    def test_native_connection_does_not_close_contrast(self):
        self._init_wal()
        reference = []
        with sqlite3.connect(self.path, timeout=30) as conn:
            reference.append(conn)
            conn.execute("SELECT 1")
        # Native context manager leaves it open (documents the leak).
        reference[0].execute("SELECT 1")
        reference[0].close()

    def test_with_block_commits_on_success(self):
        self._init_wal()
        with open_managed(self.path) as conn:
            conn.execute("INSERT INTO t (v) VALUES ('x')")
        with open_managed(self.path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM t").fetchone()[0], 1)

    def test_with_block_rolls_back_on_exception(self):
        self._init_wal()
        with self.assertRaises(RuntimeError):
            with open_managed(self.path) as conn:
                conn.execute("INSERT INTO t (v) VALUES ('x')")
                raise RuntimeError("boom")
        with open_managed(self.path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM t").fetchone()[0], 0)

    def test_factory_returns_real_connection(self):
        conn = open_managed(self.path)
        self.assertIsInstance(conn, sqlite3.Connection)
        conn.execute("SELECT 1")
        conn.close()

    @unittest.skipUnless(os.path.exists("/proc/self/fd"), "requires /proc/self/fd")
    def test_repeated_with_does_not_leak_fds(self):
        self._init_wal()
        base = len(os.listdir("/proc/self/fd"))
        for _ in range(2000):
            with open_managed(self.path) as conn:
                conn.execute("SELECT 1")
        after = len(os.listdir("/proc/self/fd"))
        self.assertLessEqual(after - base, 8)

    def test_concurrent_threads_no_database_locked(self):
        self._init_wal()
        errors = []
        barrier = threading.Barrier(8)

        def worker():
            try:
                barrier.wait()
                for i in range(60):
                    with open_managed(self.path) as conn:
                        conn.execute("INSERT INTO t (v) VALUES (?)", (str(i),))
                        conn.execute("SELECT COUNT(*) FROM t")
            except Exception as exc:  # pragma: no cover - assertion aid
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        locked = [exc for exc in errors if isinstance(exc, sqlite3.OperationalError) and "locked" in str(exc).lower()]
        self.assertEqual(errors, [])
        self.assertEqual(locked, [])
        with open_managed(self.path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM t").fetchone()[0], 8 * 60)


class SqliteConnectionDefinitionTests(unittest.TestCase):
    def test_all_definitions_use_managed_factory(self):
        for name, source in (
            ("main.py", MAIN),
            ("api/rtbh.py", RTBH_API),
            ("services/threat_intelligence.py", THREAT_INTEL),
            ("services/clickhouse.py", CLICKHOUSE_SVC),
        ):
            self.assertIn("from app.services.sqlite_managed import open_managed", source, name)
            self.assertIn("open_managed(", source, name)
            # No bare sqlite3.connect inside sqlite_connection anymore.
            self.assertNotIn("sqlite3.connect(path", source, name)
            self.assertNotIn("sqlite3.connect(os.getenv", source, name)

    def test_network_context_closes_factory_owned_connection(self):
        self.assertIn("owns_connection = conn is None", NETWORK_CONTEXT)
        self.assertIn("if owns_connection and connection is not None:", NETWORK_CONTEXT)
        self.assertIn("connection.close()", NETWORK_CONTEXT)

    def test_snmp_poll_commits_per_sample(self):
        insert = MAIN[MAIN.find("def insert_snmp_counter_sample"):MAIN.find("def sensor_poll_due")]
        self.assertIn("conn.commit()", insert)
        self.assertIn("Release the WAL write lock", insert)


if __name__ == "__main__":
    unittest.main()
