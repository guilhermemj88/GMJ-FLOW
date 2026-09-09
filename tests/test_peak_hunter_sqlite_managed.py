"""Fase 1: as fábricas SQLite do Peak Hunter devem fechar a conexão no __exit__.

Prova que ``with sqlite_connect() as conn:`` e ``with _sqlite_connect() as conn:``
usam ``AutoCloseConnection`` (via ``open_managed``) e fecham automaticamente.
"""

import os
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

sys.modules.setdefault("clickhouse_connect", types.SimpleNamespace(get_client=lambda **_kwargs: None))

from app.services.peak_hunter_runner import sqlite_connect  # noqa: E402
from app.api.peak_hunter import _sqlite_connect  # noqa: E402


class PeakHunterSqliteManagedTest(unittest.TestCase):
    def _assert_factory_closes(self, factory):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "peak.db")
            with mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": db_path}):
                with factory() as conn:
                    self.assertIsNotNone(conn)
                    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
                    conn.execute("INSERT INTO t (id) VALUES (1)")
                # Depois do `with`, a conexão deve estar FECHADA.
                with self.assertRaises(sqlite3.ProgrammingError):
                    conn.execute("SELECT 1")
                # Reabre para confirmar que o commit do __exit__ persistiu.
                with factory() as conn2:
                    row = conn2.execute("SELECT COUNT(*) AS c FROM t").fetchone()
                    self.assertEqual(row["c"], 1)

    def test_runner_sqlite_connect_closes_on_exit(self):
        self._assert_factory_closes(sqlite_connect)

    def test_api_sqlite_connect_closes_on_exit(self):
        self._assert_factory_closes(_sqlite_connect)


if __name__ == "__main__":
    unittest.main()
