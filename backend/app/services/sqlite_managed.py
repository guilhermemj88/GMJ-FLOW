"""Managed SQLite connection factory.

The native ``sqlite3.Connection`` context manager commits/rollbacks but does
NOT close the connection on exit. Recurring workers that use
``with sqlite_connection() as conn:`` therefore leak file descriptors and WAL
readers, eventually surfacing as ``sqlite3.OperationalError: database is
locked`` under load.

``AutoCloseConnection`` keeps the exact native commit/rollback semantics and
adds ``close()`` in ``__exit__``. Because it is still a real
``sqlite3.Connection``, it remains safe to use as a plain factory
(``conn = sqlite_connection()``) where call sites manage the lifecycle
explicitly.
"""

from __future__ import annotations

import sqlite3
from typing import Any


class AutoCloseConnection(sqlite3.Connection):
    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()
        return False


def open_managed(
    db_path: str,
    *,
    timeout: float = 30,
    check_same_thread: bool = False,
) -> sqlite3.Connection:
    return sqlite3.connect(
        db_path,
        timeout=timeout,
        check_same_thread=check_same_thread,
        factory=AutoCloseConnection,
    )
