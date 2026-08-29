from __future__ import annotations

import os
import sqlite3
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.network_sweep_noop_adapter import (  # noqa: E402
    ADAPTER_VERSION,
    build_noop_record,
    ensure_noop_adapter_schema,
    resolve_would_use_connector,
    run_noop_adapter,
)
from app.services.network_sweep_policy import evaluate_network_sweep  # noqa: E402
from app.services.threat_intelligence import utc_now_iso  # noqa: E402


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
        "source_asn": "",
        "src_is_cgnat": False,
        "campaign_id": "",
    }
    base.update(overrides)
    return base


def _eligible_decision(**kw):
    return evaluate_network_sweep(
        _candidate(),
        source_protected=False,
        target_protected=False,
        existing_mitigation=False,
        bgp_ready=True,
        **kw,
    )


EVENT_COLS = [
    "id", "public_id", "campaign_id", "attack_type", "verdict", "severity",
    "direction", "src_role", "dst_role", "src_ip", "src_prefix", "target_prefix",
    "recurrence_count", "detector_score", "unique_destinations", "unique_dst_ports",
    "network_context_json", "last_seen",
]


def _make_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE security_events (
            id INTEGER PRIMARY KEY, public_id TEXT, campaign_id TEXT, attack_type TEXT,
            verdict TEXT, severity TEXT, direction TEXT, src_role TEXT, dst_role TEXT,
            src_ip TEXT, src_prefix TEXT, target_prefix TEXT, recurrence_count INTEGER,
            detector_score INTEGER, unique_destinations INTEGER, unique_dst_ports INTEGER,
            network_context_json TEXT, last_seen TEXT
        );
        CREATE TABLE system_settings (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE bgp_connectors (
            id INTEGER PRIMARY KEY, name TEXT, enabled INTEGER DEFAULT 1, is_active INTEGER DEFAULT 1
        );
        """
    )
    return conn


def _insert_event(conn, **overrides):
    vals = {
        "id": 1, "public_id": "GMJ-TEST-1", "campaign_id": "", "attack_type": "NETWORK_SWEEP",
        "verdict": "CONFIRMED_ATTACK", "severity": "CRITICAL", "direction": "INBOUND",
        "src_role": "EXTERNAL", "dst_role": "CUSTOMER", "src_ip": "203.0.113.50",
        "src_prefix": "", "target_prefix": "186.232.160.0/24", "recurrence_count": 3,
        "detector_score": 94, "unique_destinations": 34, "unique_dst_ports": 12,
        "network_context_json": "{}", "last_seen": utc_now_iso(),
    }
    vals.update(overrides)
    conn.execute(
        "INSERT INTO security_events (" + ",".join(EVENT_COLS) + ") VALUES (" + ",".join("?" * len(EVENT_COLS)) + ")",
        [vals[c] for c in EVENT_COLS],
    )
    return vals


def _enable(conn):
    conn.execute(
        "INSERT OR REPLACE INTO system_settings (key, value) VALUES ('network_sweep_noop_adapter_enabled', 'true')"
    )


def _add_connector(conn, cid=2, name="BGP-TEST"):
    conn.execute("INSERT INTO bgp_connectors (id, name, enabled, is_active) VALUES (?, ?, 1, 1)", (cid, name))


def _audit_count(conn):
    try:
        return conn.execute("SELECT COUNT(*) FROM network_sweep_noop_adapter_audit").fetchone()[0]
    except sqlite3.OperationalError:
        return 0


class NetworkSweepNoopBuildTest(unittest.TestCase):
    """Pure record-builder tests (no DB)."""

    def test_eligible_event_would_execute_true_executed_false(self):
        d = _eligible_decision()
        conn = {"id": 2, "name": "BGP-TEST", "ready": True, "readiness": "ready"}
        rec = build_noop_record("pub-1", "1", "203.0.113.50", "186.232.160.0/24", d, connector=conn, recurrence=3)
        self.assertTrue(rec["would_execute"])
        self.assertFalse(rec["executed"])
        self.assertEqual("discard", rec["action"])
        self.assertEqual(2700, rec["ttl_seconds"])
        self.assertEqual(2, rec["connector_id"])
        self.assertEqual("BGP-TEST", rec["connector_name"])
        self.assertEqual("eligible_shadow_policy", rec["reason"])

    def test_bgp_not_ready_would_execute_false(self):
        d = _eligible_decision()
        rec = build_noop_record("pub-1", "1", "203.0.113.50", "186.232.160.0/24", d, connector=None, recurrence=3)
        self.assertFalse(rec["would_execute"])
        self.assertFalse(rec["executed"])
        self.assertEqual("not_ready", rec["connector_readiness"])

    def test_ineligible_build_would_execute_false(self):
        d = evaluate_network_sweep(_candidate(direction="OUTBOUND"), bgp_ready=True)
        self.assertFalse(d["eligible"])
        conn = {"id": 2, "name": "BGP-TEST", "ready": True, "readiness": "ready"}
        rec = build_noop_record("pub-1", "1", "203.0.113.50", "x", d, connector=conn, recurrence=3)
        self.assertFalse(rec["would_execute"])
        self.assertEqual("", rec["action"])
        self.assertEqual(0, rec["ttl_seconds"])
        self.assertIn("NOT_INBOUND", rec["reason"])


class NetworkSweepNoopRunTest(unittest.TestCase):
    """Wrapper integration tests (in-memory sqlite)."""

    def setUp(self):
        self._env_patcher = mock.patch.dict(
            os.environ,
            {"GMJFLOW_NETWORK_SWEEP_NOOP_ADAPTER_ENABLED": "", "GMJFLOW_NETWORK_SWEEP_NOOP_ADAPTER_KILL_SWITCH": ""},
        )
        self._env_patcher.start()

    def tearDown(self):
        self._env_patcher.stop()

    def test_eligible_persists_row_executed_false(self):
        conn = _make_conn()
        _enable(conn)
        _add_connector(conn)
        _insert_event(conn)
        persisted = run_noop_adapter(conn)
        self.assertEqual(1, persisted)
        row = conn.execute("SELECT * FROM network_sweep_noop_adapter_audit").fetchone()
        self.assertEqual(1, row["would_execute"])
        self.assertEqual(0, row["executed"])
        self.assertEqual("discard", row["action"])
        self.assertEqual(2, row["connector_id"])
        conn.close()

    def test_ineligible_no_adapter_invocation(self):
        conn = _make_conn()
        _enable(conn)
        _add_connector(conn)
        _insert_event(conn, direction="OUTBOUND")
        persisted = run_noop_adapter(conn)
        self.assertEqual(0, persisted)
        self.assertEqual(0, _audit_count(conn))
        conn.close()

    def test_duplicate_recurrence_dedup(self):
        conn = _make_conn()
        _enable(conn)
        _add_connector(conn)
        _insert_event(conn)
        run_noop_adapter(conn)
        run_noop_adapter(conn)
        self.assertEqual(1, _audit_count(conn))
        conn.close()

    def test_new_recurrence_new_row(self):
        conn = _make_conn()
        _enable(conn)
        _add_connector(conn)
        _insert_event(conn, recurrence_count=3)
        run_noop_adapter(conn)
        conn.execute("UPDATE security_events SET recurrence_count = 4 WHERE id = 1")
        run_noop_adapter(conn)
        self.assertEqual(2, _audit_count(conn))
        conn.close()

    def test_protected_source_not_invoked(self):
        conn = _make_conn()
        _enable(conn)
        _add_connector(conn)
        _insert_event(conn, src_ip="10.0.0.5")
        self.assertEqual(0, run_noop_adapter(conn))
        self.assertEqual(0, _audit_count(conn))
        conn.close()

    def test_cgnat_source_not_invoked(self):
        conn = _make_conn()
        _enable(conn)
        _add_connector(conn)
        _insert_event(conn, network_context_json='{"src_is_cgnat": true}')
        self.assertEqual(0, run_noop_adapter(conn))
        self.assertEqual(0, _audit_count(conn))
        conn.close()

    def test_internal_direction_not_invoked(self):
        conn = _make_conn()
        _enable(conn)
        _add_connector(conn)
        _insert_event(conn, direction="INTERNAL")
        self.assertEqual(0, run_noop_adapter(conn))
        self.assertEqual(0, _audit_count(conn))
        conn.close()

    def test_likely_benign_not_invoked(self):
        conn = _make_conn()
        _enable(conn)
        _add_connector(conn)
        _insert_event(conn, verdict="LIKELY_BENIGN")
        self.assertEqual(0, run_noop_adapter(conn))
        self.assertEqual(0, _audit_count(conn))
        conn.close()

    def test_feature_disabled_nothing_happens(self):
        conn = _make_conn()
        _add_connector(conn)
        _insert_event(conn)
        self.assertEqual(0, run_noop_adapter(conn))
        self.assertEqual(0, _audit_count(conn))
        conn.close()

    def test_kill_switch_nothing_happens(self):
        conn = _make_conn()
        _enable(conn)
        _add_connector(conn)
        _insert_event(conn)
        with mock.patch.dict(os.environ, {"GMJFLOW_NETWORK_SWEEP_NOOP_ADAPTER_KILL_SWITCH": "1"}):
            self.assertEqual(0, run_noop_adapter(conn))
        self.assertEqual(0, _audit_count(conn))
        conn.close()


class NetworkSweepNoopIsolationTest(unittest.TestCase):
    """The adapter must never touch the real execution path."""

    def test_module_isolation_no_real_executor(self):
        import inspect

        import app.services.network_sweep_noop_adapter as mod
        source = inspect.getsource(mod)
        for forbidden in (
            "from app.services.automatic_mitigation",
            "import automatic_mitigation",
            "from app.main",
            "from app.services.host_agent",
            "import host_agent",
            "subprocess",
            "os.system",
            "exabgp_pipe",
        ):
            self.assertNotIn(forbidden, source, f"forbidden token in source: {forbidden}")

    def test_zero_fifo_or_file_write(self):
        import inspect

        import app.services.network_sweep_noop_adapter as mod
        source = inspect.getsource(mod)
        self.assertNotIn("open(", source)
        self.assertNotIn(".write(", source)

    def test_module_never_exposes_execution(self):
        import app.services.network_sweep_noop_adapter as mod
        for name in ("announce", "withdraw", "send_flowspec", "execute_mitigation"):
            self.assertFalse(hasattr(mod, name), f"module must not expose {name}")


if __name__ == "__main__":
    unittest.main()
