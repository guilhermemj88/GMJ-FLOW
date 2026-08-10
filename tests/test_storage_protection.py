from __future__ import annotations

import ast
import json
import math
import os
import re
import sqlite3
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = ROOT / "backend" / "app" / "main.py"
PMACCT_PATH = ROOT / "collector" / "pmacct" / "parse_pmacct.py"
FRONTEND_PATH = ROOT / "frontend" / "index.html"
MAIN_SOURCE = MAIN_PATH.read_text(encoding="utf-8")
PMACCT_SOURCE = PMACCT_PATH.read_text(encoding="utf-8")
FRONTEND_SOURCE = FRONTEND_PATH.read_text(encoding="utf-8")


class FakeHttpException(Exception):
    def __init__(self, status_code: int, detail: Any):
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


def load_definitions(
    source: str,
    *,
    functions: tuple[str, ...] = (),
    assignments: tuple[str, ...] = (),
    namespace: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tree = ast.parse(source)
    selected = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in functions:
            node.decorator_list = []
            selected.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {target.id for target in targets if isinstance(target, ast.Name)}
            if names.intersection(assignments):
                selected.append(node)
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *selected],
        type_ignores=[],
    )
    ast.fix_missing_locations(module)
    values: dict[str, Any] = {
        "Any": Any,
        "HTTPException": FakeHttpException,
        "Path": Path,
        "datetime": datetime,
        "timedelta": timedelta,
        "timezone": timezone,
        "json": json,
        "math": math,
        "os": os,
        "re": re,
        "sqlite3": sqlite3,
        "threading": threading,
        "time": time,
        "clean_text": lambda value: str(value or "").strip(),
    }
    values.update(namespace or {})
    exec(compile(module, "<storage-protection-test>", "exec"), values)
    return values


def function_source(source: str, name: str) -> str:
    start = source.index(f"def {name}(")
    next_function = source.find("\ndef ", start + 1)
    next_route = source.find("\n@app.", start + 1)
    endings = [value for value in (next_function, next_route) if value >= 0]
    return source[start : min(endings) if endings else len(source)]


class RetentionCompatibilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ns = load_definitions(
            MAIN_SOURCE,
            functions=(
                "setting_int",
                "setting_bool",
                "retention_hours_from_settings",
                "table_retention_hours",
                "table_retention_days",
                "normalize_retention_unit",
                "retention_value_to_hours",
                "apply_clickhouse_table_ttl",
                "apply_flow_retention_ttl",
                "migrate_retention_hours_settings",
            ),
            assignments=(
                "SYSTEM_SETTING_DEFAULTS",
                "RETENTION_HOURS_MIGRATIONS",
                "FLOW_RETENTION_TABLES",
            ),
            namespace={"DATABASE_MAINTENANCE_LOCK": threading.Lock()},
        )

    def test_legacy_days_remain_valid_and_convert_to_hours(self):
        settings = {"flow_raw_retention_days": "7"}
        self.assertEqual(168, self.ns["table_retention_hours"](settings, "flow_raw"))
        self.assertEqual(7, self.ns["table_retention_days"](settings, "flow_raw"))

    def test_hours_take_precedence_and_support_less_than_one_day(self):
        settings = {"flow_raw_retention_hours": "12", "flow_raw_retention_days": "7"}
        self.assertEqual(12, self.ns["table_retention_hours"](settings, "flow_raw"))
        self.assertEqual(0.5, self.ns["table_retention_days"](settings, "flow_raw"))
        self.assertEqual(12, self.ns["retention_value_to_hours"](12, "hours"))

    def test_each_clickhouse_table_receives_its_own_hours(self):
        calls = []
        self.ns["apply_clickhouse_table_ttl"] = lambda table, column, enabled, hours: calls.append(
            (table, column, enabled, hours)
        ) or "ok"
        result = self.ns["apply_flow_retention_ttl"](
            True,
            12,
            168,
            360,
            retention_hours_by_table={"anomaly_events": 720},
            enabled_by_table={"flow_tops_1m": False},
        )
        self.assertEqual({"flow_raw", "flow_1m", "flow_tops_1m", "anomaly_events"}, set(result))
        self.assertIn(("flow_raw", "flow_time", True, 12), calls)
        self.assertIn(("flow_1m", "minute", True, 168), calls)
        self.assertIn(("flow_tops_1m", "minute", False, 360), calls)
        self.assertIn(("anomaly_events", "event_time", True, 720), calls)

    def test_generated_ttl_uses_hour_syntax(self):
        ns = load_definitions(
            MAIN_SOURCE,
            functions=("setting_int", "apply_clickhouse_table_ttl"),
        )
        commands = []
        ns["clickhouse_ttl_matches"] = lambda *_args, **_kwargs: False
        ns["clickhouse_table_name"] = lambda table: f"flowdb.{table}"
        ns["command_clickhouse"] = lambda command, **_kwargs: commands.append(command)
        command = ns["apply_clickhouse_table_ttl"]("flow_raw", "flow_time", True, 12)
        self.assertIn("INTERVAL 12 HOUR DELETE", command)
        self.assertNotIn("OPTIMIZE", command.upper())
        self.assertEqual([command], commands)

    def test_migration_survives_reopen_and_never_overwrites_existing_hours(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.db"
            conn = sqlite3.connect(path)
            conn.row_factory = sqlite3.Row
            conn.execute("CREATE TABLE system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)")
            conn.execute("INSERT INTO system_settings VALUES ('flow_raw_retention_days', '7', 'old')")
            conn.execute("INSERT INTO system_settings VALUES ('flow_1m_retention_days', '30', 'old')")
            conn.execute("INSERT INTO system_settings VALUES ('flow_tops_1m_retention_days', '15', 'old')")
            conn.execute("INSERT INTO system_settings VALUES ('snmp_retention_days', '180', 'old')")
            conn.execute("INSERT INTO system_settings VALUES ('flow_raw_retention_hours', '12', 'new')")
            self.ns["migrate_retention_hours_settings"](conn, "now")
            conn.commit()
            conn.close()
            reopened = sqlite3.connect(path)
            rows = dict(reopened.execute("SELECT key, value FROM system_settings").fetchall())
            reopened.close()
        self.assertEqual("12", rows["flow_raw_retention_hours"])
        self.assertEqual("720", rows["flow_1m_retention_hours"])
        self.assertEqual("360", rows["flow_tops_1m_retention_hours"])
        self.assertEqual("4320", rows["snmp_retention_hours"])


class DiskGuardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.state_ns = load_definitions(
            MAIN_SOURCE,
            functions=("disk_guard_state_for_free_gb", "validate_disk_guard_config"),
        )

    def config(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "warning_free_gb": 15,
            "cleanup_free_gb": 10,
            "emergency_free_gb": 7,
            "absolute_floor_gb": 5,
            "target_free_gb": 15,
            "check_seconds": 60,
        }

    def test_states_match_thresholds(self):
        state = self.state_ns["disk_guard_state_for_free_gb"]
        config = self.config()
        self.assertEqual("NORMAL", state(20, config))
        self.assertEqual("WARNING", state(12, config))
        self.assertEqual("CRITICAL", state(9, config))
        self.assertEqual("EMERGENCY", state(6, config))
        self.assertEqual("ABSOLUTE_DANGER", state(4, config))

    def test_incoherent_thresholds_are_rejected(self):
        config = self.config()
        config["target_free_gb"] = 10
        with self.assertRaises(FakeHttpException):
            self.state_ns["validate_disk_guard_config"](config)

    def cleanup_namespace(self) -> dict[str, Any]:
        lock = threading.Lock()
        runtime = {"cleanup_running": False}
        ns = load_definitions(
            MAIN_SOURCE,
            functions=("run_disk_guard_cleanup",),
            assignments=("GIB", "DISK_GUARD_CLEANUP_STATES"),
            namespace={
                "DATABASE_MAINTENANCE_LOCK": lock,
                "DISK_GUARD_STATUS_LOCK": threading.Lock(),
                "DISK_GUARD_RUNTIME": runtime,
                "disk_guard_config": lambda settings: settings,
                "validate_disk_guard_config": self.state_ns["validate_disk_guard_config"],
                "disk_guard_state_for_free_gb": self.state_ns["disk_guard_state_for_free_gb"],
                "utc_now_iso": lambda: "2026-08-10T12:00:00Z",
                "persist_disk_guard_runtime": lambda _values: None,
                "log_disk_guard_event": lambda *_args, **_kwargs: None,
            },
        )
        ns["test_lock"] = lock
        return ns

    def test_cleanup_starts_in_critical_rechecks_and_stops_at_target(self):
        ns = self.cleanup_namespace()
        usage_values = iter(
            [
                {"free_bytes": 12 * ns["GIB"]},
                {"free_bytes": 16 * ns["GIB"]},
                {"free_bytes": 16 * ns["GIB"]},
            ]
        )
        checks = []
        ns["disk_guard_disk_usage"] = lambda: checks.append(True) or next(usage_values)
        ns["disk_guard_table_candidates"] = lambda _excluded: [{"table": "flow_raw"}]
        ns["disk_guard_cleanup_batch"] = lambda _candidate, window: {
            "table": "flow_raw",
            "cutoff": f"oldest+{window}h",
            "rows_before": 10,
            "rows_after": 0,
        }
        config = self.config()
        original = dict(config)
        result = ns["run_disk_guard_cleanup"](
            settings=config,
            initial_usage={"free_bytes": 9 * ns["GIB"]},
        )
        self.assertTrue(result["ok"])
        self.assertEqual("target_reached", result["status"])
        self.assertEqual(2, len(result["batches"]))
        self.assertGreaterEqual(len(checks), 3)
        self.assertEqual(original, config, "Disk Guard must not rewrite retention/config values")
        self.assertNotIn("OPTIMIZE", function_source(MAIN_SOURCE, "run_disk_guard_cleanup").upper())

    def test_shared_lock_prevents_concurrent_cleanup(self):
        ns = self.cleanup_namespace()
        ns["test_lock"].acquire()
        try:
            result = ns["run_disk_guard_cleanup"](
                settings=self.config(),
                initial_usage={"free_bytes": 9 * ns["GIB"]},
            )
        finally:
            ns["test_lock"].release()
        self.assertEqual("maintenance_busy", result["status"])

    def test_batch_cutoff_advances_from_oldest_and_never_optimizes(self):
        commands = []

        class Result:
            column_names = ["count"]

            def __init__(self, count: int):
                self.result_rows = [(count,)]

        counts = iter([Result(10), Result(0)])
        ns = load_definitions(
            MAIN_SOURCE,
            functions=("disk_guard_cleanup_batch",),
            namespace={
                "clickhouse_identifier": lambda value: value,
                "clickhouse_table_name": lambda table: f"flowdb.{table}",
                "query_clickhouse": lambda *_args, **_kwargs: next(counts),
                "rows_as_dicts": lambda result: [dict(zip(result.column_names, row)) for row in result.result_rows],
                "command_clickhouse": lambda command, parameters, admin=False: commands.append((command, parameters, admin)),
                "iso": lambda value: value.isoformat(),
            },
        )
        oldest = datetime(2026, 8, 1, tzinfo=timezone.utc)
        result = ns["disk_guard_cleanup_batch"](
            {
                "table": "flow_raw",
                "time_column": "flow_time",
                "oldest": oldest,
                "recent_limit": oldest + timedelta(days=1),
            },
            1,
        )
        self.assertEqual(oldest + timedelta(hours=1), commands[0][1]["cutoff"].replace(tzinfo=timezone.utc))
        self.assertIn("DELETE WHERE", commands[0][0])
        self.assertNotIn("OPTIMIZE", commands[0][0].upper())
        self.assertEqual(10, result["rows_deleted"])

    def test_background_loop_catches_failures(self):
        loop_source = function_source(MAIN_SOURCE, "database_disk_guard_loop")
        self.assertIn("except Exception", loop_source)
        self.assertIn("run_disk_guard_check()", loop_source)


class PmacctProtectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ns = load_definitions(
            PMACCT_SOURCE,
            functions=("rotation_checkpoint_path", "rotation_cleanup_eligible", "cleanup_old_rotations"),
        )

    def write_checkpoint(self, path: Path, *, offset: int, file_size: int, complete: bool = True) -> None:
        checkpoint = {
            "archive": str(path),
            "offset": offset,
            "file_size": file_size,
            "lag_bytes": max(0, file_size - offset),
            "checkpoint_valid": True,
            "ingestion_complete": complete,
        }
        self.ns["rotation_checkpoint_path"](path).write_text(json.dumps(checkpoint), encoding="utf-8")

    def test_active_backlog_and_incomplete_files_are_never_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "nfacctd.csv"
            backlog = root / "nfacctd-backlog-20260801-010101.csv.gz"
            incomplete = root / "nfacctd-20260801-020202.csv.gz"
            complete = root / "nfacctd-20260801-030303.csv.gz"
            for path in (active, backlog, incomplete, complete):
                path.write_bytes(b"0123456789")
                os.utime(path, (1, 1))
            self.write_checkpoint(active, offset=10, file_size=10)
            self.write_checkpoint(backlog, offset=10, file_size=10)
            self.write_checkpoint(incomplete, offset=5, file_size=10)
            self.write_checkpoint(complete, offset=10, file_size=10)
            deleted = self.ns["cleanup_old_rotations"](root, 1, active_file=active)
            self.assertEqual(1, deleted)
            self.assertTrue(active.exists())
            self.assertTrue(backlog.exists())
            self.assertTrue(incomplete.exists())
            self.assertFalse(complete.exists())


class StorageUiAndSafetyStaticTest(unittest.TestCase):
    def test_admin_ui_and_api_contract_are_present(self):
        for text in (
            "Retenção de Dados",
            "Proteção de Disco",
            "flowRawRetentionValue",
            "flowRawRetentionUnit",
            "saveDiskGuardButton",
            "/api/system/disk-guard",
        ):
            self.assertIn(text, FRONTEND_SOURCE)
        self.assertIn('@app.get("/api/system/disk-guard")', MAIN_SOURCE)
        self.assertIn('@app.put("/api/system/disk-guard")', MAIN_SOURCE)

    def test_forbidden_destructive_commands_are_absent_from_guard(self):
        guard_start = MAIN_SOURCE.index("def disk_guard_disk_usage")
        guard_end = MAIN_SOURCE.index("def upsert_discovered_interfaces", guard_start)
        guard_source = MAIN_SOURCE[guard_start:guard_end].lower()
        for forbidden in (
            "docker system prune",
            "docker volume prune",
            "docker compose down -v",
            "rm -rf /var/lib/docker",
            "rm -rf /var/lib/clickhouse",
            "optimize table",
        ):
            self.assertNotIn(forbidden, guard_source)


if __name__ == "__main__":
    unittest.main()
