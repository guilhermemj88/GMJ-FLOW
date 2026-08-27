from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavior_engine import (  # noqa: E402
    CHUNK_STATUS_COMPLETED,
    DEFAULT_CLOSED_WINDOW_DELAY_MINUTES,
    ENTITY_INTERFACE,
    ENTITY_PREFIX,
    ENTITY_PREFIX_DIRECTION,
    ENTITY_SENSOR,
    IpTriePrefixLookup,
    MultiIfPrefixLookup,
    NO_NEW_MINUTES,
    SKIPPED_ALREADY_PROCESSED,
    SKIPPED_LOAD_GUARD,
    BaselineBuilder,
    BaselineBuilderConfig,
    WINDOW_SECONDS,
    _build_metrics_payload,
    _signal_matches_entity,
    bootstrap_load_guard,
    continuous_shadow_cycle,
    ensure_behavior_engine_schema,
    fanout_entity_minutes,
    fetch_attack_signals,
    fetch_batch_interface_uniques,
    fetch_batch_prefix_metrics,
    fetch_batch_prefix_uniques,
    fetch_batch_protocol_metrics,
)

NOW = datetime(2026, 8, 14, 12, 10, 0, tzinfo=timezone.utc)  # Friday
PREFIX = "186.232.160.0/20"


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def minute_range(start, end):
    out = []
    cursor = start
    while cursor < end:
        out.append(cursor)
        cursor += timedelta(minutes=1)
    return out


class FakeClickHouse:
    """Fake executor for the 4 fixed batch queries."""

    def __init__(self):
        self.calls = []
        self.fail = False
        self.proto_rows = []          # {minute, sensor, input_if, output_if, proto, bytes, packets, flows}
        self.uniq_rows = []           # {minute, sensor, if_index, direction, kind, value}
        self.prefix_metric_rows = []  # {minute, prefix_key, direction, proto, dst_port, bytes, packets, flows}
        self.prefix_uniq_rows = []    # {minute, prefix_key, direction, unique_sources, unique_destinations}

    def __call__(self, sql, params):
        self.calls.append((sql, dict(params or {})))
        if self.fail:
            raise RuntimeError("clickhouse down")
        if "flow_dashboard_protocol_1m" in sql:
            return self._filter(self.proto_rows, params)
        if "flow_dashboard_prefix_1m" in sql:
            if "uniqExact" in sql:
                return self._filter(self.prefix_uniq_rows, params)
            return self._filter(self.prefix_metric_rows, params)
        return self._filter(self.uniq_rows, params)

    @staticmethod
    def _filter(rows, params):
        start = params["start"]
        end = params["end"]
        return [row for row in rows if start <= row["minute"] <= end]


def proto_rows_for(minutes, sensor="S1", if_index=10, bytes_per=7500.0, packets=100.0, flows=10.0, proto=6):
    return [
        {"minute": minute, "sensor": sensor, "input_if": if_index, "output_if": if_index,
         "proto": proto, "bytes": bytes_per, "packets": packets, "flows": flows}
        for minute in minutes
    ]


def uniq_rows_for(minutes, sensor="S1", if_index=10, src=5, dst=7):
    rows = []
    for minute in minutes:
        for direction in (1, 2):
            rows.append({"minute": minute, "sensor": sensor, "if_index": if_index, "direction": direction, "kind": "src", "value": src})
            rows.append({"minute": minute, "sensor": sensor, "if_index": if_index, "direction": direction, "kind": "dst", "value": dst})
        rows.append({"minute": minute, "sensor": sensor, "if_index": 0, "direction": 0, "kind": "src", "value": src})
        rows.append({"minute": minute, "sensor": sensor, "if_index": 0, "direction": 0, "kind": "dst", "value": dst})
    return rows


def prefix_metric_rows_for(minutes, prefix=PREFIX, bytes_per=7500.0, packets=100.0, flows=10.0, proto=6):
    rows = []
    for minute in minutes:
        for direction in ("in", "out"):
            rows.append({"minute": minute, "prefix_key": prefix, "direction": direction, "proto": proto,
                         "dst_port": 443, "bytes": bytes_per, "packets": packets, "flows": flows})
    return rows


def prefix_uniq_rows_for(minutes, prefix=PREFIX, src=5, dst=7):
    return [
        {"minute": minute, "prefix_key": prefix, "direction": direction,
         "unique_sources": src, "unique_destinations": dst}
        for minute in minutes for direction in ("in", "out")
    ]


def make_conn(path):
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def seed_entities(conn, prefixes=(PREFIX,), sensors=(("1", "S1"),), ifaces=(("1", 10),)):
    conn.execute("CREATE TABLE IF NOT EXISTS ip_zone_prefixes (cidr TEXT, active INTEGER)")
    conn.execute("CREATE TABLE IF NOT EXISTS sensors (id INTEGER PRIMARY KEY, name TEXT, active INTEGER)")
    conn.execute("CREATE TABLE IF NOT EXISTS sensor_interfaces (sensor_id INTEGER, if_index INTEGER, monitor_enabled INTEGER)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS security_events (attack_type TEXT, severity TEXT, verdict TEXT, src_ip TEXT,"
        " target_ip TEXT, target_prefix TEXT, sensor TEXT, first_seen TEXT, last_seen TEXT)"
    )
    for prefix in prefixes:
        conn.execute("INSERT INTO ip_zone_prefixes (cidr, active) VALUES (?, 1)", (prefix,))
    for sensor_id, name in sensors:
        conn.execute("INSERT INTO sensors (id, name, active) VALUES (?, ?, 1)", (int(sensor_id), name))
    for sensor_id, if_index in ifaces:
        conn.execute("INSERT INTO sensor_interfaces (sensor_id, if_index, monitor_enabled) VALUES (?, ?, 1)", (int(sensor_id), if_index))
    conn.commit()


def seed_confirmed_event(conn, minute, target_ip="186.232.160.10", attack_type="UDP_FLOOD"):
    stamp = iso(minute)
    conn.execute(
        "INSERT INTO security_events (attack_type, severity, verdict, src_ip, target_ip, target_prefix, sensor, first_seen, last_seen)"
        " VALUES (?, 'CRITICAL', 'CONFIRMED_ATTACK', '203.0.113.7', ?, '', '', ?, ?)",
        (attack_type, target_ip, stamp, stamp),
    )
    conn.commit()


class BuilderTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="behavior_engine_test_")
        self.db_path = os.path.join(self.tmp, "test.db")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_builder(self, fake, now=NOW, persist=True, **config_overrides):
        config = BaselineBuilderConfig(bootstrap_hours=config_overrides.pop("bootstrap_hours", 1), **config_overrides)
        builder = BaselineBuilder(lambda: make_conn(self.db_path), fake, config, now_fn=lambda: now)
        return builder.build_once(persist=persist)

    def standard_setup(self, bootstrap_hours=1, now=NOW, **kwargs):
        conn = make_conn(self.db_path)
        seed_entities(conn)
        conn.close()
        fake = FakeClickHouse()
        end = now - timedelta(minutes=DEFAULT_CLOSED_WINDOW_DELAY_MINUTES)
        start = now - timedelta(hours=bootstrap_hours)
        minutes = minute_range(start, end + timedelta(minutes=5))
        fake.proto_rows = proto_rows_for(minutes, **kwargs)
        fake.uniq_rows = uniq_rows_for(minutes)
        fake.prefix_metric_rows = prefix_metric_rows_for(minutes, **kwargs)
        fake.prefix_uniq_rows = prefix_uniq_rows_for(minutes)
        return fake


class EntityDiscoveryTest(BuilderTestCase):
    def test_entity_cardinality(self):
        conn = make_conn(self.db_path)
        seed_entities(conn)
        from app.services.behavior_engine import discover_entities
        entities = discover_entities(conn)
        by_type = {}
        for entity in entities:
            by_type[entity["entity_type"]] = by_type.get(entity["entity_type"], 0) + 1
        self.assertEqual(1, by_type[ENTITY_PREFIX])
        self.assertEqual(2, by_type[ENTITY_PREFIX_DIRECTION])
        self.assertEqual(2, by_type[ENTITY_SENSOR])
        self.assertEqual(2, by_type[ENTITY_INTERFACE])
        self.assertEqual(7, len(entities))
        conn.close()


class DryRunSafetyTest(BuilderTestCase):
    def test_dry_run_does_not_create_tables_nor_persist(self):
        fake = self.standard_setup()
        report = self.run_builder(fake, persist=False)
        self.assertFalse(report["persisted"])
        conn = make_conn(self.db_path)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("behavior_baselines_v1", tables)
        self.assertNotIn("behavior_baseline_runtime_state", tables)
        self.assertNotIn("behavior_baseline_window_audit", tables)
        self.assertNotIn("behavior_baseline_hour_counters", tables)
        conn.close()


class WindowHandlingTest(BuilderTestCase):
    def test_closed_windows_only(self):
        # Rows exist for 12:08 and 12:09 (inside the closed delay) — they must
        # be ignored; end of range is now - closed_delay.
        fake = self.standard_setup()
        report = self.run_builder(fake, persist=False)
        self.assertEqual("2026-08-14T12:07:00Z", report["window_range"]["end"])
        self.assertEqual(57 * 7, report["windows_processed"])
        self.assertEqual(0, report["insufficient"])
        self.assertEqual(57 * 7, report["eligible"])

    def test_batch_queries_fixed_count_no_flow_raw(self):
        fake = self.standard_setup()
        report = self.run_builder(fake, persist=False)
        # 4 fixed queries: protocol metrics + interface uniques + prefix metrics
        # + prefix uniques — regardless of entity count.
        self.assertEqual(4, len(fake.calls))
        self.assertEqual(4, report["queries_executed"])
        for sql, _params in fake.calls:
            self.assertNotIn("flow_raw", sql.lower())

    def test_prefix_queries_use_ipv4_normalization_and_multiif(self):
        fake = self.standard_setup()
        self.run_builder(fake, persist=False)
        prefix_calls = [sql for sql, _ in fake.calls if "flow_dashboard_prefix_1m" in sql]
        self.assertEqual(2, len(prefix_calls))
        for sql in prefix_calls:
            self.assertIn("multiIf", sql)
            self.assertIn("isIPAddressInRange", sql)
            self.assertIn("replaceRegexpOne", sql)
            self.assertIn("::ffff:", sql)

    def test_open_window_rows_are_ignored(self):
        # Rows only in the still-open minutes (>= 12:07) -> all insufficient.
        conn = make_conn(self.db_path)
        seed_entities(conn)
        conn.close()
        fake = FakeClickHouse()
        minutes = minute_range(datetime(2026, 8, 14, 12, 7, tzinfo=timezone.utc), datetime(2026, 8, 14, 12, 15, tzinfo=timezone.utc))
        fake.proto_rows = proto_rows_for(minutes)
        fake.uniq_rows = uniq_rows_for(minutes)
        fake.prefix_metric_rows = prefix_metric_rows_for(minutes)
        fake.prefix_uniq_rows = prefix_uniq_rows_for(minutes)
        report = self.run_builder(fake, persist=False)
        self.assertEqual(57 * 7, report["insufficient"])


class EmptyAndFailureTest(BuilderTestCase):
    def test_empty_input_all_insufficient(self):
        fake = self.standard_setup()
        fake.proto_rows = []
        fake.uniq_rows = []
        fake.prefix_metric_rows = []
        fake.prefix_uniq_rows = []
        report = self.run_builder(fake, persist=True)
        self.assertEqual(57 * 7, report["insufficient"])
        self.assertEqual(0, report["eligible"])
        self.assertEqual(0, report["snapshots_to_upsert"])

    def test_clickhouse_failure_marks_insufficient_and_resumes(self):
        conn = make_conn(self.db_path)
        seed_entities(conn)
        conn.close()
        fake = FakeClickHouse()
        fake.fail = True
        report = self.run_builder(fake, persist=True)
        self.assertEqual(57 * 7, report["insufficient"])
        self.assertEqual(0, report["eligible"])
        # Checkpoint advanced: a retry resumes from the new checkpoint.
        conn = make_conn(self.db_path)
        row = conn.execute("SELECT last_processed_minute FROM behavior_baseline_runtime_state WHERE id = 1").fetchone()
        self.assertIsNotNone(row)
        conn.close()


class ClassificationTest(BuilderTestCase):
    def test_confirmed_attack_rejected_and_not_in_baseline(self):
        fake = self.standard_setup()
        conn = make_conn(self.db_path)
        attacked_minute = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
        seed_confirmed_event(conn, attacked_minute)
        conn.close()
        report = self.run_builder(fake, persist=True)
        # The 3 prefix-scoped entities for that single window are REJECTED.
        self.assertEqual(3, report["rejected"])
        conn = make_conn(self.db_path)
        audit = conn.execute("SELECT classification, reason FROM behavior_baseline_window_audit WHERE classification = 'REJECTED'").fetchall()
        self.assertEqual(3, len(audit))
        for row in audit:
            self.assertIn("CONFIRMED_ATTACK", row["reason"])
        # Anti-contamination: the attacked window never entered the baseline.
        row = conn.execute(
            "SELECT samples FROM behavior_baselines_v1 WHERE entity_type='prefix' AND entity_key=? AND metric='bps' AND bucket_type='global'",
            (PREFIX,),
        ).fetchone()
        self.assertEqual(56, int(row["samples"]))
        conn.close()

    def test_high_anomaly_quarantined_via_previous_snapshot(self):
        conn = make_conn(self.db_path)
        seed_entities(conn)
        ensure_behavior_engine_schema(conn)
        for entity_type, entity_key, p50 in (
            ("prefix", PREFIX, 2000.0),
            ("prefix_direction", f"{PREFIX}|in", 1000.0),
            ("prefix_direction", f"{PREFIX}|out", 1000.0),
        ):
            conn.execute(
                "INSERT INTO behavior_baselines_v1 (entity_type, entity_key, metric, bucket_type, bucket_key, samples, p50, mad, updated_at)"
                " VALUES (?, ?, 'bps', 'global', 'global', 30, ?, 100, 'x')",
                (entity_type, entity_key, p50),
            )
        conn.commit()
        conn.close()
        fake = FakeClickHouse()
        end = NOW - timedelta(minutes=DEFAULT_CLOSED_WINDOW_DELAY_MINUTES)
        start = NOW - timedelta(hours=1)
        minutes = minute_range(start, end)
        spike = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
        fake.proto_rows = proto_rows_for(minutes)
        fake.uniq_rows = uniq_rows_for(minutes)
        fake.prefix_metric_rows = prefix_metric_rows_for(minutes)
        for row in fake.prefix_metric_rows:
            if row["minute"] == spike:
                row["bytes"] = 15000.0  # bps 2000 per direction -> robust z saturates
        fake.prefix_uniq_rows = prefix_uniq_rows_for(minutes)
        report = self.run_builder(fake, persist=True)
        self.assertEqual(3, report["quarantined"])
        conn = make_conn(self.db_path)
        audit = conn.execute("SELECT reason FROM behavior_baseline_window_audit WHERE classification = 'QUARANTINED'").fetchall()
        self.assertEqual(3, len(audit))
        for row in audit:
            self.assertIn("HIGH_ANOMALY", row["reason"])
        # The quarantined spike is excluded from the refreshed snapshot.
        row = conn.execute(
            "SELECT samples FROM behavior_baselines_v1 WHERE entity_type='prefix' AND entity_key=? AND metric='bps' AND bucket_type='global'",
            (PREFIX,),
        ).fetchone()
        self.assertEqual(56, int(row["samples"]))
        conn.close()

    def test_normal_window_eligible_without_history(self):
        # Bootstrap: no previous snapshot -> everything is ELIGIBLE (documented
        # conservative strategy), never QUARANTINED.
        fake = self.standard_setup()
        report = self.run_builder(fake, persist=True)
        self.assertEqual(0, report["quarantined"])
        self.assertEqual(0, report["rejected"])
        self.assertEqual(57 * 7, report["eligible"])


class BootstrapConfidenceTest(BuilderTestCase):
    def test_cold_start_first_24h_and_low_after_span(self):
        conn = make_conn(self.db_path)
        seed_entities(conn, sensors=(), ifaces=())
        conn.close()
        fake = FakeClickHouse()
        now = NOW
        end = now - timedelta(minutes=DEFAULT_CLOSED_WINDOW_DELAY_MINUTES)
        start = now - timedelta(hours=1)
        minutes = minute_range(start, end)
        fake.prefix_metric_rows = prefix_metric_rows_for(minutes)
        fake.prefix_uniq_rows = prefix_uniq_rows_for(minutes)
        report = self.run_builder(fake, now=now, persist=True, bootstrap_hours=1, min_bucket_samples=1)
        self.assertTrue(report["snapshots_to_upsert"] > 0)
        conn = make_conn(self.db_path)
        rows = conn.execute("SELECT DISTINCT confidence FROM behavior_baselines_v1").fetchall()
        self.assertEqual({"COLD"}, {row[0] for row in rows})
        conn.close()

        # 25h span -> the global bucket reaches LOW (>= 24h), while narrow
        # dow:hour buckets remain COLD. Fresh DB so the run is a new bootstrap
        # instead of resuming from the previous checkpoint.
        for suffix in ("", "-wal", "-shm"):
            candidate = self.db_path + suffix
            if os.path.exists(candidate):
                os.remove(candidate)
        conn = make_conn(self.db_path)
        seed_entities(conn, sensors=(), ifaces=())
        conn.close()
        fake = FakeClickHouse()
        now = NOW
        end = now - timedelta(minutes=DEFAULT_CLOSED_WINDOW_DELAY_MINUTES)
        start = now - timedelta(hours=25)
        minutes = minute_range(start, end)
        fake.prefix_metric_rows = prefix_metric_rows_for(minutes)
        fake.prefix_uniq_rows = prefix_uniq_rows_for(minutes)
        self.run_builder(fake, now=now, persist=True, bootstrap_hours=25, min_bucket_samples=1)
        conn = make_conn(self.db_path)
        row = conn.execute(
            "SELECT confidence FROM behavior_baselines_v1 WHERE metric='bps' AND bucket_type='global' LIMIT 1"
        ).fetchone()
        self.assertEqual("LOW", row[0])
        dow = conn.execute(
            "SELECT confidence FROM behavior_baselines_v1 WHERE metric='bps' AND bucket_type='dow_hour' LIMIT 1"
        ).fetchone()
        self.assertEqual("COLD", dow[0])
        conn.close()


class SeasonalityTest(BuilderTestCase):
    def test_seasonal_buckets_created(self):
        conn = make_conn(self.db_path)
        seed_entities(conn, sensors=(), ifaces=())
        conn.close()
        fake = FakeClickHouse()
        end = NOW - timedelta(minutes=DEFAULT_CLOSED_WINDOW_DELAY_MINUTES)
        start = NOW - timedelta(hours=25)
        minutes = minute_range(start, end)
        fake.prefix_metric_rows = prefix_metric_rows_for(minutes)
        fake.prefix_uniq_rows = prefix_uniq_rows_for(minutes)
        report = self.run_builder(fake, persist=True, bootstrap_hours=25, min_bucket_samples=1)
        self.assertTrue(report["snapshots_to_upsert"] > 0)
        conn = make_conn(self.db_path)
        hour_keys = {row[0] for row in conn.execute(
            "SELECT DISTINCT bucket_key FROM behavior_baselines_v1 WHERE metric='bps' AND bucket_type='hour'"
        )}
        dow_keys = {row[0] for row in conn.execute(
            "SELECT DISTINCT bucket_key FROM behavior_baselines_v1 WHERE metric='bps' AND bucket_type='dow_hour'"
        )}
        global_keys = {row[0] for row in conn.execute(
            "SELECT DISTINCT bucket_key FROM behavior_baselines_v1 WHERE metric='bps' AND bucket_type='global'"
        )}
        self.assertGreaterEqual(len(hour_keys), 2)
        self.assertGreaterEqual(len(dow_keys), 2)  # Thursday + Friday
        self.assertEqual({"global"}, global_keys)
        self.assertTrue(all(key.startswith("hour:") for key in hour_keys))
        self.assertTrue(all(key.startswith("dow:") for key in dow_keys))
        conn.close()


class SnapshotTest(BuilderTestCase):
    def test_snapshot_values_match_distribution(self):
        fake = self.standard_setup()
        report = self.run_builder(fake, persist=True)
        self.assertTrue(report["snapshots_to_upsert"] > 0)
        conn = make_conn(self.db_path)
        row = conn.execute(
            "SELECT samples, p50, mad, min, max, avg, first_sample_at, last_sample_at"
            " FROM behavior_baselines_v1 WHERE entity_type='prefix_direction' AND entity_key=? AND metric='bps' AND bucket_type='global'",
            (f"{PREFIX}|in",),
        ).fetchone()
        # 7500 bytes/min -> bps = 7500*8/60 = 1000, constant across 57 windows.
        self.assertEqual(57, int(row["samples"]))
        self.assertAlmostEqual(1000.0, row["p50"])
        self.assertAlmostEqual(0.0, row["mad"])
        self.assertAlmostEqual(1000.0, row["min"])
        self.assertAlmostEqual(1000.0, row["max"])
        self.assertAlmostEqual(1000.0, row["avg"])
        self.assertTrue(row["first_sample_at"].startswith("2026-08-14T11:10"))
        self.assertTrue(row["last_sample_at"].startswith("2026-08-14T12:06"))
        conn.close()

    def test_aggregate_prefix_combines_both_directions(self):
        fake = self.standard_setup()
        self.run_builder(fake, persist=True)
        conn = make_conn(self.db_path)
        row = conn.execute(
            "SELECT samples, p50 FROM behavior_baselines_v1 WHERE entity_type='prefix' AND entity_key=? AND metric='bps' AND bucket_type='global'",
            (PREFIX,),
        ).fetchone()
        # in (7500 bytes) + out (7500 bytes) = 15000 bytes -> bps 2000.
        self.assertEqual(57, int(row["samples"]))
        self.assertAlmostEqual(2000.0, row["p50"])
        conn.close()

    def test_payload_protocol_distribution_stored(self):
        fake = self.standard_setup()
        report = self.run_builder(fake, persist=True, min_bucket_samples=1)
        self.assertTrue(report["payload_snapshots_to_upsert"] > 0)
        conn = make_conn(self.db_path)
        rows = conn.execute(
            "SELECT payload_json FROM behavior_baselines_v1 WHERE metric='protocol_distribution' AND entity_type='prefix_direction'"
        ).fetchall()
        self.assertTrue(rows)
        payload = json.loads(rows[0]["payload_json"])
        self.assertEqual(1.0, payload["protocol_distribution"].get("6"))
        self.assertTrue(payload["top_dst_ports"])
        self.assertEqual("443", payload["top_dst_ports"][0]["port"])
        conn.close()

    def test_hour_counters_upserted(self):
        fake = self.standard_setup()
        report = self.run_builder(fake, persist=True)
        # 2 hours touched (11 and 12) x 7 entities.
        self.assertEqual(14, report["counter_rows_to_upsert"])
        conn = make_conn(self.db_path)
        row = conn.execute(
            "SELECT eligible, quarantined, rejected, insufficient FROM behavior_baseline_hour_counters WHERE hour='2026-08-14T12:00:00Z'"
            " AND entity_type='prefix' AND entity_key=?",
            (PREFIX,),
        ).fetchone()
        self.assertEqual(7, int(row["eligible"]))  # minutes 12:00..12:06
        conn.close()


class CheckpointResumeTest(BuilderTestCase):
    def test_incremental_checkpoint_and_resume(self):
        fake = self.standard_setup()
        report1 = self.run_builder(fake, persist=True)
        self.assertEqual("2026-08-14T12:07:00Z", report1["window_range"]["end"])
        conn = make_conn(self.db_path)
        state = conn.execute("SELECT last_processed_minute, last_success_at FROM behavior_baseline_runtime_state WHERE id=1").fetchone()
        self.assertEqual("2026-08-14T12:07:00Z", state["last_processed_minute"])
        self.assertTrue(state["last_success_at"])
        conn.close()

        # Advance 80 minutes: only the new closed minutes are processed.
        now2 = datetime(2026, 8, 14, 13, 30, tzinfo=timezone.utc)
        fake2 = FakeClickHouse()
        end2 = now2 - timedelta(minutes=DEFAULT_CLOSED_WINDOW_DELAY_MINUTES)
        start2 = datetime(2026, 8, 14, 12, 7, tzinfo=timezone.utc)
        minutes = minute_range(start2, end2)
        fake2.proto_rows = proto_rows_for(minutes)
        fake2.uniq_rows = uniq_rows_for(minutes)
        fake2.prefix_metric_rows = prefix_metric_rows_for(minutes)
        fake2.prefix_uniq_rows = prefix_uniq_rows_for(minutes)
        report2 = self.run_builder(fake2, now=now2, persist=True)
        self.assertEqual("2026-08-14T12:07:00Z", report2["window_range"]["start"])
        self.assertEqual(80 * 7, report2["windows_processed"])
        self.assertEqual(80 * 7, report2["eligible"])
        conn = make_conn(self.db_path)
        state = conn.execute("SELECT last_processed_minute FROM behavior_baseline_runtime_state WHERE id=1").fetchone()
        self.assertEqual("2026-08-14T13:27:00Z", state["last_processed_minute"])
        conn.close()

    def test_idempotency_second_run_processes_nothing(self):
        fake = self.standard_setup()
        self.run_builder(fake, persist=True)
        conn = make_conn(self.db_path)
        snapshots_before = conn.execute("SELECT COUNT(*) FROM behavior_baselines_v1").fetchone()[0]
        audit_before = conn.execute("SELECT COUNT(*) FROM behavior_baseline_window_audit").fetchone()[0]
        conn.close()
        report2 = self.run_builder(FakeClickHouse(), persist=True)
        self.assertEqual(0, report2["windows_processed"])
        conn = make_conn(self.db_path)
        self.assertEqual(snapshots_before, conn.execute("SELECT COUNT(*) FROM behavior_baselines_v1").fetchone()[0])
        self.assertEqual(audit_before, conn.execute("SELECT COUNT(*) FROM behavior_baseline_window_audit").fetchone()[0])
        conn.close()

    def test_sqlite_failure_keeps_checkpoint_unchanged(self):
        class BrokenConn:
            def __init__(self, real):
                self.real = real

            def execute(self, *args, **kwargs):
                return self.real.execute(*args, **kwargs)

            def commit(self):
                raise RuntimeError("disk full")

            def rollback(self):
                self.real.rollback()

            def close(self):
                self.real.close()

        fake = self.standard_setup()
        config = BaselineBuilderConfig()
        builder = BaselineBuilder(
            lambda: BrokenConn(make_conn(self.db_path)), fake, config, now_fn=lambda: NOW
        )
        with self.assertRaises(RuntimeError):
            builder.build_once(persist=True)
        conn = make_conn(self.db_path)
        try:
            state = conn.execute("SELECT COUNT(*) FROM behavior_baseline_runtime_state").fetchone()[0]
        except sqlite3.OperationalError:
            state = 0
        self.assertEqual(0, state)
        conn.close()


class UnitHelpersTest(BuilderTestCase):
    def test_signal_matching_rules(self):
        prefix_entity = {"entity_type": ENTITY_PREFIX, "entity_key": PREFIX, "prefix": PREFIX, "direction": "in"}
        sensor_entity = {"entity_type": ENTITY_SENSOR, "entity_key": "S1|in", "sensor": "S1", "direction": "in"}
        signal_in_prefix = {"sensor": "", "target_ip": "186.232.160.10", "src_ip": "", "target_prefix": ""}
        signal_wrong_sensor = {"sensor": "OTHER", "target_ip": "186.232.160.10", "src_ip": "", "target_prefix": ""}
        self.assertTrue(_signal_matches_entity(signal_in_prefix, prefix_entity))
        self.assertFalse(_signal_matches_entity(signal_in_prefix, sensor_entity))
        self.assertFalse(_signal_matches_entity(signal_wrong_sensor, sensor_entity))
        self.assertTrue(_signal_matches_entity({"sensor": "S1"}, sensor_entity))

    def test_build_metrics_payload_rates_and_shares(self):
        bucket = {"bytes": 15000.0, "packets": 150.0, "flows": 15.0,
                  "proto_bytes": {"6": 7500.0, "17": 7500.0},
                  "port_bytes": {"443": 7500.0, "53": 7500.0},
                  "unique_sources": 20.0, "unique_destinations": 30.0}
        metrics, payload = _build_metrics_payload(bucket)
        self.assertAlmostEqual(2000.0, metrics["bps"])
        self.assertAlmostEqual(2.5, metrics["pps"])
        self.assertAlmostEqual(15.0, metrics["flows"])
        self.assertEqual(20.0, metrics["unique_sources"])
        self.assertEqual(30.0, metrics["unique_destinations"])
        self.assertAlmostEqual(0.5, payload["protocol_shares"]["6"])
        self.assertAlmostEqual(0.5, payload["protocol_shares"]["17"])
        ports = {item["port"]: item["share"] for item in payload["top_dst_ports"]}
        self.assertAlmostEqual(0.5, ports["443"])
        self.assertAlmostEqual(0.5, ports["53"])

    def test_fanout_produces_all_entity_views(self):
        minute = datetime(2026, 8, 14, 11, 10, tzinfo=timezone.utc)
        entities = [
            {"entity_type": ENTITY_PREFIX, "entity_key": PREFIX, "prefix": PREFIX, "direction": "in"},
            {"entity_type": ENTITY_PREFIX_DIRECTION, "entity_key": f"{PREFIX}|in", "prefix": PREFIX, "direction": "in"},
            {"entity_type": ENTITY_PREFIX_DIRECTION, "entity_key": f"{PREFIX}|out", "prefix": PREFIX, "direction": "out"},
            {"entity_type": ENTITY_SENSOR, "entity_key": "S1|in", "sensor": "S1", "direction": "in"},
            {"entity_type": ENTITY_INTERFACE, "entity_key": "S1|10|in", "sensor": "S1", "if_index": 10, "direction": "in"},
        ]
        out = fanout_entity_minutes(
            proto_rows_for([minute]),
            uniq_rows_for([minute]),
            prefix_metric_rows_for([minute]),
            prefix_uniq_rows_for([minute]),
            entities,
        )
        minute_iso = iso(minute)
        # aggregate prefix combines in+out (bps 2000, no uniques)
        metrics, _ = out[PREFIX][minute_iso]
        self.assertAlmostEqual(2000.0, metrics["bps"])
        self.assertNotIn("unique_sources", metrics)
        # prefix direction in: bps 1000 with uniques
        metrics, _ = out[f"{PREFIX}|in"][minute_iso]
        self.assertAlmostEqual(1000.0, metrics["bps"])
        self.assertEqual(5.0, metrics["unique_sources"])
        self.assertEqual(7.0, metrics["unique_destinations"])
        # sensor and interface
        metrics, _ = out["S1|in"][minute_iso]
        self.assertAlmostEqual(1000.0, metrics["bps"])
        metrics, _ = out["S1|10|in"][minute_iso]
        self.assertAlmostEqual(1000.0, metrics["bps"])
        self.assertEqual(5.0, metrics["unique_sources"])

    def test_attack_signals_query_reads_security_events(self):
        conn = make_conn(self.db_path)
        seed_entities(conn)
        minute = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
        seed_confirmed_event(conn, minute)
        signals = fetch_attack_signals(conn, minute, minute + timedelta(seconds=WINDOW_SECONDS))
        self.assertEqual(1, len(signals))
        self.assertEqual("CONFIRMED_ATTACK", signals[0]["verdict"])
        conn.close()


class PrefixLookupTest(BuilderTestCase):
    def test_longest_prefix_match_orders_most_specific_first(self):
        lookup = MultiIfPrefixLookup(["100.64.0.0/10", "100.64.1.10/32", "100.64.1.0/24"])
        self.assertEqual(["100.64.1.10/32", "100.64.1.0/24", "100.64.0.0/10"], lookup.prefixes)
        expr = lookup.expression("dst_ip")
        self.assertLess(expr.index("/32"), expr.index("/24"))
        self.assertLess(expr.index("/24"), expr.index("/10"))

    def test_normalizes_ipv4_mapped_and_uses_isipaddressinrange(self):
        lookup = MultiIfPrefixLookup([PREFIX])
        expr = lookup.expression("dst_ip")
        self.assertIn("replaceRegexpOne", expr)
        self.assertIn("::ffff:", expr)
        self.assertIn("isIPAddressInRange", expr)
        self.assertIn("multiIf", expr)

    def test_ip_trie_is_gated_until_approved(self):
        with self.assertRaises(NotImplementedError):
            IpTriePrefixLookup([PREFIX]).expression("dst_ip")


class QueryCountScaleTest(BuilderTestCase):
    def test_query_count_constant_with_entity_count(self):
        class Counting:
            def __init__(self):
                self.n = 0

            def __call__(self, sql, params=None):
                self.n += 1
                return []

        start = NOW - timedelta(hours=1)
        # Prefixes: 20 / 100 / 500 / 2000 -> always exactly 2 queries.
        for n_prefixes in (20, 100, 500, 2000):
            lookup = MultiIfPrefixLookup([f"10.{i // 256}.{i % 256}.0/24" for i in range(n_prefixes)])
            counter = Counting()
            fetch_batch_prefix_metrics(counter, start, NOW, lookup)
            fetch_batch_prefix_uniques(counter, start, NOW, lookup)
            self.assertEqual(2, counter.n, f"{n_prefixes} prefixes must stay at 2 queries")

        # Interface/sensor: constant 2 queries (not parameterized by entity).
        counter = Counting()
        fetch_batch_protocol_metrics(counter, start, NOW)
        fetch_batch_interface_uniques(counter, start, NOW)
        self.assertEqual(2, counter.n)


class ProcessedChunksIdempotencyTest(BuilderTestCase):
    """Explicit chunk deduplication (FASE 1.1/1.2/1.3)."""

    def test_processed_chunk_recorded_with_deterministic_id(self):
        fake = self.standard_setup()
        self.run_builder(fake, persist=True)
        conn = make_conn(self.db_path)
        row = conn.execute(
            "SELECT chunk_id, chunk_start, chunk_end, status, windows_processed, runtime_seconds "
            "FROM behavior_baseline_processed_chunks"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(CHUNK_STATUS_COMPLETED, row["status"])
        self.assertEqual("2026-08-14T11:10:00Z", row["chunk_start"])
        self.assertEqual("2026-08-14T12:07:00Z", row["chunk_end"])
        self.assertGreater(int(row["windows_processed"]), 0)
        conn.close()

    def test_same_chunk_twice_does_not_double_counters(self):
        fake = self.standard_setup()
        self.run_builder(fake, persist=True)
        conn = make_conn(self.db_path)
        eligible_before = conn.execute(
            "SELECT COALESCE(SUM(eligible),0) FROM behavior_baseline_hour_counters"
        ).fetchone()[0]
        snapshots_before = conn.execute("SELECT COUNT(*) FROM behavior_baselines_v1").fetchone()[0]
        audit_before = conn.execute("SELECT COUNT(*) FROM behavior_baseline_window_audit").fetchone()[0]
        counter_rows_before = conn.execute("SELECT COUNT(*) FROM behavior_baseline_hour_counters").fetchone()[0]
        chunks_before = conn.execute("SELECT COUNT(*) FROM behavior_baseline_processed_chunks").fetchone()[0]
        conn.close()

        # Explicitly re-run the exact same chunk.
        start = NOW - timedelta(hours=1)
        end = NOW - timedelta(minutes=DEFAULT_CLOSED_WINDOW_DELAY_MINUTES)
        builder = BaselineBuilder(
            lambda: make_conn(self.db_path),
            FakeClickHouse(),
            BaselineBuilderConfig(bootstrap_hours=1),
            now_fn=lambda: NOW,
        )
        report2 = builder.build_once(persist=True, start=start, end=end)

        self.assertEqual(SKIPPED_ALREADY_PROCESSED, report2["chunk_status"])
        self.assertEqual(0, report2["windows_processed"])
        conn = make_conn(self.db_path)
        self.assertEqual(eligible_before, conn.execute(
            "SELECT COALESCE(SUM(eligible),0) FROM behavior_baseline_hour_counters"
        ).fetchone()[0])
        self.assertEqual(snapshots_before, conn.execute("SELECT COUNT(*) FROM behavior_baselines_v1").fetchone()[0])
        self.assertEqual(audit_before, conn.execute("SELECT COUNT(*) FROM behavior_baseline_window_audit").fetchone()[0])
        self.assertEqual(counter_rows_before, conn.execute("SELECT COUNT(*) FROM behavior_baseline_hour_counters").fetchone()[0])
        self.assertEqual(chunks_before, conn.execute("SELECT COUNT(*) FROM behavior_baseline_processed_chunks").fetchone()[0])
        conn.close()


class ContinuousShadowTest(BuilderTestCase):
    """Continuous SHADOW (FASE 1.5-1.8): only new minutes, load-guard skip, no overlap."""

    def _seed_checkpoint(self):
        fake = self.standard_setup()
        self.run_builder(fake, persist=True)  # checkpoint = 12:07

    def _fill(self, fake, start, end):
        minutes = minute_range(start, end)
        fake.proto_rows = proto_rows_for(minutes)
        fake.uniq_rows = uniq_rows_for(minutes)
        fake.prefix_metric_rows = prefix_metric_rows_for(minutes)
        fake.prefix_uniq_rows = prefix_uniq_rows_for(minutes)

    def test_cycle_processes_only_new_minutes_since_checkpoint(self):
        self._seed_checkpoint()
        now2 = datetime(2026, 8, 14, 12, 20, tzinfo=timezone.utc)
        fake2 = FakeClickHouse()
        self._fill(fake2, datetime(2026, 8, 14, 12, 7, tzinfo=timezone.utc),
                   now2 - timedelta(minutes=DEFAULT_CLOSED_WINDOW_DELAY_MINUTES))
        report = continuous_shadow_cycle(
            lambda: make_conn(self.db_path), fake2, now_fn=lambda: now2, persist=True,
        )
        self.assertEqual(CHUNK_STATUS_COMPLETED, report["status"])
        self.assertEqual("2026-08-14T12:07:00Z", report["window_range"]["start"])
        self.assertEqual("2026-08-14T12:17:00Z", report["window_range"]["end"])
        self.assertEqual(10 * 7, report["windows_processed"])
        # A second cycle with no new minutes yields NO_NEW_MINUTES.
        report2 = continuous_shadow_cycle(
            lambda: make_conn(self.db_path), FakeClickHouse(), now_fn=lambda: now2, persist=True,
        )
        self.assertEqual(NO_NEW_MINUTES, report2["status"])

    def test_cycle_skips_on_load_guard_and_checkpoint_does_not_advance(self):
        self._seed_checkpoint()
        now2 = datetime(2026, 8, 14, 12, 20, tzinfo=timezone.utc)
        with mock.patch("app.services.behavior_engine._host_load_1", return_value=99.0):
            report = continuous_shadow_cycle(
                lambda: make_conn(self.db_path), FakeClickHouse(),
                max_load=8.0, now_fn=lambda: now2, persist=True,
            )
        self.assertEqual(SKIPPED_LOAD_GUARD, report["status"])
        conn = make_conn(self.db_path)
        state = conn.execute(
            "SELECT last_processed_minute FROM behavior_baseline_runtime_state WHERE id=1"
        ).fetchone()
        self.assertEqual("2026-08-14T12:07:00Z", state["last_processed_minute"])
        conn.close()


if __name__ == "__main__":
    unittest.main()
