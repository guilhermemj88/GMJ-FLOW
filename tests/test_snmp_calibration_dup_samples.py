"""Testes para o par SNMP válido na calibração (poll duplicado / zero-delta).

Cenário de produção: o poll forçado grava uma amostra poucos segundos após a
anterior com os MESMOS ifHCInOctets/ifHCOutOctets. A leitura cega das duas
últimas linhas devolvia in_bps=0/out_bps=0 e "SNMP inválido".

Cobre os casos A-G solicitados:
  A) duas últimas iguais + terceira anterior válida -> par válido
  B) várias duplicadas + par válido anterior -> funciona
  C) somente duplicadas -> erro SNMP claro
  D) counter reset/regressão -> par ignorado
  E) IN com delta / OUT sem delta -> IN calibrável
  F) OUT com delta / IN sem delta -> OUT calibrável
  G) calibração histórica ignora zero-delta -> robust ratio correto
"""

import sqlite3
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

_ai_stub = types.ModuleType("app.services.ai_integration")
_ai_stub.__getattr__ = lambda name: (lambda *args, **kwargs: None)
sys.modules.setdefault("app.services.ai_integration", _ai_stub)

from tests.test_collector_apply_static import backend_main


class FakeClickHouseResult:
    def __init__(self, columns, rows):
        self.column_names = columns
        self.result_rows = rows


class _ConnCM:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self.conn

    def __exit__(self, *args):
        return False


def sample(time_text, in_octets, out_octets, in_bps=0.0, out_bps=0.0):
    return {
        "sample_time": time_text,
        "in_octets": in_octets,
        "out_octets": out_octets,
        "in_bps": in_bps,
        "out_bps": out_bps,
    }


class SnmpPairSelectionTests(unittest.TestCase):
    def test_case_a_last_two_equal_third_older_valid(self):
        rows = [
            sample("2026-08-30T00:10:05Z", 200, 200),  # dup (poll forçado)
            sample("2026-08-30T00:10:00Z", 200, 200),  # igual
            sample("2026-08-30T00:09:00Z", 100, 100),  # anterior válida
        ]
        pair = backend_main.select_snmp_sample_pair(rows)
        self.assertTrue(pair["ok"])
        self.assertEqual(pair["interval_seconds"], 60.0)
        self.assertEqual(pair["in_octets_2"], 200)
        self.assertEqual(pair["in_octets_1"], 100)
        self.assertEqual(pair["in_bps"], round(100 * 8 / 60, 2))
        self.assertGreater(pair["in_bps"], 0)

    def test_case_b_several_duplicates_then_valid_pair(self):
        rows = [
            sample("2026-08-30T00:10:20Z", 500, 500),
            sample("2026-08-30T00:10:15Z", 500, 500),
            sample("2026-08-30T00:10:10Z", 500, 500),
            sample("2026-08-30T00:10:05Z", 500, 500),
            sample("2026-08-30T00:09:00Z", 100, 100),
        ]
        pair = backend_main.select_snmp_sample_pair(rows)
        self.assertTrue(pair["ok"])
        self.assertGreater(pair["in_bps"], 0)
        self.assertGreater(pair["out_bps"], 0)

    def test_case_c_only_duplicates_clear_snmp_error(self):
        rows = [
            sample("2026-08-30T00:10:20Z", 500, 500),
            sample("2026-08-30T00:10:15Z", 500, 500),
            sample("2026-08-30T00:10:10Z", 500, 500),
        ]
        pair = backend_main.select_snmp_sample_pair(rows)
        self.assertFalse(pair["ok"])
        self.assertIn("SNMP", pair["error"])

    def test_case_c_single_sample_error(self):
        pair = backend_main.select_snmp_sample_pair([sample("2026-08-30T00:10:00Z", 1, 1)])
        self.assertFalse(pair["ok"])
        self.assertIn("SNMP", pair["error"])

    def test_case_d_counter_regression_pair_ignored(self):
        rows = [
            sample("2026-08-30T00:10:10Z", 150, 150),  # menor que anterior: reset
            sample("2026-08-30T00:10:00Z", 300, 300),
        ]
        pair = backend_main.select_snmp_sample_pair(rows)
        self.assertFalse(pair["ok"])
        self.assertIn("SNMP", pair["error"])

    def test_case_d_regression_skipped_older_pair_used(self):
        rows = [
            sample("2026-08-30T00:10:10Z", 50, 50),    # reset após reboot
            sample("2026-08-30T00:10:00Z", 900, 900),  # regressão em relação a 00:09
            sample("2026-08-30T00:09:00Z", 100, 100),  # par válido antigo
        ]
        pair = backend_main.select_snmp_sample_pair(rows)
        self.assertTrue(pair["ok"])
        self.assertEqual((pair["in_octets_2"], pair["in_octets_1"]), (900, 100))
        self.assertGreater(pair["in_bps"], 0)

    def test_case_e_in_delta_out_zero(self):
        rows = [
            sample("2026-08-30T00:10:00Z", 300, 100),
            sample("2026-08-30T00:09:00Z", 100, 100),
        ]
        pair = backend_main.select_snmp_sample_pair(rows)
        self.assertTrue(pair["ok"])
        self.assertGreater(pair["in_bps"], 0)
        self.assertEqual(pair["out_bps"], 0.0)

    def test_case_f_out_delta_in_zero(self):
        rows = [
            sample("2026-08-30T00:10:00Z", 100, 300),
            sample("2026-08-30T00:09:00Z", 100, 100),
        ]
        pair = backend_main.select_snmp_sample_pair(rows)
        self.assertTrue(pair["ok"])
        self.assertEqual(pair["in_bps"], 0.0)
        self.assertGreater(pair["out_bps"], 0)

    def test_pair_recomputes_bps_ignoring_stored_zero(self):
        # in_bps/out_bps pré-calculados zerados na linha mais recente não
        # podem esconder o par válido.
        rows = [
            sample("2026-08-30T00:10:00Z", 1000, 1000, in_bps=0.0, out_bps=0.0),
            sample("2026-08-30T00:09:00Z", 0, 0, in_bps=0.0, out_bps=0.0),
        ]
        pair = backend_main.select_snmp_sample_pair(rows)
        self.assertTrue(pair["ok"])
        self.assertEqual(pair["in_bps"], round(1000 * 8 / 60, 2))


class CalibrationDiagnosticsWithDuplicatesTests(unittest.TestCase):
    def test_case_a_diagnostics_finds_valid_pair_and_returns_bps(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            CREATE TABLE interface_snmp_samples (
                sensor_id INTEGER, if_index INTEGER, sample_time TEXT,
                in_octets INTEGER, out_octets INTEGER, in_bps REAL, out_bps REAL,
                if_oper_status TEXT DEFAULT ''
            )
            """
        )
        conn.execute("CREATE TABLE sensor_interfaces (id INTEGER, sensor_id INTEGER, if_index INTEGER)")
        conn.execute("INSERT INTO sensor_interfaces (id, sensor_id, if_index) VALUES (1, 1, 202)")
        rows = [
            ("2026-08-30T00:10:05Z", 200, 200),
            ("2026-08-30T00:10:00Z", 200, 200),
            ("2026-08-30T00:09:00Z", 100, 100),
        ]
        for time_text, in_octets, out_octets in rows:
            conn.execute(
                "INSERT INTO interface_snmp_samples (sensor_id, if_index, sample_time, in_octets, out_octets, in_bps, out_bps) "
                "VALUES (1, 202, ?, ?, ?, 0, 0)",
                (time_text, in_octets, out_octets),
            )
        conn.commit()

        def fake_fetch_sensor(connection, sensor_id):
            return {"exporter_ip": "::ffff:1.2.3.4"}

        def fake_clickhouse(query, params=None):
            return FakeClickHouseResult(
                ["rows", "raw_input_bps", "raw_output_bps"],
                [[3, 2_000_000.0, 1_500_000.0]],
            )

        with mock.patch.object(backend_main, "ensure_sensor_db", lambda: None), \
             mock.patch.object(backend_main, "sqlite_connection", lambda: _ConnCM(conn)), \
             mock.patch.object(backend_main, "fetch_sensor_without_interfaces", fake_fetch_sensor), \
             mock.patch.object(backend_main, "query_clickhouse", fake_clickhouse):
            result = backend_main.calibration_diagnostics(1, 202, 5)

        self.assertTrue(result["snmp"]["ok"], result)
        self.assertGreater(result["snmp"]["in_bps"], 0)
        self.assertGreater(result["flow"]["raw_input_bps"], 0)
        self.assertEqual(
            result["suggested_sample_rate"]["in"],
            round(result["snmp"]["in_bps"] / result["flow"]["raw_input_bps"], 2),
        )
        self.assertEqual(result["reason"], "")

    def test_case_c_diagnostics_only_duplicates_clear_error(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            CREATE TABLE interface_snmp_samples (
                sensor_id INTEGER, if_index INTEGER, sample_time TEXT,
                in_octets INTEGER, out_octets INTEGER, in_bps REAL, out_bps REAL,
                if_oper_status TEXT DEFAULT ''
            )
            """
        )
        conn.execute("CREATE TABLE sensor_interfaces (id INTEGER, sensor_id INTEGER, if_index INTEGER)")
        conn.execute("INSERT INTO sensor_interfaces (id, sensor_id, if_index) VALUES (1, 1, 202)")
        for time_text in ("2026-08-30T00:10:10Z", "2026-08-30T00:10:05Z", "2026-08-30T00:10:00Z"):
            conn.execute(
                "INSERT INTO interface_snmp_samples (sensor_id, if_index, sample_time, in_octets, out_octets, in_bps, out_bps) "
                "VALUES (1, 202, ?, 500, 500, 0, 0)",
                (time_text,),
            )
        conn.commit()

        def fake_fetch_sensor(connection, sensor_id):
            return {"exporter_ip": "::ffff:1.2.3.4"}

        def fake_clickhouse(query, params=None):
            return FakeClickHouseResult(
                ["rows", "raw_input_bps", "raw_output_bps"],
                [[3, 2_000_000.0, 1_500_000.0]],
            )

        with mock.patch.object(backend_main, "ensure_sensor_db", lambda: None), \
             mock.patch.object(backend_main, "sqlite_connection", lambda: _ConnCM(conn)), \
             mock.patch.object(backend_main, "fetch_sensor_without_interfaces", fake_fetch_sensor), \
             mock.patch.object(backend_main, "query_clickhouse", fake_clickhouse):
            result = backend_main.calibration_diagnostics(1, 202, 5)

        self.assertFalse(result["snmp"]["ok"])
        self.assertIn("SNMP", result["snmp"]["error"])
        self.assertEqual(result["suggested_sample_rate"]["in"], 1.0)


class CalibrateIgnoresZeroDeltaTests(unittest.TestCase):
    def _memory_db(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE sensor_interfaces (id INTEGER, sensor_id INTEGER, if_index INTEGER)")
        conn.execute(
            """
            CREATE TABLE interface_snmp_samples (
                sensor_id INTEGER, if_index INTEGER, sample_time TEXT,
                in_octets INTEGER, out_octets INTEGER, in_bps REAL, out_bps REAL,
                if_oper_status TEXT DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE sensor_interface_calibration (
                sensor_id INTEGER,
                if_index INTEGER,
                estimated_sample_rate_in REAL,
                estimated_sample_rate_out REAL,
                confidence REAL,
                last_calibrated_at TEXT,
                method TEXT,
                samples_used INTEGER,
                snmp_in_bps REAL,
                snmp_out_bps REAL,
                flow_in_bps REAL,
                flow_out_bps REAL,
                PRIMARY KEY (sensor_id, if_index)
            )
            """
        )
        conn.commit()
        return conn

    def test_case_g_historical_calibration_ignores_zero_delta(self):
        conn = self._memory_db()
        now = datetime.now(timezone.utc)
        t0 = now - timedelta(minutes=12)
        t_dup = t0 + timedelta(seconds=5)
        t2 = t0 + timedelta(seconds=120)
        samples = [
            (backend_main.iso(t0), 1_000_000_000, 0),
            (backend_main.iso(t_dup), 1_000_000_000, 0),  # dup: delta zero
            (backend_main.iso(t2), 1_007_500_000, 0),      # 7.5MB em 120s = 500 kbps
        ]
        for time_text, in_octets, out_octets in samples:
            conn.execute(
                "INSERT INTO interface_snmp_samples (sensor_id, if_index, sample_time, in_octets, out_octets, in_bps, out_bps) "
                "VALUES (1, 284, ?, ?, ?, 0, 0)",
                (time_text, in_octets, out_octets),
            )
        conn.execute("INSERT INTO sensor_interfaces (id, sensor_id, if_index) VALUES (1, 1, 284)")
        conn.commit()

        def fake_fetch_sensor(connection, sensor_id):
            return {"exporter_ip": "1.2.3.4", "name": "s"}

        def fake_flow(exporter_ip, if_index, direction, start, end):
            return 1_000_000.0

        with mock.patch.object(backend_main, "ensure_sensor_db", lambda: None), \
             mock.patch.object(backend_main, "sqlite_connection", lambda: _ConnCM(conn)), \
             mock.patch.object(backend_main, "fetch_sensor_without_interfaces", fake_fetch_sensor), \
             mock.patch.object(backend_main, "flow_interface_direction_bps", fake_flow):
            result = backend_main.calibrate_interface_sample_rate(1, 284, 15)

        self.assertTrue(result["snmp_ok"], result)
        self.assertEqual(result["samples_used_in"], 1)
        self.assertEqual(result["estimated_sample_rate_in"], 0.5)
        self.assertGreater(result["confidence_in"], 0)
        self.assertEqual(result["snmp_in_bps"], 500_000.0)
        self.assertTrue(result["saved"])

    def test_case_g_only_duplicates_calibration_does_not_persist(self):
        conn = self._memory_db()
        now = datetime.now(timezone.utc)
        t0 = now - timedelta(minutes=12)
        for seconds in (0, 5, 10, 15):
            conn.execute(
                "INSERT INTO interface_snmp_samples (sensor_id, if_index, sample_time, in_octets, out_octets, in_bps, out_bps) "
                "VALUES (1, 284, ?, 500, 500, 0, 0)",
                (backend_main.iso(t0 + timedelta(seconds=seconds)),),
            )
        conn.execute("INSERT INTO sensor_interfaces (id, sensor_id, if_index) VALUES (1, 1, 284)")
        conn.commit()

        def fake_fetch_sensor(connection, sensor_id):
            return {"exporter_ip": "1.2.3.4", "name": "s"}

        def fake_flow(exporter_ip, if_index, direction, start, end):
            return 1_000_000.0

        with mock.patch.object(backend_main, "ensure_sensor_db", lambda: None), \
             mock.patch.object(backend_main, "sqlite_connection", lambda: _ConnCM(conn)), \
             mock.patch.object(backend_main, "fetch_sensor_without_interfaces", fake_fetch_sensor), \
             mock.patch.object(backend_main, "flow_interface_direction_bps", fake_flow):
            result = backend_main.calibrate_interface_sample_rate(1, 284, 15)

        self.assertFalse(result["snmp_ok"])
        self.assertFalse(result["saved"])
        self.assertEqual(result["samples_used"], 0)


if __name__ == "__main__":
    unittest.main()
