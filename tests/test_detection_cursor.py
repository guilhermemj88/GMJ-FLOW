"""Testes do cursor temporal / reconciliacao do detector (PERF-B).

Cobrem: bootstrap, contiguidade (sem gap), falha de bucket (cursor nao avanca),
retry, limite de buckets por ciclo, restart (cursor persistido), clock skew,
watermark e ausencia de buckets duplicados.
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for candidate in (str(ROOT), str(ROOT / "backend")):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from backend.app import main as backend_main  # noqa: E402

WINDOW = 60


def make_connection(path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    backend_main.ensure_ip_zone_detection_db(conn)
    return conn


def rule_row(template_id: int = 1, window: int = WINDOW, rule_id: int = 1) -> dict:
    return {
        "id": rule_id,
        "template_id": template_id,
        "enabled": 1,
        "template_active": 1,
        "window_seconds": window,
        "vector": "TESTE",
    }


class FakeEvaluator:
    def __init__(self, fail_on=()):
        self.calls = []
        self.fail_on = set(fail_on)

    def __call__(self, conn, raw_rule, end_dt, **kwargs):
        key = backend_main.iso(end_dt)
        self.calls.append(key)
        if key in self.fail_on:
            raise RuntimeError("falha simulada no bucket")
        return {"anomalies_created": 0, "skipped_reason": ""}


class ReconciliationTest(unittest.TestCase):
    def setUp(self):
        self._env = mock.patch.dict(
            os.environ,
            {
                "GMJFLOW_DETECTION_WATERMARK_SECONDS": "240",
                "GMJFLOW_DETECTION_RECONCILE_MAX_BUCKETS": "6",
                "GMJFLOW_DETECTION_RECONCILE_ENABLED": "true",
            },
            clear=False,
        )
        self._env.start()
        self.addCleanup(self._env.stop)
        self._flush = mock.patch.object(backend_main.media_dispatch, "flush_pending_created", lambda *a, **k: None)
        self._flush.start()
        self.addCleanup(self._flush.stop)

    def run_reconcile(self, conn, rows, end_dt, evaluator, **kwargs):
        return backend_main.reconcile_detection_template_buckets(
            conn,
            rows,
            end_dt=end_dt,
            create_anomalies=False,
            evaluator=evaluator,
            **kwargs,
        )

    def test_bootstrap_processa_apenas_um_bucket_e_persiste_cursor(self):
        conn = make_connection()
        end_dt = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)
        evaluator = FakeEvaluator()
        result = self.run_reconcile(conn, [rule_row()], end_dt, evaluator)

        self.assertEqual(result["buckets_processed"], 1)
        self.assertEqual(len(evaluator.calls), 1)
        watermark_at = backend_main.parse_datetime_text(result["watermark_at"])
        self.assertEqual(backend_main.iso(watermark_at), "2026-10-06T11:56:00Z")
        # bucket [11:55:00, 11:56:00) — fim alinhado ao watermark
        self.assertEqual(evaluator.calls[0], "2026-10-06T11:56:00Z")
        self.assertEqual(result["last_evaluated_until"], "2026-10-06T11:56:00Z")
        stored = backend_main.detection_cursor_until(conn, 1, WINDOW)
        self.assertEqual(backend_main.iso(stored), "2026-10-06T11:56:00Z")

    def test_buckets_contiguos_sem_gap(self):
        conn = make_connection()
        start = datetime(2026, 10, 6, 11, 0, 0, tzinfo=timezone.utc)
        backend_main.detection_cursor_write(conn, 1, WINDOW, start)
        conn.commit()
        end_dt = start + timedelta(seconds=5 * WINDOW + 240)
        evaluator = FakeEvaluator()
        result = self.run_reconcile(conn, [rule_row()], end_dt, evaluator)

        self.assertEqual(result["buckets_processed"], 5)
        expected = [
            backend_main.iso(start + timedelta(seconds=(index + 1) * WINDOW)) for index in range(5)
        ]
        self.assertEqual(evaluator.calls, expected)
        # contiguidade: cada bucket termina onde o proximo comeca
        for previous, current in zip(expected, expected[1:]):
            self.assertEqual(
                backend_main.parse_datetime_text(previous),
                backend_main.parse_datetime_text(current) - timedelta(seconds=WINDOW),
            )
        self.assertEqual(result["last_evaluated_until"], backend_main.iso(start + timedelta(seconds=5 * WINDOW)))
        self.assertEqual(result["buckets_pending"], 0)

    def test_falha_nao_avanca_cursor_e_retry_reprocessa(self):
        conn = make_connection()
        start = datetime(2026, 10, 6, 11, 0, 0, tzinfo=timezone.utc)
        backend_main.detection_cursor_write(conn, 1, WINDOW, start)
        conn.commit()
        end_dt = start + timedelta(seconds=3 * WINDOW + 240)
        failing = backend_main.iso(start + timedelta(seconds=2 * WINDOW))

        evaluator = FakeEvaluator(fail_on=[failing])
        result = self.run_reconcile(conn, [rule_row()], end_dt, evaluator)

        self.assertEqual(result["buckets_processed"], 1)
        self.assertEqual(
            backend_main.iso(backend_main.detection_cursor_until(conn, 1, WINDOW)),
            backend_main.iso(start + timedelta(seconds=WINDOW)),
        )

        retry = FakeEvaluator()
        retry_result = self.run_reconcile(conn, [rule_row()], end_dt, retry)
        self.assertEqual(retry.calls[0], failing)  # mesmo bucket, sem pular
        self.assertEqual(retry_result["buckets_processed"], 2)
        self.assertEqual(
            backend_main.iso(backend_main.detection_cursor_until(conn, 1, WINDOW)),
            backend_main.iso(start + timedelta(seconds=3 * WINDOW)),
        )

    def test_limite_de_buckets_por_ciclo_conta_pendentes(self):
        conn = make_connection()
        start = datetime(2026, 10, 6, 11, 0, 0, tzinfo=timezone.utc)
        backend_main.detection_cursor_write(conn, 1, WINDOW, start)
        conn.commit()
        end_dt = start + timedelta(seconds=5 * WINDOW + 240)
        with mock.patch.dict(os.environ, {"GMJFLOW_DETECTION_RECONCILE_MAX_BUCKETS": "2"}):
            evaluator = FakeEvaluator()
            result = self.run_reconcile(conn, [rule_row()], end_dt, evaluator)

        self.assertEqual(result["buckets_processed"], 2)
        self.assertEqual(result["buckets_pending"], 3)
        self.assertEqual(
            backend_main.iso(backend_main.detection_cursor_until(conn, 1, WINDOW)),
            backend_main.iso(start + timedelta(seconds=2 * WINDOW)),
        )

    def test_restart_retoma_do_cursor_persistido(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "cursor.sqlite")
            conn = make_connection(db_path)
            start = datetime(2026, 10, 6, 11, 0, 0, tzinfo=timezone.utc)
            backend_main.detection_cursor_write(conn, 1, WINDOW, start)
            conn.commit()
            end_dt = start + timedelta(seconds=2 * WINDOW + 240)
            self.run_reconcile(conn, [rule_row()], end_dt, FakeEvaluator())
            conn.close()

            reopened = make_connection(db_path)
            evaluator = FakeEvaluator()
            result = self.run_reconcile(reopened, [rule_row()], end_dt + timedelta(seconds=WINDOW), evaluator)
            reopened.close()

        self.assertEqual(evaluator.calls[0], backend_main.iso(start + timedelta(seconds=3 * WINDOW)))
        self.assertEqual(result["buckets_processed"], 1)

    def test_clock_skew_nao_processa_nem_avanca(self):
        conn = make_connection()
        cursor0 = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)
        backend_main.detection_cursor_write(conn, 1, WINDOW, cursor0)
        conn.commit()
        # "agora" atras do watermark (relogio andou para tras)
        end_dt = cursor0 + timedelta(seconds=60)
        evaluator = FakeEvaluator()
        result = self.run_reconcile(conn, [rule_row()], end_dt, evaluator)
        self.assertEqual(evaluator.calls, [])
        self.assertEqual(result["buckets_processed"], 0)
        self.assertEqual(
            backend_main.iso(backend_main.detection_cursor_until(conn, 1, WINDOW)), backend_main.iso(cursor0)
        )

    def test_nunca_avalia_bucket_duplicado(self):
        conn = make_connection()
        start = datetime(2026, 10, 6, 11, 0, 0, tzinfo=timezone.utc)
        backend_main.detection_cursor_write(conn, 1, WINDOW, start)
        conn.commit()
        end_dt = start + timedelta(seconds=4 * WINDOW + 240)
        evaluator = FakeEvaluator()
        self.run_reconcile(conn, [rule_row()], end_dt, evaluator)
        self.run_reconcile(conn, [rule_row()], end_dt, evaluator)
        self.assertEqual(len(evaluator.calls), len(set(evaluator.calls)))

    def test_watermark_limita_janela(self):
        conn = make_connection()
        start = datetime(2026, 10, 6, 11, 0, 0, tzinfo=timezone.utc)
        backend_main.detection_cursor_write(conn, 1, WINDOW, start)
        conn.commit()
        end_dt = start + timedelta(seconds=10 * WINDOW)
        evaluator = FakeEvaluator()
        result = self.run_reconcile(conn, [rule_row()], end_dt, evaluator)
        watermark_at = backend_main.parse_datetime_text(result["watermark_at"])
        for call in evaluator.calls:
            self.assertLessEqual(backend_main.parse_datetime_text(call), watermark_at)
        self.assertEqual(result["watermark_seconds"], 240)

    def test_isolamento_por_janela_e_template(self):
        conn = make_connection()
        end_dt = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)
        rows = [rule_row(template_id=1, window=60, rule_id=1), rule_row(template_id=1, window=30, rule_id=2)]
        evaluator = FakeEvaluator()
        result = self.run_reconcile(conn, rows, end_dt, evaluator)
        self.assertEqual(result["buckets_processed"], 2)
        self.assertEqual(len(evaluator.calls), 2)  # um bucket por (template, janela)
        self.assertIsNotNone(backend_main.detection_cursor_until(conn, 1, 60))
        self.assertIsNotNone(backend_main.detection_cursor_until(conn, 1, 30))

    def test_dedupe_key_estavel_entre_fast_e_reconciliacao(self):
        """A chave de dedupe NAO pode depender de tempo/bucket: FAST e reconciliacao
        precisam consolidar o MESMO evento (sem duplicar alerta)."""
        candidate = {
            "vector": "PREFIX_INTERNAL_IP_HIGH_UDP_PPS",
            "zone_id": 7,
            "domain": "internal_ip",
            "scope_type": "internal_ip_32",
            "target_cidr": "45.168.200.10/32",
            "protocol": "UDP",
            "first_seen": "2026-10-06T12:00:00Z",
            "last_seen": "2026-10-06T12:01:00Z",
        }
        fast = backend_main.security_anomaly_dedupe_key(dict(candidate))
        reconciled = backend_main.security_anomaly_dedupe_key(
            {**candidate, "first_seen": "2026-10-06T11:00:00Z", "last_seen": "2026-10-06T11:01:00Z"}
        )
        self.assertEqual(fast, reconciled)
        self.assertNotIn("2026", fast)

    def test_regra_desabilitada_nao_cria_cursor(self):
        conn = make_connection()
        end_dt = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)
        disabled = dict(rule_row())
        disabled["enabled"] = 0
        evaluator = FakeEvaluator()
        result = self.run_reconcile(conn, [disabled], end_dt, evaluator)
        self.assertEqual(result["buckets_processed"], 0)
        self.assertIsNone(backend_main.detection_cursor_until(conn, 1, WINDOW))


if __name__ == "__main__":
    unittest.main()
