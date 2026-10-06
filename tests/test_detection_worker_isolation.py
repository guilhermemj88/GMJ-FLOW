"""PERF-C.0 — isolamento do detector: ownership, lease e status compartilhado."""
import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for candidate in (str(ROOT), str(ROOT / "backend")):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from backend.app import main as backend_main  # noqa: E402


class DetectionIsolationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "isolated.sqlite")
        self._env = mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": self.db_path}, clear=False)
        self._env.start()
        self.addCleanup(self._env.stop)
        original_ready = backend_main.SENSOR_DB_READY
        backend_main.SENSOR_DB_READY = False
        self.addCleanup(setattr, backend_main, "SENSOR_DB_READY", original_ready)
        self._thread_backup = backend_main.ANOMALY_DETECTION_THREAD
        self.addCleanup(setattr, backend_main, "ANOMALY_DETECTION_THREAD", self._thread_backup)
        backend_main.ensure_sensor_db()

    # ---- ownership / start ------------------------------------------------
    def test_api_nao_inicia_detector_com_inprocess_desligado(self):
        backend_main.ANOMALY_DETECTION_THREAD = None
        with mock.patch.dict(os.environ, {"GMJFLOW_DETECTION_INPROCESS_ENABLED": "false"}):
            backend_main.start_anomaly_detection_thread()
        self.assertIsNone(backend_main.ANOMALY_DETECTION_THREAD)

    def test_api_inicia_detector_quando_inprocess_ligado(self):
        backend_main.ANOMALY_DETECTION_THREAD = None
        backend_main.ANOMALY_DETECTION_STOP.clear()
        with mock.patch.dict(
            os.environ,
            {
                "GMJFLOW_DETECTION_INPROCESS_ENABLED": "true",
                "GMJFLOW_DETECTION_ENABLED": "true",
                "GMJFLOW_ANOMALY_INTERVAL_SECONDS": "60",
            },
        ):
            backend_main.start_anomaly_detection_thread()
            started = backend_main.ANOMALY_DETECTION_THREAD
            self.assertIsNotNone(started)
            self.assertIsInstance(started, threading.Thread)
            self.assertTrue(started.is_alive())
            backend_main.ANOMALY_DETECTION_STOP.set()
            started.join(timeout=5)
        backend_main.ANOMALY_DETECTION_STOP.clear()

    def test_worker_flag(self):
        with mock.patch.dict(os.environ, {"GMJFLOW_DETECTION_WORKER_ENABLED": "true"}):
            self.assertTrue(backend_main.detection_worker_enabled())
        with mock.patch.dict(os.environ, {"GMJFLOW_DETECTION_WORKER_ENABLED": "false"}):
            self.assertFalse(backend_main.detection_worker_enabled())

    # ---- lease ------------------------------------------------------------
    def test_lease_exclusivo_entre_processos(self):
        self.assertTrue(backend_main.detection_lease_acquire("worker-a", 60))
        self.assertFalse(backend_main.detection_lease_acquire("worker-b", 60))
        info = backend_main.detection_lease_info()
        self.assertIsNotNone(info)
        self.assertEqual(info["owner"], "worker-a")
        self.assertTrue(backend_main.detection_lease_renew("worker-a", 60))
        self.assertFalse(backend_main.detection_lease_renew("worker-b", 60))

    def test_lease_expira_e_permite_takeover(self):
        self.assertTrue(backend_main.detection_lease_acquire("worker-a", 30))
        expired = backend_main.iso(datetime.now(timezone.utc) - timedelta(seconds=5))
        with backend_main.sqlite_connection() as conn:
            conn.execute(
                "UPDATE detection_worker_lease SET expires_at = ? WHERE id = ?",
                (expired, backend_main.DETECTION_LEASE_ID),
            )
            conn.commit()
        self.assertTrue(backend_main.detection_lease_acquire("worker-b", 60))
        self.assertEqual(backend_main.detection_lease_info()["owner"], "worker-b")

    def test_release_libera_lease(self):
        backend_main.detection_lease_acquire("worker-a", 60)
        backend_main.detection_lease_release("worker-a")
        self.assertIsNone(backend_main.detection_lease_info())

    def test_release_nao_remove_lease_de_outro(self):
        backend_main.detection_lease_acquire("worker-a", 60)
        backend_main.detection_lease_release("worker-b")
        self.assertEqual(backend_main.detection_lease_info()["owner"], "worker-a")

    # ---- status compartilhado --------------------------------------------
    def test_status_endpoint_le_status_do_worker(self):
        backend_main.ANOMALY_DETECTION_THREAD = None
        backend_main.persist_detection_status(
            {
                "last_success_at": "2026-10-06T12:00:00Z",
                "cycle_duration_seconds": 42.5,
                "owner": "detector@host:99",
                "rules_evaluated_last_run": 28,
                "buckets_pending": 2,
            }
        )
        payload = backend_main.detection_status()
        self.assertEqual(payload["status_source"], "worker")
        self.assertEqual(payload["owner"], "detector@host:99")
        self.assertEqual(payload["cycle_duration_seconds"], 42.5)
        self.assertEqual(payload["rules_evaluated_last_run"], 28)
        self.assertEqual(payload["buckets_pending"], 2)
        self.assertGreaterEqual(payload["status_age_seconds"], 0)

    def test_status_endpoint_sem_status(self):
        backend_main.ANOMALY_DETECTION_THREAD = None
        payload = backend_main.detection_status()
        self.assertIn(payload["status_source"], {"none", "inprocess"})
        self.assertEqual(payload["scheduler_running"], False)

    def test_status_reporta_lease_vivo_como_scheduler_running(self):
        backend_main.ANOMALY_DETECTION_THREAD = None
        backend_main.detection_lease_acquire("detector@host:1", 60)
        payload = backend_main.detection_status()
        self.assertTrue(payload["scheduler_running"])
        self.assertEqual((payload["worker_lease"] or {}).get("owner"), "detector@host:1")

    # ---- guarda do run-now -----------------------------------------------
    def test_run_now_bloqueia_quando_outro_processo_tem_lease(self):
        backend_main.detection_lease_acquire("detector@other:123", 120)
        with self.assertRaises(backend_main.HTTPException) as ctx:
            backend_main.detection_run_now()
        self.assertEqual(ctx.exception.status_code, 409)

    def test_run_now_permitido_sem_lease_de_terceiro(self):
        expected = {"ok": True, "started_at": "x", "rules_enabled": 0, "rules_evaluated": 0, "anomalies_created": 0, "skipped_reasons": {}, "items": []}
        with mock.patch.object(backend_main, "run_detection_template_rules_once", return_value=expected) as mocked:
            payload = backend_main.detection_run_now()
        self.assertTrue(payload["ok"])
        self.assertEqual(mocked.call_count, 1)


if __name__ == "__main__":
    unittest.main()
