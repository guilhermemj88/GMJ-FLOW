from __future__ import annotations

import os
import sqlite3
import sys
import types
import unittest
from unittest.mock import patch


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

try:
    import fastapi  # noqa: F401
except ImportError:
    fastapi_stub = types.ModuleType("fastapi")

    class APIRouter:
        def __init__(self, *args, **kwargs):
            pass

        def get(self, *args, **kwargs):
            return lambda function: function

        def post(self, *args, **kwargs):
            return lambda function: function

    class HTTPException(Exception):
        def __init__(self, status_code, detail=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    def Query(default=None, **_kwargs):
        return default

    fastapi_stub.APIRouter = APIRouter
    fastapi_stub.FastAPI = APIRouter
    fastapi_stub.HTTPException = HTTPException
    fastapi_stub.Query = Query
    sys.modules["fastapi"] = fastapi_stub

from app.api import threat_engine as api  # noqa: E402
from app.services.behavioral_detection import AttackVector, ensure_behavioral_schema  # noqa: E402
from app.services.security_events import ensure_security_event_schema, upsert_security_event  # noqa: E402


class SecurityEventApiTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(self.conn)
        ensure_security_event_schema(self.conn)
        self.previous_factory = api.BEHAVIORAL_THREAT_RUNTIME.connection_factory
        api.BEHAVIORAL_THREAT_RUNTIME.connection_factory = lambda: self.conn
        self.event_id = upsert_security_event(
            self.conn,
            AttackVector(
                attack_type="PORT_SCAN_VERTICAL",
                detector="port_scan",
                detector_score=70,
                confidence=.7,
                first_seen="2026-08-12T10:00:00Z",
                last_seen="2026-08-12T10:01:00Z",
                src_ip="198.51.100.10",
                target_ip="203.0.113.10",
                direction="INBOUND",
                protocol="tcp",
                features={"packet_count": 50, "unique_dst_ports": 50},
                network_context={"src_role": "EXTERNAL", "dst_role": "CUSTOMER"},
                evidence=["50 portas TCP SYN sem ACK"],
            ),
        )
        self.conn.commit()

    def tearDown(self):
        api.BEHAVIORAL_THREAT_RUNTIME.connection_factory = self.previous_factory
        self.conn.close()

    def test_list_detail_evidence_and_intel(self):
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_EVENTS_UI_REFRESH_SECONDS": "10"}):
            payload = api.list_security_events(limit=200, offset=0)
        self.assertEqual(1, payload["total"])
        self.assertEqual(10, payload["ui_refresh_seconds"])
        self.assertEqual(self.event_id, payload["items"][0]["id"])
        detail = api.get_security_event(self.event_id)
        self.assertEqual("SCAN_FAMILY", detail["attack_family"])
        self.assertIn("facts", api.get_security_event_evidence(self.event_id)["evidence"])
        self.assertIn("não confirma", api.get_security_event_threat_intel(self.event_id)["interpretation"])

    def test_manual_status_is_audited_without_mitigation(self):
        result = api.mark_event_investigating(self.event_id)
        self.assertEqual("investigating", result["status"])
        row = self.conn.execute(
            "SELECT * FROM threat_engine_audit WHERE event_type='SECURITY_EVENT_STATUS'"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertIn("no_mitigation", row["non_mitigation_reason"])

    def test_ui_refresh_interval_is_configurable_and_bounded(self):
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_EVENTS_UI_REFRESH_SECONDS": "5"}):
            self.assertEqual(5, api.security_events_ui_refresh_seconds())
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_EVENTS_UI_REFRESH_SECONDS": "60"}):
            self.assertEqual(15, api.security_events_ui_refresh_seconds())
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_EVENTS_UI_REFRESH_SECONDS": "invalid"}):
            self.assertEqual(10, api.security_events_ui_refresh_seconds())


if __name__ == "__main__":
    unittest.main()
