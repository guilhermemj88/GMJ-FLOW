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

    class Request:
        def __init__(self):
            self.headers = {}

    class Response:
        def __init__(self, status_code=200, headers=None):
            self.status_code = status_code
            self.headers = dict(headers or {})

    def Query(default=None, **_kwargs):
        return default

    fastapi_stub.APIRouter = APIRouter
    fastapi_stub.FastAPI = APIRouter
    fastapi_stub.HTTPException = HTTPException
    fastapi_stub.Query = Query
    fastapi_stub.Request = Request
    fastapi_stub.Response = Response
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
            payload = api.list_security_events(Request(), Response(), limit=200, offset=0)
        self.assertEqual(1, payload["total"])
        self.assertEqual(10, payload["ui_refresh_seconds"])
        self.assertEqual(self.event_id, payload["items"][0]["id"])
        detail = api.get_security_event(self.event_id)
        self.assertEqual("SCAN_FAMILY", detail["attack_family"])
        self.assertIn("facts", api.get_security_event_evidence(self.event_id)["evidence"])
        self.assertIn("não confirma", api.get_security_event_threat_intel(self.event_id)["interpretation"])

    def test_etag_short_circuits_unchanged_payload(self):
        response = Response()
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_EVENTS_UI_REFRESH_SECONDS": "10"}):
            first = api.list_security_events(Request(), response, limit=200, offset=0)
        etag = response.headers.get("ETag")
        self.assertTrue(etag and etag.startswith('"sec-'))
        self.assertIn("no-cache", response.headers.get("Cache-Control", ""))
        conditional = Request()
        conditional.headers["if-none-match"] = etag
        result = api.list_security_events(conditional, Response(), limit=200, offset=0)
        self.assertEqual(304, result.status_code)
        self.assertEqual(etag, result.headers.get("ETag"))
        self.assertIn("no-cache", result.headers.get("Cache-Control", ""))

    def test_manual_status_is_audited_without_mitigation(self):
        result = api.mark_event_investigating(self.event_id)
        self.assertEqual("investigating", result["status"])
        row = self.conn.execute(
            "SELECT * FROM threat_engine_audit WHERE event_type='SECURITY_EVENT_STATUS'"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertIn("no_mitigation", row["non_mitigation_reason"])

    def test_security_summary_contract(self):
        from datetime import datetime, timedelta, timezone
        now = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        vector = AttackVector(
            attack_type="NETWORK_SWEEP",
            detector="port_scan",
            detector_score=88,
            confidence=.9,
            severity="HIGH",
            verdict="LIKELY_ATTACK",
            first_seen=now,
            last_seen=now,
            src_ip="198.51.100.77",
            direction="INBOUND",
            protocol="tcp",
            features={"packet_count": 500, "unique_dst_ips": 25, "persistent_windows": 3, "top_source_details": []},
            network_context={"src_role": "EXTERNAL", "dst_role": "CUSTOMER", "sensor": "edge-1"},
            evidence=["25 destinos em 60s"],
        )
        upsert_security_event(self.conn, vector)
        self.conn.commit()
        payload = api.security_summary(window=60)
        self.assertEqual(60, payload["window_minutes"])
        self.assertEqual("shadow", payload["threat_score_mode"])
        self.assertGreaterEqual(payload["detections"], 1)
        self.assertIn("NETWORK_SWEEP", payload["by_type"])
        self.assertGreaterEqual(payload["critical"] + payload["high"], 1)
        for key in ("analyzed", "suspicious", "security_events", "corroborated", "eligible_for_mitigation", "mitigated"):
            self.assertIn(key, payload)

    def test_ui_refresh_interval_is_configurable_and_bounded(self):
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_EVENTS_UI_REFRESH_SECONDS": "5"}):
            self.assertEqual(5, api.security_events_ui_refresh_seconds())
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_EVENTS_UI_REFRESH_SECONDS": "60"}):
            self.assertEqual(15, api.security_events_ui_refresh_seconds())
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_EVENTS_UI_REFRESH_SECONDS": "invalid"}):
            self.assertEqual(10, api.security_events_ui_refresh_seconds())


if __name__ == "__main__":
    unittest.main()
