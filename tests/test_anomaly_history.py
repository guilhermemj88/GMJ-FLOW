import os
import gc
import json
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from unittest import mock

from tests.test_anomaly_threshold_policy_static import main


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


class AnomalyHistoryTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "gmjflow.db")
        self.environment = mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": self.db_path}, clear=False)
        self.ready = mock.patch.object(main, "SENSOR_DB_READY", False)
        self.password = mock.patch.object(main, "hash_password", return_value="test-hash")
        self.environment.start()
        self.ready.start()
        self.password.start()
        main.ensure_sensor_db()

    def tearDown(self):
        self.password.stop()
        self.ready.stop()
        self.environment.stop()
        gc.collect()
        self.tmpdir.cleanup()

    def insert_event(
        self,
        *,
        status="ended",
        severity="warning",
        vector="DNS_ABUSE_OUTBOUND",
        target="186.232.172.231",
        last_seen="2026-08-03T12:00:00Z",
    ):
        with main.sqlite_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO anomaly_events (
                    target_ip, target_cidr, vector_name, direction, decoder, severity,
                    metric_unit, threshold_value, observed_value, peak_value, started_at,
                    last_seen_at, ended_at, status, estimated_bytes, estimated_packets,
                    flow_count, summary, dedupe_key, created_at, updated_at
                ) VALUES (?, ?, ?, 'transmits', 'DNS', ?, 'packets_s', 100, 200, 300,
                          ?, ?, ?, ?, 1000, 100, 10, ?, ?, ?, ?)
                """,
                (
                    target,
                    f"{target}/32",
                    vector,
                    severity,
                    last_seen,
                    last_seen,
                    last_seen if status != "active" else None,
                    status,
                    vector,
                    f"{vector}|{target}|{status}|{last_seen}",
                    last_seen,
                    last_seen,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)

    def test_history_orders_by_last_seen_then_id_descending(self):
        older = self.insert_event(last_seen="2026-08-03T11:59:00Z")
        first_tie = self.insert_event(last_seen="2026-08-03T12:00:00Z")
        second_tie = self.insert_event(last_seen="2026-08-03T12:00:00Z")

        result = main.anomaly_page("history", 1, 100)

        self.assertEqual([second_tie, first_tie, older], [item["id"] for item in result["items"]])
        self.assertEqual(3, result["total"])
        self.assertFalse(result["has_more"])

    def test_pagination_and_total_use_the_same_filters(self):
        for index in range(5):
            self.insert_event(
                severity="critical" if index < 4 else "warning",
                last_seen=f"2026-08-03T12:0{index}:00Z",
            )

        first = main.anomaly_page("history", 1, 2, severity="critical")
        second = main.anomaly_page("history", 2, 2, severity="critical")

        self.assertEqual(4, first["total"])
        self.assertEqual(2, len(first["items"]))
        self.assertTrue(first["has_more"])
        self.assertEqual(2, len(second["items"]))
        self.assertFalse(second["has_more"])
        self.assertTrue(all(item["severity"] == "critical" for item in first["items"] + second["items"]))

    def test_id_period_status_severity_type_and_target_can_be_combined(self):
        expected = self.insert_event(
            status="closed",
            severity="critical",
            vector="DNS_SINGLE_FLOW_OUTBOUND",
            target="186.232.172.231",
            last_seen="2026-08-03T13:30:00Z",
        )
        self.insert_event(status="closed", severity="warning", last_seen="2026-08-03T13:30:00Z")

        result = main.anomaly_page(
            "history",
            1,
            100,
            anomaly_id=expected,
            start_at=main.parse_anomaly_filter_datetime("2026-08-03T10:00:00-03:00", "start_at"),
            end_at=main.parse_anomaly_filter_datetime("2026-08-03T10:30:00-03:00", "end_at"),
            status="closed",
            severity="critical",
            anomaly_type="single_flow",
            target="172.231",
        )

        self.assertEqual(expected, result["items"][0]["id"])
        self.assertEqual(1, result["total"])

    def test_naive_sao_paulo_range_is_converted_to_utc_and_end_is_inclusive(self):
        boundary = self.insert_event(last_seen="2026-08-03T03:00:00Z")
        self.insert_event(last_seen="2026-08-03T02:59:59Z")
        start = main.parse_anomaly_filter_datetime("2026-08-03T00:00:00", "start_at")
        end = main.parse_anomaly_filter_datetime("2026-08-03T00:00:00", "end_at")

        result = main.anomaly_page("history", 1, 100, start_at=start, end_at=end)

        self.assertEqual(datetime(2026, 8, 3, 3, 0, tzinfo=timezone.utc), start)
        self.assertEqual([boundary], [item["id"] for item in result["items"]])

    def test_active_and_history_use_central_status_sets(self):
        active = self.insert_event(status="active")
        history_ids = {
            self.insert_event(status=status, last_seen=f"2026-08-03T12:0{index}:00Z")
            for index, status in enumerate(main.ANOMALY_HISTORY_STATUSES)
        }
        self.insert_event(status="open", last_seen="2026-08-03T13:00:00Z")

        self.assertEqual([active], [item["id"] for item in main.anomaly_page("active", 1, 100)["items"]])
        self.assertEqual(history_ids, {item["id"] for item in main.anomaly_page("history", 1, 100)["items"]})

    def test_security_evidence_endpoint_uses_the_same_central_status_sets(self):
        with main.sqlite_connection() as conn:
            ids = {}
            for index, status in enumerate((*main.ANOMALY_ACTIVE_STATUSES, *main.ANOMALY_HISTORY_STATUSES, "open")):
                timestamp = f"2026-08-03T12:{index:02d}:00Z"
                cursor = conn.execute(
                    """
                    INSERT INTO security_anomalies (
                        vector, severity, status, last_seen, dedupe_key, created_at, updated_at
                    ) VALUES ('DNS_TEST', 'warning', ?, ?, ?, ?, ?)
                    """,
                    (status, timestamp, f"security-{status}", timestamp, timestamp),
                )
                ids[status] = int(cursor.lastrowid)
            conn.commit()

        active = main.list_security_anomalies("active", None, None, None, None, None, None, None, 100)
        history = main.list_security_anomalies("history", None, None, None, None, None, None, None, 100)

        self.assertEqual({ids["active"]}, {item["id"] for item in active["items"]})
        self.assertEqual(
            {ids[status] for status in main.ANOMALY_HISTORY_STATUSES},
            {item["id"] for item in history["items"]},
        )

    def test_period_without_results_returns_empty_page(self):
        self.insert_event(last_seen="2026-08-03T12:00:00Z")

        result = main.anomaly_page(
            "history",
            1,
            100,
            start_at=main.parse_anomaly_filter_datetime("2026-08-04T00:00:00-03:00", "start_at"),
            end_at=main.parse_anomaly_filter_datetime("2026-08-04T23:59:59-03:00", "end_at"),
        )

        self.assertEqual([], result["items"])
        self.assertEqual(0, result["total"])
        self.assertFalse(result["has_more"])

    def test_read_only_diagnostics_report_both_anomaly_tables(self):
        event_id = self.insert_event(last_seen="2026-08-03T12:00:00Z")
        with main.sqlite_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO security_anomalies (
                    vector, severity, status, last_seen, dedupe_key, created_at, updated_at
                ) VALUES ('DNS_TEST', 'warning', 'ended', ?, 'diagnostics-test', ?, ?)
                """,
                ("2026-08-03T12:01:00Z", "2026-08-03T12:01:00Z", "2026-08-03T12:01:00Z"),
            )
            security_id = int(cursor.lastrowid)
            conn.commit()

        with mock.patch.object(main, "require_admin", return_value=None):
            payload = main.anomaly_diagnostics(object())

        self.assertEqual(event_id, payload["anomaly_events"]["max_id"])
        self.assertEqual(security_id, payload["security_anomalies"]["max_id"])
        self.assertEqual("ended", payload["statuses"][0]["status"])
        self.assertEqual("ended", payload["security_statuses"][0]["status"])

    def test_invalid_range_is_rejected_by_endpoint(self):
        with mock.patch.object(main, "require_admin", return_value=None):
            with self.assertRaises(main.HTTPException) as raised:
                main.anomaly_history(
                    object(),
                    page=1,
                    page_size=100,
                    start_at="2026-08-03T11:00:00-03:00",
                    end_at="2026-08-03T10:00:00-03:00",
                    limit=None,
                )
        self.assertEqual(400, raised.exception.status_code)

    def test_detector_to_database_and_history_api_flow(self):
        candidate = {
            "template_id": 1,
            "template_name": "CLIENTES-PUBLICOS-DEFAULT",
            "rule_id": 77,
            "rule_name": main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
            "vector": main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
            "severity": "critical",
            "metric": "packets_s",
            "metric_value": 7000,
            "packets_s": 7000,
            "threshold_warning": 5000,
            "threshold_critical": 5000,
            "first_seen": "2026-08-03T12:00:00Z",
            "last_seen": "2026-08-03T12:00:00Z",
            "top_src_ip": "186.232.172.231",
            "top_src_port": 53000,
            "top_dst_ip": "8.8.8.8",
            "top_dst_port": 53,
            "packets": 420000,
            "bytes": 33600000,
            "flows": 1,
            "zone_id": 1,
            "zone_name": "FIBINET",
        }
        conn = main.sqlite_connection()
        try:
            self.assertEqual("created", main.upsert_detection_template_dns_anomaly_event(conn, candidate))
            first_id = int(conn.execute("SELECT MAX(id) AS id FROM anomaly_events").fetchone()["id"])
            conn.execute(
                "UPDATE anomaly_events SET status = 'ended', ended_at = ? WHERE id = ?",
                (candidate["last_seen"], first_id),
            )
            later = {**candidate, "first_seen": "2026-08-03T12:10:00Z", "last_seen": "2026-08-03T12:10:00Z"}
            self.assertEqual("created", main.upsert_detection_template_dns_anomaly_event(conn, later))
            second_id = int(conn.execute("SELECT MAX(id) AS id FROM anomaly_events").fetchone()["id"])
            conn.commit()
        finally:
            conn.close()
        self.assertGreater(second_id, first_id, "Um evento posterior ao incidente encerrado deve receber novo ID")

        with mock.patch.object(main, "require_admin", return_value=None):
            payload = main.anomaly_history(
                object(), page=1, page_size=100, anomaly_id=first_id,
                start_at=None, end_at=None, status="ended", severity=None,
                anomaly_type=None, target=None, anomaly_source=None, source_engine=None, limit=None,
            )
        self.assertEqual(first_id, payload["items"][0]["id"])
        self.assertEqual(1, payload["total"])


class AnomalyHistoryFrontendStaticTest(unittest.TestCase):
    def test_history_controls_and_complete_query_key_are_present(self):
        for element_id in (
            "anomalyIdSearch", "anomalyStartAt", "anomalyEndAt", "anomalyStatusFilter",
            "anomalySeverityFilter", "anomalyTypeFilter", "anomalyTargetFilter",
            "anomalyPageSize", "anomalyPreviousPage", "anomalyNextPage",
        ):
            self.assertIn(f'id="{element_id}"', HTML)
        for query_field in ("id", "start_at", "end_at", "status", "severity", "type", "target", "page", "page_size"):
            self.assertIn(query_field, HTML[HTML.index("function anomalyListEndpoint"):HTML.index("function setAnomalyError")])

    def test_presets_cover_requested_ranges_and_manual_refetch_disables_cache(self):
        preset_source = HTML[HTML.index("function applyAnomalyRangePreset"):HTML.index("function anomalyHistoryFilters")]
        for value in ("'1h'", "'4h'", "'12h'", "'24h'", "'7d'", "'today'", "'yesterday'"):
            self.assertIn(value, preset_source)
        load_source = HTML[HTML.index("async function loadAnomalies"):HTML.index("function niceAnomalyAxisMax")]
        self.assertIn("cache: 'no-store'", load_source)

    def test_failed_refresh_clears_stale_rows_and_exposes_retry(self):
        load_source = HTML[HTML.index("async function loadAnomalies"):HTML.index("function niceAnomalyAxisMax")]
        self.assertIn("anomalyItems = [];", load_source)
        self.assertIn("renderAnomalyTable([]);", load_source)
        self.assertIn("setAnomalyError(`Não foi possível atualizar", load_source)
        self.assertIn('id="anomalyRetryButton"', HTML)
        self.assertIn("anomalyLoadInFlight = false;", load_source)
        self.assertIn("refreshAnomaliesButton').disabled = false", load_source)

    def test_manual_update_refetches_the_current_tab_and_filters(self):
        handlers = HTML[HTML.index("document.getElementById('refreshAnomaliesButton')"):]
        self.assertIn("addEventListener('click', () => loadAnomalies()", handlers)
        self.assertIn("apiRequest(anomalyListEndpoint(tab), { cache: 'no-store' })", HTML)

    def test_auto_refresh_loads_the_complete_current_page(self):
        refresh_source = HTML[HTML.index("async function refreshOpsSummary"):HTML.index("function startOpsSummaryPolling")]
        self.assertIn("loadAnomalies(anomalyActiveTab", refresh_source)
        self.assertIn("ANOMALY_AUTO_REFRESH_MS", refresh_source)


class AnomalyHistoryBrowserSmokeTest(unittest.TestCase):
    @staticmethod
    def edge_path():
        candidates = (
            Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        )
        return next((path for path in candidates if path.exists()), None)

    def test_full_frontend_script_parses_and_reaches_initialization(self):
        edge = self.edge_path()
        if edge is None:
            self.skipTest("Microsoft Edge não está disponível")
        with tempfile.TemporaryDirectory(prefix="gmj-anomaly-edge-") as profile:
            completed = subprocess.run(
                [
                    str(edge),
                    "--headless=new",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--no-first-run",
                    "--force-time-zone=America/Sao_Paulo",
                    "--allow-file-access-from-files",
                    "--virtual-time-budget=4000",
                    f"--user-data-dir={profile}",
                    "--dump-dom",
                    (ROOT / "frontend" / "index.html").resolve().as_uri(),
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        self.assertEqual(0, completed.returncode, completed.stderr[-4000:])
        self.assertIn(
            '<div id="attackDetectionTemplateMount"><section id="detectionTemplateSection"',
            completed.stdout,
            "O script principal não chegou à inicialização; verifique erro de sintaxe/runtime.",
        )

    def test_detector_database_api_and_real_frontend_table_flow(self):
        edge = self.edge_path()
        if edge is None:
            self.skipTest("Microsoft Edge não está disponível")
        with tempfile.TemporaryDirectory(prefix="gmj-anomaly-flow-") as workspace:
            db_path = str(Path(workspace) / "gmjflow.db")
            with mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": db_path}, clear=False), \
                 mock.patch.object(main, "SENSOR_DB_READY", False), \
                 mock.patch.object(main, "hash_password", return_value="test-hash"), \
                 mock.patch.object(main, "require_admin", return_value=None):
                main.ensure_sensor_db()
                candidate = {
                    "template_id": 1,
                    "template_name": "CLIENTES-PUBLICOS-DEFAULT",
                    "rule_id": 77,
                    "rule_name": main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
                    "vector": main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR,
                    "severity": "critical",
                    "metric": "packets_s",
                    "metric_value": 7000,
                    "packets_s": 7000,
                    "threshold_warning": 5000,
                    "threshold_critical": 5000,
                    "first_seen": "2026-08-03T12:00:00Z",
                    "last_seen": "2026-08-03T12:00:00Z",
                    "top_src_ip": "186.232.172.231",
                    "top_src_port": 53000,
                    "top_dst_ip": "8.8.8.8",
                    "top_dst_port": 53,
                    "packets": 420000,
                    "bytes": 33600000,
                    "flows": 1,
                    "zone_id": 1,
                    "zone_name": "FIBINET",
                }
                with main.sqlite_connection() as conn:
                    self.assertEqual("created", main.upsert_detection_template_dns_anomaly_event(conn, candidate))
                    event_id = int(conn.execute("SELECT MAX(id) AS id FROM anomaly_events").fetchone()["id"])
                    conn.execute(
                        "UPDATE anomaly_events SET status = 'ended', ended_at = last_seen_at WHERE id = ?",
                        (event_id,),
                    )
                    conn.commit()
                conn.close()

                served_html = HTML.replace(
                    "<title>GMJ-FLOW</title>",
                    "<script>localStorage.setItem('gmjFlowAuthToken','integration-test');</script><title>GMJ-FLOW</title>",
                ).replace("let anomalyActiveTab = 'active';", "let anomalyActiveTab = 'history';")

                class Handler(BaseHTTPRequestHandler):
                    def send_json(self, payload):
                        body = json.dumps(payload).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json; charset=utf-8")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)

                    def do_GET(self):
                        parsed = urlparse(self.path)
                        query = parse_qs(parsed.query)
                        if parsed.path == "/api/auth/me":
                            return self.send_json({"user": {"id": 1, "username": "test", "role": "admin", "must_change_password": False}})
                        if parsed.path == "/api/ops/summary":
                            return self.send_json({"active_anomalies": 0, "active_total": 0, "active_critical": 0, "active_warning": 0})
                        if parsed.path == "/api/anomalies/history":
                            payload = main.anomaly_history(
                                object(),
                                page=int(query.get("page", ["1"])[0]),
                                page_size=int(query.get("page_size", ["100"])[0]),
                                anomaly_id=int(query["id"][0]) if query.get("id") and query["id"][0] else None,
                                start_at=query.get("start_at", [None])[0],
                                end_at=query.get("end_at", [None])[0],
                                status=query.get("status", [None])[0],
                                severity=query.get("severity", [None])[0],
                                anomaly_type=query.get("type", [None])[0],
                                target=query.get("target", [None])[0],
                                anomaly_source=None,
                                source_engine=None,
                                limit=None,
                            )
                            return self.send_json(payload)
                        if parsed.path == "/api/anomalies/stats":
                            return self.send_json({"total": 1, "by_direction": [], "by_severity": [], "by_status": []})
                        if parsed.path.startswith("/api/anomalies/top-") or parsed.path == "/api/security/anomalies/history":
                            return self.send_json({"items": []})
                        if parsed.path in {"/", "/index.html"}:
                            body = served_html.encode("utf-8")
                            self.send_response(200)
                            self.send_header("Content-Type", "text/html; charset=utf-8")
                            self.send_header("Content-Length", str(len(body)))
                            self.end_headers()
                            self.wfile.write(body)
                            return
                        asset = ROOT / "frontend" / parsed.path.lstrip("/")
                        if asset.is_file():
                            body = asset.read_bytes()
                            self.send_response(200)
                            self.send_header("Content-Type", "application/javascript; charset=utf-8")
                            self.send_header("Content-Length", str(len(body)))
                            self.end_headers()
                            self.wfile.write(body)
                            return
                        self.send_error(404)

                    def log_message(self, *args):
                        return

                server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                server_thread = threading.Thread(target=server.serve_forever, daemon=True)
                server_thread.start()
                try:
                    with tempfile.TemporaryDirectory(prefix="gmj-anomaly-edge-") as profile:
                        completed = subprocess.run(
                            [
                                str(edge),
                                "--headless=new",
                                "--disable-gpu",
                                "--disable-extensions",
                                "--no-first-run",
                                "--force-time-zone=America/Sao_Paulo",
                                "--virtual-time-budget=8000",
                                f"--user-data-dir={profile}",
                                "--dump-dom",
                                f"http://127.0.0.1:{server.server_port}/#anomalies",
                            ],
                            check=False,
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            timeout=40,
                        )
                finally:
                    server.shutdown()
                    server.server_close()
                    server_thread.join(timeout=5)
                self.assertEqual(0, completed.returncode, completed.stderr[-4000:])
                self.assertIn(f"#{event_id}", completed.stdout)
                self.assertIn(main.DNS_SINGLE_FLOW_OUTBOUND_VECTOR, completed.stdout)
            gc.collect()


if __name__ == "__main__":
    unittest.main()
