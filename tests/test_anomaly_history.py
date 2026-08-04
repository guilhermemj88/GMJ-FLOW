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
        acknowledged_at=None,
        ended_at="__auto__",
        updated_at=None,
        peak_value=300,
        estimated_bytes=1000,
        response_status="",
    ):
        ended_value = last_seen if ended_at == "__auto__" and status != "active" else (None if ended_at == "__auto__" else ended_at)
        updated_value = updated_at or last_seen
        with main.sqlite_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO anomaly_events (
                    target_ip, target_cidr, vector_name, direction, decoder, severity,
                    metric_unit, threshold_value, observed_value, peak_value, started_at,
                    last_seen_at, acknowledged_at, ended_at, status, estimated_bytes, estimated_packets,
                    flow_count, summary, dedupe_key, created_at, updated_at, auto_mitigation_status
                ) VALUES (?, ?, ?, 'transmits', 'DNS', ?, 'packets_s', 100, 200, ?,
                          ?, ?, ?, ?, ?, ?, 100, 10, ?, ?, ?, ?, ?)
                """,
                (
                    target,
                    f"{target}/32",
                    vector,
                    severity,
                    peak_value,
                    last_seen,
                    last_seen,
                    acknowledged_at,
                    ended_value,
                    status,
                    estimated_bytes,
                    vector,
                    f"{vector}|{target}|{status}|{last_seen}",
                    last_seen,
                    updated_value,
                    response_status,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)

    def history_endpoint(self, **overrides):
        parameters = {
            "page": 1,
            "page_size": 100,
            "anomaly_id": None,
            "start_at": None,
            "end_at": None,
            "status": None,
            "severity": None,
            "anomaly_type": None,
            "target": None,
            "anomaly_source": None,
            "source_engine": None,
            "limit": None,
        }
        parameters.update(overrides)
        with mock.patch.object(main, "require_admin", return_value=None):
            return main.anomaly_history(object(), **parameters)

    def test_history_endpoint_without_filters(self):
        event_id = self.insert_event()

        payload = self.history_endpoint()

        self.assertEqual([event_id], [item["id"] for item in payload["items"]])
        self.assertEqual(1, payload["total"])
        self.assertIsNone(payload["applied_filters"]["id"])

    def test_empty_id_is_treated_as_an_absent_filter(self):
        event_id = self.insert_event()

        payload = self.history_endpoint(anomaly_id="")

        self.assertEqual([event_id], [item["id"] for item in payload["items"]])
        self.assertIsNone(payload["applied_filters"]["id"])

    def test_valid_id_is_converted_and_applied(self):
        expected = self.insert_event(last_seen="2026-08-03T12:01:00Z")
        self.insert_event(last_seen="2026-08-03T12:00:00Z")

        payload = self.history_endpoint(anomaly_id=str(expected))

        self.assertEqual([expected], [item["id"] for item in payload["items"]])
        self.assertEqual(expected, payload["applied_filters"]["id"])

    def test_non_numeric_id_returns_a_friendly_bad_request(self):
        with self.assertRaises(main.HTTPException) as raised:
            self.history_endpoint(anomaly_id="abc")

        self.assertEqual(400, raised.exception.status_code)
        self.assertEqual("O ID da anomalia deve ser um número inteiro.", raised.exception.detail)

    def test_pagination_works_without_filters(self):
        ids = [
            self.insert_event(last_seen=f"2026-08-03T12:0{index}:00Z")
            for index in range(3)
        ]

        payload = self.history_endpoint(page=2, page_size=2)

        self.assertEqual([ids[0]], [item["id"] for item in payload["items"]])
        self.assertEqual(3, payload["total"])
        self.assertEqual(2, payload["page"])
        self.assertEqual(2, payload["page_size"])
        self.assertFalse(payload["has_more"])

    def test_id_sort_supports_descending_and_ascending(self):
        ids = [self.insert_event(last_seen=f"2026-08-03T12:0{index}:00Z") for index in range(3)]

        descending = main.anomaly_page("history", 1, 100, sort_by="id", sort_dir="desc")
        ascending = main.anomaly_page("history", 1, 100, sort_by="id", sort_dir="asc")

        self.assertEqual(list(reversed(ids)), [item["id"] for item in descending["items"]])
        self.assertEqual(ids, [item["id"] for item in ascending["items"]])

    def test_event_time_and_last_seen_have_distinct_semantics(self):
        newest_detection = self.insert_event(
            last_seen="2026-08-03T14:00:00Z",
            updated_at="2026-08-03T14:01:00Z",
        )
        newest_movement = self.insert_event(
            last_seen="2026-08-03T13:00:00Z",
            updated_at="2026-08-03T15:00:00Z",
        )

        by_event_time = main.anomaly_page("history", 1, 100, sort_by="event_time", sort_dir="desc")
        by_last_seen = main.anomaly_page("history", 1, 100, sort_by="last_seen", sort_dir="desc")

        self.assertEqual([newest_movement, newest_detection], [item["id"] for item in by_event_time["items"]])
        self.assertEqual([newest_detection, newest_movement], [item["id"] for item in by_last_seen["items"]])

    def test_acknowledged_ended_and_updated_dates_sort_descending_with_nulls_last(self):
        older = self.insert_event(
            acknowledged_at="2026-08-03T12:10:00Z",
            ended_at="2026-08-03T12:20:00Z",
            updated_at="2026-08-03T12:30:00Z",
        )
        newer = self.insert_event(
            acknowledged_at="2026-08-03T13:10:00Z",
            ended_at="2026-08-03T13:20:00Z",
            updated_at="2026-08-03T13:30:00Z",
        )
        missing = self.insert_event(
            acknowledged_at=None,
            ended_at=None,
            updated_at="2026-08-03T11:30:00Z",
        )

        for sort_by in ("acknowledged_at", "ended_at", "updated_at"):
            items = main.anomaly_page("history", 1, 100, sort_by=sort_by, sort_dir="desc")["items"]
            expected = [newer, older, missing] if sort_by != "updated_at" else [newer, older, missing]
            self.assertEqual(expected, [item["id"] for item in items], sort_by)
        ascending_ack = main.anomaly_page("history", 1, 100, sort_by="acknowledged_at", sort_dir="asc")["items"]
        self.assertEqual([older, newer, missing], [item["id"] for item in ascending_ack])

    def test_peak_total_and_response_sort_descending(self):
        low = self.insert_event(peak_value=100, estimated_bytes=1000, response_status="failed")
        high = self.insert_event(peak_value=900, estimated_bytes=9000, response_status="queued")

        for sort_by in ("peak_value", "estimated_bytes", "response"):
            items = main.anomaly_page("history", 1, 100, sort_by=sort_by, sort_dir="desc")["items"]
            self.assertEqual([high, low], [item["id"] for item in items], sort_by)

    def test_type_and_target_sort_over_the_complete_filtered_set(self):
        zulu = self.insert_event(vector="ZULU", target="10.0.0.20")
        alpha = self.insert_event(vector="ALPHA", target="10.0.0.10")

        by_type = main.anomaly_page("history", 1, 100, sort_by="type", sort_dir="asc")["items"]
        by_target = main.anomaly_page("history", 1, 100, sort_by="target", sort_dir="desc")["items"]

        self.assertEqual([alpha, zulu], [item["id"] for item in by_type])
        self.assertEqual([zulu, alpha], [item["id"] for item in by_target])

    def test_severity_and_status_use_semantic_order(self):
        info = self.insert_event(severity="info", status="archived")
        warning = self.insert_event(severity="warning", status="ended")
        critical = self.insert_event(severity="critical", status="acknowledged")

        severity_desc = main.anomaly_page("history", 1, 100, sort_by="severity", sort_dir="desc")["items"]
        severity_asc = main.anomaly_page("history", 1, 100, sort_by="severity", sort_dir="asc")["items"]
        status_desc = main.anomaly_page("history", 1, 100, sort_by="status", sort_dir="desc")["items"]

        self.assertEqual([critical, warning, info], [item["id"] for item in severity_desc])
        self.assertEqual([info, warning, critical], [item["id"] for item in severity_asc])
        self.assertEqual([critical, warning, info], [item["id"] for item in status_desc])

    def test_sort_ties_always_use_id_descending(self):
        first = self.insert_event(peak_value=500)
        second = self.insert_event(peak_value=500)

        for direction in ("asc", "desc"):
            items = main.anomaly_page("history", 1, 100, sort_by="peak_value", sort_dir=direction)["items"]
            self.assertEqual([second, first], [item["id"] for item in items])

    def test_sort_is_applied_before_limit_and_offset(self):
        by_peak = {}
        for peak in (10, 50, 30, 40, 20):
            by_peak[peak] = self.insert_event(peak_value=peak)

        first = main.anomaly_page("history", 1, 2, sort_by="peak_value", sort_dir="desc")
        second = main.anomaly_page("history", 2, 2, sort_by="peak_value", sort_dir="desc")

        self.assertEqual([by_peak[50], by_peak[40]], [item["id"] for item in first["items"]])
        self.assertEqual([by_peak[30], by_peak[20]], [item["id"] for item in second["items"]])

    def test_invalid_sort_field_and_direction_return_friendly_400(self):
        with self.assertRaises(main.HTTPException) as invalid_field:
            self.history_endpoint(sort_by="drop_table", sort_dir="desc")
        with self.assertRaises(main.HTTPException) as invalid_direction:
            self.history_endpoint(sort_by="id", sort_dir="sideways")

        self.assertEqual(400, invalid_field.exception.status_code)
        self.assertEqual("Campo de ordenação de anomalias inválido.", invalid_field.exception.detail)
        self.assertEqual(400, invalid_direction.exception.status_code)
        self.assertEqual("A direção de ordenação deve ser 'asc' ou 'desc'.", invalid_direction.exception.detail)

    def test_allowed_sort_map_is_closed_and_acknowledgement_records_its_own_time(self):
        self.assertEqual(
            {
                "event_time", "last_seen", "acknowledged_at", "ended_at", "updated_at",
                "id", "status", "severity", "type", "target", "peak_value",
                "estimated_bytes", "response",
            },
            set(main.ANOMALY_SORT_SQL_FIELDS),
        )
        event_id = self.insert_event(status="active", ended_at=None)

        with mock.patch.object(main, "require_admin", return_value=None):
            main.acknowledge_anomaly(object(), event_id)
        with main.sqlite_connection() as conn:
            row = conn.execute(
                "SELECT status, acknowledged_at, ended_at, updated_at FROM anomaly_events WHERE id = ?",
                (event_id,),
            ).fetchone()

        self.assertEqual("acknowledged", row["status"])
        self.assertTrue(row["acknowledged_at"])
        self.assertEqual(row["acknowledged_at"], row["ended_at"])
        self.assertEqual(row["acknowledged_at"], row["updated_at"])

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

    def test_security_acknowledgement_records_acknowledged_and_ended_times(self):
        timestamp = "2026-08-03T12:00:00Z"
        with main.sqlite_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO security_anomalies (
                    vector, severity, status, last_seen, dedupe_key, created_at, updated_at
                ) VALUES ('DNS_TEST', 'warning', 'active', ?, 'security-ack', ?, ?)
                """,
                (timestamp, timestamp, timestamp),
            )
            anomaly_id = int(cursor.lastrowid)
            conn.commit()

        main.acknowledge_security_anomaly(anomaly_id)
        with main.sqlite_connection() as conn:
            row = conn.execute(
                "SELECT status, acknowledged_at, ended_at, updated_at FROM security_anomalies WHERE id = ?",
                (anomaly_id,),
            ).fetchone()

        self.assertEqual("acknowledged", row["status"])
        self.assertTrue(row["acknowledged_at"])
        self.assertEqual(row["acknowledged_at"], row["ended_at"])
        self.assertEqual(row["acknowledged_at"], row["updated_at"])

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
        query_source = HTML[HTML.index("function anomalyHistoryFilters"):HTML.index("function setAnomalyError")]
        for query_field in ("id", "start_at", "end_at", "status", "severity", "type", "target", "page", "page_size"):
            self.assertIn(query_field, query_source)

    def test_empty_filters_are_omitted_and_pagination_is_always_preserved(self):
        endpoint_source = HTML[HTML.index("function anomalyListEndpoint"):HTML.index("function setAnomalyError")]
        self.assertIn("const params = new URLSearchParams();", endpoint_source)
        self.assertIn("params.set('page',", endpoint_source)
        self.assertIn("params.set('page_size',", endpoint_source)
        self.assertIn("if (!value) return;", endpoint_source)
        self.assertNotIn("id: filters.id", endpoint_source)

    def test_all_requested_history_columns_are_server_sortable(self):
        expected = (
            "status", "severity", "id", "type", "target", "peak_value", "estimated_bytes",
            "last_seen", "acknowledged_at", "ended_at", "updated_at", "event_time", "response",
        )
        for field in expected:
            self.assertIn(f'data-anomaly-sort="{field}"', HTML)
            self.assertIn(field, main.ANOMALY_SORT_SQL_FIELDS)

    def test_sort_click_resets_page_preserves_filters_and_refetches(self):
        endpoint_source = HTML[HTML.index("function anomalyListEndpoint"):HTML.index("function setAnomalyError")]
        click_source = HTML[HTML.index("document.querySelector('#anomalyHistoryTable thead')"):HTML.index("document.getElementById('refreshBgpButton')")]
        self.assertIn("const filters = anomalyHistoryFilters();", endpoint_source)
        self.assertIn("appendAnomalySortParams(params, tab);", endpoint_source)
        self.assertIn("anomalyHistoryState.page = 1;", click_source)
        self.assertIn("loadAnomalies(anomalyActiveTab)", click_source)
        self.assertIn("sortDir: current.sortBy === column && current.sortDir === 'desc' ? 'asc' : 'desc'", click_source)

    def test_sort_state_is_per_tab_and_has_accessible_visual_indicators(self):
        state_source = HTML[HTML.index("const anomalySortStates"):HTML.index("let currentAnomalyDetailId")]
        indicator_source = HTML[HTML.index("function updateAnomalySortIndicators"):HTML.index("function anomalyListEndpoint")]
        self.assertIn("active: { sortBy: 'event_time', sortDir: 'desc' }", state_source)
        self.assertIn("history: { sortBy: 'event_time', sortDir: 'desc' }", state_source)
        self.assertIn("'↑' : '↓'", indicator_source)
        self.assertIn(": '↕'", indicator_source)
        self.assertIn("header.setAttribute('aria-sort'", indicator_source)

    def test_manual_and_automatic_refresh_reuse_the_current_sort_url(self):
        auto_source = HTML[HTML.index("async function refreshOpsSummary"):HTML.index("function startOpsSummaryPolling")]
        self.assertIn("loadAnomalies(anomalyActiveTab", auto_source)
        self.assertIn("anomalyListEndpoint(tab)", HTML[HTML.index("async function loadAnomalies"):HTML.index("function niceAnomalyAxisMax")])
        self.assertIn("loadAnomalies()", HTML[HTML.index("refreshAnomaliesButton"):])

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
                ).replace(
                    "let anomalyActiveTab = 'active';",
                    "let anomalyActiveTab = 'history';",
                ).replace(
                    "</body>",
                    """
                    <script>
                      setTimeout(() => document.querySelector('[data-anomaly-sort="id"]')?.click(), 1200);
                      setTimeout(() => document.querySelector('[data-anomaly-sort="id"]')?.click(), 3200);
                    </script>
                    </body>
                    """,
                )
                history_requests = []

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
                            return self.send_json({"user": {"id": 1, "username": "test", "role": "admin", "permissions": ["anomalies.view", "anomalies.manage"], "must_change_password": False}})
                        if parsed.path == "/api/ops/summary":
                            return self.send_json({"active_anomalies": 0, "active_total": 0, "active_critical": 0, "active_warning": 0})
                        if parsed.path == "/api/anomalies/history":
                            history_requests.append(self.path)
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
                                sort_by=query.get("sort_by", [main.ANOMALY_DEFAULT_SORT_BY])[0],
                                sort_dir=query.get("sort_dir", [main.ANOMALY_DEFAULT_SORT_DIR])[0],
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
                self.assertIn(
                    "/api/anomalies/history?page=1&page_size=100",
                    history_requests,
                    "O navegador não deve enviar filtros vazios ao endpoint do histórico.",
                )
                self.assertIn(
                    "/api/anomalies/history?page=1&page_size=100&sort_by=id&sort_dir=desc",
                    history_requests,
                )
                self.assertIn(
                    "/api/anomalies/history?page=1&page_size=100&sort_by=id&sort_dir=asc",
                    history_requests,
                )
            gc.collect()


if __name__ == "__main__":
    unittest.main()
