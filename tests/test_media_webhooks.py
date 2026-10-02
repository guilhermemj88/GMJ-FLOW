"""Midia / Alertas por Webhook: CRUD, validacao, entrega e isolamento de falha."""
import json
import os
import sqlite3
import tempfile
import types
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_collector_apply_static import backend_main  # noqa: E402  (instala os stubs)

media_dispatch = backend_main.media_dispatch


class _FakeResponse:
    def __init__(self, status=200, body=b"ok"):
        self.status = status
        self._body = body

    def read(self, size=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeCrypto:
    @staticmethod
    def encrypt_secret(value, explicit_seed=None):
        return "enc:" + value

    @staticmethod
    def decrypt_secret(value, explicit_seed=None):
        return value[4:] if str(value).startswith("enc:") else ""

    @staticmethod
    def mask_secret(value):
        return "***"


class MediaBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmpdir) / "gmjflow.db")
        self._patchers = [
            mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": self.db_path}, clear=False),
            mock.patch.object(media_dispatch, "_crypto", lambda: _FakeCrypto),
            mock.patch.object(backend_main, "SENSOR_DB_READY", False),
            mock.patch.object(backend_main, "hash_password", return_value="test-hash"),
            mock.patch.object(backend_main, "require_permission", return_value={"id": 1, "username": "tester"}),
        ]
        for patcher in self._patchers:
            patcher.start()
        backend_main.ensure_sensor_db()
        media_dispatch._PENDING.items = []
        self._drain_queue()

    def tearDown(self):
        media_dispatch._PENDING.items = []
        self._drain_queue()
        for patcher in reversed(self._patchers):
            patcher.stop()

    @staticmethod
    def _drain_queue():
        while not media_dispatch._QUEUE.empty():
            try:
                media_dispatch._QUEUE.get_nowait()
                media_dispatch._QUEUE.task_done()
            except Exception:
                break

    def payload(self, **overrides):
        values = {
            "name": "n8n alertas",
            "type": "webhook",
            "url": "http://10.0.0.5:5678/webhook/gmj-flow",
            "active": True,
            "event_types": ["anomaly_detected"],
            "minimum_severity": "info",
            "timeout_seconds": 5,
            "secret": "",
            "secret_header": "X-GMJ-Flow-Token",
        }
        values.update(overrides)
        return backend_main.MediaIntegrationPayload(**values)

    def insert_row(self, **overrides):
        row = {
            "media_id": 1,
            "event_id": 7,
            "event_type": "anomaly_detected",
            "status": "success",
            "http_status": 200,
            "duration_ms": 12,
            "error": "",
            "created_at": "2026-09-28T18:00:00Z",
        }
        row.update(overrides)
        return row

    def insert_sensor(self, sensor_id, name, exporter_ip=""):
        with backend_main.sqlite_connection() as conn:
            conn.execute(
                "INSERT INTO sensors (id, name, exporter_ip, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (int(sensor_id), name, exporter_ip, "2026-10-02T00:00:00Z", "2026-10-02T00:00:00Z"),
            )
            conn.commit()


class MediaUrlValidationTest(MediaBase):
    def test_rejects_invalid_scheme_and_empty(self):
        for value in ("", "   ", "ftp://n8n/webhook", "file:///etc/passwd", "n8n.local/webhook"):
            with self.assertRaises(media_dispatch.MediaUrlError):
                media_dispatch.validate_webhook_url(value)

    def test_rejects_metadata_and_localhost(self):
        for value in (
            "http://169.254.169.254/latest/meta-data",
            "http://100.100.100.200/latest/meta-data",
            "http://192.0.0.192/opc/v1/instance",
            "http://localhost:5678/webhook",
            "http://127.0.0.1:5678/webhook",
            "http://[::1]:5678/webhook",
        ):
            with self.assertRaises(media_dispatch.MediaUrlError):
                media_dispatch.validate_webhook_url(value)

    def test_allows_private_network_by_default(self):
        self.assertEqual(
            "http://10.0.0.5:5678/webhook/gmj-flow",
            media_dispatch.validate_webhook_url("http://10.0.0.5:5678/webhook/gmj-flow"),
        )
        self.assertEqual(
            "https://172.16.4.9/hook",
            media_dispatch.validate_webhook_url("https://172.16.4.9/hook"),
        )

    def test_loopback_only_when_explicitly_allowed(self):
        with mock.patch.dict(os.environ, {"GMJFLOW_MEDIA_ALLOW_LOOPBACK": "1"}, clear=False):
            self.assertEqual(
                "http://127.0.0.1:5678/webhook",
                media_dispatch.validate_webhook_url("http://127.0.0.1:5678/webhook"),
            )

    def test_private_can_be_blocked_by_env(self):
        with mock.patch.dict(os.environ, {"GMJFLOW_MEDIA_ALLOW_PRIVATE": "0"}, clear=False):
            with self.assertRaises(media_dispatch.MediaUrlError):
                media_dispatch.validate_webhook_url("http://10.0.0.5:5678/webhook")


class MediaPayloadTest(MediaBase):
    def test_envelope_uses_real_anomaly_fields(self):
        row = {
            "id": 123,
            "target_ip": "100.64.17.245",
            "target_port": 443,
            "protocol": "udp",
            "vector_name": "UDP_DOWNLOAD_SAME_DST_PORT",
            "severity": "critical",
            "direction": "receives",
            "metric_unit": "packets_s",
            "observed_value": 420000,
            "threshold_value": 200000,
            "unique_dst_ports": 3,
            "top_src_ip": "203.0.113.9",
            "top_dst_ip": "100.64.17.245",
            "started_at": "2026-09-28T18:00:00Z",
            "last_seen_at": "2026-09-28T18:02:00Z",
            "sensor": "edge-1",
            "source_name": "legacy",
            "decoder": "udp",
            "mitigation_reason": "volume acima do limite",
            "dedupe_key": "vec:100.64.17.245:udp",
        }
        envelope = media_dispatch.build_envelope("anomaly_detected", media_dispatch.anomaly_event_data(row))
        self.assertEqual(envelope["version"], 1)
        self.assertEqual(envelope["event"], "anomaly_detected")
        self.assertIn("sent_at", envelope)
        data = envelope["data"]
        self.assertEqual(data["event_id"], 123)
        self.assertEqual(data["target_ip"], "100.64.17.245")
        self.assertEqual(data["target_port"], 443)
        self.assertEqual(data["protocol"], "udp")
        self.assertEqual(data["vector_name"], "UDP_DOWNLOAD_SAME_DST_PORT")
        self.assertEqual(data["severity"], "critical")
        self.assertEqual(data["direction"], "receives")
        self.assertEqual(data["pps"], 420000)
        self.assertEqual(data["packets_s"], 420000)
        self.assertEqual(data["threshold_value"], 200000)
        self.assertEqual(data["mitigation_reason"], "volume acima do limite")

    def test_security_anomaly_shape_is_supported(self):
        row = {"id": 9, "vector": "DNS_AMPLIFICATION", "severity": "warning", "packets_s": 1000, "bits_s": 2000000, "target_ip": "200.1.2.3"}
        data = media_dispatch.anomaly_event_data(row)
        self.assertEqual(data["vector_name"], "DNS_AMPLIFICATION")
        self.assertEqual(data["pps"], 1000)
        self.assertEqual(data["bps"], 2000000)
        self.assertEqual(data["severity"], "warning")

    def test_missing_columns_do_not_break_serialization(self):
        data = media_dispatch.anomaly_event_data({})
        self.assertEqual(data["event_id"], 0)
        self.assertEqual(data["pps"], 0.0)
        self.assertIsNone(data["target_port"])


class MediaFilterTest(MediaBase):
    def test_active_event_and_severity_filters(self):
        integration = {
            "active": 1,
            "type": "webhook",
            "event_types": '["anomaly_detected"]',
            "minimum_severity": "warning",
        }
        self.assertTrue(media_dispatch.integration_matches(integration, "anomaly_detected", "warning"))
        self.assertTrue(media_dispatch.integration_matches(integration, "anomaly_detected", "critical"))
        self.assertFalse(media_dispatch.integration_matches(integration, "anomaly_detected", "info"))
        self.assertFalse(media_dispatch.integration_matches(integration, "anomaly_closed", "critical"))
        self.assertFalse(media_dispatch.integration_matches({**integration, "active": 0}, "anomaly_detected", "critical"))


class MediaSensorFilterTest(MediaBase):
    """Filtro por sensor: allSensors / sensorIds (requisitos A-H)."""

    def _insert(self, **overrides):
        all_sensors = overrides.pop("all_sensors", 1)
        sensor_ids = overrides.pop("sensor_ids", ())
        values = {
            "name": overrides.pop("name", "destino"),
            "type": "webhook",
            "url": "http://10.0.0.5:5678/webhook",
            "active": overrides.pop("active", 1),
            "all_sensors": all_sensors,
            "event_types": json.dumps(overrides.pop("event_types", ["anomaly_detected"])),
            "minimum_severity": overrides.pop("minimum_severity", "info"),
            "timeout_seconds": 5,
            "secret_encrypted": "",
            "secret_header": "X-GMJ-Flow-Token",
            "created_at": "2026-10-02T00:00:00Z",
            "updated_at": "2026-10-02T00:00:00Z",
        }
        values.update(overrides)
        with backend_main.sqlite_connection() as conn:
            cursor = backend_main.sqlite_insert_dict(conn, "media_integrations", values)
            media_id = int(cursor.lastrowid)
            for sensor_id in sensor_ids:
                conn.execute(
                    "INSERT INTO media_destination_sensors (media_id, sensor_id) VALUES (?, ?)",
                    (media_id, int(sensor_id)),
                )
            conn.commit()
        return media_id

    def _drain(self):
        jobs = []
        while not media_dispatch._QUEUE.empty():
            jobs.append(media_dispatch._QUEUE.get_nowait())
            media_dispatch._QUEUE.task_done()
        return jobs

    def test_a_legacy_destination_still_receives_every_sensor(self):
        # Destino criado antes da migration: sem all_sensors explicito => default 1.
        with backend_main.sqlite_connection() as conn:
            backend_main.sqlite_insert_dict(
                conn,
                "media_integrations",
                {
                    "name": "legado",
                    "type": "webhook",
                    "url": "http://10.0.0.5:5678/webhook",
                    "active": 1,
                    "event_types": json.dumps(["anomaly_detected"]),
                    "minimum_severity": "info",
                    "timeout_seconds": 5,
                    "secret_encrypted": "",
                    "secret_header": "X-GMJ-Flow-Token",
                    "created_at": "2026-10-02T00:00:00Z",
                    "updated_at": "2026-10-02T00:00:00Z",
                },
            )
            conn.commit()
        summary = media_dispatch.dispatch_media_event("anomaly_detected", {"event_id": 1, "severity": "critical", "sensor_id": 99})
        self.assertEqual(summary["queued"], 1)
        self.assertEqual(len(self._drain()), 1)

    def test_b_all_sensors_allows_any_sensor(self):
        self._insert(all_sensors=1)
        for sensor_id in (1, 2, 99):
            summary = media_dispatch.dispatch_media_event(
                "anomaly_detected", {"event_id": 1, "severity": "critical", "sensor_id": sensor_id}
            )
            self.assertEqual(summary["queued"], 1, f"sensor {sensor_id} deveria passar")
            self._drain()

    def test_c_selected_sensor_receives(self):
        self._insert(all_sensors=0, sensor_ids=[1])
        summary = media_dispatch.dispatch_media_event(
            "anomaly_detected", {"event_id": 1, "severity": "critical", "sensor_id": 1}
        )
        self.assertEqual(summary["queued"], 1)

    def test_d_unselected_sensor_is_skipped(self):
        self._insert(all_sensors=0, sensor_ids=[1])
        summary = media_dispatch.dispatch_media_event(
            "anomaly_detected", {"event_id": 1, "severity": "critical", "sensor_id": 2}
        )
        self.assertEqual(summary["queued"], 0)
        self.assertEqual(summary["matched"], 0)
        self.assertEqual(self._drain(), [])

    def test_e_one_sensor_feeds_two_destinations(self):
        self._insert(name="a", all_sensors=0, sensor_ids=[1])
        self._insert(name="b", all_sensors=0, sensor_ids=[1, 2])
        summary = media_dispatch.dispatch_media_event(
            "anomaly_detected", {"event_id": 1, "severity": "critical", "sensor_id": 1}
        )
        self.assertEqual(summary["queued"], 2)
        self.assertEqual(len(self._drain()), 2)

    def test_f_inactive_destination_is_skipped(self):
        self._insert(all_sensors=1, active=0)
        summary = media_dispatch.dispatch_media_event(
            "anomaly_detected", {"event_id": 1, "severity": "critical", "sensor_id": 1}
        )
        self.assertEqual(summary["queued"], 0)

    def test_g_disabled_event_is_skipped(self):
        self._insert(all_sensors=1, event_types=["anomaly_closed"])
        summary = media_dispatch.dispatch_media_event(
            "anomaly_detected", {"event_id": 1, "severity": "critical", "sensor_id": 1}
        )
        self.assertEqual(summary["queued"], 0)

    def test_h_severity_below_minimum_is_skipped(self):
        self._insert(all_sensors=1, minimum_severity="critical")
        summary = media_dispatch.dispatch_media_event(
            "anomaly_detected", {"event_id": 1, "severity": "info", "sensor_id": 1}
        )
        self.assertEqual(summary["queued"], 0)

    def test_restricted_destination_without_event_sensor_is_skipped(self):
        self._insert(all_sensors=0, sensor_ids=[1])
        summary = media_dispatch.dispatch_media_event("anomaly_detected", {"event_id": 1, "severity": "critical"})
        self.assertEqual(summary["queued"], 0)


class MediaPayloadTemplateTest(MediaBase):
    """Payload JSON editavel por destino (requisitos A-J)."""

    FIXED_SENT_AT = "2026-10-02T12:00:00Z"

    def _insert(self, **overrides):
        values = {
            "name": overrides.pop("name", "template"),
            "type": "webhook",
            "url": overrides.pop("url", "http://10.0.0.5:5678/webhook"),
            "active": overrides.pop("active", 1),
            "all_sensors": overrides.pop("all_sensors", 1),
            "payload_template": overrides.pop("payload_template", None),
            "event_types": json.dumps(overrides.pop("event_types", ["anomaly_detected"])),
            "minimum_severity": overrides.pop("minimum_severity", "info"),
            "timeout_seconds": 5,
            "secret_encrypted": "",
            "secret_header": "X-GMJ-Flow-Token",
            "created_at": "2026-10-02T00:00:00Z",
            "updated_at": "2026-10-02T00:00:00Z",
        }
        values.update(overrides)
        with backend_main.sqlite_connection() as conn:
            cursor = backend_main.sqlite_insert_dict(conn, "media_integrations", values)
            conn.commit()
            return int(cursor.lastrowid)

    def _row(self, media_id):
        with backend_main.sqlite_connection() as conn:
            return conn.execute("SELECT * FROM media_integrations WHERE id = ?", (int(media_id),)).fetchone()

    def _drain(self):
        jobs = []
        while not media_dispatch._QUEUE.empty():
            jobs.append(media_dispatch._QUEUE.get_nowait())
            media_dispatch._QUEUE.task_done()
        return jobs

    def _data(self, **overrides):
        data = dict(media_dispatch.TEST_SAMPLE_EVENT)
        data.update({"event_id": 7, "severity": "critical"})
        data.update(overrides)
        return data

    def test_a_legacy_destination_payload_is_byte_identical(self):
        data = self._data()
        expected = json.dumps(
            media_dispatch.build_envelope("anomaly_detected", data, sent_at=self.FIXED_SENT_AT),
            ensure_ascii=False,
        )
        actual = json.dumps(
            media_dispatch.render_payload_from_template(
                media_dispatch.DEFAULT_PAYLOAD_TEMPLATE,
                data,
                event_type="anomaly_detected",
                sent_at=self.FIXED_SENT_AT,
            ),
            ensure_ascii=False,
        )
        self.assertEqual(actual, expected)

        # Destino sem payload_template (NULL) continua enviando o payload legado.
        self._insert(payload_template=None)
        media_dispatch.dispatch_media_event("anomaly_detected", data)
        envelope = self._drain()[0]["envelope"]
        self.assertEqual(sorted(envelope.keys()), ["data", "event", "sent_at", "version"])
        self.assertNotIn("test", envelope)
        self.assertEqual(envelope["data"], data)

    def test_b_custom_template_removes_fields(self):
        template = '{"event": "{{event}}", "data": {"target_ip": "{{target_ip}}"}}'
        self._insert(payload_template=template)
        media_dispatch.dispatch_media_event("anomaly_detected", self._data(target_ip="9.9.9.9"))
        envelope = self._drain()[0]["envelope"]
        self.assertEqual(envelope, {"event": "anomaly_detected", "data": {"target_ip": "9.9.9.9"}})

    def test_c_custom_template_changes_structure(self):
        template = '{"alert": {"sensor": "{{sensor_name}}", "pps": {{pps}}}}'
        self._insert(payload_template=template)
        media_dispatch.dispatch_media_event("anomaly_detected", self._data(pps=420000))
        envelope = self._drain()[0]["envelope"]
        self.assertEqual(envelope, {"alert": {"sensor": "SENSOR-BHE-F1A", "pps": 420000}})

    def test_d_production_and_test_render_the_same_template(self):
        template = '{"event": "{{event}}", "target": "{{target_ip}}", "pps": {{pps}}}'
        media_id = self._insert(payload_template=template)
        data = self._data()
        media_dispatch.dispatch_media_event("anomaly_detected", data)
        production = self._drain()[0]["envelope"]
        with mock.patch.object(
            media_dispatch,
            "post_json",
            return_value={"ok": True, "http_status": 200, "duration_ms": 1, "error": ""},
        ) as post:
            media_dispatch.test_media_integration(self._row(media_id), sample_data=data)
        test_envelope = post.call_args[0][1]
        self.assertEqual({k: v for k, v in production.items() if k != "test"}, {k: v for k, v in test_envelope.items() if k != "test"})

    def test_e_test_flag_semantics(self):
        media_id = self._insert(payload_template='{"event": "{{event}}"}')
        # (1) template sem {{test}}: nem producao nem teste ganham a chave
        media_dispatch.dispatch_media_event("anomaly_detected", self._data())
        self.assertNotIn("test", self._drain()[0]["envelope"])
        with mock.patch.object(
            media_dispatch,
            "post_json",
            return_value={"ok": True, "http_status": 200, "duration_ms": 1, "error": ""},
        ) as post:
            media_dispatch.send_test_event({"severity": "critical"})
        self.assertNotIn("test", post.call_args[0][1])

        # (2) template com {{test}}: teste => true, producao => false
        explicit = '{"event": "{{event}}", "test": {{test}}}'
        with backend_main.sqlite_connection() as conn:
            conn.execute(
                "UPDATE media_integrations SET payload_template = ? WHERE id = ?", (explicit, media_id)
            )
            conn.commit()
        media_dispatch.dispatch_media_event("anomaly_detected", self._data())
        self.assertIs(self._drain()[0]["envelope"]["test"], False)
        with mock.patch.object(
            media_dispatch,
            "post_json",
            return_value={"ok": True, "http_status": 200, "duration_ms": 1, "error": ""},
        ) as post:
            media_dispatch.send_test_event({"severity": "critical"})
        self.assertIs(post.call_args[0][1]["test"], True)

    def test_f_numeric_placeholder_stays_number(self):
        template = '{"pps": {{pps}}, "event_id": {{event_id}}, "target_port": {{target_port}}}'
        payload = media_dispatch.render_payload_from_template(
            template, self._data(pps=420000, target_port=443), event_type="anomaly_detected"
        )
        self.assertIsInstance(payload["pps"], (int, float))
        self.assertEqual(payload["pps"], 420000)
        self.assertIsInstance(payload["event_id"], int)
        self.assertIsInstance(payload["target_port"], int)

    def test_g_boolean_placeholder_stays_boolean(self):
        template = '{"test": {{test}}}'
        production = media_dispatch.render_payload_from_template(
            template, self._data(), event_type="anomaly_detected", is_test=False
        )
        testing = media_dispatch.render_payload_from_template(
            template, self._data(), event_type="anomaly_detected", is_test=True
        )
        self.assertIs(production["test"], False)
        self.assertIs(testing["test"], True)

    def test_h_unknown_placeholder_is_rejected(self):
        with self.assertRaises(media_dispatch.MediaTemplateError):
            media_dispatch.validate_payload_template('{"x": "{{nao_existe}}"}')
        with self.assertRaises(backend_main.HTTPException):
            backend_main.create_media(self.payload(payload_template='{"x": "{{nao_existe}}"}'), request=None)

    def test_i_invalid_json_is_rejected(self):
        with self.assertRaises(media_dispatch.MediaTemplateError):
            media_dispatch.validate_payload_template('{"x": }')
        with self.assertRaises(backend_main.HTTPException):
            backend_main.create_media(self.payload(payload_template='{"x": }'), request=None)

    def test_j_format_restores_placeholders(self):
        formatted = media_dispatch.format_payload_template(media_dispatch.DEFAULT_PAYLOAD_TEMPLATE)
        self.assertIn("{{pps}}", formatted)
        self.assertNotIn("__GMJFLOW_PLACEHOLDER_", formatted)
        self.assertIn('"pps": {{pps}}', formatted)

    def test_crud_persists_and_clears_payload_template(self):
        template = '{"event": "{{event}}", "pps": {{pps}}}'
        created = backend_main.create_media(self.payload(payload_template=template), request=None)
        self.assertEqual(created["payload_template"], template)
        listed = backend_main.list_media(request=None)["items"][0]
        self.assertEqual(listed["payload_template"], template)
        cleared = backend_main.update_media(created["id"], self.payload(payload_template=""), request=None)
        self.assertEqual(cleared["payload_template"], "")
        # volta a usar o default sem alterar o payload legado
        self.assertEqual(cleared["allSensors"], True)


class MediaTestEventPayloadMappingTest(MediaBase):
    """Enriquecimento do evento de teste: origem/destino, sensor e preview (A-F)."""

    def _payload(self, **overrides):
        values = {
            "src_ip": "198.51.100.25",
            "src_port": 54321,
            "target_ip": "100.64.18.250",
            "target_port": 53,
            "protocol": "udp",
            "vector_name": "TEST_UDP_FLOOD",
            "display_name": "Teste UDP Flood",
            "source_name": "Evento manual de teste",
            "severity": "critical",
            "direction": "receives",
            "pps": 420000,
            "bps": 3800000000,
            "sensor_id": None,
            "flows": 12,
            "unique_src_ips": 1,
            "unique_dst_ips": 1,
            "unique_dst_ports": 1,
        }
        values.update(overrides)
        return backend_main.MediaTestEventPayload(**values)

    def _data(self, payload):
        with backend_main.sqlite_connection() as conn:
            return backend_main.media_test_event_data(payload, conn)

    def test_a_source_destination_mapping(self):
        data = self._data(self._payload())
        self.assertEqual(data["top_src_ip"], "198.51.100.25")
        self.assertEqual(data["top_src_port"], 54321)
        self.assertEqual(data["top_dst_ip"], "100.64.18.250")
        self.assertEqual(data["top_dst_port"], 53)
        self.assertEqual(data["target_ip"], "100.64.18.250")
        self.assertEqual(data["target_port"], 53)

    def test_b_cgnat_source_is_accepted(self):
        data = self._data(self._payload(src_ip="100.64.17.245", src_port=54321))
        self.assertEqual(data["top_src_ip"], "100.64.17.245")
        self.assertEqual(data["top_src_port"], 54321)

    def test_c_sensor_is_resolved_automatically(self):
        self.insert_sensor(7, "SENSOR-TESTE", "203.0.113.9")
        data = self._data(self._payload(sensor_id=7))
        self.assertEqual(data["sensor_id"], 7)
        self.assertEqual(data["sensor_name"], "SENSOR-TESTE")
        self.assertEqual(data["exporter_ip"], "203.0.113.9")
        self.assertEqual(data["sensor_resolution"], "single")
        self.assertEqual(data["sensor"], "SENSOR-TESTE")

    def test_no_sensor_does_not_invent_one(self):
        data = self._data(self._payload(sensor_id=None))
        self.assertIsNone(data["sensor_id"])
        self.assertIsNone(data["sensor_name"])
        self.assertEqual(data["exporter_ip"], "")
        self.assertEqual(data["sensor_resolution"], "unresolved")

    def test_unknown_sensor_is_rejected(self):
        with self.assertRaises(backend_main.HTTPException):
            self._data(self._payload(sensor_id=999))

    def test_d_numeric_types_are_preserved(self):
        data = self._data(self._payload(flows=7, unique_src_ips=3, unique_dst_ips=4, unique_dst_ports=5, pps=1000, bps=2000))
        for key in ("pps", "bps", "packets_s", "bits_s", "flows"):
            self.assertIsInstance(data[key], float, key)
        for key in ("unique_src_ips", "unique_dst_ips", "unique_dst_ports", "top_src_port", "target_port"):
            self.assertIsInstance(data[key], int, key)
        self.assertEqual(data["flows"], 7.0)
        self.assertEqual(data["unique_src_ips"], 3)

    def test_e_preview_exposes_the_same_values_that_would_be_sent(self):
        preview = backend_main.media_test_event_preview(self._payload(), request=None)
        self.assertTrue(preview["ok"])
        self.assertEqual(preview["payload"]["data"], preview["data"])
        for key in (
            "top_src_ip", "top_src_port", "top_dst_ip", "top_dst_port",
            "target_ip", "target_port", "sensor_name", "exporter_ip",
            "flows", "unique_src_ips", "unique_dst_ips", "unique_dst_ports", "pps", "bps",
        ):
            self.assertIn(key, preview["payload"]["data"])

    def test_e_preview_can_use_a_destination_template(self):
        media_id = backend_main.create_media(
            self.payload(payload_template='{"event": "{{event}}", "src": "{{top_src_ip}}", "pps": {{pps}}}'),
            request=None,
        )["id"]
        preview = backend_main.media_test_event_preview(self._payload(destination_id=media_id), request=None)
        self.assertEqual(preview["payload"], {"event": "anomaly_detected", "src": "198.51.100.25", "pps": 420000.0})
        self.assertFalse(preview["uses_default_template"])
        self.assertEqual(preview["destination"]["id"], media_id)

    def test_test_flag_only_exists_when_template_declares_it(self):
        # default nao declara {{test}}: teste tambem nao ganha a chave
        preview = backend_main.media_test_event_preview(self._payload(), request=None)
        self.assertNotIn("test", preview["payload"])
        production = media_dispatch.render_payload_from_template(
            media_dispatch.DEFAULT_PAYLOAD_TEMPLATE,
            dict(media_dispatch.TEST_SAMPLE_EVENT),
            event_type="anomaly_detected",
            is_test=False,
        )
        self.assertNotIn("test", production)
        # template explicito: teste true / producao false
        explicit = '{"event": "{{event}}", "test": {{test}}}'
        data = self._data(self._payload())
        self.assertIs(
            media_dispatch.render_payload_from_template(explicit, data, event_type="anomaly_detected", is_test=True)["test"],
            True,
        )
        self.assertIs(
            media_dispatch.render_payload_from_template(explicit, data, event_type="anomaly_detected", is_test=False)["test"],
            False,
        )

    def test_f_production_payload_is_not_affected(self):
        data = dict(media_dispatch.TEST_SAMPLE_EVENT)
        production = media_dispatch.render_payload_from_template(
            media_dispatch.DEFAULT_PAYLOAD_TEMPLATE, data, event_type="anomaly_detected", is_test=False
        )
        self.assertEqual(sorted(production.keys()), ["data", "event", "sent_at", "version"])
        self.assertEqual(production["data"], data)


class MediaHttpTest(MediaBase):
    def _post(self, behavior):
        envelope = media_dispatch.build_envelope("anomaly_detected", {"event_id": 1})
        with mock.patch.object(media_dispatch.urllib.request, "urlopen", side_effect=behavior):
            return media_dispatch.post_json("http://10.0.0.5:5678/webhook", envelope, {"Content-Type": "application/json"}, 3.0)

    def test_http_200_is_success(self):
        result = self._post(lambda *a, **k: _FakeResponse(200))
        self.assertTrue(result["ok"])
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["error"], "")
        self.assertGreaterEqual(result["duration_ms"], 0)

    def test_http_400_is_reported(self):
        result = self._post(lambda *a, **k: (_ for _ in ()).throw(urllib.error.HTTPError("u", 400, "Bad Request", {}, None)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["http_status"], 400)
        self.assertIn("400", result["error"])

    def test_http_500_is_reported(self):
        result = self._post(lambda *a, **k: (_ for _ in ()).throw(urllib.error.HTTPError("u", 500, "Server Error", {}, None)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["http_status"], 500)

    def test_timeout_is_reported(self):
        result = self._post(lambda *a, **k: (_ for _ in ()).throw(TimeoutError("timed out")))
        self.assertFalse(result["ok"])
        self.assertEqual(result["http_status"], 0)
        self.assertIn("TimeoutError", result["error"])

    def test_unreachable_destination_is_reported(self):
        result = self._post(lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("connection refused")))
        self.assertFalse(result["ok"])
        self.assertEqual(result["http_status"], 0)
        self.assertIn("URLError", result["error"])


class MediaCrudTest(MediaBase):
    def test_create_list_update_toggle_and_delete(self):
        created = backend_main.create_media(self.payload(secret="s3cr3t"), request=None)
        self.assertEqual(created["name"], "n8n alertas")
        self.assertTrue(created["active"])
        self.assertTrue(created["has_secret"])
        self.assertNotIn("secret", created)
        self.assertNotIn("s3cr3t", json.dumps(created))

        listing = backend_main.list_media(request=None)
        self.assertEqual(len(listing["items"]), 1)
        self.assertIn("anomaly_detected", listing["event_types"])
        self.assertNotIn("s3cr3t", json.dumps(listing))

        media_id = created["id"]
        updated = backend_main.update_media(
            media_id,
            self.payload(name="n8n clientes", minimum_severity="critical", event_types=["anomaly_detected", "mitigation_applied"]),
            request=None,
        )
        self.assertEqual(updated["name"], "n8n clientes")
        self.assertEqual(updated["minimum_severity"], "critical")
        self.assertEqual(sorted(updated["event_types"]), ["anomaly_detected", "mitigation_applied"])
        # segredo existente e preservado quando o campo vem vazio
        self.assertTrue(updated["has_secret"])

        toggled = backend_main.toggle_media(media_id, request=None)
        self.assertFalse(toggled["active"])
        toggled = backend_main.toggle_media(media_id, request=None)
        self.assertTrue(toggled["active"])

        deleted = backend_main.delete_media(media_id, request=None)
        self.assertTrue(deleted["ok"])
        self.assertEqual(len(backend_main.list_media(request=None)["items"]), 0)

    def test_create_rejects_dangerous_url_and_empty_events(self):
        with self.assertRaises(backend_main.HTTPException):
            backend_main.create_media(self.payload(url="http://169.254.169.254/latest"), request=None)
        with self.assertRaises(backend_main.HTTPException):
            backend_main.create_media(self.payload(event_types=[]), request=None)
        with self.assertRaises(backend_main.HTTPException):
            backend_main.create_media(self.payload(name=""), request=None)

    def test_test_endpoint_records_last_result(self):
        created = backend_main.create_media(self.payload(), request=None)
        media_id = created["id"]
        with mock.patch.object(media_dispatch, "post_json", return_value={"ok": True, "http_status": 200, "duration_ms": 34, "error": ""}):
            result = backend_main.test_media(media_id, request=None)
        self.assertTrue(result["ok"])
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["duration_ms"], 34)

        listed = backend_main.list_media(request=None)["items"][0]
        self.assertEqual(listed["last_test_status"], "success")
        self.assertEqual(listed["last_test_http_status"], 200)
        self.assertEqual(listed["last_test_duration_ms"], 34)
        self.assertTrue(listed["last_test_at"])

    def test_test_endpoint_reports_failure(self):
        created = backend_main.create_media(self.payload(), request=None)
        with mock.patch.object(media_dispatch, "post_json", return_value={"ok": False, "http_status": 500, "duration_ms": 12, "error": "HTTP 500"}):
            result = backend_main.test_media(created["id"], request=None)
        self.assertFalse(result["ok"])
        self.assertEqual(result["http_status"], 500)
        listed = backend_main.list_media(request=None)["items"][0]
        self.assertEqual(listed["last_test_status"], "error")
        self.assertEqual(listed["last_test_error"], "HTTP 500")

    def test_logs_endpoint_returns_delivery_history(self):
        created = backend_main.create_media(self.payload(), request=None)
        media_id = created["id"]
        media_dispatch.record_delivery(media_id, 42, "anomaly_detected", {"ok": True, "http_status": 200, "duration_ms": 9, "error": ""})
        media_dispatch.record_delivery(media_id, 43, "anomaly_detected", {"ok": False, "http_status": 0, "duration_ms": 5000, "error": "URLError"})
        logs = backend_main.media_logs(media_id, request=None, limit=10)["items"]
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0]["event_id"], 43)
        self.assertEqual(logs[0]["status"], "error")
        self.assertEqual(logs[1]["status"], "success")

    def test_create_and_update_sensor_selection(self):
        self.insert_sensor(1, "SENSOR-BHE-F1A", "10.0.0.1")
        self.insert_sensor(2, "SENSOR-BHE-F1B", "10.0.0.2")

        created = backend_main.create_media(
            self.payload(allSensors=False, sensorIds=[1, 2]), request=None
        )
        self.assertFalse(created["allSensors"])
        self.assertEqual(created["sensorIds"], [1, 2])

        listed = backend_main.list_media(request=None)["items"][0]
        self.assertFalse(listed["allSensors"])
        self.assertEqual(listed["sensorIds"], [1, 2])

        updated = backend_main.update_media(
            created["id"], self.payload(allSensors=True), request=None
        )
        self.assertTrue(updated["allSensors"])
        self.assertEqual(updated["sensorIds"], [])

    def test_snake_case_sensor_fields_are_accepted(self):
        self.insert_sensor(1, "SENSOR-BHE-F1A", "10.0.0.1")
        created = backend_main.create_media(
            self.payload(all_sensors=False, sensor_ids=[1]), request=None
        )
        self.assertFalse(created["allSensors"])
        self.assertEqual(created["sensorIds"], [1])

    def test_sensor_validation_rejects_empty_and_unknown(self):
        # I) allSensors=false com lista vazia deve ser rejeitado.
        with self.assertRaises(backend_main.HTTPException):
            backend_main.create_media(self.payload(allSensors=False, sensorIds=[]), request=None)
        # sensor inexistente tambem deve ser rejeitado.
        with self.assertRaises(backend_main.HTTPException):
            backend_main.create_media(self.payload(allSensors=False, sensorIds=[999]), request=None)
        # atualizacao com lista vazia tambem deve ser rejeitada.
        self.insert_sensor(1, "SENSOR-BHE-F1A", "10.0.0.1")
        created = backend_main.create_media(self.payload(), request=None)
        with self.assertRaises(backend_main.HTTPException):
            backend_main.update_media(created["id"], self.payload(allSensors=False, sensorIds=[]), request=None)


class MediaDispatchTest(MediaBase):
    def _insert(self, **overrides):
        values = {
            "name": overrides.pop("name", "hook"),
            "type": "webhook",
            "url": overrides.pop("url", "http://10.0.0.5:5678/webhook"),
            "active": overrides.pop("active", 1),
            "event_types": json.dumps(overrides.pop("event_types", ["anomaly_detected"])),
            "minimum_severity": overrides.pop("minimum_severity", "info"),
            "timeout_seconds": 5,
            "secret_encrypted": overrides.pop("secret_encrypted", ""),
            "secret_header": "X-GMJ-Flow-Token",
            "created_at": "2026-09-28T18:00:00Z",
            "updated_at": "2026-09-28T18:00:00Z",
        }
        with backend_main.sqlite_connection() as conn:
            cursor = backend_main.sqlite_insert_dict(conn, "media_integrations", values)
            conn.commit()
            return int(cursor.lastrowid)

    def _drain(self):
        jobs = []
        while not media_dispatch._QUEUE.empty():
            jobs.append(media_dispatch._QUEUE.get_nowait())
            media_dispatch._QUEUE.task_done()
        return jobs

    def test_multiple_active_targets_receive_same_event(self):
        self._insert(name="a")
        self._insert(name="b", minimum_severity="critical")
        summary = media_dispatch.dispatch_media_event("anomaly_detected", {"event_id": 1, "severity": "critical"})
        self.assertEqual(summary["matched"], 2)
        self.assertEqual(summary["queued"], 2)
        jobs = self._drain()
        self.assertEqual(len(jobs), 2)
        self.assertEqual({job["envelope"]["event"] for job in jobs}, {"anomaly_detected"})

    def test_inactive_disabled_event_and_low_severity_are_skipped(self):
        self._insert(name="inativo", active=0)
        self._insert(name="outro evento", event_types=["anomaly_closed"])
        self._insert(name="critico", minimum_severity="critical")
        summary = media_dispatch.dispatch_media_event("anomaly_detected", {"event_id": 1, "severity": "info"})
        self.assertEqual(summary["matched"], 0)
        self.assertEqual(summary["queued"], 0)
        self.assertEqual(self._drain(), [])

    def test_secret_header_is_applied_and_never_logged(self):
        self._insert(secret_encrypted="enc:super-secret")
        jobs = []
        summary = media_dispatch.dispatch_media_event("anomaly_detected", {"event_id": 1, "severity": "critical"})
        self.assertEqual(summary["queued"], 1)
        jobs = self._drain()
        self.assertEqual(jobs[0]["headers"]["X-GMJ-Flow-Token"], "super-secret")
        self.assertNotIn("super-secret", json.dumps(summary))

    def test_dispatch_never_raises_when_database_is_unavailable(self):
        with mock.patch.object(media_dispatch, "connect", side_effect=sqlite3.OperationalError("database is locked")):
            summary = media_dispatch.dispatch_media_event("anomaly_detected", {"event_id": 1, "severity": "critical"})
        self.assertEqual(summary["queued"], 0)
        self.assertTrue(summary["errors"])

    def test_unsupported_event_is_ignored(self):
        summary = media_dispatch.dispatch_media_event("evento_inventado", {})
        self.assertEqual(summary["queued"], 0)
        self.assertTrue(summary["errors"])

    def test_flush_pending_created_only_after_commit(self):
        self._insert()
        with backend_main.sqlite_connection() as conn:
            backend_main.sqlite_insert_dict(
                conn,
                "anomaly_events",
                {
                    "target_ip": "100.64.17.245",
                    "target_role": "internal",
                    "zone_name": "",
                    "vector_name": "VEC",
                    "scope_type": "internal_ip_32",
                    "invalid_scope": 0,
                    "direction": "receives",
                    "decoder": "udp",
                    "severity": "critical",
                    "metric_unit": "packets_s",
                    "threshold_value": 1,
                    "observed_value": 2,
                    "peak_value": 2,
                    "started_at": "2026-09-28T18:00:00Z",
                    "last_seen_at": "2026-09-28T18:00:00Z",
                    "status": "active",
                    "estimated_bytes": 0,
                    "estimated_packets": 0,
                    "flow_count": 0,
                    "summary": "",
                    "dedupe_key": "media-test",
                    "protocol": "udp",
                    "mitigation_basis": "",
                    "mitigation_reason": "",
                    "top_src_ip": "",
                    "top_dst_ip": "",
                    "top_packets": 0,
                    "top_bytes": 0,
                    "detection_engine": "legacy",
                    "rule_snapshot_json": "{}",
                    "anomaly_source": "detection",
                    "source_engine": "detection_templates",
                    "source_id": "",
                    "source_name": "",
                    "source_details_json": "{}",
                    "auto_mitigation_status": "",
                    "auto_mitigation_reason": "",
                    "auto_mitigation_details_json": "{}",
                    "auto_mitigation_updated_at": "",
                    "created_at": "2026-09-28T18:00:00Z",
                    "updated_at": "2026-09-28T18:00:00Z",
                },
            )
            event_id = int(conn.execute("SELECT MAX(id) AS id FROM anomaly_events").fetchone()["id"])
            conn.commit()
            backend_main.media_dispatch.track_created("anomaly_event", event_id)
            # nada foi disparado antes do flush
            self.assertEqual(media_dispatch.pending_created(), [("anomaly_event", event_id)])
            summary = backend_main.media_dispatch.flush_pending_created(conn)
        self.assertEqual(summary["dispatched"], 1)
        self.assertEqual(media_dispatch.pending_created(), [])
        jobs = self._drain()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["envelope"]["data"]["event_id"], event_id)

    def test_flush_isolates_anomaly_when_webhook_target_is_invalid(self):
        self._insert(url="http://localhost:5678/webhook")
        with backend_main.sqlite_connection() as conn:
            conn.execute(
                "UPDATE media_integrations SET secret_encrypted = '' WHERE id = 1"
            )
            conn.commit()
        summary = media_dispatch.dispatch_media_event("anomaly_detected", {"event_id": 1, "severity": "critical"})
        # o destino casa com o filtro, mas a URL insegura e recusada na hora do disparo
        self.assertEqual(summary["matched"], 1)
        self.assertEqual(summary["queued"], 0)
        self.assertTrue(summary["errors"])
        self.assertEqual(self._drain(), [])

    def test_dispatch_survives_broken_queue(self):
        self._insert()
        with mock.patch.object(media_dispatch._QUEUE, "put_nowait", side_effect=RuntimeError("fila quebrada")):
            summary = media_dispatch.dispatch_media_event("anomaly_detected", {"event_id": 1, "severity": "critical"})
        self.assertEqual(summary["queued"], 0)
        self.assertTrue(summary["errors"])

    def test_flush_never_raises_and_clears_pending(self):
        media_dispatch.track_created("anomaly_event", 999)
        with mock.patch.object(media_dispatch, "connect", side_effect=RuntimeError("banco fora")):
            summary = media_dispatch.flush_pending_created(None)
        self.assertEqual(summary["dispatched"], 0)
        self.assertTrue(summary["errors"])
        self.assertEqual(media_dispatch.pending_created(), [])

    def test_anomaly_row_survives_webhook_failure(self):
        """A anomalia existe e permanece mesmo que toda a midia falhe."""
        self._insert()
        with backend_main.sqlite_connection() as conn:
            backend_main.sqlite_insert_dict(
                conn,
                "media_delivery_logs",
                {
                    "media_id": 1,
                    "event_id": 5,
                    "event_type": "anomaly_detected",
                    "status": "error",
                    "http_status": 0,
                    "duration_ms": 5000,
                    "error": "URLError: connection refused",
                    "created_at": "2026-09-28T18:00:00Z",
                },
            )
            conn.commit()
            with mock.patch.object(media_dispatch, "post_json", side_effect=RuntimeError("destino fora")):
                media_dispatch.dispatch_media_event("anomaly_detected", {"event_id": 5, "severity": "critical"})
            rows = conn.execute("SELECT COUNT(*) AS c FROM media_delivery_logs").fetchone()["c"]
        self.assertEqual(int(rows), 1)

    def test_webhook_failure_does_not_interrupt_the_caller(self):
        """Falha do webhook nao propaga: o pipeline da anomalia segue intacto."""
        self._insert()
        media_dispatch.track_created("anomaly_event", 1)
        media_dispatch.track_created("security_anomaly", 2)
        with mock.patch.object(media_dispatch, "dispatch_anomaly_detected", side_effect=RuntimeError("boom")), \
             mock.patch.object(media_dispatch, "dispatch_security_anomaly_detected", side_effect=RuntimeError("boom")):
            summary = media_dispatch.flush_pending_created(backend_main.sqlite_connection())
        self.assertEqual(summary["dispatched"], 0)
        self.assertEqual(media_dispatch.pending_created(), [])
        # a conexao continua utilizavel depois da falha da midia
        with backend_main.sqlite_connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) AS c FROM media_integrations").fetchone()["c"], 1)



class MediaTestEventTest(MediaBase):
    """Ferramentas administrativas de teste (nao podem tocar o detector real)."""

    def _insert_media(self, **overrides):
        values = {
            "name": overrides.pop("name", "n8n"),
            "type": "webhook",
            "url": overrides.pop("url", "http://10.0.0.5:5678/webhook"),
            "active": overrides.pop("active", 1),
            "event_types": json.dumps(overrides.pop("event_types", ["anomaly_detected"])),
            "minimum_severity": overrides.pop("minimum_severity", "info"),
            "timeout_seconds": 5,
            "secret_encrypted": "",
            "secret_header": "X-GMJ-Flow-Token",
            "created_at": "2026-09-28T18:00:00Z",
            "updated_at": "2026-09-28T18:00:00Z",
        }
        with backend_main.sqlite_connection() as conn:
            cursor = backend_main.sqlite_insert_dict(conn, "media_integrations", values)
            conn.commit()
            return int(cursor.lastrowid)

    def _counts(self):
        with backend_main.sqlite_connection() as conn:
            return {
                table: conn.execute("SELECT COUNT(*) AS c FROM %s" % table).fetchone()["c"]
                for table in ("anomaly_events", "security_anomalies", "media_delivery_logs")
            }

    def test_envelope_has_typed_values_without_test_key_by_default(self):
        self._insert_media()
        with mock.patch.object(media_dispatch, "post_json", return_value={"ok": True, "http_status": 200, "duration_ms": 7, "error": ""}):
            payload = media_dispatch.send_test_event({
                "target_ip": "100.64.17.245",
                "target_port": 443,
                "protocol": "udp",
                "vector_name": "TEST_UDP_FLOOD",
                "display_name": "Teste UDP Flood",
                "source_name": "Evento manual de teste",
                "severity": "critical",
                "direction": "receives",
                "status": "test",
                "pps": 420000,
                "bps": 3800000000,
            })
        envelope = payload["envelope"]
        # o template padrao nao declara {{test}}, entao a chave nao e injetada
        self.assertNotIn("test", envelope)
        self.assertEqual(envelope["version"], 1)
        self.assertEqual(envelope["event"], "anomaly_detected")
        data = envelope["data"]
        self.assertEqual(data["event_id"], 0)
        self.assertEqual(data["target_ip"], "100.64.17.245")
        self.assertEqual(data["target_port"], 443)
        self.assertEqual(data["protocol"], "udp")
        self.assertEqual(data["vector_name"], "TEST_UDP_FLOOD")
        self.assertEqual(data["severity"], "critical")
        self.assertEqual(data["pps"], 420000)
        self.assertEqual(data["bps"], 3800000000)
        self.assertEqual(payload["results"][0]["media_id"], 1)
        self.assertTrue(payload["results"][0]["ok"])

    def test_test_event_does_not_create_real_anomaly(self):
        self._insert_media()
        before = self._counts()
        with mock.patch.object(media_dispatch, "post_json", return_value={"ok": True, "http_status": 200, "duration_ms": 5, "error": ""}):
            media_dispatch.send_test_event({"target_ip": "100.64.17.245", "severity": "critical"})
        after = self._counts()
        self.assertEqual(after["anomaly_events"], before["anomaly_events"])
        self.assertEqual(after["security_anomalies"], before["security_anomalies"])
        # o log de entrega e o unico registro criado, e marcado como "test"
        self.assertEqual(after["media_delivery_logs"], before["media_delivery_logs"] + 1)
        with backend_main.sqlite_connection() as conn:
            row = conn.execute("SELECT event_type, event_id FROM media_delivery_logs ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["event_type"], "test")
        self.assertIsNone(row["event_id"])

    def test_test_event_failure_does_not_raise(self):
        self._insert_media()
        with mock.patch.object(media_dispatch, "post_json", side_effect=RuntimeError("destino fora")):
            payload = media_dispatch.send_test_event({"severity": "critical"})
        self.assertEqual(len(payload["results"]), 1)
        self.assertFalse(payload["results"][0]["ok"])
        self.assertIn("RuntimeError", payload["results"][0]["error"])

    def test_test_event_skips_incompatible_targets(self):
        self._insert_media(name="inativo", active=0)
        self._insert_media(name="outro evento", event_types=["anomaly_closed"])
        self._insert_media(name="minimo critical", minimum_severity="critical")
        with mock.patch.object(media_dispatch, "post_json", return_value={"ok": True, "http_status": 200, "duration_ms": 3, "error": ""}):
            payload = media_dispatch.send_test_event({"severity": "info"})
        self.assertEqual(payload["results"], [])

    def test_endpoint_test_event_requires_permission_and_returns_results(self):
        self._insert_media()
        body = backend_main.MediaTestEventPayload(
            target_ip="100.64.17.245", target_port=443, protocol="udp",
            vector_name="TEST_UDP_FLOOD", display_name="Teste UDP Flood",
            source_name="Evento manual de teste", severity="critical",
            direction="receives", pps=420000, bps=3800000000,
        )
        with mock.patch.object(media_dispatch, "post_json", return_value={"ok": True, "http_status": 200, "duration_ms": 11, "error": ""}):
            result = backend_main.media_test_event(body, request=None)
        # template padrao nao declara {{test}}: a chave nao e injetada
        self.assertNotIn("test", result["envelope"])
        self.assertEqual(result["results"][0]["http_status"], 200)

        with mock.patch.object(backend_main, "require_permission", side_effect=backend_main.HTTPException(status_code=403, detail="negado")):
            with self.assertRaises(backend_main.HTTPException):
                backend_main.media_test_event(body, request=None)

    def test_telegram_token_never_returned_or_leaked(self):
        token = "123456789:SUPER-SECRET-TOKEN"
        body = backend_main.MediaTestTelegramPayload(bot_token=token, chat_id="-100999", text="oi")
        with mock.patch.object(
            media_dispatch,
            "post_json",
            return_value={"ok": False, "http_status": 401, "duration_ms": 30, "error": "HTTP 401 Unauthorized"},
        ) as post:
            result = backend_main.media_test_telegram(body, request=None)
        self.assertFalse(result["ok"])
        self.assertEqual(result["http_status"], 401)
        self.assertNotIn(token, json.dumps(result))
        # a URL de destino carrega o token e nao pode vazar em nenhum campo de retorno
        called_url = post.call_args[0][0]
        self.assertIn(token, called_url)
        self.assertNotIn(token, json.dumps(result))

    def test_telegram_error_is_scrubbed(self):
        token = "123456789:SUPER-SECRET-TOKEN"
        with mock.patch.object(
            media_dispatch,
            "post_json",
            return_value={"ok": False, "http_status": 0, "duration_ms": 5, "error": f"URLError: {token} recusado"},
        ):
            result = media_dispatch.send_telegram_message(token, "1", "oi")
        self.assertNotIn(token, result["error"])
        self.assertIn("***", result["error"])

    def test_telegram_validation_errors(self):
        empty = media_dispatch.send_telegram_message("", "1", "oi")
        self.assertFalse(empty["ok"])
        self.assertIn("vazio", empty["error"])
        body = backend_main.MediaTestTelegramPayload(bot_token="sem-dois-pontos", chat_id="1", text="oi")
        with self.assertRaises(backend_main.HTTPException):
            backend_main.media_test_telegram(body, request=None)
        body2 = backend_main.MediaTestTelegramPayload(bot_token="123:abc", chat_id="", text="oi")
        with self.assertRaises(backend_main.HTTPException):
            backend_main.media_test_telegram(body2, request=None)

    def test_telegram_timeout_is_reported(self):
        with mock.patch.object(media_dispatch.urllib.request, "urlopen", side_effect=TimeoutError("timed out")):
            result = media_dispatch.send_telegram_message("123:abc", "-100999", "oi")
        self.assertFalse(result["ok"])
        self.assertEqual(result["http_status"], 0)
        self.assertIn("TimeoutError", result["error"])

    def test_test_event_endpoint_requires_permission(self):
        body = backend_main.MediaTestEventPayload()
        with mock.patch.object(backend_main, "require_permission", side_effect=backend_main.HTTPException(status_code=403, detail="negado")):
            with self.assertRaises(backend_main.HTTPException):
                backend_main.media_test_event(body, request=None)

if __name__ == "__main__":
    unittest.main()
