import asyncio
import os
import json
import sqlite3
import sys
import tempfile
import threading
import time
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

SKIP_RUNTIME_IMPORT = sys.version_info < (3, 10)

class HTTPException(Exception):
    def __init__(self, status_code=500, detail=""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _RouterStub:
    def __init__(self, *args, **kwargs):
        pass

    def add_middleware(self, *args, **kwargs):
        pass

    def include_router(self, *args, **kwargs):
        pass

    def _decorator(self, *args, **kwargs):
        def wrap(func):
            return func
        return wrap

    def on_event(self, *args, **kwargs):
        return self._decorator(*args, **kwargs)

    def middleware(self, *args, **kwargs):
        return self._decorator(*args, **kwargs)

    def api_route(self, *args, **kwargs):
        return self._decorator(*args, **kwargs)

    get = post = put = patch = delete = _decorator


def _query(default=None, *args, **kwargs):
    return default


sys.modules.setdefault("clickhouse_connect", types.SimpleNamespace(get_client=lambda **_kwargs: None))
fastapi_stub = types.ModuleType("fastapi")
fastapi_stub.FastAPI = _RouterStub
fastapi_stub.APIRouter = _RouterStub
fastapi_stub.HTTPException = HTTPException
fastapi_stub.Query = _query
fastapi_stub.Request = type("Request", (), {})
fastapi_stub.Response = type("Response", (), {})
sys.modules.setdefault("fastapi", fastapi_stub)
cors_stub = types.ModuleType("fastapi.middleware.cors")
cors_stub.CORSMiddleware = object
sys.modules.setdefault("fastapi.middleware", types.ModuleType("fastapi.middleware"))
sys.modules.setdefault("fastapi.middleware.cors", cors_stub)
jose_stub = types.ModuleType("jose")
jose_stub.JWTError = Exception
jose_stub.jwt = types.SimpleNamespace(encode=lambda *a, **k: "", decode=lambda *a, **k: {})
sys.modules.setdefault("jose", jose_stub)
passlib_context_stub = types.ModuleType("passlib.context")
passlib_context_stub.CryptContext = lambda *a, **k: types.SimpleNamespace(hash=lambda value: value, verify=lambda value, hashed: value == hashed)
sys.modules.setdefault("passlib", types.ModuleType("passlib"))
sys.modules.setdefault("passlib.context", passlib_context_stub)
responses_stub = types.ModuleType("starlette.responses")


class _JSONResponse:
    def __init__(self, content=None, status_code=200, *args, **kwargs):
        self.content = content if content is not None else kwargs.get("content")
        self.status_code = status_code
        self.body = json.dumps(self.content).encode("utf-8") if self.content is not None else b""

    def __getitem__(self, key):
        return self.content[key]


responses_stub.JSONResponse = _JSONResponse
responses_stub.Response = type("Response", (), {"__init__": lambda self, *a, **k: None})
sys.modules.setdefault("starlette", types.ModuleType("starlette"))
sys.modules.setdefault("starlette.responses", responses_stub)
if SKIP_RUNTIME_IMPORT:
    for _name in (
        "clickhouse_connect",
        "fastapi",
        "fastapi.middleware",
        "fastapi.middleware.cors",
        "jose",
        "passlib",
        "passlib.context",
        "starlette",
        "starlette.responses",
    ):
        sys.modules.pop(_name, None)

if not SKIP_RUNTIME_IMPORT:
    from app import main
else:
    main = None


class temporary_main_db:
    def __enter__(self):
        self.original = os.environ.get("GMJFLOW_DB_PATH")
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.close()
        self.path = handle.name
        os.environ["GMJFLOW_DB_PATH"] = self.path
        main.SENSOR_DB_READY = False
        main.ensure_sensor_db()
        return self.path

    def __exit__(self, *_exc):
        main.SENSOR_DB_READY = False
        if self.original is None:
            os.environ.pop("GMJFLOW_DB_PATH", None)
        else:
            os.environ["GMJFLOW_DB_PATH"] = self.original
        try:
            os.unlink(self.path)
        except OSError:
            pass


@unittest.skipIf(SKIP_RUNTIME_IMPORT, "backend/app/main.py requires Python 3.10+ for runtime import tests")
class BgpMitigationTest(unittest.TestCase):
    def setUp(self):
        self._real_pipe_guard = patch.object(
            main,
            "exabgp_write_pipe",
            side_effect=AssertionError("Teste tentou escrever no pipe ExaBGP real."),
        )
        self.exabgp_pipe_guard = self._real_pipe_guard.start()
        self.addCleanup(self._real_pipe_guard.stop)
        self._readiness_guard_patch = patch.object(
            main,
            "check_bgp_connector_readiness",
            side_effect=lambda _conn, connector: self._readiness_result(connector),
        )
        self.bgp_readiness_guard = self._readiness_guard_patch.start()
        self.addCleanup(self._readiness_guard_patch.stop)
        self._automatic_ai_gate_patch = patch.object(
            main,
            "run_automatic_mitigation_ai_analysis",
            return_value=(
                {
                    "id": 1,
                    "apply_mitigation": True,
                    "reason": "Teste: automacao autorizada.",
                    "status": "success",
                    "error_message": "",
                },
                {"allow_auto": True},
            ),
        )
        self.automatic_ai_gate = self._automatic_ai_gate_patch.start()
        self.addCleanup(self._automatic_ai_gate_patch.stop)

    def _admin_request(self):
        return types.SimpleNamespace(state=types.SimpleNamespace(user={"role": "admin", "username": "tester"}))

    def _connector_and_profile(self, max_duration=3600):
        conn = main.sqlite_connection()
        now = main.utc_now_iso()
        connector_id = conn.execute(
            """
            INSERT INTO bgp_connectors (
                name, role, backend_type, mode, max_active_rules, max_duration_seconds,
                enabled, is_active, created_at, updated_at
            )
            VALUES ('BGP-FIBINET-BORDA', 'flowspec_mitigation', 'exabgp', 'manual_approval', 50, ?, 1, 1, ?, ?)
            """,
            (max_duration, now, now),
        ).lastrowid
        profile_id = conn.execute(
            """
            INSERT INTO bgp_response_profiles (
                name, enabled, response_type, connector_id, approval_mode, action, default_action,
                target_selector, protocol_selector, dst_port_selector, require_protocol_or_port,
                max_duration_seconds, default_duration_seconds, created_at, updated_at
            )
            VALUES ('FLOWSPEC_VALID', 1, 'flowspec', ?, 'manual_approval', 'discard', 'discard',
                    'dst_ip', 'anomaly_protocol', 'anomaly_dst_port', 1, ?, 300, ?, ?)
            """,
            (connector_id, max_duration, now, now),
        ).lastrowid
        conn.commit()
        connector = main.fetch_bgp_connector(conn, connector_id)
        profile = main.fetch_bgp_profile(conn, profile_id)
        return conn, connector, profile

    def _stage2_candidate(self, connector, profile, mitigation_key="stage2-attempt", anomaly_id=None):
        return {
            "response_profile_id": profile["id"],
            "connector_id": connector["id"],
            "response_type": "flowspec",
            "action": "discard",
            "then_action": "discard",
            "target_prefix": "203.0.113.10/32",
            "dst_prefix": "203.0.113.10/32",
            "dst_ip": "203.0.113.10",
            "protocol": "udp",
            "dst_port": "53",
            "duration_seconds": 300,
            "mitigation_key": mitigation_key,
            "anomaly_id": anomaly_id,
            "source": "stage2_test",
            "source_id": str(anomaly_id or mitigation_key),
        }

    def _readiness_result(self, connector, peer_state="established", ready=None, reason=""):
        if ready is None:
            ready = peer_state == "established"
        confirmation_level = "peer_established" if ready else "peer_not_ready"
        status = {
            "connector_id": connector["id"],
            "bgp_state": peer_state,
            "flowspec_state": peer_state if ready else "not_verified",
            "pipe_state": "ok" if ready else "not_verified",
            "last_checked_at": main.utc_now_iso(),
            "pipes": {"ok": ready, "status": "ok" if ready else "not_verified"},
            "session": {"tcp_established": ready},
            "service": {"active": ready},
            "verification": {
                "bgp_verified": peer_state in {"established", "down"},
                "flowspec_verified": ready,
                "pipe_verified": ready,
            },
        }
        details = {
            "checked_at": status["last_checked_at"],
            "bgp_state": status["bgp_state"],
            "flowspec_state": status["flowspec_state"],
            "pipe_state": status["pipe_state"],
            "pipe_ok": ready,
        }
        return {
            "ready": ready,
            "peer_state": peer_state,
            "confirmation_level": confirmation_level,
            "reason": reason or ("peer_established" if ready else f"peer_{peer_state}"),
            "failure_status": "" if ready else "peer_down",
            "status": status,
            "details": details,
        }

    def _announcement_event_types(self, conn, announcement_id):
        return [
            row["event_type"]
            for row in conn.execute(
                "SELECT event_type FROM bgp_announcement_events WHERE announcement_id = ? ORDER BY id",
                (announcement_id,),
            ).fetchall()
        ]

    def _dns_multi_target_context(self, max_active_rules=50, min_packets_s=1000, add_whitelist=True):
        conn = main.sqlite_connection()
        now = main.utc_now_iso()
        connector_id = conn.execute(
            """
            INSERT INTO bgp_connectors (
                name, role, backend_type, mode, max_active_rules, max_duration_seconds,
                enabled, is_active, exabgp_pipe_in, created_at, updated_at
            )
            VALUES ('BGP-SENSOR-ORIGIN', 'flowspec_mitigation', 'exabgp', 'manual_approval', ?, 1800,
                    1, 1, '/run/exabgp/exabgp.in', ?, ?)
            """,
            (max_active_rules, now, now),
        ).lastrowid
        conn.execute(
            """
            INSERT OR IGNORE INTO sensors (id, name, exporter_ip, created_at, updated_at)
            VALUES (9, 'sensor-origin', '192.0.2.9', ?, ?)
            """,
            (now, now),
        )
        conn.execute(
            """
            INSERT INTO bgp_protected_prefixes (cidr, name, enabled, block_rtbh, block_flowspec, created_at, updated_at)
            VALUES ('45.5.248.0/24', 'Fibinet clientes', 1, 1, 1, ?, ?)
            """,
            (now, now),
        )
        conn.execute(
            """
            INSERT INTO ip_zones (id, name, connector_id, active, created_at, updated_at)
            VALUES (1, 'Clientes', ?, 1, ?, ?)
            """,
            (connector_id, now, now),
        )
        conn.execute(
            """
            INSERT INTO ip_zone_prefixes (zone_id, cidr, name, active, created_at, updated_at)
            VALUES (1, '45.5.248.0/24', 'Fibinet clientes', 1, ?, ?)
            """,
            (now, now),
        )
        profile = conn.execute("SELECT * FROM bgp_response_profiles WHERE name = 'FLOWSPEC_AUTO_BLOCK_DST_DNS'").fetchone()
        conn.execute(
            """
            UPDATE bgp_response_profiles
            SET enable_multi_target_dns = 1,
                max_targets_per_anomaly = 10,
                min_target_packets_s = ?,
                min_target_bits_s = NULL,
                mitigation_target_mode = 'sensor_origin',
                approval_mode = 'auto',
                target_selector = 'dst_ip',
                protocol_selector = 'udp',
                dst_port_selector = 'fixed',
                dst_port_value = '53',
                default_duration_seconds = 600
            WHERE id = ?
            """,
            (min_packets_s, int(profile["id"])),
        )
        template_id = conn.execute(
            "INSERT INTO detection_templates (name, description, active, created_at, updated_at) VALUES ('DNS', '', 1, ?, ?)",
            (now, now),
        ).lastrowid
        conn.execute(
            """
            INSERT INTO detection_template_rules (
                template_id, vector, display_name, domain, direction, protocol, metric, comparison,
                warning_value, critical_value, window_seconds, consecutive_windows, cooldown_minutes,
                enabled, response, critical_response_profile_id, mitigation_mode, mitigation_enabled,
                created_at, updated_at
            )
            VALUES (?, 'DNS_INTERNAL_IP_TO_DST_HIGH_PPS', 'DNS alto por destino', 'internal_ip',
                    'transmits', 'DNS', 'packets_s', 'over', 5000, 15000, 60, 1, 5,
                    1, 'DETECTION_ONLY', ?, 'response_profile', 1, ?, ?)
            """,
            (template_id, int(profile["id"]), now, now),
        )
        conn.execute(
            """
            INSERT INTO detection_template_rules (
                template_id, vector, display_name, domain, direction, protocol, metric, comparison,
                warning_value, critical_value, window_seconds, consecutive_windows, cooldown_minutes,
                enabled, response, critical_response_profile_id, mitigation_mode, mitigation_enabled,
                created_at, updated_at
            )
            VALUES (?, 'DNS_QUERY_OUTBOUND_CLIENT', 'DNS outbound por cliente', 'internal_ip',
                    'transmits', 'DNS', 'packets_s', 'over', 5000, 15000, 60, 1, 5,
                    1, 'DETECTION_ONLY', ?, 'response_profile', 1, ?, ?)
            """,
            (template_id, int(profile["id"]), now, now),
        )
        if add_whitelist:
            conn.execute(
                """
                INSERT INTO detection_whitelist (
                    name, type, dst_cidr, protocol, active, created_at, updated_at
                )
                VALUES ('dns-ok', 'destination', '103.192.159.11/32', 'udp', 1, ?, ?)
                """,
                (now, now),
            )
        conn.commit()
        profile = main.fetch_bgp_profile(conn, int(profile["id"]))
        connector = main.fetch_bgp_connector(conn, int(connector_id))
        return conn, connector, profile

    def _dns_event_and_flows(self):
        event = {
            "id": 77,
            "attack_vector_name": "DNS_INTERNAL_IP_TO_DST_HIGH_PPS",
            "classification": "dns_abuse_outbound",
            "direction": "transmits",
            "decoder": "DNS",
            "protocol": "udp",
            "target_ip": "45.5.248.205",
            "target_cidr": "45.5.248.205/32",
            "target_role": "src_ip",
            "target_port": 53,
            "sensor_id": 9,
            "severity": "critical",
        }
        flows = [
            {
                "src_ip": "45.5.248.205",
                "src_port": 1100 + index,
                "dst_ip": f"103.192.159.{index}",
                "dst_port": 53,
                "proto": 17,
                "packets": 100000 + index,
                "bytes": 1000000 + index,
                "packets_s": 2000 + index,
                "bits_s": 500000 + index,
            }
            for index in range(1, 12)
        ]
        flows.append({
            "src_ip": "45.5.248.205",
            "src_port": 2200,
            "dst_ip": "103.192.159.250",
            "dst_port": 53,
            "proto": 17,
            "packets": 10,
            "bytes": 1000,
            "packets_s": 10,
            "bits_s": 100,
        })
        return event, flows

    def _insert_dns_query_anomaly_event(self, conn, event_id=140, src_ip="45.5.248.205", dst_ip="103.100.169.200"):
        now = main.utc_now_iso()
        conn.execute(
            """
            INSERT INTO anomaly_events (
                id, sensor_id, target_ip, target_cidr, target_role, zone_id, zone_name,
                vector_name, scope_type, direction, decoder, severity, metric_unit,
                threshold_value, observed_value, peak_value, started_at, last_seen_at,
                estimated_bytes, estimated_packets, flow_count, summary, dedupe_key,
                created_at, updated_at, top_src_ip, top_dst_ip, top_src_port, top_dst_port,
                top_packets, top_bytes, protocol
            )
            VALUES (?, 9, ?, ?, 'src_ip', 1, 'Clientes', 'DNS_QUERY_OUTBOUND_CLIENT',
                    'internal_ip_32', 'transmits', 'DNS', 'critical', 'packets_s',
                    10000, 13000, 13000, ?, ?, 1000000, 13000, 1,
                    'DNS outbound alto', ?, ?, ?, ?, ?, 62129, 53, 13000, 1000000, 'udp')
            """,
            (event_id, src_ip, f"{src_ip}/32", now, now, f"dns-query-{event_id}", now, now, src_ip, dst_ip),
        )
        conn.execute(
            """
            INSERT INTO anomaly_event_flows (
                anomaly_event_id, flow_time, sensor, exporter_ip, src_ip, dst_ip,
                src_port, dst_port, proto, bytes, packets, flow_count
            )
            VALUES (?, ?, 'sensor-9', '192.0.2.9', ?, ?, 62129, 53, 17, 1000000, 13000, 1)
            """,
            (event_id, now, src_ip, dst_ip),
        )
        conn.commit()
        return event_id

    def _insert_udp_many_anomaly_event(
        self,
        conn,
        event_id=1767,
        src_ip="45.5.248.205",
        dst_ip="51.222.110.42",
        dst_port=9987,
        zone_id=None,
        sensor_id=None,
    ):
        now = main.utc_now_iso()
        values = {
            "id": event_id,
            "sensor_id": sensor_id,
            "target_ip": dst_ip,
            "target_cidr": main.host_cidr_for_ip(dst_ip),
            "target_role": "dst_ip",
            "zone_id": zone_id,
            "zone_name": "Clientes" if zone_id else "",
            "vector_name": main.UDP_UPLOAD_MANY_CLIENTS_VECTOR,
            "scope_type": "external_dst_ip_port",
            "direction": "sends",
            "decoder": "UDP",
            "severity": "warning",
            "metric_unit": "packets_s",
            "threshold_value": 10000,
            "observed_value": 40000,
            "peak_value": 40000,
            "started_at": now,
            "last_seen_at": now,
            "status": "active",
            "estimated_bytes": 4000000,
            "estimated_packets": 40000,
            "flow_count": 1,
            "summary": "UDP outbound para destino/porta agregados",
            "dedupe_key": f"udp-many-{event_id}",
            "created_at": now,
            "updated_at": now,
            "top_src_ip": src_ip,
            "top_dst_ip": dst_ip,
            "top_src_port": 45000,
            "top_dst_port": dst_port,
            "top_packets": 40000,
            "top_bytes": 4000000,
            "protocol": "udp",
        }
        columns = list(values)
        conn.execute(
            f"INSERT INTO anomaly_events ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            tuple(values[column] for column in columns),
        )
        conn.execute(
            """
            INSERT INTO anomaly_event_flows (
                anomaly_event_id, flow_time, sensor, exporter_ip, src_ip, dst_ip,
                src_port, dst_port, proto, bytes, packets, flow_count
            )
            VALUES (?, ?, 'sensor-test', '192.0.2.10', ?, ?, 45000, ?, 17, 4000000, 40000, 1)
            """,
            (event_id, now, src_ip, dst_ip, dst_port),
        )
        conn.commit()
        return event_id

    def _insert_zone_connector_mapping(self, conn, name, cidr, connector_id, zone_id=None):
        now = main.utc_now_iso()
        if zone_id is None:
            zone_id = conn.execute(
                "INSERT INTO ip_zones (name, connector_id, active, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
                (name, connector_id, now, now),
            ).lastrowid
        else:
            conn.execute(
                "INSERT INTO ip_zones (id, name, connector_id, active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)",
                (zone_id, name, connector_id, now, now),
            )
        conn.execute(
            "INSERT INTO ip_zone_prefixes (zone_id, cidr, active, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
            (zone_id, cidr, now, now),
        )
        return int(zone_id)

    def _insert_flowspec_connector(self, conn, name, pipe_path):
        now = main.utc_now_iso()
        return int(conn.execute(
            """
            INSERT INTO bgp_connectors (
                name, role, backend_type, mode, max_active_rules, max_duration_seconds,
                enabled, is_active, exabgp_pipe_in, created_at, updated_at
            )
            VALUES (?, 'flowspec_mitigation', 'exabgp', 'manual_approval', 50, 1800,
                    1, 1, ?, ?, ?)
            """,
            (name, pipe_path, now, now),
        ).lastrowid)

    def _insert_legacy_dns_anomaly_event(self, conn, event_id=143):
        now = main.utc_now_iso()
        conn.execute(
            """
            INSERT INTO anomaly_events (
                id, sensor_id, target_ip, target_cidr, target_role, zone_id, zone_name,
                vector_name, scope_type, direction, decoder, severity, metric_unit,
                threshold_value, observed_value, peak_value, started_at, last_seen_at,
                estimated_bytes, estimated_packets, flow_count, summary, dedupe_key,
                detection_engine, detection_template_rule_id, response_profile_id,
                top_src_ip, top_dst_ip, protocol, mitigation_basis, created_at, updated_at
            )
            VALUES (?, 9, '45.5.248.205', '45.5.248.205/32', 'src_ip', 1, 'Clientes',
                    'dns', 'internal_ip_32', 'transmits', 'DNS', 'critical', 'packets_s',
                    10000, 13000, 13000, ?, ?, 1000000, 13000, 1,
                    'DNS legacy sem top flow persistido', ?, 'legacy', NULL, NULL,
                    '', '', '', '', ?, ?)
            """,
            (event_id, now, now, f"legacy-dns-{event_id}", now, now),
        )
        conn.commit()
        return event_id

    def _insert_response_announcement(
        self,
        conn,
        anomaly_id,
        status,
        updated_at,
        *,
        anomaly_source="anomaly_events",
        expires_at=None,
        dst_prefix="203.0.113.10/32",
        last_error="",
    ):
        queued_at = updated_at if status in {"queued", "sent", "advertised"} else None
        sent_at = updated_at if status in {"sent", "advertised"} else None
        advertised_at = updated_at if status == "advertised" else None
        cursor = conn.execute(
            """
            INSERT INTO bgp_announcements (
                anomaly_id, status, route_type, response_type, action,
                target_prefix, dst_prefix, protocol, dst_port, duration_seconds,
                expires_at, queued_at, sent_at, advertised_at, last_attempt_at,
                peer_state, confirmation_level, requested_mode,
                source, source_id, anomaly_source, last_error,
                created_by, created_at, updated_at
            )
            VALUES (?, ?, 'flowspec', 'flowspec', 'discard',
                    ?, ?, 'udp', '9987', 900,
                    ?, ?, ?, ?, ?,
                    ?, ?, 'announce_now',
                    'manual', ?, ?, ?,
                    'response-test', ?, ?)
            """,
            (
                anomaly_id,
                status,
                dst_prefix,
                dst_prefix,
                expires_at,
                queued_at,
                sent_at,
                advertised_at,
                updated_at,
                "established" if status == "advertised" else "down" if status == "peer_down" else "",
                "announce_requested_peer_established" if status == "advertised" else "registered",
                str(anomaly_id),
                anomaly_source,
                last_error,
                updated_at,
                updated_at,
            ),
        )
        return int(cursor.lastrowid)

    def _insert_security_response_anomaly(self, conn, anomaly_id, src_ip="45.5.248.210", dst_ip="198.51.100.210"):
        now = main.utc_now_iso()
        conn.execute(
            """
            INSERT INTO security_anomalies (
                id, vector, severity, status, zone_id, zone_name,
                domain, direction, src_ip, dst_ip, target_ip, target_cidr,
                target_role, scope_type, protocol, packets_s, bits_s, flows,
                first_seen, last_seen, message, dedupe_key,
                anomaly_source, source_engine, source_id, source_name,
                created_at, updated_at
            )
            VALUES (?, 'UDP_UPLOAD_MANY_CLIENTS_SAME_DST_PORT', 'warning', 'active', 7, 'Security zone',
                    'internal_ip', 'transmits', ?, ?, ?, ?,
                    'src_ip', 'internal_ip_32', 'udp', 22000, 1000000, 10,
                    ?, ?, 'Security anomaly response test', ?,
                    'detection_template_rule', 'detection_templates', ?, 'Security response test',
                    ?, ?)
            """,
            (
                anomaly_id,
                src_ip,
                dst_ip,
                src_ip,
                f"{src_ip}/32",
                now,
                now,
                f"security-response-{anomaly_id}",
                str(anomaly_id),
                now,
                now,
            ),
        )
        conn.commit()
        return anomaly_id

    def test_dry_run_has_no_ttl_and_does_not_start_expiration(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            payload = main.BgpAnnouncementDryRunPayload(
                response_profile_id=profile["id"],
                dst_ip="203.0.113.10",
                dst_port=53,
                protocol="udp",
                duration_seconds=300,
            )
            candidate = main.candidate_from_bgp_payload(payload, profile)
            validation = main.validate_mitigation_candidate(candidate, connector, profile)
            item = main.create_bgp_announcement(conn, candidate, connector, profile, validation, "test")
            self.assertIn("announce flow route", item["announce_command"])
            self.assertIn("withdraw flow route", item["withdraw_command"])
            self.assertNotIn("ttl", item["announce_command"].lower())
            self.assertNotIn("duration", item["announce_command"].lower())
            self.assertEqual(item["duration_seconds"], 300)
            self.assertIsNone(item["expires_at"])
            self.assertFalse(item["operationally_active"])

    def test_manual_announce_blocks_duration_above_max_before_pipe(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile(max_duration=300)
            candidate = {
                "response_profile_id": profile["id"],
                "connector_id": connector["id"],
                "response_type": "flowspec",
                "action": "discard",
                "then_action": "discard",
                "target_prefix": "203.0.113.10/32",
                "dst_prefix": "203.0.113.10/32",
                "protocol": "udp",
                "dst_port": "53",
                "duration_seconds": 3600,
                "mitigation_key": "over-duration",
            }
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                with self.assertRaises(HTTPException) as ctx:
                    main.apply_mitigation_candidate(conn, candidate, "announce_now", "test")
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(calls, [])
            self.assertIn("Nenhum anuncio foi enviado", str(ctx.exception.detail))

    def test_scheduler_expires_advertised_announcement_with_saved_withdraw(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            now = main.utc_now_iso()
            past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
            conn.execute(
                """
                INSERT INTO bgp_announcements (
                    connector_id, connector_name, status, route_type, response_type, action,
                    target_prefix, dst_prefix, protocol, dst_port, duration_seconds,
                    expires_at, announced_at, announce_command, withdraw_command, rendered_command,
                    created_at, updated_at
                )
                VALUES (?, ?, 'advertised', 'flowspec', 'flowspec', 'discard',
                        '203.0.113.10/32', '203.0.113.10/32', 'udp', '53', 60,
                        ?, ?, 'announce flow route X', 'withdraw flow route X', 'announce flow route X',
                        ?, ?)
                """,
                (connector["id"], connector["name"], past, now, now, now),
            )
            conn.commit()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                stats = main.process_expired_bgp_announcements(conn)
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(stats["withdrawn"], 1)
            self.assertEqual(calls, ["withdraw flow route X"])
            row = conn.execute("SELECT status FROM bgp_announcements").fetchone()
            self.assertEqual(row["status"], "expired")

    def test_sent_transition_starts_safety_ttl_before_advertised(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "sent-safety-ttl")
            policy = main.policy_for_candidate(candidate)
            validation = main.validate_mitigation_candidate(candidate, connector, profile)
            queued = main.insert_bgp_mitigation_announcement(
                conn,
                candidate,
                connector,
                profile,
                policy,
                validation,
                "queued",
                main.render_exabgp_flowspec_command("announce", candidate),
                "tester",
            )
            sent = main.transition_bgp_announcement(
                conn,
                queued["id"],
                "sent",
                "sent",
                "Comando entregue no teste.",
                "tester",
            )
            self.assertTrue(sent["sent_at"])
            self.assertTrue(sent["expires_at"])
            self.assertIsNone(sent["advertised_at"])
            self.assertFalse(sent["operationally_active"])

    def test_scheduler_withdraws_all_delivered_states_and_preserves_pending(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            now = main.utc_now_iso()
            past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
            inserted = {}
            for status, sent_at, advertised_at, announced_at in (
                ("sent", now, None, None),
                ("peer_down", now, now, now),
                ("active", None, None, now),
                ("pending_approval", None, None, None),
            ):
                inserted[status] = conn.execute(
                    """
                    INSERT INTO bgp_announcements (
                        connector_id, status, route_type, response_type, action,
                        target_prefix, dst_prefix, duration_seconds, expires_at,
                        sent_at, advertised_at, announced_at, withdraw_command,
                        created_at, updated_at
                    )
                    VALUES (?, ?, 'flowspec', 'flowspec', 'discard',
                            '203.0.113.10/32', '203.0.113.10/32', 60, ?,
                            ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        connector["id"],
                        status,
                        past,
                        sent_at,
                        advertised_at,
                        announced_at,
                        f"withdraw flow route {status}",
                        now,
                        now,
                    ),
                ).lastrowid
            conn.commit()
            with patch.object(main, "exabgp_write_pipe") as write_pipe:
                stats = main.process_expired_bgp_announcements(conn)

            self.assertEqual(stats, {"withdrawn": 3, "failed": 0})
            self.assertEqual(write_pipe.call_count, 3)
            rows = {
                row["id"]: row
                for row in conn.execute("SELECT id, status, expires_at FROM bgp_announcements").fetchall()
            }
            for status in ("sent", "peer_down", "active"):
                self.assertEqual(rows[inserted[status]]["status"], "expired")
                self.assertEqual(rows[inserted[status]]["expires_at"], past)
                self.assertIn("withdraw_requested", self._announcement_event_types(conn, inserted[status]))
            self.assertEqual(rows[inserted["pending_approval"]]["status"], "pending_approval")
            self.assertNotIn("withdraw_requested", self._announcement_event_types(conn, inserted["pending_approval"]))

    def test_delivery_intent_left_by_a_crash_gets_a_safety_withdraw(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "crash-after-send-intent")
            policy = main.policy_for_candidate(candidate)
            validation = main.validate_mitigation_candidate(candidate, connector, profile)
            queued = main.insert_bgp_mitigation_announcement(
                conn,
                candidate,
                connector,
                profile,
                policy,
                validation,
                "queued",
                main.render_exabgp_flowspec_command("announce", candidate),
                "tester",
            )
            conn.commit()

            claim_token = main.persist_bgp_send_intent(conn, queued["id"], "tester", queued["announce_command"])
            past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
            conn.execute("UPDATE bgp_announcements SET expires_at = ? WHERE id = ?", (past, queued["id"]))
            conn.commit()

            with patch.object(main, "exabgp_write_pipe") as write_pipe:
                stats = main.process_expired_bgp_announcements(conn)

            stored = main.fetch_bgp_announcement(conn, queued["id"])
            self.assertTrue(claim_token)
            self.assertEqual(stats, {"withdrawn": 1, "failed": 0})
            self.assertEqual(stored["status"], "expired")
            self.assertEqual(stored["confirmation_level"], "withdrawn")
            self.assertIn("delivery_attempted", self._announcement_event_types(conn, queued["id"]))
            self.assertIn("withdraw_requested", self._announcement_event_types(conn, queued["id"]))
            write_pipe.assert_called_once_with(connector, queued["withdraw_command"])

    def test_failed_withdraw_is_retried_and_remains_reserved_until_success(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "failed-withdraw-retry")
            policy = main.policy_for_candidate(candidate)
            validation = main.validate_mitigation_candidate(candidate, connector, profile)
            advertised = main.insert_bgp_mitigation_announcement(
                conn,
                candidate,
                connector,
                profile,
                policy,
                validation,
                "advertised",
                main.render_exabgp_flowspec_command("announce", candidate),
                "tester",
            )
            conn.commit()
            conn.close()

            with patch.object(main, "exabgp_write_pipe", side_effect=HTTPException(status_code=503, detail="pipe busy")):
                failed = main.withdraw_bgp_announcement(self._admin_request(), advertised["id"])
            self.assertEqual(failed["status"], "failed_withdraw")
            with main.sqlite_connection() as check:
                self.assertTrue(main.active_mitigation_exists(check, candidate["mitigation_key"]))
                stale = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat().replace("+00:00", "Z")
                check.execute("UPDATE bgp_announcements SET updated_at = ? WHERE id = ?", (stale, advertised["id"]))
                check.commit()
                with patch.object(main, "exabgp_write_pipe") as write_pipe:
                    stats = main.process_expired_bgp_announcements(check)
                stored = main.fetch_bgp_announcement(check, advertised["id"])
                self.assertFalse(main.active_mitigation_exists(check, candidate["mitigation_key"]))
            self.assertEqual(stats, {"withdrawn": 1, "failed": 0})
            self.assertEqual(stored["status"], "withdrawn")
            write_pipe.assert_called_once()

    def test_expiring_older_equivalent_attempt_does_not_withdraw_newer_delivery(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            now = main.utc_now_iso()
            past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
            future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
            ids = []
            for index, expires_at in enumerate((past, future)):
                ids.append(conn.execute(
                    """
                    INSERT INTO bgp_announcements (
                        connector_id, status, route_type, response_type, action,
                        target_prefix, dst_prefix, protocol, dst_port, mitigation_key,
                        duration_seconds, expires_at, sent_at, advertised_at,
                        withdraw_command, created_at, updated_at
                    ) VALUES (?, 'advertised', 'flowspec', 'flowspec', 'discard',
                              '203.0.113.10/32', '203.0.113.10/32', 'udp', '53',
                              ?, 300, ?, ?, ?, 'withdraw flow route SAME', ?, ?)
                    """,
                    (connector["id"], f"historical-race-{index}", expires_at, now, now, now, now),
                ).lastrowid)
            conn.commit()

            with patch.object(main, "exabgp_write_pipe") as write_pipe:
                stats = main.process_expired_bgp_announcements(conn)

            older = main.fetch_bgp_announcement(conn, ids[0])
            newer = main.fetch_bgp_announcement(conn, ids[1])
            self.assertEqual(stats, {"withdrawn": 1, "failed": 0})
            self.assertEqual(older["status"], "expired")
            self.assertEqual(older["confirmation_level"], "superseded_by_newer_delivery")
            self.assertEqual(older["status_details"]["superseded_by_announcement_id"], ids[1])
            self.assertEqual(newer["status"], "advertised")
            write_pipe.assert_not_called()

    def test_elapsed_ttl_keeps_dedup_and_capacity_until_withdraw_is_confirmed(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            conn.execute("UPDATE bgp_connectors SET max_active_rules = 1 WHERE id = ?", (connector["id"],))
            connector = main.fetch_bgp_connector(conn, connector["id"])
            candidate = self._stage2_candidate(connector, profile, "expired-equivalent")
            past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
            now = main.utc_now_iso()
            conn.execute(
                """
                INSERT INTO bgp_announcements (
                    connector_id, response_profile_id, status, route_type, response_type,
                    action, target_prefix, dst_prefix, protocol, dst_port,
                    duration_seconds, expires_at, mitigation_key, created_at, updated_at
                )
                VALUES (?, ?, 'advertised', 'flowspec', 'flowspec',
                        'discard', ?, ?, 'udp', '53', 300, ?, ?, ?, ?)
                """,
                (
                    connector["id"],
                    profile["id"],
                    candidate["target_prefix"],
                    candidate["dst_prefix"],
                    past,
                    candidate["mitigation_key"],
                    now,
                    now,
                ),
            )
            conn.commit()

            validation = main.validate_mitigation_candidate(candidate, connector, profile)

            self.assertIsNotNone(main.equivalent_mitigation_announcement(conn, candidate["mitigation_key"]))
            self.assertTrue(main.active_mitigation_exists(conn, candidate["mitigation_key"]))
            self.assertTrue(any("equivalente ativa" in error for error in validation["errors"]))
            self.assertIn("Limite de regras ativas do conector excedido.", validation["errors"])

    def test_stage2_schema_adds_traceable_attempt_fields_without_replacing_legacy_columns(self):
        with temporary_main_db():
            with main.sqlite_connection() as conn:
                columns = {
                    row["name"]
                    for row in conn.execute("PRAGMA table_info(bgp_announcements)").fetchall()
                }
            self.assertTrue(
                {
                    "queued_at",
                    "sent_at",
                    "advertised_at",
                    "last_attempt_at",
                    "peer_state",
                    "confirmation_level",
                    "status_details_json",
                    "requested_mode",
                    "retry_of_announcement_id",
                    "announced_at",
                    "expires_at",
                }.issubset(columns)
            )

    def test_pending_approval_never_checks_peer_writes_pipe_or_counts_as_active(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "stage2-pending")
            with patch.object(main, "check_bgp_connector_readiness") as readiness, \
                 patch.object(main, "exabgp_write_pipe") as write_pipe:
                item = main.apply_mitigation_candidate(conn, candidate, "manual_approval", "tester")
            conn.commit()

            self.assertEqual(item["status"], "pending_approval")
            self.assertFalse(item["operationally_active"])
            self.assertIsNone(item["queued_at"])
            self.assertIsNone(item["sent_at"])
            self.assertIsNone(item["advertised_at"])
            self.assertIsNone(item["last_attempt_at"])
            self.assertIsNone(item["expires_at"])
            self.assertEqual(item["requested_mode"], "manual_approval")
            readiness.assert_not_called()
            write_pipe.assert_not_called()
            summary = main.bgp_summary_payload(conn)
            self.assertEqual(summary["active_bgp_announcements"], 0)
            self.assertEqual(summary["pending_bgp_announcements"], 1)
            events = self._announcement_event_types(conn, item["id"])
            self.assertIn("pending_approval", events)
            self.assertNotIn("queued", events)
            self.assertNotIn("sent", events)
            self.assertNotIn("advertised", events)
            conn.close()

    def test_peer_down_or_unverified_persists_peer_down_without_pipe_write(self):
        for peer_state in ("down", "not_verified"):
            with self.subTest(peer_state=peer_state), temporary_main_db():
                conn, connector, profile = self._connector_and_profile()
                candidate = self._stage2_candidate(
                    connector,
                    profile,
                    f"stage2-peer-{peer_state}",
                )
                readiness_result = self._readiness_result(
                    connector,
                    peer_state=peer_state,
                    ready=False,
                    reason=f"peer_{peer_state}",
                )
                with patch.object(
                    main,
                    "check_bgp_connector_readiness",
                    return_value=readiness_result,
                ) as readiness, patch.object(main, "exabgp_write_pipe") as write_pipe:
                    item = main.apply_mitigation_candidate(conn, candidate, "announce_now", "tester")
                conn.commit()

                self.assertEqual(item["status"], "peer_down")
                self.assertFalse(item["operationally_active"])
                self.assertTrue(item["queued_at"])
                self.assertTrue(item["last_attempt_at"])
                self.assertIsNone(item["sent_at"])
                self.assertIsNone(item["advertised_at"])
                self.assertIsNone(item["announced_at"])
                self.assertIsNone(item["expires_at"])
                self.assertFalse(item["status_details"].get("send_claim_token"))
                self.assertEqual(item["status_details"]["send_claim_cancelled_reason"], f"peer_{peer_state}")
                self.assertEqual(item["peer_state"], peer_state)
                self.assertIn(peer_state, item["last_error"])
                self.assertEqual(item["status_details"]["bgp_state"], peer_state)
                readiness.assert_called_once()
                write_pipe.assert_not_called()
                events = self._announcement_event_types(conn, item["id"])
                self.assertLess(events.index("queued"), events.index("peer_down"))
                self.assertNotIn("sent", events)
                self.assertNotIn("advertised", events)
                conn.close()

    def test_peer_down_before_delivery_can_be_rejected_without_a_withdraw(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "peer-down-rejectable")
            readiness_result = self._readiness_result(
                connector,
                peer_state="down",
                ready=False,
                reason="peer_bgp_down",
            )
            with patch.object(main, "check_bgp_connector_readiness", return_value=readiness_result), \
                 patch.object(main, "exabgp_write_pipe") as write_pipe:
                item = main.apply_mitigation_candidate(conn, candidate, "announce_now", "tester")
            conn.commit()
            conn.close()

            rejected = main.reject_bgp_announcement(self._admin_request(), item["id"])

            self.assertEqual(rejected["status"], "rejected")
            self.assertIsNone(rejected["sent_at"])
            write_pipe.assert_not_called()

    def test_peer_up_and_pipe_success_trace_queued_sent_advertised_and_start_ttl(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "stage2-success")
            readiness_result = self._readiness_result(connector)
            with patch.object(
                main,
                "check_bgp_connector_readiness",
                return_value=readiness_result,
            ) as readiness, patch.object(main, "exabgp_write_pipe") as write_pipe:
                item = main.apply_mitigation_candidate(conn, candidate, "announce_now", "tester")
            conn.commit()

            self.assertEqual(item["status"], "advertised")
            self.assertTrue(item["operationally_active"])
            self.assertTrue(item["queued_at"])
            self.assertTrue(item["sent_at"])
            self.assertTrue(item["advertised_at"])
            self.assertTrue(item["announced_at"])
            self.assertTrue(item["last_attempt_at"])
            self.assertTrue(item["expires_at"])
            self.assertEqual(item["peer_state"], "established")
            self.assertNotEqual(item["confirmation_level"], "registered")
            self.assertEqual(item["requested_mode"], "announce_now")
            self.assertEqual(item["status_details"]["bgp_state"], "established")
            readiness.assert_called_once()
            write_pipe.assert_called_once()
            self.assertEqual(write_pipe.call_args.args[0]["id"], connector["id"])
            self.assertEqual(write_pipe.call_args.args[1], item["announce_command"])
            events = self._announcement_event_types(conn, item["id"])
            self.assertLess(events.index("queued"), events.index("sent"))
            self.assertLess(events.index("sent"), events.index("advertised"))
            self.assertEqual(main.bgp_summary_payload(conn)["active_bgp_announcements"], 1)
            conn.close()

    def test_pipe_failure_after_peer_check_is_failed_without_ttl(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "stage2-pipe-failure")
            readiness_result = self._readiness_result(connector)
            with patch.object(
                main,
                "check_bgp_connector_readiness",
                return_value=readiness_result,
            ), patch.object(
                main,
                "exabgp_write_pipe",
                side_effect=HTTPException(status_code=400, detail="pipe down"),
            ) as write_pipe:
                item = main.apply_mitigation_candidate(conn, candidate, "announce_now", "tester")
            conn.commit()

            self.assertEqual(item["status"], "failed")
            self.assertFalse(item["operationally_active"])
            self.assertTrue(item["queued_at"])
            self.assertTrue(item["last_attempt_at"])
            self.assertIsNone(item["sent_at"])
            self.assertIsNone(item["advertised_at"])
            self.assertIsNone(item["announced_at"])
            self.assertIsNone(item["expires_at"])
            self.assertFalse(item["status_details"].get("send_claim_token"))
            self.assertEqual(item["status_details"]["send_claim_cancelled_reason"], "pipe down")
            self.assertIn("pipe down", item["last_error"])
            write_pipe.assert_called_once()
            events = self._announcement_event_types(conn, item["id"])
            self.assertLess(events.index("queued"), events.index("announce_failed"))
            self.assertNotIn("sent", events)
            self.assertNotIn("advertised", events)
            self.assertEqual(main.bgp_summary_payload(conn)["active_bgp_announcements"], 0)
            conn.close()

    def test_approval_uses_the_same_queued_sent_advertised_attempt_flow(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "stage2-approval")
            pending = main.apply_mitigation_candidate(conn, candidate, "manual_approval", "tester")
            conn.commit()
            conn.close()

            readiness_result = self._readiness_result(connector)
            with patch.object(
                main,
                "check_bgp_connector_readiness",
                return_value=readiness_result,
            ) as readiness, patch.object(main, "exabgp_write_pipe") as write_pipe:
                item = main.approve_bgp_announcement(self._admin_request(), pending["id"])

            self.assertEqual(item["id"], pending["id"])
            self.assertEqual(item["status"], "advertised")
            self.assertTrue(item["queued_at"])
            self.assertTrue(item["sent_at"])
            self.assertTrue(item["advertised_at"])
            self.assertTrue(item["expires_at"])
            readiness.assert_called_once()
            write_pipe.assert_called_once()
            with main.sqlite_connection() as check:
                events = self._announcement_event_types(check, item["id"])
            self.assertLess(events.index("pending_approval"), events.index("queued"))
            self.assertLess(events.index("queued"), events.index("sent"))
            self.assertLess(events.index("sent"), events.index("advertised"))

    def test_advertised_announcement_cannot_be_rejected_without_withdraw(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "reject-advertised")
            with patch.object(main, "check_bgp_connector_readiness", return_value=self._readiness_result(connector)), \
                 patch.object(main, "exabgp_write_pipe"):
                advertised = main.apply_mitigation_candidate(conn, candidate, "announce_now", "tester")
            conn.commit()
            conn.close()

            with self.assertRaises(HTTPException) as raised:
                main.reject_bgp_announcement(self._admin_request(), advertised["id"])

            self.assertEqual(raised.exception.status_code, 409)
            self.assertIn("withdraw", str(raised.exception.detail))
            with main.sqlite_connection() as check:
                stored = main.fetch_bgp_announcement(check, advertised["id"])
                events = self._announcement_event_types(check, advertised["id"])
            self.assertEqual(stored["status"], "advertised")
            self.assertNotIn("rejected", events)

    def test_delivered_withdraw_without_operational_connector_is_failed_not_withdrawn(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "withdraw-unavailable")
            with patch.object(main, "check_bgp_connector_readiness", return_value=self._readiness_result(connector)), \
                 patch.object(main, "exabgp_write_pipe"):
                advertised = main.apply_mitigation_candidate(conn, candidate, "announce_now", "tester")
            conn.execute(
                "UPDATE bgp_connectors SET backend_type = 'dry_run', mode = 'dry_run' WHERE id = ?",
                (connector["id"],),
            )
            conn.commit()
            conn.close()

            with patch.object(main, "exabgp_write_pipe") as write_pipe:
                result = main.withdraw_bgp_announcement(self._admin_request(), advertised["id"])

            self.assertEqual(result["status"], "failed_withdraw")
            self.assertIn("nao enviado", result["last_error"])
            self.assertEqual(result["confirmation_level"], "withdraw_failed")
            self.assertIn("withdraw_requested", [event["event_type"] for event in result["events"]])
            write_pipe.assert_not_called()

    def test_reannounce_after_peer_returns_creates_a_linked_new_attempt(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "stage2-retry")
            down = self._readiness_result(connector, peer_state="down", ready=False, reason="peer_bgp_down")
            up = self._readiness_result(connector)
            with patch.object(
                main,
                "check_bgp_connector_readiness",
                side_effect=[down, up],
            ) as readiness, patch.object(main, "exabgp_write_pipe") as write_pipe:
                first = main.apply_mitigation_candidate(conn, candidate, "announce_now", "tester")
                conn.commit()
                second = main.apply_mitigation_candidate(conn, candidate, "announce_now", "tester")
            conn.commit()

            self.assertEqual(first["status"], "peer_down")
            self.assertEqual(second["status"], "advertised")
            self.assertNotEqual(first["id"], second["id"])
            self.assertEqual(second["retry_of_announcement_id"], first["id"])
            self.assertEqual(
                conn.execute("SELECT COUNT(*) AS count FROM bgp_announcements").fetchone()["count"],
                2,
            )
            self.assertIn("peer_down", self._announcement_event_types(conn, first["id"]))
            second_events = self._announcement_event_types(conn, second["id"])
            self.assertLess(second_events.index("queued"), second_events.index("sent"))
            self.assertLess(second_events.index("sent"), second_events.index("advertised"))
            self.assertEqual(readiness.call_count, 2)
            write_pipe.assert_called_once()
            conn.close()

    def test_expire_and_anomaly_withdraw_ignore_pending_approval(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(
                connector,
                profile,
                "stage2-pending-withdraw",
                anomaly_id=404,
            )
            pending = main.apply_mitigation_candidate(conn, candidate, "manual_approval", "tester")
            past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
            conn.execute(
                "UPDATE bgp_announcements SET expires_at = ? WHERE id = ?",
                (past, pending["id"]),
            )
            conn.commit()
            with patch.object(main, "exabgp_write_pipe") as write_pipe:
                stats = main.process_expired_bgp_announcements(conn)
                withdrawn = main.withdraw_anomaly_mitigations(
                    self._admin_request(),
                    404,
                    main.BgpAnomalyMitigationWithdrawPayload(),
                )
            row = conn.execute(
                "SELECT status, withdrawn_at FROM bgp_announcements WHERE id = ?",
                (pending["id"],),
            ).fetchone()

            self.assertEqual(stats["withdrawn"], 0)
            self.assertEqual(withdrawn["count"], 0)
            self.assertEqual(row["status"], "pending_approval")
            self.assertIsNone(row["withdrawn_at"])
            write_pipe.assert_not_called()
            conn.close()

    def test_response_profile_status_connector_validation(self):
        with temporary_main_db():
            conn, _connector, profile = self._connector_and_profile()
            self.assertEqual(profile["connector_name"], "BGP-FIBINET-BORDA")
            self.assertEqual(profile["profile_status"], "valid")
            now = main.utc_now_iso()
            profile_id = conn.execute(
                """
                INSERT INTO bgp_response_profiles (
                    name, enabled, response_type, mitigation_target_mode, approval_mode, action, default_action,
                    target_selector, protocol_selector, created_at, updated_at
                )
                VALUES ('NO_CONNECTOR', 1, 'flowspec', 'fixed_connector', 'manual_approval', 'discard', 'discard',
                        'dst_ip', 'anomaly_protocol', ?, ?)
                """,
                (now, now),
            ).lastrowid
            conn.commit()
            self.assertEqual(main.fetch_bgp_profile(conn, profile_id)["profile_status"], "invalid_connector")

    def test_response_profile_missing_connector_returns_clear_error(self):
        with temporary_main_db():
            conn, _connector, _profile = self._connector_and_profile()
            payload = main.BgpResponseProfilePayload(name="NO_CONNECTOR", response_type="flowspec", mitigation_target_mode="fixed_connector")
            values = main.bgp_profile_payload_to_values(payload)
            with self.assertRaises(HTTPException) as ctx:
                main.validate_profile_connector_for_save(conn, values)
            self.assertIn("connector_id obrigatorio", str(ctx.exception.detail))

    def test_response_profile_invalid_connector_returns_clear_error(self):
        with temporary_main_db():
            conn, _connector, _profile = self._connector_and_profile()
            payload = main.BgpResponseProfilePayload(name="BAD_CONNECTOR", response_type="flowspec", connector_id=999)
            values = main.bgp_profile_payload_to_values(payload)
            with self.assertRaises(HTTPException) as ctx:
                main.validate_profile_connector_for_save(conn, values)
            self.assertIn("connector_id invalido", str(ctx.exception.detail))

    def test_response_profile_alias_payload_normalizes_to_real_columns(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            payload = main.BgpResponseProfilePayload(
                name="FLOWSPEC_BLOCK_DST_DNS",
                type="flowspec",
                active=True,
                connector_id=connector["id"],
                action="discard",
                default_action="discard",
                target_selector="dst_ip",
                protocol_selector="udp",
                dst_port_selector="fixed",
                dst_port_value="53",
                duration_default=1800,
                max_duration_seconds=3600,
            )
            values = main.bgp_profile_payload_to_values(payload)
            main.validate_profile_connector_for_save(conn, values)
            self.assertEqual(values["response_type"], "flowspec")
            self.assertEqual(values["enabled"], 1)
            self.assertEqual(values["connector_id"], connector["id"])
            self.assertEqual(values["action"], "discard")
            self.assertEqual(values["dst_port_selector"], "fixed")
            self.assertEqual(values["dst_port_value"], "53")
            self.assertEqual(values["default_duration_seconds"], 1800)
            self.assertEqual(values["max_duration_seconds"], 3600)

    def test_response_profile_protected_prefix_validation_applies_to_anomaly_flow(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            now = main.utc_now_iso()
            zone_id = conn.execute(
                "INSERT INTO ip_zones (name, active, created_at, updated_at) VALUES ('Clientes', 1, ?, ?)",
                (now, now),
            ).lastrowid
            conn.execute(
                "INSERT INTO ip_zone_prefixes (zone_id, cidr, active, created_at, updated_at) VALUES (?, '198.51.100.0/24', 1, ?, ?)",
                (zone_id, now, now),
            )
            conn.execute(
                """
                INSERT INTO bgp_protected_prefixes (
                    name, cidr, enabled, block_rtbh, block_flowspec, block_diversion, created_at, updated_at
                ) VALUES (?, ?, 1, 1, 1, 1, ?, ?)
                """,
                ("DNS-PROTECTED", "8.8.8.8/32", now, now),
            )
            conn.execute(
                """
                INSERT INTO bgp_protected_prefixes (
                    name, cidr, enabled, block_rtbh, block_flowspec, block_diversion, created_at, updated_at
                ) VALUES (?, ?, 1, 1, 0, 1, ?, ?)
                """,
                ("DNS-BLOCKED-FLOWSPEC", "8.8.4.4/32", now, now),
            )
            conn.commit()

            def validate_target(
                target: str,
                require_protected: bool,
                *,
                direction: str = "outbound",
                source_ip: str = "198.51.100.10",
            ):
                profile = {
                    "id": 1,
                    "name": "RESPONSE_DNS-UPLOAD",
                    "enabled": True,
                    "response_type": "flowspec",
                    "connector_id": 1,
                    "connector_name": "TEST-CONNECTOR",
                    "connector_enabled": True,
                    "connector_active": True,
                    "target_selector": "dst_ip",
                    "protocol_selector": "udp",
                    "dst_port_selector": "fixed",
                    "dst_port_value": "53",
                    "action": "discard",
                    "default_action": "discard",
                    "require_protected_prefix": require_protected,
                }
                anomaly = {
                    "direction": direction,
                    "top_src_ip": source_ip,
                    "top_dst_ip": target,
                    "protocol": "udp",
                    "top_dst_port": 53,
                }
                flow_context = {
                    "evidence_status": "sufficient",
                    "dominant_dst_ip": target,
                    "dominant_dst_port": 53,
                    "dominant_protocol": "udp",
                }
                candidate = main.response_profile_candidate_for_anomaly(profile, anomaly, flow_context)
                candidate["require_protected_prefix"] = require_protected
                return main.validate_response_profile_for_anomaly(profile, anomaly, flow_context, candidate, {"id": 1, "enabled": True})

            protected_result = validate_target("8.8.8.8", True)
            self.assertEqual(protected_result["validation_status"], "valid")
            self.assertEqual(protected_result["errors"], [])
            self.assertFalse(protected_result["apply_enabled"])
            self.assertFalse(protected_result["allow_auto"])

            outside_result = validate_target("203.0.113.10", True)
            self.assertEqual(outside_result["validation_status"], "valid")
            self.assertEqual(outside_result["errors"], [])

            unauthorized_origin = validate_target("203.0.113.10", True, source_ip="192.0.2.10")
            self.assertEqual(unauthorized_origin["validation_status"], "origin_not_in_authorized_zone_or_prefix")
            self.assertIn("origin_not_in_authorized_zone_or_prefix", unauthorized_origin["errors"])

            disabled_requirement_result = validate_target("203.0.113.10", False)
            self.assertEqual(disabled_requirement_result["validation_status"], "valid")
            self.assertEqual(disabled_requirement_result["errors"], [])

            blocked_action_result = validate_target("8.8.4.4", True, direction="inbound")
            self.assertEqual(blocked_action_result["validation_status"], "protected_prefix_action_not_allowed")
            self.assertIn("protected_prefix_action_not_allowed", blocked_action_result["errors"])

    def test_negative_anomaly_draft_accepts_minimal_payload_without_candidates(self):
        class _RequestStub:
            def __init__(self, payload):
                self._payload = payload
                self.method = "POST"
                self.state = types.SimpleNamespace(user={"role": "admin", "username": "tester"})

            async def json(self):
                return self._payload

        class _JSONResponseStub:
            def __init__(self, content=None, status_code=200, *args, **kwargs):
                self.content = content if isinstance(content, dict) else kwargs.get("content", None)
                self.status_code = status_code
                self.body = json.dumps(self.content).encode("utf-8") if self.content is not None else b""

            def __getitem__(self, key):
                return self.content[key]

        payload = {
            "anomaly": {
                "id": -123,
                "target_ip": "203.0.113.10",
                "direction": "outbound",
                "decoder": "IP",
                "vector_name": "DNS_INTERNAL_IP_TO_DST_HIGH_PPS",
                "metric": "packets_s",
                "peak_value": 1000,
                "severity": "high",
            }
        }
        with patch.object(main, "ai_effective_config", return_value={"enabled": True, "selected_model": "", "timeout_seconds": 10, "max_context_chars": 1000, "max_top_flows": 10, "keep_alive": "30m"}):
            with patch.object(main, "JSONResponse", _JSONResponseStub):
                response = asyncio.run(main.draft_anomaly_ai_analysis(_RequestStub(payload), -123))
        self.assertTrue(response["draft"])
        self.assertFalse(response["persisted"])
        self.assertIsInstance(response["response"], dict)
        self.assertTrue(response["error_message"])

        empty_payload = {}
        with patch.object(main, "ai_effective_config", return_value={"enabled": True, "selected_model": "", "timeout_seconds": 10, "max_context_chars": 1000, "max_top_flows": 10, "keep_alive": "30m"}):
            with patch.object(main, "JSONResponse", _JSONResponseStub):
                response = asyncio.run(main.draft_anomaly_ai_analysis(_RequestStub(empty_payload), -123))
        self.assertEqual(response.status_code, 422)
        self.assertIn('"error_type": "missing_draft_payload"', response.body.decode("utf-8"))
        self.assertIn('"missing_fields": ["anomaly"]', response.body.decode("utf-8"))

    def test_detection_rule_saves_response_profile_ids(self):
        with temporary_main_db():
            conn, _connector, profile = self._connector_and_profile()
            payload = main.DetectionRulePayload(
                vector="UDP_TEST",
                warning_value=100,
                critical_value=200,
                warning_response_profile_id=profile["id"],
                critical_response_profile_id=profile["id"],
                fallback_response_profile_id=profile["id"],
                mitigation_mode="response_profile",
            )
            data = main.normalize_detection_rule_payload(payload)
            main.validate_detection_rule_profile_refs(conn, data)
            self.assertEqual(data["warning_response_profile_id"], profile["id"])
            self.assertEqual(data["critical_response_profile_id"], profile["id"])
            self.assertEqual(data["fallback_response_profile_id"], profile["id"])
            self.assertEqual(data["mitigation_mode"], "response_profile")
            self.assertEqual(data["mitigation_enabled"], 1)

    def test_detection_rule_serializer_preserves_legacy_response_profile_ids(self):
        item = main.detection_rule_row_to_dict({
            "id": 1,
            "template_id": 1,
            "vector": "UDP_TEST",
            "domain": "internal_ip",
            "direction": "transmits",
            "metric": "packets_s",
            "comparison": "over",
            "warning_response_profile_id": 16,
            "critical_response_profile_id": 16,
            "fallback_response_profile_id": 16,
            "mitigation_mode": "response_profile",
            "mitigation_enabled": 0,
            "created_at": "2026-07-19T00:00:00Z",
            "updated_at": "2026-07-19T00:00:00Z",
        })

        self.assertEqual(item["warning_response_profile_id"], 16)
        self.assertEqual(item["critical_response_profile_id"], 16)
        self.assertEqual(item["fallback_response_profile_id"], 16)
        self.assertEqual(item["mitigation_mode"], "response_profile")
        self.assertTrue(item["mitigation_enabled"])
        self.assertEqual(item["response"], "RESPONSE_PROFILE")

    def test_automatic_runner_uses_automatic_for_auto_profiles(self):
        source = Path(ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        start = source.find("def process_anomaly_mitigation")
        end = source.find("def anomaly_detection_enabled")
        worker = source[start:end]
        self.assertIn("automatic_mitigation_execution_mode", worker)
        self.assertIn("application_mode, \"worker\"", worker)
        self.assertIn("run_automatic_mitigation_ai_analysis", worker)

    def test_dns_outbound_related_flow_recommends_destination_candidate_first(self):
        with temporary_main_db():
            event = {
                "id": 10,
                "attack_vector_name": "DNS_QUERY_OUTBOUND_CLIENT",
                "direction": "sends",
                "decoder": "DNS",
                "protocol": "udp",
                "target_ip": "168.232.196.123",
                "target_cidr": "168.232.196.123/32",
                "target_role": "src_ip",
                "target_port": 53,
                "estimated_packets": 10000,
                "estimated_bytes": 1000000,
            }
            flows = [{
                "src_ip": "168.232.196.123",
                "src_port": 35732,
                "dst_ip": "75.131.245.200",
                "dst_port": 53,
                "proto": 17,
                "packets": 8000,
                "bytes": 900000,
            }]
            candidates = main.build_mitigation_candidates_from_anomaly({"event": event, "flows": flows})
            self.assertGreaterEqual(len(candidates), 2)
            self.assertEqual(candidates[0]["candidate_role"], "recommended")
            self.assertEqual(candidates[0]["dst_prefix"], "75.131.245.200/32")
            self.assertEqual(candidates[0]["src_prefix"], "")
            self.assertEqual(candidates[0]["protocol"], "udp")
            self.assertEqual(candidates[0]["dst_port"], "53")
            self.assertIn("destination 75.131.245.200/32; protocol =udp; destination-port =53", main.render_exabgp_flowspec_command("announce", candidates[0]))
            self.assertNotEqual(candidates[0].get("candidate_role"), "not_recommended")

    def test_detection_rule_mitigation_config_loads_dns_template_rule_profile(self):
        with temporary_main_db():
            conn, _connector, profile = self._dns_multi_target_context()
            try:
                config = main.detection_rule_mitigation_config(conn, "DNS_INTERNAL_IP_TO_DST_HIGH_PPS")
            finally:
                conn.close()
            self.assertIsNotNone(config)
            self.assertEqual(config["detection_key"], "DNS_INTERNAL_IP_TO_DST_HIGH_PPS")
            self.assertEqual(config["response_profile_id"], profile["id"])
            self.assertEqual(config["mitigation_mode"], "response_profile")
            self.assertTrue(config["mitigation_enabled"])

    def test_ai_analysis_accepts_anomaly_events_id(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context()
            event_id = self._insert_dns_query_anomaly_event(conn)
            conn.close()

            get_response = main.get_anomaly_ai_analysis(self._admin_request(), event_id)
            self.assertEqual(get_response["anomaly_id"], event_id)
            self.assertFalse(get_response["available"])

            config = {
                "enabled": True,
                "provider": "ollama",
                "base_url": "http://ollama.invalid",
                "selected_model": "test",
                "selected_profile": "economical",
                "timeout_seconds": 1,
                "max_context_chars": 10000,
                "max_top_flows": 10,
                "num_predict": 64,
                "keep_alive": "30m",
                "allow_auto": False,
                "require_policy_validation": True,
            }
            with patch.object(main, "ai_effective_config", return_value=config), \
                 patch.object(main, "call_ollama_mitigation_ai", side_effect=RuntimeError("offline")), \
                 patch.object(main, "persist_ai_pending_bgp_approval", return_value=None):
                post_response = main.create_anomaly_ai_analysis(self._admin_request(), event_id)
            self.assertEqual(post_response["anomaly_id"], event_id)
            self.assertTrue(post_response["error_message"])

    def test_legacy_dns_event_does_not_create_bgp_or_pending_approval(self):
        with temporary_main_db():
            conn, connector, profile = self._dns_multi_target_context(add_whitelist=False)
            event_id = self._insert_legacy_dns_anomaly_event(conn)
            context = main.fetch_anomaly_mitigation_context(conn, event_id)
            candidate = {
                "candidate_index": 0,
                "connector_id": connector["id"],
                "response_profile_id": profile["id"],
                "response_type": "flowspec",
                "action": "discard",
                "dst_prefix": "103.100.169.200/32",
                "protocol": "udp",
                "dst_port": "53",
                "duration_seconds": 600,
                "manual_approval_required": True,
                "allow_auto": False,
            }
            pending = main.persist_ai_pending_bgp_approval(
                conn,
                event_id,
                {"anomaly": context["event"], "candidates": [candidate]},
                {"recommended_candidate_index": 0, "manual_approval_required": True, "allow_auto": False},
                created_by="test-ai",
            )
            conn.commit()
            conn.close()

            self.assertIsNone(pending)
            evaluated = main.evaluated_mitigation_candidates(event_id)
            self.assertTrue(evaluated["legacy_dns_mitigation_disabled"])
            self.assertEqual(evaluated["candidates"], [])
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                stats = main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(calls, [])
            self.assertEqual(stats["advertised"], 0)
            self.assertEqual(stats["pending_approval"], 0)
            with main.sqlite_connection() as check:
                count = check.execute("SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = ?", (event_id,)).fetchone()["total"]
            self.assertEqual(count, 0)

    def test_legacy_dns_ui_hides_mitigation_action_and_shows_warning(self):
        source = Path(ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Detector legacy: mitigação automática desativada. Use templates de detecção.", source)
        self.assertIn("function isLegacyDnsAnomaly", source)
        self.assertIn("${legacyDns ? '' : `<button", source)

    def test_official_dns_template_event_persists_top_flow_and_auto_applies(self):
        with temporary_main_db():
            conn, connector, profile = self._dns_multi_target_context(add_whitelist=False)
            official_rows = conn.execute(
                """
                SELECT r.vector, r.critical_response_profile_id, r.mitigation_mode, r.mitigation_enabled,
                       r.dst_port, p.name AS profile_name, p.approval_mode, p.mitigation_target_mode,
                       p.enable_multi_target_dns
                FROM detection_template_rules r
                JOIN detection_templates t ON t.id = r.template_id
                LEFT JOIN bgp_response_profiles p ON p.id = r.critical_response_profile_id
                WHERE t.name = 'CLIENTES-PUBLICOS-DEFAULT'
                  AND upper(r.vector) IN ('DNS_INTERNAL_IP_TO_DST_HIGH_PPS', 'DNS_QUERY_OUTBOUND_CLIENT', 'DNS_ABUSE_OUTBOUND')
                """
            ).fetchall()
            self.assertEqual({item["vector"].upper() for item in official_rows}, {"DNS_INTERNAL_IP_TO_DST_HIGH_PPS", "DNS_QUERY_OUTBOUND_CLIENT", "DNS_ABUSE_OUTBOUND"})
            for item in official_rows:
                self.assertEqual(item["critical_response_profile_id"], profile["id"])
                self.assertEqual(item["profile_name"], "FLOWSPEC_AUTO_BLOCK_DST_DNS")
                self.assertEqual(item["approval_mode"], "auto")
                self.assertEqual(item["mitigation_target_mode"], "sensor_origin")
                self.assertEqual(item["enable_multi_target_dns"], 1)
                self.assertEqual(item["mitigation_mode"], "response_profile")
                self.assertEqual(item["mitigation_enabled"], 1)
                self.assertEqual(item["dst_port"], "53")
            row = conn.execute(
                """
                SELECT r.*, t.name AS template_name, t.active AS template_active
                FROM detection_template_rules r
                JOIN detection_templates t ON t.id = r.template_id
                WHERE t.name = 'CLIENTES-PUBLICOS-DEFAULT'
                  AND r.vector = 'DNS_QUERY_OUTBOUND_CLIENT'
                ORDER BY r.id
                LIMIT 1
                """
            ).fetchone()
            self.assertIsNotNone(row)
            now = main.utc_now_iso()
            zone_id = conn.execute(
                "INSERT INTO ip_zones (name, detection_template_id, active, created_at, updated_at) VALUES ('Clientes', ?, 1, ?, ?)",
                (int(row["template_id"]), now, now),
            ).lastrowid
            prefix_id = conn.execute(
                "INSERT INTO ip_zone_prefixes (zone_id, cidr, name, active, created_at, updated_at) VALUES (?, '45.5.248.0/24', 'Clientes', 1, ?, ?)",
                (zone_id, now, now),
            ).lastrowid
            candidate = {
                "matched": True,
                "zone_id": int(zone_id),
                "zone_name": "Clientes",
                "template_id": int(row["template_id"]),
                "template_name": "CLIENTES-PUBLICOS-DEFAULT",
                "sensor_id": 9,
                "rule_id": int(row["id"]),
                "rule_name": "DNS_QUERY_OUTBOUND_CLIENT",
                "display_name": "DNS outbound por cliente",
                "rule_config": {"dst_port": "53", "group_by": "src_ip,dst_ip,dst_port,proto"},
                "prefix_id": int(prefix_id),
                "prefix_cidr": "45.5.248.0/24",
                "domain": "internal_ip",
                "direction": "transmits",
                "vector": "DNS_QUERY_OUTBOUND_CLIENT",
                "severity": "critical",
                "src_ip": "45.5.248.205",
                "dst_ip": "103.100.169.200",
                "internal_ip": "45.5.248.205",
                "target_ip": "45.5.248.205",
                "target_cidr": "45.5.248.205/32",
                "target_role": "src_ip",
                "scope_type": "internal_ip_32",
                "protocol": "udp",
                "target_port": 53,
                "top_src_ip": "45.5.248.205",
                "top_dst_ip": "103.100.169.200",
                "top_src_port": 62129,
                "top_dst_port": 53,
                "top_packets": 13000,
                "top_bytes": 1000000,
                "packets": 13000,
                "bytes": 1000000,
                "packets_s": 13000,
                "bits_s": 8000000,
                "flows": 1,
                "unique_dst_ips": 1,
                "unique_dst_ports": 1,
                "first_seen": now,
                "last_seen": now,
                "threshold_warning": 5000,
                "threshold_critical": 15000,
                "metric": "packets_s",
                "metric_value": 13000,
                "warning_response_profile_id": profile["id"],
                "critical_response_profile_id": profile["id"],
                "fallback_response_profile_id": profile["id"],
                "mitigation_mode": "response_profile",
                "mitigation_enabled": True,
            }
            with patch.object(main, "query_detection_rule_candidates", return_value=[candidate]):
                result = main.evaluate_detection_template_rule(conn, dict(row), datetime.now(timezone.utc))
            conn.commit()
            self.assertTrue(result["anomaly_created"])
            event_id = int(result["anomaly_id"])
            event = conn.execute(
                """
                SELECT detection_engine, detection_template_rule_id, response_profile_id, sensor_id,
                       top_src_ip, top_dst_ip, top_src_port, top_dst_port, top_packets, top_bytes,
                       protocol, target_port, mitigation_basis
                FROM anomaly_events
                WHERE id = ?
                """,
                (event_id,),
            ).fetchone()
            self.assertEqual(event["detection_engine"], "detection_template")
            self.assertEqual(event["detection_template_rule_id"], row["id"])
            self.assertEqual(event["response_profile_id"], profile["id"])
            self.assertEqual(event["sensor_id"], 9)
            self.assertEqual(event["top_src_ip"], "45.5.248.205")
            self.assertEqual(event["top_dst_ip"], "103.100.169.200")
            self.assertEqual(event["top_src_port"], 62129)
            self.assertEqual(event["top_dst_port"], 53)
            self.assertEqual(event["top_packets"], 13000)
            self.assertEqual(event["top_bytes"], 1000000)
            self.assertEqual(event["protocol"], "udp")
            self.assertEqual(event["target_port"], 53)
            self.assertEqual(event["mitigation_basis"], "dns_outbound_destination")
            conn.close()

            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append((_connector["id"], command))
            try:
                stats = main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(stats["advertised"], 1)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], connector["id"])
            self.assertIn("destination 103.100.169.200/32", calls[0][1])
            self.assertIn("protocol =udp", calls[0][1])
            self.assertIn("destination-port =53", calls[0][1])
            self.assertNotIn("source ", calls[0][1])
            self.assertNotIn("source-port", calls[0][1])
            with main.sqlite_connection() as check:
                announcement = check.execute(
                    """
                    SELECT status, response_profile_id, sensor_id, dst_ip, protocol, dst_port, pipe_path,
                           announce_command, withdraw_command
                    FROM bgp_announcements
                    WHERE anomaly_id = ?
                    """,
                    (event_id,),
                ).fetchone()
            self.assertEqual(announcement["status"], "advertised")
            self.assertEqual(announcement["response_profile_id"], profile["id"])
            self.assertEqual(announcement["sensor_id"], 9)
            self.assertEqual(announcement["dst_ip"], "103.100.169.200")
            self.assertEqual(announcement["protocol"], "udp")
            self.assertEqual(announcement["dst_port"], "53")
            self.assertEqual(announcement["pipe_path"], "/run/exabgp/exabgp.in")
            self.assertIn("announce flow route", announcement["announce_command"])
            self.assertIn("withdraw flow route", announcement["withdraw_command"])

    def test_dns_query_outbound_auto_policy_uses_source_protected_not_destination(self):
        with temporary_main_db():
            conn, _connector, profile = self._dns_multi_target_context(add_whitelist=False)
            conn.close()
            event = {
                "id": 140,
                "attack_vector_name": "DNS_QUERY_OUTBOUND_CLIENT",
                "classification": "dns_abuse_outbound",
                "direction": "transmits",
                "decoder": "DNS",
                "protocol": "udp",
                "target_ip": "45.5.248.205",
                "target_cidr": "45.5.248.205/32",
                "target_role": "src_ip",
                "target_port": 53,
                "sensor_id": 9,
                "severity": "critical",
            }
            flows = [{
                "src_ip": "45.5.248.205",
                "src_port": 62129,
                "dst_ip": "103.100.169.200",
                "dst_port": 53,
                "proto": 17,
                "packets": 13000,
                "bytes": 1000000,
                "packets_s": 13000,
                "bits_s": 8000000,
            }]
            candidates = main.build_mitigation_candidates_from_anomaly({"event": event, "flows": flows})
            recommended = candidates[0]
            policy = main.policy_for_candidate(recommended)
            command = main.render_exabgp_flowspec_command("announce", recommended)
            self.assertEqual(recommended["response_profile_id"], profile["id"])
            self.assertEqual(recommended["response_profile_name"], "FLOWSPEC_AUTO_BLOCK_DST_DNS")
            self.assertEqual(recommended["mitigation_mode"], "automatic")
            self.assertEqual(policy["decision"], "allow_auto")
            self.assertFalse(recommended.get("src_prefix"))
            self.assertFalse(recommended.get("src_port"))
            self.assertIn("destination 103.100.169.200/32; protocol =udp; destination-port =53", command)
            self.assertNotIn("source ", command)
            self.assertNotIn("source-port", command)

    def test_dns_query_outbound_requires_source_protected_and_respects_destination_whitelist(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context()
            conn.close()
            protected_event, protected_flows = self._dns_event_and_flows()
            protected_event["attack_vector_name"] = "DNS_QUERY_OUTBOUND_CLIENT"
            protected_flows = [protected_flows[10]]
            protected_flows[0]["dst_ip"] = "103.192.159.11"
            whitelist_candidate = main.build_mitigation_candidates_from_anomaly({"event": protected_event, "flows": protected_flows})[0]
            whitelist_policy = main.policy_for_candidate(whitelist_candidate)
            self.assertNotEqual(whitelist_policy["decision"], "allow_auto")
            self.assertIn("whitelist", " ".join(whitelist_policy["warnings"] + whitelist_policy["reasons"]).lower())

        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context(add_whitelist=False)
            conn.close()
            event, flows = self._dns_event_and_flows()
            event["attack_vector_name"] = "DNS_QUERY_OUTBOUND_CLIENT"
            event["target_ip"] = "198.51.100.10"
            event["target_cidr"] = "198.51.100.10/32"
            flows = [flows[0]]
            flows[0]["src_ip"] = "198.51.100.10"
            candidate = main.build_mitigation_candidates_from_anomaly({"event": event, "flows": flows})[0]
            policy = main.policy_for_candidate(candidate)
            self.assertEqual(policy["decision"], "deny")
            self.assertIn("Origem interna nao confirmada em zona ou prefixo autorizado.", policy["reasons"])

    def test_dns_query_outbound_evaluation_reports_auto_without_pipe_write(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context(add_whitelist=False)
            event_id = self._insert_dns_query_anomaly_event(conn)
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                evaluated = main.evaluated_mitigation_candidates(event_id)
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(calls, [])
            self.assertTrue(evaluated["candidates"][0]["allow_auto"])
            self.assertFalse(evaluated["candidates"][0]["manual_approval_required"])
            self.assertEqual(evaluated["candidates"][0]["policy_decision"]["decision"], "allow_auto")
            self.assertTrue(evaluated["candidates"][0]["evaluation_only"])
            self.assertFalse(evaluated["candidates"][0]["dry_run"])
            self.assertIn("nenhum comando foi enviado", evaluated["candidates"][0]["dry_run_message"].lower())
            self.assertEqual(evaluated["candidates"][0]["connector_name"], "BGP-SENSOR-ORIGIN")
            self.assertEqual(evaluated["candidates"][0]["mitigation_target_mode"], "sensor_origin")
            self.assertEqual(evaluated["candidates"][0]["pipe_path"], "/run/exabgp/exabgp.in")

    def test_dns_query_outbound_worker_auto_applies_to_sensor_origin_connector(self):
        with temporary_main_db():
            conn, connector, profile = self._dns_multi_target_context(add_whitelist=False)
            self._insert_dns_query_anomaly_event(conn)
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append((_connector["id"], command))
            try:
                with self.assertLogs("gmj-flow", level="INFO") as logs:
                    stats = main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(stats["advertised"], 1)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], connector["id"])
            self.assertNotIn("source ", calls[0][1])
            self.assertNotIn("source-port", calls[0][1])
            with main.sqlite_connection() as check:
                row = check.execute(
                    """
                    SELECT status, connector_id, response_profile_id, sensor_id, dst_ip, protocol, dst_port,
                           policy_decision, pipe_path, announce_command, withdraw_command
                    FROM bgp_announcements
                    WHERE anomaly_id = 140
                    """
                ).fetchone()
            self.assertEqual(row["status"], "advertised")
            self.assertEqual(row["connector_id"], connector["id"])
            self.assertEqual(row["response_profile_id"], profile["id"])
            self.assertEqual(row["sensor_id"], 9)
            self.assertEqual(row["dst_ip"], "103.100.169.200")
            self.assertEqual(row["protocol"], "udp")
            self.assertEqual(row["dst_port"], "53")
            self.assertEqual(row["policy_decision"], "allow_auto")
            self.assertEqual(row["pipe_path"], "/run/exabgp/exabgp.in")
            self.assertIn("announce flow route", row["announce_command"])
            self.assertIn("withdraw flow route", row["withdraw_command"])
            log_text = "\n".join(logs.output)
            self.assertIn("dns_auto_mitigation_applied", log_text)
            self.assertIn("anomaly_id=140", log_text)
            self.assertIn("connector_id=", log_text)
            self.assertIn("pipe_path=/run/exabgp/exabgp.in", log_text)
            self.assertIn("top_src_ip=45.5.248.205", log_text)
            self.assertIn("top_dst_ip=103.100.169.200", log_text)
            self.assertIn("destination 103.100.169.200/32", log_text)

    def test_dns_query_outbound_ai_veto_or_error_keeps_manual_proposal_without_pipe_write(self):
        decisions = (
            ("success", False, "IA nao recomenda a automacao.", ""),
            ("timeout", False, "Timeout do provider.", "timed out"),
            ("invalid_json", False, "JSON invalido.", "invalid json"),
        )
        for status, apply_mitigation, reason, error_message in decisions:
            with self.subTest(status=status), temporary_main_db():
                conn, connector, _profile = self._dns_multi_target_context(add_whitelist=False)
                self._insert_dns_query_anomaly_event(conn)
                conn.close()
                self.automatic_ai_gate.return_value = (
                    {
                        "id": 91,
                        "apply_mitigation": apply_mitigation,
                        "reason": reason,
                        "status": status,
                        "error_message": error_message,
                    },
                    {"allow_auto": True},
                )
                calls = []
                with patch.object(main, "exabgp_write_pipe", side_effect=lambda _connector, command: calls.append(command)):
                    stats = main.process_anomaly_mitigation()
                self.assertEqual(calls, [])
                self.assertEqual(stats["advertised"], 0)
                self.assertGreaterEqual(stats["pending_approval"], 1)
                with main.sqlite_connection() as check:
                    row = check.execute(
                        "SELECT status, dst_prefix, protocol, dst_port, announce_command FROM bgp_announcements WHERE anomaly_id = 140 ORDER BY id LIMIT 1"
                    ).fetchone()
                self.assertEqual(row["status"], "pending_approval")
                self.assertEqual(row["dst_prefix"], "103.100.169.200/32")
                self.assertEqual(row["protocol"], "udp")
                self.assertEqual(row["dst_port"], "53")
                self.assertIn("destination 103.100.169.200/32; protocol =udp; destination-port =53", row["announce_command"])

    def test_dns_query_outbound_sensor_null_uses_single_active_flowspec_connector(self):
        with temporary_main_db():
            conn, connector, _profile = self._dns_multi_target_context(add_whitelist=False)
            event_id = self._insert_dns_query_anomaly_event(conn)
            conn.execute("UPDATE anomaly_events SET sensor_id = NULL WHERE id = ?", (event_id,))
            conn.commit()
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append((_connector["id"], command))
            try:
                stats = main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(stats["advertised"], 1)
            self.assertEqual(calls[0][0], connector["id"])
            with main.sqlite_connection() as check:
                row = check.execute("SELECT connector_id, sensor_id, status FROM bgp_announcements WHERE anomaly_id = ?", (event_id,)).fetchone()
            self.assertEqual(row["connector_id"], connector["id"])
            self.assertIsNone(row["sensor_id"])
            self.assertEqual(row["status"], "advertised")

    def test_dns_query_outbound_sensor_null_uses_selected_connector_ids(self):
        with temporary_main_db():
            conn, connector, profile = self._dns_multi_target_context(add_whitelist=False)
            now = main.utc_now_iso()
            conn.execute(
                """
                INSERT INTO bgp_connectors (
                    name, role, backend_type, mode, max_active_rules, max_duration_seconds,
                    enabled, is_active, exabgp_pipe_in, created_at, updated_at
                )
                VALUES ('BGP-OTHER', 'flowspec_mitigation', 'exabgp', 'manual_approval', 50, 1800,
                        1, 1, '/run/exabgp/other.in', ?, ?)
                """,
                (now, now),
            )
            conn.execute(
                "UPDATE bgp_response_profiles SET selected_connector_ids = ?, connector_id = NULL WHERE id = ?",
                (json.dumps([connector["id"]]), profile["id"]),
            )
            event_id = self._insert_dns_query_anomaly_event(conn)
            conn.execute("UPDATE anomaly_events SET sensor_id = NULL WHERE id = ?", (event_id,))
            conn.commit()
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append((_connector["id"], command))
            try:
                stats = main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(stats["advertised"], 1)
            self.assertEqual([call[0] for call in calls], [connector["id"]])

    def test_sensor_null_resolves_fibinet_and_gm_connectors_from_origin_prefix(self):
        with temporary_main_db():
            conn, fibinet, profile = self._dns_multi_target_context(add_whitelist=False)
            gm_id = self._insert_flowspec_connector(conn, "BGP-GM-BORDA", "/run/exabgp/gm.in")
            fib_zone = self._insert_zone_connector_mapping(conn, "Clientes FIBINET", "179.189.83.0/24", fibinet["id"])
            gm_zone = self._insert_zone_connector_mapping(conn, "Clientes GM", "45.5.249.0/24", gm_id)
            conn.commit()

            def candidate(source_ip):
                return {
                    "sensor_id": None,
                    "raw_payload": {
                        "anomaly": {
                            "top_src_ip": source_ip,
                            "target_ip": source_ip,
                            "target_role": "src_ip",
                            "zone_name": "nome-nao-usado",
                        }
                    },
                }

            fib_candidate = candidate("179.189.83.212")
            gm_candidate = candidate("45.5.249.10")
            fib_resolved = main.resolve_mitigation_target_connectors(conn, fib_candidate, profile)
            gm_resolved = main.resolve_mitigation_target_connectors(conn, gm_candidate, profile)
            target_fallback_candidate = {
                "sensor_id": None,
                "raw_payload": {"anomaly": {"top_src_ip": "", "target_ip": "179.189.83.212", "target_role": "src_ip"}},
            }
            target_fallback_resolved = main.resolve_mitigation_target_connectors(conn, target_fallback_candidate, profile)
            self.assertEqual([item["id"] for item in fib_resolved], [fibinet["id"]])
            self.assertEqual([item["id"] for item in gm_resolved], [gm_id])
            self.assertEqual([item["id"] for item in target_fallback_resolved], [fibinet["id"]])
            self.assertEqual(fib_candidate["connector_resolution_zone_id"], fib_zone)
            self.assertEqual(gm_candidate["connector_resolution_zone_id"], gm_zone)
            self.assertEqual(fib_candidate["connector_resolution_method"], "zone_prefix")

    def test_udp_outbound_uses_top_src_zone_and_allows_external_destination_host(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            connector_id = self._insert_flowspec_connector(conn, "BGP-ZONE", "/tmp/test-zone.in")
            zone_id = self._insert_zone_connector_mapping(
                conn,
                "Clientes",
                "45.5.248.0/24",
                connector_id,
            )
            event_id = self._insert_udp_many_anomaly_event(conn, zone_id=zone_id)
            conn.close()

            evaluated = main.evaluated_mitigation_candidates(event_id)
            candidate = evaluated["candidates"][0]

            self.assertEqual(candidate["top_src_ip"], "45.5.248.205")
            self.assertEqual(candidate["dst_prefix"], "51.222.110.42/32")
            self.assertEqual(candidate["selected_connector_id"], connector_id)
            self.assertEqual(candidate["connector_resolution_method"], "zone_id")
            self.assertTrue(candidate["policy_decision"]["outbound_destination"])
            self.assertTrue(candidate["policy_decision"]["origin_authorization"]["authorized"])
            self.assertNotIn("Destino nao confirmado dentro de prefixo protegido.", candidate["policy_decision"]["reasons"])
            self.assertEqual(candidate["validation_errors"], [])
            self.assertTrue(candidate["actionable"])
            self.assertTrue(candidate["can_submit_approval"])
            self.assertTrue(candidate["can_announce_now"])
            self.exabgp_pipe_guard.assert_not_called()

    def test_persisted_zone_has_priority_over_sensor_connector(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            zone_connector_id = self._insert_flowspec_connector(conn, "BGP-ZONE", "/tmp/test-zone.in")
            sensor_connector_id = self._insert_flowspec_connector(conn, "BGP-SENSOR", "/tmp/test-sensor.in")
            now = main.utc_now_iso()
            conn.execute(
                "INSERT INTO sensors (id, name, exporter_ip, created_at, updated_at) VALUES (9, 'sensor-9', '192.0.2.9', ?, ?)",
                (now, now),
            )
            conn.execute("UPDATE bgp_connectors SET sensor_id = 9 WHERE id = ?", (sensor_connector_id,))
            zone_id = self._insert_zone_connector_mapping(
                conn,
                "Clientes",
                "45.5.248.0/24",
                zone_connector_id,
            )
            event_id = self._insert_udp_many_anomaly_event(conn, event_id=1768, zone_id=zone_id, sensor_id=9)
            conn.close()

            candidate = main.evaluated_mitigation_candidates(event_id)["candidates"][0]

            self.assertEqual(candidate["selected_connector_id"], zone_connector_id)
            self.assertNotEqual(candidate["selected_connector_id"], sensor_connector_id)
            self.assertEqual(candidate["connector_resolution_method"], "zone_id")
            self.exabgp_pipe_guard.assert_not_called()

    def test_inbound_persisted_zone_does_not_validate_the_external_top_source_as_origin(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            connector_id = self._insert_flowspec_connector(conn, "BGP-INBOUND-ZONE", "/tmp/test-inbound.in")
            zone_id = self._insert_zone_connector_mapping(conn, "Cliente inbound", "45.5.248.0/24", connector_id)
            conn.commit()
            candidate = {
                "zone_id": zone_id,
                "top_src_ip": "198.51.100.200",
                "top_dst_ip": "45.5.248.205",
                "dst_prefix": "45.5.248.205/32",
                "target_role": "dst_ip",
                "direction": "receives",
                "scope_type": "internal_ip_32",
                "raw_payload": {
                    "anomaly": {
                        "zone_id": zone_id,
                        "top_src_ip": "198.51.100.200",
                        "top_dst_ip": "45.5.248.205",
                        "target_ip": "45.5.248.205",
                        "target_role": "dst_ip",
                        "direction": "receives",
                    }
                },
            }

            resolved = main.resolve_mitigation_target_connectors(conn, candidate, {})
            conn.close()

            self.assertEqual([item["id"] for item in resolved], [connector_id])
            self.assertEqual(candidate["connector_resolution_method"], "zone_id")
            self.assertNotIn("connector_resolution_error", candidate)
            self.exabgp_pipe_guard.assert_not_called()

    def test_sensor_connector_has_priority_over_ambiguous_origin_prefixes(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            sensor_connector_id = self._insert_flowspec_connector(conn, "BGP-SENSOR", "/tmp/test-sensor.in")
            first_prefix_connector_id = self._insert_flowspec_connector(conn, "BGP-PREFIX-1", "/tmp/test-prefix-1.in")
            second_prefix_connector_id = self._insert_flowspec_connector(conn, "BGP-PREFIX-2", "/tmp/test-prefix-2.in")
            now = main.utc_now_iso()
            conn.execute(
                "INSERT INTO sensors (id, name, exporter_ip, created_at, updated_at) VALUES (9, 'sensor-9', '192.0.2.9', ?, ?)",
                (now, now),
            )
            conn.execute("UPDATE bgp_connectors SET sensor_id = 9 WHERE id = ?", (sensor_connector_id,))
            self._insert_zone_connector_mapping(conn, "Overlap 1", "45.5.248.0/24", first_prefix_connector_id)
            self._insert_zone_connector_mapping(conn, "Overlap 2", "45.5.248.0/24", second_prefix_connector_id)
            conn.commit()

            candidate = {
                "sensor_id": 9,
                "top_src_ip": "45.5.248.205",
                "dst_prefix": "51.222.110.42/32",
                "target_role": "dst_ip",
                "direction": "sends",
                "scope_type": "external_dst_ip_port",
                "raw_payload": {
                    "anomaly": {
                        "sensor_id": 9,
                        "top_src_ip": "45.5.248.205",
                        "target_ip": "51.222.110.42",
                        "target_role": "dst_ip",
                        "direction": "sends",
                        "scope_type": "external_dst_ip_port",
                    }
                },
            }

            resolved = main.resolve_mitigation_target_connectors(conn, candidate, {})
            conn.close()

            self.assertEqual([item["id"] for item in resolved], [sensor_connector_id])
            self.assertEqual(candidate["connector_resolution_method"], "sensor")
            self.assertEqual(candidate["candidate_connector_ids"], [sensor_connector_id])
            self.assertNotIn("connector_resolution_error", candidate)
            self.exabgp_pipe_guard.assert_not_called()

    def test_mitigation_key_includes_every_route_and_action_dimension(self):
        base = {
            "connector_id": 7,
            "response_type": "flowspec",
            "src_prefix": "45.5.248.0/32",
            "dst_prefix": "203.0.113.10/32",
            "protocol": "tcp",
            "src_port": "12345",
            "dst_port": "443",
            "tcp_flags": "syn",
            "action": "rate_limit",
            "rate_limit_bps": 1_000_000,
        }
        base_key = main.mitigation_key_for_candidate(base)
        for field, value in (
            ("connector_id", 8),
            ("response_type", "rtbh"),
            ("src_prefix", "45.5.248.1/32"),
            ("dst_prefix", "203.0.113.11/32"),
            ("protocol", "udp"),
            ("src_port", "12346"),
            ("dst_port", "444"),
            ("tcp_flags", "ack"),
            ("action", "discard"),
            ("rate_limit_bps", 2_000_000),
        ):
            with self.subTest(field=field):
                self.assertNotEqual(base_key, main.mitigation_key_for_candidate({**base, field: value}))

    def test_udp_outbound_origin_without_authorized_zone_or_prefix_is_not_actionable(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            self._insert_flowspec_connector(conn, "BGP-ONLY", "/tmp/test-only.in")
            event_id = self._insert_udp_many_anomaly_event(
                conn,
                event_id=1769,
                src_ip="192.0.2.20",
                zone_id=None,
                sensor_id=None,
            )
            conn.close()

            candidate = main.evaluated_mitigation_candidates(event_id)["candidates"][0]

            self.assertEqual(candidate["policy_decision"]["decision"], "deny")
            self.assertIn("Origem interna nao confirmada em zona ou prefixo autorizado.", candidate["policy_decision"]["reasons"])
            self.assertIn("Origem interna nao pertence a uma zona ou prefixo autorizado.", candidate["validation_errors"])
            self.assertEqual(candidate["automatic_not_applied_reason"], "origin_not_in_authorized_zone_or_prefix")
            self.assertFalse(candidate["actionable"])
            self.assertFalse(candidate["can_submit_approval"])
            self.assertFalse(candidate["can_announce_now"])
            self.exabgp_pipe_guard.assert_not_called()

    def test_manual_apply_failure_commits_the_persisted_outcome_before_4xx(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            now = main.utc_now_iso()
            conn.execute(
                "INSERT INTO bgp_protected_prefixes (cidr, enabled, created_at, updated_at) VALUES ('45.5.248.0/24', 1, ?, ?)",
                (now, now),
            )
            event_id = self._insert_udp_many_anomaly_event(conn, event_id=17691)
            conn.close()

            with self.assertRaises(HTTPException) as raised:
                main.apply_anomaly_mitigation(
                    self._admin_request(),
                    event_id,
                    main.BgpAnomalyMitigationApplyPayload(candidate_index=0, mode="manual_approval"),
                )

            self.assertEqual(raised.exception.status_code, 400)
            with main.sqlite_connection() as check:
                outcome = check.execute(
                    "SELECT auto_mitigation_status, auto_mitigation_reason, auto_mitigation_updated_at FROM anomaly_events WHERE id = ?",
                    (event_id,),
                ).fetchone()
            self.assertEqual(outcome["auto_mitigation_status"], "not_applied")
            self.assertIn("connector", outcome["auto_mitigation_reason"])
            self.assertTrue(outcome["auto_mitigation_updated_at"])
            self.exabgp_pipe_guard.assert_not_called()

    def test_udp_outbound_unique_connector_is_selected_when_origin_is_protected(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            connector_id = self._insert_flowspec_connector(conn, "BGP-ONLY", "/tmp/test-only.in")
            now = main.utc_now_iso()
            conn.execute(
                "INSERT INTO bgp_protected_prefixes (cidr, enabled, created_at, updated_at) VALUES ('45.5.248.0/24', 1, ?, ?)",
                (now, now),
            )
            event_id = self._insert_udp_many_anomaly_event(conn, event_id=1770)
            conn.close()

            candidate = main.evaluated_mitigation_candidates(event_id)["candidates"][0]

            self.assertEqual(candidate["selected_connector_id"], connector_id)
            self.assertEqual(candidate["connector_resolution_method"], "single_active_connector")
            self.assertEqual(candidate["eligible_connectors"][0]["id"], connector_id)
            self.assertFalse(candidate["requires_connector_selection"])
            self.assertTrue(candidate["actionable"])
            self.exabgp_pipe_guard.assert_not_called()

    def test_ambiguous_connectors_require_selection_and_manual_choice_recalculates(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            first_id = self._insert_flowspec_connector(conn, "BGP-FIRST", "/tmp/test-first.in")
            second_id = self._insert_flowspec_connector(conn, "BGP-SECOND", "/tmp/test-second.in")
            now = main.utc_now_iso()
            conn.execute(
                "INSERT INTO bgp_protected_prefixes (cidr, enabled, created_at, updated_at) VALUES ('45.5.248.0/24', 1, ?, ?)",
                (now, now),
            )
            event_id = self._insert_udp_many_anomaly_event(conn, event_id=1771)
            conn.close()

            unresolved = main.evaluated_mitigation_candidates(event_id)["candidates"][0]
            first = main.evaluated_mitigation_candidates(event_id, first_id)["candidates"][0]
            second = main.evaluated_mitigation_candidates(event_id, second_id)["candidates"][0]

            self.assertEqual(
                [item["id"] for item in unresolved["eligible_connectors"]],
                sorted([first_id, second_id]),
            )
            self.assertTrue(unresolved["requires_connector_selection"])
            self.assertFalse(unresolved["actionable"])
            self.assertNotEqual(unresolved["policy_decision"]["decision"], "deny")
            self.assertEqual(unresolved["validation_errors"], [])
            self.assertEqual(first["selected_connector_id"], first_id)
            self.assertEqual(second["selected_connector_id"], second_id)
            self.assertEqual(first["connector_resolution_method"], "operator_connector_id")
            self.assertEqual(second["connector_resolution_method"], "operator_connector_id")
            self.assertNotEqual(first["mitigation_key"], second["mitigation_key"])
            self.assertEqual(first["policy_decision"]["decision"], "require_manual_approval")
            self.assertEqual(second["policy_decision"]["decision"], "require_manual_approval")
            self.assertEqual(first["validation_errors"], [])
            self.assertEqual(second["validation_errors"], [])
            self.assertTrue(first["actionable"])
            self.assertTrue(second["actionable"])
            self.assertTrue(first["cooldown_allowed"])
            self.assertTrue(second["cooldown_allowed"])
            self.exabgp_pipe_guard.assert_not_called()

    def test_manual_connector_must_belong_to_the_authorized_origin_zone(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            zone_connector_id = self._insert_flowspec_connector(conn, "BGP-ZONE", "/tmp/test-zone.in")
            other_connector_id = self._insert_flowspec_connector(conn, "BGP-OTHER", "/tmp/test-other.in")
            zone_id = self._insert_zone_connector_mapping(conn, "Clientes", "45.5.248.0/24", zone_connector_id)
            event_id = self._insert_udp_many_anomaly_event(conn, event_id=17710, zone_id=zone_id)
            conn.close()

            candidate = main.evaluated_mitigation_candidates(event_id, other_connector_id)["candidates"][0]

            self.assertIsNone(candidate["selected_connector_id"])
            self.assertEqual(candidate["automatic_not_applied_reason"], "operator_connector_not_eligible_for_origin")
            self.assertEqual(candidate["policy_decision"]["decision"], "deny")
            self.assertFalse(candidate["actionable"])
            self.assertFalse(candidate["can_submit_approval"])
            self.assertFalse(candidate["can_announce_now"])
            self.exabgp_pipe_guard.assert_not_called()

    def test_manual_rejection_persists_anomaly_and_related_announcement(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            connector_id = self._insert_flowspec_connector(conn, "BGP-REJECT", "/tmp/test-reject.in")
            zone_id = self._insert_zone_connector_mapping(conn, "Clientes", "45.5.248.0/24", connector_id)
            event_id = self._insert_udp_many_anomaly_event(conn, event_id=1772, zone_id=zone_id)
            conn.close()

            result = main.reject_anomaly_mitigation(
                self._admin_request(),
                event_id,
                main.BgpAnomalyMitigationRejectPayload(
                    candidate_index=0,
                    connector_id=connector_id,
                    reason="rejeitado pelo operador no teste",
                ),
            )

            announcement = result["announcement"]
            self.assertEqual(announcement["status"], "rejected")
            self.assertEqual(announcement["anomaly_id"], event_id)
            self.assertEqual(announcement["connector_id"], connector_id)
            self.assertEqual(announcement["created_by"], "tester")
            with main.sqlite_connection() as check:
                anomaly = check.execute(
                    "SELECT auto_mitigation_status, auto_mitigation_reason, auto_mitigation_details_json FROM anomaly_events WHERE id = ?",
                    (event_id,),
                ).fetchone()
                total = check.execute(
                    "SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = ?",
                    (event_id,),
                ).fetchone()["total"]
            details = json.loads(anomaly["auto_mitigation_details_json"])
            self.assertEqual(anomaly["auto_mitigation_status"], "rejected")
            self.assertEqual(anomaly["auto_mitigation_reason"], "rejeitado pelo operador no teste")
            self.assertEqual(details["connector_id"], connector_id)
            self.assertEqual(details["announcement_id"], announcement["id"])
            self.assertEqual(details["created_by"], "tester")
            self.assertEqual(details["origin"], "manual")
            self.assertEqual(details["requested_mode"], "manual_rejection")
            self.assertTrue(details["mitigation_key"])
            self.assertEqual(total, 1)
            self.exabgp_pipe_guard.assert_not_called()

    def test_send_for_manual_approval_creates_related_pending_announcement_without_pipe(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            connector_id = self._insert_flowspec_connector(conn, "BGP-APPROVAL", "/tmp/test-approval.in")
            zone_id = self._insert_zone_connector_mapping(conn, "Clientes", "45.5.248.0/24", connector_id)
            event_id = self._insert_udp_many_anomaly_event(conn, event_id=1773, zone_id=zone_id)
            conn.close()

            result = main.apply_anomaly_mitigation(
                self._admin_request(),
                event_id,
                main.BgpAnomalyMitigationApplyPayload(
                    candidate_index=0,
                    connector_id=connector_id,
                    mode="manual_approval",
                ),
            )

            announcement = result["announcement"]
            self.assertEqual(announcement["status"], "pending_approval")
            self.assertEqual(announcement["anomaly_id"], event_id)
            self.assertEqual(announcement["connector_id"], connector_id)
            self.assertEqual(announcement["created_by"], "tester")
            with main.sqlite_connection() as check:
                anomaly = check.execute(
                    "SELECT auto_mitigation_status, auto_mitigation_details_json FROM anomaly_events WHERE id = ?",
                    (event_id,),
                ).fetchone()
            details = json.loads(anomaly["auto_mitigation_details_json"])
            self.assertEqual(anomaly["auto_mitigation_status"], "pending_approval")
            self.assertEqual(details["announcement_id"], announcement["id"])
            self.assertEqual(details["connector_id"], connector_id)
            self.assertEqual(details["created_by"], "tester")
            self.assertEqual(details["requested_mode"], "manual_approval")
            self.exabgp_pipe_guard.assert_not_called()

    def test_manual_announce_uses_selected_connector_and_links_announcement(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            connector_id = self._insert_flowspec_connector(conn, "BGP-ANNOUNCE", "/tmp/test-announce.in")
            zone_id = self._insert_zone_connector_mapping(conn, "Clientes", "45.5.248.0/24", connector_id)
            event_id = self._insert_udp_many_anomaly_event(conn, event_id=1774, zone_id=zone_id)
            conn.close()

            with patch.object(main, "exabgp_write_pipe") as write_pipe:
                result = main.apply_anomaly_mitigation(
                    self._admin_request(),
                    event_id,
                    main.BgpAnomalyMitigationApplyPayload(
                        candidate_index=0,
                        connector_id=connector_id,
                        mode="announce_now",
                    ),
                )

            announcement = result["announcement"]
            write_pipe.assert_called_once()
            self.assertEqual(write_pipe.call_args.args[0]["id"], connector_id)
            self.assertIn("destination 51.222.110.42/32", write_pipe.call_args.args[1])
            self.assertEqual(announcement["anomaly_id"], event_id)
            self.assertEqual(announcement["connector_id"], connector_id)
            self.assertEqual(announcement["created_by"], "tester")
            self.assertEqual(announcement["status"], "advertised")
            with main.sqlite_connection() as check:
                anomaly = check.execute(
                    "SELECT auto_mitigation_status, auto_mitigation_details_json FROM anomaly_events WHERE id = ?",
                    (event_id,),
                ).fetchone()
            details = json.loads(anomaly["auto_mitigation_details_json"])
            self.assertEqual(details["announcement_id"], announcement["id"])
            self.assertEqual(details["connector_id"], connector_id)
            self.assertEqual(details["requested_mode"], "announce_now")

    def test_equivalent_manual_response_is_exposed_and_not_duplicated(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            connector_id = self._insert_flowspec_connector(conn, "BGP-DEDUP", "/tmp/test-dedup.in")
            zone_id = self._insert_zone_connector_mapping(conn, "Clientes", "45.5.248.0/24", connector_id)
            event_id = self._insert_udp_many_anomaly_event(conn, event_id=1775, zone_id=zone_id)
            conn.close()
            request = self._admin_request()
            payload = main.BgpAnomalyMitigationApplyPayload(
                candidate_index=0,
                connector_id=connector_id,
                mode="manual_approval",
            )

            first = main.apply_anomaly_mitigation(request, event_id, payload)["announcement"]
            evaluated = main.evaluated_mitigation_candidates(event_id, connector_id)["candidates"][0]

            self.assertEqual(evaluated["equivalent_announcement"]["id"], first["id"])
            self.assertFalse(evaluated["actionable"])
            self.assertFalse(evaluated["can_submit_approval"])
            self.assertFalse(evaluated["can_announce_now"])
            with self.assertRaises(HTTPException) as ctx:
                main.apply_anomaly_mitigation(request, event_id, payload)
            self.assertEqual(ctx.exception.status_code, 409)
            self.assertIn(f"#{first['id']}", str(ctx.exception.detail))
            with main.sqlite_connection() as check:
                count = check.execute(
                    "SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = ?",
                    (event_id,),
                ).fetchone()["total"]
                anomaly = check.execute(
                    "SELECT auto_mitigation_status, auto_mitigation_details_json FROM anomaly_events WHERE id = ?",
                    (event_id,),
                ).fetchone()
            self.assertEqual(count, 1)
            self.assertEqual(anomaly["auto_mitigation_status"], "deduplicated")
            self.assertEqual(json.loads(anomaly["auto_mitigation_details_json"])["announcement_id"], first["id"])
            self.exabgp_pipe_guard.assert_not_called()

    def test_dry_run_connector_never_writes_pipe_or_offers_announce_now(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            connector_id = self._insert_flowspec_connector(conn, "BGP-DRY", "/run/exabgp/must-not-open.in")
            conn.execute(
                "UPDATE bgp_connectors SET backend_type = 'dry_run', mode = 'dry_run' WHERE id = ?",
                (connector_id,),
            )
            zone_id = self._insert_zone_connector_mapping(conn, "Clientes", "45.5.248.0/24", connector_id)
            event_id = self._insert_udp_many_anomaly_event(conn, event_id=1776, zone_id=zone_id)
            conn.close()

            candidate = main.evaluated_mitigation_candidates(event_id, connector_id)["candidates"][0]
            self.assertTrue(candidate["connector_dry_run"])
            self.assertTrue(candidate["dry_run"])
            self.assertTrue(candidate["can_submit_approval"])
            self.assertFalse(candidate["can_announce_now"])

            result = main.apply_anomaly_mitigation(
                self._admin_request(),
                event_id,
                main.BgpAnomalyMitigationApplyPayload(
                    candidate_index=0,
                    connector_id=connector_id,
                    mode="announce_now",
                ),
            )
            self.assertEqual(result["announcement"]["status"], "dry_run")
            self.exabgp_pipe_guard.assert_not_called()

    def test_analysis_only_candidate_cannot_overwrite_primary_outcome(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            event_id = self._insert_udp_many_anomaly_event(conn, event_id=1777)
            conn.execute(
                "UPDATE anomaly_events SET auto_mitigation_status = 'pending_approval', auto_mitigation_reason = 'primary' WHERE id = ?",
                (event_id,),
            )
            main.record_auto_mitigation_outcome(
                conn,
                {
                    "anomaly_id": event_id,
                    "mitigation_mode": "analysis_only",
                    "candidate_role": "analysis_only",
                    "raw_payload": {"anomaly": {"id": event_id, "source": "anomaly_events"}},
                },
                "failed",
                "auxiliary candidate",
            )
            conn.commit()
            row = conn.execute(
                "SELECT auto_mitigation_status, auto_mitigation_reason FROM anomaly_events WHERE id = ?",
                (event_id,),
            ).fetchone()
            conn.close()

            self.assertEqual(row["auto_mitigation_status"], "pending_approval")
            self.assertEqual(row["auto_mitigation_reason"], "primary")
            self.exabgp_pipe_guard.assert_not_called()

    def test_recently_ended_unprocessed_anomaly_is_retried_once(self):
        with temporary_main_db():
            conn, connector, _profile = self._dns_multi_target_context(add_whitelist=False)
            event_id = self._insert_dns_query_anomaly_event(conn, event_id=1901)
            recent = main.iso(datetime.now(timezone.utc) - timedelta(seconds=10))
            conn.execute(
                "UPDATE anomaly_events SET status = 'ended', ended_at = ?, last_seen_at = ? WHERE id = ?",
                (recent, recent, event_id),
            )
            conn.commit()
            conn.close()

            calls = []
            with patch.dict(os.environ, {"GMJFLOW_ANOMALY_MITIGATION_RETRY_WINDOW_SECONDS": "60"}), \
                 patch.object(main, "exabgp_write_pipe", side_effect=lambda item, command: calls.append((item["id"], command))):
                first = main.process_anomaly_mitigation()
                second = main.process_anomaly_mitigation()

            self.assertEqual(first["retried_ended"], 1)
            self.assertEqual(second["queued"], 0)
            self.assertEqual([item[0] for item in calls], [connector["id"]])
            with main.sqlite_connection() as check:
                outcome = check.execute(
                    "SELECT auto_mitigation_status FROM anomaly_events WHERE id = ?",
                    (event_id,),
                ).fetchone()
                total = check.execute(
                    "SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = ?",
                    (event_id,),
                ).fetchone()["total"]
            self.assertEqual(outcome["auto_mitigation_status"], "applied")
            self.assertEqual(total, 1)

    def test_ended_anomaly_older_than_retry_window_is_not_processed(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context(add_whitelist=False)
            event_id = self._insert_dns_query_anomaly_event(conn, event_id=1902)
            old = main.iso(datetime.now(timezone.utc) - timedelta(minutes=5))
            conn.execute(
                "UPDATE anomaly_events SET status = 'ended', ended_at = ?, last_seen_at = ? WHERE id = ?",
                (old, old, event_id),
            )
            conn.commit()
            conn.close()

            with patch.dict(os.environ, {"GMJFLOW_ANOMALY_MITIGATION_RETRY_WINDOW_SECONDS": "60"}), \
                 patch.object(main, "exabgp_write_pipe") as write_pipe:
                stats = main.process_anomaly_mitigation()

            self.assertEqual(stats["queued"], 0)
            write_pipe.assert_not_called()
            with main.sqlite_connection() as check:
                row = check.execute(
                    "SELECT auto_mitigation_status FROM anomaly_events WHERE id = ?",
                    (event_id,),
                ).fetchone()
                total = check.execute("SELECT COUNT(*) AS total FROM bgp_announcements").fetchone()["total"]
            self.assertEqual(row["auto_mitigation_status"], "")
            self.assertEqual(total, 0)

    def test_transient_database_lock_leaves_event_retryable_after_it_ends(self):
        with temporary_main_db():
            conn, connector, _profile = self._dns_multi_target_context(add_whitelist=False)
            event_id = self._insert_dns_query_anomaly_event(conn, event_id=1903)
            conn.close()

            with patch.object(main, "build_mitigation_candidates_from_anomaly", side_effect=sqlite3.OperationalError("database is locked")):
                with self.assertRaisesRegex(sqlite3.OperationalError, "database is locked"):
                    main.process_anomaly_mitigation()

            recent = main.iso(datetime.now(timezone.utc) - timedelta(seconds=5))
            with main.sqlite_connection() as conn:
                before = conn.execute(
                    "SELECT auto_mitigation_status FROM anomaly_events WHERE id = ?",
                    (event_id,),
                ).fetchone()
                conn.execute(
                    "UPDATE anomaly_events SET status = 'ended', ended_at = ?, last_seen_at = ? WHERE id = ?",
                    (recent, recent, event_id),
                )
                conn.commit()
            self.assertEqual(before["auto_mitigation_status"], "")

            calls = []
            with patch.dict(os.environ, {"GMJFLOW_ANOMALY_MITIGATION_RETRY_WINDOW_SECONDS": "60"}), \
                 patch.object(main, "exabgp_write_pipe", side_effect=lambda item, command: calls.append(item["id"])):
                stats = main.process_anomaly_mitigation()

            self.assertEqual(stats["retried_ended"], 1)
            self.assertEqual(calls, [connector["id"]])

    def test_persisted_outcome_prevents_active_event_reprocessing(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context(add_whitelist=False)
            event_id = self._insert_dns_query_anomaly_event(conn, event_id=1904)
            conn.execute(
                "UPDATE anomaly_events SET auto_mitigation_status = 'not_applied', auto_mitigation_reason = 'policy deny' WHERE id = ?",
                (event_id,),
            )
            conn.commit()
            conn.close()

            with patch.object(main, "exabgp_write_pipe") as write_pipe:
                stats = main.process_anomaly_mitigation()

            self.assertEqual(stats["queued"], 0)
            write_pipe.assert_not_called()

    def test_ambiguous_zone_connector_resolution_persists_reason_and_does_not_announce(self):
        with temporary_main_db():
            conn, fibinet, profile = self._dns_multi_target_context(add_whitelist=False)
            gm_id = self._insert_flowspec_connector(conn, "BGP-GM-BORDA", "/run/exabgp/gm.in")
            self._insert_zone_connector_mapping(conn, "FIBINET", "179.189.83.0/24", fibinet["id"])
            self._insert_zone_connector_mapping(conn, "GM overlap", "179.189.83.0/24", gm_id)
            conn.execute(
                "INSERT INTO bgp_protected_prefixes (cidr, enabled, created_at, updated_at) VALUES ('179.189.83.0/24', 1, ?, ?)",
                (main.utc_now_iso(), main.utc_now_iso()),
            )
            event_id = self._insert_dns_query_anomaly_event(conn, event_id=1727, src_ip="179.189.83.212", dst_ip="174.55.141.233")
            conn.execute("UPDATE anomaly_events SET sensor_id = NULL, zone_id = NULL WHERE id = ?", (event_id,))
            conn.commit()
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda connector, command: calls.append((connector["id"], command))
            try:
                with self.assertLogs("gmj-flow", level="INFO") as logs:
                    main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(calls, [])
            with main.sqlite_connection() as check:
                total = check.execute("SELECT COUNT(*) AS total FROM bgp_announcements").fetchone()["total"]
                outcome = check.execute(
                    "SELECT auto_mitigation_status, auto_mitigation_reason, auto_mitigation_details_json FROM anomaly_events WHERE id = ?",
                    (event_id,),
                ).fetchone()
            self.assertEqual(total, 0)
            self.assertEqual(outcome["auto_mitigation_status"], "not_applied")
            self.assertEqual(outcome["auto_mitigation_reason"], "ambiguous_connector_resolution")
            details = json.loads(outcome["auto_mitigation_details_json"])
            self.assertEqual(details["source_ip"], "179.189.83.212")
            self.assertEqual(details["candidate_connector_ids"], sorted([fibinet["id"], gm_id]))
            log_text = "\n".join(logs.output)
            self.assertIn("reason=ambiguous_connector_resolution", log_text)
            self.assertIn("source_ip=179.189.83.212", log_text)
            self.assertIn("candidate_connector_ids=", log_text)

    def test_no_zone_mapping_with_multiple_connectors_does_not_announce(self):
        with temporary_main_db():
            conn, _fibinet, _profile = self._dns_multi_target_context(add_whitelist=False)
            self._insert_flowspec_connector(conn, "BGP-GM-BORDA", "/run/exabgp/gm.in")
            event_id = self._insert_dns_query_anomaly_event(conn, event_id=1727)
            conn.execute("UPDATE ip_zone_prefixes SET active = 0")
            conn.execute("UPDATE anomaly_events SET sensor_id = NULL, zone_id = NULL WHERE id = ?", (event_id,))
            conn.commit()
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda connector, command: calls.append(command)
            try:
                main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(calls, [])
            with main.sqlite_connection() as check:
                self.assertEqual(check.execute("SELECT COUNT(*) AS total FROM bgp_announcements").fetchone()["total"], 0)

    def test_three_equivalent_anomalies_create_one_flowspec_announcement(self):
        with temporary_main_db():
            conn, fibinet, _profile = self._dns_multi_target_context(add_whitelist=False)
            self._insert_flowspec_connector(conn, "BGP-GM-BORDA", "/run/exabgp/gm.in")
            now = main.utc_now_iso()
            conn.execute(
                "INSERT INTO ip_zone_prefixes (zone_id, cidr, active, created_at, updated_at) VALUES (1, '179.189.83.0/24', 1, ?, ?)",
                (now, now),
            )
            conn.execute(
                "INSERT INTO bgp_protected_prefixes (cidr, enabled, created_at, updated_at) VALUES ('179.189.83.0/24', 1, ?, ?)",
                (now, now),
            )
            for event_id in (1727, 1728, 1729):
                self._insert_dns_query_anomaly_event(conn, event_id=event_id, src_ip="179.189.83.212", dst_ip="174.55.141.233")
                conn.execute("UPDATE anomaly_events SET sensor_id = NULL WHERE id = ?", (event_id,))
            conn.commit()
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda connector, command: calls.append((connector["id"], command))
            try:
                stats = main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(len(calls), 1)
            self.assertEqual(stats["advertised"], 1)
            self.assertGreaterEqual(stats["skipped"], 2)
            with main.sqlite_connection() as check:
                rows = check.execute(
                    "SELECT connector_id, dst_prefix, protocol, dst_port, action FROM bgp_announcements"
                ).fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(tuple(rows[0]), (fibinet["id"], "174.55.141.233/32", "udp", "53", "discard"))

    def test_same_destination_on_different_connectors_is_not_deduplicated(self):
        with temporary_main_db():
            conn, fibinet, _profile = self._dns_multi_target_context(add_whitelist=False)
            gm_id = self._insert_flowspec_connector(conn, "BGP-GM-BORDA", "/run/exabgp/gm.in")
            self._insert_zone_connector_mapping(conn, "FIBINET", "179.189.83.0/24", fibinet["id"])
            self._insert_zone_connector_mapping(conn, "GM", "45.5.249.0/24", gm_id)
            now = main.utc_now_iso()
            for cidr in ("179.189.83.0/24", "45.5.249.0/24"):
                conn.execute(
                    "INSERT INTO bgp_protected_prefixes (cidr, enabled, created_at, updated_at) VALUES (?, 1, ?, ?)",
                    (cidr, now, now),
                )
            for event_id, source_ip in ((1801, "179.189.83.212"), (1802, "45.5.249.10")):
                self._insert_dns_query_anomaly_event(conn, event_id=event_id, src_ip=source_ip, dst_ip="174.55.141.233")
                conn.execute("UPDATE anomaly_events SET sensor_id = NULL, zone_id = NULL WHERE id = ?", (event_id,))
            conn.commit()
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda connector, command: calls.append((connector["id"], command))
            try:
                main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(sorted(connector_id for connector_id, _command in calls), sorted([fibinet["id"], gm_id]))
            with main.sqlite_connection() as check:
                connector_ids = [row["connector_id"] for row in check.execute("SELECT connector_id FROM bgp_announcements").fetchall()]
            self.assertEqual(sorted(connector_ids), sorted([fibinet["id"], gm_id]))

    def test_selected_and_explicit_profile_connectors_keep_priority(self):
        with temporary_main_db():
            conn, fibinet, profile = self._dns_multi_target_context(add_whitelist=False)
            gm_id = self._insert_flowspec_connector(conn, "BGP-GM-BORDA", "/run/exabgp/gm.in")
            self._insert_zone_connector_mapping(conn, "FIBINET", "179.189.83.0/24", fibinet["id"])
            candidate = {
                "sensor_id": None,
                "raw_payload": {"anomaly": {"top_src_ip": "179.189.83.212", "target_role": "src_ip"}},
            }
            selected_profile = {**profile, "selected_connector_ids": [gm_id], "connector_id": fibinet["id"]}
            selected = main.resolve_mitigation_target_connectors(conn, dict(candidate), selected_profile)
            self.assertEqual([item["id"] for item in selected], [gm_id])
            explicit_profile = {**profile, "selected_connector_ids": [], "connector_id": gm_id}
            explicit = main.resolve_mitigation_target_connectors(conn, dict(candidate), explicit_profile)
            self.assertEqual([item["id"] for item in explicit], [gm_id])

    def test_dns_query_outbound_multiple_active_connectors_without_selection_does_not_announce(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context(add_whitelist=False)
            now = main.utc_now_iso()
            conn.execute(
                """
                INSERT INTO bgp_connectors (
                    name, role, backend_type, mode, max_active_rules, max_duration_seconds,
                    enabled, is_active, exabgp_pipe_in, created_at, updated_at
                )
                VALUES ('BGP-SECOND', 'flowspec_mitigation', 'exabgp', 'manual_approval', 50, 1800,
                        1, 1, '/run/exabgp/second.in', ?, ?)
                """,
                (now, now),
            )
            event_id = self._insert_dns_query_anomaly_event(conn)
            conn.execute("UPDATE ip_zone_prefixes SET active = 0")
            conn.execute("UPDATE anomaly_events SET sensor_id = NULL, zone_id = NULL WHERE id = ?", (event_id,))
            conn.commit()
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                with self.assertLogs("gmj-flow", level="INFO") as logs:
                    stats = main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(calls, [])
            self.assertEqual(stats["advertised"], 0)
            with main.sqlite_connection() as check:
                total = check.execute("SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = ?", (event_id,)).fetchone()["total"]
            self.assertEqual(total, 0)
            log_text = "\n".join(logs.output)
            self.assertIn("reason=ambiguous_connector_resolution", log_text)
            self.assertIn("connector_resolution_error=ambiguous_connector_resolution", log_text)

    def test_dns_query_outbound_no_active_connector_does_not_announce(self):
        with temporary_main_db():
            conn, connector, _profile = self._dns_multi_target_context(add_whitelist=False)
            event_id = self._insert_dns_query_anomaly_event(conn)
            conn.execute("UPDATE bgp_connectors SET enabled = 0, is_active = 0 WHERE id = ?", (connector["id"],))
            conn.commit()
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                stats = main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(calls, [])
            self.assertEqual(stats["advertised"], 0)
            with main.sqlite_connection() as check:
                total = check.execute("SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = ?", (event_id,)).fetchone()["total"]
            self.assertEqual(total, 0)

    def test_dns_query_outbound_dry_run_connector_is_not_operational_active(self):
        with temporary_main_db():
            conn, connector, _profile = self._dns_multi_target_context(add_whitelist=False)
            event_id = self._insert_dns_query_anomaly_event(conn)
            conn.execute("UPDATE bgp_connectors SET backend_type = 'dry_run', mode = 'dry_run' WHERE id = ?", (connector["id"],))
            conn.commit()
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(calls, [])
            with main.sqlite_connection() as check:
                row = check.execute("SELECT * FROM bgp_announcements WHERE anomaly_id = ?", (event_id,)).fetchone()
                summary = main.bgp_summary_payload(check)
            item = main.bgp_announcement_row_to_dict(row)
            self.assertEqual(item["status"], "dry_run")
            self.assertFalse(item["operationally_active"])
            self.assertIsNone(item["expires_at"])
            self.assertIsNone(item["advertised_at"])
            self.assertEqual(summary["active_bgp_announcements"], 0)

    def test_bgp_summary_counts_only_current_advertised_and_marks_legacy_unconfirmed(self):
        with temporary_main_db():
            conn, connector, profile = self._dns_multi_target_context(add_whitelist=False)
            now = main.utc_now_iso()
            future = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
            past = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
            for status, expires_at in (
                ("advertised", future),
                ("advertised", None),
                ("advertised", past),
                ("active", future),
                ("announced", None),
                ("pending_approval", None),
                ("failed", None),
            ):
                conn.execute(
                    """
                    INSERT INTO bgp_announcements (
                        connector_id, response_profile_id, status, route_type, response_type, action,
                        target_prefix, duration_seconds, expires_at, created_by, created_at, updated_at
                    )
                    VALUES (?, ?, ?, 'flowspec', 'flowspec', 'discard', '203.0.113.10/32', 600, ?, 'test', ?, ?)
                    """,
                    (connector["id"], profile["id"], status, expires_at, now, now),
                )
            conn.commit()
            summary = main.bgp_summary_payload(conn)
            self.assertEqual(summary["active_bgp_announcements"], 3)
            self.assertEqual(summary["pending_bgp_announcements"], 1)
            self.assertEqual(summary["failed_bgp_announcements"], 1)
            legacy_rows = conn.execute(
                "SELECT * FROM bgp_announcements WHERE status IN ('active', 'announced') ORDER BY id"
            ).fetchall()
            for row in legacy_rows:
                item = main.bgp_announcement_row_to_dict(row)
                self.assertTrue(item["legacy_unconfirmed"])
                self.assertFalse(item["operationally_active"])

    def test_template_dns_destination_whitelist_does_not_apply(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context()
            event_id = self._insert_dns_query_anomaly_event(conn, event_id=141, dst_ip="103.192.159.11")
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                with self.assertLogs("gmj-flow", level="INFO") as logs:
                    stats = main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(calls, [])
            self.assertEqual(stats["advertised"], 0)
            with main.sqlite_connection() as check:
                count = check.execute("SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = ?", (event_id,)).fetchone()["total"]
            self.assertEqual(count, 0)
            self.assertIn("destino em whitelist", "\n".join(logs.output))

    def test_template_dns_source_outside_protected_prefix_does_not_apply(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context(add_whitelist=False)
            event_id = self._insert_dns_query_anomaly_event(conn, event_id=142, src_ip="198.51.100.10")
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                with self.assertLogs("gmj-flow", level="INFO") as logs:
                    stats = main.process_anomaly_mitigation()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(calls, [])
            self.assertEqual(stats["advertised"], 0)
            with main.sqlite_connection() as check:
                count = check.execute("SELECT COUNT(*) AS total FROM bgp_announcements WHERE anomaly_id = ?", (event_id,)).fetchone()["total"]
            self.assertEqual(count, 0)
            self.assertIn("src fora de prefixo protegido", "\n".join(logs.output))

    def test_dns_outbound_multi_target_candidate_filters_and_renders_dst_only(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context()
            conn.close()
            event, flows = self._dns_event_and_flows()
            candidates = main.build_mitigation_candidates_from_anomaly({"event": event, "flows": flows})
            group = candidates[0]
            self.assertTrue(group["multi_target_dns"])
            self.assertEqual(group["attack_vector_name"], "DNS_INTERNAL_IP_TO_DST_HIGH_PPS")
            self.assertEqual(group["response_profile_id"], _profile["id"])
            self.assertEqual(group["response_profile_name"], "FLOWSPEC_AUTO_BLOCK_DST_DNS")
            self.assertEqual(group["mitigation_target_mode"], "sensor_origin")
            self.assertNotEqual(group["mitigation_target_mode"], "all_connectors")
            self.assertEqual(group["eligible_dns_targets_count"], 10)
            ignored = {item["reason"] for item in group["ignored_dns_targets"]}
            self.assertIn("whitelist", ignored)
            self.assertIn("below_threshold", ignored)
            self.assertEqual(len(group["dns_targets"]), 10)
            for target in group["dns_targets"]:
                command = main.render_exabgp_flowspec_command("announce", target["candidate"])
                self.assertIn("destination ", command)
                self.assertIn("protocol =udp", command)
                self.assertIn("destination-port =53", command)
                self.assertNotIn("source ", command)
                self.assertNotIn("source-port", command)

    def test_dns_outbound_multi_target_apply_creates_one_announcement_per_destination(self):
        with temporary_main_db():
            conn, connector, _profile = self._dns_multi_target_context()
            conn.close()
            event, flows = self._dns_event_and_flows()
            group = main.build_mitigation_candidates_from_anomaly({"event": event, "flows": flows})[0]
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append((_connector["id"], command))
            try:
                with main.sqlite_connection() as apply_conn:
                    result = main.apply_mitigation_candidates(apply_conn, [group], "announce_now", "test")
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(result["count"], 10)
            self.assertEqual(len(calls), 10)
            self.assertTrue(all(call[0] == connector["id"] for call in calls))
            self.assertTrue(all("source " not in command and "source-port" not in command for _cid, command in calls))
            with main.sqlite_connection() as check:
                rows = check.execute(
                    "SELECT status, connector_id, sensor_id, dst_ip, protocol, dst_port, announce_command, withdraw_command, pipe_path FROM bgp_announcements ORDER BY dst_ip"
                ).fetchall()
            self.assertEqual(len(rows), 10)
            self.assertTrue(all(row["status"] == "advertised" for row in rows))
            self.assertTrue(all(row["connector_id"] == connector["id"] for row in rows))
            self.assertTrue(all(row["sensor_id"] == 9 for row in rows))
            self.assertTrue(all(row["protocol"] == "udp" and row["dst_port"] == "53" for row in rows))
            self.assertTrue(all(row["pipe_path"] == "/run/exabgp/exabgp.in" for row in rows))
            self.assertTrue(all("withdraw flow route" in row["withdraw_command"] for row in rows))

    def test_dns_outbound_multi_target_does_not_duplicate_active_destination(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context()
            conn.close()
            event, flows = self._dns_event_and_flows()
            group = main.build_mitigation_candidates_from_anomaly({"event": event, "flows": flows})[0]
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                with main.sqlite_connection() as apply_conn:
                    first = main.apply_mitigation_candidates(apply_conn, [group], "announce_now", "test")
                    second = main.apply_mitigation_candidates(apply_conn, [group], "announce_now", "test")
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(first["count"], 10)
            self.assertEqual(second["count"], 0)
            self.assertEqual(len(second["skipped"]), 10)
            with main.sqlite_connection() as check:
                total = check.execute("SELECT COUNT(*) AS total FROM bgp_announcements WHERE status = 'advertised'").fetchone()["total"]
            self.assertEqual(total, 10)

    def test_dns_outbound_multi_target_respects_max_active_rules_and_pipe_failure(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context(max_active_rules=3)
            conn.close()
            event, flows = self._dns_event_and_flows()
            group = main.build_mitigation_candidates_from_anomaly({"event": event, "flows": flows})[0]
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                with main.sqlite_connection() as apply_conn:
                    result = main.apply_mitigation_candidates(apply_conn, [group], "announce_now", "test")
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(result["count"], 3)
            with main.sqlite_connection() as check:
                total = check.execute("SELECT COUNT(*) AS total FROM bgp_announcements WHERE status = 'advertised'").fetchone()["total"]
            self.assertEqual(total, 3)

        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context()
            conn.close()
            event, flows = self._dns_event_and_flows()
            group = main.build_mitigation_candidates_from_anomaly({"event": event, "flows": flows})[0]
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: (_ for _ in ()).throw(HTTPException(status_code=400, detail="pipe down"))
            try:
                with main.sqlite_connection() as apply_conn:
                    result = main.apply_mitigation_candidates(apply_conn, [group], "announce_now", "test")
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(result["count"], 10)
            with main.sqlite_connection() as check:
                statuses = [row["status"] for row in check.execute("SELECT status FROM bgp_announcements").fetchall()]
            self.assertEqual(set(statuses), {"failed"})

    def test_dns_outbound_multi_target_expiration_and_anomaly_withdraw_cover_all(self):
        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context()
            conn.close()
            event, flows = self._dns_event_and_flows()
            group = main.build_mitigation_candidates_from_anomaly({"event": event, "flows": flows})[0]
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                with main.sqlite_connection() as apply_conn:
                    main.apply_mitigation_candidates(apply_conn, [group], "announce_now", "test")
                    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
                    apply_conn.execute("UPDATE bgp_announcements SET expires_at = ? WHERE anomaly_id = 77", (past,))
                    apply_conn.commit()
                    stats = main.process_expired_bgp_announcements(apply_conn)
                    apply_conn.commit()
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(stats["withdrawn"], 10)
            self.assertEqual(len([command for command in calls if command.startswith("withdraw flow route")]), 10)
            with main.sqlite_connection() as check:
                expired_statuses = {
                    row["status"]
                    for row in check.execute("SELECT status FROM bgp_announcements").fetchall()
                }
            self.assertEqual(expired_statuses, {"expired"})

        with temporary_main_db():
            conn, _connector, _profile = self._dns_multi_target_context()
            conn.close()
            event, flows = self._dns_event_and_flows()
            group = main.build_mitigation_candidates_from_anomaly({"event": event, "flows": flows})[0]
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                with main.sqlite_connection() as apply_conn:
                    main.apply_mitigation_candidates(apply_conn, [group], "announce_now", "test")
                result = main.withdraw_anomaly_mitigations(self._admin_request(), 77, main.BgpAnomalyMitigationWithdrawPayload())
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(result["count"], 10)
            self.assertEqual(len([command for command in calls if command.startswith("withdraw flow route")]), 10)
            with main.sqlite_connection() as check:
                withdrawn_statuses = {
                    row["status"]
                    for row in check.execute("SELECT status FROM bgp_announcements").fetchall()
                }
            self.assertEqual(withdrawn_statuses, {"withdrawn"})

    def test_dns_outbound_source_only_gets_warning_and_is_not_recommended(self):
        with temporary_main_db():
            candidate = {
                "response_type": "flowspec",
                "action": "discard",
                "then_action": "discard",
                "src_prefix": "168.232.196.123/32",
                "protocol": "udp",
                "dst_port": "53",
                "duration_seconds": 1800,
                "requested_mode": "automatic",
                "not_recommended": True,
                "raw_payload": {"anomaly": {"top_flow": {"dst_ip": "75.131.245.200"}}},
            }
            policy = main.evaluate_mitigation_policy({**candidate, "requested_mode": "automatic"})
            self.assertEqual(policy["decision"], "deny")
            self.assertIn("Source-only DNS outbound", " ".join(policy["warnings"] + policy["reasons"]))

    def test_top_flow_empty_is_enriched_from_related_dns_flow(self):
        event = {"id": 10, "target_ip": "", "target_port": None, "top_flow": {"src_ip": "", "dst_ip": "", "packets": 0, "bytes": 0}}
        flows = [
            {"src_ip": "168.232.196.123", "src_port": 35732, "dst_ip": "75.131.245.200", "dst_port": 53, "proto": 17, "packets": 20, "bytes": 2000},
            {"src_ip": "168.232.196.123", "src_port": 35733, "dst_ip": "75.131.245.201", "dst_port": 443, "proto": 6, "packets": 100, "bytes": 9000},
        ]
        enriched = main.enrich_anomaly_event_from_flows(event, flows)
        self.assertEqual(enriched["dominant_src_ip"], "168.232.196.123")
        self.assertEqual(enriched["dominant_dst_ip"], "75.131.245.200")
        self.assertEqual(enriched["dominant_dst_port"], 53)
        self.assertEqual(enriched["dominant_protocol"], "udp")
        self.assertEqual(enriched["target_ip"], "75.131.245.200")
        self.assertEqual(enriched["target_port"], 53)

    def test_manual_lab_flowspec_does_not_require_enabled_response_profile(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            payload = main.BgpFlowspecTestPayload(
                action="dry_run",
                dst_cidr="75.131.245.200",
                protocol="udp",
                dst_port="53",
                duration_seconds=1800,
            )
            candidate = main.flowspec_candidate_from_payload(payload)
            profile = {
                "enabled": False,
                "manual_lab": True,
                "response_type": "flowspec",
                "require_protocol_or_port": True,
                "allow_wide_prefix": False,
                "max_duration_seconds": 1800,
                "default_duration_seconds": 1800,
            }
            validation = main.validate_mitigation_candidate({**candidate, "manual_lab": True}, connector, profile)
            self.assertNotIn("Perfil de resposta desativado.", validation["errors"])
            command = main.render_exabgp_flowspec_command("announce", candidate)
            self.assertEqual(command, "announce flow route { match { destination 75.131.245.200/32; protocol =udp; destination-port =53; } then { discard; } }")
            self.assertNotIn("ttl", command.lower())

    def test_manual_flowspec_dry_run_does_not_send_or_create_active_announcement(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            conn.close()
            calls = []
            original = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                item = main.test_bgp_connector_flowspec(
                    self._admin_request(),
                    connector["id"],
                    main.BgpFlowspecTestPayload(
                        action="dry_run",
                        dst_cidr="203.0.113.10",
                        protocol="udp",
                        dst_port="53",
                        duration_seconds=300,
                    ),
                )
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(calls, [])
            self.assertEqual(item["status"], "dry_run")
            self.assertIsNone(item["expires_at"])
            self.assertIn("announce flow route", item["announce_command"])
            self.assertIn("withdraw flow route", item["withdraw_command"])
            self.assertNotIn("ttl", item["announce_command"].lower())
            with main.sqlite_connection() as check:
                count = check.execute("SELECT COUNT(*) AS count FROM bgp_announcements").fetchone()["count"]
            self.assertEqual(count, 0)

    def test_manual_flowspec_announce_uses_shared_attempt_and_starts_advertised_ttl(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            conn.close()
            readiness_result = self._readiness_result(connector)
            with patch.object(
                main,
                "check_bgp_connector_readiness",
                return_value=readiness_result,
            ) as readiness, patch.object(main, "exabgp_write_pipe") as write_pipe:
                item = main.test_bgp_connector_flowspec(
                    self._admin_request(),
                    connector["id"],
                    main.BgpFlowspecTestPayload(
                        action="announce",
                        dst_cidr="203.0.113.10",
                        protocol="udp",
                        dst_port="53",
                        duration_seconds=300,
                        confirm="ANUNCIAR",
                    ),
                )
            self.assertTrue(
                {
                    "queued_at",
                    "sent_at",
                    "advertised_at",
                    "last_attempt_at",
                    "peer_state",
                    "confirmation_level",
                    "status_details_json",
                    "requested_mode",
                    "retry_of_announcement_id",
                }.issubset(set(main.MANUAL_FLOWSPEC_ANNOUNCEMENT_COLUMNS))
            )
            readiness.assert_called_once()
            write_pipe.assert_called_once()
            self.assertEqual(write_pipe.call_args.args[0]["id"], connector["id"])
            self.assertEqual(write_pipe.call_args.args[1], item["announce_command"])
            self.assertEqual(item["status"], "advertised")
            self.assertTrue(item["queued_at"])
            self.assertTrue(item["sent_at"])
            self.assertTrue(item["advertised_at"])
            self.assertTrue(item["announced_at"])
            self.assertTrue(item["last_attempt_at"])
            self.assertTrue(item["expires_at"])
            self.assertEqual(item["peer_state"], "established")
            self.assertTrue(item["operationally_active"])
            self.assertNotIn("ttl", item["announce_command"].lower())
            self.assertNotIn("duration", item["announce_command"].lower())
            with main.sqlite_connection() as check:
                row = check.execute(
                    "SELECT status, expires_at, announce_command, withdraw_command FROM bgp_announcements"
                ).fetchone()
                events = self._announcement_event_types(check, item["id"])
            self.assertEqual(row["status"], "advertised")
            self.assertTrue(row["expires_at"])
            self.assertEqual(row["announce_command"], item["announce_command"])
            self.assertEqual(row["withdraw_command"], item["withdraw_command"])
            self.assertLess(events.index("queued"), events.index("sent"))
            self.assertLess(events.index("sent"), events.index("advertised"))

    def test_manual_flowspec_withdraw_terminalizes_the_tracked_advertisement(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            conn.close()
            payload = main.BgpFlowspecTestPayload(
                action="announce",
                dst_cidr="203.0.113.10",
                protocol="udp",
                dst_port="53",
                duration_seconds=300,
                confirm="ANUNCIAR",
            )
            with patch.object(main, "exabgp_write_pipe"):
                advertised = main.test_bgp_connector_flowspec(
                    self._admin_request(),
                    connector["id"],
                    payload,
                )

            with patch.object(main, "exabgp_write_pipe") as write_pipe:
                withdrawn = main.test_bgp_connector_flowspec(
                    self._admin_request(),
                    connector["id"],
                    main.BgpFlowspecTestPayload(
                        action="withdraw",
                        dst_cidr="203.0.113.10",
                        protocol="udp",
                        dst_port="53",
                        duration_seconds=300,
                    ),
                )

            self.assertEqual(withdrawn["id"], advertised["id"])
            self.assertEqual(withdrawn["matched_announcement_id"], advertised["id"])
            self.assertEqual(withdrawn["status"], "withdrawn")
            self.assertFalse(withdrawn["operationally_active"])
            write_pipe.assert_called_once_with(connector, advertised["withdraw_command"])
            with main.sqlite_connection() as check:
                rows = check.execute(
                    "SELECT id, status FROM bgp_announcements ORDER BY id"
                ).fetchall()
            self.assertEqual([(row["id"], row["status"]) for row in rows], [(advertised["id"], "withdrawn")])

    def test_legacy_active_record_does_not_infer_a_flowspec_session(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            connector["router_check_enabled"] = True
            now = main.utc_now_iso()
            conn.execute(
                """
                INSERT INTO bgp_announcements (
                    connector_id, status, route_type, response_type, action,
                    announce_command, withdraw_command, rendered_command, created_at, updated_at
                )
                VALUES (?, 'active', 'flowspec', 'flowspec', 'discard',
                        'announce flow route { match { destination 203.0.113.10/32; protocol udp; destination-port =53; } then { discard; } }',
                        'withdraw flow route { match { destination 203.0.113.10/32; protocol udp; destination-port =53; } then { discard; } }',
                        'announce flow route { match { destination 203.0.113.10/32; protocol udp; destination-port =53; } then { discard; } }',
                        ?, ?)
                """,
                (connector["id"], now, now),
            )
            conn.commit()
            conn.close()
            with patch.object(main, "router_ssh_status", return_value={"enabled": True, "bgp_state": "established", "flowspec_state": "not_verified", "message": ""}), \
                 patch.object(main, "host_agent_status", return_value={"enabled": False, "message": ""}):
                status = main.bgp_connector_status(connector)
            self.assertEqual(status["bgp_state"], "established")
            self.assertEqual(status["flowspec_state"], "not_verified")
            self.assertFalse(status["verification"]["flowspec_verified"])
            self.assertEqual(status["verification"]["flowspec_active_announcements"], 0)

    def test_bgp_status_worker_checks_periodically(self):
        calls = []
        called_twice = threading.Event()

        def run_once():
            calls.append(time.monotonic())
            if len(calls) >= 2:
                called_twice.set()
            return {"checked": 0, "failed": 0, "skipped": 0, "concurrent": False}

        main.BGP_STATUS_CHECK_STOP.clear()
        with patch.object(main, "bgp_check_interval_seconds", return_value=0.01), \
             patch.object(main, "run_bgp_connector_status_checks_once", side_effect=run_once):
            thread = threading.Thread(target=main.bgp_status_check_loop)
            thread.start()
            try:
                self.assertTrue(called_twice.wait(1))
            finally:
                main.BGP_STATUS_CHECK_STOP.set()
                thread.join(1)
        self.assertGreaterEqual(len(calls), 2)
        self.assertFalse(thread.is_alive())

    def test_manual_bgp_check_endpoint_uses_central_check(self):
        with temporary_main_db():
            status = {
                "connector_id": 2,
                "bgp_state": "established",
                "flowspec_state": "established",
                "pipe_state": "ok",
                "verification": {"router_check_enabled": True},
                "router_check": {"vendor": "huawei_vrp"},
            }
            with patch.object(main, "check_and_persist_bgp_connector_status", return_value=status) as central:
                result = main.check_bgp_connector_router(self._admin_request(), 2)
        central.assert_called_once_with(2)
        self.assertEqual(result["bgp_state"], "established")
        self.assertEqual(result["flowspec_state"], "established")

    def test_bgp_status_endpoint_only_reads_persisted_snapshot(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            conn.execute(
                """
                UPDATE bgp_connectors
                SET bgp_state = 'established', flowspec_state = 'established', pipe_state = 'ok',
                    status_message = 'persisted', last_checked_at = '2026-07-19T12:00:00Z'
                WHERE id = ?
                """,
                (connector["id"],),
            )
            conn.commit()
            conn.close()
            with patch.object(main, "bgp_connector_status") as live_check:
                result = main.get_bgp_connector_status(self._admin_request(), connector["id"])
            live_check.assert_not_called()
            self.assertEqual(result["bgp_state"], "established")
            self.assertEqual(result["flowspec_state"], "established")
            self.assertEqual(result["pipe_state"], "ok")
            self.assertEqual(result["message"], "persisted")

    def test_later_explicit_peer_down_marks_only_advertised_and_preserves_delivery_history(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            anomaly_id = self._insert_udp_many_anomaly_event(conn, event_id=1776)
            candidate = self._stage2_candidate(
                connector,
                profile,
                "stage2-later-peer-down",
                anomaly_id=anomaly_id,
            )
            with patch.object(main, "exabgp_write_pipe"):
                advertised = main.apply_mitigation_candidate(
                    conn,
                    candidate,
                    "announce_now",
                    "tester",
                )
            now = main.utc_now_iso()
            sent_id = conn.execute(
                """
                INSERT INTO bgp_announcements (
                    connector_id, status, route_type, response_type, action,
                    sent_at, last_attempt_at, created_at, updated_at
                )
                VALUES (?, 'sent', 'flowspec', 'flowspec', 'discard', ?, ?, ?, ?)
                """,
                (connector["id"], now, now, now, now),
            ).lastrowid
            conn.commit()
            original_timestamps = {
                key: advertised[key]
                for key in ("queued_at", "sent_at", "advertised_at", "announced_at", "last_attempt_at")
            }
            conn.close()

            down_status = self._readiness_result(
                connector,
                peer_state="down",
                ready=False,
                reason="peer_bgp_down",
            )["status"]
            down_status["flowspec_state"] = "down"
            down_status["pipes"] = {"ok": True, "status": "ok"}
            down_status["pipe_state"] = "ok"
            with patch.object(main, "bgp_connector_status", return_value=down_status):
                checked = main.check_and_persist_bgp_connector_status(connector["id"])

            self.assertEqual(checked["bgp_state"], "down")
            with main.sqlite_connection() as check:
                changed = main.fetch_bgp_announcement(check, advertised["id"])
                untouched = main.fetch_bgp_announcement(check, sent_id)
                outcome = check.execute(
                    """
                    SELECT auto_mitigation_status, auto_mitigation_reason,
                           auto_mitigation_details_json, auto_mitigation_updated_at
                    FROM anomaly_events
                    WHERE id = ?
                    """,
                    (anomaly_id,),
                ).fetchone()
                summary = main.bgp_summary_payload(check)

            self.assertEqual(changed["status"], "peer_down")
            self.assertEqual(changed["peer_state"], "down")
            self.assertIn("indisponivel", changed["last_error"].lower())
            for key, value in original_timestamps.items():
                self.assertEqual(changed[key], value)
            self.assertIn("peer_down", [event["event_type"] for event in changed["events"]])
            self.assertEqual(untouched["status"], "sent")
            self.assertEqual(outcome["auto_mitigation_status"], "peer_down")
            self.assertEqual(outcome["auto_mitigation_reason"], "peer_bgp_down_after_advertisement")
            self.assertTrue(outcome["auto_mitigation_updated_at"])
            details = json.loads(outcome["auto_mitigation_details_json"])
            self.assertEqual(details["announcement_id"], advertised["id"])
            self.assertEqual(details["peer_state"], "down")
            self.assertEqual(summary["active_bgp_announcements"], 0)

    def test_peer_down_checker_does_not_overwrite_a_withdraw_claim(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            candidate = self._stage2_candidate(connector, profile, "withdraw-peer-race")
            policy = main.policy_for_candidate(candidate)
            validation = main.validate_mitigation_candidate(candidate, connector, profile)
            advertised = main.insert_bgp_mitigation_announcement(
                conn,
                candidate,
                connector,
                profile,
                policy,
                validation,
                "advertised",
                main.render_exabgp_flowspec_command("announce", candidate),
                "tester",
            )
            conn.commit()
            token = main.persist_bgp_withdraw_intent(
                conn,
                advertised["id"],
                "tester",
                "Retirada concorrente em teste.",
                expected_statuses={"advertised"},
            )
            down_status = self._readiness_result(
                connector,
                peer_state="down",
                ready=False,
                reason="peer_bgp_down",
            )["status"]
            down_status["flowspec_state"] = "down"

            changed = main.mark_connector_advertisements_peer_down(conn, connector, down_status)
            stored = main.fetch_bgp_announcement(conn, advertised["id"])

            self.assertEqual(changed, 0)
            self.assertEqual(stored["status"], "advertised")
            self.assertEqual(stored["confirmation_level"], "withdraw_requested")
            self.assertEqual(stored["status_details"]["withdraw_claim_token"], token)

    def test_unknown_peer_check_does_not_demote_advertised_announcement(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            now = main.utc_now_iso()
            announcement_id = conn.execute(
                """
                INSERT INTO bgp_announcements (
                    connector_id, status, route_type, response_type, action,
                    queued_at, sent_at, advertised_at, announced_at, last_attempt_at,
                    created_at, updated_at
                )
                VALUES (?, 'advertised', 'flowspec', 'flowspec', 'discard',
                        ?, ?, ?, ?, ?, ?, ?)
                """,
                (connector["id"], now, now, now, now, now, now, now),
            ).lastrowid
            conn.commit()
            conn.close()

            unknown_status = self._readiness_result(
                connector,
                peer_state="unknown",
                ready=False,
                reason="peer_bgp_not_verified",
            )["status"]
            unknown_status["flowspec_state"] = "unknown"
            with patch.object(main, "bgp_connector_status", return_value=unknown_status):
                checked = main.check_and_persist_bgp_connector_status(connector["id"])

            self.assertEqual(checked["bgp_state"], "unknown")
            with main.sqlite_connection() as check:
                item = main.fetch_bgp_announcement(check, announcement_id)
            self.assertEqual(item["status"], "advertised")
            self.assertNotIn("peer_down", [event["event_type"] for event in item["events"]])

    def test_router_check_disabled_keeps_pipe_check_without_inferring_peer_state(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            with tempfile.NamedTemporaryFile() as pipe_in, tempfile.NamedTemporaryFile() as pipe_out:
                conn.execute(
                    """
                    UPDATE bgp_connectors
                    SET router_check_enabled = 0, exabgp_pipe_in = ?, exabgp_pipe_out = ?
                    WHERE id = ?
                    """,
                    (pipe_in.name, pipe_out.name, connector["id"]),
                )
                conn.commit()
                conn.close()
                with patch.object(main, "router_ssh_command") as ssh_command, \
                     patch.object(main, "exabgp_peer_from_pipe", return_value={"state": "unknown"}), \
                     patch.object(main, "exabgp_peer_from_log_heuristic", return_value={"state": "unknown"}):
                    status = main.check_and_persist_bgp_connector_status(connector["id"])
            self.assertEqual(status["pipe_state"], "ok")
            self.assertEqual(status["bgp_state"], "not_verified")
            self.assertEqual(status["flowspec_state"], "not_verified")
            self.assertIn("desabilitada", status["message"].lower())
            ssh_command.assert_not_called()
            with main.sqlite_connection() as check:
                persisted = check.execute(
                    "SELECT bgp_state, flowspec_state, pipe_state, last_checked_at FROM bgp_connectors WHERE id = ?",
                    (connector["id"],),
                ).fetchone()
            self.assertEqual(persisted["bgp_state"], "not_verified")
            self.assertEqual(persisted["flowspec_state"], "not_verified")
            self.assertEqual(persisted["pipe_state"], "ok")
            self.assertTrue(persisted["last_checked_at"])

    def test_log_heuristic_never_authorizes_an_announcement(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            with tempfile.NamedTemporaryFile() as pipe_in, tempfile.NamedTemporaryFile() as pipe_out:
                connector.update(
                    {
                        "router_check_enabled": False,
                        "exabgp_pipe_in": pipe_in.name,
                        "exabgp_pipe_out": pipe_out.name,
                    }
                )
                with patch.object(main, "exabgp_peer_from_pipe", return_value={"state": "unknown", "source": "exabgp_pipe"}), \
                     patch.object(main, "exabgp_peer_from_log_heuristic", return_value={"state": "established", "source": "exabgp_log_heuristic"}), \
                     patch.object(main, "host_agent_status", return_value={"enabled": False}):
                    status = main.bgp_connector_status(connector)
            conn.close()
        self.assertEqual(status["bgp_state"], "not_verified")
        self.assertEqual(status["exabgp_peer"]["state"], "unknown")
        self.assertEqual(status["exabgp_log_peer"]["state"], "established")
        self.assertTrue(any("nao autoriza" in message for message in status["messages"]))

    def test_router_ssh_status_parses_bgp_and_flowspec_established(self):
        connector = {
            "router_check_enabled": True,
            "router_vendor": "huawei_vrp",
            "peer_ip": "192.0.2.2",
        }
        bgp_output = "192.0.2.2 4 65002 10 10 0 0 00:10:00 Established"
        flow_output = "BGP current state: Established\nPeer: 192.0.2.2"
        with patch.object(main, "router_ssh_command", side_effect=[(0, bgp_output), (0, flow_output)]) as command:
            status = main.router_ssh_status(connector)
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertEqual(command.call_args_list[0].args[1], "display bgp peer")
        self.assertEqual(command.call_args_list[1].args[1], "display bgp flow peer")

    def test_huawei_parser_does_not_treat_up_down_header_without_requested_peer_as_state(self):
        output = """
        BGP local router ID : 203.0.113.254
        Peer        V    AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv
        198.51.100.2 4 65002       10       10     0 00:10:00 Established       12
        """
        parsed = main.parse_huawei_vrp_peer_state(output, "192.0.2.2")
        self.assertEqual(parsed["state"], "unknown")
        self.assertEqual(parsed["peer_ip"], "192.0.2.2")

    def test_exabgp_parser_uses_only_the_requested_peer_line(self):
        output = "\n".join(
            [
                "neighbor 198.51.100.2 state established",
                "neighbor 192.0.2.2 state down",
            ]
        )
        requested = main.parse_exabgp_peer_state(output, "192.0.2.2")
        missing = main.parse_exabgp_peer_state(output, "203.0.113.2")
        self.assertEqual(requested["state"], "down")
        self.assertEqual(missing["state"], "unknown")

    def test_router_ssh_timeout_is_reported_and_persisted(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            conn.execute("UPDATE bgp_connectors SET router_check_enabled = 1 WHERE id = ?", (connector["id"],))
            conn.commit()
            conn.close()
            with patch.object(main, "router_ssh_command", return_value=(124, "ssh timeout")), \
                 patch.object(main, "host_agent_status", return_value={"enabled": False}), \
                 patch.object(main, "exabgp_peer_from_log_heuristic", return_value={"state": "unknown"}):
                status = main.check_and_persist_bgp_connector_status(connector["id"])
            self.assertEqual(status["bgp_state"], "not_verified")
            self.assertEqual(status["flowspec_state"], "not_verified")
            self.assertTrue(any("timeout" in error.lower() for error in status["errors"]))
            with main.sqlite_connection() as check:
                row = check.execute("SELECT status_errors_json FROM bgp_connectors WHERE id = ?", (connector["id"],)).fetchone()
            self.assertTrue(any("timeout" in error.lower() for error in json.loads(row["status_errors_json"])))

    def test_bgp_worker_continues_after_connector_failure(self):
        with temporary_main_db():
            conn, first, _profile = self._connector_and_profile()
            now = main.utc_now_iso()
            second_id = conn.execute(
                """
                INSERT INTO bgp_connectors (name, enabled, is_active, created_at, updated_at)
                VALUES ('SECOND', 1, 1, ?, ?)
                """,
                (now, now),
            ).lastrowid
            conn.commit()
            conn.close()
            finished = []

            def begin_connector(connector_id, owner=""):
                if connector_id == first["id"]:
                    raise RuntimeError("first failed")
                self.assertEqual(owner, "automatic")
                return {"connector": {"id": connector_id}}

            def finish_connector(execution):
                finished.append(execution["connector"]["id"])
                return {"connector_id": execution["connector"]["id"]}

            with patch.object(main, "begin_bgp_connector_status_check", side_effect=begin_connector), \
                 patch.object(main, "finish_bgp_connector_status_check", side_effect=finish_connector), \
                 patch.object(main, "bgp_active_status_check_count", return_value=0):
                result = main.run_bgp_connector_status_checks_once()
            self.assertEqual(result["failed"], 1)
            self.assertEqual(result["checked"], 1)
            self.assertEqual(finished, [second_id])

    def test_bgp_worker_rejects_concurrent_cycle(self):
        self.assertTrue(main.BGP_STATUS_CHECK_CYCLE_LOCK.acquire(blocking=False))
        try:
            result = main.run_bgp_connector_status_checks_once()
        finally:
            main.BGP_STATUS_CHECK_CYCLE_LOCK.release()
        self.assertTrue(result["concurrent"])
        self.assertEqual(result["skipped"], 1)

    def test_bgp_worker_shutdown_cancels_thread(self):
        main.stop_bgp_status_check_thread(timeout=0.1)
        with patch.dict(os.environ, {"GMJFLOW_BGP_AUTO_CHECK_ENABLED": "true"}), \
             patch.object(main, "bgp_check_interval_seconds", return_value=30), \
             patch.object(main, "run_bgp_connector_status_checks_once", return_value={"checked": 0}):
            main.start_bgp_status_check_thread()
            thread = main.BGP_STATUS_CHECK_THREAD
            self.assertIsNotNone(thread)
            self.assertTrue(thread.is_alive())
            main.stop_bgp_status_check_thread(timeout=1)
        self.assertTrue(main.BGP_STATUS_CHECK_STOP.is_set())
        self.assertFalse(thread.is_alive())
        self.assertIsNone(main.BGP_STATUS_CHECK_THREAD)

    def test_ai_pending_approval_is_registered_without_writing_pipe(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            profile = main.bgp_response_profile_row_to_dict(
                conn.execute("SELECT * FROM bgp_response_profiles WHERE name = 'FLOWSPEC_AUTO_BLOCK_DST_DNS'").fetchone()
            )
            calls = []
            payload = {
                "anomaly": {
                    "id": 51,
                    "vector_name": "DNS_INTERNAL_IP_HIGH_BITS",
                    "target_ip": "186.232.163.237",
                    "metric_unit": "bits_s",
                    "peak_value": 120_000_000,
                },
                "candidates": [
                    {
                        "candidate_index": 0,
                        "connector_id": connector["id"],
                        "response_profile_id": profile["id"],
                        "response_type": "flowspec",
                        "action": "discard",
                        "dst_prefix": "92.38.143.209/32",
                        "protocol": "udp",
                        "dst_port": "53",
                        "duration_seconds": 900,
                        "manual_approval_required": True,
                        "allow_auto": False,
                    }
                ],
            }
            response = {
                "recommended_candidate_index": 0,
                "manual_approval_required": True,
                "allow_auto": False,
                "reason": "Fallback deterministico: IA local falhou ou excedeu timeout.",
            }
            original_pipe = main.exabgp_write_pipe
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            try:
                item = main.persist_ai_pending_bgp_approval(conn, 51, payload, response, created_by="test-ai")
                conn.commit()
            finally:
                main.exabgp_write_pipe = original_pipe
                conn.close()
            self.assertIsNotNone(item)
            self.assertEqual(calls, [])
            self.assertEqual(item["status"], "pending_approval")
            self.assertEqual(item["anomaly_id"], 51)
            self.assertIn("announce flow route", item["announce_command"])
            with main.sqlite_connection() as check:
                row = check.execute("SELECT status, source, source_id FROM bgp_announcements WHERE anomaly_id = 51").fetchone()
            self.assertEqual(row["status"], "pending_approval")
            self.assertEqual(row["source"], "ai_mitigation")
            self.assertEqual(row["source_id"], "51")

    def test_manual_flowspec_insert_failure_before_announce_sends_nothing(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            conn.close()
            calls = []
            original_pipe = main.exabgp_write_pipe
            original_insert = main.insert_manual_flowspec_announcement
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            main.insert_manual_flowspec_announcement = lambda *_args, **_kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("insert failed"))
            try:
                response = main.test_bgp_connector_flowspec(
                    self._admin_request(),
                    connector["id"],
                    main.BgpFlowspecTestPayload(
                        action="announce",
                        dst_cidr="203.0.113.10",
                        protocol="udp",
                        dst_port="53",
                        duration_seconds=300,
                        confirm="ANUNCIAR",
                    ),
                )
            finally:
                main.exabgp_write_pipe = original_pipe
                main.insert_manual_flowspec_announcement = original_insert
            self.assertEqual(calls, [])
            self.assertEqual(response.status_code, 500)
            body = json.loads(response.body.decode("utf-8"))
            self.assertFalse(body["ok"])
            self.assertFalse(body["rollback_attempted"])

    def test_manual_flowspec_insert_failure_before_withdraw_sends_nothing(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            conn.close()
            with patch.object(main, "exabgp_write_pipe") as write_pipe, patch.object(
                main,
                "insert_manual_flowspec_announcement",
                side_effect=sqlite3.OperationalError("insert failed"),
            ):
                response = main.test_bgp_connector_flowspec(
                    self._admin_request(),
                    connector["id"],
                    main.BgpFlowspecTestPayload(
                        action="withdraw",
                        dst_cidr="203.0.113.10",
                        protocol="udp",
                        dst_port="53",
                        duration_seconds=300,
                    ),
                )
            self.assertEqual(response.status_code, 500)
            write_pipe.assert_not_called()
            with main.sqlite_connection() as check:
                self.assertEqual(check.execute("SELECT COUNT(*) FROM bgp_announcements").fetchone()[0], 0)

    def test_manual_flowspec_update_failure_after_announce_rolls_back_with_withdraw(self):
        class FailingSentTransitionConnection:
            def __init__(self, inner):
                self.inner = inner

            def __enter__(self):
                self.inner.__enter__()
                return self

            def __exit__(self, *exc):
                return self.inner.__exit__(*exc)

            def execute(self, sql, params=()):
                if (
                    "UPDATE bgp_announcements SET" in sql
                    and params
                    and params[0] == "sent"
                ):
                    raise sqlite3.OperationalError("sent transition failed")
                return self.inner.execute(sql, params)

            def __getattr__(self, name):
                return getattr(self.inner, name)

        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            conn.close()
            calls = []
            original_pipe = main.exabgp_write_pipe
            original_sqlite_connection = main.sqlite_connection
            main.exabgp_write_pipe = lambda _connector, command: calls.append(command)
            main.sqlite_connection = lambda: FailingSentTransitionConnection(original_sqlite_connection())
            try:
                response = main.test_bgp_connector_flowspec(
                    self._admin_request(),
                    connector["id"],
                    main.BgpFlowspecTestPayload(
                        action="announce",
                        dst_cidr="203.0.113.10",
                        protocol="udp",
                        dst_port="53",
                        duration_seconds=300,
                        confirm="ANUNCIAR",
                    ),
                )
            finally:
                main.exabgp_write_pipe = original_pipe
                main.sqlite_connection = original_sqlite_connection
            self.assertEqual(len(calls), 2)
            self.assertTrue(calls[0].startswith("announce flow route"))
            self.assertTrue(calls[1].startswith("withdraw flow route"))
            self.assertFalse(response["ok"])
            self.assertEqual(response["status"], "failed")
            self.assertIsNone(response["expires_at"])
            self.assertIn("withdraw compensatorio executado", response["last_error"])
            self.assertIn("announce_db_failure", [event["event_type"] for event in response["events"]])
            with main.sqlite_connection() as check:
                row = check.execute("SELECT status, last_error FROM bgp_announcements").fetchone()
            self.assertEqual(row["status"], "failed")
            self.assertIn("withdraw compensatorio executado", row["last_error"])

    def test_manual_lab_port_without_protocol_has_clear_error(self):
        with self.assertRaises(HTTPException) as ctx:
            main.flowspec_candidate_from_payload(
                main.BgpFlowspecTestPayload(action="dry_run", dst_cidr="75.131.245.200", protocol="", dst_port="53")
            )
        self.assertIn("Protocolo e obrigatorio quando porta e informada", str(ctx.exception.detail))

    def test_anomaly_list_response_contract_handles_empty_and_auto_only_outcomes(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            empty_id = self._insert_udp_many_anomaly_event(conn, event_id=3101)
            applied_id = self._insert_udp_many_anomaly_event(conn, event_id=3102, dst_ip="51.222.110.43")
            outcome_at = "2026-07-20T12:00:00Z"
            conn.execute(
                """
                UPDATE anomaly_events
                SET auto_mitigation_status = 'applied',
                    auto_mitigation_reason = 'Aplicado sem anuncio relacionado',
                    auto_mitigation_details_json = '{"origin":"manual"}',
                    auto_mitigation_updated_at = ?
                WHERE id = ?
                """,
                (outcome_at, applied_id),
            )
            conn.commit()
            conn.close()

            items = {item["id"]: item for item in main.anomaly_list("active", 20)}
            empty = items[empty_id]
            self.assertEqual(empty["response_status"], "")
            self.assertEqual(empty["response_reason"], "")
            self.assertEqual(empty["response_updated_at"], "")
            self.assertIsNone(empty["response_announcement"])
            self.assertEqual(empty["response_announcements"], [])

            applied = items[applied_id]
            self.assertEqual(applied["response_status"], "applied")
            self.assertEqual(applied["response_reason"], "Aplicado sem anuncio relacionado")
            self.assertEqual(applied["response_updated_at"], outcome_at)
            self.assertIsNone(applied["response_announcement"])
            self.assertEqual(applied["response_announcements"], [])

    def test_anomaly_list_exposes_principal_announcement_states(self):
        statuses = (
            "pending_approval",
            "queued",
            "sent",
            "advertised",
            "peer_down",
            "dry_run",
            "deduplicated",
            "rejected",
            "failed",
            "withdrawn",
            "expired",
        )
        with temporary_main_db():
            conn = main.sqlite_connection()
            expected = {}
            for offset, status in enumerate(statuses):
                anomaly_id = 3120 + offset
                self._insert_udp_many_anomaly_event(
                    conn,
                    event_id=anomaly_id,
                    dst_ip=f"51.222.111.{offset + 1}",
                )
                updated_at = f"2026-07-20T12:{offset:02d}:00Z"
                announcement_id = self._insert_response_announcement(
                    conn,
                    anomaly_id,
                    status,
                    updated_at,
                    expires_at="2099-01-01T00:00:00Z" if status == "advertised" else None,
                    dst_prefix=f"203.0.113.{offset + 1}/32",
                )
                conn.execute(
                    """
                    UPDATE anomaly_events
                    SET auto_mitigation_status = 'applied',
                        auto_mitigation_reason = 'Resultado persistido',
                        auto_mitigation_details_json = ?,
                        auto_mitigation_updated_at = '2026-07-20T11:00:00Z'
                    WHERE id = ?
                    """,
                    (json.dumps({"announcement_id": announcement_id}), anomaly_id),
                )
                expected[anomaly_id] = (status, announcement_id, updated_at)
            conn.commit()
            conn.close()

            items = {item["id"]: item for item in main.anomaly_list("active", 100)}
            for anomaly_id, (status, announcement_id, updated_at) in expected.items():
                with self.subTest(status=status):
                    item = items[anomaly_id]
                    self.assertEqual(item["response_status"], status)
                    self.assertEqual(item["response_reason"], "Resultado persistido")
                    self.assertEqual(item["response_updated_at"], updated_at)
                    self.assertEqual(item["response_announcement"]["id"], announcement_id)
                    self.assertEqual(
                        [announcement["id"] for announcement in item["response_announcements"]],
                        [announcement_id],
                    )

    def test_anomaly_list_uses_persisted_outcome_states_without_announcement(self):
        statuses = ("not_applied", "rejected_by_policy", "rejected", "deduplicated")
        with temporary_main_db():
            conn = main.sqlite_connection()
            expected = {}
            for offset, status in enumerate(statuses):
                anomaly_id = 3140 + offset
                self._insert_udp_many_anomaly_event(
                    conn,
                    event_id=anomaly_id,
                    dst_ip=f"51.222.113.{offset + 1}",
                )
                updated_at = f"2026-07-20T12:2{offset}:00Z"
                reason = f"outcome-{status}"
                conn.execute(
                    """
                    UPDATE anomaly_events
                    SET auto_mitigation_status = ?, auto_mitigation_reason = ?,
                        auto_mitigation_updated_at = ?
                    WHERE id = ?
                    """,
                    (status, reason, updated_at, anomaly_id),
                )
                expected[anomaly_id] = (status, reason, updated_at)
            conn.commit()
            conn.close()

            items = {item["id"]: item for item in main.anomaly_list("active", 20)}
            for anomaly_id, (status, reason, updated_at) in expected.items():
                with self.subTest(status=status):
                    item = items[anomaly_id]
                    self.assertEqual(item["response_status"], status)
                    self.assertEqual(item["response_reason"], reason)
                    self.assertEqual(item["response_updated_at"], updated_at)
                    self.assertIsNone(item["response_announcement"])
                    self.assertEqual(item["response_announcements"], [])

    def test_new_standalone_failure_outcome_wins_over_an_older_terminal_announcement(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            anomaly_id = self._insert_udp_many_anomaly_event(conn, event_id=3165)
            old_announcement_id = self._insert_response_announcement(
                conn,
                anomaly_id,
                "withdrawn",
                "2026-07-20T10:00:00Z",
            )
            conn.execute(
                """
                UPDATE anomaly_events
                SET auto_mitigation_status = 'not_applied',
                    auto_mitigation_reason = 'no_connector_resolved',
                    auto_mitigation_details_json = '{"origin":"manual","connector_id":null}',
                    auto_mitigation_updated_at = '2026-07-20T11:00:00Z'
                WHERE id = ?
                """,
                (anomaly_id,),
            )
            conn.commit()
            conn.close()

            item = next(item for item in main.anomaly_list("active", 20) if item["id"] == anomaly_id)

            self.assertEqual(item["response_status"], "not_applied")
            self.assertEqual(item["response_reason"], "no_connector_resolved")
            self.assertEqual(item["response_updated_at"], "2026-07-20T11:00:00Z")
            self.assertIsNone(item["response_announcement"])
            self.assertEqual([attempt["id"] for attempt in item["response_announcements"]], [old_announcement_id])
            self.assertTrue(item["response_outcome"]["standalone"])

    def test_operational_advertised_still_wins_over_a_newer_standalone_failure(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            anomaly_id = self._insert_udp_many_anomaly_event(conn, event_id=3166)
            advertised_id = self._insert_response_announcement(
                conn,
                anomaly_id,
                "advertised",
                "2026-07-20T10:00:00Z",
                expires_at="2099-01-01T00:00:00Z",
            )
            conn.execute(
                """
                UPDATE anomaly_events
                SET auto_mitigation_status = 'failed', auto_mitigation_reason = 'new_attempt_failed',
                    auto_mitigation_details_json = '{}', auto_mitigation_updated_at = '2026-07-20T11:00:00Z'
                WHERE id = ?
                """,
                (anomaly_id,),
            )
            conn.commit()
            conn.close()

            item = next(item for item in main.anomaly_list("active", 20) if item["id"] == anomaly_id)

            self.assertEqual(item["response_status"], "advertised")
            self.assertEqual(item["response_announcement"]["id"], advertised_id)
            self.assertEqual(item["response_reason"], "")

    def test_each_announcement_keeps_its_own_execution_origin(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            anomaly_id = self._insert_udp_many_anomaly_event(conn, event_id=3167)
            automatic_id = self._insert_response_announcement(conn, anomaly_id, "withdrawn", "2026-07-20T10:00:00Z")
            manual_id = self._insert_response_announcement(conn, anomaly_id, "failed", "2026-07-20T11:00:00Z")
            conn.execute(
                "UPDATE bgp_announcements SET requested_mode = 'automatic', created_by = 'worker' WHERE id = ?",
                (automatic_id,),
            )
            conn.execute(
                "UPDATE bgp_announcements SET requested_mode = 'announce_now', created_by = 'tester' WHERE id = ?",
                (manual_id,),
            )
            conn.execute(
                """
                UPDATE anomaly_events
                SET auto_mitigation_status = 'failed', auto_mitigation_reason = 'manual_failure',
                    auto_mitigation_details_json = ?, auto_mitigation_updated_at = '2026-07-20T11:00:00Z'
                WHERE id = ?
                """,
                (json.dumps({"announcement_id": manual_id, "origin": "manual"}), anomaly_id),
            )
            conn.commit()
            conn.close()

            item = next(item for item in main.anomaly_list("active", 20) if item["id"] == anomaly_id)
            attempts = {attempt["id"]: attempt for attempt in item["response_announcements"]}

            self.assertEqual(attempts[automatic_id]["response_origin"], "automatic")
            self.assertEqual(attempts[manual_id]["response_origin"], "manual")
            self.assertEqual(attempts[automatic_id]["reason"], "")
            self.assertEqual(attempts[manual_id]["reason"], "manual_failure")

    def test_anomaly_list_response_reason_falls_back_to_announcement_error(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            anomaly_id = self._insert_udp_many_anomaly_event(conn, event_id=3150)
            updated_at = "2026-07-20T13:00:00Z"
            self._insert_response_announcement(
                conn,
                anomaly_id,
                "failed",
                updated_at,
                last_error="Falha simulada de entrega",
            )
            conn.commit()
            conn.close()

            item = next(item for item in main.anomaly_list("active", 20) if item["id"] == anomaly_id)
            self.assertEqual(item["response_status"], "failed")
            self.assertEqual(item["response_reason"], "Falha simulada de entrega")
            self.assertEqual(item["response_updated_at"], updated_at)

    def test_anomaly_history_list_uses_the_same_response_contract(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            anomaly_id = self._insert_udp_many_anomaly_event(conn, event_id=3151)
            conn.execute("UPDATE anomaly_events SET status = 'closed' WHERE id = ?", (anomaly_id,))
            announcement_id = self._insert_response_announcement(
                conn,
                anomaly_id,
                "withdrawn",
                "2026-07-20T13:10:00Z",
            )
            conn.commit()
            conn.close()

            item = next(item for item in main.anomaly_list("history", 20) if item["id"] == anomaly_id)
            self.assertEqual(item["response_status"], "withdrawn")
            self.assertEqual(item["response_announcement"]["id"], announcement_id)
            self.assertEqual([announcement["id"] for announcement in item["response_announcements"]], [announcement_id])

    def test_anomaly_list_prioritizes_active_advertised_and_keeps_all_announcements(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            anomaly_id = self._insert_udp_many_anomaly_event(conn, event_id=3160)
            advertised_id = self._insert_response_announcement(
                conn,
                anomaly_id,
                "advertised",
                "2026-07-20T10:00:00Z",
                expires_at="2099-01-01T00:00:00Z",
                dst_prefix="203.0.113.10/32",
            )
            other_ids = {
                self._insert_response_announcement(conn, anomaly_id, "sent", "2026-07-20T11:00:00Z", dst_prefix="203.0.113.11/32"),
                self._insert_response_announcement(conn, anomaly_id, "queued", "2026-07-20T12:00:00Z", dst_prefix="203.0.113.12/32"),
                self._insert_response_announcement(conn, anomaly_id, "pending_approval", "2026-07-20T13:00:00Z", dst_prefix="203.0.113.13/32"),
                self._insert_response_announcement(conn, anomaly_id, "failed", "2026-07-20T14:00:00Z", dst_prefix="203.0.113.14/32"),
            }
            conn.commit()
            conn.close()

            item = next(item for item in main.anomaly_list("active", 20) if item["id"] == anomaly_id)
            self.assertEqual(item["response_status"], "advertised")
            self.assertEqual(item["response_announcement"]["id"], advertised_id)
            self.assertTrue(item["response_announcement"]["operationally_active"])
            self.assertEqual(
                {announcement["id"] for announcement in item["response_announcements"]},
                {advertised_id, *other_ids},
            )

    def test_primary_advertised_does_not_inherit_failure_reason_from_another_attempt(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            anomaly_id = self._insert_udp_many_anomaly_event(conn, event_id=3161)
            advertised_id = self._insert_response_announcement(
                conn,
                anomaly_id,
                "advertised",
                "2026-07-20T10:00:00Z",
                expires_at="2099-01-01T00:00:00Z",
            )
            failed_id = self._insert_response_announcement(
                conn,
                anomaly_id,
                "failed",
                "2026-07-20T11:00:00Z",
                last_error="pipe failure on second connector",
            )
            conn.execute(
                """
                UPDATE anomaly_events
                SET auto_mitigation_status = 'failed', auto_mitigation_reason = 'pipe failure on second connector',
                    auto_mitigation_details_json = ?, auto_mitigation_updated_at = '2026-07-20T11:00:00Z'
                WHERE id = ?
                """,
                (json.dumps({"announcement_id": failed_id}), anomaly_id),
            )
            conn.commit()
            conn.close()

            item = next(item for item in main.anomaly_list("active", 20) if item["id"] == anomaly_id)
            attempts = {attempt["id"]: attempt for attempt in item["response_announcements"]}
            self.assertEqual(item["response_status"], "advertised")
            self.assertEqual(item["response_announcement"]["id"], advertised_id)
            self.assertEqual(item["response_reason"], "")
            self.assertEqual(attempts[advertised_id]["reason"], "")
            self.assertEqual(attempts[failed_id]["reason"], "pipe failure on second connector")

    def test_anomaly_list_response_priority_uses_tiers_then_recency(self):
        with temporary_main_db():
            conn = main.sqlite_connection()

            sent_or_queued_id = self._insert_udp_many_anomaly_event(conn, event_id=3170)
            self._insert_response_announcement(conn, sent_or_queued_id, "sent", "2026-07-20T10:00:00Z")
            queued_id = self._insert_response_announcement(conn, sent_or_queued_id, "queued", "2026-07-20T11:00:00Z")
            self._insert_response_announcement(conn, sent_or_queued_id, "pending_approval", "2026-07-20T12:00:00Z")
            self._insert_response_announcement(conn, sent_or_queued_id, "failed", "2026-07-20T13:00:00Z")

            pending_id = self._insert_udp_many_anomaly_event(conn, event_id=3171, dst_ip="51.222.110.44")
            pending_announcement_id = self._insert_response_announcement(conn, pending_id, "pending_approval", "2026-07-20T10:00:00Z")
            self._insert_response_announcement(conn, pending_id, "failed", "2026-07-20T11:00:00Z")

            newest_id = self._insert_udp_many_anomaly_event(conn, event_id=3172, dst_ip="51.222.110.45")
            self._insert_response_announcement(conn, newest_id, "withdrawn", "2026-07-20T10:00:00Z")
            failed_id = self._insert_response_announcement(conn, newest_id, "failed", "2026-07-20T11:00:00Z")
            conn.commit()
            conn.close()

            items = {item["id"]: item for item in main.anomaly_list("active", 20)}
            self.assertEqual(items[sent_or_queued_id]["response_status"], "queued")
            self.assertEqual(items[sent_or_queued_id]["response_announcement"]["id"], queued_id)
            self.assertEqual(items[pending_id]["response_status"], "pending_approval")
            self.assertEqual(items[pending_id]["response_announcement"]["id"], pending_announcement_id)
            self.assertEqual(items[newest_id]["response_status"], "failed")
            self.assertEqual(items[newest_id]["response_announcement"]["id"], failed_id)

    def test_elapsed_ttl_advertised_remains_primary_until_withdraw_is_confirmed(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            anomaly_id = self._insert_udp_many_anomaly_event(conn, event_id=3180)
            sent_id = self._insert_response_announcement(
                conn,
                anomaly_id,
                "sent",
                "2026-07-20T10:00:00Z",
                dst_prefix="203.0.113.20/32",
            )
            expired_advertised_id = self._insert_response_announcement(
                conn,
                anomaly_id,
                "advertised",
                "2026-07-20T11:00:00Z",
                expires_at="2000-01-01T00:00:00Z",
                dst_prefix="203.0.113.21/32",
            )
            conn.commit()
            conn.close()

            item = next(item for item in main.anomaly_list("active", 20) if item["id"] == anomaly_id)
            self.assertEqual(item["response_status"], "advertised")
            self.assertEqual(item["response_announcement"]["id"], expired_advertised_id)
            expired = next(
                announcement
                for announcement in item["response_announcements"]
                if announcement["id"] == expired_advertised_id
            )
            self.assertTrue(expired["operationally_active"])
            self.assertTrue(expired["ttl_elapsed"])

    def test_anomaly_list_does_not_cross_associate_colliding_table_ids(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            shared_id = self._insert_udp_many_anomaly_event(conn, event_id=3190)
            self._insert_security_response_anomaly(conn, shared_id)
            anomaly_event_announcement_id = self._insert_response_announcement(
                conn,
                shared_id,
                "sent",
                "2026-07-20T10:00:00Z",
                anomaly_source="anomaly_events",
                dst_prefix="203.0.113.30/32",
            )
            security_announcement_id = self._insert_response_announcement(
                conn,
                shared_id,
                "pending_approval",
                "2026-07-20T11:00:00Z",
                anomaly_source="security_anomalies",
                dst_prefix="203.0.113.31/32",
            )
            raw_security = main.security_anomaly_row_to_dict(
                conn.execute("SELECT * FROM security_anomalies WHERE id = ?", (shared_id,)).fetchone()
            )
            conn.commit()
            conn.close()

            colliding = [item for item in main.anomaly_list("active", 20) if item["id"] == shared_id]
            self.assertEqual(len(colliding), 2)
            security = next(item for item in colliding if item.get("source") == "security_anomalies")
            anomaly_event = next(item for item in colliding if item.get("source") != "security_anomalies")
            self.assertEqual(security["response_status"], "pending_approval")
            self.assertEqual(security["response_announcement"]["id"], security_announcement_id)
            self.assertEqual([item["id"] for item in security["response_announcements"]], [security_announcement_id])
            self.assertEqual(anomaly_event["response_status"], "sent")
            self.assertEqual(anomaly_event["response_announcement"]["id"], anomaly_event_announcement_id)
            self.assertEqual([item["id"] for item in anomaly_event["response_announcements"]], [anomaly_event_announcement_id])
            self.assertLess(security["action_id"], 0)
            self.assertEqual(raw_security["action_id"], security["action_id"])
            self.assertEqual(anomaly_event.get("action_id") or anomaly_event["id"], shared_id)
            with main.sqlite_connection() as check:
                regular_context = main.fetch_anomaly_mitigation_context(check, shared_id)
                security_context = main.fetch_anomaly_mitigation_context(check, security["action_id"])
            self.assertNotIn("security_anomalies", regular_context)
            self.assertEqual(regular_context["event"]["top_dst_ip"], "51.222.110.42")
            self.assertEqual(security_context["event"]["source"], "security_anomalies")

    def test_negative_security_action_id_withdraws_its_positive_announcement(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            security_id = self._insert_security_response_anomaly(conn, 3195)
            raw_security = main.security_anomaly_row_to_dict(
                conn.execute("SELECT * FROM security_anomalies WHERE id = ?", (security_id,)).fetchone()
            )
            announcement_id = self._insert_response_announcement(
                conn,
                security_id,
                "advertised",
                "2026-07-20T10:00:00Z",
                anomaly_source="security_anomalies",
                expires_at="2099-01-01T00:00:00Z",
            )
            conn.execute(
                """
                UPDATE bgp_announcements
                SET connector_id = ?, connector_name = ?, withdraw_command = 'withdraw flow route SECURITY'
                WHERE id = ?
                """,
                (connector["id"], connector["name"], announcement_id),
            )
            conn.commit()
            conn.close()

            with patch.object(main, "exabgp_write_pipe") as write_pipe:
                result = main.withdraw_anomaly_mitigations(
                    self._admin_request(),
                    raw_security["action_id"],
                    main.BgpAnomalyMitigationWithdrawPayload(),
                )

            self.assertEqual(result["count"], 1)
            self.assertEqual(result["items"][0]["id"], announcement_id)
            self.assertEqual(result["items"][0]["status"], "withdrawn")
            write_pipe.assert_called_once()

    def test_legacy_from_anomaly_preview_links_negative_security_action_to_response(self):
        with temporary_main_db():
            conn, connector, profile = self._connector_and_profile()
            security_id = self._insert_security_response_anomaly(conn, 3196)
            raw_security = main.security_anomaly_row_to_dict(
                conn.execute("SELECT * FROM security_anomalies WHERE id = ?", (security_id,)).fetchone()
            )
            payload = main.BgpAnnouncementDryRunPayload(
                response_profile_id=profile["id"],
                duration_seconds=300,
            )

            candidate = main.candidate_from_anomaly(
                conn,
                raw_security["action_id"],
                payload,
                profile,
            )
            positive_id_candidate = main.candidate_from_anomaly(
                conn,
                security_id,
                payload,
                profile,
            )

            self.assertEqual(candidate["dst_prefix"], "198.51.100.210/32")
            self.assertEqual(candidate["protocol"], "udp")
            self.assertEqual(candidate["anomaly_id"], security_id)
            self.assertEqual(candidate["anomaly_source"], "security_anomalies")
            self.assertEqual(candidate["raw_payload"]["anomaly_id"], security_id)
            self.assertEqual(candidate["raw_payload"]["anomaly_action_id"], raw_security["action_id"])
            self.assertEqual(positive_id_candidate["anomaly_id"], security_id)
            self.assertEqual(positive_id_candidate["anomaly_source"], "security_anomalies")
            conn.close()

            item = main.create_bgp_dry_run_from_anomaly(
                self._admin_request(),
                raw_security["action_id"],
                main.BgpAnnouncementDryRunPayload(
                    response_profile_id=profile["id"],
                    connector_id=connector["id"],
                    duration_seconds=300,
                ),
            )

            self.assertEqual(item["anomaly_id"], security_id)
            self.assertEqual(item["anomaly_source"], "security_anomalies")
            self.assertTrue(item["mitigation_key"])
            security = next(
                event
                for event in main.anomaly_list("active", 20)
                if event.get("source") == "security_anomalies" and event["id"] == security_id
            )
            self.assertEqual(security["response_status"], "dry_run")
            self.assertEqual(security["response_announcement"]["id"], item["id"])

    def test_explicit_deduplicated_reference_does_not_steal_announcement_from_original_anomaly(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            original_anomaly_id = self._insert_udp_many_anomaly_event(conn, event_id=3191)
            deduplicated_anomaly_id = self._insert_udp_many_anomaly_event(
                conn,
                event_id=3192,
                dst_ip="51.222.110.46",
            )
            announcement_id = self._insert_response_announcement(
                conn,
                original_anomaly_id,
                "advertised",
                "2026-07-20T10:00:00Z",
                expires_at="2099-01-01T00:00:00Z",
                anomaly_source="anomaly_events",
                dst_prefix="203.0.113.40/32",
            )
            conn.execute(
                """
                UPDATE anomaly_events
                SET auto_mitigation_status = 'deduplicated',
                    auto_mitigation_reason = 'Resposta equivalente ja ativa',
                    auto_mitigation_details_json = ?,
                    auto_mitigation_updated_at = '2026-07-20T11:00:00Z'
                WHERE id = ?
                """,
                (json.dumps({"announcement_id": announcement_id}), deduplicated_anomaly_id),
            )
            conn.commit()
            conn.close()

            items = {item["id"]: item for item in main.anomaly_list("active", 20)}
            original = items[original_anomaly_id]
            deduplicated = items[deduplicated_anomaly_id]

            self.assertEqual(original["response_status"], "advertised")
            self.assertEqual(original["response_announcement"]["id"], announcement_id)
            self.assertEqual(
                [announcement["id"] for announcement in original["response_announcements"]],
                [announcement_id],
            )
            self.assertEqual(deduplicated["response_status"], "advertised")
            self.assertEqual(deduplicated["response_reason"], "Resposta equivalente ja ativa")
            self.assertEqual(deduplicated["response_announcement"]["id"], announcement_id)
            self.assertEqual(
                [announcement["id"] for announcement in deduplicated["response_announcements"]],
                [announcement_id],
            )

    def test_anomaly_list_loads_related_announcements_in_one_batch_query(self):
        with temporary_main_db():
            conn = main.sqlite_connection()
            for offset in range(3):
                anomaly_id = 3200 + offset
                self._insert_udp_many_anomaly_event(
                    conn,
                    event_id=anomaly_id,
                    dst_ip=f"51.222.112.{offset + 1}",
                )
                self._insert_response_announcement(
                    conn,
                    anomaly_id,
                    "pending_approval",
                    f"2026-07-20T12:0{offset}:00Z",
                )
            conn.commit()
            conn.close()

            traced_sql = []
            original_sqlite_connection = main.sqlite_connection

            def traced_connection():
                traced = original_sqlite_connection()
                traced.set_trace_callback(traced_sql.append)
                return traced

            with patch.object(main, "sqlite_connection", side_effect=traced_connection):
                items = main.anomaly_list("active", 20)

            self.assertEqual(len([item for item in items if 3200 <= item["id"] <= 3202]), 3)
            response_queries = [
                sql
                for sql in traced_sql
                if "bgp_announcements" in sql.lower()
                and sql.lstrip().lower().startswith(("select", "with"))
            ]
            self.assertEqual(
                len(response_queries),
                1,
                f"Esperava uma consulta em lote, recebeu: {response_queries}",
            )

    def test_anomaly_source_backfill_prefers_legacy_vector(self):
        source = main.anomaly_source_fields_from_row(
            {
                "id": 1,
                "attack_vector_id": 99,
                "legacy_attack_vector_id": 99,
                "vector_name": "DNS_QUERY_OUTBOUND_CLIENT",
                "rule_snapshot_json": "{}",
                "source_details_json": "{}",
            }
        )
        self.assertEqual(source["anomaly_source"], "legacy_attack_vector")
        self.assertEqual(source["source_engine"], "legacy_detector")
        self.assertEqual(source["source_name"], "DNS_QUERY_OUTBOUND_CLIENT")


    def test_readiness_requires_service_bgp_flowspec_and_pipe(self):
        status = {
            "service": {"active": True},
            "bgp_state": "established",
            "flowspec_state": "established",
            "pipes": {"ok": True, "status": "ok", "is_fifo": True, "reader_active": True},
            "session": {"tcp_established": True},
            "host_agent": {
                "evidence": {"source": "exabgp_journal", "last_connected_at": "2026-07-21T10:00:00Z"},
                "pipe": {"reader_active": True},
            },
        }
        readiness = main.evaluate_bgp_connector_readiness(status)
        self.assertTrue(readiness["ready"])
        self.assertEqual(readiness["confirmation_level"], "peer_established")
        self.assertEqual(readiness["details"]["host_agent_evidence"]["source"], "exabgp_journal")

    def test_established_bgp_without_flowspec_evidence_is_not_ready(self):
        status = {
            "service": {"active": True},
            "bgp_state": "established",
            "flowspec_state": "not_verified",
            "pipes": {"ok": True, "status": "ok", "is_fifo": True, "reader_active": True},
        }
        readiness = main.evaluate_bgp_connector_readiness(status)
        self.assertFalse(readiness["ready"])
        self.assertEqual(readiness["reason"], "flowspec_not_verified")
        self.assertEqual(readiness["confirmation_level"], "peer_established")
        self.assertIn("Familia FlowSpec nao confirmada", readiness["reason_message"])

    def test_readiness_uses_peer_specific_tcp_session_as_bgp_source_of_truth(self):
        status = {
            "service": {"active": True},
            "bgp_state": "not_verified",
            "flowspec_state": "established",
            "session": {"tcp_established": True},
            "exabgp_peer": {"state": "established"},
            "pipes": {"ok": True, "is_fifo": True, "reader_active": True},
        }
        readiness = main.evaluate_bgp_connector_readiness(status)
        self.assertTrue(readiness["ready"])
        self.assertTrue(readiness["bgp_ok"])
        self.assertEqual(readiness["confirmation_level"], "peer_established")

    def test_established_peer_with_unavailable_pipe_is_not_ready(self):
        status = {
            "service": {"active": True},
            "bgp_state": "established",
            "flowspec_state": "established",
            "pipes": {"ok": False, "status": "down", "is_fifo": True, "reader_active": False},
        }
        readiness = main.evaluate_bgp_connector_readiness(status)
        self.assertFalse(readiness["ready"])
        self.assertEqual(readiness["reason"], "exabgp_pipe_unavailable")

    def test_unverified_and_down_have_distinct_confirmation_levels_and_messages(self):
        base = {
            "service": {"active": True},
            "flowspec_state": "not_verified",
            "pipes": {"ok": True, "is_fifo": True, "reader_active": True},
        }
        unverified = main.evaluate_bgp_connector_readiness({**base, "bgp_state": "not_verified"})
        down = main.evaluate_bgp_connector_readiness({**base, "bgp_state": "down"})
        self.assertEqual(unverified["reason"], "peer_bgp_not_verified")
        self.assertEqual(unverified["confirmation_level"], "peer_not_verified")
        self.assertIn("nao confirmado", unverified["reason_message"])
        self.assertEqual(down["reason"], "peer_bgp_down")
        self.assertEqual(down["confirmation_level"], "peer_down")
        self.assertIn("indisponivel", down["reason_message"])

    def test_host_agent_request_includes_configured_exabgp_log_and_config_paths(self):
        connector = {
            "peer_ip": "45.5.249.0",
            "listen_port": 179,
            "systemd_service_name": "exabgp-gmj-flow.service",
            "exabgp_pipe_in": "/run/exabgp/gm-teste.in",
        }
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

            def read(self):
                return b'{"available": true}'

        def fake_urlopen(request, timeout=0):
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            return FakeResponse()

        with patch.object(main, "GMJFLOW_HOST_AGENT_URL", "http://127.0.0.1:18080"), \
             patch.object(main, "GMJFLOW_EXABGP_LOG_PATH", "/var/log/exabgp-gmj-flow.log"), \
             patch.object(main, "GMJFLOW_EXABGP_CONFIG_PATH", "/etc/exabgp/gmj-flow-ne8000.conf"), \
             patch.object(main.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = main.host_agent_status(connector)

        params = main.urllib.parse.parse_qs(main.urllib.parse.urlparse(captured["url"]).query)
        self.assertTrue(result["available"])
        self.assertEqual(params["log_path"], ["/var/log/exabgp-gmj-flow.log"])
        self.assertEqual(params["config_path"], ["/etc/exabgp/gmj-flow-ne8000.conf"])
        self.assertEqual(params["pipe_path"], ["/run/exabgp/gm-teste.in"])
        self.assertEqual(captured["timeout"], 5)

    def test_host_agent_confirmation_does_not_require_huawei_query(self):
        connector = {
            "id": 901,
            "name": "FIBINET",
            "role": "flowspec_mitigation",
            "backend_type": "exabgp",
            "peer_ip": "179.189.80.0",
            "listen_port": 179,
            "systemd_service_name": "exabgp-gmj-flow.service",
            "exabgp_pipe_in": "/run/exabgp/exabgp.in",
            "router_check_enabled": True,
        }
        agent = {
            "enabled": True,
            "available": True,
            "service": {"active": True, "raw": "active"},
            "listener": {"listening": True},
            "session": {"tcp_established": True},
            "bgp_state": "established",
            "flowspec_state": "established",
            "pipe": {
                "path": "/run/exabgp/exabgp.in",
                "exists": True,
                "is_fifo": True,
                "reader_active": True,
            },
            "evidence": {
                "source": "exabgp_journal + exabgp_config",
                "flowspec_evidence_source": "exabgp_config",
                "neighbor_found": True,
                "family_block_found": True,
                "ipv4_flow_configured": True,
            },
        }
        with patch.object(main, "host_agent_status", return_value=agent), \
             patch.object(main, "router_ssh_status") as router_status, \
             patch.object(main, "exabgp_pipe_status", return_value={"ok": False, "status": "down", "message": "local mount unavailable"}), \
             patch.object(main, "exabgp_peer_from_log_heuristic", return_value={"state": "unknown"}), \
             patch.object(main, "active_flowspec_announcement_count", return_value=0), \
             patch.object(main.shutil, "which", return_value=None):
            status = main.bgp_connector_status(connector)
        router_status.assert_not_called()
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertTrue(status["pipes"]["ok"])
        self.assertTrue(main.evaluate_bgp_connector_readiness(status)["ready"])

    def test_shared_service_fallback_makes_two_established_connectors_ready(self):
        with temporary_main_db():
            now = main.utc_now_iso()
            with main.sqlite_connection() as conn:
                connector_ids = []
                for name, peer, pipe_path, service in (
                    (
                        "BGP-FIBINET-BORDA",
                        "179.189.80.0",
                        "/run/exabgp/exabgp.in",
                        "exabgp-gmj-flow",
                    ),
                    (
                        "BGP-GM-BORDA",
                        "45.5.249.0",
                        "/run/exabgp/gm-teste.in",
                        "",
                    ),
                ):
                    connector_ids.append(
                        conn.execute(
                            """
                            INSERT INTO bgp_connectors (
                                name, role, backend_type, mode, peer_ip,
                                exabgp_config_path, exabgp_pipe_in,
                                systemd_service_name, enabled, is_active,
                                created_at, updated_at
                            )
                            VALUES (?, 'flowspec_mitigation', 'exabgp',
                                    'manual_approval', ?,
                                    '/etc/exabgp/gmj-flow-ne8000.conf', ?, ?,
                                    1, 1, ?, ?)
                            """,
                            (name, peer, pipe_path, service, now, now),
                        ).lastrowid
                    )
                conn.commit()

            def agent_status(connector):
                pipe_path = connector["exabgp_pipe_in"]
                return {
                    "enabled": True,
                    "available": True,
                    "service": {
                        "name": "exabgp-gmj-flow.service",
                        "active": True,
                        "raw": "active",
                    },
                    "listener": {"listening": True},
                    "session": {
                        "tcp_established": True,
                        "query_ok": True,
                        "close_wait_count": 0,
                        "close_wait_alert_threshold": 5,
                        "recv_q_max": 0,
                    },
                    "bgp_state": "established",
                    "flowspec_state": "established",
                    "pipe": {
                        "path": pipe_path,
                        "exists": True,
                        "is_fifo": True,
                        "reader_active": True,
                        "reader_waiting_for_writer": True,
                    },
                    "evidence": {
                        "neighbor_found": True,
                        "family_block_found": True,
                        "ipv4_flow_configured": True,
                    },
                }

            statuses = []
            with patch.object(main, "host_agent_status", side_effect=agent_status), \
                 patch.object(main, "exabgp_pipe_status", return_value={"ok": False, "status": "down", "message": "container sem mount"}), \
                 patch.object(main, "exabgp_peer_from_log_heuristic", return_value={"state": "unknown"}), \
                 patch.object(main, "active_flowspec_announcement_count", return_value=0), \
                 patch.object(main, "exabgp_write_pipe") as write_pipe, \
                 patch.object(main.shutil, "which", return_value=None):
                for connector_id in connector_ids:
                    connector = main.bgp_connector_for_status_check(connector_id)
                    statuses.append(main.bgp_connector_status(connector))
            write_pipe.assert_not_called()
            self.assertEqual(
                [status["pipes"]["input_path"] for status in statuses],
                ["/run/exabgp/exabgp.in", "/run/exabgp/gm-teste.in"],
            )
            for status in statuses:
                self.assertEqual(
                    status["service"]["name"],
                    "exabgp-gmj-flow.service",
                )
                self.assertTrue(status["service_ok"])
                self.assertTrue(status["listener_ok"])
                self.assertTrue(status["bgp_ok"])
                self.assertTrue(status["flowspec_ok"])
                self.assertTrue(status["pipe_ok"])
                self.assertTrue(status["readiness"]["ready"])
            self.assertTrue(statuses[1]["service"]["fallback_used"])
            self.assertEqual(
                statuses[1]["service"]["resolution_source"],
                "shared_connector",
            )

    def test_connector_save_defaults_shared_service_but_preserves_explicit_value(self):
        with temporary_main_db():
            payload = main.BgpConnectorPayload(
                name="BGP-GM-BORDA",
                role="flowspec_mitigation",
                backend_type="exabgp",
                mode="manual_approval",
                peer_ip="45.5.249.0",
                exabgp_config_path="/etc/exabgp/gmj-flow-ne8000.conf",
                exabgp_pipe_in="/run/exabgp/gm-teste.in",
                systemd_service_name="",
            )
            created = main.create_bgp_connector(self._admin_request(), payload)
            self.assertEqual(
                created["systemd_service_name"],
                "exabgp-gmj-flow",
            )
            explicit = main.BgpConnectorPayload(
                **{
                    **main.dump_model(payload),
                    "systemd_service_name": "custom-exabgp.service",
                }
            )
            updated = main.update_bgp_connector(
                self._admin_request(),
                created["id"],
                explicit,
            )
            self.assertEqual(
                updated["systemd_service_name"],
                "custom-exabgp.service",
            )

    def test_manual_recovery_is_audited_without_touching_announcements_or_fifo(self):
        with temporary_main_db():
            conn, connector, _profile = self._connector_and_profile()
            conn.execute(
                """
                UPDATE bgp_connectors
                SET systemd_service_name = 'exabgp-gmj-flow',
                    peer_ip = '179.189.80.0',
                    exabgp_pipe_in = '/run/exabgp/exabgp.in'
                WHERE id = ?
                """,
                (connector["id"],),
            )
            now = main.utc_now_iso()
            announcement_id = conn.execute(
                """
                INSERT INTO bgp_announcements (
                    connector_id, status, route_type, response_type, action,
                    announce_command, created_at, updated_at
                )
                VALUES (?, 'advertised', 'flowspec', 'flowspec', 'discard',
                        'announce flow route test', ?, ?)
                """,
                (connector["id"], now, now),
            ).lastrowid
            conn.commit()
            conn.close()
            agent_result = {
                "ok": True,
                "restart_attempted": True,
                "service": "exabgp-gmj-flow.service",
                "after": {
                    "session": {
                        "established_peers": ["179.189.80.0"],
                        "close_wait_count": 0,
                    }
                },
                "data_preserved": {
                    "database": True,
                    "history": True,
                    "fifos": True,
                    "announcements": True,
                },
            }
            with patch.object(
                main,
                "host_agent_recover_bgp_sessions",
                return_value=agent_result,
            ), patch.object(main, "exabgp_write_pipe") as write_pipe:
                result = main.recover_bgp_connector_sessions(
                    self._admin_request()
                )
            write_pipe.assert_not_called()
            self.assertTrue(result["ok"])
            self.assertTrue(result["audit_id"])
            with main.sqlite_connection() as check:
                announcement = check.execute(
                    "SELECT status, announce_command FROM bgp_announcements WHERE id = ?",
                    (announcement_id,),
                ).fetchone()
                audit = check.execute(
                    "SELECT action, service_name, details_json FROM bgp_admin_audit WHERE id = ?",
                    (result["audit_id"],),
                ).fetchone()
            self.assertEqual(announcement["status"], "advertised")
            self.assertEqual(
                announcement["announce_command"],
                "announce flow route test",
            )
            self.assertEqual(audit["action"], "recover_bgp_sessions")
            self.assertEqual(
                audit["service_name"],
                "exabgp-gmj-flow.service",
            )
            self.assertFalse(
                json.loads(audit["details_json"])["preservation_guarantee"][
                    "fifo_written"
                ]
            )


if __name__ == "__main__":
    unittest.main()
