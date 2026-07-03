import asyncio
import os
import json
import sqlite3
import sys
import tempfile
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
responses_stub.JSONResponse = type("JSONResponse", (), {"__init__": lambda self, *a, **k: None})
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

    def test_announce_command_has_no_ttl_and_expires_at_is_internal(self):
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
            self.assertTrue(item["expires_at"])

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

    def test_scheduler_expires_active_announcement_with_saved_withdraw(self):
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
                VALUES (?, ?, 'active', 'flowspec', 'flowspec', 'discard',
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

    def test_response_profile_status_connector_validation(self):
        with temporary_main_db():
            conn, _connector, profile = self._connector_and_profile()
            self.assertEqual(profile["connector_name"], "BGP-FIBINET-BORDA")
            self.assertEqual(profile["profile_status"], "valid")
            now = main.utc_now_iso()
            profile_id = conn.execute(
                """
                INSERT INTO bgp_response_profiles (
                    name, enabled, response_type, approval_mode, action, default_action,
                    target_selector, protocol_selector, created_at, updated_at
                )
                VALUES ('NO_CONNECTOR', 1, 'flowspec', 'manual_approval', 'discard', 'discard',
                        'dst_ip', 'anomaly_protocol', ?, ?)
                """,
                (now, now),
            ).lastrowid
            conn.commit()
            self.assertEqual(main.fetch_bgp_profile(conn, profile_id)["profile_status"], "invalid_connector")

    def test_response_profile_missing_connector_returns_clear_error(self):
        with temporary_main_db():
            conn, _connector, _profile = self._connector_and_profile()
            payload = main.BgpResponseProfilePayload(name="NO_CONNECTOR", response_type="flowspec")
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

            def validate_target(target: str, require_protected: bool, protected_cidr: str | None = None):
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
                    "direction": "outbound",
                    "top_src_ip": "198.51.100.10",
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
            self.assertEqual(outside_result["validation_status"], "target_not_in_protected_prefixes")
            self.assertIn("target_not_in_protected_prefixes", outside_result["errors"])
            self.assertIn("Destino 203.0.113.10/32 nao pertence a nenhum prefixo protegido habilitado.", outside_result["validation_messages"])

            disabled_requirement_result = validate_target("203.0.113.10", False)
            self.assertEqual(disabled_requirement_result["validation_status"], "valid")
            self.assertEqual(disabled_requirement_result["errors"], [])

            blocked_action_result = validate_target("8.8.4.4", True)
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

        payload = {
            "anomaly": {
                "id": -123,
                "target_ip": "203.0.113.10",
                "direction": "outbound",
                "decoder": "IP",
                "severity": "high",
            }
        }
        with patch.object(main, "ai_effective_config", return_value={"enabled": True, "selected_model": "", "timeout_seconds": 10, "max_context_chars": 1000, "max_top_flows": 10, "keep_alive": "30m"}):
            with patch.object(main, "JSONResponse", _JSONResponseStub):
                response = asyncio.run(main.draft_anomaly_ai_analysis(_RequestStub(payload), -123))
        self.assertTrue(response["draft"])
        self.assertFalse(response["persisted"])
        self.assertEqual(response["response"]["recommended_candidate"], "alert_only")
        self.assertEqual(response["response"]["evidence_status"], "insufficient")

        empty_payload = {}
        with patch.object(main, "ai_effective_config", return_value={"enabled": True, "selected_model": "", "timeout_seconds": 10, "max_context_chars": 1000, "max_top_flows": 10, "keep_alive": "30m"}):
            with patch.object(main, "JSONResponse", _JSONResponseStub):
                response = asyncio.run(main.draft_anomaly_ai_analysis(_RequestStub(empty_payload), -123))
        self.assertEqual(response.status_code, 400)
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

    def test_automatic_runner_does_not_call_automatic_announce(self):
        source = Path(ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        start = source.find("def process_anomaly_mitigation")
        end = source.find("def anomaly_detection_enabled")
        self.assertNotIn('"automatic", "worker"', source[start:end])
        self.assertNotIn("'automatic', 'worker'", source[start:end])

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
            self.assertIn("destination 75.131.245.200/32; protocol udp; destination-port =53", main.render_exabgp_flowspec_command("announce", candidates[0]))
            self.assertNotEqual(candidates[0].get("candidate_role"), "not_recommended")

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
            self.assertEqual(command, "announce flow route { match { destination 75.131.245.200/32; protocol udp; destination-port =53; } then { discard; } }")
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
            self.assertIn("announce flow route", item["announce_command"])
            self.assertIn("withdraw flow route", item["withdraw_command"])
            self.assertNotIn("ttl", item["announce_command"].lower())
            with main.sqlite_connection() as check:
                count = check.execute("SELECT COUNT(*) AS count FROM bgp_announcements").fetchone()["count"]
            self.assertEqual(count, 0)

    def test_manual_flowspec_announce_saves_all_columns_and_active_ttl(self):
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
                        action="announce",
                        dst_cidr="203.0.113.10",
                        protocol="udp",
                        dst_port="53",
                        duration_seconds=300,
                        confirm="ANUNCIAR",
                    ),
                )
            finally:
                main.exabgp_write_pipe = original
            self.assertEqual(len(main.MANUAL_FLOWSPEC_ANNOUNCEMENT_COLUMNS), 41)
            self.assertEqual(calls, [item["announce_command"]])
            self.assertEqual(item["status"], "active")
            self.assertTrue(item["announced_at"])
            self.assertTrue(item["expires_at"])
            self.assertNotIn("ttl", item["announce_command"].lower())
            self.assertNotIn("duration", item["announce_command"].lower())
            with main.sqlite_connection() as check:
                row = check.execute("SELECT status, expires_at, announce_command, withdraw_command FROM bgp_announcements").fetchone()
            self.assertEqual(row["status"], "active")
            self.assertTrue(row["expires_at"])
            self.assertEqual(row["announce_command"], item["announce_command"])
            self.assertEqual(row["withdraw_command"], item["withdraw_command"])

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

    def test_manual_flowspec_update_failure_after_announce_rolls_back_with_withdraw(self):
        class FailingActiveUpdateConnection:
            def __init__(self, inner):
                self.inner = inner

            def __enter__(self):
                self.inner.__enter__()
                return self

            def __exit__(self, *exc):
                return self.inner.__exit__(*exc)

            def execute(self, sql, params=()):
                if "UPDATE bgp_announcements" in sql and "status = 'active'" in sql:
                    raise sqlite3.OperationalError("active update failed")
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
            main.sqlite_connection = lambda: FailingActiveUpdateConnection(original_sqlite_connection())
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
            self.assertEqual(response.status_code, 500)
            body = json.loads(response.body.decode("utf-8"))
            self.assertFalse(body["ok"])
            self.assertTrue(body["rollback_attempted"])
            self.assertTrue(body["rollback_success"])
            with main.sqlite_connection() as check:
                row = check.execute("SELECT status, last_error FROM bgp_announcements").fetchone()
            self.assertEqual(row["status"], "failed")
            self.assertIn("rollback withdraw executado", row["last_error"])

    def test_manual_lab_port_without_protocol_has_clear_error(self):
        with self.assertRaises(HTTPException) as ctx:
            main.flowspec_candidate_from_payload(
                main.BgpFlowspecTestPayload(action="dry_run", dst_cidr="75.131.245.200", protocol="", dst_port="53")
            )
        self.assertIn("Protocolo e obrigatorio quando porta e informada", str(ctx.exception.detail))

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


if __name__ == "__main__":
    unittest.main()
