"""Persistence tests for the single-owner configuration model.

effective_value = persistent_setting(DB) AND NOT environment_kill_switch

Covers the required scenarios A-K without fastapi installed (stubbed import of
backend.app.main, same pattern used by the other static/behavioural tests).
"""

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))


class _FastAPI:
    def __init__(self, *args, **kwargs):
        pass

    def add_middleware(self, *args, **kwargs):
        return None

    def include_router(self, *args, **kwargs):
        return None

    def get(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator

    def post(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator

    def put(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator

    def patch(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator

    def delete(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator

    def middleware(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator

    def on_event(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator

    def api_route(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator


class _HTTPException(Exception):
    def __init__(self, status_code=200, detail=None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _Query:
    def __init__(self, default=None, **kwargs):
        self.default = default


class _Request:
    pass


class _BaseModel:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def dict(self):
        return self.__dict__.copy()

    def model_dump(self):
        return self.__dict__.copy()


class _Field:
    def __init__(self, default=None, **kwargs):
        self.default = default


class _CryptContext:
    def __init__(self, *args, **kwargs):
        pass

    def hash(self, value):
        return f"test-hash:{value}"

    def verify(self, value, hashed):
        return hashed == f"test-hash:{value}"


class _JSONResponse:
    def __init__(self, content=None, status_code=200):
        self.content = content
        self.status_code = status_code


class _Response:
    def __init__(self, content=None, status_code=200):
        self.content = content
        self.status_code = status_code


fastapi_module = types.ModuleType("fastapi")
fastapi_module.FastAPI = _FastAPI
fastapi_module.HTTPException = _HTTPException
fastapi_module.Query = _Query
fastapi_module.Request = _Request
sys.modules.setdefault("fastapi", fastapi_module)

fastapi_cors_module = types.ModuleType("fastapi.middleware.cors")
fastapi_cors_module.CORSMiddleware = type("CORSMiddleware", (), {})
sys.modules.setdefault("fastapi.middleware.cors", fastapi_cors_module)

jose_module = types.ModuleType("jose")
jose_module.JWTError = type("JWTError", (Exception,), {})
jose_module.jwt = types.SimpleNamespace(decode=lambda *args, **kwargs: {})
sys.modules.setdefault("jose", jose_module)

passlib_module = types.ModuleType("passlib")
passlib_context_module = types.ModuleType("passlib.context")
passlib_context_module.CryptContext = _CryptContext
sys.modules.setdefault("passlib", passlib_module)
sys.modules.setdefault("passlib.context", passlib_context_module)

starlette_module = types.ModuleType("starlette")
starlette_responses_module = types.ModuleType("starlette.responses")
starlette_responses_module.JSONResponse = _JSONResponse
starlette_responses_module.Response = _Response
sys.modules.setdefault("starlette", starlette_module)
sys.modules.setdefault("starlette.responses", starlette_responses_module)

pydantic_module = types.ModuleType("pydantic")
pydantic_module.BaseModel = _BaseModel
pydantic_module.Field = _Field
sys.modules.setdefault("pydantic", pydantic_module)

clickhouse_connect_module = types.ModuleType("clickhouse_connect")
clickhouse_connect_module.get_client = lambda *args, **kwargs: None
sys.modules.setdefault("clickhouse_connect", clickhouse_connect_module)


class _InvalidToken(Exception):
    pass


class _FakeFernet:
    def __init__(self, key=None):
        self.key = key

    @staticmethod
    def generate_key():
        return b"f" * 44

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        return b"fernet:v1:" + data

    def decrypt(self, token):
        if isinstance(token, str):
            token = token.encode("utf-8")
        if token.startswith(b"fernet:v1:"):
            return token[len(b"fernet:v1:"):]
        raise _InvalidToken()


cryptography_module = types.ModuleType("cryptography")
cryptography_fernet_module = types.ModuleType("cryptography.fernet")
cryptography_fernet_module.Fernet = _FakeFernet
cryptography_fernet_module.InvalidToken = _InvalidToken
sys.modules.setdefault("cryptography", cryptography_module)
sys.modules.setdefault("cryptography.fernet", cryptography_fernet_module)

mitigation_module = types.ModuleType("app.api.mitigation")
mitigation_module.router = object()
sys.modules.setdefault("app.api.mitigation", mitigation_module)

peak_hunter_module = types.ModuleType("app.api.peak_hunter")
peak_hunter_module.router = object()
sys.modules.setdefault("app.api.peak_hunter", peak_hunter_module)

humanize_module = types.ModuleType("app.services.humanize")
humanize_module.format_bits_per_second = lambda *args, **kwargs: ""
humanize_module.format_bytes = lambda *args, **kwargs: ""
humanize_module.format_flows = lambda *args, **kwargs: ""
humanize_module.format_packets = lambda *args, **kwargs: ""
humanize_module.format_packets_per_second = lambda *args, **kwargs: ""
humanize_module.format_pdf_metric = lambda *args, **kwargs: ""
sys.modules.setdefault("app.services.humanize", humanize_module)

clickhouse_service_module = types.ModuleType("app.services.clickhouse")
clickhouse_service_module.fetch_learning_traffic_series = lambda *args, **kwargs: []
sys.modules.setdefault("app.services.clickhouse", clickhouse_service_module)

peak_hunter_service_module = types.ModuleType("app.services.peak_hunter")
peak_hunter_service_module.ensure_peak_analysis_db = lambda *args, **kwargs: None
sys.modules.setdefault("app.services.peak_hunter", peak_hunter_service_module)

peak_hunter_runner_module = types.ModuleType("app.services.peak_hunter_runner")
peak_hunter_runner_module.ensure_peak_hunter_automation_db = lambda *args, **kwargs: None
peak_hunter_runner_module.mark_peak_hunter_scheduler_started = lambda *args, **kwargs: None
peak_hunter_runner_module.mark_peak_hunter_scheduler_stopped = lambda *args, **kwargs: None
peak_hunter_runner_module.run_due_peak_hunter_jobs = lambda *args, **kwargs: None
sys.modules.setdefault("app.services.peak_hunter_runner", peak_hunter_runner_module)

from backend.app import main as backend_main  # noqa: E402
from app.services import config_effective as ce  # noqa: E402
from app.services import ai_integration as ai  # noqa: E402
from app.services.security_event_ai import security_ai_config  # noqa: E402


class ConfigPersistenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "gmjflow.db"
        self.env_patch = mock.patch.dict(
            os.environ,
            {"GMJFLOW_DB_PATH": str(self.db_path)},
            clear=False,
        )
        self.env_patch.start()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.tmp.cleanup()

    def _conn(self):
        return backend_main.sqlite_connection()

    def _ensure(self, conn):
        backend_main.ensure_system_settings_table(conn)
        return conn

    def _setting(self, key):
        with self._conn() as conn:
            return backend_main.get_system_settings(conn).get(key)

    # --- A / B: configured value survives restart and recreate ---
    def test_configured_true_survives_restart(self) -> None:
        with self._conn() as conn:
            self._ensure(conn)
            backend_main.set_system_settings(conn, {"auto_mitigation_enabled": "true"})
            conn.commit()
        # "restart": fresh connection + ensure (startup path) must not reset.
        with self._conn() as conn:
            self._ensure(conn)
            self.assertEqual(backend_main.get_system_settings(conn)["auto_mitigation_enabled"], "true")

    def test_configured_true_survives_recreate(self) -> None:
        with self._conn() as conn:
            self._ensure(conn)
            backend_main.set_system_settings(conn, {"auto_mitigation_enabled": "true"})
            conn.commit()
        # "recreate": brand new connection, same persisted file, ensure again.
        with self._conn() as conn:
            self._ensure(conn)
            self.assertEqual(backend_main.get_system_settings(conn)["auto_mitigation_enabled"], "true")

    # --- E: DB value is not overwritten at startup ---
    def test_db_value_not_overwritten_on_startup(self) -> None:
        with self._conn() as conn:
            self._ensure(conn)
            backend_main.set_system_settings(conn, {"auto_mitigation_enabled": "true"})
            conn.commit()
        with mock.patch.dict(os.environ, {"GMJFLOW_AUTO_MITIGATION_ENABLED": "false"}, clear=False):
            with self._conn() as conn:
                self._ensure(conn)
                self.assertEqual(backend_main.get_system_settings(conn)["auto_mitigation_enabled"], "true")

    # --- F: legacy env explicitly set -> one-shot import ---
    def test_legacy_env_explicit_import(self) -> None:
        with mock.patch.dict(os.environ, {"GMJFLOW_AUTO_MITIGATION_ENABLED": "true"}, clear=False):
            with self._conn() as conn:
                self._ensure(conn)
                self.assertEqual(backend_main.get_system_settings(conn)["auto_mitigation_enabled"], "true")

    # --- G: legacy env absent -> fail-safe default ---
    def test_legacy_env_absent_fail_safe(self) -> None:
        os.environ.pop("GMJFLOW_AUTO_MITIGATION_ENABLED", None)
        with self._conn() as conn:
            self._ensure(conn)
            self.assertEqual(backend_main.get_system_settings(conn)["auto_mitigation_enabled"], "false")

    # --- I: auto mitigation stays OFF during migration ---
    def test_auto_mitigation_stays_off_during_migration(self) -> None:
        os.environ.pop("GMJFLOW_AUTO_MITIGATION_ENABLED", None)
        os.environ.pop("GMJFLOW_AUTO_MITIGATION_KILL_SWITCH", None)
        with self._conn() as conn:
            self._ensure(conn)
            self.assertEqual(backend_main.get_system_settings(conn)["auto_mitigation_enabled"], "false")
        self.assertFalse(backend_main.automatic_mitigation_worker_enabled())

    # --- C: kill switch ON -> effective false (preference preserved) ---
    def test_kill_switch_blocks_effective(self) -> None:
        with self._conn() as conn:
            self._ensure(conn)
            backend_main.set_system_settings(conn, {"auto_mitigation_enabled": "true"})
            conn.commit()
        with mock.patch.dict(os.environ, {"GMJFLOW_AUTO_MITIGATION_KILL_SWITCH": "true"}, clear=False):
            with self._conn() as conn:
                effective = ce.auto_mitigation_effective(conn)
            self.assertTrue(effective["configured"])
            self.assertTrue(effective["kill_switch"])
            self.assertFalse(effective["effective"])
            self.assertEqual(effective["reason"], "disabled_by_kill_switch")
            self.assertFalse(backend_main.automatic_mitigation_worker_enabled())

    # --- D: remove kill switch -> effective true again ---
    def test_kill_switch_removed_restores_effective(self) -> None:
        with self._conn() as conn:
            self._ensure(conn)
            backend_main.set_system_settings(conn, {"auto_mitigation_enabled": "true"})
            conn.commit()
        with mock.patch.dict(os.environ, {"GMJFLOW_AUTO_MITIGATION_KILL_SWITCH": "true"}, clear=False):
            with self._conn() as conn:
                self.assertFalse(ce.auto_mitigation_effective(conn)["effective"])
        os.environ.pop("GMJFLOW_AUTO_MITIGATION_KILL_SWITCH", None)
        with self._conn() as conn:
            effective = ce.auto_mitigation_effective(conn)
        self.assertTrue(effective["effective"])
        self.assertEqual(effective["reason"], "enabled")

    # --- H: Security AI route enabled survives restart ---
    def test_security_ai_route_survives_restart(self) -> None:
        with self._conn() as conn:
            ai.ensure_ai_schema(conn, {})
            provider = ai.save_ai_provider(
                conn,
                {"name": "P", "provider_type": "ollama", "enabled": True, "base_url": "http://p", "default_model": "m"},
                "test",
            )
            ai.save_ai_route(
                conn,
                "security_event_analysis",
                {"enabled": True, "primary_provider_id": provider["id"], "primary_model": "m", "require_structured": True},
                "test",
            )
            ai.update_global_ai_settings(conn, {"global_enabled": True}, "test")
            conn.commit()
        with self._conn() as conn:
            ai.ensure_ai_schema(conn, {})
            routes = {item["function_key"]: item for item in ai.list_ai_routes(conn)}
            self.assertTrue(routes["security_event_analysis"]["enabled"])

    def test_security_ai_effective_respects_kill_switch(self) -> None:
        with self._conn() as conn:
            ai.ensure_ai_schema(conn, {})
            provider = ai.save_ai_provider(
                conn,
                {"name": "P", "provider_type": "ollama", "enabled": True, "base_url": "http://p", "default_model": "m"},
                "test",
            )
            ai.save_ai_route(
                conn,
                "security_event_analysis",
                {"enabled": True, "primary_provider_id": provider["id"], "primary_model": "m", "require_structured": True},
                "test",
            )
            ai.update_global_ai_settings(conn, {"global_enabled": True}, "test")
            conn.commit()
            self.assertTrue(security_ai_config(conn, "security_event_analysis")["enabled"])
        with mock.patch.dict(os.environ, {"GMJFLOW_SECURITY_AI_KILL_SWITCH": "true"}, clear=False):
            with self._conn() as conn:
                config = security_ai_config(conn, "security_event_analysis")
            self.assertFalse(config["enabled"])
            self.assertTrue(config["kill_switch"])

    # --- F (preflight fix): bgp_observability reflects real Host Agent availability ---
    def test_host_agent_preflight_unverified_without_config(self) -> None:
        with mock.patch.dict(os.environ, {"GMJFLOW_HOST_AGENT_URL": "", "GMJFLOW_HOST_AGENT_TOKEN": ""}, clear=False):
            self.assertEqual(backend_main.host_agent_preflight()["status"], "unverified")

    def test_host_agent_preflight_ok_when_reachable(self) -> None:
        with mock.patch.dict(os.environ, {"GMJFLOW_HOST_AGENT_URL": "http://172.18.0.1:18080", "GMJFLOW_HOST_AGENT_TOKEN": "t"}, clear=False):
            with mock.patch("urllib.request.urlopen") as urlopen:
                context = mock.MagicMock()
                context.__enter__.return_value = mock.MagicMock(status=200)
                urlopen.return_value = context
                result = backend_main.host_agent_preflight()
        self.assertEqual(result["status"], "ok")

    def test_host_agent_preflight_degraded_when_unreachable(self) -> None:
        with mock.patch.dict(os.environ, {"GMJFLOW_HOST_AGENT_URL": "http://172.18.0.1:18080", "GMJFLOW_HOST_AGENT_TOKEN": "t"}, clear=False):
            with mock.patch("urllib.request.urlopen", side_effect=Exception("down")):
                result = backend_main.host_agent_preflight()
        self.assertEqual(result["status"], "degraded")

    # --- J: project dir wrong is detected in preflight ---
    def test_preflight_detects_missing_project_dir(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"GMJFLOW_PROJECT_DIR": "", "GMJFLOW_COLLECTORS_DIR": ""},
            clear=False,
        ):
            report = backend_main.collect_preflight_report()
        self.assertEqual(report["collector_management"]["status"], "blocked")

    # --- K: missing sensor config blocks only that sensor/component ---
    def test_preflight_sensor_missing_blocks_only_that_sensor(self) -> None:
        coll_dir = Path(self.tmp.name) / "collectors"
        (coll_dir / "sensor-1").mkdir(parents=True)
        (coll_dir / "sensor-1" / "nfacctd.conf").write_text("conf", encoding="utf-8")
        (coll_dir / "sensor-1" / "allow.lst").write_text("allow", encoding="utf-8")
        with mock.patch.dict(
            os.environ,
            {"GMJFLOW_PROJECT_DIR": "/valid/host/dir", "GMJFLOW_COLLECTORS_DIR": str(coll_dir)},
            clear=False,
        ):
            report = backend_main.collect_preflight_report()
        self.assertEqual(report["collector_management"]["status"], "ok")
        self.assertEqual(report["sensor_1"]["status"], "ok")
        self.assertEqual(report["sensor_2"]["status"], "blocked")


class MitigationLeaseTest(unittest.TestCase):
    """Lease vs hard-cap semantics for DNS_SINGLE_FLOW_OUTBOUND (no real announce)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "lease.db"
        self.env_patch = mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": str(self.db_path)}, clear=False)
        self.env_patch.start()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.tmp.cleanup()

    def _ensure_announcement_tables(self, conn) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS bgp_connectors (id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS bgp_response_profiles (id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS bgp_announcements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connector_id INTEGER,
                response_profile_id INTEGER,
                mitigation_key TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'advertised',
                dst_ip TEXT NOT NULL DEFAULT '',
                dst_prefix TEXT NOT NULL DEFAULT '',
                target_prefix TEXT NOT NULL DEFAULT '',
                protocol TEXT NOT NULL DEFAULT '',
                dst_port TEXT NOT NULL DEFAULT '',
                duration_seconds INTEGER NOT NULL DEFAULT 0,
                expires_at TEXT,
                sent_at TEXT,
                advertised_at TEXT,
                announced_at TEXT,
                confirmation_level TEXT NOT NULL DEFAULT 'registered',
                created_at TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS bgp_announcement_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                announcement_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}',
                created_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            """
        )
        conn.commit()

    @staticmethod
    def dns_profile(**overrides) -> dict:
        profile = {
            "initial_lease_seconds": 3600,
            "recurrence_lease_seconds": 86400,
            "max_lifetime_seconds": None,
            "recurrence_renewal_enabled": 1,
            "default_duration_seconds": 3600,
        }
        profile.update(overrides)
        return profile

    @staticmethod
    def dns_candidate(**overrides) -> dict:
        candidate = {
            "attack_vector_name": "DNS_SINGLE_FLOW_OUTBOUND",
            "vector": "DNS_SINGLE_FLOW_OUTBOUND",
            "mitigation_scope": "destination_dns_udp53",
            "protocol": "udp",
            "dst_port": "53",
            "dst_ip": "203.0.113.53",
        }
        candidate.update(overrides)
        return candidate

    def test_A_initial_lease_is_3600(self) -> None:
        self.assertEqual(backend_main.mitigation_initial_lease_seconds(self.dns_profile()), 3600)

    def test_B_recurrence_lease_is_86400(self) -> None:
        self.assertEqual(backend_main.mitigation_recurrence_lease_seconds(self.dns_profile()), 86400)

    def test_B_recurrence_lease_falls_back_to_initial(self) -> None:
        profile = self.dns_profile(recurrence_lease_seconds=None)
        self.assertEqual(backend_main.mitigation_recurrence_lease_seconds(profile), 3600)

    def test_K_max_lifetime_unlimited_is_none(self) -> None:
        self.assertIsNone(backend_main.mitigation_max_lifetime_seconds(self.dns_profile()))
        self.assertEqual(backend_main.mitigation_max_lifetime_seconds(self.dns_profile(max_lifetime_seconds=7200)), 7200)

    def test_G_same_ip_different_port_is_not_recurrence(self) -> None:
        active = {"dst_ip": "203.0.113.53", "protocol": "udp", "dst_port": "53"}
        candidate = self.dns_candidate(dst_port="5353")
        self.assertFalse(backend_main.is_dns_single_flow_recurrence(candidate, active))

    def test_H_same_ip_different_protocol_is_not_recurrence(self) -> None:
        active = {"dst_ip": "203.0.113.53", "protocol": "udp", "dst_port": "53"}
        candidate = self.dns_candidate(protocol="tcp")
        self.assertFalse(backend_main.is_dns_single_flow_recurrence(candidate, active))

    def test_I_same_ip_udp53_different_vector_is_not_recurrence(self) -> None:
        active = {"dst_ip": "203.0.113.53", "protocol": "udp", "dst_port": "53"}
        candidate = self.dns_candidate(attack_vector_name="UDP_FLOOD", vector="UDP_FLOOD")
        self.assertFalse(backend_main.is_dns_single_flow_recurrence(candidate, active))

    def test_recurrence_is_true_for_exact_match(self) -> None:
        active = {"dst_ip": "203.0.113.53", "protocol": "udp", "dst_port": "53"}
        self.assertTrue(backend_main.is_dns_single_flow_recurrence(self.dns_candidate(), active))

    def test_J_extension_updates_expires_and_audits(self) -> None:
        conn = backend_main.sqlite_connection()
        try:
            self._ensure_announcement_tables(conn)
            conn.execute(
                "INSERT INTO bgp_announcements (mitigation_key, status, dst_ip, protocol, dst_port, duration_seconds, expires_at, updated_at) "
                "VALUES ('dns:203.0.113.53', 'advertised', '203.0.113.53', 'udp', '53', 3600, '2026-08-22T12:00:00Z', '2026-08-22T12:00:00Z')"
            )
            conn.commit()
            announcement = backend_main.equivalent_mitigation_announcement(conn, "dns:203.0.113.53")
            self.assertIsNotNone(announcement)
            new_expires = "2026-08-23T12:00:00Z"
            backend_main.extend_active_announcement_lease(
                conn, announcement, new_expires, old_lease_seconds=3600, new_lease_seconds=86400,
            )
            conn.commit()
            row = conn.execute("SELECT expires_at FROM bgp_announcements WHERE id = ?", (announcement["id"],)).fetchone()
            event = conn.execute(
                "SELECT event_type, payload_json FROM bgp_announcement_events WHERE announcement_id = ?", (announcement["id"],)
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["expires_at"], new_expires)
        self.assertEqual(event["event_type"], "AUTO_MITIGATION_EXTENDED")

    def test_L_kill_switch_blocks_effective(self) -> None:
        with mock.patch.dict(os.environ, {"GMJFLOW_AUTO_MITIGATION_KILL_SWITCH": "true"}, clear=False):
            with backend_main.sqlite_connection() as conn:
                backend_main.ensure_system_settings_table(conn)
                effective = ce.auto_mitigation_effective(conn)
        self.assertFalse(effective["effective"])
        self.assertTrue(effective["kill_switch"])

    # --- K/prova: 86400 + max_lifetime NULL não é bloqueado pelo antigo cap 3600 ---
    def test_duration_86400_unlimited_is_accepted(self) -> None:
        errors = backend_main.validate_mitigation_duration(
            {"duration_seconds": 86400},
            {"max_lifetime_seconds": None, "max_duration_seconds": 3600},
        )
        self.assertNotIn("Duracao excede", " | ".join(errors))
        self.assertNotIn("excede", " | ".join(errors))

    def test_duration_86400_with_explicit_lifetime_is_capped(self) -> None:
        errors = backend_main.validate_mitigation_duration(
            {"duration_seconds": 86400},
            {"max_lifetime_seconds": 7200, "max_duration_seconds": 3600},
        )
        self.assertTrue(any("excede" in error for error in errors))

    def test_duration_zero_is_invalid(self) -> None:
        errors = backend_main.validate_mitigation_duration(
            {"duration_seconds": 0},
            {"max_lifetime_seconds": None},
        )
        self.assertTrue(any("Duracao invalida" in error for error in errors))

    # --- fixed_connector: profile connector_id=2 resolve exatamente o connector 2 ---
    def _ensure_connector_resolution_tables(self, conn) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS bgp_connectors (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT '',
                backend_type TEXT NOT NULL DEFAULT '',
                mode TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                is_active INTEGER NOT NULL DEFAULT 1,
                peer_ip TEXT NOT NULL DEFAULT '',
                exabgp_pipe_in TEXT NOT NULL DEFAULT '',
                exabgp_pipe_out TEXT NOT NULL DEFAULT '',
                status_snapshot_json TEXT NOT NULL DEFAULT '{}',
                last_checked_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS ip_zones (id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1, connector_id INTEGER);
            CREATE TABLE IF NOT EXISTS ip_zone_prefixes (id INTEGER PRIMARY KEY, zone_id INTEGER, cidr TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS bgp_protected_prefixes (id INTEGER PRIMARY KEY, cidr TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1);
            """
        )
        conn.commit()

    def test_fixed_connector_resolves_exactly_connector_2(self) -> None:
        conn = backend_main.sqlite_connection()
        try:
            self._ensure_connector_resolution_tables(conn)
            conn.execute(
                "INSERT INTO bgp_connectors (id, name, role, backend_type, mode, enabled, is_active, peer_ip) "
                "VALUES (2, 'BGP-NE40-VNT', 'flowspec_mitigation', 'exabgp', 'automatic', 1, 1, '186.232.160.37')"
            )
            conn.commit()
            candidate = {
                "target_prefix": "203.0.113.53/32",
                "src_prefix": "198.51.100.7/32",
                "mitigation_target_mode": "fixed_connector",
            }
            profile = {"connector_id": 2, "selected_connector_ids": [], "mitigation_target_mode": "fixed_connector"}
            result = backend_main.resolve_mitigation_target_connectors(conn, candidate, profile)
        finally:
            conn.close()
        self.assertEqual([int(item["id"]) for item in result], [2])
        self.assertEqual(int(candidate.get("connector_id")), 2)
        self.assertFalse(candidate.get("connector_resolution_error"))


class _FakeDirPath:
    def __init__(self, exists):
        self._exists = exists

    def exists(self):
        return self._exists


class _FakePath:
    """Minimal pathlib.Path stand-in for backend delivery-path tests."""

    def __init__(self, path, exists=True, is_fifo=True, parent_exists=None):
        self._path = path
        self._exists = exists
        self._is_fifo = is_fifo
        self._parent_exists = parent_exists if parent_exists is not None else exists

    @property
    def parent(self):
        return _FakeDirPath(self._parent_exists)

    def exists(self):
        return self._exists

    def stat(self):
        mode = 0o010000 if self._is_fifo else 0o100000  # S_IFIFO vs S_IFREG
        return types.SimpleNamespace(st_mode=mode)

    def __str__(self):
        return self._path


class BackendDeliveryPathTest(unittest.TestCase):
    """Readiness de duas visões: host (Host Agent) + backend delivery path (FIFO)."""

    def _patch_paths(self, behaviors):
        def factory(path):
            key = str(path)
            b = behaviors.get(key, {})
            return _FakePath(
                key,
                exists=b.get("exists", True),
                is_fifo=b.get("is_fifo", True),
                parent_exists=b.get("parent_exists", b.get("exists", True)),
            )
        return mock.patch.object(backend_main, "Path", side_effect=factory)

    def _delivery(self, pipe_in="/run/exabgp/exabgp.in", pipe_out="/run/exabgp/exabgp.out"):
        return backend_main.exabgp_backend_delivery_path_status(pipe_in, pipe_out)

    def test_A_mount_absent_not_ready(self):
        behaviors = {"/run/exabgp/exabgp.in": {"exists": False, "parent_exists": False}}
        with self._patch_paths(behaviors), mock.patch.object(os, "access", return_value=True):
            result = self._delivery()
        self.assertFalse(result["backend_mount_visible"])
        self.assertFalse(result["backend_pipe_in_visible"])
        self.assertFalse(result["delivery_path_ready"])
        self.assertEqual(result["reason"], "backend_exabgp_pipe_unavailable")

    def test_B_fifo_absent_not_ready(self):
        behaviors = {"/run/exabgp/exabgp.in": {"exists": False, "parent_exists": True}}
        with self._patch_paths(behaviors), mock.patch.object(os, "access", return_value=True):
            result = self._delivery()
        self.assertTrue(result["backend_mount_visible"])
        self.assertFalse(result["backend_pipe_in_visible"])
        self.assertFalse(result["delivery_path_ready"])
        self.assertEqual(result["reason"], "backend_exabgp_pipe_unavailable")

    def test_C_fifo_present_ready(self):
        with self._patch_paths({}), mock.patch.object(os, "access", return_value=True):
            result = self._delivery()
        self.assertTrue(result["backend_mount_visible"])
        self.assertTrue(result["backend_pipe_in_visible"])
        self.assertTrue(result["backend_pipe_out_visible"])
        self.assertTrue(result["backend_pipe_in_is_fifo"])
        self.assertTrue(result["backend_pipe_writable"])
        self.assertTrue(result["delivery_path_ready"])
        self.assertEqual(result["reason"], "")

    def test_D_not_fifo_not_ready(self):
        behaviors = {"/run/exabgp/exabgp.in": {"exists": True, "is_fifo": False}}
        with self._patch_paths(behaviors), mock.patch.object(os, "access", return_value=True):
            result = self._delivery()
        self.assertTrue(result["backend_pipe_in_visible"])
        self.assertFalse(result["backend_pipe_in_is_fifo"])
        self.assertFalse(result["delivery_path_ready"])
        self.assertEqual(result["reason"], "backend_exabgp_pipe_not_fifo")

    def test_E_not_writable_not_ready(self):
        with self._patch_paths({}), mock.patch.object(os, "access", return_value=False):
            result = self._delivery()
        self.assertTrue(result["backend_pipe_in_is_fifo"])
        self.assertFalse(result["backend_pipe_writable"])
        self.assertFalse(result["delivery_path_ready"])
        self.assertEqual(result["reason"], "backend_exabgp_pipe_not_writable")

    def _host_ok_status(self, backend_pipes=None):
        status = {
            "backend": "exabgp",
            "bgp_state": "established",
            "flowspec_state": "established",
            "pipe_state": "ok",
            "service": {"active": True},
            "session": {"tcp_established": True, "close_wait_count": 0, "close_wait_alert": False},
            "pipes": {
                "input_path": "/run/exabgp/exabgp.in",
                "output_path": "/run/exabgp/exabgp.out",
                "ok": True,
                "is_fifo": True,
                "reader_active": True,
                "exists": True,
            },
        }
        if backend_pipes is not None:
            status["backend_pipes"] = backend_pipes
        return status

    def test_readiness_false_when_reader_unverified(self):
        # Pipe exists + fifo + writable, but no reader/consumer is proven:
        # operational evidence only => delivery_path_ready=false.
        status = self._host_ok_status()
        status["pipes"] = {
            "input_path": "/run/exabgp/exabgp.in",
            "output_path": "/run/exabgp/exabgp.out",
            "ok": True,
            "is_fifo": True,
            "exists": True,
            # reader_active intentionally omitted => reader UNKNOWN
        }
        readiness = backend_main.evaluate_bgp_connector_readiness(status)
        self.assertFalse(readiness["ready"])
        self.assertFalse(readiness["delivery_path_ready"])
        self.assertEqual(readiness["delivery_path_source"], "operational_evidence")
        self.assertEqual(readiness["delivery_path_reason"], "delivery_reader_unverified")

    def test_readiness_true_when_direct_pipe_reader_verified(self):
        # Pipe payload proves fifo + active reader: direct delivery path ready.
        status = self._host_ok_status()
        readiness = backend_main.evaluate_bgp_connector_readiness(status)
        self.assertTrue(readiness["ready"])
        self.assertTrue(readiness["delivery_path_ready"])
        self.assertEqual(readiness["delivery_path_source"], "direct_pipe")
        self.assertEqual(readiness["reason"], "")

    def test_F_write_pipe_with_valid_fifo(self):
        connector = {"exabgp_pipe_in": "/tmp/gmj-test-fifo", "exabgp_pipe_out": ""}
        written = []

        def fake_open(path, flags):
            written.append(path)
            return 12345

        had_nonblock = hasattr(os, "O_NONBLOCK")
        if not had_nonblock:
            os.O_NONBLOCK = 0
        try:
            with mock.patch.object(os, "open", side_effect=fake_open), \
                 mock.patch.object(os, "write") as write_mock, \
                 mock.patch.object(os, "close"):
                backend_main.exabgp_write_pipe(connector, "announce flow route { ... }")
        finally:
            if not had_nonblock:
                del os.O_NONBLOCK
        self.assertEqual(written, ["/tmp/gmj-test-fifo"])
        write_mock.assert_called_once_with(12345, b"announce flow route { ... }\n")

    def test_G_no_real_production_fifo_written(self):
        connector = {"exabgp_pipe_in": "/run/exabgp/exabgp.in", "exabgp_pipe_out": ""}
        behaviors = {"/run/exabgp/exabgp.in": {"exists": False, "parent_exists": False}}
        with self._patch_paths(behaviors), mock.patch.object(os, "open") as open_mock:
            with self.assertRaises(backend_main.HTTPException) as ctx:
                backend_main.exabgp_write_pipe(connector, "announce flow route { ... }")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("montado", str(ctx.exception.detail))
        open_mock.assert_not_called()


class InitialTtlSingleOwnerTest(unittest.TestCase):
    """TTL inicial do DNS automático é single-owner: profile.initial_lease_seconds."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "ttl.db"
        self.env_patch = mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": str(self.db_path)}, clear=False)
        self.env_patch.start()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.tmp.cleanup()

    def _ensure_profile_ttl_tables(self, conn) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS bgp_response_profiles (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                approval_mode TEXT NOT NULL DEFAULT 'manual_approval',
                mitigation_target_mode TEXT NOT NULL DEFAULT '',
                connector_id INTEGER,
                default_action TEXT NOT NULL DEFAULT 'discard',
                default_duration_seconds INTEGER,
                duration_seconds INTEGER,
                initial_lease_seconds INTEGER,
                recurrence_lease_seconds INTEGER,
                max_lifetime_seconds INTEGER,
                recurrence_renewal_enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS bgp_connectors (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                is_active INTEGER NOT NULL DEFAULT 1,
                role TEXT NOT NULL DEFAULT '',
                backend_type TEXT NOT NULL DEFAULT '',
                mode TEXT NOT NULL DEFAULT ''
            );
            """
        )
        conn.commit()

    def _profile(self, initial_lease):
        conn = backend_main.sqlite_connection()
        self._ensure_profile_ttl_tables(conn)
        conn.execute(
            "INSERT INTO bgp_response_profiles (id, name, approval_mode, mitigation_target_mode, initial_lease_seconds, recurrence_lease_seconds, max_lifetime_seconds, recurrence_renewal_enabled, default_duration_seconds, duration_seconds) "
            "VALUES (17, 'FLOWSPEC_AUTO_BLOCK_DST_DNS', 'auto', 'fixed_connector', ?, 86400, NULL, 1, 900, 900)",
            (initial_lease,),
        )
        conn.commit()
        return conn

    def _candidate(self):
        return {
            "attack_vector_name": "DNS_SINGLE_FLOW_OUTBOUND",
            "mitigation_basis": "dns_outbound_conversation",
            "src_cidr": "186.232.169.254/32",
            "dst_cidr": "98.98.215.41/32",
            "protocol": "udp",
            "dst_port": "53",
            "action": "discard",
        }

    def _vector(self):
        # duration_seconds=900 é o legado hardcoded que NÃO deve vencer o perfil.
        return {"response_profile_id": 17, "mitigation_mode": "response_profile", "duration_seconds": 900}

    def test_initial_lease_3600_drives_candidate_ttl(self):
        conn = self._profile(3600)
        try:
            result = backend_main.attach_mitigation_config(conn, self._candidate(), self._vector())
        finally:
            conn.close()
        self.assertEqual(result["duration_seconds"], 3600)

    def test_initial_lease_7200_drives_candidate_ttl(self):
        conn = self._profile(7200)
        try:
            result = backend_main.attach_mitigation_config(conn, self._candidate(), self._vector())
        finally:
            conn.close()
        self.assertEqual(result["duration_seconds"], 7200)

    def test_initial_lease_fallback_is_3600_not_900(self):
        self.assertEqual(backend_main.mitigation_initial_lease_seconds({}), 3600)

    def test_recurrence_lease_86400_and_unlimited_max_lifetime(self):
        profile = {
            "initial_lease_seconds": 3600,
            "recurrence_lease_seconds": 86400,
            "max_lifetime_seconds": None,
            "recurrence_renewal_enabled": 1,
        }
        self.assertEqual(backend_main.mitigation_recurrence_lease_seconds(profile), 86400)
        self.assertIsNone(backend_main.mitigation_max_lifetime_seconds(profile))


if __name__ == "__main__":
    unittest.main()
