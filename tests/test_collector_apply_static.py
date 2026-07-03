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

from backend.app import main as backend_main

MAIN = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
ENV_EXAMPLE = (ROOT / ".env.example").read_text(encoding="utf-8")
INSTALL = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
UPDATE = (ROOT / "scripts" / "update.sh").read_text(encoding="utf-8")


class CollectorApplyStaticTest(unittest.TestCase):
    def test_collector_apply_defaults_to_enabled_for_new_installs(self):
        self.assertIn("GMJFLOW_ENABLE_COLLECTOR_APPLY=true", ENV_EXAMPLE)
        self.assertIn('os.getenv("GMJFLOW_ENABLE_COLLECTOR_APPLY", "true")', MAIN)
        self.assertIn("set_env_value GMJFLOW_ENABLE_COLLECTOR_APPLY true", INSTALL)

    def test_save_sensor_runs_collector_apply_and_shows_not_applied_warning(self):
        self.assertIn("async function applyCollectorsAfterSave(saved)", HTML)
        self.assertIn("await applyCollectorsAfterSave(saved);", HTML)
        self.assertIn("apiRequest('/api/collectors/apply', { method: 'POST' })", HTML)
        self.assertIn(
            "Sensor salvo, mas collector ainda não aplicado. Clique em Aplicar Coletor.",
            HTML,
        )

    def test_ingestion_status_backend_exposes_operational_diagnostics(self):
        self.assertIn("def docker_container_snapshot", MAIN)
        self.assertIn("nfacctd_conf_exists", MAIN)
        self.assertIn("pmacct_container_running", MAIN)
        self.assertIn("udp_port_published", MAIN)
        self.assertIn("csv_exists", MAIN)
        self.assertIn("parser_reading", MAIN)
        self.assertIn("clickhouse_receiving", MAIN)
        self.assertIn('"diagnostics"', MAIN)

    def test_ingestion_status_frontend_renders_diagnostics(self):
        self.assertIn("diagnosticBadge(item.nfacctd_conf_exists", HTML)
        self.assertIn("diagnosticBadge(item.pmacct_container_running", HTML)
        self.assertIn("diagnosticBadge(item.udp_port_published", HTML)
        self.assertIn("diagnosticBadge(item.csv_exists", HTML)
        self.assertIn("diagnosticBadge(item.parser_reading", HTML)
        self.assertIn("diagnosticBadge(item.clickhouse_receiving", HTML)
        self.assertIn("ingestionDiagnosticTitle(item)", HTML)

    def test_install_and_update_include_collectors_compose_when_present(self):
        for script in (INSTALL, UPDATE):
            self.assertIn("docker-compose.collectors.yml", script)
            self.assertIn("-f docker-compose.yml", script)
            self.assertIn("-f docker-compose.collectors.yml", script)
            self.assertIn("--remove-orphans", script)

    def test_sensor_save_generates_collector_files_for_enabled_collectors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            backend_main.COLLECTORS_DIR = tmp_path / "collectors"
            backend_main.COLLECTORS_COMPOSE_PATH = tmp_path / "docker-compose.collectors.yml"
            backend_main.COLLECTORS_DIR.mkdir(parents=True, exist_ok=True)
            backend_main.COLLECTORS_COMPOSE_PATH.write_text("", encoding="utf-8")
            with backend_main.sqlite_connection() as conn:
                backend_main.ensure_sensor_db()
                conn.execute("DELETE FROM sensors")
                conn.commit()

            sensor_payload = backend_main.SensorPayload(
                name="sensor-a",
                exporter_ip="192.0.2.10",
                listener_port=9995,
                snmp_port=161,
                granularity_seconds=60,
                snmp_polling_seconds=60,
                flow_collector_enabled=True,
                active=True,
                interfaces=[],
            )
            with mock.patch.object(backend_main, "run_apply_collectors_script", return_value={"services_updated": True, "message": "ok", "stdout": "", "stderr": "", "returncode": 0}):
                created = backend_main.create_sensor(sensor_payload)

            self.assertEqual(created["name"], "sensor-a")
            self.assertTrue((backend_main.COLLECTORS_DIR / "sensor-1" / "nfacctd.conf").exists())
            self.assertTrue((backend_main.COLLECTORS_DIR / "sensor-1" / "allow.lst").exists())
            self.assertIn("192.0.2.10", (backend_main.COLLECTORS_DIR / "sensor-1" / "allow.lst").read_text(encoding="utf-8"))
            self.assertIn("nfacctd_port: 9995", (backend_main.COLLECTORS_DIR / "sensor-1" / "nfacctd.conf").read_text(encoding="utf-8"))
            self.assertTrue(backend_main.COLLECTORS_COMPOSE_PATH.exists())


if __name__ == "__main__":
    unittest.main()
