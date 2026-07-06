import os
import shutil
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
APPLY_COLLECTORS = (ROOT / "scripts" / "apply_collectors.sh").read_text(encoding="utf-8")
ROOT_COLLECTORS_COMPOSE = (ROOT / "docker-compose.collectors.yml").read_text(encoding="utf-8")


def assert_safe_runtime_compose(test_case, compose_text, project_dir=None, network_name="gmj-flow_default"):
    test_case.assertIn("pmacct-sensor-1:", compose_text)
    test_case.assertIn("pmacct-parser-sensor-1:", compose_text)
    test_case.assertIn("pmacct-sensor-2:", compose_text)
    test_case.assertIn("pmacct-parser-sensor-2:", compose_text)
    test_case.assertNotIn("\n  pmacct:", compose_text)
    test_case.assertNotIn("\n  pmacct-parser:", compose_text)
    test_case.assertNotIn("\n  clickhouse:", compose_text)
    test_case.assertNotIn("\n  backend:", compose_text)
    test_case.assertNotIn("depends_on:\n      clickhouse:", compose_text)
    test_case.assertIn("networks:", compose_text)
    test_case.assertIn("external: true", compose_text)
    test_case.assertIn(f'name: "{network_name}"', compose_text)
    if project_dir is not None:
        build_context = backend_main.host_path_join(str(project_dir), "collector", "pmacct")
        collectors_volume = backend_main.host_path_join(str(project_dir), "data", "collectors")
        test_case.assertTrue(Path(build_context).is_absolute())
        test_case.assertTrue(Path(collectors_volume).is_absolute())
        test_case.assertIn(f"context: {backend_main.yaml_quote(build_context)}", compose_text)
        test_case.assertIn(backend_main.yaml_quote(f"{collectors_volume}:/app/data/collectors:ro"), compose_text)


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

    def test_collector_apply_only_starts_pmacct_services_without_dependencies(self):
        self.assertIn("config --services", APPLY_COLLECTORS)
        self.assertIn("/^pmacct-sensor-[0-9]+$/", APPLY_COLLECTORS)
        self.assertIn("/^pmacct-parser-sensor-[0-9]+$/", APPLY_COLLECTORS)
        apply_line = next(line for line in APPLY_COLLECTORS.splitlines() if " up -d " in line)
        self.assertIn("--no-deps", apply_line)
        self.assertIn("$SERVICES", apply_line)
        self.assertIn('docker compose -f "$COMPOSE_OVERRIDE"', apply_line)
        self.assertNotIn("docker-compose.yml", APPLY_COLLECTORS)
        self.assertNotIn("--env-file", APPLY_COLLECTORS)
        self.assertNotIn("clickhouse", apply_line)
        self.assertNotIn("backend", apply_line)

    def test_collector_apply_response_command_is_script_not_core_service(self):
        command_block = MAIN[MAIN.find("def run_apply_collectors_script"):MAIN.find("def docker_container_snapshot")]
        self.assertIn('"docker", "compose", "-f", str(compose_path)', command_block)
        self.assertIn('"--no-deps"', command_block)
        self.assertIn('"command": command_text', command_block)
        self.assertNotIn("gmj-flow-clickhouse", command_block)
        self.assertNotIn("gmj-flow-backend", command_block)

    def test_root_runtime_collectors_compose_is_safe(self):
        self.assertIn("pmacct-sensor-1:", ROOT_COLLECTORS_COMPOSE)
        self.assertIn("pmacct-parser-sensor-1:", ROOT_COLLECTORS_COMPOSE)
        self.assertNotIn("\n  pmacct:", ROOT_COLLECTORS_COMPOSE)
        self.assertNotIn("\n  pmacct-parser:", ROOT_COLLECTORS_COMPOSE)
        self.assertNotIn("\n  clickhouse:", ROOT_COLLECTORS_COMPOSE)
        self.assertNotIn("\n  backend:", ROOT_COLLECTORS_COMPOSE)
        self.assertNotIn("depends_on:\n      clickhouse:", ROOT_COLLECTORS_COMPOSE)
        self.assertIn("${GMJFLOW_PROJECT_DIR}/collector/pmacct", ROOT_COLLECTORS_COMPOSE)
        self.assertIn("${GMJFLOW_PROJECT_DIR}/data/collectors:/app/data/collectors:ro", ROOT_COLLECTORS_COMPOSE)
        self.assertIn("external: true", ROOT_COLLECTORS_COMPOSE)

    def test_generated_runtime_compose_has_only_pmacct_services(self):
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.dict(os.environ, {"GMJFLOW_PROJECT_DIR": tmpdir, "GMJFLOW_DOCKER_NETWORK": "gmj-flow_default", "GMJFLOW_COLLECTORS_DIR": ""}, clear=False):
            compose_text = backend_main.compose_for_collectors(
                [
                    {"id": 1, "name": "sensor-a", "exporter_ip": "192.0.2.10", "listener_port": 9995},
                    {"id": 2, "name": "sensor-b", "exporter_ip": "192.0.2.11", "listener_port": 9996},
                ]
            )
        assert_safe_runtime_compose(self, compose_text, tmpdir)
        self.assertNotIn("clickhouse:\n", compose_text)
        services_block = compose_text.split("\nvolumes:", 1)[0]
        service_lines = [line for line in services_block.splitlines() if line.startswith("  ") and line.endswith(":") and not line.startswith("    ")]
        self.assertEqual(
            service_lines,
            [
                "  pmacct-sensor-1:",
                "  pmacct-parser-sensor-1:",
                "  pmacct-sensor-2:",
                "  pmacct-parser-sensor-2:",
            ],
        )

    def test_write_collector_artifacts_writes_safe_runtime_compose(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            output_dir = tmp_path / "data" / "collectors"
            compose_path = tmp_path / "docker-compose.collectors.yml"
            with mock.patch.dict(os.environ, {"GMJFLOW_PROJECT_DIR": tmpdir, "GMJFLOW_DOCKER_NETWORK": "gmj-flow_default", "GMJFLOW_COLLECTORS_DIR": ""}, clear=False):
                backend_main.write_collector_artifacts(
                    [
                        {"id": 1, "name": "sensor-a", "exporter_ip": "192.0.2.10", "listener_port": 9995},
                        {"id": 2, "name": "sensor-b", "exporter_ip": "192.0.2.11", "listener_port": 9996},
                    ],
                    output_dir=output_dir,
                    compose_path=compose_path,
                )
            compose_text = compose_path.read_text(encoding="utf-8")
            assert_safe_runtime_compose(self, compose_text, tmpdir)
            self.assertTrue((output_dir / "sensor-1" / "nfacctd.conf").exists())
            self.assertTrue((output_dir / "sensor-2" / "allow.lst").exists())
            service_lines = [
                line for line in compose_text.split("\nvolumes:", 1)[0].splitlines()
                if line.startswith("  ") and line.endswith(":") and not line.startswith("    ")
            ]
            self.assertEqual(
                service_lines,
                [
                    "  pmacct-sensor-1:",
                    "  pmacct-parser-sensor-1:",
                    "  pmacct-sensor-2:",
                    "  pmacct-parser-sensor-2:",
                ],
            )

    def test_sync_collector_artifacts_writes_safe_runtime_compose_used_by_apply_endpoint(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            output_dir = tmp_path / "data" / "collectors"
            compose_path = tmp_path / "docker-compose.collectors.yml"
            sensors = [
                {"id": 1, "name": "sensor-a", "exporter_ip": "192.0.2.10", "listener_port": 9995},
                {"id": 2, "name": "sensor-b", "exporter_ip": "192.0.2.11", "listener_port": 9996},
            ]
            apply_result = {
                "services_updated": True,
                "message": "Collectors atualizados",
                "command": "docker compose -f /app/runtime/docker-compose.collectors.yml up -d --build --no-deps pmacct-sensor-1 pmacct-parser-sensor-1 pmacct-sensor-2 pmacct-parser-sensor-2",
                "stdout": "",
                "stderr": "",
                "returncode": 0,
            }

            with mock.patch.dict(os.environ, {"GMJFLOW_PROJECT_DIR": tmpdir, "GMJFLOW_DOCKER_NETWORK": "gmj-flow_default", "GMJFLOW_COLLECTORS_DIR": ""}, clear=False), \
                 mock.patch.object(backend_main, "collectors_compose_path", return_value=compose_path), \
                 mock.patch.object(backend_main, "active_collector_sensors", return_value=sensors), \
                 mock.patch.object(backend_main, "backup_collector_artifacts", return_value={}), \
                 mock.patch.object(backend_main, "run_apply_collectors_script", return_value=apply_result) as apply_mock:
                result = backend_main.sync_collector_artifacts(mock.Mock())

            apply_mock.assert_called_once_with(compose_path)
            compose_text = compose_path.read_text(encoding="utf-8")
            self.assertTrue(result["services_updated"])
            self.assertEqual(result["collectors_dir"], str(output_dir))
            self.assertTrue((output_dir / "sensor-1" / "nfacctd.conf").exists())
            self.assertTrue((output_dir / "sensor-2" / "allow.lst").exists())
            assert_safe_runtime_compose(self, compose_text, tmpdir)
            service_lines = [
                line for line in compose_text.split("\nvolumes:", 1)[0].splitlines()
                if line.startswith("  ") and line.endswith(":") and not line.startswith("    ")
            ]
            self.assertEqual(
                service_lines,
                [
                    "  pmacct-sensor-1:",
                    "  pmacct-parser-sensor-1:",
                    "  pmacct-sensor-2:",
                    "  pmacct-parser-sensor-2:",
                ],
            )

    def test_run_apply_collectors_uses_runtime_compose_and_explicit_pmacct_services(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            compose_path = Path(tmpdir) / "docker-compose.collectors.yml"
            compose_path.write_text("services: {}\n", encoding="utf-8")
            services_stdout = "\n".join(
                [
                    "pmacct-sensor-1",
                    "pmacct-parser-sensor-1",
                    "pmacct-sensor-2",
                    "pmacct-parser-sensor-2",
                    "",
                ]
            )
            results = [
                types.SimpleNamespace(returncode=0, stdout=services_stdout, stderr=""),
                types.SimpleNamespace(returncode=0, stdout="ok", stderr=""),
            ]
            with mock.patch.object(backend_main, "collector_apply_enabled", return_value=True), \
                 mock.patch.object(backend_main.subprocess, "run", side_effect=results) as run_mock:
                result = backend_main.run_apply_collectors_script(compose_path)

            expected = [
                "docker",
                "compose",
                "-f",
                str(compose_path),
                "up",
                "-d",
                "--build",
                "--no-deps",
                "pmacct-sensor-1",
                "pmacct-parser-sensor-1",
                "pmacct-sensor-2",
                "pmacct-parser-sensor-2",
            ]
            self.assertTrue(result["services_updated"])
            self.assertEqual(run_mock.call_args_list[1][0][0], expected)
            self.assertEqual(result["command"], " ".join(expected))
            self.assertNotIn("clickhouse", result["command"])
            self.assertNotIn("backend", result["command"])

    def test_subnet_detection_query_does_not_emit_empty_string_ip_aliases(self):
        zone = {"id": 1, "name": "clientes"}
        template = {"id": 1, "name": "CLIENTES-PUBLICOS-DEFAULT"}
        rule = {
            "id": 5,
            "vector": "PREFIX_SUBNET_HIGH_PPS",
            "domain": "subnet",
            "direction": "transmits",
            "protocol": "UDP",
            "metric": "packets_s",
            "warning_value": 10,
            "critical_value": 100,
            "comparison": "over",
            "window_seconds": 60,
            "consecutive_windows": 1,
            "cooldown_seconds": 300,
            "src_port": "",
            "dst_port": "",
            "response": "DETECTION_ONLY",
            "mitigation_mode": "detection_only",
            "enabled": True,
        }
        captured_queries = []

        def fake_query(query, params):
            captured_queries.append(query)
            return types.SimpleNamespace(column_names=[], result_rows=[])

        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query), \
             mock.patch.object(backend_main, "clickhouse_sample_rate_expr", return_value="toFloat64(1)"):
            for prefix_cidr in ("203.0.113.0/24", "2001:db8::/32"):
                backend_main.query_detection_rule_candidates(
                    zone,
                    template,
                    rule,
                    {"id": 1, "cidr": prefix_cidr},
                    backend_main.datetime(2026, 1, 1, tzinfo=backend_main.timezone.utc),
                    backend_main.datetime(2026, 1, 1, 0, 1, tzinfo=backend_main.timezone.utc),
                    None,
                )

        self.assertEqual(len(captured_queries), 2)
        for query in captured_queries:
            self.assertNotIn("'' AS src_ip", query)
            self.assertNotIn("'' AS dst_ip", query)
            self.assertNotIn("'' AS internal_ip", query)
            self.assertIn("NULL AS src_ip", query)
            self.assertIn("NULL AS dst_ip", query)
            self.assertIn("NULL AS internal_ip", query)

    def test_sensor_save_generates_collector_files_for_enabled_collectors(self):
        tmpdir = tempfile.mkdtemp()
        try:
            tmp_path = Path(tmpdir)
            collectors_dir = tmp_path / "collectors"
            compose_path = tmp_path / "docker-compose.collectors.yml"
            collectors_dir.mkdir(parents=True, exist_ok=True)
            compose_path.write_text("", encoding="utf-8")
            env = {
                "GMJFLOW_DB_PATH": str(tmp_path / "gmjflow.db"),
                "GMJFLOW_COLLECTORS_DIR": "",
                "GMJFLOW_PROJECT_DIR": "",
                "GMJFLOW_DOCKER_NETWORK": "gmj-flow_default",
            }

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
            with mock.patch.dict(os.environ, env, clear=False), \
                 mock.patch.object(backend_main, "COLLECTORS_DIR", collectors_dir), \
                 mock.patch.object(backend_main, "COLLECTORS_COMPOSE_PATH", compose_path), \
                 mock.patch.object(backend_main, "hash_password", return_value="test-hash"), \
                 mock.patch.object(backend_main, "run_apply_collectors_script", return_value={"services_updated": True, "message": "ok", "stdout": "", "stderr": "", "returncode": 0}):
                with backend_main.sqlite_connection() as conn:
                    backend_main.ensure_sensor_db()
                    conn.execute("DELETE FROM sensors")
                    conn.commit()
                created = backend_main.create_sensor(sensor_payload)

            self.assertEqual(created["name"], "sensor-a")
            sensor_id = int(created["id"])
            sensor_dir = collectors_dir / f"sensor-{sensor_id}"
            config_path = sensor_dir / "nfacctd.conf"
            allow_path = sensor_dir / "allow.lst"
            self.assertTrue(config_path.exists())
            self.assertTrue(allow_path.exists())
            self.assertIn("192.0.2.10", allow_path.read_text(encoding="utf-8"))
            self.assertIn("nfacctd_port: 9995", config_path.read_text(encoding="utf-8"))
            self.assertTrue(compose_path.exists())
            compose_text = compose_path.read_text(encoding="utf-8")
            self.assertIn(f"pmacct-sensor-{sensor_id}", compose_text)
            self.assertIn(f"pmacct-parser-sensor-{sensor_id}", compose_text)
            self.assertNotIn("clickhouse:", compose_text)
            self.assertNotIn("backend:", compose_text)
            self.assertNotIn("depends_on:\n      clickhouse:", compose_text)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
