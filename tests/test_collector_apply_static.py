import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
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


if __name__ == "__main__":
    unittest.main()
