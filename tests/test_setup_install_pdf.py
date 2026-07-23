import unittest
from pathlib import Path

from backend.app.services.humanize import (
    format_bits_per_second,
    format_bytes,
    format_pdf_metric,
    format_packets,
    format_packets_per_second,
)


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
NGINX = (ROOT / "frontend" / "nginx.conf").read_text(encoding="utf-8")
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
INSTALL = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")


class SetupInstallPdfTest(unittest.TestCase):
    def test_pdf_metric_formatters(self):
        self.assertEqual(format_bits_per_second(213400000), "213.4 Mbps")
        self.assertEqual(format_bits_per_second(27000000000), "27 Gbps")
        self.assertEqual(format_packets_per_second(242500), "242.5 Kpps")
        self.assertEqual(format_packets_per_second(3200000), "3.2 Mpps")
        self.assertEqual(format_bytes(96030000), "96 MB")
        self.assertEqual(format_bytes(3800000000), "3.8 GB")
        self.assertEqual(format_packets(873000), "873 K")
        self.assertEqual(format_packets(3808000), "3.8 M")
        self.assertEqual(format_pdf_metric("bits_s", 213400000), "213.4 Mbps")
        self.assertEqual(format_bytes(None), "-")
        self.assertEqual(format_packets_per_second("invalid"), "-")

    def test_flows_pdf_uses_humanized_metrics_and_summary(self):
        self.assertIn("def flow_pdf_rows", MAIN)
        self.assertIn('"Taxa por registro"', MAIN)
        self.assertIn('"Indisponivel sem duracao real exportada pelo flow"', MAIN)
        self.assertIn('"label": "Duracao"', MAIN)
        self.assertIn('"label": "Taxa"', MAIN)
        self.assertNotIn('"headers": ["flow_time", "sensor", "src_ip", "src_port", "dst_ip", "dst_port", "proto_name", "bytes", "packets", "bits_s", "packets_s"]', MAIN)

    def test_nginx_uses_dynamic_docker_resolver(self):
        self.assertIn("resolver 127.0.0.11 valid=10s ipv6=off;", NGINX)
        self.assertIn("set $backend_upstream http://backend:8000;", NGINX)
        self.assertNotIn("proxy_pass http://backend:8000/api/;", NGINX)
        self.assertNotIn("proxy_pass http://backend:8000/health;", NGINX)
        self.assertIn("proxy_pass $backend_upstream/api/;", NGINX)
        self.assertIn("proxy_pass $backend_upstream/health;", NGINX)

    def test_compose_and_scripts_include_autostart_ai_exabgp(self):
        for service in ("clickhouse:", "backend:", "frontend:", "gmj-flow-ollama:"):
            self.assertIn(service, COMPOSE)
        self.assertGreaterEqual(COMPOSE.count("restart: unless-stopped"), 7)
        self.assertIn("--with-ai", INSTALL)
        self.assertIn("--with-exabgp", INSTALL)
        self.assertIn("docker exec gmj-flow-ollama ollama pull", INSTALL)
        self.assertTrue((ROOT / "scripts" / "install-systemd-service.sh").exists())
        self.assertTrue((ROOT / "scripts" / "install-exabgp.sh").exists())
        self.assertTrue((ROOT / "scripts" / "post-install-check.sh").exists())
        self.assertTrue((ROOT / "deploy" / "systemd" / "gmj-flow.service.template").exists())
        self.assertTrue((ROOT / "deploy" / "exabgp" / "gmj-flow-exabgp.conf.template").exists())

    def test_system_setup_endpoints_exist(self):
        for route in (
            "/api/system/setup/status",
            "/api/system/ai/status",
            "/api/system/ai/config",
            "/api/system/ai/ollama/pull",
            "/api/system/ai/ollama/models",
            "/api/system/ai/test",
            "/api/system/exabgp/status",
            "/api/system/exabgp/render-config",
            "/api/system/exabgp/install-instructions",
        ):
            self.assertIn(route, MAIN)
        self.assertIn("require_admin(request)", MAIN)
        self.assertIn('"ai_allow_auto": "false"', MAIN)
        self.assertIn('"recommendations"', MAIN)

    def test_ai_status_uses_env_fallback_and_reports_source(self):
        self.assertIn("def get_persisted_system_settings", MAIN)
        self.assertIn('if key.startswith("ai_"):', MAIN)
        self.assertIn('"source": source', MAIN)
        self.assertIn('"settings_source": settings_source', MAIN)
        self.assertIn('"overrides_env": overrides_env', MAIN)
        self.assertIn('"override_message": (', MAIN)
        self.assertIn('"reachable": provider_reachable', MAIN)
        self.assertIn('"ollama_reachable": models["reachable"]', MAIN)
        self.assertIn('"ai_keep_alive": os.getenv("AI_KEEP_ALIVE", "30m")', MAIN)
        self.assertIn('"keep_alive": clean_text(settings.get("ai_keep_alive")) or "30m"', MAIN)

    def test_ai_analysis_negative_anomaly_uses_draft_endpoint(self):
        self.assertIn('"/api/anomalies/{event_id}/ai-analysis/draft"', MAIN)
        self.assertIn("def draft_ai_analysis", MAIN)
        self.assertIn("def anomaly_ai_analysis_result", MAIN)
        self.assertIn("def valid_draft_ai_payload", MAIN)
        self.assertIn("missing_draft_payload", MAIN)
        self.assertIn("return missing_draft_payload_response()", MAIN)
        self.assertIn("request_payload=payload if event_id < 0 else None", MAIN)

        html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn("function anomalyAiAnalysisEndpoint", html)
        self.assertIn("function anomalyAiDraftPayload", html)
        self.assertIn("Number(anomalyId) < 0", html)
        self.assertIn("ai-analysis/draft", html)
        self.assertIn("body: JSON.stringify(anomalyAiDraftPayload(anomalyId))", html)

    def test_ai_ollama_keep_alive_timeout_and_analysis_only_contracts(self):
        self.assertIn('"keep_alive": config.get("keep_alive") or "30m"', MAIN)
        self.assertIn('"temperature": 0.1', MAIN)
        self.assertIn('"num_predict": 500', MAIN)
        self.assertIn('"num_ctx": 2048', MAIN)
        self.assertIn("class AiProviderTimeoutError", MAIN)
        self.assertIn('"error_type": "timeout"', MAIN)
        self.assertIn("JSONResponse(status_code=504, content=exc.payload)", MAIN)
        self.assertIn('endpoint=%s anomaly_id=%s is_draft=%s model=%s timeout_seconds=%s', MAIN)
        self.assertIn('success=false error_type=timeout', MAIN)
        self.assertIn('mode in {"disabled", "analysis_only"} or candidate.get("never_announce")', MAIN)
        html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn("const analysisOnly = candidate.never_announce || candidate.mitigation_mode === 'analysis_only'", html)
        self.assertIn("Informativo: sem ação de mitigação.", html)

    def test_containerized_bgp_status_distinguishes_unverified_from_down(self):
        self.assertIn("def parse_huawei_vrp_peer_state", MAIN)
        self.assertIn("display bgp peer", MAIN)
        self.assertIn("display bgp flow peer", MAIN)
        self.assertIn("def router_ssh_status", MAIN)
        self.assertIn("def host_agent_status", MAIN)
        self.assertIn("GMJFLOW_HOST_AGENT_URL", MAIN)
        self.assertTrue((ROOT / "scripts" / "host-agent.py").exists())
        self.assertIn('"bgp_state": bgp_state', MAIN)
        self.assertIn('"flowspec_state": flowspec_state', MAIN)
        self.assertIn('"pipe_verified": pipes_ok', MAIN)
        self.assertIn("Estado do peer BGP nao confirmado pelo ExaBGP.", MAIN)

        html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Pipe ExaBGP", html)
        self.assertIn("BGP não verificado", html)
        self.assertIn("FlowSpec não verificado", html)
        self.assertIn("bgpConnectorRouterCheck", html)
        self.assertIn("bgpConnectorRouterMgmtIp", html)


if __name__ == "__main__":
    unittest.main()
