from __future__ import annotations

import os
import sqlite3
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services import ai_integration as ai  # noqa: E402
from app.services.security_event_ai import execute_security_ai_provider, security_ai_config  # noqa: E402


class SecurityAiRoutingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ai.ensure_ai_schema(self.conn, {})
        ai.update_global_ai_settings(self.conn, {"global_enabled": True}, "test")
        self.event_provider = self._provider("Event Provider", "event-default")
        self.campaign_provider = self._provider("Campaign Provider", "campaign-default")
        self._route("security_event_analysis", self.event_provider["id"], "event-model")
        self._route("security_campaign_analysis", self.campaign_provider["id"], "campaign-model")
        self.conn.commit()

    def tearDown(self) -> None:
        self.conn.close()

    def _provider(self, name: str, model: str) -> dict:
        return ai.save_ai_provider(
            self.conn,
            {
                "name": name,
                "provider_type": "ollama",
                "enabled": True,
                "base_url": f"http://{name.lower().replace(' ', '-')}",
                "default_model": model,
            },
            "test",
        )

    def _route(self, function_key: str, provider_id: int, model: str) -> None:
        ai.save_ai_route(
            self.conn,
            function_key,
            {
                "enabled": True,
                "primary_provider_id": provider_id,
                "primary_model": model,
                "require_structured": True,
            },
            "test",
        )

    def test_registry_contains_distinct_event_and_campaign_functions(self) -> None:
        functions = dict(ai.AI_FUNCTIONS)
        self.assertEqual("Análise de Evento de Segurança", functions["security_event_analysis"])
        self.assertEqual("Análise de Campanha de Segurança", functions["security_campaign_analysis"])
        routes = {item["function_key"]: item for item in ai.list_ai_routes(self.conn)}
        self.assertIn("security_event_analysis", routes)
        self.assertIn("security_campaign_analysis", routes)

    def test_security_ai_and_automatic_policy_gates_remain_off_by_default(self) -> None:
        env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for key in (
            "GMJFLOW_SECURITY_AI_ENABLED",
            "GMJFLOW_AUTO_MITIGATION_ENABLED",
            "GMJFLOW_THREAT_POLICY_AUTO_ENABLED",
        ):
            self.assertIn(f"{key}=false", env_example)
            self.assertIn(f"{key}-false", compose)

    def test_each_security_function_uses_its_own_provider_and_model(self) -> None:
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_AI_ENABLED": "true"}, clear=False):
            event = security_ai_config(self.conn, "security_event_analysis")
            campaign = security_ai_config(self.conn, "security_campaign_analysis")
        self.assertTrue(event["enabled"])
        self.assertEqual("ai_routing", event["config_source"])
        self.assertEqual("Event Provider", event["provider_name"])
        self.assertEqual("event-model", event["model"])
        self.assertEqual("Campaign Provider", campaign["provider_name"])
        self.assertEqual("campaign-model", campaign["model"])
        self.assertNotEqual(event["provider_name"], campaign["provider_name"])
        self.assertNotEqual(event["model"], campaign["model"])

    def test_global_security_kill_switch_blocks_both_routes_before_provider_execution(self) -> None:
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_AI_ENABLED": "false"}, clear=False), patch(
            "app.services.ai_integration.execute_ai_route"
        ) as routed:
            for function_key in ("security_event_analysis", "security_campaign_analysis"):
                result = execute_security_ai_provider(
                    self.conn,
                    function_key,
                    "bounded payload",
                    system_prompt="advisory only",
                    schema={"type": "object"},
                )
                self.assertFalse(result["ok"])
                self.assertEqual("disabled", result["error_type"])
        routed.assert_not_called()

    def test_enabled_routes_are_delegated_to_the_existing_central_router(self) -> None:
        routed_result = {"ok": True, "provider": "routed", "model": "selected", "structured": {"summary": "ok"}}
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_AI_ENABLED": "true"}, clear=False), patch(
            "app.services.ai_integration.execute_ai_route", return_value=routed_result
        ) as routed:
            result = execute_security_ai_provider(
                self.conn,
                "security_campaign_analysis",
                "bounded payload",
                system_prompt="advisory only",
                schema={"type": "object"},
            )
        self.assertEqual(routed_result, result)
        routed.assert_called_once()
        self.assertEqual("security_campaign_analysis", routed.call_args[0][1])


if __name__ == "__main__":
    unittest.main()
