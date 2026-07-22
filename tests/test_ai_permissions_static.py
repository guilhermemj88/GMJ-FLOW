import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")


def function_source(name):
    start = MAIN.index(f"def {name}(")
    match = re.search(r"\n(?:async )?def \w+\(", MAIN[start + 1 :])
    end = start + 1 + match.start() if match else len(MAIN)
    return MAIN[start:end]


class AiPermissionsStaticTest(unittest.TestCase):
    def test_ai_api_is_covered_by_auth_middleware(self):
        source = function_source("auth_middleware")
        self.assertIn('not path.startswith("/api/")', source)
        self.assertIn("token_user_from_request(request)", source)
        self.assertNotIn('path.startswith("/api/ai")', source)

    def test_configuration_mutations_require_admin(self):
        mutations = (
            "ai_provider_create",
            "ai_provider_update",
            "ai_provider_remove",
            "ai_provider_duplicate",
            "ai_provider_toggle",
            "ai_provider_connection_test",
            "ai_provider_models_refresh",
            "ai_provider_model_create",
            "ai_provider_model_pull",
            "ai_provider_model_pull_cancel",
            "ai_provider_model_remove",
            "ai_route_update",
            "ai_prompt_create",
            "ai_prompt_update",
            "ai_prompt_duplicate",
            "ai_prompt_restore",
            "ai_central_settings_update",
        )
        for name in mutations:
            with self.subTest(name=name):
                self.assertIn("require_admin(request)", function_source(name))

    def test_operator_read_and_playground_endpoints_do_not_require_admin(self):
        readable = (
            "ai_overview",
            "ai_provider_list",
            "ai_provider_detail",
            "ai_model_list",
            "ai_route_list",
            "ai_prompt_list",
            "ai_request_history",
            "ai_audit_log",
            "ai_playground",
        )
        for name in readable:
            with self.subTest(name=name):
                self.assertNotIn("require_admin(request)", function_source(name))

    def test_operator_history_is_sanitized(self):
        source = function_source("ai_request_history")
        self.assertIn('user.get("role")', source)
        self.assertIn("sanitize_ai_content", source)
        self.assertIn('external_provider=True', source)

    def test_legacy_configuration_endpoints_delegate_to_central_storage(self):
        self.assertIn("sync_legacy_ai_payload_to_central(conn, values, ai_actor(request))", function_source("save_ai_settings"))
        self.assertIn("sync_legacy_ai_payload_to_central(conn, values, ai_actor(request))", function_source("system_ai_config"))


if __name__ == "__main__":
    unittest.main()
