import hashlib
import io
import json
import socket
import sqlite3
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services import ai_integration as ai  # noqa: E402


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def request_headers(request):
    return {str(key).lower(): str(value) for key, value in request.header_items()}


def database(legacy=None):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    ai.ensure_ai_schema(conn, legacy or {})
    conn.commit()
    return conn


def provider(conn, name, base_url, provider_type="ollama", **overrides):
    payload = {
        "name": name,
        "provider_type": provider_type,
        "enabled": True,
        "base_url": base_url,
        "default_model": "model-a",
        "retries": 0,
        **overrides,
    }
    return ai.save_ai_provider(conn, payload, "admin")


def route(conn, primary, fallback=None, **overrides):
    ai.update_global_ai_settings(conn, {"global_enabled": True}, "admin")
    return ai.save_ai_route(
        conn,
        "mitigation_analysis",
        {
            "enabled": True,
            "primary_provider_id": primary["id"],
            "primary_model": "model-a",
            "fallback_provider_id": fallback["id"] if fallback else None,
            "fallback_model": "model-b" if fallback else "",
            "timeout_seconds": 2,
            "max_attempts": 1,
            "require_structured": True,
            "repair_json_once": False,
            "fallback_on_timeout": True,
            "fallback_on_rate_limit": True,
            "fallback_on_server_error": True,
            "fallback_on_invalid_json": False,
            "fallback_on_cost_limit": False,
            **overrides,
        },
        "admin",
    )


SCHEMA = {
    "type": "object",
    "required": ["summary"],
    "properties": {"summary": {"type": "string"}},
}


class CentralAiMigrationTest(unittest.TestCase):
    def test_migration_preserves_legacy_configuration_and_is_idempotent(self):
        legacy = {
            "ai_mitigation_enabled": "true",
            "ai_provider": "ollama",
            "ai_base_url": "http://ollama:11434",
            "ai_model": "qwen-current",
            "ai_timeout_seconds": "27",
            "ai_max_top_flows": "41",
            "ai_max_context_chars": "15000",
            "ai_keep_alive": "45m",
            "ai_model_profile": "low-memory",
        }
        conn = database(legacy)
        ai.ensure_ai_schema(conn, legacy)
        providers = ai.list_ai_providers(conn)
        self.assertEqual(1, len(providers))
        self.assertEqual("qwen-current", providers[0]["default_model"])
        self.assertEqual(27, providers[0]["timeout_seconds"])
        self.assertEqual("45m", providers[0]["custom_options"]["keep_alive"])
        self.assertEqual("low-memory", providers[0]["custom_options"]["model_profile"])
        selected = next(item for item in ai.list_ai_routes(conn) if item["function_key"] == "mitigation_analysis")
        self.assertEqual(15000, selected["max_context_chars"])
        self.assertEqual(41, selected["max_top_flows"])
        self.assertEqual("qwen-current", selected["primary_model"])
        self.assertEqual(11, conn.execute("SELECT COUNT(*) FROM ai_routes").fetchone()[0])

    def test_central_disable_is_not_reverted_by_legacy_migration(self):
        legacy = {"ai_mitigation_enabled": "true", "ai_provider": "ollama"}
        conn = database(legacy)
        ai.update_global_ai_settings(conn, {"global_enabled": False}, "admin")
        ai.ensure_ai_schema(conn, legacy)
        self.assertEqual("false", ai.global_ai_settings(conn)["global_enabled"])


class CentralAiProviderTest(unittest.TestCase):
    def test_multiple_providers_and_encrypted_masked_secret(self):
        conn = database()
        first = provider(conn, "External one", "http://one", "openai_compatible", api_key="sk-super-secret-ABCD", extra_headers={"X-API-Token": "header-secret", "X-Region": "br"})
        second = provider(conn, "External two", "http://two", "openai_compatible", api_key="key-two-WXYZ")
        self.assertNotEqual(first["id"], second["id"])
        raw = conn.execute("SELECT api_key_encrypted FROM ai_providers WHERE id = ?", (first["id"],)).fetchone()[0]
        self.assertTrue(raw.startswith("fernet:v1:"))
        self.assertNotIn("sk-super-secret-ABCD", raw)
        raw_headers = conn.execute("SELECT extra_headers_json FROM ai_providers WHERE id = ?", (first["id"],)).fetchone()[0]
        self.assertTrue(raw_headers.startswith("fernet:v1:"))
        self.assertNotIn("header-secret", raw_headers)
        public = ai.get_ai_provider(conn, first["id"])
        self.assertNotIn("api_key", public)
        self.assertNotIn("api_key_encrypted", public)
        self.assertTrue(public["has_api_key"])
        self.assertTrue(public["api_key_masked"].endswith("ABCD"))
        self.assertNotIn("sk-super-secret-ABCD", json.dumps(public))
        self.assertEqual("[configured]", public["extra_headers"]["X-API-Token"])
        self.assertEqual("br", public["extra_headers"]["X-Region"])
        self.assertNotIn("secret", json.dumps(ai.ai_audit_history(conn)).lower())

    def test_ollama_connection_models_and_generation(self):
        conn = database()
        item = provider(conn, "Ollama test", "http://ollama")

        def opener(request, timeout=0):
            if request.full_url.endswith("/api/tags"):
                return FakeResponse({"models": [{"name": "qwen:3b", "size": 1000}]})
            if request.full_url.endswith("/api/ps"):
                return FakeResponse({"models": [{"name": "qwen:3b"}]})
            self.assertTrue(request.full_url.endswith("/api/generate"))
            return FakeResponse({"response": "OK", "model": "qwen:3b", "prompt_eval_count": 2, "eval_count": 1})

        with mock.patch.object(ai.socket, "getaddrinfo", return_value=[("", "", "", "", "")]):
            result = ai.test_ai_provider(conn, item["id"], "admin", opener=opener)
        self.assertTrue(result["ok"])
        self.assertTrue(result["generation_ok"])
        models = ai.refresh_provider_models(conn, item["id"], "admin", opener=opener)
        self.assertEqual("qwen:3b", models[0]["name"])
        self.assertEqual(1000, models[0]["disk_bytes"])
        self.assertEqual(1200, models[0]["estimated_ram_bytes"])
        self.assertTrue(models[0]["loaded"])

    def test_openai_compatible_models_auth_and_generation(self):
        conn = database()
        item = provider(conn, "Compatible", "http://compatible", "openai_compatible", api_key="secret-1234")
        seen = []

        def opener(request, timeout=0):
            seen.append((request.full_url, request.headers.get("Authorization")))
            if request.full_url.endswith("/v1/models"):
                return FakeResponse({"data": [{"id": "fast-model"}]})
            return FakeResponse({"model": "fast-model", "choices": [{"message": {"content": "OK"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

        with mock.patch.object(ai.socket, "getaddrinfo", return_value=[("", "", "", "", "")]):
            result = ai.test_ai_provider(conn, item["id"], "admin", opener=opener)
        self.assertTrue(result["ok"])
        self.assertTrue(all(auth == "Bearer secret-1234" for _, auth in seen))

    def test_extra_headers_cannot_override_required_or_authentication_headers(self):
        secret = "gsk_protected_credential_123456"
        provider_instance = ai.GroqProvider({
            "provider_type": "groq",
            "base_url": "https://api.groq.com/openai/v1",
            "api_key": secret,
            "extra_headers": {
                "Authorization": "",
                "authorization": "Bearer attacker-value",
                "User-Agent": "",
                "user-agent": "Mozilla/5.0",
                "Accept": "text/html",
                "Content-Type": "",
                "X-Admin-Header": "allowed",
            },
        })
        headers = {key.lower(): value for key, value in provider_instance.headers(json_request=True).items()}
        self.assertEqual("GMJ-FLOW/1.0", headers["user-agent"])
        self.assertEqual("application/json", headers["accept"])
        self.assertEqual("application/json", headers["content-type"])
        self.assertEqual(f"Bearer {secret}", headers["authorization"])
        self.assertEqual("allowed", headers["x-admin-header"])

    def test_groq_uses_trimmed_credential_canonical_urls_and_safe_diagnostic(self):
        conn = database()
        secret = "gsk_test_credential_1234567890"
        item = provider(
            conn,
            "Groq",
            "https://api.groq.com/openai",
            "groq",
            api_key=f"  {secret}\r\n",
            default_model="openai/gpt-oss-120b",
            models_endpoint="/v1/models",
            chat_endpoint="/v1/chat/completions",
        )
        self.assertEqual("https://api.groq.com/openai/v1", item["base_url"])
        self.assertEqual("/models", item["models_endpoint"])
        self.assertEqual("/chat/completions", item["chat_endpoint"])
        self.assertEqual(secret, ai.get_ai_provider(conn, item["id"], runtime=True)["api_key"])
        seen = []

        def opener(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8")) if request.data else {}
            seen.append((request.full_url, request_headers(request), payload.get("model")))
            if request.full_url.endswith("/models"):
                return FakeResponse({"data": [{"id": "openai/gpt-oss-120b"}]})
            return FakeResponse({"model": "openai/gpt-oss-120b", "choices": [{"message": {"content": "OK"}}]})

        with mock.patch.object(ai.socket, "getaddrinfo", return_value=[("", "", "", "", "")]):
            result = ai.test_ai_provider(conn, item["id"], "admin", opener=opener)

        self.assertTrue(result["ok"])
        self.assertEqual(
            [
                "https://api.groq.com/openai/v1/models",
                "https://api.groq.com/openai/v1/chat/completions",
            ],
            [entry[0] for entry in seen],
        )
        self.assertTrue(all(entry[1]["user-agent"] == "GMJ-FLOW/1.0" for entry in seen))
        self.assertTrue(all(entry[1]["accept"] == "application/json" for entry in seen))
        self.assertTrue(all(entry[1]["authorization"] == f"Bearer {secret}" for entry in seen))
        self.assertNotIn("content-type", seen[0][1])
        self.assertEqual("application/json", seen[1][1]["content-type"])
        diagnostic = result["diagnostic"]
        self.assertTrue(diagnostic["starts_with_gsk"])
        self.assertEqual(len(secret), diagnostic["credential_length"])
        self.assertEqual(hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12], diagnostic["credential_fingerprint_sha256"])
        self.assertEqual("https://api.groq.com/openai/v1/chat/completions", diagnostic["final_url"])
        self.assertTrue(diagnostic["authorization_present"])
        self.assertTrue(diagnostic["authorization_is_bearer_credential"])
        self.assertTrue(diagnostic["user_agent_present"])
        self.assertEqual("GMJ-FLOW/1.0", diagnostic["user_agent_value"])
        self.assertTrue(diagnostic["accept_header_present"])
        self.assertEqual("application/json", diagnostic["content_type"])
        self.assertEqual("openai/gpt-oss-120b", diagnostic["model"])
        self.assertNotIn(secret, json.dumps(result))

    def test_masked_credential_never_overwrites_encrypted_secret(self):
        conn = database()
        secret = "gsk_original_credential_123456"
        item = provider(conn, "Groq mask", "https://api.groq.com/openai/v1", "groq", api_key=secret)
        encrypted_before = conn.execute("SELECT api_key_encrypted FROM ai_providers WHERE id = ?", (item["id"],)).fetchone()[0]
        ai.save_ai_provider(conn, {**item, "api_key": item["api_key_masked"]}, "admin", item["id"])
        encrypted_after = conn.execute("SELECT api_key_encrypted FROM ai_providers WHERE id = ?", (item["id"],)).fetchone()[0]
        self.assertEqual(encrypted_before, encrypted_after)
        self.assertEqual(secret, ai.get_ai_provider(conn, item["id"], runtime=True)["api_key"])

    def test_legacy_encrypted_visual_mask_is_rejected_before_header_creation(self):
        conn = database()
        item = provider(conn, "Legacy mask", "https://api.groq.com/openai/v1", "groq", api_key="gsk_original_123456")
        visual_mask = item["api_key_masked"]
        conn.execute(
            "UPDATE ai_providers SET api_key_encrypted = ?, api_key_last4 = ? WHERE id = ?",
            (ai.encrypt_secret(visual_mask), visual_mask[-4:], item["id"]),
        )
        runtime = ai.get_ai_provider(conn, item["id"], runtime=True)
        self.assertEqual("", runtime["api_key"])
        self.assertTrue(runtime["credential_placeholder_rejected"])
        built = ai.build_ai_provider(runtime)
        self.assertNotIn("Authorization", built.headers())

    def test_playground_preserves_sanitized_http_error_body_and_diagnostic(self):
        conn = database()
        secret = "gsk_rejected_credential_123456"
        item = provider(
            conn,
            "Groq error",
            "https://api.groq.com/openai/v1",
            "groq",
            api_key=secret,
            default_model="openai/gpt-oss-120b",
        )

        def opener(request, timeout=0):
            body = json.dumps({"error": {"message": f"Invalid API key: {secret}", "type": "authentication_error", "code": "invalid_api_key", "credential": secret}}).encode("utf-8")
            raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, io.BytesIO(body))

        result = ai.execute_ai_playground(
            conn,
            item["id"],
            "operator_explanation",
            "synthetic",
            model="openai/gpt-oss-120b",
            opener=opener,
        )
        self.assertFalse(result["ok"])
        self.assertEqual("credential_invalid", result["error_type"])
        self.assertIn("HTTP 403 Forbidden", result["error_message"])
        self.assertEqual("invalid_api_key", result["provider_error_code"])
        self.assertEqual("authentication_error", result["provider_error_type"])
        self.assertNotIn(secret, result["error_message"])
        self.assertEqual("https://api.groq.com/openai/v1/chat/completions", result["diagnostic"]["final_url"])
        self.assertEqual("openai/gpt-oss-120b", result["diagnostic"]["model"])
        self.assertTrue(result["diagnostic"]["authorization_present"])
        self.assertTrue(result["diagnostic"]["authorization_is_bearer_credential"])
        self.assertFalse(result["retryable"])

    def test_cloudflare_1010_is_client_blocked_with_safe_structured_details(self):
        conn = database()
        secret = "gsk_cloudflare_credential_123456"
        item = provider(
            conn,
            "Groq Cloudflare",
            "https://api.groq.com/openai/v1",
            "groq",
            api_key=secret,
            default_model="openai/gpt-oss-120b",
        )
        seen = []

        def opener(request, timeout=0):
            seen.append((request.full_url, request_headers(request)))
            body = f"""
                <html><title>Access denied</title>
                <span class="cf-error-code">1010</span>
                <div>browser_signature_banned</div>
                <div>Authorization: Bearer {secret}</div>
                <div>Ray ID: body-ray-id</div></html>
            """.encode("utf-8")
            raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {"CF-Ray": "header-ray-id-GRU"}, io.BytesIO(body))

        with mock.patch.object(ai.socket, "getaddrinfo", return_value=[("", "", "", "", "")]):
            tested = ai.test_ai_provider(conn, item["id"], "admin", opener=opener)
        played = ai.execute_ai_playground(
            conn,
            item["id"],
            "operator_explanation",
            "synthetic",
            model="openai/gpt-oss-120b",
            opener=opener,
        )

        for result in (tested, played):
            self.assertFalse(result["ok"])
            self.assertEqual("client_blocked", result["status"])
            self.assertEqual("client_blocked", result["error_type"])
            self.assertEqual(403, result["http_status"])
            self.assertEqual("cloudflare_1010", result["provider_error"])
            self.assertEqual("1010", result["provider_error_code"])
            self.assertEqual("browser_signature_banned", result["provider_error_type"])
            self.assertEqual("browser_signature_banned", result["provider_message"])
            self.assertTrue(result["cloudflare_error"])
            self.assertEqual("1010", result["cloudflare_error_code"])
            self.assertEqual("header-ray-id-GRU", result["cloudflare_ray_id"])
            self.assertFalse(result["retryable"])
            self.assertTrue(result["user_agent_present"])
            self.assertEqual("1010", result["diagnostic"]["cloudflare_error_code"])
            self.assertFalse(result["diagnostic"]["retryable"])
            self.assertTrue(result["diagnostic"]["user_agent_present"])
            self.assertEqual("GMJ-FLOW/1.0", result["diagnostic"]["user_agent_value"])
            self.assertTrue(result["diagnostic"]["accept_header_present"])
            self.assertNotIn(secret, json.dumps(result))
            self.assertNotIn("Authorization: Bearer", json.dumps(result))

        self.assertEqual("https://api.groq.com/openai/v1/models", tested["final_url"])
        self.assertEqual("https://api.groq.com/openai/v1/chat/completions", played["final_url"])
        self.assertEqual("", tested["diagnostic"]["content_type"])
        self.assertEqual("application/json", played["diagnostic"]["content_type"])
        self.assertTrue(all(headers["user-agent"] == "GMJ-FLOW/1.0" for _, headers in seen))
        self.assertTrue(all(headers["accept"] == "application/json" for _, headers in seen))
        stored_error = conn.execute("SELECT last_error FROM ai_providers WHERE id = ?", (item["id"],)).fetchone()[0]
        self.assertNotIn(secret, stored_error)
        self.assertNotIn(secret, json.dumps(ai.ai_history(conn)))


class CentralAiRoutingTest(unittest.TestCase):
    def test_cloudflare_client_block_is_not_retried_or_sent_to_fallback(self):
        conn = database()
        primary = provider(conn, "Blocked", "https://api.groq.com/openai/v1", "groq", api_key="gsk_blocked_123456", retries=2)
        fallback = provider(conn, "Must not run", "https://fallback.example", "openai_compatible", api_key="fallback-secret")
        route(conn, primary, fallback, max_attempts=3)
        calls = []

        def opener(request, timeout=0):
            calls.append(request.full_url)
            body = b'<span class="cf-error-code">1010</span><div>browser_signature_banned</div>'
            raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, io.BytesIO(body))

        result = ai.execute_ai_route(conn, "mitigation_analysis", "synthetic", schema=SCHEMA, opener=opener)
        self.assertFalse(result["ok"])
        self.assertEqual("client_blocked", result["status"])
        self.assertEqual("client_blocked", result["error_type"])
        self.assertEqual("cloudflare_1010", result["provider_error"])
        self.assertFalse(result["retryable"])
        self.assertEqual(1, len(calls))
        self.assertTrue(all("fallback.example" not in url for url in calls))

    def test_routing_and_fallback_use_the_shared_external_headers(self):
        conn = database()
        primary = provider(conn, "Primary external", "https://primary.example", "openai_compatible", api_key="primary-secret")
        fallback = provider(conn, "Fallback external", "https://fallback.example", "openai_compatible", api_key="fallback-secret")
        route(conn, primary, fallback)
        seen = []

        def opener(request, timeout=0):
            headers = request_headers(request)
            seen.append((request.full_url, headers))
            if "primary.example" in request.full_url:
                raise socket.timeout("slow")
            return FakeResponse({"model": "model-b", "choices": [{"message": {"content": '{"summary":"fallback"}'}}]})

        result = ai.execute_ai_route(conn, "mitigation_analysis", "synthetic", schema=SCHEMA, opener=opener)
        self.assertTrue(result["ok"])
        self.assertTrue(result["fallback_used"])
        self.assertEqual(2, len(seen))
        self.assertTrue(all(headers["user-agent"] == "GMJ-FLOW/1.0" for _, headers in seen))
        self.assertTrue(all(headers["accept"] == "application/json" for _, headers in seen))
        self.assertTrue(all(headers["content-type"] == "application/json" for _, headers in seen))
        self.assertEqual("Bearer primary-secret", seen[0][1]["authorization"])
        self.assertEqual("Bearer fallback-secret", seen[1][1]["authorization"])

    def test_timeout_retries_then_succeeds(self):
        conn = database()
        primary = provider(conn, "Retry", "http://retry", retries=1, retry_interval_ms=0)
        route(conn, primary, max_attempts=2)
        calls = []

        def opener(request, timeout=0):
            calls.append(request.full_url)
            if len(calls) == 1:
                raise socket.timeout("slow")
            return FakeResponse({"response": '{"summary":"ok"}'})

        result = ai.execute_ai_route(conn, "mitigation_analysis", "synthetic", schema=SCHEMA, opener=opener)
        self.assertTrue(result["ok"])
        self.assertEqual(2, result["attempts"])
        self.assertFalse(result["fallback_used"])

    def test_timeout_uses_configured_fallback(self):
        conn = database()
        primary = provider(conn, "Primary", "http://primary")
        fallback = provider(conn, "Fallback", "http://fallback")
        route(conn, primary, fallback)

        def opener(request, timeout=0):
            if "primary" in request.full_url:
                raise socket.timeout("slow")
            return FakeResponse({"response": '{"summary":"fallback"}'})

        result = ai.execute_ai_route(conn, "mitigation_analysis", "synthetic", schema=SCHEMA, opener=opener)
        self.assertTrue(result["ok"])
        self.assertTrue(result["fallback_used"])
        self.assertEqual("Fallback", result["provider"])

    def test_cost_limit_does_not_fallback_unless_configured(self):
        conn = database()
        primary = provider(conn, "Paid", "http://paid", daily_cost_limit=1, block_on_limit=True)
        fallback = provider(conn, "Local", "http://local")
        route(conn, primary, fallback, fallback_on_cost_limit=False)
        conn.execute(
            "INSERT INTO ai_requests (function_key, provider_id, status, estimated_cost, created_at) VALUES (?, ?, ?, ?, ?)",
            ("mitigation_analysis", primary["id"], "success", 1.5, ai.utc_now_iso()),
        )
        calls = []

        def opener(request, timeout=0):
            calls.append(request.full_url)
            return FakeResponse({"response": '{"summary":"should not run"}'})

        result = ai.execute_ai_route(conn, "mitigation_analysis", "synthetic", schema=SCHEMA, opener=opener)
        self.assertFalse(result["ok"])
        self.assertEqual("cost_limit", result["error_type"])
        self.assertFalse(result["fallback_used"])
        self.assertEqual([], calls)

    def test_invalid_structured_response_never_becomes_a_decision(self):
        conn = database()
        primary = provider(conn, "Invalid", "http://invalid")
        fallback = provider(conn, "Unused", "http://unused")
        route(conn, primary, fallback, repair_json_once=False, fallback_on_invalid_json=False)
        calls = []

        def opener(request, timeout=0):
            calls.append(request.full_url)
            return FakeResponse({"response": "free-form recommendation"})

        result = ai.execute_ai_route(conn, "mitigation_analysis", "synthetic", schema=SCHEMA, opener=opener)
        self.assertFalse(result["ok"])
        self.assertEqual("invalid_json", result["error_type"])
        self.assertFalse(result["fallback_used"])
        self.assertTrue(all("unused" not in url for url in calls))

    def test_disabled_provider_does_not_trigger_fallback(self):
        conn = database()
        primary = provider(conn, "Disabled", "http://disabled", enabled=False)
        fallback = provider(conn, "Fallback disabled path", "http://fallback")
        route(conn, primary, fallback)
        result = ai.execute_ai_route(conn, "mitigation_analysis", "synthetic", schema=SCHEMA, opener=lambda *_args, **_kwargs: self.fail("provider called"))
        self.assertFalse(result["ok"])
        self.assertEqual("credential_disabled", result["error_type"])
        self.assertFalse(result["fallback_used"])

    def test_external_provider_internal_ip_policy_is_enforced(self):
        conn = database()
        primary = provider(conn, "External privacy", "http://external", "openai_compatible")
        route(conn, primary, sensitive_data_policy="full")
        prompts = []

        def opener(request, timeout=0):
            body = json.loads(request.data.decode("utf-8"))
            prompts.append(body["messages"][-1]["content"])
            return FakeResponse({"model": "model-a", "choices": [{"message": {"content": '{"summary":"ok"}'}}]})

        first = ai.execute_ai_route(conn, "mitigation_analysis", "cliente=ACME ip=192.168.1.20", schema=SCHEMA, opener=opener)
        self.assertTrue(first["ok"])
        self.assertIn("[internal-ip]", prompts[-1])
        ai.update_global_ai_settings(conn, {"external_ip_policy": "route_policy"}, "admin")
        second = ai.execute_ai_route(conn, "mitigation_analysis", "cliente=ACME ip=192.168.1.20", schema=SCHEMA, opener=opener)
        self.assertTrue(second["ok"])
        self.assertIn("192.168.1.20", prompts[-1])

    def test_playground_has_no_operational_side_effect_apis(self):
        source = Path(ai.__file__).read_text(encoding="utf-8")
        start = source.index("def execute_ai_playground(")
        end = source.index("def ai_overview(", start)
        playground = source[start:end]
        for forbidden in ("/api/bgp", "exabgp.in", "subprocess", "os.open(", "Path("):
            self.assertNotIn(forbidden, playground)


if __name__ == "__main__":
    unittest.main()
