from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography.fernet import Fernet, InvalidToken


AI_PROVIDER_TYPES = {
    "ollama",
    "openai_compatible",
    "openai",
    "gemini",
    "anthropic",
    "groq",
    "openrouter",
    "custom_http",
}

AI_FUNCTIONS = (
    ("anomaly_analysis", "Análise de anomalia"),
    ("mitigation_analysis", "Análise de mitigação"),
    ("flowspec_explanation", "Explicação de regra FlowSpec"),
    ("attack_summary", "Resumo de ataque"),
    ("severity_classification", "Classificação de severidade"),
    ("report_generation", "Geração de relatório"),
    ("daily_summary", "Resumo diário"),
    ("bgp_diagnosis", "Diagnóstico BGP"),
    ("sensor_diagnosis", "Diagnóstico de sensor"),
    ("operator_explanation", "Explicação para operador"),
    ("notification_text", "Texto para Telegram/e-mail"),
)

MITIGATION_SCHEMA = {
    "type": "object",
    "required": ["recommended_candidate_index", "confidence", "risk", "classification", "reason"],
    "properties": {
        "recommended_candidate_index": {"type": "integer"},
        "confidence": {"type": ["number", "string"]},
        "risk": {"enum": ["low", "medium", "high", "none"]},
        "classification": {"type": "string"},
        "reason": {"type": "string"},
        "operator_summary": {"type": "string"},
    },
}

DEFAULT_PROMPTS = {
    "mitigation_analysis": {
        "name": "Análise consultiva de mitigação",
        "system_prompt": (
            "Você analisa evidências e recomenda uma opção já fornecida. Nunca execute mitigação, "
            "nunca anuncie FlowSpec, nunca escreva em FIFO e nunca ignore políticas determinísticas."
        ),
        "user_template": "Analise a anomalia {{anomaly_id}} e os candidates existentes: {{flows}}",
        "variables": ["anomaly_id", "sensor_name", "connector_name", "flows", "bgp_status"],
        "schema": MITIGATION_SCHEMA,
    },
    "notification_text": {
        "name": "Texto de notificação",
        "system_prompt": "Produza texto objetivo. Se falhar, o template determinístico será usado.",
        "user_template": "Resuma {{rule_name}} com severidade {{severity}}.",
        "variables": ["rule_name", "severity", "sensor_name", "duration", "bps", "pps"],
        "schema": {"type": "object", "required": ["summary"], "properties": {"summary": {"type": "string"}}},
    },
}

PROVIDER_DEFAULTS = {
    "ollama": {"base_url": "http://gmj-flow-ollama:11434", "models_endpoint": "/api/tags", "chat_endpoint": "/api/generate"},
    "openai_compatible": {"base_url": "", "models_endpoint": "/v1/models", "chat_endpoint": "/v1/chat/completions"},
    "openai": {"base_url": "https://api.openai.com", "models_endpoint": "/v1/models", "chat_endpoint": "/v1/chat/completions"},
    "gemini": {"base_url": "https://generativelanguage.googleapis.com", "models_endpoint": "/v1beta/models", "chat_endpoint": "/v1beta/models/{model}:generateContent"},
    "anthropic": {"base_url": "https://api.anthropic.com", "models_endpoint": "/v1/models", "chat_endpoint": "/v1/messages"},
    "groq": {"base_url": "https://api.groq.com/openai/v1", "models_endpoint": "/models", "chat_endpoint": "/chat/completions"},
    "openrouter": {"base_url": "https://openrouter.ai/api", "models_endpoint": "/v1/models", "chat_endpoint": "/v1/chat/completions"},
    "custom_http": {"base_url": "", "models_endpoint": "/models", "chat_endpoint": "/generate"},
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def clean_text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def is_masked_credential(value: Any) -> bool:
    """Identify UI placeholders that must never be encrypted as credentials."""
    candidate = clean_text(value)
    if not candidate:
        return False
    lowered = candidate.casefold()
    if lowered in {"[configured]", "configured", "not configured", "nao configurada", "não configurada"}:
        return True
    if "•" in candidate or "â€¢" in candidate:
        return True
    return bool(re.fullmatch(r"(?i)(?:key|gsk|sk)[-_]?(?:\*|x){3,}[A-Za-z0-9_-]{0,8}", candidate))


def normalize_provider_transport(
    provider_type: Any,
    base_url: Any,
    models_endpoint: Any,
    chat_endpoint: Any,
) -> tuple[str, str, str]:
    """Return canonical transport settings while accepting legacy Groq records."""
    normalized_type = clean_text(provider_type).lower().replace("-", "_")
    defaults = _provider_defaults(normalized_type)
    normalized_base = clean_text(base_url) or defaults["base_url"]
    normalized_models = clean_text(models_endpoint) or defaults["models_endpoint"]
    normalized_chat = clean_text(chat_endpoint) or defaults["chat_endpoint"]

    if normalized_type == "groq":
        parsed = urllib.parse.urlsplit(normalized_base.rstrip("/"))
        if (parsed.hostname or "").lower() == "api.groq.com":
            normalized_base = "https://api.groq.com/openai/v1"
        if normalized_base.rstrip("/").endswith("/openai/v1"):
            if normalized_models == "/v1/models":
                normalized_models = "/models"
            if normalized_chat == "/v1/chat/completions":
                normalized_chat = "/chat/completions"

    return normalized_base.rstrip("/"), normalized_models, normalized_chat


def normalize_provider_config(config: dict[str, Any]) -> dict[str, Any]:
    item = dict(config)
    base_url, models_endpoint, chat_endpoint = normalize_provider_transport(
        item.get("provider_type") or item.get("provider"),
        item.get("base_url"),
        item.get("models_endpoint"),
        item.get("chat_endpoint"),
    )
    item["base_url"] = base_url
    item["models_endpoint"] = models_endpoint
    item["chat_endpoint"] = chat_endpoint
    return item


def sqlite_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    return bool(value)


def json_loads(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(clean_text(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _secret_seed(explicit_seed: str | None = None) -> str:
    seed = clean_text(explicit_seed or os.getenv("GMJFLOW_AI_CREDENTIAL_KEY") or os.getenv("GMJFLOW_AUTH_SECRET"))
    if not seed:
        seed = "gmj-flow-dev-secret-change-me"
    return seed


def credential_cipher(explicit_seed: str | None = None) -> Fernet:
    digest = hashlib.sha256(("gmj-flow-ai-credentials:v1:" + _secret_seed(explicit_seed)).encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(secret: str, explicit_seed: str | None = None) -> str:
    value = clean_text(secret)
    if not value:
        return ""
    token = credential_cipher(explicit_seed).encrypt(value.encode("utf-8")).decode("ascii")
    return f"fernet:v1:{token}"


def decrypt_secret(value: str, explicit_seed: str | None = None) -> str:
    token = clean_text(value)
    if not token:
        return ""
    if not token.startswith("fernet:v1:"):
        raise ValueError("Formato de credencial não suportado")
    try:
        return clean_text(credential_cipher(explicit_seed).decrypt(token.split(":", 2)[2].encode("ascii")).decode("utf-8"))
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise ValueError("Credencial não pôde ser descriptografada") from exc


def mask_secret(secret: str) -> str:
    value = clean_text(secret)
    if not value:
        return "Não configurada"
    suffix = value[-4:] if len(value) >= 4 else value
    prefix = value[:3] if len(value) > 8 else "key"
    return f"{prefix}-••••••••••••{suffix}"


def decode_extra_headers(value: Any, explicit_seed: str | None = None) -> dict[str, str]:
    raw = clean_text(value)
    if not raw or raw == "{}":
        return {}
    if raw.startswith("fernet:v1:"):
        raw = decrypt_secret(raw, explicit_seed)
    parsed = json_loads(raw, {})
    return {str(key): str(item) for key, item in parsed.items()} if isinstance(parsed, dict) else {}


def sensitive_header_name(name: str) -> bool:
    return bool(re.search(r"(?i)(authorization|api[_-]?key|token|secret|credential)", clean_text(name)))


def sanitize_error(error: Any, secrets: list[str] | None = None) -> str:
    text = clean_text(error)
    for secret in secrets or []:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)([A-Za-z0-9_-]*(?:authorization|api[_-]?key|token|secret|credential)[A-Za-z0-9_-]*)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", text)
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "sk-[REDACTED]", text)
    text = re.sub(r"\bgsk_[A-Za-z0-9_-]{8,}\b", "gsk_[REDACTED]", text)
    return text[:2000]


def safe_request_diagnostic(
    api_key: Any,
    final_url: Any,
    headers: dict[str, Any] | None,
    payload: dict[str, Any] | None,
) -> dict[str, Any]:
    credential = clean_text(api_key)
    effective_headers = {clean_text(key).lower(): clean_text(value) for key, value in (headers or {}).items()}
    authorization = effective_headers.get("authorization", "")
    return {
        "starts_with_gsk": credential.startswith("gsk_"),
        "credential_length": len(credential),
        "credential_fingerprint_sha256": hashlib.sha256(credential.encode("utf-8")).hexdigest()[:12] if credential else "",
        "final_url": clean_text(final_url),
        "authorization_present": bool(authorization),
        "authorization_is_bearer_credential": bool(credential) and authorization == f"Bearer {credential}",
        "credential_placeholder_rejected": False,
        "model": clean_text((payload or {}).get("model")),
    }


def sanitized_http_error(exc: urllib.error.HTTPError, secrets: list[str] | None = None) -> str:
    try:
        raw_body = exc.read()
    except Exception:
        raw_body = b""
    if isinstance(raw_body, bytes):
        body = raw_body.decode("utf-8", errors="replace")
    else:
        body = clean_text(raw_body)
    status = f"HTTP {int(exc.code)} {clean_text(getattr(exc, 'reason', ''))}".strip()
    sanitized_body = sanitize_error(body, secrets)
    return sanitize_error(f"{status}: {sanitized_body}" if sanitized_body else status, secrets)


def _provider_defaults(provider_type: str) -> dict[str, str]:
    return dict(PROVIDER_DEFAULTS.get(provider_type) or PROVIDER_DEFAULTS["custom_http"])


def ensure_ai_schema(conn: sqlite3.Connection, legacy_settings: dict[str, Any] | None = None) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS ai_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            provider_type TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            base_url TEXT NOT NULL DEFAULT '',
            api_key_encrypted TEXT NOT NULL DEFAULT '',
            api_key_last4 TEXT NOT NULL DEFAULT '',
            organization TEXT NOT NULL DEFAULT '',
            project TEXT NOT NULL DEFAULT '',
            timeout_seconds INTEGER NOT NULL DEFAULT 30,
            default_model TEXT NOT NULL DEFAULT '',
            max_context_tokens INTEGER NOT NULL DEFAULT 8192,
            max_output_tokens INTEGER NOT NULL DEFAULT 1024,
            temperature REAL NOT NULL DEFAULT 0.1,
            top_p REAL NOT NULL DEFAULT 1.0,
            retries INTEGER NOT NULL DEFAULT 1,
            retry_interval_ms INTEGER NOT NULL DEFAULT 500,
            priority INTEGER NOT NULL DEFAULT 100,
            requests_per_minute INTEGER NOT NULL DEFAULT 0,
            tokens_per_minute INTEGER NOT NULL DEFAULT 0,
            calls_per_day INTEGER NOT NULL DEFAULT 0,
            daily_cost_limit REAL NOT NULL DEFAULT 0,
            monthly_cost_limit REAL NOT NULL DEFAULT 0,
            block_on_limit INTEGER NOT NULL DEFAULT 1,
            fallback_local_on_limit INTEGER NOT NULL DEFAULT 0,
            supports_json INTEGER NOT NULL DEFAULT 1,
            supports_tools INTEGER NOT NULL DEFAULT 0,
            notes TEXT NOT NULL DEFAULT '',
            models_endpoint TEXT NOT NULL DEFAULT '',
            chat_endpoint TEXT NOT NULL DEFAULT '',
            extra_headers_json TEXT NOT NULL DEFAULT '{}',
            custom_options_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'not_configured',
            last_latency_ms INTEGER NOT NULL DEFAULT 0,
            last_error TEXT NOT NULL DEFAULT '',
            last_checked_at TEXT NOT NULL DEFAULT '',
            legacy_key TEXT UNIQUE,
            created_by TEXT NOT NULL DEFAULT 'system',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ai_models (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            manually_configured INTEGER NOT NULL DEFAULT 0,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            disk_bytes INTEGER NOT NULL DEFAULT 0,
            estimated_ram_bytes INTEGER NOT NULL DEFAULT 0,
            context_tokens INTEGER NOT NULL DEFAULT 0,
            downloaded_at TEXT NOT NULL DEFAULT '',
            modified_at TEXT NOT NULL DEFAULT '',
            loaded INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL DEFAULT 'available',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(provider_id, name),
            FOREIGN KEY(provider_id) REFERENCES ai_providers(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS ai_routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            function_key TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            primary_provider_id INTEGER,
            primary_model TEXT NOT NULL DEFAULT '',
            fallback_provider_id INTEGER,
            fallback_model TEXT NOT NULL DEFAULT '',
            timeout_seconds INTEGER NOT NULL DEFAULT 30,
            temperature REAL NOT NULL DEFAULT 0.1,
            max_context_chars INTEGER NOT NULL DEFAULT 12000,
            max_top_flows INTEGER NOT NULL DEFAULT 30,
            max_attempts INTEGER NOT NULL DEFAULT 1,
            sensitive_data_policy TEXT NOT NULL DEFAULT 'mask_ips',
            require_structured INTEGER NOT NULL DEFAULT 1,
            repair_json_once INTEGER NOT NULL DEFAULT 1,
            fallback_on_timeout INTEGER NOT NULL DEFAULT 1,
            fallback_on_rate_limit INTEGER NOT NULL DEFAULT 1,
            fallback_on_server_error INTEGER NOT NULL DEFAULT 1,
            fallback_on_invalid_json INTEGER NOT NULL DEFAULT 0,
            fallback_on_cost_limit INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(primary_provider_id) REFERENCES ai_providers(id) ON DELETE SET NULL,
            FOREIGN KEY(fallback_provider_id) REFERENCES ai_providers(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS ai_prompts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            function_key TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 1,
            system_prompt TEXT NOT NULL DEFAULT '',
            user_template TEXT NOT NULL DEFAULT '',
            variables_json TEXT NOT NULL DEFAULT '[]',
            expected_format TEXT NOT NULL DEFAULT 'json',
            schema_json TEXT NOT NULL DEFAULT '{}',
            recommended_model TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT 'system',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(name, version)
        );
        CREATE TABLE IF NOT EXISTS ai_prompt_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt_id INTEGER NOT NULL,
            version INTEGER NOT NULL,
            snapshot_json TEXT NOT NULL,
            changed_by TEXT NOT NULL DEFAULT 'system',
            created_at TEXT NOT NULL,
            UNIQUE(prompt_id, version),
            FOREIGN KEY(prompt_id) REFERENCES ai_prompts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS ai_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_key TEXT NOT NULL DEFAULT '',
            function_key TEXT NOT NULL,
            provider_id INTEGER,
            provider_name TEXT NOT NULL DEFAULT '',
            model TEXT NOT NULL DEFAULT '',
            duration_ms INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            fallback_used INTEGER NOT NULL DEFAULT 0,
            input_tokens INTEGER NOT NULL DEFAULT 0,
            output_tokens INTEGER NOT NULL DEFAULT 0,
            estimated_cost REAL NOT NULL DEFAULT 0,
            anomaly_id INTEGER,
            mitigation_id INTEGER,
            error_type TEXT NOT NULL DEFAULT '',
            error_message TEXT NOT NULL DEFAULT '',
            prompt_snapshot TEXT NOT NULL DEFAULT '',
            response_snapshot TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(provider_id) REFERENCES ai_providers(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS ai_usage_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id INTEGER NOT NULL UNIQUE,
            requests_per_minute INTEGER NOT NULL DEFAULT 0,
            tokens_per_minute INTEGER NOT NULL DEFAULT 0,
            calls_per_day INTEGER NOT NULL DEFAULT 0,
            daily_cost_limit REAL NOT NULL DEFAULT 0,
            monthly_cost_limit REAL NOT NULL DEFAULT 0,
            block_on_limit INTEGER NOT NULL DEFAULT 1,
            fallback_local_on_limit INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(provider_id) REFERENCES ai_providers(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS ai_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ai_global_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ai_requests_created ON ai_requests(created_at, function_key);
        CREATE INDEX IF NOT EXISTS idx_ai_requests_provider ON ai_requests(provider_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_ai_audit_created ON ai_audit_log(created_at);
        """
    )
    now = utc_now_iso()
    defaults = {
        "global_enabled": "false",
        "history_content_policy": "sanitized",
        "history_retention_days": "30",
        "external_ip_policy": "never_internal_full",
    }
    for key, value in defaults.items():
        conn.execute(
            "INSERT OR IGNORE INTO ai_global_settings (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, now),
        )
    migrate_legacy_ai_settings(conn, legacy_settings or {})
    _seed_routes_and_prompts(conn)


def migrate_legacy_ai_settings(conn: sqlite3.Connection, settings: dict[str, Any]) -> None:
    now = utc_now_iso()
    completed = conn.execute("SELECT value FROM ai_global_settings WHERE key = 'legacy_migration_completed'").fetchone()
    if completed is not None and sqlite_bool(completed["value"]):
        return
    provider_type = clean_text(settings.get("ai_provider") or "ollama").lower().replace("-", "_")
    if provider_type in {"llama.cpp", "llamacpp"}:
        provider_type = "openai_compatible"
    if provider_type not in AI_PROVIDER_TYPES:
        provider_type = "openai_compatible"
    defaults = _provider_defaults(provider_type)
    base_url = clean_text(settings.get("ai_base_url")) or defaults["base_url"]
    model = clean_text(settings.get("ai_model")) or "qwen2.5:3b-instruct"
    timeout = _bounded_int(settings.get("ai_timeout_seconds"), 20, 1, 300)
    enabled = sqlite_bool(settings.get("ai_mitigation_enabled", False))
    conn.execute(
        """
        INSERT INTO ai_providers (
            name, provider_type, enabled, base_url, timeout_seconds, default_model,
            max_context_tokens, max_output_tokens, priority, supports_json,
            models_endpoint, chat_endpoint, custom_options_json, status, legacy_key, created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'migration', ?, ?)
        ON CONFLICT(legacy_key) DO NOTHING
        """,
        (
            "Ollama Produção" if provider_type == "ollama" else "Provider migrado",
            provider_type,
            1 if enabled else 0,
            base_url,
            timeout,
            model,
            _bounded_int(settings.get("ai_max_context_chars"), 12000, 1000, 100000),
            _bounded_int(settings.get("ai_num_predict"), 160, 32, 4096),
            10,
            1,
            defaults["models_endpoint"],
            defaults["chat_endpoint"],
            json_dumps({
                "keep_alive": clean_text(settings.get("ai_keep_alive")) or "30m",
                "model_profile": clean_text(settings.get("ai_model_profile")) or "recommended",
            }),
            "not_configured",
            "legacy_default",
            now,
            now,
        ),
    )
    provider_row = conn.execute("SELECT * FROM ai_providers WHERE legacy_key = 'legacy_default'").fetchone()
    if provider_row is None:
        return
    provider_id = int(provider_row["id"])
    conn.execute(
        """
        INSERT INTO ai_models (provider_id, name, display_name, enabled, manually_configured, context_tokens, state, created_at, updated_at)
        VALUES (?, ?, ?, 1, 1, ?, 'configured', ?, ?)
        ON CONFLICT(provider_id, name) DO NOTHING
        """,
        (provider_id, model, model, _bounded_int(settings.get("ai_max_context_chars"), 12000, 1000, 100000), now, now),
    )
    conn.execute(
        "UPDATE ai_global_settings SET value = ?, updated_at = ? WHERE key = 'global_enabled' AND value = 'false'",
        ("true" if enabled else "false", now),
    )
    route = conn.execute("SELECT id FROM ai_routes WHERE function_key = 'mitigation_analysis'").fetchone()
    if route is None:
        conn.execute(
            """
            INSERT INTO ai_routes (
                function_key, display_name, enabled, primary_provider_id, primary_model,
                timeout_seconds, max_context_chars, max_top_flows, max_attempts,
                sensitive_data_policy, require_structured, created_at, updated_at
            ) VALUES ('mitigation_analysis', 'Análise de mitigação', ?, ?, ?, ?, ?, ?, 1, 'mask_ips', 1, ?, ?)
            """,
            (
                1 if enabled else 0,
                provider_id,
                model,
                timeout,
                _bounded_int(settings.get("ai_max_context_chars"), 12000, 1000, 100000),
                _bounded_int(settings.get("ai_max_top_flows"), 30, 1, 200),
                now,
                now,
            ),
        )
    conn.execute(
        "INSERT OR REPLACE INTO ai_global_settings (key, value, updated_at) VALUES ('legacy_migration_completed', 'true', ?)",
        (now,),
    )


def _seed_routes_and_prompts(conn: sqlite3.Connection) -> None:
    now = utc_now_iso()
    for function_key, display_name in AI_FUNCTIONS:
        conn.execute(
            """
            INSERT OR IGNORE INTO ai_routes (
                function_key, display_name, enabled, sensitive_data_policy,
                require_structured, created_at, updated_at
            ) VALUES (?, ?, 0, 'mask_ips', 1, ?, ?)
            """,
            (function_key, display_name, now, now),
        )
    for function_key, item in DEFAULT_PROMPTS.items():
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO ai_prompts (
                name, function_key, version, enabled, system_prompt, user_template,
                variables_json, expected_format, schema_json, created_by, created_at, updated_at
            ) VALUES (?, ?, 1, 1, ?, ?, ?, 'json', ?, 'migration', ?, ?)
            """,
            (
                item["name"],
                function_key,
                item["system_prompt"],
                item["user_template"],
                json_dumps(item["variables"]),
                json_dumps(item["schema"]),
                now,
                now,
            ),
        )
        prompt_id = int(cursor.lastrowid or 0)
        if prompt_id:
            prompt = conn.execute("SELECT * FROM ai_prompts WHERE id = ?", (prompt_id,)).fetchone()
            conn.execute(
                "INSERT OR IGNORE INTO ai_prompt_versions (prompt_id, version, snapshot_json, changed_by, created_at) VALUES (?, 1, ?, 'migration', ?)",
                (prompt_id, json_dumps(dict(prompt)), now),
            )


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    return max(minimum, min(result, maximum))


def global_ai_settings(conn: sqlite3.Connection) -> dict[str, str]:
    rows = conn.execute("SELECT key, value FROM ai_global_settings").fetchall()
    return {row["key"]: row["value"] for row in rows}


def update_global_ai_settings(conn: sqlite3.Connection, values: dict[str, Any], actor: str) -> dict[str, str]:
    allowed = {"global_enabled", "history_content_policy", "history_retention_days", "external_ip_policy"}
    now = utc_now_iso()
    for key, value in values.items():
        if key not in allowed:
            continue
        if key == "global_enabled":
            value = "true" if sqlite_bool(value) else "false"
        elif key == "history_content_policy":
            value = clean_text(value) if clean_text(value) in {"none", "sanitized", "full"} else "sanitized"
        elif key == "history_retention_days":
            value = str(_bounded_int(value, 30, 1, 3650))
        elif key == "external_ip_policy":
            value = clean_text(value) if clean_text(value) in {"never_internal_full", "route_policy"} else "never_internal_full"
        conn.execute(
            "INSERT INTO ai_global_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, str(value), now),
        )
    retention_days = _bounded_int(global_ai_settings(conn).get("history_retention_days"), 30, 1, 3650)
    cutoff = datetime.fromtimestamp(time.time() - retention_days * 86400, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    conn.execute("DELETE FROM ai_requests WHERE created_at < ?", (cutoff,))
    audit_ai_action(conn, actor, "update_settings", "ai_global_settings", None, {"keys": sorted(set(values) & allowed)})
    return global_ai_settings(conn)


def audit_ai_action(conn: sqlite3.Connection, actor: str, action: str, entity_type: str, entity_id: int | None, details: dict[str, Any] | None = None) -> None:
    safe_details = dict(details or {})
    for key in list(safe_details):
        if "key" in key.lower() or "secret" in key.lower() or "password" in key.lower():
            safe_details.pop(key, None)
    conn.execute(
        "INSERT INTO ai_audit_log (actor, action, entity_type, entity_id, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (clean_text(actor) or "system", action, entity_type, entity_id, json_dumps(safe_details), utc_now_iso()),
    )


def provider_public(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = normalize_provider_config(dict(row))
    encrypted = clean_text(item.pop("api_key_encrypted", ""))
    last4 = clean_text(item.pop("api_key_last4", ""))
    item["enabled"] = sqlite_bool(item.get("enabled"))
    item["supports_json"] = sqlite_bool(item.get("supports_json"))
    item["supports_tools"] = sqlite_bool(item.get("supports_tools"))
    item["block_on_limit"] = sqlite_bool(item.get("block_on_limit"))
    item["fallback_local_on_limit"] = sqlite_bool(item.get("fallback_local_on_limit"))
    item["has_api_key"] = bool(encrypted)
    item["api_key_masked"] = f"key-••••••••••••{last4}" if last4 else "Não configurada"
    headers = decode_extra_headers(item.pop("extra_headers_json", "{}"))
    item["extra_headers"] = {
        key: "[configured]" if sensitive_header_name(key) and value else value
        for key, value in headers.items()
    }
    item["custom_options"] = json_loads(item.pop("custom_options_json", "{}"), {})
    return item


def provider_runtime(row: sqlite3.Row | dict[str, Any], explicit_seed: str | None = None) -> dict[str, Any]:
    item = normalize_provider_config(dict(row))
    encrypted = clean_text(item.get("api_key_encrypted"))
    decrypted = clean_text(decrypt_secret(encrypted, explicit_seed)) if encrypted else ""
    item["credential_placeholder_rejected"] = is_masked_credential(decrypted)
    item["api_key"] = "" if item["credential_placeholder_rejected"] else decrypted
    item["extra_headers"] = decode_extra_headers(item.get("extra_headers_json"), explicit_seed)
    item["custom_options"] = json_loads(item.get("custom_options_json"), {})
    return item


def list_ai_providers(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM ai_providers ORDER BY priority, name, id").fetchall()
    return [provider_public(row) for row in rows]


def get_ai_provider(conn: sqlite3.Connection, provider_id: int, runtime: bool = False) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM ai_providers WHERE id = ?", (int(provider_id),)).fetchone()
    if row is None:
        return None
    return provider_runtime(row) if runtime else provider_public(row)


def save_ai_provider(conn: sqlite3.Connection, payload: dict[str, Any], actor: str, provider_id: int | None = None) -> dict[str, Any]:
    provider_type = clean_text(payload.get("provider_type") or payload.get("type")).lower().replace("-", "_")
    if provider_type not in AI_PROVIDER_TYPES:
        raise ValueError("Tipo de provider inválido")
    name = clean_text(payload.get("name"))
    if not name:
        raise ValueError("Nome do provider é obrigatório")
    now = utc_now_iso()
    existing = conn.execute("SELECT * FROM ai_providers WHERE id = ?", (int(provider_id),)).fetchone() if provider_id else None
    api_key = clean_text(payload.get("api_key"))
    encrypted = clean_text(existing["api_key_encrypted"]) if existing is not None else ""
    last4 = clean_text(existing["api_key_last4"]) if existing is not None else ""
    if is_masked_credential(api_key):
        api_key = ""
    if api_key:
        encrypted = encrypt_secret(api_key)
        last4 = api_key[-4:]
    existing_headers = decode_extra_headers(existing["extra_headers_json"]) if existing is not None else {}
    incoming_headers = {
        str(key): str(value)
        for key, value in dict(payload.get("extra_headers") or {}).items()
    }
    for key, value in list(incoming_headers.items()):
        if value == "[configured]" and key in existing_headers:
            incoming_headers[key] = existing_headers[key]
    encrypted_headers = encrypt_secret(json_dumps(incoming_headers)) if incoming_headers else "{}"
    base_url, models_endpoint, chat_endpoint = normalize_provider_transport(
        provider_type,
        payload.get("base_url"),
        payload.get("models_endpoint"),
        payload.get("chat_endpoint"),
    )
    values = {
        "name": name,
        "provider_type": provider_type,
        "enabled": 1 if payload.get("enabled", True) else 0,
        "base_url": base_url,
        "api_key_encrypted": encrypted,
        "api_key_last4": last4,
        "organization": clean_text(payload.get("organization")),
        "project": clean_text(payload.get("project")),
        "timeout_seconds": _bounded_int(payload.get("timeout_seconds"), 30, 1, 300),
        "default_model": clean_text(payload.get("default_model")),
        "max_context_tokens": _bounded_int(payload.get("max_context_tokens"), 8192, 256, 1000000),
        "max_output_tokens": _bounded_int(payload.get("max_output_tokens"), 1024, 1, 100000),
        "temperature": max(0.0, min(float(payload.get("temperature", 0.1)), 2.0)),
        "top_p": max(0.0, min(float(payload.get("top_p", 1.0)), 1.0)),
        "retries": _bounded_int(payload.get("retries"), 1, 0, 10),
        "retry_interval_ms": _bounded_int(payload.get("retry_interval_ms"), 500, 0, 60000),
        "priority": _bounded_int(payload.get("priority"), 100, 1, 10000),
        "requests_per_minute": _bounded_int(payload.get("requests_per_minute"), 0, 0, 1000000),
        "tokens_per_minute": _bounded_int(payload.get("tokens_per_minute"), 0, 0, 1000000000),
        "calls_per_day": _bounded_int(payload.get("calls_per_day"), 0, 0, 10000000),
        "daily_cost_limit": max(0.0, float(payload.get("daily_cost_limit") or 0)),
        "monthly_cost_limit": max(0.0, float(payload.get("monthly_cost_limit") or 0)),
        "block_on_limit": 1 if payload.get("block_on_limit", True) else 0,
        "fallback_local_on_limit": 1 if payload.get("fallback_local_on_limit", False) else 0,
        "supports_json": 1 if payload.get("supports_json", True) else 0,
        "supports_tools": 1 if payload.get("supports_tools", False) else 0,
        "notes": clean_text(payload.get("notes")),
        "models_endpoint": models_endpoint,
        "chat_endpoint": chat_endpoint,
        "extra_headers_json": encrypted_headers,
        "custom_options_json": json_dumps(payload.get("custom_options") or {}),
        "updated_at": now,
    }
    if existing is None:
        columns = [*values.keys(), "created_by", "created_at"]
        insert_values = [*values.values(), clean_text(actor) or "admin", now]
        placeholders = ",".join("?" for _ in columns)
        cursor = conn.execute(f"INSERT INTO ai_providers ({','.join(columns)}) VALUES ({placeholders})", insert_values)
        provider_id = int(cursor.lastrowid)
        action = "create"
    else:
        assignments = ",".join(f"{column} = ?" for column in values)
        conn.execute(f"UPDATE ai_providers SET {assignments} WHERE id = ?", [*values.values(), int(provider_id)])
        action = "update"
    conn.execute(
        """
        INSERT INTO ai_usage_limits (
            provider_id, requests_per_minute, tokens_per_minute, calls_per_day,
            daily_cost_limit, monthly_cost_limit, block_on_limit, fallback_local_on_limit, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(provider_id) DO UPDATE SET
            requests_per_minute = excluded.requests_per_minute,
            tokens_per_minute = excluded.tokens_per_minute,
            calls_per_day = excluded.calls_per_day,
            daily_cost_limit = excluded.daily_cost_limit,
            monthly_cost_limit = excluded.monthly_cost_limit,
            block_on_limit = excluded.block_on_limit,
            fallback_local_on_limit = excluded.fallback_local_on_limit,
            updated_at = excluded.updated_at
        """,
        (
            provider_id,
            values["requests_per_minute"],
            values["tokens_per_minute"],
            values["calls_per_day"],
            values["daily_cost_limit"],
            values["monthly_cost_limit"],
            values["block_on_limit"],
            values["fallback_local_on_limit"],
            now,
        ),
    )
    audit_ai_action(conn, actor, action, "ai_provider", int(provider_id), {"name": name, "provider_type": provider_type, "credential_changed": bool(api_key)})
    return get_ai_provider(conn, int(provider_id)) or {}


def duplicate_ai_provider(conn: sqlite3.Connection, provider_id: int, actor: str) -> dict[str, Any]:
    source = conn.execute("SELECT * FROM ai_providers WHERE id = ?", (int(provider_id),)).fetchone()
    if source is None:
        raise ValueError("Provider não encontrado")
    data = dict(source)
    base_name = f"{data['name']} (cópia)"
    name = base_name
    index = 2
    while conn.execute("SELECT 1 FROM ai_providers WHERE name = ?", (name,)).fetchone():
        name = f"{base_name} {index}"
        index += 1
    data["name"] = name
    data["api_key"] = decrypt_secret(data.get("api_key_encrypted")) if data.get("api_key_encrypted") else ""
    data["extra_headers"] = decode_extra_headers(data.get("extra_headers_json"))
    data["custom_options"] = json_loads(data.get("custom_options_json"), {})
    result = save_ai_provider(conn, data, actor)
    audit_ai_action(conn, actor, "duplicate", "ai_provider", int(result["id"]), {"source_provider_id": provider_id})
    return result


def delete_ai_provider(conn: sqlite3.Connection, provider_id: int, actor: str) -> None:
    row = conn.execute("SELECT name FROM ai_providers WHERE id = ?", (int(provider_id),)).fetchone()
    if row is None:
        raise ValueError("Provider não encontrado")
    in_use = conn.execute(
        "SELECT 1 FROM ai_routes WHERE primary_provider_id = ? OR fallback_provider_id = ? LIMIT 1",
        (int(provider_id), int(provider_id)),
    ).fetchone()
    if in_use:
        raise ValueError("Provider está em uso por uma rota")
    audit_ai_action(conn, actor, "delete", "ai_provider", int(provider_id), {"name": row["name"]})
    conn.execute("DELETE FROM ai_providers WHERE id = ?", (int(provider_id),))


def toggle_ai_provider(conn: sqlite3.Connection, provider_id: int, actor: str) -> dict[str, Any]:
    row = conn.execute("SELECT enabled FROM ai_providers WHERE id = ?", (int(provider_id),)).fetchone()
    if row is None:
        raise ValueError("Provider não encontrado")
    enabled = not sqlite_bool(row["enabled"])
    conn.execute("UPDATE ai_providers SET enabled = ?, updated_at = ? WHERE id = ?", (1 if enabled else 0, utc_now_iso(), int(provider_id)))
    audit_ai_action(conn, actor, "activate" if enabled else "deactivate", "ai_provider", int(provider_id))
    return get_ai_provider(conn, int(provider_id)) or {}


def list_ai_routes(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT r.*, p.name AS primary_provider_name, f.name AS fallback_provider_name
        FROM ai_routes r
        LEFT JOIN ai_providers p ON p.id = r.primary_provider_id
        LEFT JOIN ai_providers f ON f.id = r.fallback_provider_id
        ORDER BY r.display_name
        """
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        for key in (
            "enabled", "require_structured", "repair_json_once", "fallback_on_timeout",
            "fallback_on_rate_limit", "fallback_on_server_error", "fallback_on_invalid_json", "fallback_on_cost_limit",
        ):
            item[key] = sqlite_bool(item.get(key))
        result.append(item)
    return result


def save_ai_route(conn: sqlite3.Connection, function_key: str, payload: dict[str, Any], actor: str) -> dict[str, Any]:
    if function_key not in {item[0] for item in AI_FUNCTIONS}:
        raise ValueError("Função de IA inválida")
    now = utc_now_iso()
    values = {
        "enabled": 1 if payload.get("enabled", False) else 0,
        "primary_provider_id": int(payload["primary_provider_id"]) if payload.get("primary_provider_id") else None,
        "primary_model": clean_text(payload.get("primary_model")),
        "fallback_provider_id": int(payload["fallback_provider_id"]) if payload.get("fallback_provider_id") else None,
        "fallback_model": clean_text(payload.get("fallback_model")),
        "timeout_seconds": _bounded_int(payload.get("timeout_seconds"), 30, 1, 300),
        "temperature": max(0.0, min(float(payload.get("temperature", 0.1)), 2.0)),
        "max_context_chars": _bounded_int(payload.get("max_context_chars"), 12000, 1000, 1000000),
        "max_top_flows": _bounded_int(payload.get("max_top_flows"), 30, 1, 1000),
        "max_attempts": _bounded_int(payload.get("max_attempts"), 1, 1, 10),
        "sensitive_data_policy": clean_text(payload.get("sensitive_data_policy")) or "mask_ips",
        "require_structured": 1 if payload.get("require_structured", True) else 0,
        "repair_json_once": 1 if payload.get("repair_json_once", True) else 0,
        "fallback_on_timeout": 1 if payload.get("fallback_on_timeout", True) else 0,
        "fallback_on_rate_limit": 1 if payload.get("fallback_on_rate_limit", True) else 0,
        "fallback_on_server_error": 1 if payload.get("fallback_on_server_error", True) else 0,
        "fallback_on_invalid_json": 1 if payload.get("fallback_on_invalid_json", False) else 0,
        "fallback_on_cost_limit": 1 if payload.get("fallback_on_cost_limit", False) else 0,
        "updated_at": now,
    }
    assignments = ",".join(f"{key} = ?" for key in values)
    conn.execute(f"UPDATE ai_routes SET {assignments} WHERE function_key = ?", [*values.values(), function_key])
    audit_ai_action(conn, actor, "update", "ai_route", None, {"function_key": function_key})
    return next(item for item in list_ai_routes(conn) if item["function_key"] == function_key)


def list_ai_prompts(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM ai_prompts ORDER BY function_key, version DESC").fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["enabled"] = sqlite_bool(item.get("enabled"))
        item["variables"] = json_loads(item.pop("variables_json", "[]"), [])
        item["schema"] = json_loads(item.pop("schema_json", "{}"), {})
        result.append(item)
    return result


def save_ai_prompt(conn: sqlite3.Connection, payload: dict[str, Any], actor: str, prompt_id: int | None = None) -> dict[str, Any]:
    function_key = clean_text(payload.get("function_key"))
    if function_key not in {item[0] for item in AI_FUNCTIONS}:
        raise ValueError("Função de prompt inválida")
    name = clean_text(payload.get("name"))
    if not name:
        raise ValueError("Nome do prompt é obrigatório")
    now = utc_now_iso()
    existing = conn.execute("SELECT * FROM ai_prompts WHERE id = ?", (int(prompt_id),)).fetchone() if prompt_id else None
    version = int(existing["version"] or 1) + 1 if existing is not None else 1
    values = {
        "name": name,
        "function_key": function_key,
        "version": version,
        "enabled": 1 if payload.get("enabled", True) else 0,
        "system_prompt": clean_text(payload.get("system_prompt")),
        "user_template": clean_text(payload.get("user_template")),
        "variables_json": json_dumps(payload.get("variables") or []),
        "expected_format": clean_text(payload.get("expected_format")) or "json",
        "schema_json": json_dumps(payload.get("schema") or {}),
        "recommended_model": clean_text(payload.get("recommended_model")),
        "updated_at": now,
    }
    if existing is None:
        columns = [*values, "created_by", "created_at"]
        cursor = conn.execute(
            f"INSERT INTO ai_prompts ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            [*values.values(), clean_text(actor) or "admin", now],
        )
        prompt_id = int(cursor.lastrowid)
        action = "create"
    else:
        conn.execute(
            f"UPDATE ai_prompts SET {','.join(f'{key} = ?' for key in values)} WHERE id = ?",
            [*values.values(), int(prompt_id)],
        )
        action = "version"
    snapshot = conn.execute("SELECT * FROM ai_prompts WHERE id = ?", (int(prompt_id),)).fetchone()
    conn.execute(
        "INSERT OR REPLACE INTO ai_prompt_versions (prompt_id, version, snapshot_json, changed_by, created_at) VALUES (?, ?, ?, ?, ?)",
        (int(prompt_id), version, json_dumps(dict(snapshot)), clean_text(actor) or "admin", now),
    )
    audit_ai_action(conn, actor, action, "ai_prompt", int(prompt_id), {"function_key": function_key, "version": version})
    return next(item for item in list_ai_prompts(conn) if int(item["id"]) == int(prompt_id))


def prompt_versions(conn: sqlite3.Connection, prompt_id: int) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM ai_prompt_versions WHERE prompt_id = ? ORDER BY version DESC", (int(prompt_id),)).fetchall()
    return [{**dict(row), "snapshot": json_loads(row["snapshot_json"], {})} for row in rows]


def restore_prompt_version(conn: sqlite3.Connection, prompt_id: int, version: int, actor: str) -> dict[str, Any]:
    row = conn.execute("SELECT snapshot_json FROM ai_prompt_versions WHERE prompt_id = ? AND version = ?", (int(prompt_id), int(version))).fetchone()
    if row is None:
        raise ValueError("Versão do prompt não encontrada")
    snapshot = json_loads(row["snapshot_json"], {})
    return save_ai_prompt(
        conn,
        {
            "name": snapshot.get("name"),
            "function_key": snapshot.get("function_key"),
            "enabled": sqlite_bool(snapshot.get("enabled")),
            "system_prompt": snapshot.get("system_prompt"),
            "user_template": snapshot.get("user_template"),
            "variables": json_loads(snapshot.get("variables_json"), []),
            "expected_format": snapshot.get("expected_format"),
            "schema": json_loads(snapshot.get("schema_json"), {}),
            "recommended_model": snapshot.get("recommended_model"),
        },
        actor,
        prompt_id,
    )


def render_prompt(template: str, variables: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        return clean_text(variables.get(match.group(1), ""))

    return re.sub(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}", replace, clean_text(template))


def mask_ip_addresses(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        value = match.group(0)
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return value
        if address.version == 4:
            parts = value.split(".")
            return ".".join([*parts[:3], "x"])
        return ":".join(value.split(":")[:4]) + ":xxxx"

    return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9A-Fa-f:]{3,}\b", replace, clean_text(text))


def remove_internal_ip_addresses(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        value = match.group(0)
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return value
        return "[internal-ip]" if address.is_private else value

    return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", replace, clean_text(text))


def sanitize_ai_content(text: str, policy: str, external_provider: bool = False) -> str:
    result = clean_text(text)
    if policy in {"mask_ips", "aggregates_only"}:
        result = mask_ip_addresses(result)
    if policy in {"remove_internal_ips", "aggregates_only"} or external_provider:
        result = remove_internal_ip_addresses(result)
    if policy in {"remove_client_names", "aggregates_only"}:
        result = re.sub(r"(?i)(client|cliente|customer)[=: ]+[^,;\n]+", "cliente=[removido]", result)
    if policy in {"remove_descriptions", "aggregates_only"}:
        result = re.sub(r"(?i)(description|descrição|descricao)[=: ]+[^,;\n]+", "descrição=[removida]", result)
    return result


def validate_structured_response(value: Any, schema: dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, str):
        content = value.strip()
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?", "", content, flags=re.IGNORECASE).strip()
            content = re.sub(r"```$", "", content).strip()
        value = json.loads(content)
    if not isinstance(value, dict):
        raise ValueError("Resposta estruturada deve ser um objeto JSON")
    for field in schema.get("required") or []:
        if field not in value:
            raise ValueError(f"Campo obrigatório ausente: {field}")
    for field, rules in (schema.get("properties") or {}).items():
        if field not in value:
            continue
        item = value[field]
        expected = rules.get("type")
        expected_types = expected if isinstance(expected, list) else [expected] if expected else []
        mapping = {"string": str, "number": (int, float), "integer": int, "boolean": bool, "array": list, "object": dict}
        if expected_types and not any(isinstance(item, mapping[kind]) and not (kind in {"number", "integer"} and isinstance(item, bool)) for kind in expected_types if kind in mapping):
            raise ValueError(f"Tipo inválido em {field}")
        if rules.get("enum") and item not in rules["enum"]:
            raise ValueError(f"Valor inválido em {field}")
    return value


@dataclass
class AIProviderError(Exception):
    message: str
    category: str = "unavailable"
    status_code: int | None = None
    diagnostic: dict[str, Any] | None = None

    def __str__(self) -> str:
        return self.message


class AIProvider:
    provider_type = "custom_http"

    def __init__(self, config: dict[str, Any], opener: Callable[..., Any] | None = None):
        provider_config = dict(config)
        provider_config.setdefault("provider_type", self.provider_type)
        self.config = normalize_provider_config(provider_config)
        self.opener = opener or urllib.request.urlopen
        self.api_key = clean_text(self.config.get("api_key"))
        self.last_request_diagnostic: dict[str, Any] = {}

    @property
    def base_url(self) -> str:
        return clean_text(self.config.get("base_url")).rstrip("/")

    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers.update({str(key): str(value) for key, value in (self.config.get("extra_headers") or {}).items()})
        return headers

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    def _request(self, path: str, method: str = "GET", payload: dict[str, Any] | None = None, timeout: int | None = None) -> tuple[dict[str, Any], int]:
        if not self.base_url:
            raise AIProviderError("Base URL não configurada", "not_configured")
        final_url = self._url(path)
        effective_headers = self.headers()
        self.last_request_diagnostic = safe_request_diagnostic(self.api_key, final_url, effective_headers, payload)
        self.last_request_diagnostic["credential_placeholder_rejected"] = bool(self.config.get("credential_placeholder_rejected"))
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(final_url, data=body, headers=effective_headers, method=method)
        started = time.monotonic()
        try:
            with self.opener(request, timeout=timeout or int(self.config.get("timeout_seconds") or 30)) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace") or "{}")
                return data if isinstance(data, dict) else {"items": data}, int((time.monotonic() - started) * 1000)
        except urllib.error.HTTPError as exc:
            category = "rate_limit" if exc.code == 429 else "credential_invalid" if exc.code in {401, 403} else "server_error" if exc.code >= 500 else "policy"
            raise AIProviderError(sanitized_http_error(exc, [self.api_key]), category, exc.code, dict(self.last_request_diagnostic)) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise AIProviderError("Timeout do provider", "timeout", diagnostic=dict(self.last_request_diagnostic)) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise AIProviderError("Timeout do provider", "timeout", diagnostic=dict(self.last_request_diagnostic)) from exc
            raise AIProviderError(sanitize_error(exc.reason, [self.api_key]), "unavailable", diagnostic=dict(self.last_request_diagnostic)) from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AIProviderError("Resposta HTTP inválida", "invalid_response", diagnostic=dict(self.last_request_diagnostic)) from exc

    def health(self) -> dict[str, Any]:
        started = time.monotonic()
        hostname = urllib.parse.urlparse(self.base_url).hostname
        dns_ok = False
        if hostname:
            try:
                socket.getaddrinfo(hostname, None)
                dns_ok = True
            except socket.gaierror:
                dns_ok = False
        try:
            models = self.list_models()
            return {"ok": True, "dns_ok": dns_ok, "models": models, "latency_ms": int((time.monotonic() - started) * 1000), "status": "available", "error": "", "diagnostic": dict(self.last_request_diagnostic)}
        except AIProviderError as exc:
            return {"ok": False, "dns_ok": dns_ok, "models": [], "latency_ms": int((time.monotonic() - started) * 1000), "status": exc.category, "error": sanitize_error(exc, [self.api_key]), "diagnostic": dict(exc.diagnostic or self.last_request_diagnostic)}

    def test_connection(self) -> dict[str, Any]:
        health = self.health()
        if not health["ok"]:
            return health
        try:
            response = self.generate("Responda somente: OK", model=clean_text(self.config.get("default_model")), structured=False)
            return {**health, "generation_ok": True, "model": response.get("model") or self.config.get("default_model"), "response_preview": clean_text(response.get("content"))[:160], "diagnostic": dict(self.last_request_diagnostic)}
        except AIProviderError as exc:
            return {**health, "ok": False, "generation_ok": False, "status": exc.category, "error": sanitize_error(exc, [self.api_key]), "response_preview": "", "diagnostic": dict(exc.diagnostic or self.last_request_diagnostic)}

    def list_models(self) -> list[dict[str, Any]]:
        payload, _ = self._request(clean_text(self.config.get("models_endpoint")) or "/models")
        raw = payload.get("data") or payload.get("models") or payload.get("items") or []
        return [{"name": clean_text(item.get("id") or item.get("name") or item.get("model")), "metadata": item} for item in raw if isinstance(item, dict)]

    def generate(self, prompt: str, model: str = "", structured: bool = False, system_prompt: str = "") -> dict[str, Any]:
        payload, latency = self._request(
            clean_text(self.config.get("chat_endpoint")) or "/generate",
            "POST",
            {"model": model or self.config.get("default_model"), "prompt": prompt, "system": system_prompt, "json": structured},
        )
        content = payload.get("response") or payload.get("content") or payload.get("text") or ""
        return {"content": clean_text(content), "latency_ms": latency, "model": model or self.config.get("default_model"), "usage": payload.get("usage") or {}}

    def estimate_usage(self, prompt: str, response: str) -> dict[str, Any]:
        return {"input_tokens": max(1, len(prompt) // 4), "output_tokens": max(1, len(response) // 4), "estimated_cost": 0.0}


class OllamaProvider(AIProvider):
    provider_type = "ollama"

    def list_models(self) -> list[dict[str, Any]]:
        payload, _ = self._request(clean_text(self.config.get("models_endpoint")) or "/api/tags")
        loaded_names: set[str] = set()
        try:
            running, _ = self._request("/api/ps")
            loaded_names = {
                clean_text(item.get("name") or item.get("model"))
                for item in running.get("models", [])
                if isinstance(item, dict)
            }
        except AIProviderError:
            loaded_names = set()
        return [
            {
                "name": clean_text(item.get("name") or item.get("model")),
                "size_bytes": int(item.get("size") or 0),
                "modified_at": clean_text(item.get("modified_at")),
                "loaded": clean_text(item.get("name") or item.get("model")) in loaded_names,
                "metadata": item,
            }
            for item in payload.get("models", [])
            if isinstance(item, dict)
        ]

    def generate(self, prompt: str, model: str = "", structured: bool = False, system_prompt: str = "") -> dict[str, Any]:
        selected_model = model or clean_text(self.config.get("default_model"))
        options = {
            "temperature": float(self.config.get("temperature") or 0.1),
            "top_p": float(self.config.get("top_p") or 1.0),
            "num_predict": int(self.config.get("max_output_tokens") or 1024),
            "num_ctx": int(self.config.get("max_context_tokens") or 8192),
        }
        body: dict[str, Any] = {"model": selected_model, "prompt": prompt, "stream": False, "options": options}
        if system_prompt:
            body["system"] = system_prompt
        if structured:
            body["format"] = "json"
        keep_alive = clean_text((self.config.get("custom_options") or {}).get("keep_alive"))
        if keep_alive:
            body["keep_alive"] = keep_alive
        payload, latency = self._request(clean_text(self.config.get("chat_endpoint")) or "/api/generate", "POST", body)
        content = payload.get("response") or (payload.get("message") or {}).get("content") or ""
        return {"content": clean_text(content), "latency_ms": latency, "model": selected_model, "usage": {"input_tokens": payload.get("prompt_eval_count"), "output_tokens": payload.get("eval_count")}}


class OpenAICompatibleProvider(AIProvider):
    provider_type = "openai_compatible"

    def headers(self) -> dict[str, str]:
        headers = super().headers()
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if clean_text(self.config.get("organization")):
            headers["OpenAI-Organization"] = clean_text(self.config.get("organization"))
        if clean_text(self.config.get("project")):
            headers["OpenAI-Project"] = clean_text(self.config.get("project"))
        return headers

    def generate(self, prompt: str, model: str = "", structured: bool = False, system_prompt: str = "") -> dict[str, Any]:
        selected_model = model or clean_text(self.config.get("default_model"))
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        body: dict[str, Any] = {
            "model": selected_model,
            "messages": messages,
            "temperature": float(self.config.get("temperature") or 0.1),
            "top_p": float(self.config.get("top_p") or 1.0),
            "max_tokens": int(self.config.get("max_output_tokens") or 1024),
        }
        if structured and sqlite_bool(self.config.get("supports_json", True)):
            body["response_format"] = {"type": "json_object"}
        payload, latency = self._request(clean_text(self.config.get("chat_endpoint")) or "/v1/chat/completions", "POST", body)
        choices = payload.get("choices") or []
        content = ((choices[0].get("message") or {}).get("content") if choices else "") or ""
        return {"content": clean_text(content), "latency_ms": latency, "model": payload.get("model") or selected_model, "usage": payload.get("usage") or {}}


class OpenAIProvider(OpenAICompatibleProvider):
    provider_type = "openai"


class GroqProvider(OpenAICompatibleProvider):
    provider_type = "groq"


class OpenRouterProvider(OpenAICompatibleProvider):
    provider_type = "openrouter"


class GeminiProvider(AIProvider):
    provider_type = "gemini"

    def headers(self) -> dict[str, str]:
        headers = super().headers()
        if self.api_key:
            headers["x-goog-api-key"] = self.api_key
        return headers

    def generate(self, prompt: str, model: str = "", structured: bool = False, system_prompt: str = "") -> dict[str, Any]:
        selected_model = model or clean_text(self.config.get("default_model"))
        path = (clean_text(self.config.get("chat_endpoint")) or "/v1beta/models/{model}:generateContent").replace("{model}", urllib.parse.quote(selected_model, safe=""))
        generation_config: dict[str, Any] = {"temperature": float(self.config.get("temperature") or 0.1), "topP": float(self.config.get("top_p") or 1.0), "maxOutputTokens": int(self.config.get("max_output_tokens") or 1024)}
        if structured:
            generation_config["responseMimeType"] = "application/json"
        body: dict[str, Any] = {"contents": [{"role": "user", "parts": [{"text": prompt}]}], "generationConfig": generation_config}
        if system_prompt:
            body["systemInstruction"] = {"parts": [{"text": system_prompt}]}
        payload, latency = self._request(path, "POST", body)
        candidates = payload.get("candidates") or []
        parts = ((candidates[0].get("content") or {}).get("parts") if candidates else []) or []
        content = "".join(clean_text(part.get("text")) for part in parts if isinstance(part, dict))
        return {"content": content, "latency_ms": latency, "model": selected_model, "usage": payload.get("usageMetadata") or {}}


class AnthropicProvider(AIProvider):
    provider_type = "anthropic"

    def headers(self) -> dict[str, str]:
        headers = super().headers()
        if self.api_key:
            headers["x-api-key"] = self.api_key
        headers["anthropic-version"] = "2023-06-01"
        return headers

    def generate(self, prompt: str, model: str = "", structured: bool = False, system_prompt: str = "") -> dict[str, Any]:
        selected_model = model or clean_text(self.config.get("default_model"))
        body: dict[str, Any] = {
            "model": selected_model,
            "max_tokens": int(self.config.get("max_output_tokens") or 1024),
            "temperature": float(self.config.get("temperature") or 0.1),
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            body["system"] = system_prompt
        payload, latency = self._request(clean_text(self.config.get("chat_endpoint")) or "/v1/messages", "POST", body)
        content = "".join(clean_text(item.get("text")) for item in payload.get("content", []) if isinstance(item, dict))
        return {"content": content, "latency_ms": latency, "model": payload.get("model") or selected_model, "usage": payload.get("usage") or {}}


class CustomHTTPProvider(AIProvider):
    provider_type = "custom_http"


PROVIDER_CLASSES = {
    "ollama": OllamaProvider,
    "openai_compatible": OpenAICompatibleProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "anthropic": AnthropicProvider,
    "groq": GroqProvider,
    "openrouter": OpenRouterProvider,
    "custom_http": CustomHTTPProvider,
}


def build_ai_provider(config: dict[str, Any], opener: Callable[..., Any] | None = None) -> AIProvider:
    provider_type = clean_text(config.get("provider_type") or config.get("provider")).lower().replace("-", "_")
    provider_class = PROVIDER_CLASSES.get(provider_type, CustomHTTPProvider)
    return provider_class(config, opener=opener)


def refresh_provider_models(conn: sqlite3.Connection, provider_id: int, actor: str, opener: Callable[..., Any] | None = None) -> list[dict[str, Any]]:
    config = get_ai_provider(conn, provider_id, runtime=True)
    if config is None:
        raise ValueError("Provider não encontrado")
    provider = build_ai_provider(config, opener)
    models = provider.list_models()
    now = utc_now_iso()
    for model in models:
        name = clean_text(model.get("name"))
        if not name:
            continue
        conn.execute(
            """
            INSERT INTO ai_models (
                provider_id, name, display_name, enabled, size_bytes, disk_bytes,
                estimated_ram_bytes, downloaded_at, modified_at,
                loaded, state, metadata_json, created_at, updated_at
            ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider_id, name) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                disk_bytes = excluded.disk_bytes,
                estimated_ram_bytes = excluded.estimated_ram_bytes,
                downloaded_at = CASE WHEN ai_models.downloaded_at = '' THEN excluded.downloaded_at ELSE ai_models.downloaded_at END,
                modified_at = excluded.modified_at,
                loaded = excluded.loaded,
                state = excluded.state,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at
            """,
            (
                provider_id,
                name,
                name,
                int(model.get("size_bytes") or 0),
                int(model.get("size_bytes") or 0),
                int(int(model.get("size_bytes") or 0) * 1.2),
                clean_text(model.get("modified_at")),
                clean_text(model.get("modified_at")),
                1 if model.get("loaded") else 0,
                "loaded" if model.get("loaded") else "available",
                json_dumps(model.get("metadata") or {}),
                now,
                now,
            ),
        )
    audit_ai_action(conn, actor, "list_models", "ai_provider", provider_id, {"model_count": len(models)})
    return list_provider_models(conn, provider_id)


def list_provider_models(conn: sqlite3.Connection, provider_id: int | None = None) -> list[dict[str, Any]]:
    params: list[Any] = []
    where = ""
    if provider_id:
        where = "WHERE m.provider_id = ?"
        params.append(int(provider_id))
    rows = conn.execute(
        f"""
        SELECT m.*, p.name AS provider_name, p.provider_type
        FROM ai_models m JOIN ai_providers p ON p.id = m.provider_id
        {where}
        ORDER BY p.priority, p.name, m.name
        """,
        params,
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["enabled"] = sqlite_bool(item.get("enabled"))
        item["manually_configured"] = sqlite_bool(item.get("manually_configured"))
        item["loaded"] = sqlite_bool(item.get("loaded"))
        item["metadata"] = json_loads(item.pop("metadata_json", "{}"), {})
        result.append(item)
    return result


def provider_usage_state(conn: sqlite3.Connection, provider: dict[str, Any]) -> tuple[bool, str]:
    provider_id = int(provider["id"])
    minute_ago = datetime.fromtimestamp(time.time() - 60, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    day_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
    month_start = datetime.now(timezone.utc).strftime("%Y-%m-01T00:00:00Z")
    minute = conn.execute("SELECT COUNT(*) AS requests, COALESCE(SUM(input_tokens + output_tokens), 0) AS tokens FROM ai_requests WHERE provider_id = ? AND created_at >= ?", (provider_id, minute_ago)).fetchone()
    day = conn.execute("SELECT COUNT(*) AS requests, COALESCE(SUM(estimated_cost), 0) AS cost FROM ai_requests WHERE provider_id = ? AND created_at >= ?", (provider_id, day_start)).fetchone()
    month = conn.execute("SELECT COALESCE(SUM(estimated_cost), 0) AS cost FROM ai_requests WHERE provider_id = ? AND created_at >= ?", (provider_id, month_start)).fetchone()
    checks = (
        (int(provider.get("requests_per_minute") or 0), int(minute["requests"] or 0), "Limite de requisições por minuto atingido"),
        (int(provider.get("tokens_per_minute") or 0), int(minute["tokens"] or 0), "Limite de tokens por minuto atingido"),
        (int(provider.get("calls_per_day") or 0), int(day["requests"] or 0), "Limite diário de chamadas atingido"),
    )
    for limit, usage, message in checks:
        if limit and usage >= limit:
            return (False, message) if sqlite_bool(provider.get("block_on_limit", True)) else (True, message)
    daily_cost = float(provider.get("daily_cost_limit") or 0)
    if daily_cost and float(day["cost"] or 0) >= daily_cost:
        return (False, "Limite financeiro diário atingido") if sqlite_bool(provider.get("block_on_limit", True)) else (True, "Limite financeiro diário registrado")
    monthly_cost = float(provider.get("monthly_cost_limit") or 0)
    if monthly_cost and float(month["cost"] or 0) >= monthly_cost:
        return (False, "Limite financeiro mensal atingido") if sqlite_bool(provider.get("block_on_limit", True)) else (True, "Limite financeiro mensal registrado")
    return True, ""


def _route_row(conn: sqlite3.Connection, function_key: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM ai_routes WHERE function_key = ?", (function_key,)).fetchone()
    return dict(row) if row else None


def central_ai_effective_config(conn: sqlite3.Connection, function_key: str = "mitigation_analysis") -> dict[str, Any] | None:
    route = _route_row(conn, function_key)
    if route is None or not route.get("primary_provider_id"):
        return None
    provider = get_ai_provider(conn, int(route["primary_provider_id"]), runtime=True)
    if provider is None:
        return None
    custom_options = provider.get("custom_options") or {}
    global_enabled = sqlite_bool(global_ai_settings(conn).get("global_enabled"))
    return {
        "enabled": global_enabled and sqlite_bool(route.get("enabled")) and sqlite_bool(provider.get("enabled")),
        "provider": provider["provider_type"],
        "provider_id": provider["id"],
        "provider_name": provider["name"],
        "base_url": provider["base_url"],
        "api_key": provider.get("api_key") or "",
        "selected_model": clean_text(route.get("primary_model")) or clean_text(provider.get("default_model")),
        "timeout_seconds": int(route.get("timeout_seconds") or provider.get("timeout_seconds") or 30),
        "max_top_flows": int(route.get("max_top_flows") or 30),
        "max_context_chars": int(route.get("max_context_chars") or 12000),
        "num_predict": int(provider.get("max_output_tokens") or 1024),
        "keep_alive": clean_text(custom_options.get("keep_alive")) or "30m",
        "selected_profile": "centralized",
        "allow_auto": False,
        "require_policy_validation": True,
        "route": route,
    }


def _history_content(conn: sqlite3.Connection, content: str, sanitized: str) -> str:
    policy = global_ai_settings(conn).get("history_content_policy", "sanitized")
    if policy == "none":
        return ""
    if policy == "full":
        return clean_text(content)[:12000]
    return clean_text(sanitized)[:12000]


def _log_ai_request(
    conn: sqlite3.Connection,
    function_key: str,
    provider: dict[str, Any] | None,
    model: str,
    status: str,
    duration_ms: int,
    attempts: int,
    fallback_used: bool,
    usage: dict[str, Any],
    error_type: str = "",
    error_message: str = "",
    prompt: str = "",
    sanitized_prompt: str = "",
    response: str = "",
    anomaly_id: int | None = None,
    mitigation_id: int | None = None,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO ai_requests (
            function_key, provider_id, provider_name, model, duration_ms, status,
            attempts, fallback_used, input_tokens, output_tokens, estimated_cost,
            anomaly_id, mitigation_id, error_type, error_message,
            prompt_snapshot, response_snapshot, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            function_key,
            int(provider["id"]) if provider else None,
            clean_text(provider.get("name")) if provider else "",
            model,
            duration_ms,
            status,
            attempts,
            1 if fallback_used else 0,
            int(usage.get("input_tokens") or 0),
            int(usage.get("output_tokens") or 0),
            float(usage.get("estimated_cost") or 0),
            anomaly_id,
            mitigation_id,
            error_type,
            sanitize_error(error_message, [clean_text(provider.get("api_key"))] if provider else []),
            _history_content(conn, prompt, sanitized_prompt),
            _history_content(conn, response, sanitize_ai_content(response, "mask_ips")),
            utc_now_iso(),
        ),
    )
    return int(cursor.lastrowid)


def _should_fallback(route: dict[str, Any], category: str) -> bool:
    mapping = {
        "timeout": "fallback_on_timeout",
        "rate_limit": "fallback_on_rate_limit",
        "server_error": "fallback_on_server_error",
        "unavailable": "fallback_on_server_error",
        "invalid_response": "fallback_on_invalid_json",
        "invalid_json": "fallback_on_invalid_json",
        "cost_limit": "fallback_on_cost_limit",
    }
    key = mapping.get(category)
    return bool(key and sqlite_bool(route.get(key)))


def execute_ai_route(
    conn: sqlite3.Connection,
    function_key: str,
    prompt: str,
    *,
    system_prompt: str = "",
    schema: dict[str, Any] | None = None,
    anomaly_id: int | None = None,
    mitigation_id: int | None = None,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    route = _route_row(conn, function_key)
    global_settings = global_ai_settings(conn)
    if not route or not sqlite_bool(route.get("enabled")) or not sqlite_bool(global_settings.get("global_enabled")):
        return {"ok": False, "status": "disabled", "error_type": "disabled", "error_message": "Função de IA desativada", "fallback_used": False}
    if not route.get("primary_provider_id"):
        return {"ok": False, "status": "not_configured", "error_type": "not_configured", "error_message": "Provider principal não configurado", "fallback_used": False}
    candidates = [
        (int(route["primary_provider_id"]), clean_text(route.get("primary_model")), False),
    ]
    if route.get("fallback_provider_id"):
        candidates.append((int(route["fallback_provider_id"]), clean_text(route.get("fallback_model")), True))
    last_error = ""
    last_category = "unavailable"
    fallback_attempted = False
    total_attempts = 0
    last_provider_config: dict[str, Any] | None = None
    last_model = ""
    started_total = time.monotonic()
    for provider_id, route_model, fallback_used in candidates:
        fallback_attempted = fallback_attempted or fallback_used
        provider_config = get_ai_provider(conn, provider_id, runtime=True)
        if provider_config is None:
            last_error = "Provider removido"
            last_category = "unavailable"
            if fallback_used or not _should_fallback(route, last_category):
                break
            continue
        last_provider_config = provider_config
        last_model = route_model or clean_text(provider_config.get("default_model"))
        if not sqlite_bool(provider_config.get("enabled")):
            last_error = "Provider desativado ou removido"
            last_category = "credential_disabled"
            break
        allowed, limit_message = provider_usage_state(conn, provider_config)
        if not allowed:
            last_error = limit_message
            last_category = "cost_limit" if "financeiro" in limit_message.lower() else "rate_limit"
            conn.execute(
                "UPDATE ai_providers SET status = 'limited', last_error = ?, last_checked_at = ?, updated_at = ? WHERE id = ?",
                (sanitize_error(limit_message), utc_now_iso(), utc_now_iso(), provider_id),
            )
            fallback_provider = get_ai_provider(conn, int(route.get("fallback_provider_id") or 0), runtime=True) if route.get("fallback_provider_id") else None
            provider_forces_local_fallback = sqlite_bool(provider_config.get("fallback_local_on_limit")) and clean_text((fallback_provider or {}).get("provider_type")) == "ollama"
            if fallback_used or (not provider_forces_local_fallback and not _should_fallback(route, last_category)):
                break
            continue
        provider = build_ai_provider(provider_config, opener)
        model = route_model or clean_text(provider_config.get("default_model"))
        last_model = model
        external_provider = provider_config.get("provider_type") != "ollama"
        force_external_privacy = external_provider and global_settings.get("external_ip_policy", "never_internal_full") != "route_policy"
        sanitized_prompt = sanitize_ai_content(prompt, clean_text(route.get("sensitive_data_policy")) or "mask_ips", external_provider=force_external_privacy)
        attempts = max(1, min(int(route.get("max_attempts") or 1), int(provider_config.get("retries") or 0) + 1))
        for attempt in range(1, attempts + 1):
            total_attempts += 1
            started = time.monotonic()
            try:
                generated = provider.generate(
                    sanitized_prompt,
                    model=model,
                    structured=sqlite_bool(route.get("require_structured")),
                    system_prompt=system_prompt,
                )
                content = clean_text(generated.get("content"))
                structured = None
                if sqlite_bool(route.get("require_structured")):
                    try:
                        structured = validate_structured_response(content, schema or {})
                    except (ValueError, json.JSONDecodeError) as exc:
                        if sqlite_bool(route.get("repair_json_once")):
                            correction = provider.generate(
                                f"Corrija a resposta abaixo para JSON válido, sem acrescentar texto:\n{content[:6000]}",
                                model=model,
                                structured=True,
                                system_prompt="Retorne somente JSON válido.",
                            )
                            content = clean_text(correction.get("content"))
                            structured = validate_structured_response(content, schema or {})
                        else:
                            raise AIProviderError(sanitize_error(exc), "invalid_json") from exc
                usage = dict(generated.get("usage") or {})
                estimate = provider.estimate_usage(sanitized_prompt, content)
                usage = {
                    "input_tokens": usage.get("prompt_tokens") or usage.get("input_tokens") or estimate["input_tokens"],
                    "output_tokens": usage.get("completion_tokens") or usage.get("output_tokens") or estimate["output_tokens"],
                    "estimated_cost": estimate["estimated_cost"],
                }
                duration_ms = int((time.monotonic() - started) * 1000)
                request_id = _log_ai_request(
                    conn, function_key, provider_config, model, "success", duration_ms, attempt,
                    fallback_used, usage, prompt=prompt, sanitized_prompt=sanitized_prompt,
                    response=content, anomaly_id=anomaly_id, mitigation_id=mitigation_id,
                )
                conn.execute(
                    "UPDATE ai_providers SET status = 'available', last_latency_ms = ?, last_error = '', last_checked_at = ?, updated_at = ? WHERE id = ?",
                    (duration_ms, utc_now_iso(), utc_now_iso(), provider_id),
                )
                return {
                    "ok": True,
                    "request_id": request_id,
                    "function_key": function_key,
                    "provider_id": provider_id,
                    "provider": provider_config["name"],
                    "provider_type": provider_config["provider_type"],
                    "model": generated.get("model") or model,
                    "content": content,
                    "structured": structured,
                    "duration_ms": duration_ms,
                    "attempts": attempt,
                    "fallback_used": fallback_used,
                    "usage": usage,
                }
            except AIProviderError as exc:
                last_error = sanitize_error(exc, [provider_config.get("api_key") or ""])
                last_category = exc.category
            except (ValueError, json.JSONDecodeError) as exc:
                last_error = sanitize_error(exc)
                last_category = "invalid_json"
            except Exception as exc:  # defensive boundary: provider failures never escape into detection/mitigation
                last_error = sanitize_error(exc, [provider_config.get("api_key") or ""])
                last_category = "timeout" if isinstance(exc, (TimeoutError, socket.timeout)) else "unavailable"
            if attempt < attempts and last_category in {"timeout", "rate_limit", "server_error", "unavailable"}:
                delay = max(0, int(provider_config.get("retry_interval_ms") or 0)) / 1000
                if delay:
                    time.sleep(min(delay, 2.0))
                continue
            break
        conn.execute(
            "UPDATE ai_providers SET status = ?, last_error = ?, last_checked_at = ?, updated_at = ? WHERE id = ?",
            (last_category, last_error, utc_now_iso(), utc_now_iso(), provider_id),
        )
        if fallback_used or not _should_fallback(route, last_category):
            break
    duration_ms = int((time.monotonic() - started_total) * 1000)
    request_id = _log_ai_request(
        conn, function_key, last_provider_config, last_model, "failed", duration_ms, total_attempts, fallback_attempted,
        {}, error_type=last_category, error_message=last_error, prompt=prompt,
        sanitized_prompt=sanitize_ai_content(prompt, "mask_ips"), anomaly_id=anomaly_id, mitigation_id=mitigation_id,
    )
    return {
        "ok": False,
        "request_id": request_id,
        "function_key": function_key,
        "status": "failed",
        "error_type": last_category,
        "error_message": last_error or "Todos os providers falharam",
        "duration_ms": duration_ms,
        "attempts": total_attempts,
        "fallback_used": fallback_attempted,
    }


def test_ai_provider(conn: sqlite3.Connection, provider_id: int, actor: str, opener: Callable[..., Any] | None = None) -> dict[str, Any]:
    config = get_ai_provider(conn, provider_id, runtime=True)
    if config is None:
        raise ValueError("Provider não encontrado")
    provider = build_ai_provider(config, opener)
    result = provider.test_connection()
    status = clean_text(result.get("status")) or ("available" if result.get("ok") else "unavailable")
    conn.execute(
        "UPDATE ai_providers SET status = ?, last_latency_ms = ?, last_error = ?, last_checked_at = ?, updated_at = ? WHERE id = ?",
        (status, int(result.get("latency_ms") or 0), sanitize_error(result.get("error"), [config.get("api_key") or ""]), utc_now_iso(), utc_now_iso(), provider_id),
    )
    audit_ai_action(conn, actor, "test", "ai_provider", provider_id, {"ok": bool(result.get("ok")), "status": status, "latency_ms": int(result.get("latency_ms") or 0)})
    result["error"] = sanitize_error(result.get("error"), [config.get("api_key") or ""])
    return result


def execute_ai_playground(
    conn: sqlite3.Connection,
    provider_id: int,
    function_key: str,
    prompt: str,
    *,
    model: str = "",
    context: str = "",
    temperature: float | None = None,
    timeout_seconds: int | None = None,
    structured: bool = False,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    config = get_ai_provider(conn, provider_id, runtime=True)
    if config is None or not sqlite_bool(config.get("enabled")):
        return {"ok": False, "status": "not_configured", "error_type": "not_configured", "error_message": "Provider não encontrado ou desativado"}
    allowed, limit_message = provider_usage_state(conn, config)
    if not allowed:
        return {"ok": False, "status": "limited", "error_type": "cost_limit", "error_message": limit_message}
    if temperature is not None:
        config["temperature"] = max(0.0, min(float(temperature), 2.0))
    if timeout_seconds is not None:
        config["timeout_seconds"] = _bounded_int(timeout_seconds, int(config.get("timeout_seconds") or 30), 1, 300)
    combined = clean_text(prompt)
    if context:
        combined = f"{combined}\n\nContexto de teste:\n{clean_text(context)}"
    external = config.get("provider_type") != "ollama"
    sanitized = sanitize_ai_content(combined, "mask_ips", external_provider=external)
    provider = build_ai_provider(config, opener)
    started = time.monotonic()
    selected_model = clean_text(model) or clean_text(config.get("default_model"))
    try:
        generated = provider.generate(sanitized, model=selected_model, structured=structured)
        content = clean_text(generated.get("content"))
        usage = dict(generated.get("usage") or {})
        estimate = provider.estimate_usage(sanitized, content)
        usage = {
            "input_tokens": usage.get("prompt_tokens") or usage.get("input_tokens") or estimate["input_tokens"],
            "output_tokens": usage.get("completion_tokens") or usage.get("output_tokens") or estimate["output_tokens"],
            "estimated_cost": estimate["estimated_cost"],
        }
        duration_ms = int((time.monotonic() - started) * 1000)
        request_id = _log_ai_request(
            conn, function_key or "playground", config, selected_model, "success", duration_ms,
            1, False, usage, prompt=combined, sanitized_prompt=sanitized, response=content,
        )
        return {"ok": True, "request_id": request_id, "content": content, "raw": content, "provider": config["name"], "model": generated.get("model") or selected_model, "duration_ms": duration_ms, "usage": usage, "diagnostic": dict(provider.last_request_diagnostic)}
    except Exception as exc:
        error = sanitize_error(exc, [config.get("api_key") or ""])
        category = exc.category if isinstance(exc, AIProviderError) else "unavailable"
        duration_ms = int((time.monotonic() - started) * 1000)
        request_id = _log_ai_request(
            conn, function_key or "playground", config, selected_model, "failed", duration_ms,
            1, False, {}, error_type=category, error_message=error, prompt=combined,
            sanitized_prompt=sanitized,
        )
        diagnostic = dict(exc.diagnostic or provider.last_request_diagnostic) if isinstance(exc, AIProviderError) else dict(provider.last_request_diagnostic)
        return {"ok": False, "request_id": request_id, "status": "failed", "error_type": category, "error_message": error, "duration_ms": duration_ms, "diagnostic": diagnostic}


def ai_overview(conn: sqlite3.Connection, memory: dict[str, Any] | None = None) -> dict[str, Any]:
    settings = global_ai_settings(conn)
    providers = list_ai_providers(conn)
    routes = list_ai_routes(conn)
    default_route = next((item for item in routes if item["function_key"] == "mitigation_analysis"), {})
    since = datetime.fromtimestamp(time.time() - 86400, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    usage = conn.execute(
        """
        SELECT COUNT(*) AS requests,
               SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS successes,
               SUM(CASE WHEN status != 'success' THEN 1 ELSE 0 END) AS failures,
               COALESCE(AVG(duration_ms), 0) AS avg_duration_ms,
               COALESCE(SUM(input_tokens + output_tokens), 0) AS tokens,
               COALESCE(SUM(estimated_cost), 0) AS cost
        FROM ai_requests WHERE created_at >= ?
        """,
        (since,),
    ).fetchone()
    ollama = next((item for item in providers if item["provider_type"] == "ollama"), None)
    return {
        "global_enabled": sqlite_bool(settings.get("global_enabled")),
        "default_provider": default_route.get("primary_provider_name") or "Não configurado",
        "default_model": default_route.get("primary_model") or "Não configurado",
        "fallback_provider": default_route.get("fallback_provider_name") or "Não configurado",
        "ollama_status": ollama.get("status") if ollama else "not_configured",
        "memory": memory or {"total": None, "available": None},
        "usage_24h": {
            "requests": int(usage["requests"] or 0),
            "successes": int(usage["successes"] or 0),
            "failures": int(usage["failures"] or 0),
            "avg_duration_ms": round(float(usage["avg_duration_ms"] or 0), 1),
            "tokens": int(usage["tokens"] or 0),
            "cost": round(float(usage["cost"] or 0), 6),
        },
        "providers": providers,
        "routes": routes,
        "safety_notice": "A IA fornece análise e recomendação. A execução é controlada pelas políticas determinísticas do GMJ-FLOW.",
    }


def ai_history(conn: sqlite3.Connection, limit: int = 200) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM ai_requests ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 1000)),)).fetchall()
    return [dict(row) for row in rows]


def ai_audit_history(conn: sqlite3.Connection, limit: int = 200) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM ai_audit_log ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 1000)),)).fetchall()
    return [{**dict(row), "details": json_loads(row["details_json"], {})} for row in rows]


__all__ = [
    "AI_FUNCTIONS",
    "AI_PROVIDER_TYPES",
    "AIProvider",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "OpenAIProvider",
    "GeminiProvider",
    "AnthropicProvider",
    "GroqProvider",
    "OpenRouterProvider",
    "CustomHTTPProvider",
    "ai_audit_history",
    "ai_history",
    "ai_overview",
    "audit_ai_action",
    "build_ai_provider",
    "central_ai_effective_config",
    "delete_ai_provider",
    "duplicate_ai_provider",
    "encrypt_secret",
    "ensure_ai_schema",
    "execute_ai_route",
    "execute_ai_playground",
    "get_ai_provider",
    "global_ai_settings",
    "list_ai_prompts",
    "list_ai_providers",
    "list_ai_routes",
    "list_provider_models",
    "mask_secret",
    "migrate_legacy_ai_settings",
    "prompt_versions",
    "provider_public",
    "refresh_provider_models",
    "render_prompt",
    "restore_prompt_version",
    "sanitize_ai_content",
    "sanitize_error",
    "save_ai_prompt",
    "save_ai_provider",
    "save_ai_route",
    "test_ai_provider",
    "toggle_ai_provider",
    "update_global_ai_settings",
    "validate_structured_response",
]
