"""Single-owner effective configuration model for GMJ-FLOW.

Operational state lives in SQLite (system_settings); environment variables are
either bootstrap/infrastructure or emergency kill switches. This module computes
the effective value for each operational flag as:

    effective = persistent_setting(DB) AND NOT environment_kill_switch

It is deliberately dependency-light (only threat_intelligence helpers) so that
service modules can use it without importing the FastAPI application module.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any, Mapping

from app.services.threat_intelligence import clean_text

TRUTHY = {"1", "true", "yes", "on"}

# Kill switches are OFF by default (absence never disables a feature).
AUTO_MITIGATION_KILL_SWITCH = "GMJFLOW_AUTO_MITIGATION_KILL_SWITCH"
SECURITY_AI_KILL_SWITCH = "GMJFLOW_SECURITY_AI_KILL_SWITCH"
THREAT_POLICY_AUTO_KILL_SWITCH = "GMJFLOW_THREAT_POLICY_AUTO_KILL_SWITCH"

# Legacy env variables used ONLY for one-shot migration into SQLite. They are
# not read as operational state after migration.
LEGACY_ENV_KEYS = {
    "auto_mitigation_enabled": "GMJFLOW_AUTO_MITIGATION_ENABLED",
    "threat_policy_auto_enabled": "GMJFLOW_THREAT_POLICY_AUTO_ENABLED",
    "threat_response_profile_id": "GMJFLOW_THREAT_RESPONSE_PROFILE_ID",
}


def env_flag(name: str, default: str = "false") -> bool:
    return clean_text(os.getenv(name, default)).lower() in TRUTHY


def env_explicitly_set(name: str) -> bool:
    """True only when the variable is present with a non-empty value."""
    return clean_text(os.getenv(name, "")) != ""


def kill_switch_active(name: str) -> bool:
    """Kill switches default to OFF; only an explicit truthy value blocks."""
    return env_flag(name, "false")


def system_settings_rows(conn: sqlite3.Connection) -> dict[str, str]:
    """Read system_settings from an OPEN connection; tolerant to missing table."""
    try:
        rows = conn.execute("SELECT key, value FROM system_settings").fetchall()
        return {row["key"]: row["value"] for row in rows}
    except sqlite3.OperationalError:
        return {}
    except Exception:
        return {}


def setting_bool(rows: Mapping[str, str], key: str, default: bool = False) -> bool:
    value = clean_text(rows.get(key, "true" if default else "false"))
    return value.lower() in TRUTHY


def _effective(configured: bool, kill_switch: bool) -> tuple[bool, str]:
    if kill_switch:
        return False, "disabled_by_kill_switch"
    if not configured:
        return False, "disabled_by_operator"
    return True, "enabled"


def auto_mitigation_effective(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = system_settings_rows(conn)
    configured = setting_bool(rows, "auto_mitigation_enabled")
    kill_switch = kill_switch_active(AUTO_MITIGATION_KILL_SWITCH)
    effective, reason = _effective(configured, kill_switch)
    return {
        "configured": configured,
        "configured_source": "database",
        "kill_switch": kill_switch,
        "effective": effective,
        "reason": reason,
    }


def threat_policy_auto_effective(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = system_settings_rows(conn)
    configured = setting_bool(rows, "threat_policy_auto_enabled")
    kill_switch = kill_switch_active(THREAT_POLICY_AUTO_KILL_SWITCH)
    effective, reason = _effective(configured, kill_switch)
    return {
        "configured": configured,
        "configured_source": "database",
        "kill_switch": kill_switch,
        "effective": effective,
        "reason": reason,
    }


def threat_policy_auto_enabled(conn: sqlite3.Connection) -> bool:
    return bool(threat_policy_auto_effective(conn)["effective"])


def threat_response_profile_id(conn: sqlite3.Connection) -> str:
    rows = system_settings_rows(conn)
    return clean_text(rows.get("threat_response_profile_id", ""))


def security_ai_kill_switch() -> bool:
    return kill_switch_active(SECURITY_AI_KILL_SWITCH)
