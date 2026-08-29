"""NO-OP mitigation adapter for NETWORK_SWEEP (simulated execution path).

This component simulates the FULL operational path of a NETWORK_SWEEP
mitigation WITHOUT ever writing to BGP / FlowSpec / ExaBGP / Host Agent:

    shadow policy decision (network_sweep_policy)
        -> action proposal (discard source /32 + TTL)
        -> NO-OP mitigation adapter (resolves the would-use connector)
        -> audit record (would_execute / executed=false)

Safety invariants (enforced by design, verified by tests):
- ``executed`` is ALWAYS False — never a real mitigation.
- never imports/calls ``automatic_mitigation``, host-agent, ExaBGP, FlowSpec.
- never writes to any FIFO or pipe.
- reuses ``network_sweep_policy.evaluate_network_sweep`` (single owner of the
  eligibility logic) instead of reimplementing the gates.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from datetime import timedelta
from typing import Any, Mapping

from app.services.config_effective import setting_bool, system_settings_rows
from app.services.network_sweep_policy import (
    POLICY_VERSION,
    _bgp_ready,
    _existing_mitigation,
    _is_protected_subject,
    _load_campaign,
    _parse_network_context_json,
    evaluate_network_sweep,
    network_sweep_dedup_key,
)
from app.services.threat_intelligence import clean_text, json_dump, utc_now, utc_now_iso

ADAPTER_VERSION = "network_sweep_noop_v1"

_RETENTION_SECONDS = 72 * 3600
_CLEANUP_INTERVAL_SECONDS = 3600
_last_cleanup_ts = 0.0
_cleanup_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Feature switch (persistent setting AND NOT environment kill switch)
# ---------------------------------------------------------------------------

def _kill_switch_active() -> bool:
    env = clean_text(os.getenv("GMJFLOW_NETWORK_SWEEP_NOOP_ADAPTER_KILL_SWITCH", ""))
    return env.lower() in {"1", "true", "yes", "on"}


def network_sweep_noop_adapter_enabled(conn: sqlite3.Connection) -> bool:
    """Configured (env override or persistent system_setting). Default False."""
    env = clean_text(os.getenv("GMJFLOW_NETWORK_SWEEP_NOOP_ADAPTER_ENABLED", ""))
    if env:
        return env.lower() in {"1", "true", "yes", "on"}
    return setting_bool(system_settings_rows(conn), "network_sweep_noop_adapter_enabled", default=False)


def network_sweep_noop_adapter_effective(conn: sqlite3.Connection) -> bool:
    if _kill_switch_active():
        return False
    return network_sweep_noop_adapter_enabled(conn)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def ensure_noop_adapter_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS network_sweep_noop_adapter_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            dedup_key TEXT NOT NULL UNIQUE,
            event_id TEXT NOT NULL DEFAULT '',
            public_id TEXT NOT NULL DEFAULT '',
            campaign_id TEXT NOT NULL DEFAULT '',
            recurrence INTEGER NOT NULL DEFAULT 0,
            source_ip TEXT NOT NULL DEFAULT '',
            prefix TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL DEFAULT '',
            ttl_seconds INTEGER NOT NULL DEFAULT 0,
            connector_id INTEGER,
            connector_name TEXT NOT NULL DEFAULT '',
            connector_readiness TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            policy_version TEXT NOT NULL DEFAULT '',
            adapter_version TEXT NOT NULL DEFAULT '',
            would_execute INTEGER NOT NULL DEFAULT 0,
            executed INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_network_sweep_noop_audit_time
            ON network_sweep_noop_adapter_audit(created_at);
        """
    )


# ---------------------------------------------------------------------------
# Connector resolution (read-only — never executes anything)
# ---------------------------------------------------------------------------

def resolve_would_use_connector(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """Return the first enabled+active BGP connector that WOULD be used.

    Read-only: never touches BGP/FlowSpec/exabgp.
    """
    try:
        row = conn.execute(
            "SELECT id, name FROM bgp_connectors WHERE enabled=1 AND is_active=1 ORDER BY id LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    if hasattr(row, "keys"):
        return {"id": row["id"], "name": clean_text(row["name"]), "ready": True, "readiness": "ready"}
    return {"id": row[0], "name": clean_text(row[1]), "ready": True, "readiness": "ready"}


# ---------------------------------------------------------------------------
# Pure record builder (unit-testable, no DB)
# ---------------------------------------------------------------------------

def _record_reason(decision: Mapping[str, Any]) -> str:
    if decision.get("eligible"):
        return "eligible_shadow_policy"
    reasons = decision.get("ineligible_reasons") or []
    return ",".join(reasons) if reasons else "ineligible"


def build_noop_record(
    public_id: str,
    event_id: str,
    source_ip: str,
    prefix: str,
    decision: Mapping[str, Any],
    *,
    connector: Mapping[str, Any] | None,
    recurrence: Any = 0,
    campaign_id: str = "",
    policy_version: str = POLICY_VERSION,
    adapter_version: str = ADAPTER_VERSION,
) -> dict[str, Any]:
    """Produce the NO-OP execution record for one decision. ``executed`` is always False."""
    eligible = bool(decision.get("eligible"))
    connector_ready = bool(connector and connector.get("ready"))
    would_execute = eligible and connector_ready
    return {
        "public_id": clean_text(public_id),
        "event_id": clean_text(event_id),
        "campaign_id": clean_text(campaign_id),
        "recurrence": max(0, int(recurrence or 0)),
        "source_ip": clean_text(source_ip),
        "prefix": clean_text(prefix),
        "action": clean_text(decision.get("proposed_action")) if eligible else "",
        "ttl_seconds": int(decision.get("proposed_ttl") or 0) if eligible else 0,
        "connector_id": connector.get("id") if connector else None,
        "connector_name": clean_text(connector.get("name")) if connector else "",
        "connector_readiness": clean_text(connector.get("readiness")) if connector else ("not_ready" if eligible else ""),
        "reason": _record_reason(decision),
        "policy_version": policy_version,
        "adapter_version": adapter_version,
        "would_execute": bool(would_execute),
        "executed": False,
    }


# ---------------------------------------------------------------------------
# Production wrapper
# ---------------------------------------------------------------------------

def run_noop_adapter(conn: sqlite3.Connection, lookback_seconds: int = 7200) -> int:
    """Simulate the execution path for recent eligible NETWORK_SWEEP events.

    Only persists records for ELIGIBLE shadow decisions; ineligible events are
    never sent to the adapter (no row). Returns the number of records persisted.
    """
    if not network_sweep_noop_adapter_effective(conn):
        return 0
    ensure_noop_adapter_schema(conn)
    cutoff_iso = (utc_now() - timedelta(seconds=max(60, int(lookback_seconds)))).isoformat().replace("+00:00", "Z")
    rows = conn.execute(
        "SELECT * FROM security_events WHERE attack_type='NETWORK_SWEEP' AND last_seen >= ? ORDER BY last_seen DESC LIMIT 200",
        (cutoff_iso,),
    ).fetchall()
    persisted = 0
    for row in rows:
        event = dict(row)
        ctx = _parse_network_context_json(event.get("network_context_json") or "")
        candidate = {
            "attack_type": event.get("attack_type"),
            "verdict": event.get("verdict"),
            "severity": event.get("severity"),
            "direction": event.get("direction"),
            "src_role": event.get("src_role"),
            "dst_role": event.get("dst_role"),
            "src_ip": event.get("src_ip"),
            "src_prefix": event.get("src_prefix"),
            "target_prefix": event.get("target_prefix"),
            "recurrence_count": event.get("recurrence_count"),
            "detector_score": event.get("detector_score"),
            "unique_destinations": event.get("unique_destinations"),
            "unique_dst_ports": event.get("unique_dst_ports"),
            "source_asn": clean_text(ctx.get("src_asn") or ""),
            "src_is_cgnat": bool(ctx.get("src_is_cgnat")),
            "campaign_id": event.get("campaign_id"),
        }
        decision = evaluate_network_sweep(
            candidate,
            source_protected=_is_protected_subject(conn, candidate["src_ip"] or candidate["src_prefix"]),
            target_protected=_is_protected_subject(conn, candidate["target_prefix"]),
            existing_mitigation=_existing_mitigation(conn, candidate["src_ip"]),
            bgp_ready=_bgp_ready(conn),
            campaign=_load_campaign(conn, candidate["campaign_id"]),
        )
        if not decision["eligible"]:
            continue
        connector = resolve_would_use_connector(conn)
        record = build_noop_record(
            event.get("public_id"),
            event.get("id"),
            candidate["src_ip"],
            candidate["target_prefix"],
            decision,
            connector=connector,
            recurrence=event.get("recurrence_count"),
            campaign_id=event.get("campaign_id"),
        )
        dedup_key = network_sweep_dedup_key(
            event.get("public_id"), event.get("id"), event.get("recurrence_count"), POLICY_VERSION
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO network_sweep_noop_adapter_audit (
                created_at, dedup_key, event_id, public_id, campaign_id, recurrence,
                source_ip, prefix, action, ttl_seconds, connector_id, connector_name,
                connector_readiness, reason, policy_version, adapter_version,
                would_execute, executed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now_iso(),
                dedup_key,
                record["event_id"],
                record["public_id"],
                record["campaign_id"],
                record["recurrence"],
                record["source_ip"],
                record["prefix"],
                record["action"],
                record["ttl_seconds"],
                record["connector_id"],
                record["connector_name"],
                record["connector_readiness"],
                record["reason"],
                record["policy_version"],
                record["adapter_version"],
                int(record["would_execute"]),
                int(record["executed"]),
            ),
        )
        persisted += 1
    _cleanup_noop_audit(conn)
    return persisted


def _cleanup_noop_audit(conn: sqlite3.Connection) -> None:
    global _last_cleanup_ts
    now_ts = time.time()
    with _cleanup_lock:
        if now_ts - _last_cleanup_ts < _CLEANUP_INTERVAL_SECONDS:
            return
        _last_cleanup_ts = now_ts
    cutoff_iso = (utc_now() - timedelta(seconds=_RETENTION_SECONDS)).isoformat().replace("+00:00", "Z")
    try:
        conn.execute("DELETE FROM network_sweep_noop_adapter_audit WHERE created_at < ?", (cutoff_iso,))
    except sqlite3.OperationalError:
        pass


__all__ = [
    "ADAPTER_VERSION",
    "build_noop_record",
    "ensure_noop_adapter_schema",
    "network_sweep_noop_adapter_effective",
    "network_sweep_noop_adapter_enabled",
    "resolve_would_use_connector",
    "run_noop_adapter",
]
