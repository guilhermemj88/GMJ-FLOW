"""Deterministic SHADOW policy evaluator for NETWORK_SWEEP (Phase 6B).

Single owner of the NETWORK_SWEEP auto-mitigation decision logic.

This module is a read-only observer:
- the detector keeps detecting (behavioral_detection.py);
- this module only computes and persists a SHADOW eligibility verdict;
- it NEVER returns ALLOW_AUTO to ThreatPolicyEngine;
- it NEVER calls automatic_mitigation.py;
- it NEVER generates FlowSpec/BGP announce/withdraw;
- it IGNORES all AI fields for gating.

Everything that touches the database lives in the wrapper functions; the pure
``evaluate_network_sweep`` function is side-effect free and unit-testable.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import timedelta
from ipaddress import ip_address, ip_network
from typing import Any, Mapping

from app.services.config_effective import setting_bool, system_settings_rows
from app.services.threat_intelligence import clean_text, json_dump, utc_now, utc_now_iso


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(float(value or 0)))
    except (TypeError, ValueError):
        return 0

POLICY_VERSION = "network_sweep_shadow_v1"

# --- TTL (shadow proposal only; no real timer is created) ---
INITIAL_TTL_SECONDS = 900              # 15 min
RECURRENCE_EXTENSION_SECONDS = 900     # +15 min per recurrence step beyond the first
MAX_TTL_SECONDS = 3600                 # 60 min
COOLDOWN_SECONDS = 3600                # 60 min (documented proposal only)

# --- Confidence gates ---
MIN_DETECTOR_SCORE = 90
MIN_UNIQUE_DESTINATIONS = 20
MIN_RECURRENCE = 2
MIN_CAMPAIGN_COORDINATION_SCORE = 40

SCAN_CAMPAIGN_CLASSIFICATIONS = {"SCANNING_CAMPAIGN", "COORDINATED_SCANNING"}

PROTECTED_DST_ROLES = {"INFRASTRUCTURE", "MANAGEMENT"}

# Built-in protected ranges (RFC1918 + loopback + infra). Same spirit as the
# ThreatPolicy safety guard, kept here so the evaluator stays self-contained.
_RFC1918_AND_INFRA = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10", "224.0.0.0/4", "240.0.0.0/4",
    "::1/128", "fc00::/7", "fe80::/10",
)

# --- Controlled ineligible-reason enum (no free text as the primary signal) ---
NOT_NETWORK_SWEEP = "NOT_NETWORK_SWEEP"
NOT_CONFIRMED = "NOT_CONFIRMED"
NOT_CRITICAL = "NOT_CRITICAL"
NOT_INBOUND = "NOT_INBOUND"
SOURCE_NOT_EXTERNAL = "SOURCE_NOT_EXTERNAL"
SOURCE_PROTECTED = "SOURCE_PROTECTED"
TARGET_PROTECTED = "TARGET_PROTECTED"
DESTINATION_INFRASTRUCTURE = "DESTINATION_INFRASTRUCTURE"
DESTINATION_MANAGEMENT = "DESTINATION_MANAGEMENT"
SOURCE_CGNAT_OR_SHARED = "SOURCE_CGNAT_OR_SHARED"
RECURRENCE_TOO_LOW = "RECURRENCE_TOO_LOW"
DETECTOR_SCORE_TOO_LOW = "DETECTOR_SCORE_TOO_LOW"
INSUFFICIENT_DESTINATIONS = "INSUFFICIENT_DESTINATIONS"
EXISTING_MITIGATION = "EXISTING_MITIGATION"
BGP_NOT_READY = "BGP_NOT_READY"
CAMPAIGN_NOT_CORROBORATED = "CAMPAIGN_NOT_CORROBORATED"
MISSING_CONTEXT = "MISSING_CONTEXT"

_RETENTION_SECONDS = 72 * 3600
_CLEANUP_INTERVAL_SECONDS = 3600
_last_cleanup_ts = 0.0
_cleanup_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def compute_proposed_ttl(recurrence_count: Any) -> int:
    """initial + (recurrence - 1) extensions, capped at MAX_TTL_SECONDS.

    recurrence 1 -> 15 min, 2 -> 30 min, 3 -> 45 min, >=4 -> 60 min.
    """
    recurrence = max(1, _safe_int(recurrence_count))
    return min(
        INITIAL_TTL_SECONDS + (recurrence - 1) * RECURRENCE_EXTENSION_SECONDS,
        MAX_TTL_SECONDS,
    )


def campaign_corroboration(campaign: Mapping[str, Any] | None) -> bool:
    """A campaign corroborates only with real signals: a valid id, a scanning
    classification and a coordination score at/above the threshold."""
    if not isinstance(campaign, Mapping):
        return False
    campaign_id = clean_text(campaign.get("campaign_id") or campaign.get("id") or "")
    classification = clean_text(campaign.get("classification") or "").upper()
    coordination = _safe_int(campaign.get("coordination_score"))
    return bool(campaign_id) and classification in SCAN_CAMPAIGN_CLASSIFICATIONS and coordination >= MIN_CAMPAIGN_COORDINATION_SCORE


def network_sweep_dedup_key(public_id: str, event_id: str, recurrence_count: Any, policy_version: str = POLICY_VERSION) -> str:
    identity = clean_text(public_id) or f"event:{event_id}"
    return f"{identity}:{_safe_int(recurrence_count)}:{policy_version}"


def evaluate_network_sweep(
    candidate: Mapping[str, Any],
    *,
    source_protected: bool = False,
    target_protected: bool = False,
    existing_mitigation: bool = False,
    bgp_ready: bool = False,
    campaign: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Pure, deterministic SHADOW eligibility decision for one NETWORK_SWEEP event."""
    attack_type = clean_text(candidate.get("attack_type") or "").upper()
    verdict = clean_text(candidate.get("verdict") or "").upper()
    severity = clean_text(candidate.get("severity") or "").upper()
    direction = clean_text(candidate.get("direction") or "").upper()
    src_role = clean_text(candidate.get("src_role") or "").upper()
    dst_role = clean_text(candidate.get("dst_role") or "").upper()
    src_ip = clean_text(candidate.get("src_ip") or "")
    target_prefix = clean_text(candidate.get("target_prefix") or "")
    recurrence = _safe_int(candidate.get("recurrence_count"))
    detector_score = _safe_int(candidate.get("detector_score"))
    unique_destinations = _safe_int(candidate.get("unique_destinations"))
    unique_dst_ports = _safe_int(candidate.get("unique_dst_ports"))
    src_is_cgnat = bool(candidate.get("src_is_cgnat"))

    reasons: list[str] = []

    # Mandatory gates.
    if attack_type != "NETWORK_SWEEP":
        reasons.append(NOT_NETWORK_SWEEP)
    if verdict != "CONFIRMED_ATTACK":
        reasons.append(NOT_CONFIRMED)
    if severity != "CRITICAL":
        reasons.append(NOT_CRITICAL)
    if direction != "INBOUND":
        reasons.append(NOT_INBOUND)
    if src_role != "EXTERNAL":
        reasons.append(SOURCE_NOT_EXTERNAL)
    if not src_ip:
        reasons.append(MISSING_CONTEXT)
    if source_protected:
        reasons.append(SOURCE_PROTECTED)
    if target_protected:
        reasons.append(TARGET_PROTECTED)
    if dst_role == "INFRASTRUCTURE":
        reasons.append(DESTINATION_INFRASTRUCTURE)
    if dst_role == "MANAGEMENT":
        reasons.append(DESTINATION_MANAGEMENT)
    if src_is_cgnat:
        reasons.append(SOURCE_CGNAT_OR_SHARED)
    if existing_mitigation:
        reasons.append(EXISTING_MITIGATION)
    if not bgp_ready:
        reasons.append(BGP_NOT_READY)

    # Confidence gates.
    corroborated = campaign_corroboration(campaign)
    if recurrence < MIN_RECURRENCE and not corroborated:
        reasons.append(RECURRENCE_TOO_LOW)
    if detector_score < MIN_DETECTOR_SCORE:
        reasons.append(DETECTOR_SCORE_TOO_LOW)
    if unique_destinations < MIN_UNIQUE_DESTINATIONS:
        reasons.append(INSUFFICIENT_DESTINATIONS)

    eligible = not reasons
    proposed_ttl = compute_proposed_ttl(recurrence) if eligible else 0
    evidence: dict[str, Any] = {
        "source": src_ip,
        "source_asn": clean_text(candidate.get("source_asn") or ""),
        "source_role": src_role,
        "destination_scope": target_prefix,
        "dst_role": dst_role,
        "direction": direction,
        "unique_destinations": unique_destinations,
        "unique_ports": unique_dst_ports,
        "detector_score": detector_score,
        "recurrence_count": recurrence,
        "severity": severity,
        "verdict": verdict,
        "campaign_id": clean_text(candidate.get("campaign_id") or ""),
        "campaign": dict(campaign) if isinstance(campaign, Mapping) else {},
        "source_protected": bool(source_protected),
        "target_protected": bool(target_protected),
        "source_cgnat_or_shared": bool(src_is_cgnat),
        "existing_mitigation": bool(existing_mitigation),
        "bgp_ready": bool(bgp_ready),
        "proposed_action": "discard" if eligible else "",
        "proposed_ttl": proposed_ttl,
        "policy_version": POLICY_VERSION,
    }

    return {
        "eligible": eligible,
        "ineligible_reasons": reasons,
        "would_mitigate": eligible,
        "proposed_action": "discard" if eligible else "",
        "proposed_ttl": proposed_ttl,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Shadow persistence
# ---------------------------------------------------------------------------

def ensure_network_sweep_shadow_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS network_sweep_policy_shadow_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            dedup_key TEXT NOT NULL UNIQUE,
            event_id TEXT NOT NULL DEFAULT '',
            public_id TEXT NOT NULL DEFAULT '',
            campaign_id TEXT NOT NULL DEFAULT '',
            source_ip TEXT NOT NULL DEFAULT '',
            target_prefix TEXT NOT NULL DEFAULT '',
            eligible INTEGER NOT NULL DEFAULT 0,
            would_mitigate INTEGER NOT NULL DEFAULT 0,
            proposed_action TEXT NOT NULL DEFAULT '',
            proposed_ttl INTEGER NOT NULL DEFAULT 0,
            ineligible_reasons_json TEXT NOT NULL DEFAULT '[]',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            policy_version TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_network_sweep_shadow_audit_time
            ON network_sweep_policy_shadow_audit(created_at);
        """
    )


def network_sweep_policy_shadow_enabled(conn: sqlite3.Connection) -> bool:
    rows = system_settings_rows(conn)
    env = clean_text(os.getenv("GMJFLOW_NETWORK_SWEEP_POLICY_SHADOW_ENABLED", ""))
    if env:
        return env.lower() in {"1", "true", "yes", "on"}
    return setting_bool(rows, "network_sweep_policy_shadow_enabled", default=True)


# ---------------------------------------------------------------------------
# Context lookups (self-contained, tolerant — shadow-only)
# ---------------------------------------------------------------------------

def _normalize_subject(value: str) -> Any:
    value = clean_text(value)
    if not value:
        return None
    try:
        if "/" in value:
            return ip_network(value, strict=False)
        return ip_address(value)
    except ValueError:
        return None


def _overlaps_subject(subject: str, network: str) -> bool:
    left = _normalize_subject(subject)
    right = _normalize_subject(network)
    if left is None or right is None:
        return False
    try:
        if left.version != right.version:
            return False
        left_is_network = hasattr(left, "overlaps")
        right_is_network = hasattr(right, "overlaps")
        if left_is_network and right_is_network:
            return left.overlaps(right)
        if left_is_network:
            return right in left
        if right_is_network:
            return left in right
        return str(left) == str(right)
    except (TypeError, ValueError):
        return False


def _is_protected_subject(conn: sqlite3.Connection, subject: str) -> bool:
    if not clean_text(subject):
        return False
    for network in _RFC1918_AND_INFRA:
        if _overlaps_subject(subject, network):
            return True
    for network in [v.strip() for v in os.getenv("GMJFLOW_THREAT_PROTECTED_RANGES", "").split(",") if v.strip()]:
        if _overlaps_subject(subject, network):
            return True
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "detection_whitelist" in tables:
        try:
            for row in conn.execute("SELECT src_cidr, dst_cidr FROM detection_whitelist WHERE active=1").fetchall():
                if _overlaps_subject(subject, clean_text(row[0])) or _overlaps_subject(subject, clean_text(row[1])):
                    return True
        except sqlite3.OperationalError:
            pass
    if "bgp_protected_prefixes" in tables:
        try:
            for row in conn.execute("SELECT cidr FROM bgp_protected_prefixes WHERE enabled=1").fetchall():
                if _overlaps_subject(subject, clean_text(row[0])):
                    return True
        except sqlite3.OperationalError:
            pass
    if "threat_network_contexts" in tables:
        try:
            for row in conn.execute("SELECT protected_ranges_json FROM threat_network_contexts WHERE enabled=1").fetchall():
                for network in json.loads(row[0] or "[]"):
                    if _overlaps_subject(subject, clean_text(network)):
                        return True
        except (sqlite3.OperationalError, ValueError):
            pass
    exact_tables = {"bgp_connectors": ("peer_ip", "local_address", "router_mgmt_ip"), "sensors": ("exporter_ip", "listener_ip", "snmp_ip")}
    host = _normalize_subject(subject)
    if host is None:
        return False
    for table, cols in exact_tables.items():
        if table not in tables:
            continue
        where = "enabled=1" if table == "bgp_connectors" else "active=1"
        try:
            rows = conn.execute(f"SELECT {', '.join(cols)} FROM {table} WHERE {where}").fetchall()
        except sqlite3.OperationalError:
            continue
        for row in rows:
            for value in row:
                candidate = _normalize_subject(clean_text(value))
                if candidate is None:
                    continue
                try:
                    if getattr(host, "version", None) == getattr(candidate, "version", None) and str(host) == str(candidate):
                        return True
                except ValueError:
                    continue
    return False


def _existing_mitigation(conn: sqlite3.Connection, source_ip: str) -> bool:
    if not clean_text(source_ip):
        return False
    src = _normalize_subject(source_ip)
    if src is None:
        return False
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "bgp_announcements" in tables:
        try:
            for row in conn.execute("SELECT src_prefix, dst_prefix FROM bgp_announcements WHERE status IN ('advertised','queued','active')").fetchall():
                for prefix in (clean_text(row[0]), clean_text(row[1])):
                    if _overlaps_subject(source_ip, prefix):
                        return True
        except sqlite3.OperationalError:
            pass
    if "mitigation_executions" in tables:
        try:
            for row in conn.execute("SELECT candidate_json FROM mitigation_executions WHERE status IN ('active','applied','queued')").fetchall():
                try:
                    payload = json.loads(row[0] or "{}")
                except ValueError:
                    payload = {}
                for key in ("source_ip", "src_ip"):
                    if _overlaps_subject(source_ip, clean_text(payload.get(key))):
                        return True
        except sqlite3.OperationalError:
            pass
    return False


def _bgp_ready(conn: sqlite3.Connection) -> bool:
    try:
        row = conn.execute("SELECT COUNT(*) FROM bgp_connectors WHERE enabled=1 AND is_active=1").fetchone()
    except sqlite3.OperationalError:
        return False
    return bool(row and row[0] and int(row[0]) > 0)


def _load_campaign(conn: sqlite3.Connection, campaign_id: str) -> Mapping[str, Any] | None:
    cid = clean_text(campaign_id)
    if not cid:
        return None
    try:
        row = conn.execute(
            "SELECT campaign_id, classification, coordination_score, unique_sources, recurrence_count, first_seen, last_seen "
            "FROM threat_campaigns WHERE campaign_id=? LIMIT 1",
            (cid,),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    return dict(row) if row else None


def _parse_network_context_json(raw: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except ValueError:
        value = {}
    return value if isinstance(value, Mapping) else {}


# ---------------------------------------------------------------------------
# Production wrapper
# ---------------------------------------------------------------------------

def evaluate_and_audit_network_sweep_shadow(conn: sqlite3.Connection, lookback_seconds: int = 7200) -> int:
    """Evaluate recent NETWORK_SWEEP security events and persist SHADOW audit.

    Returns the number of evaluations persisted (0 when deduped or disabled).
    """
    if not network_sweep_policy_shadow_enabled(conn):
        return 0
    ensure_network_sweep_shadow_schema(conn)
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
        dedup_key = network_sweep_dedup_key(event.get("public_id"), event.get("id"), event.get("recurrence_count"))
        conn.execute(
            """
            INSERT OR IGNORE INTO network_sweep_policy_shadow_audit (
                created_at, dedup_key, event_id, public_id, campaign_id, source_ip, target_prefix,
                eligible, would_mitigate, proposed_action, proposed_ttl,
                ineligible_reasons_json, evidence_json, policy_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now_iso(), dedup_key, event.get("id"), event.get("public_id"), event.get("campaign_id"),
                candidate["src_ip"], candidate["target_prefix"],
                int(decision["eligible"]), int(decision["would_mitigate"]),
                decision["proposed_action"], decision["proposed_ttl"],
                json_dump(decision["ineligible_reasons"]), json_dump(decision["evidence"]), POLICY_VERSION,
            ),
        )
        persisted += 1
    _cleanup_shadow_audit(conn)
    return persisted


def _cleanup_shadow_audit(conn: sqlite3.Connection) -> None:
    global _last_cleanup_ts
    now_ts = time.time()
    with _cleanup_lock:
        if now_ts - _last_cleanup_ts < _CLEANUP_INTERVAL_SECONDS:
            return
        _last_cleanup_ts = now_ts
    cutoff_iso = (utc_now() - timedelta(seconds=_RETENTION_SECONDS)).isoformat().replace("+00:00", "Z")
    try:
        conn.execute("DELETE FROM network_sweep_policy_shadow_audit WHERE created_at < ?", (cutoff_iso,))
    except sqlite3.OperationalError:
        pass
