"""Transit-aware RTBH (Remotely Triggered Black Hole) support for GMJ-FLOW.

This module implements the Threat Intelligence -> RTBH mitigation-candidate
pipeline in RECOMMEND_ONLY mode:

- ``transit_providers``: a transit/edge provider (name, optional sensor,
  ``input_if`` used to map flow ingress to the provider).
- ``transit_rtbh_policies``: per-provider RTBH policy. Communities are NEVER
  hardcoded here; the operator registers them. Threat Intelligence never
  receives or creates communities.
- ``rtbh_mitigation_candidates``: persistent candidates generated from
  behavioral/Threat Intelligence evidence.

Safety invariants (this version):

- Maximum candidate lifecycle: PROPOSED -> REVIEW_REQUIRED -> DRY_RUN.
  The executor only performs dry runs. EXECUTING/ACTIVE are unreachable.
- No BGP announcement, no pipe/FIFO write, no router change happens here.
- ``RTBH_EXECUTION_ENABLED`` (default false) is a real kill switch:
  ``effective_execution = env_enabled AND persistent policy mode``.
- Communities flagged as sensitive are masked in reports/APIs for viewers.

The module has no imports from ``app.main`` so it can be exercised by pure
unit tests against an in-memory SQLite database.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from ipaddress import ip_address, ip_network
from typing import Any, Iterable, Mapping

from app.services.threat_intelligence import clean_text, safe_json, utc_now_iso

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RTBH_MODE_OFF = "OFF"
RTBH_MODE_RECOMMEND_ONLY = "RECOMMEND_ONLY"
RTBH_MODE_MANUAL_APPROVAL = "MANUAL_APPROVAL"
RTBH_MODE_AUTO = "AUTO"
RTBH_MODES = {
    RTBH_MODE_OFF,
    RTBH_MODE_RECOMMEND_ONLY,
    RTBH_MODE_MANUAL_APPROVAL,
    RTBH_MODE_AUTO,
}

CANDIDATE_STATUS_PROPOSED = "PROPOSED"
CANDIDATE_STATUS_REVIEW_REQUIRED = "REVIEW_REQUIRED"
CANDIDATE_STATUS_APPROVED = "APPROVED"
CANDIDATE_STATUS_REJECTED = "REJECTED"
CANDIDATE_STATUS_DRY_RUN = "DRY_RUN"
CANDIDATE_STATUS_EXECUTING = "EXECUTING"
CANDIDATE_STATUS_ACTIVE = "ACTIVE"
CANDIDATE_STATUS_WITHDRAW_PENDING = "WITHDRAW_PENDING"
CANDIDATE_STATUS_WITHDRAWN = "WITHDRAWN"
CANDIDATE_STATUS_FAILED = "FAILED"

CANDIDATE_STATUSES = {
    CANDIDATE_STATUS_PROPOSED,
    CANDIDATE_STATUS_REVIEW_REQUIRED,
    CANDIDATE_STATUS_APPROVED,
    CANDIDATE_STATUS_REJECTED,
    CANDIDATE_STATUS_DRY_RUN,
    CANDIDATE_STATUS_EXECUTING,
    CANDIDATE_STATUS_ACTIVE,
    CANDIDATE_STATUS_WITHDRAW_PENDING,
    CANDIDATE_STATUS_WITHDRAWN,
    CANDIDATE_STATUS_FAILED,
}

# Statuses reachable in this version. EXECUTING/ACTIVE/... are defined for
# schema completeness but no code path transitions into them.
REACHABLE_STATUSES = {
    CANDIDATE_STATUS_PROPOSED,
    CANDIDATE_STATUS_REVIEW_REQUIRED,
    CANDIDATE_STATUS_REJECTED,
    CANDIDATE_STATUS_DRY_RUN,
}

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    CANDIDATE_STATUS_PROPOSED: {
        CANDIDATE_STATUS_REVIEW_REQUIRED,
        CANDIDATE_STATUS_REJECTED,
        CANDIDATE_STATUS_DRY_RUN,
        CANDIDATE_STATUS_FAILED,
    },
    CANDIDATE_STATUS_REVIEW_REQUIRED: {
        CANDIDATE_STATUS_PROPOSED,
        CANDIDATE_STATUS_REJECTED,
        CANDIDATE_STATUS_DRY_RUN,
        CANDIDATE_STATUS_FAILED,
    },
    CANDIDATE_STATUS_DRY_RUN: {
        CANDIDATE_STATUS_REJECTED,
        CANDIDATE_STATUS_PROPOSED,
        CANDIDATE_STATUS_FAILED,
    },
    CANDIDATE_STATUS_REJECTED: {
        CANDIDATE_STATUS_PROPOSED,
    },
    CANDIDATE_STATUS_FAILED: {
        CANDIDATE_STATUS_PROPOSED,
    },
}

ACTION_TYPE_RTBH = "RTBH"
ACTION_TYPE_MANUAL_LARGE_PREFIX_RTBH = "MANUAL_LARGE_PREFIX_RTBH"
ACTION_TYPE_UPSTREAM_SCRUBBING = "UPSTREAM_SCRUBBING"

COLLATERAL_NONE = "NONE"
COLLATERAL_LOW = "LOW"
COLLATERAL_MEDIUM = "MEDIUM"
COLLATERAL_HIGH = "HIGH"
COLLATERAL_CRITICAL = "CRITICAL"
COLLATERAL_LEVELS = {
    COLLATERAL_NONE,
    COLLATERAL_LOW,
    COLLATERAL_MEDIUM,
    COLLATERAL_HIGH,
    COLLATERAL_CRITICAL,
}

SUITABILITY_VERY_LOW = "VERY_LOW"
SUITABILITY_LOW = "LOW"
SUITABILITY_MEDIUM = "MEDIUM"
SUITABILITY_HIGH = "HIGH"
SUITABILITY_VERY_HIGH = "VERY_HIGH"
SUITABILITY_LEVELS = {
    SUITABILITY_VERY_LOW,
    SUITABILITY_LOW,
    SUITABILITY_MEDIUM,
    SUITABILITY_HIGH,
    SUITABILITY_VERY_HIGH,
}

CLASSIFICATION_UDP_VOLUMETRIC_CARPET_BOMBING = "UDP_VOLUMETRIC_CARPET_BOMBING"

# Classification families this pipeline is allowed to create RTBH candidates for.
RTBH_ELIGIBLE_CLASSIFICATIONS = {
    "CARPET_BOMBING",
    "UDP_FLOOD",
    "DISTRIBUTED_UDP_FLOOD",
    "UDP_REFLECTION_SUSPECTED",
    "DISTRIBUTED_SYN_FLOOD",
    "SPOOFED_SYN_FLOOD",
    "MULTI_VECTOR_DDOS",
    "BOTNET_LIKELY",
    CLASSIFICATION_UDP_VOLUMETRIC_CARPET_BOMBING,
}

# BGP well-known community shapes we accept as configuration.
_STANDARD_COMMUNITY_RE = re.compile(r"^\d{1,10}:\d{1,10}$")
_LARGE_COMMUNITY_RE = re.compile(r"^\d{1,10}:\d{1,10}:\d{1,10}$")


def json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Kill switch (real): environment AND persistent policy. Default false.
# ---------------------------------------------------------------------------


def rtbh_execution_enabled_env() -> bool:
    return clean_text(os.getenv("RTBH_EXECUTION_ENABLED", "false")).lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def rtbh_version_allows_execution() -> bool:
    """This version is dry-run only; the real executor must never be reachable."""
    return False


def effective_execution_allowed(policy: Mapping[str, Any]) -> bool:
    """effectiveExecution = persistent_enabled AND environment_execution_enabled.

    In this version an additional hard gate exists: the executor only supports
    DRY RUN, so even a true result here does not produce announcements.
    """
    mode = clean_text(policy.get("mode")).upper()
    policy_allows = bool(policy.get("enabled")) and mode == RTBH_MODE_AUTO
    return policy_allows and rtbh_execution_enabled_env()


# ---------------------------------------------------------------------------
# Community helpers (validation + masking). No operator is hardcoded.
# ---------------------------------------------------------------------------


def valid_standard_community(value: Any) -> bool:
    text = clean_text(value)
    if not text:
        return False
    match = _STANDARD_COMMUNITY_RE.match(text)
    if not match:
        return False
    left, right = (int(part) for part in text.split(":"))
    return 0 <= left <= 4294967295 and 0 <= right <= 65535


def valid_large_community(value: Any) -> bool:
    text = clean_text(value)
    if not text:
        return False
    match = _LARGE_COMMUNITY_RE.match(text)
    if not match:
        return False
    first, second, third = (int(part) for part in text.split(":"))
    return (
        0 <= first <= 4294967295
        and 0 <= second <= 4294967295
        and 0 <= third <= 4294967295
    )


def validate_community_list(kind: str, values: Any) -> list[str]:
    validator = valid_standard_community if kind == "standard" else valid_large_community
    if values is None:
        return []
    if isinstance(values, str):
        try:
            values = json.loads(values or "[]")
        except json.JSONDecodeError as exc:
            raise ValueError(f"{kind}_communities_invalid_json") from exc
    if not isinstance(values, list):
        raise ValueError(f"{kind}_communities_must_be_list")
    normalized: list[str] = []
    for value in values:
        text = clean_text(value)
        if not validator(text):
            raise ValueError(f"invalid_{kind}_community:{text}")
        if text not in normalized:
            normalized.append(text)
    return normalized


def communities_mask(communities: Iterable[Any], sensitive: bool) -> list[str]:
    values = [clean_text(item) for item in communities if clean_text(item)]
    if not values:
        return []
    return ["Configured"] if sensitive else values


# ---------------------------------------------------------------------------
# Schema (idempotent, incremental — mirrors backend/migrations file)
# ---------------------------------------------------------------------------


def ensure_transit_rtbh_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS transit_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            sensor_id INTEGER,
            input_if INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS transit_rtbh_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id INTEGER NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1,
            standard_communities_json TEXT NOT NULL DEFAULT '[]',
            large_communities_json TEXT NOT NULL DEFAULT '[]',
            communities_sensitive INTEGER NOT NULL DEFAULT 1,
            address_family TEXT NOT NULL DEFAULT 'ipv4',
            mode TEXT NOT NULL DEFAULT 'RECOMMEND_ONLY',
            min_prefix_length INTEGER NOT NULL DEFAULT 32,
            max_prefix_length INTEGER NOT NULL DEFAULT 32,
            min_confidence REAL NOT NULL DEFAULT 0.90,
            min_attack_bps REAL NOT NULL DEFAULT 1000000000.0,
            min_duration_seconds INTEGER NOT NULL DEFAULT 60,
            cooldown_seconds INTEGER NOT NULL DEFAULT 3600,
            allow_auto INTEGER NOT NULL DEFAULT 0,
            require_manual_approval INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(provider_id) REFERENCES transit_providers(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rtbh_mitigation_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL DEFAULT '',
            threat_assessment_id TEXT NOT NULL DEFAULT '',
            classification TEXT NOT NULL DEFAULT '',
            action_type TEXT NOT NULL DEFAULT 'RTBH',
            target_prefix TEXT NOT NULL DEFAULT '',
            provider_id INTEGER,
            input_if INTEGER NOT NULL DEFAULT 0,
            confidence REAL NOT NULL DEFAULT 0,
            attack_bps_observed REAL NOT NULL DEFAULT 0,
            attack_bps_estimated REAL NOT NULL DEFAULT 0,
            attack_pps_observed REAL NOT NULL DEFAULT 0,
            attack_pps_estimated REAL NOT NULL DEFAULT 0,
            baseline_bps REAL NOT NULL DEFAULT 0,
            attack_baseline_ratio REAL NOT NULL DEFAULT 0,
            attack_share_provider REAL NOT NULL DEFAULT 0,
            suitability_json TEXT NOT NULL DEFAULT '{}',
            collateral_risk TEXT NOT NULL DEFAULT 'NONE',
            reason TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'PROPOSED',
            no_safe_selective_rtbh_candidate INTEGER NOT NULL DEFAULT 0,
            large_prefix_manual_only INTEGER NOT NULL DEFAULT 0,
            dry_run_json TEXT NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT 'GMJ_FLOW',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(provider_id) REFERENCES transit_providers(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rtbh_candidate_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL,
            incident_id TEXT NOT NULL DEFAULT '',
            candidate_id INTEGER,
            provider_id INTEGER,
            target_prefix TEXT NOT NULL DEFAULT '',
            policy_id INTEGER,
            communities_ref TEXT NOT NULL DEFAULT '',
            old_state TEXT NOT NULL DEFAULT '',
            new_state TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_rtbh_candidate_incident_provider_target "
        "ON rtbh_mitigation_candidates(incident_id, COALESCE(provider_id, 0), target_prefix)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_rtbh_candidates_status ON rtbh_mitigation_candidates(status, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_rtbh_candidates_incident ON rtbh_mitigation_candidates(incident_id, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_rtbh_candidate_audit_candidate ON rtbh_candidate_audit(candidate_id, created_at DESC)"
    )
    ensure_transit_rtbh_columns(conn)


def _json_column(columns: set[str], table: str, column: str, ddl: str, conn: sqlite3.Connection) -> None:
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def ensure_transit_rtbh_columns(conn: sqlite3.Connection) -> None:
    provider_columns = {row[1] for row in conn.execute("PRAGMA table_info(transit_providers)").fetchall()}
    for column, ddl in (
        ("notes", "notes TEXT NOT NULL DEFAULT ''"),
    ):
        _json_column(provider_columns, "transit_providers", column, ddl, conn)
    policy_columns = {row[1] for row in conn.execute("PRAGMA table_info(transit_rtbh_policies)").fetchall()}
    for column, ddl in (
        ("communities_sensitive", "communities_sensitive INTEGER NOT NULL DEFAULT 1"),
    ):
        _json_column(policy_columns, "transit_rtbh_policies", column, ddl, conn)


# ---------------------------------------------------------------------------
# Row conversion
# ---------------------------------------------------------------------------


def provider_row_to_dict(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "name": clean_text(item["name"]),
        "sensor_id": safe_int(item.get("sensor_id")) if item.get("sensor_id") is not None else None,
        "input_if": safe_int(item.get("input_if")),
        "enabled": bool(int(item.get("enabled") or 0)),
        "notes": clean_text(item.get("notes")),
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


def policy_row_to_dict(row: sqlite3.Row | Mapping[str, Any], *, include_communities: bool = False) -> dict[str, Any]:
    item = dict(row)
    sensitive = bool(int(item.get("communities_sensitive") or 1))
    standard = safe_json(item.get("standard_communities_json"), [])
    large = safe_json(item.get("large_communities_json"), [])
    standard = standard if isinstance(standard, list) else []
    large = large if isinstance(large, list) else []
    standard = [clean_text(value) for value in standard if clean_text(value)]
    large = [clean_text(value) for value in large if clean_text(value)]
    configured = bool(standard or large)
    if not include_communities:
        standard = communities_mask(standard, sensitive)
        large = communities_mask(large, sensitive)
    return {
        "id": int(item["id"]),
        "provider_id": int(item["provider_id"]),
        "enabled": bool(int(item.get("enabled") or 0)),
        "standard_communities": standard,
        "large_communities": large,
        "communities_configured": configured,
        "communities_sensitive": sensitive,
        "address_family": clean_text(item.get("address_family") or "ipv4").lower(),
        "mode": clean_text(item.get("mode") or RTBH_MODE_RECOMMEND_ONLY).upper(),
        "min_prefix_length": safe_int(item.get("min_prefix_length"), 32),
        "max_prefix_length": safe_int(item.get("max_prefix_length"), 32),
        "min_confidence": safe_float(item.get("min_confidence"), 0.90),
        "min_attack_bps": safe_float(item.get("min_attack_bps"), 1_000_000_000.0),
        "min_duration_seconds": safe_int(item.get("min_duration_seconds"), 60),
        "cooldown_seconds": safe_int(item.get("cooldown_seconds"), 3600),
        "allow_auto": bool(int(item.get("allow_auto") or 0)),
        "require_manual_approval": bool(int(item.get("require_manual_approval") or 1)),
        "execution_enabled_env": rtbh_execution_enabled_env(),
        "execution_effective": effective_execution_allowed(item),
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


def candidate_row_to_dict(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    suitability = safe_json(item.get("suitability_json"), {})
    evidence = safe_json(item.get("evidence_json"), {})
    dry_run = safe_json(item.get("dry_run_json"), {})
    suitability = suitability if isinstance(suitability, dict) else {}
    evidence = evidence if isinstance(evidence, dict) else {}
    dry_run = dry_run if isinstance(dry_run, dict) else {}
    return {
        "id": int(item["id"]),
        "incident_id": clean_text(item.get("incident_id")),
        "threat_assessment_id": clean_text(item.get("threat_assessment_id")),
        "classification": clean_text(item.get("classification")),
        "action_type": clean_text(item.get("action_type") or ACTION_TYPE_RTBH),
        "target_prefix": clean_text(item.get("target_prefix")),
        "provider_id": safe_int(item.get("provider_id")) if item.get("provider_id") is not None else None,
        "provider_name": clean_text(item.get("provider_name")) if "provider_name" in set(item.keys()) else "",
        "input_if": safe_int(item.get("input_if")),
        "confidence": safe_float(item.get("confidence")),
        "attack_bps_observed": safe_float(item.get("attack_bps_observed")),
        "attack_bps_estimated": safe_float(item.get("attack_bps_estimated")),
        "attack_pps_observed": safe_float(item.get("attack_pps_observed")),
        "attack_pps_estimated": safe_float(item.get("attack_pps_estimated")),
        "baseline_bps": safe_float(item.get("baseline_bps")),
        "attack_baseline_ratio": safe_float(item.get("attack_baseline_ratio")),
        "attack_share_provider": safe_float(item.get("attack_share_provider")),
        "suitability": suitability,
        "collateral_risk": clean_text(item.get("collateral_risk") or COLLATERAL_NONE),
        "reason": clean_text(item.get("reason")),
        "evidence": evidence,
        "status": clean_text(item.get("status") or CANDIDATE_STATUS_PROPOSED),
        "no_safe_selective_rtbh_candidate": bool(int(item.get("no_safe_selective_rtbh_candidate") or 0)),
        "large_prefix_manual_only": bool(int(item.get("large_prefix_manual_only") or 0)),
        "dry_run": dry_run,
        "protected_services_affected": safe_int(evidence.get("protected_services_affected")),
        "affected_service_names": list(evidence.get("affected_service_names") or []),
        "affected_host_count": safe_int(evidence.get("affected_host_count")),
        "estimated_legitimate_traffic_available": bool(evidence.get("estimated_legitimate_traffic_available")),
        "created_by": clean_text(item.get("created_by") or "GMJ_FLOW"),
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


# ---------------------------------------------------------------------------
# Suitability assessment for volumetric carpet bombing
# ---------------------------------------------------------------------------


def classify_rtbh_incident(classification: str, features: Mapping[str, Any]) -> dict[str, Any]:
    """Classify the incident for RTBH purposes.

    Returns classification plus supporting signals. UDP volumetric with many
    sources, likely spoofing, random ports and high fanout is classified as
    UDP_VOLUMETRIC_CARPET_BOMBING.
    """
    source_classification = clean_text(classification).upper()
    if source_classification not in RTBH_ELIGIBLE_CLASSIFICATIONS:
        return {
            "classification": source_classification or "UNKNOWN",
            "rtbh_eligible": False,
            "reason": "classification_not_rtbh_eligible",
        }
    features = dict(features or {})
    is_udp = source_classification in {
        "UDP_FLOOD",
        "DISTRIBUTED_UDP_FLOOD",
        "UDP_REFLECTION_SUSPECTED",
    }
    spoofing_likelihood = safe_float(features.get("spoofing_likelihood") or 0)
    unique_sources = safe_int(features.get("unique_src_ips") or features.get("unique_sources"))
    unique_dst_ports = safe_int(features.get("unique_dst_ports"))
    unique_dst_ips = safe_int(features.get("unique_dst_ips"))
    destination_port_distribution = features.get("destination_port_distribution") or {}
    distribution_items = (
        dict(destination_port_distribution).items()
        if isinstance(destination_port_distribution, Mapping)
        else ()
    )
    ordered = sorted(((safe_int(value), clean_text(key)) for key, value in distribution_items), reverse=True)
    total_packets = sum(item[0] for item in ordered)
    dominant_port = ""
    dominant_share = 0.0
    if ordered and total_packets > 0:
        dominant_share = ordered[0][0] / total_packets
        dominant_port = ordered[0][1] if dominant_share >= 0.7 else ""
    distributed = unique_sources >= 20
    random_ports = unique_dst_ports >= 20 and dominant_share < 0.7
    high_fanout = unique_dst_ips >= 8
    spoofing_probable = spoofing_likelihood >= 50 or (distributed and unique_dst_ports >= 20)
    is_carpet_bombing = (
        is_udp and distributed and random_ports and high_fanout and source_classification != "UDP_REFLECTION_SUSPECTED"
    )
    classification_result = (
        CLASSIFICATION_UDP_VOLUMETRIC_CARPET_BOMBING if is_carpet_bombing else source_classification
    )
    return {
        "classification": classification_result,
        "rtbh_eligible": True,
        "is_carpet_bombing": is_carpet_bombing,
        "spoofing_probable": spoofing_probable,
        "random_ports": random_ports,
        "high_fanout": high_fanout,
        "dominant_port": dominant_port,
        "dominant_port_share": round(dominant_share, 4),
        "unique_sources": unique_sources,
        "unique_dst_ports": unique_dst_ports,
        "unique_dst_ips": unique_dst_ips,
        "reason": "rtbh_eligible",
    }


def assess_mitigation_suitability(
    incident: Mapping[str, Any],
    *,
    exceeds_local_capacity_bps: float | None = None,
    observed_bps: float = 0.0,
) -> dict[str, Any]:
    """Produce the mitigation suitability matrix used by candidates/reports."""
    spoofing_probable = bool(incident.get("spoofing_probable"))
    random_ports = bool(incident.get("random_ports"))
    dominant_port = clean_text(incident.get("dominant_port"))
    source_blocking = SUITABILITY_VERY_LOW if spoofing_probable else SUITABILITY_LOW
    asn_blocking = SUITABILITY_VERY_LOW if spoofing_probable else SUITABILITY_MEDIUM
    if not dominant_port and random_ports:
        port_flowspec = SUITABILITY_LOW
    elif dominant_port:
        port_flowspec = SUITABILITY_HIGH
    else:
        port_flowspec = SUITABILITY_MEDIUM
    # Portas aleatórias sem porta dominante limitam FlowSpec por protocolo:
    # MEDIUM quando há concentração de protocolo, LOW com dano colateral alto.
    protocol_flowspec = SUITABILITY_LOW if (random_ports and not dominant_port) else SUITABILITY_MEDIUM
    scrubbing = SUITABILITY_MEDIUM
    if exceeds_local_capacity_bps and observed_bps > float(exceeds_local_capacity_bps):
        scrubbing = SUITABILITY_VERY_HIGH
    return {
        "source_blocking_suitability": source_blocking,
        "asn_blocking_suitability": asn_blocking,
        "port_flowspec_suitability": port_flowspec,
        "protocol_flowspec_suitability": protocol_flowspec,
        "rtbh_suitability": SUITABILITY_HIGH,
        "scrubbing_suitability": scrubbing,
        "source_attribution_confidence": "LOW" if spoofing_probable else "MEDIUM",
        "asn_attribution_confidence": "LOW" if spoofing_probable else "MEDIUM",
        "blocklist_value": "LOW" if spoofing_probable else "MEDIUM",
        "no_safe_selective_rtbh_candidate": False,
    }


# ---------------------------------------------------------------------------
# Selective /32 discovery (never blackhole the parent /22 automatically)
# ---------------------------------------------------------------------------


def normalize_target_prefix(value: Any) -> str:
    text = clean_text(value)
    try:
        return str(ip_network(text, strict=False))
    except ValueError as exc:
        raise ValueError(f"invalid_target_prefix:{text}") from exc


def selective_targets(
    target_prefix: str,
    per_host_rows: Iterable[Mapping[str, Any]],
    *,
    min_host_share: float = 0.05,
    min_host_bps: float = 0.0,
    max_targets: int = 8,
    total_bps: float | None = None,
) -> list[dict[str, Any]]:
    """Choose selective /32 victims inside the incident target prefix.

    Only hosts with meaningful concentration are returned. Concentration is
    measured against the TOTAL attack volume of the target prefix
    (``total_bps`` when provided, otherwise the sum of the supplied rows).
    Supplying only a truncated top-N subset WITHOUT ``total_bps`` would
    inflate each host share and select "concentrated" victims that are not
    actually concentrated — callers must pass the real total.

    When the attack is spread uniformly, the list is empty and the caller
    must flag ``no_safe_selective_rtbh_candidate``.
    """
    network = ip_network(target_prefix, strict=False)
    rows_sum_bps = 0.0
    rows: list[dict[str, Any]] = []
    for raw in per_host_rows:
        item = dict(raw)
        host_text = clean_text(item.get("host") or item.get("dst_ip"))
        if not host_text:
            continue
        try:
            host = ip_address(host_text)
            if hasattr(host, "ipv4_mapped") and host.ipv4_mapped:
                host = host.ipv4_mapped
        except ValueError:
            continue
        if host.version != network.version or host not in network:
            continue
        bps = safe_float(item.get("bps") or item.get("attack_bps_observed"))
        pps = safe_float(item.get("pps") or item.get("attack_pps_observed"))
        rows_sum_bps += bps
        rows.append({"host": str(host), "bps": bps, "pps": pps, "bytes": safe_float(item.get("bytes"))})
    effective_total = safe_float(total_bps) if total_bps is not None else rows_sum_bps
    if effective_total <= 0:
        return []
    selected: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda item: item["bps"], reverse=True):
        share = row["bps"] / effective_total
        if share < float(min_host_share):
            continue
        if row["bps"] < float(min_host_bps):
            continue
        row["share"] = round(share, 4)
        row["prefix"] = f"{row['host']}/{32 if network.version == 4 else 128}"
        selected.append(row)
        if len(selected) >= int(max_targets):
            break
    return selected


# ---------------------------------------------------------------------------
# Provider / ingress mapping
# ---------------------------------------------------------------------------


def provider_ingress_rows(rows: Iterable[Mapping[str, Any]]) -> dict[int, dict[str, float]]:
    """Normalize ClickHouse ingress rows keyed by input_if."""
    result: dict[int, dict[str, float]] = {}
    for raw in rows:
        item = dict(raw)
        input_if = safe_int(item.get("input_if"))
        if input_if <= 0:
            continue
        result[input_if] = {
            "bps": safe_float(item.get("bps") or item.get("attack_bps_observed")),
            "pps": safe_float(item.get("pps") or item.get("attack_pps_observed")),
        }
    return result


def attack_share_by_provider(ingress: Mapping[int, Mapping[str, Any]]) -> dict[int, float]:
    total = sum(safe_float(item.get("bps")) for item in ingress.values())
    if total <= 0:
        return {}
    return {input_if: safe_float(item.get("bps")) / total for input_if, item in ingress.items()}


# ---------------------------------------------------------------------------
# Candidate generation
# ---------------------------------------------------------------------------


def candidate_insert_values(candidate: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[Any, ...]]:
    columns = (
        "incident_id", "threat_assessment_id", "classification", "action_type", "target_prefix",
        "provider_id", "input_if", "confidence",
        "attack_bps_observed", "attack_bps_estimated", "attack_pps_observed", "attack_pps_estimated",
        "baseline_bps", "attack_baseline_ratio", "attack_share_provider",
        "suitability_json", "collateral_risk", "reason", "evidence_json", "status",
        "no_safe_selective_rtbh_candidate", "large_prefix_manual_only", "dry_run_json",
        "created_by", "created_at", "updated_at",
    )
    values = (
        clean_text(candidate.get("incident_id")),
        clean_text(candidate.get("threat_assessment_id")),
        clean_text(candidate.get("classification")),
        clean_text(candidate.get("action_type") or ACTION_TYPE_RTBH),
        clean_text(candidate.get("target_prefix")),
        candidate.get("provider_id"),
        safe_int(candidate.get("input_if")),
        safe_float(candidate.get("confidence")),
        safe_float(candidate.get("attack_bps_observed")),
        safe_float(candidate.get("attack_bps_estimated")),
        safe_float(candidate.get("attack_pps_observed")),
        safe_float(candidate.get("attack_pps_estimated")),
        safe_float(candidate.get("baseline_bps")),
        safe_float(candidate.get("attack_baseline_ratio")),
        safe_float(candidate.get("attack_share_provider")),
        json_dump(candidate.get("suitability") or {}),
        clean_text(candidate.get("collateral_risk") or COLLATERAL_NONE),
        clean_text(candidate.get("reason")),
        json_dump(candidate.get("evidence") or {}),
        clean_text(candidate.get("status") or CANDIDATE_STATUS_PROPOSED),
        1 if candidate.get("no_safe_selective_rtbh_candidate") else 0,
        1 if candidate.get("large_prefix_manual_only") else 0,
        json_dump(candidate.get("dry_run") or {}),
        clean_text(candidate.get("created_by") or "GMJ_FLOW"),
        clean_text(candidate.get("created_at")) or utc_now_iso(),
        clean_text(candidate.get("updated_at")) or utc_now_iso(),
    )
    return columns, values


def persist_candidate(conn: sqlite3.Connection, candidate: Mapping[str, Any]) -> dict[str, Any]:
    ensure_transit_rtbh_schema(conn)
    columns, values = candidate_insert_values(candidate)
    placeholders = ", ".join("?" for _ in columns)
    conn.execute(
        f"INSERT INTO rtbh_mitigation_candidates ({', '.join(columns)}) VALUES ({placeholders})",
        values,
    )
    return dict(candidate)


def audit_candidate_event(
    conn: sqlite3.Connection,
    *,
    actor: str,
    action: str,
    incident_id: str = "",
    candidate_id: int | None = None,
    provider_id: int | None = None,
    target_prefix: str = "",
    policy_id: int | None = None,
    communities_ref: str = "",
    old_state: str = "",
    new_state: str = "",
    reason: str = "",
) -> None:
    ensure_transit_rtbh_schema(conn)
    conn.execute(
        """
        INSERT INTO rtbh_candidate_audit (
            actor, action, incident_id, candidate_id, provider_id, target_prefix,
            policy_id, communities_ref, old_state, new_state, reason, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            clean_text(actor)[:100],
            clean_text(action)[:80],
            clean_text(incident_id)[:200],
            candidate_id,
            provider_id,
            clean_text(target_prefix),
            policy_id,
            clean_text(communities_ref)[:200],
            clean_text(old_state)[:40],
            clean_text(new_state)[:40],
            clean_text(reason)[:500],
            utc_now_iso(),
        ),
    )


def provider_policy_lookup(conn: sqlite3.Connection) -> dict[int, dict[str, Any]]:
    ensure_transit_rtbh_schema(conn)
    rows = conn.execute(
        """
        SELECT p.*
        FROM transit_rtbh_policies p
        """
    ).fetchall()
    return {int(row["provider_id"]): policy_row_to_dict(row, include_communities=True) for row in rows}


def protected_prefix_rtbh_check(
    conn: sqlite3.Connection,
    target_prefix: str,
) -> dict[str, Any]:
    """Three-level RTBH protection for registered protected prefixes.

    Preserves compatibility with the legacy ``block_rtbh`` boolean and adds
    the incremental columns ``block_auto_rtbh`` / ``require_manual_rtbh`` /
    ``block_all_rtbh`` when present. Entries with ``service_name`` are
    explicit protected services and additionally block SELECTIVE /32 RTBH
    (dropping a /32 takes the whole address, including legitimate services).
    """
    try:
        network = ip_network(target_prefix, strict=False)
    except ValueError:
        return {
            "matched": False,
            "block_all_rtbh": False,
            "require_manual_rtbh": False,
            "matches": [],
            "protected_services": [],
            "protected_service_count": 0,
        }
    try:
        rows = conn.execute(
            "SELECT * FROM bgp_protected_prefixes WHERE enabled = 1"
        ).fetchall()
    except sqlite3.OperationalError:
        return {
            "matched": False,
            "block_all_rtbh": False,
            "require_manual_rtbh": False,
            "matches": [],
            "protected_services": [],
            "protected_service_count": 0,
        }
    matches: list[dict[str, Any]] = []
    protected_services: list[dict[str, Any]] = []
    block_all = False
    require_manual = False
    for row in rows:
        item = dict(row)
        try:
            protected = ip_network(clean_text(item.get("cidr")), strict=False)
        except ValueError:
            continue
        if network.version != protected.version or not network.overlaps(protected):
            continue
        block_all_value = item.get("block_all_rtbh")
        if block_all_value is None:
            # Legacy compatibility: the original boolean meant full RTBH block.
            block_all_value = bool(int(item.get("block_rtbh") or 0))
        require_value = item.get("require_manual_rtbh")
        if require_value is None:
            require_value = 1
        service_name = clean_text(item.get("service_name"))
        match_entry = {
            "cidr": str(protected),
            "name": clean_text(item.get("name")),
            "service_name": service_name,
            "protocol": clean_text(item.get("protocol")),
            "port": int(item["port"]) if item.get("port") is not None else None,
            "protection_level": clean_text(item.get("protection_level") or "NORMAL").upper(),
            "block_all_rtbh": bool(int(block_all_value or 0)),
            "require_manual_rtbh": bool(int(require_value or 0)),
        }
        matches.append(match_entry)
        if service_name:
            protected_services.append(match_entry)
        if bool(int(block_all_value or 0)):
            block_all = True
        if bool(int(require_value or 0)):
            require_manual = True
    return {
        "matched": bool(matches),
        "block_all_rtbh": block_all,
        "require_manual_rtbh": require_manual,
        "matches": matches,
        "protected_services": protected_services,
        "protected_service_count": len(protected_services),
    }


def protected_services_inside(
    conn: sqlite3.Connection,
    target_prefix: str,
) -> dict[str, Any]:
    """Aggregated collateral view for LARGE-PREFIX manual RTBH reviews."""
    try:
        network = ip_network(target_prefix, strict=False)
    except ValueError:
        return {
            "protected_service_count": 0,
            "affected_service_names": [],
            "affected_host_count": 0,
        }
    try:
        rows = conn.execute(
            "SELECT * FROM bgp_protected_prefixes WHERE enabled = 1"
        ).fetchall()
    except sqlite3.OperationalError:
        return {
            "protected_service_count": 0,
            "affected_service_names": [],
            "affected_host_count": 0,
        }
    affected_hosts = 0
    service_names: list[str] = []
    service_count = 0
    for row in rows:
        item = dict(row)
        try:
            protected = ip_network(clean_text(item.get("cidr")), strict=False)
        except ValueError:
            continue
        if network.version != protected.version or not network.overlaps(protected):
            continue
        affected_hosts += 1
        service_name = clean_text(item.get("service_name"))
        if service_name:
            service_count += 1
            if service_name not in service_names:
                service_names.append(service_name)
    return {
        "protected_service_count": service_count,
        "affected_service_names": service_names,
        "affected_host_count": affected_hosts,
    }


def active_provider_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    ensure_transit_rtbh_schema(conn)
    rows = conn.execute(
        """
        SELECT v.*, p.id AS policy_id, p.mode AS policy_mode, p.enabled AS policy_enabled
        FROM transit_providers v
        LEFT JOIN transit_rtbh_policies p ON p.provider_id = v.id
        ORDER BY v.name, v.id
        """
    ).fetchall()
    return [provider_row_to_dict(row) for row in rows]


def required_candidate_status(
    *,
    policy: Mapping[str, Any] | None,
    prefix_length: int,
    selective: bool,
    large_prefix_manual: bool,
    confidence: float,
    attack_bps: float,
    duration_seconds: float,
) -> tuple[str, str, bool]:
    """Compute initial candidate status + reason. Never execution.

    Returns (status, reason, eligible). Ineligible candidates (e.g. selective
    /32 outside the provider prefix constraints) are skipped by the caller.
    """
    if large_prefix_manual:
        return CANDIDATE_STATUS_REVIEW_REQUIRED, "manual_large_prefix_rtbh", True
    if policy is None:
        return CANDIDATE_STATUS_REVIEW_REQUIRED, "provider_policy_not_configured", True
    if not bool(policy.get("enabled")):
        return CANDIDATE_STATUS_REVIEW_REQUIRED, "provider_policy_disabled", True
    mode = clean_text(policy.get("mode")).upper()
    if mode == RTBH_MODE_OFF:
        return CANDIDATE_STATUS_PROPOSED, "policy_mode_off", True
    min_prefix = safe_int(policy.get("min_prefix_length"), 32)
    max_prefix = safe_int(policy.get("max_prefix_length"), 32)
    if not (min_prefix <= prefix_length <= max_prefix):
        return CANDIDATE_STATUS_PROPOSED, "prefix_outside_policy_constraints", False
    if confidence < safe_float(policy.get("min_confidence")):
        return CANDIDATE_STATUS_REVIEW_REQUIRED, "below_min_confidence", True
    if attack_bps < safe_float(policy.get("min_attack_bps")):
        return CANDIDATE_STATUS_REVIEW_REQUIRED, "below_min_attack_bps", True
    if duration_seconds < safe_int(policy.get("min_duration_seconds")):
        return CANDIDATE_STATUS_REVIEW_REQUIRED, "below_min_duration", True
    if bool(policy.get("require_manual_approval")) or mode != RTBH_MODE_AUTO:
        return CANDIDATE_STATUS_REVIEW_REQUIRED, "manual_approval_required", True
    # Even with an AUTO policy, this version never proposes execution.
    return CANDIDATE_STATUS_PROPOSED, "recommend_only_version", True


def build_incident_from_vector(vector: Any, decision: Any | None = None) -> dict[str, Any]:
    """Normalize an AttackVector/CampaignVector + policy decision into an
    incident mapping consumed by candidate generation."""
    from app.services.behavioral_detection import AttackVector, CampaignVector

    if isinstance(vector, CampaignVector):
        classification = vector.classification
        target_prefix = vector.target_prefix
        confidence = safe_float(vector.coordination_score) / 100.0
        features = dict(vector.features or {})
        first_seen = vector.first_seen
        last_seen = vector.last_seen
        sources = safe_int(vector.unique_sources)
        observed_bps = safe_float(vector.bits_per_second)
        observed_pps = safe_float(vector.packets_per_second)
    elif isinstance(vector, AttackVector):
        classification = vector.attack_type
        target_prefix = vector.target_prefix or (f"{vector.target_ip}/32" if vector.target_ip else "")
        confidence = safe_float(vector.confidence)
        features = dict(vector.features or {})
        first_seen = vector.first_seen
        last_seen = vector.last_seen
        sources = safe_int(features.get("unique_src_ips") or features.get("unique_sources"))
        observed_bps = safe_float(features.get("bits_per_second") or features.get("bps"))
        observed_pps = safe_float(features.get("packets_per_second") or features.get("pps"))
    else:
        raise ValueError("unsupported_vector_type")
    duration_seconds = 0.0
    try:
        from datetime import datetime

        start = datetime.fromisoformat(str(first_seen).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
        duration_seconds = max(0.0, (end - start).total_seconds())
    except (TypeError, ValueError):
        pass
    features = {key: value for key, value in features.items() if key in {
        "spoofing_likelihood", "unique_src_ips", "unique_sources", "unique_dst_ports",
        "unique_dst_ips", "destination_port_distribution", "max_host_pps", "aggregate_pps",
        "bits_per_second", "packets_per_second", "average_packet_size",
    }}
    classification_info = classify_rtbh_incident(classification, features)
    return {
        "vector_classification": classification,
        "classification": classification_info["classification"],
        "rtbh_eligible": classification_info["rtbh_eligible"],
        "classification_info": classification_info,
        "target_prefix": clean_text(target_prefix),
        "confidence": confidence,
        "first_seen": clean_text(first_seen),
        "last_seen": clean_text(last_seen),
        "duration_seconds": duration_seconds,
        "sources": sources,
        "observed_bps": observed_bps,
        "observed_pps": observed_pps,
        "features": features,
    }


def generate_rtbh_candidates_from_rows(
    conn: sqlite3.Connection,
    incident: Mapping[str, Any],
    per_host_rows: Iterable[Mapping[str, Any]],
    ingress_rows: Iterable[Mapping[str, Any]],
    *,
    estimate_multiplier: float = 1000.0,
    max_selective_targets: int = 8,
    min_provider_share: float = 0.0,
    max_candidates_per_incident: int | None = None,
    local_capacity_bps: float | None = None,
    total_bps: float | None = None,
) -> list[dict[str, Any]]:
    """Generate and persist RTBH candidates for one incident.

    Threat Intelligence provides action=RTBH + provider + target_prefix.
    This engine resolves provider -> TransitRtbhPolicy -> communities/prefix
    policy/approval/execution-mode. Communities are never invented here.

    - Providers whose ingress share is below ``min_provider_share`` are
      skipped (no useless candidates for irrelevant transits).
    - At most ``max_candidates_per_incident`` RTBH candidates are created;
      the remaining analysis stays aggregate, not mitigation candidates.
    - When the attack exceeds local capacity, a single UPSTREAM_SCRUBBING
      recommendation is created instead of pretending RTBH solves it.
    """
    ensure_transit_rtbh_schema(conn)
    created: list[dict[str, Any]] = []
    if not bool(incident.get("rtbh_eligible")):
        return created
    target_prefix = clean_text(incident.get("target_prefix"))
    if not target_prefix:
        return created
    try:
        network = ip_network(target_prefix, strict=False)
    except ValueError:
        return created

    observed_bps = safe_float(incident.get("observed_bps"))
    observed_pps = safe_float(incident.get("observed_pps"))
    multiplier = safe_float(estimate_multiplier, 1000.0)
    if multiplier <= 0:
        multiplier = 1.0
    estimated_bps = observed_bps * multiplier
    estimated_pps = observed_pps * multiplier
    classification_info = dict(incident.get("classification_info") or {})
    suitability = assess_mitigation_suitability(
        classification_info,
        exceeds_local_capacity_bps=local_capacity_bps,
        observed_bps=estimated_bps,
    )

    selective = selective_targets(
        target_prefix,
        per_host_rows,
        max_targets=int(max_selective_targets),
        total_bps=total_bps,
    )
    no_selective = not selective
    suitability["no_safe_selective_rtbh_candidate"] = no_selective

    ingress = provider_ingress_rows(ingress_rows)
    share_by_provider = attack_share_by_provider(ingress)
    has_ingress = bool(share_by_provider)
    policies = provider_policy_lookup(conn)
    provider_rows = {
        int(row["id"]): provider_row_to_dict(row)
        for row in conn.execute("SELECT * FROM transit_providers").fetchall()
    }

    targets: list[tuple[Any, float]] = []
    if no_selective:
        # No safe selective victim: offer MANUAL LARGE PREFIX RTBH with
        # collateral_risk=CRITICAL and explicit text. Never auto-executable.
        targets.append((network, 1.0))
    else:
        for row in selective:
            targets.append((ip_network(row["prefix"], strict=False), row["share"]))

    confidence = safe_float(incident.get("confidence"))
    duration_seconds = safe_float(incident.get("duration_seconds"))
    for provider_id, provider in provider_rows.items():
        if not bool(provider.get("enabled")):
            continue
        input_if = safe_int(provider.get("input_if"))
        provider_share = share_by_provider.get(input_if, 0.0)
        if has_ingress and provider_share < float(min_provider_share):
            # Transit with immaterial contribution: no candidate for it.
            continue
        policy = policies.get(provider_id)
        for target_network, target_share in targets:
            candidate_prefix = str(target_network)
            protection = protected_prefix_rtbh_check(conn, candidate_prefix)
            if protection.get("block_all_rtbh"):
                audit_candidate_event(
                    conn,
                    actor="GMJ_FLOW",
                    action="candidate_skipped_protected_prefix",
                    incident_id=clean_text(incident.get("incident_id")),
                    provider_id=provider_id,
                    target_prefix=candidate_prefix,
                    reason="block_all_rtbh",
                )
                continue
            large_prefix_manual = no_selective and target_network.prefixlen < 32
            if not large_prefix_manual and protection.get("protected_service_count"):
                # Selective /32 RTBH would take the whole address, including
                # legitimate services (e.g. Ookla TCP/8080). Never selective.
                audit_candidate_event(
                    conn,
                    actor="GMJ_FLOW",
                    action="candidate_skipped_protected_service",
                    incident_id=clean_text(incident.get("incident_id")),
                    provider_id=provider_id,
                    target_prefix=candidate_prefix,
                    reason="protected_service_collateral",
                )
                continue
            if no_selective:
                action_type = ACTION_TYPE_MANUAL_LARGE_PREFIX_RTBH
                collateral = COLLATERAL_CRITICAL
                reason = "Esta ação tornará todo o prefixo indisponível através deste trânsito."
            else:
                action_type = ACTION_TYPE_RTBH
                collateral = COLLATERAL_MEDIUM if target_network.prefixlen < 32 else COLLATERAL_LOW
                reason = "Vítima seletiva com concentração de ataque."
            provider_attack_bps = estimated_bps * provider_share if provider_share > 0 else estimated_bps
            status, status_reason, eligible = required_candidate_status(
                policy=policy,
                prefix_length=target_network.prefixlen,
                selective=not no_selective,
                large_prefix_manual=large_prefix_manual,
                confidence=confidence,
                attack_bps=provider_attack_bps,
                duration_seconds=duration_seconds,
            )
            if not eligible:
                continue
            if protection.get("require_manual_rtbh") and status not in {
                CANDIDATE_STATUS_REVIEW_REQUIRED,
            }:
                status = CANDIDATE_STATUS_REVIEW_REQUIRED
                status_reason = "protected_prefix_requires_manual_rtbh"
            baseline_bps = safe_float(incident.get("baseline_bps"))
            attack_baseline_ratio = round(estimated_bps / baseline_bps, 4) if baseline_bps > 0 else 0.0
            evidence = dict(incident.get("evidence") or {}) if isinstance(incident.get("evidence"), Mapping) else {}
            evidence.update(
                {
                    "classification": incident.get("classification"),
                    "spoofing_probable": bool(classification_info.get("spoofing_probable")),
                    "random_ports": bool(classification_info.get("random_ports")),
                    "unique_sources": safe_int(classification_info.get("unique_sources")),
                    "unique_dst_ports": safe_int(classification_info.get("unique_dst_ports")),
                    "selective": not no_selective,
                    "provider_share": round(provider_share, 4),
                    "target_share": round(target_share, 4),
                    "baseline_available": bool(incident.get("baseline_available")),
                }
            )
            candidate = {
                "incident_id": clean_text(incident.get("incident_id")),
                "threat_assessment_id": clean_text(incident.get("threat_assessment_id")),
                "classification": clean_text(incident.get("classification")),
                "action_type": action_type,
                "target_prefix": candidate_prefix,
                "provider_id": provider_id,
                "input_if": input_if,
                "confidence": round(confidence, 4),
                "attack_bps_observed": round(observed_bps, 2),
                "attack_bps_estimated": round(estimated_bps, 2),
                "attack_pps_observed": round(observed_pps, 2),
                "attack_pps_estimated": round(estimated_pps, 2),
                "baseline_bps": round(baseline_bps, 2),
                "attack_baseline_ratio": round(attack_baseline_ratio, 4),
                "attack_share_provider": round(provider_share, 4),
                "suitability": suitability,
                "collateral_risk": collateral,
                "reason": reason,
                "evidence": evidence,
                "status": status,
                "no_safe_selective_rtbh_candidate": 1 if no_selective else 0,
                "large_prefix_manual_only": 1 if large_prefix_manual else 0,
                "dry_run": {},
                "created_by": "GMJ_FLOW",
            }
            duplicate = conn.execute(
                """
                SELECT id FROM rtbh_mitigation_candidates
                WHERE incident_id = ? AND COALESCE(provider_id, 0) = ? AND target_prefix = ?
                LIMIT 1
                """,
                (candidate["incident_id"], int(provider_id or 0), candidate_prefix),
            ).fetchone()
            if duplicate is not None:
                continue
            try:
                columns, values = candidate_insert_values(candidate)
                placeholders = ", ".join("?" for _ in columns)
                cursor = conn.execute(
                    f"INSERT INTO rtbh_mitigation_candidates ({', '.join(columns)}) VALUES ({placeholders})",
                    values,
                )
                candidate_id = int(cursor.lastrowid)
                audit_candidate_event(
                    conn,
                    actor="GMJ_FLOW",
                    action="candidate_created",
                    incident_id=candidate["incident_id"],
                    candidate_id=candidate_id,
                    provider_id=provider_id,
                    target_prefix=candidate_prefix,
                    policy_id=safe_int(policy.get("id")) if policy else None,
                    old_state="",
                    new_state=status,
                    reason=status_reason,
                )
                created.append(
                    {
                        **candidate,
                        "id": candidate_id,
                        "status_reason": status_reason,
                        "policy_configured": policy is not None,
                        "provider_name": provider.get("name"),
                    }
                )
            except sqlite3.IntegrityError:
                continue
    # Limit the number of persistent RTBH candidates per incident. The
    # remaining /32 analysis stays aggregate data, not mitigation candidates.
    cap = safe_int(max_candidates_per_incident, 0)
    if cap and len(created) > cap:
        def candidate_score(item: Mapping[str, Any]) -> float:
            share = safe_float(item.get("attack_share_provider"))
            return safe_float(item.get("attack_bps_estimated")) * max(share, 0.0001)

        ranked = sorted(created, key=candidate_score, reverse=True)
        for dropped in ranked[cap:]:
            audit_candidate_event(
                conn,
                actor="GMJ_FLOW",
                action="candidate_skipped_cap",
                incident_id=clean_text(dropped.get("incident_id")),
                provider_id=dropped.get("provider_id"),
                target_prefix=clean_text(dropped.get("target_prefix")),
                reason=f"max_candidates_per_incident={cap}",
            )
            conn.execute(
                "DELETE FROM rtbh_mitigation_candidates WHERE id = ?",
                (safe_int(dropped.get("id")),),
            )
        created = ranked[:cap]
    if suitability.get("scrubbing_suitability") == SUITABILITY_VERY_HIGH:
        scrubbing_reasons = ["attack_above_local_capacity"]
        if no_selective:
            scrubbing_reasons.extend(
                ["uniform_distribution", "large_prefix", "high_collateral"]
            )
        scrubbing = {
            "incident_id": clean_text(incident.get("incident_id")),
            "threat_assessment_id": clean_text(incident.get("threat_assessment_id")),
            "classification": clean_text(incident.get("classification")),
            "action_type": ACTION_TYPE_UPSTREAM_SCRUBBING,
            "target_prefix": str(network),
            "provider_id": None,
            "input_if": 0,
            "confidence": round(confidence, 4),
            "attack_bps_observed": round(observed_bps, 2),
            "attack_bps_estimated": round(estimated_bps, 2),
            "attack_pps_observed": round(observed_pps, 2),
            "attack_pps_estimated": round(estimated_pps, 2),
            "baseline_bps": 0.0,
            "attack_baseline_ratio": 0.0,
            "attack_share_provider": 0.0,
            "suitability": suitability,
            "collateral_risk": COLLATERAL_MEDIUM,
            "reason": (
                "Ataque excede a capacidade local; desvio para centro de "
                "limpeza (scrubbing) recomendado. Motivos: "
                + "; ".join(scrubbing_reasons)
                + "."
            ),
            "evidence": {
                **(dict(incident.get("evidence") or {}) if isinstance(incident.get("evidence"), Mapping) else {}),
                "scrubbing_reasons": scrubbing_reasons,
                "recommendation_priority": "PRIMARY" if no_selective else "SECONDARY",
            },
            "status": CANDIDATE_STATUS_REVIEW_REQUIRED,
            "no_safe_selective_rtbh_candidate": 1 if no_selective else 0,
            "large_prefix_manual_only": 0,
            "dry_run": {},
            "created_by": "GMJ_FLOW",
        }
        duplicate = conn.execute(
            """
            SELECT id FROM rtbh_mitigation_candidates
            WHERE incident_id = ? AND COALESCE(provider_id, 0) = 0 AND target_prefix = ?
            LIMIT 1
            """,
            (scrubbing["incident_id"], scrubbing["target_prefix"]),
        ).fetchone()
        if duplicate is None:
            scrubbing_columns, scrubbing_values = candidate_insert_values(scrubbing)
            scrubbing_placeholders = ", ".join("?" for _ in scrubbing_columns)
            cursor = conn.execute(
                f"INSERT INTO rtbh_mitigation_candidates ({', '.join(scrubbing_columns)}) "
                f"VALUES ({scrubbing_placeholders})",
                scrubbing_values,
            )
            scrubbing_id = int(cursor.lastrowid)
            audit_candidate_event(
                conn,
                actor="GMJ_FLOW",
                action="candidate_created",
                incident_id=scrubbing["incident_id"],
                candidate_id=scrubbing_id,
                target_prefix=scrubbing["target_prefix"],
                old_state="",
                new_state=scrubbing["status"],
                reason="upstream_scrubbing_recommended",
            )
            created.append(
                {
                    **scrubbing,
                    "id": scrubbing_id,
                    "status_reason": "upstream_scrubbing_recommended",
                    "policy_configured": False,
                    "provider_name": "",
                }
            )
    return created


# ---------------------------------------------------------------------------
# RTBH dry-run executor
# ---------------------------------------------------------------------------


@dataclass
class RtbhDryRunResult:
    provider: str
    provider_id: int | None
    input_if: int
    target: str
    standard_communities: list[str]
    large_communities: list[str]
    address_family: str
    policy_mode: str
    policy_configured: bool
    would_announce: bool
    actually_announced: bool
    reason: str
    execution_enabled_env: bool
    execution_effective: bool
    dry_run_only_version: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def rtbh_dry_run(
    conn: sqlite3.Connection,
    candidate: Mapping[str, Any],
    *,
    include_community_values: bool = False,
) -> dict[str, Any]:
    """Build the action that WOULD be sent to BGP without sending anything.

    Never touches ExaBGP pipes, connectors or routers. The output masks
    communities when they are marked sensitive unless explicitly allowed.
    """
    ensure_transit_rtbh_schema(conn)
    provider_id = candidate.get("provider_id")
    provider_row = None
    policy_row = None
    if provider_id is not None:
        provider_row = conn.execute(
            "SELECT * FROM transit_providers WHERE id = ?",
            (int(provider_id),),
        ).fetchone()
        policy_row = conn.execute(
            "SELECT * FROM transit_rtbh_policies WHERE provider_id = ?",
            (int(provider_id),),
        ).fetchone()
    provider_name = clean_text(provider_row["name"]) if provider_row is not None else clean_text(candidate.get("provider_name"))
    policy = policy_row_to_dict(policy_row, include_communities=True) if policy_row is not None else None
    standard = (policy or {}).get("standard_communities") or []
    large = (policy or {}).get("large_communities") or []
    sensitive = bool((policy or {}).get("communities_sensitive"))
    masked_standard = communities_mask(standard, sensitive) if not include_community_values else list(standard)
    masked_large = communities_mask(large, sensitive) if not include_community_values else list(large)
    target_prefix = clean_text(candidate.get("target_prefix"))
    configured = policy is not None and bool(policy.get("enabled"))
    has_communities = bool(standard or large)
    mode = clean_text((policy or {}).get("mode") or RTBH_MODE_OFF).upper() if policy is not None else "NOT_CONFIGURED"
    # Policy readiness: would the action be announced under a normal
    # execution path (policy + communities + mode)? Actual announcement is
    # always NO in this dry-run-only version and without the kill switch.
    would_announce = bool(
        configured and has_communities and mode != RTBH_MODE_OFF
    )
    reasons: list[str] = []
    if policy is None:
        reasons.append("provider_policy_not_configured")
    elif not configured:
        reasons.append("provider_policy_disabled")
    if not has_communities:
        reasons.append("no_communities_configured")
    if mode == RTBH_MODE_OFF:
        reasons.append("policy_mode_off")
    if would_announce and not rtbh_execution_enabled_env():
        reasons.append("rtbh_execution_kill_switch_disabled")
    reasons.append("dry_run_only_version_never_announces")
    result = RtbhDryRunResult(
        provider=provider_name,
        provider_id=safe_int(provider_id) if provider_id is not None else None,
        input_if=safe_int(candidate.get("input_if")),
        target=target_prefix,
        standard_communities=masked_standard,
        large_communities=masked_large,
        address_family=clean_text((policy or {}).get("address_family") or "ipv4"),
        policy_mode=mode,
        policy_configured=policy is not None,
        would_announce=would_announce,
        actually_announced=False,
        reason="; ".join(dict.fromkeys(reasons)),
        execution_enabled_env=rtbh_execution_enabled_env(),
        execution_effective=bool(configured and effective_execution_allowed(policy or {})),
    )
    return result.as_dict()


def apply_candidate_status(
    conn: sqlite3.Connection,
    candidate_id: int,
    new_status: str,
    *,
    actor: str,
    reason: str = "",
) -> dict[str, Any]:
    ensure_transit_rtbh_schema(conn)
    new_status = clean_text(new_status).upper()
    if new_status not in CANDIDATE_STATUSES:
        raise ValueError("invalid_candidate_status")
    if new_status not in REACHABLE_STATUSES:
        raise ValueError("status_not_reachable_in_this_version")
    row = conn.execute(
        "SELECT * FROM rtbh_mitigation_candidates WHERE id = ?",
        (candidate_id,),
    ).fetchone()
    if row is None:
        raise ValueError("candidate_not_found")
    old_status = clean_text(row["status"])
    allowed = ALLOWED_TRANSITIONS.get(old_status, set())
    if new_status != old_status and new_status not in allowed:
        raise ValueError(f"transition_not_allowed:{old_status}->{new_status}")
    dry_run_json = clean_text(row["dry_run_json"] or "{}")
    if new_status == CANDIDATE_STATUS_DRY_RUN:
        candidate = candidate_row_to_dict(row)
        dry_run = rtbh_dry_run(conn, candidate)
        dry_run_json = json_dump(dry_run)
    conn.execute(
        """
        UPDATE rtbh_mitigation_candidates
        SET status = ?, dry_run_json = ?, updated_at = ?
        WHERE id = ?
        """,
        (new_status, dry_run_json, utc_now_iso(), candidate_id),
    )
    audit_candidate_event(
        conn,
        actor=actor,
        action="candidate_status_changed",
        incident_id=clean_text(row["incident_id"]),
        candidate_id=candidate_id,
        provider_id=safe_int(row["provider_id"]) if row["provider_id"] is not None else None,
        target_prefix=clean_text(row["target_prefix"]),
        old_state=old_status,
        new_state=new_status,
        reason=reason,
    )
    updated = conn.execute(
        "SELECT * FROM rtbh_mitigation_candidates WHERE id = ?",
        (candidate_id,),
    ).fetchone()
    return candidate_row_to_dict(updated)


# ---------------------------------------------------------------------------
# Report section (community values never leak unless allowed)
# ---------------------------------------------------------------------------


def rtbh_report_section(conn: sqlite3.Connection, incident_id: str) -> dict[str, Any]:
    ensure_transit_rtbh_schema(conn)
    rows = conn.execute(
        """
        SELECT c.*, v.name AS provider_name
        FROM rtbh_mitigation_candidates c
        LEFT JOIN transit_providers v ON v.id = c.provider_id
        WHERE c.incident_id = ?
        ORDER BY c.created_at, c.id
        """,
        (clean_text(incident_id),),
    ).fetchall()
    items = []
    for row in rows:
        item = candidate_row_to_dict(row)
        dry_run = item.get("dry_run") or {}
        items.append(
            {
                "id": item["id"],
                "target_prefix": item["target_prefix"],
                "action_type": item["action_type"],
                "provider": item.get("provider_name") or "-",
                "input_if": item["input_if"],
                "attack_share_provider": item["attack_share_provider"],
                "attack_bps_estimated": item["attack_bps_estimated"],
                "baseline_bps": item["baseline_bps"],
                "confidence": item["confidence"],
                "policy_configured": bool(dry_run.get("policy_configured")),
                "community_configured": bool(
                    dry_run.get("standard_communities") or dry_run.get("large_communities")
                ),
                "collateral_risk": item["collateral_risk"],
                "status": item["status"],
                "reason": item["reason"],
            }
        )
    return {"mitigation_candidates": items, "count": len(items)}
