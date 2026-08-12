from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from app.services.threat_contracts import attack_family, detector_verdict
from app.services.threat_intelligence import clean_text, json_dump, safe_json, utc_now_iso


PROTECTED_RETENTION_STATUSES = {"confirmed", "investigating", "mitigated", "manually_pinned"}
EDITABLE_STATUSES = {"active", "benign", *PROTECTED_RETENTION_STATUSES}
AI_ANALYSIS_STATUSES = {"not_analyzed", "valid", "stale"}
MITIGATION_STATUSES = {"not_executed", "shadow", "requested", "executed", "failed", "expired"}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {
        row["name"] if isinstance(row, sqlite3.Row) else row[1]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _ensure_column(conn: sqlite3.Connection, table: str, name: str, ddl: str) -> None:
    if name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def ensure_security_event_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL UNIQUE,
            detector TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            attack_family TEXT NOT NULL DEFAULT 'OTHER_FAMILY',
            severity TEXT NOT NULL DEFAULT 'INFO',
            detector_score INTEGER NOT NULL DEFAULT 0,
            confidence REAL NOT NULL DEFAULT 0,
            verdict TEXT NOT NULL DEFAULT 'INFO',
            src_ip TEXT NOT NULL DEFAULT '',
            src_prefix TEXT NOT NULL DEFAULT '',
            target_ip TEXT NOT NULL DEFAULT '',
            target_prefix TEXT NOT NULL DEFAULT '',
            src_role TEXT NOT NULL DEFAULT 'UNKNOWN',
            dst_role TEXT NOT NULL DEFAULT 'UNKNOWN',
            direction TEXT NOT NULL DEFAULT 'UNKNOWN',
            protocol TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            recurrence_count INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'active',
            packets INTEGER NOT NULL DEFAULT 0,
            packets_per_second REAL NOT NULL DEFAULT 0,
            bits_per_second REAL NOT NULL DEFAULT 0,
            flows INTEGER NOT NULL DEFAULT 0,
            flows_per_second REAL NOT NULL DEFAULT 0,
            unique_sources INTEGER NOT NULL DEFAULT 0,
            unique_destinations INTEGER NOT NULL DEFAULT 0,
            unique_src_ports INTEGER NOT NULL DEFAULT 0,
            unique_dst_ports INTEGER NOT NULL DEFAULT 0,
            unique_source_asns INTEGER NOT NULL DEFAULT 0,
            baseline_deviation REAL NOT NULL DEFAULT 0,
            input_if INTEGER NOT NULL DEFAULT 0,
            output_if INTEGER NOT NULL DEFAULT 0,
            sensor TEXT NOT NULL DEFAULT '',
            exporter TEXT NOT NULL DEFAULT '',
            cgnat_context TEXT NOT NULL DEFAULT '',
            network_context_json TEXT NOT NULL DEFAULT '{}',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            score_components_json TEXT NOT NULL DEFAULT '{}',
            threat_intel_json TEXT NOT NULL DEFAULT '{}',
            ai_analysis_json TEXT NOT NULL DEFAULT '{}',
            ai_analysis_status TEXT NOT NULL DEFAULT 'not_analyzed',
            ai_analysis_stale_at TEXT,
            analyzed_at TEXT,
            ai_provider TEXT NOT NULL DEFAULT '',
            ai_model TEXT NOT NULL DEFAULT '',
            analysis_version TEXT NOT NULL DEFAULT '',
            campaign_id TEXT NOT NULL DEFAULT '',
            mitigation_status TEXT NOT NULL DEFAULT 'not_executed',
            decision_source TEXT NOT NULL DEFAULT 'GMJ_FLOW'
        );

        CREATE TABLE IF NOT EXISTS security_event_migrations (
            migration_key TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_security_events_status_time
            ON security_events(status, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_type_time
            ON security_events(attack_type, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_campaign
            ON security_events(campaign_id, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_src
            ON security_events(src_ip, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_target
            ON security_events(target_ip, target_prefix, last_seen DESC);
        """
    )
    # Forward-compatible additive migrations for installations that received an
    # early preview of security_events.
    existing_columns = _columns(conn, "security_events")
    additions = {
        "score_components_json": "score_components_json TEXT NOT NULL DEFAULT '{}'",
        "ai_analysis_status": "ai_analysis_status TEXT NOT NULL DEFAULT 'not_analyzed'",
        "ai_analysis_stale_at": "ai_analysis_stale_at TEXT",
        "analyzed_at": "analyzed_at TEXT",
        "ai_provider": "ai_provider TEXT NOT NULL DEFAULT ''",
        "ai_model": "ai_model TEXT NOT NULL DEFAULT ''",
        "analysis_version": "analysis_version TEXT NOT NULL DEFAULT ''",
        "mitigation_status": "mitigation_status TEXT NOT NULL DEFAULT 'not_executed'",
    }
    for name, ddl in additions.items():
        _ensure_column(conn, "security_events", name, ddl)
    if "ai_analysis_status" not in existing_columns:
        conn.execute(
            """
            UPDATE security_events
            SET ai_analysis_status='valid'
            WHERE analyzed_at IS NOT NULL
              AND ai_analysis_json NOT IN ('', '{}', 'null')
            """
        )


def canonical_event_key(
    detector: Any,
    attack_type: Any,
    src_ip: Any = "",
    target_ip: Any = "",
    target_prefix: Any = "",
    direction: Any = "",
    protocol: Any = "",
) -> str:
    raw = "|".join(clean_text(value).upper() for value in (
        detector, attack_type, src_ip, target_ip, target_prefix, direction, protocol
    ))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _confidence_percent(value: Any) -> float:
    try:
        result = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    return round(max(0.0, min(100.0, result * 100 if result <= 1 else result)), 2)


def _severity(score: Any, verdict: str) -> str:
    value = int(float(score or 0))
    if verdict == "CONFIRMED_ATTACK" or value >= 90:
        return "CRITICAL"
    if verdict == "LIKELY_ATTACK" or value >= 75:
        return "HIGH"
    if value >= 55:
        return "MEDIUM"
    return "LOW"


def _feature(features: Mapping[str, Any], *names: str, default: Any = 0) -> Any:
    for name in names:
        value = features.get(name)
        if value is not None and value != "":
            return value
    return default


def vector_security_payload(vector: Any) -> dict[str, Any]:
    features = dict(getattr(vector, "features", {}) or {})
    network = dict(getattr(vector, "network_context", {}) or features.get("network_context") or {})
    score = int(getattr(vector, "detector_score", 0) or 0)
    persistent_windows = int(features.get("persistent_windows") or features.get("consecutive_windows") or 1)
    verdict = clean_text(getattr(vector, "verdict", "")) or detector_verdict(score, persistent_windows=persistent_windows)
    protocol = clean_text(getattr(vector, "protocol", "") or features.get("protocol"))
    attack_type = clean_text(getattr(vector, "attack_type", ""))
    src_ip = clean_text(getattr(vector, "src_ip", ""))
    target_ip = clean_text(getattr(vector, "target_ip", ""))
    target_prefix = clean_text(getattr(vector, "target_prefix", ""))
    direction = clean_text(getattr(vector, "direction", "UNKNOWN")) or "UNKNOWN"
    evidence = getattr(vector, "evidence", None) or features.get("evidence") or []
    if isinstance(evidence, Sequence) and not isinstance(evidence, (str, bytes, dict)):
        evidence = {"facts": list(evidence)[-50:]}
    elif not isinstance(evidence, Mapping):
        evidence = {"facts": []}
    score_components = getattr(vector, "score_components", None) or features.get("score_components") or {}
    src_role = clean_text(network.get("src_role") or features.get("src_role") or "UNKNOWN")
    dst_role = clean_text(network.get("dst_role") or features.get("dst_role") or "UNKNOWN")
    src_prefix = clean_text(network.get("src_prefix") or features.get("src_prefix"))
    cgnat_context = ""
    if network.get("src_is_cgnat"):
        cgnat_context = "source_cgnat_public"
    if network.get("dst_is_cgnat"):
        cgnat_context = "destination_cgnat_public"
    return {
        "event_key": canonical_event_key(getattr(vector, "detector", ""), attack_type, src_ip, target_ip, target_prefix, direction, protocol),
        "detector": clean_text(getattr(vector, "detector", "")),
        "attack_type": attack_type,
        "attack_family": attack_family(attack_type),
        "severity": clean_text(getattr(vector, "severity", "")) or _severity(score, verdict),
        "detector_score": score,
        "confidence": _confidence_percent(getattr(vector, "confidence", 0)),
        "verdict": verdict,
        "src_ip": src_ip,
        "src_prefix": src_prefix,
        "target_ip": target_ip,
        "target_prefix": target_prefix,
        "src_role": src_role or "UNKNOWN",
        "dst_role": dst_role or "UNKNOWN",
        "direction": direction,
        "protocol": protocol,
        "first_seen": clean_text(getattr(vector, "first_seen", "")) or utc_now_iso(),
        "last_seen": clean_text(getattr(vector, "last_seen", "")) or utc_now_iso(),
        "packets": int(_feature(features, "packet_count", "packets", default=0) or 0),
        "packets_per_second": float(_feature(features, "packets_per_second", "pps", "aggregate_pps", default=0) or 0),
        "bits_per_second": float(_feature(features, "bits_per_second", "bps", default=0) or 0),
        "flows": int(_feature(features, "flow_count", "flows", default=0) or 0),
        "flows_per_second": float(_feature(features, "flows_per_second", default=0) or 0),
        "unique_sources": int(_feature(features, "unique_sources", "unique_src_ips", default=0) or 0),
        "unique_destinations": int(_feature(features, "unique_destinations", "unique_dst_ips", "target_hosts", default=0) or 0),
        "unique_src_ports": int(_feature(features, "unique_src_ports", default=0) or 0),
        "unique_dst_ports": int(_feature(features, "unique_dst_ports", default=0) or 0),
        "unique_source_asns": int(_feature(features, "unique_source_asns", "unique_src_asns", default=0) or 0),
        "baseline_deviation": float(getattr(vector, "baseline_deviation", 0) or 0),
        "input_if": int(network.get("input_if") or features.get("input_if") or 0),
        "output_if": int(network.get("output_if") or features.get("output_if") or 0),
        "sensor": clean_text(network.get("sensor") or features.get("sensor")),
        "exporter": clean_text(network.get("exporter") or features.get("exporter")),
        "cgnat_context": cgnat_context,
        "network_context_json": json_dump(network),
        "evidence_json": json_dump(dict(evidence)),
        "score_components_json": json_dump(dict(score_components)),
        "threat_intel_json": json_dump(getattr(vector, "threat_intel", {}) or {}),
        "campaign_id": clean_text(getattr(vector, "campaign_id", "")),
        "mitigation_status": "not_executed",
        "decision_source": clean_text(getattr(vector, "decision_source", "GMJ_FLOW")) or "GMJ_FLOW",
    }


def _material_event_changes(existing: Mapping[str, Any] | None, item: Mapping[str, Any]) -> list[str]:
    if not existing:
        return []
    reasons: list[str] = []
    if clean_text(item.get("last_seen")) > clean_text(existing.get("last_seen")):
        reasons.append("last_seen")
    for field in ("detector_score", "confidence"):
        if float(item.get(field) or 0) > float(existing.get(field) or 0):
            reasons.append(field)
    for field in (
        "packets", "packets_per_second", "bits_per_second", "flows", "flows_per_second",
        "unique_sources", "unique_destinations", "unique_src_ports", "unique_dst_ports",
        "unique_source_asns", "baseline_deviation",
    ):
        previous = float(existing.get(field) or 0)
        current = float(item.get(field) or 0)
        if current > previous and (previous <= 0 or current >= previous * 1.10):
            reasons.append(field)
    for field in ("campaign_id", "network_context_json", "threat_intel_json", "evidence_json"):
        if clean_text(item.get(field)) != clean_text(existing.get(field)):
            reasons.append(field)
    return reasons


def upsert_security_event(conn: sqlite3.Connection, vector: Any) -> int:
    ensure_security_event_schema(conn)
    item = vector_security_payload(vector)
    now = utc_now_iso()
    existing_row = conn.execute(
        "SELECT * FROM security_events WHERE event_key = ?",
        (item["event_key"],),
    ).fetchone()
    existing = dict(existing_row) if existing_row is not None else None
    material_changes = _material_event_changes(existing, item)
    previous_analysis = safe_json((existing or {}).get("ai_analysis_json"), {})
    columns = list(item)
    conn.execute(
        f"""
        INSERT INTO security_events ({','.join(columns)}, created_at, updated_at)
        VALUES ({','.join('?' for _ in columns)}, ?, ?)
        ON CONFLICT(event_key) DO UPDATE SET
            detector_score=MAX(security_events.detector_score, excluded.detector_score),
            confidence=MAX(security_events.confidence, excluded.confidence),
            severity=CASE
                WHEN excluded.detector_score >= security_events.detector_score THEN excluded.severity
                ELSE security_events.severity END,
            verdict=CASE
                WHEN excluded.detector_score >= security_events.detector_score THEN excluded.verdict
                ELSE security_events.verdict END,
            first_seen=MIN(security_events.first_seen, excluded.first_seen),
            last_seen=MAX(security_events.last_seen, excluded.last_seen),
            recurrence_count=security_events.recurrence_count+1,
            packets=MAX(security_events.packets, excluded.packets),
            packets_per_second=MAX(security_events.packets_per_second, excluded.packets_per_second),
            bits_per_second=MAX(security_events.bits_per_second, excluded.bits_per_second),
            flows=MAX(security_events.flows, excluded.flows),
            flows_per_second=MAX(security_events.flows_per_second, excluded.flows_per_second),
            unique_sources=MAX(security_events.unique_sources, excluded.unique_sources),
            unique_destinations=MAX(security_events.unique_destinations, excluded.unique_destinations),
            unique_src_ports=MAX(security_events.unique_src_ports, excluded.unique_src_ports),
            unique_dst_ports=MAX(security_events.unique_dst_ports, excluded.unique_dst_ports),
            unique_source_asns=MAX(security_events.unique_source_asns, excluded.unique_source_asns),
            baseline_deviation=MAX(security_events.baseline_deviation, excluded.baseline_deviation),
            src_role=excluded.src_role, dst_role=excluded.dst_role, direction=excluded.direction,
            src_prefix=excluded.src_prefix, protocol=excluded.protocol,
            input_if=excluded.input_if, output_if=excluded.output_if,
            sensor=excluded.sensor, exporter=excluded.exporter,
            cgnat_context=excluded.cgnat_context,
            network_context_json=excluded.network_context_json,
            evidence_json=excluded.evidence_json,
            score_components_json=excluded.score_components_json,
            threat_intel_json=excluded.threat_intel_json,
            campaign_id=excluded.campaign_id,
            decision_source=excluded.decision_source,
            updated_at=excluded.updated_at
        """,
        (*[item[column] for column in columns], now, now),
    )
    if material_changes and previous_analysis:
        conn.execute(
            """
            UPDATE security_events
            SET ai_analysis_status='stale', ai_analysis_stale_at=?, updated_at=?
            WHERE event_key=?
            """,
            (now, now, item["event_key"]),
        )
        conn.execute(
            """
            INSERT INTO threat_engine_audit (
                event_type, detector, groq_result_json, reason,
                non_mitigation_reason, created_at
            ) VALUES ('AI_ANALYSIS_INVALIDATED', ?, ?, ?, 'cache_invalidation_only_no_mitigation', ?)
            """,
            (
                item["detector"],
                json_dump({"previous_analysis": previous_analysis}),
                json_dump({"event_key": item["event_key"], "material_changes": material_changes}),
                now,
            ),
        )
    row = conn.execute("SELECT id FROM security_events WHERE event_key = ?", (item["event_key"],)).fetchone()
    return int(row[0])


def update_security_event_mitigation_status(
    conn: sqlite3.Connection,
    entity: Any,
    status: str,
    *,
    decision_source: str = "GMJ_FLOW",
) -> int:
    ensure_security_event_schema(conn)
    normalized = clean_text(status).lower()
    if normalized not in MITIGATION_STATUSES:
        raise ValueError("invalid_security_event_mitigation_status")
    now = utc_now_iso()
    if clean_text(getattr(entity, "attack_type", "")):
        key = vector_security_payload(entity)["event_key"]
        cursor = conn.execute(
            """
            UPDATE security_events
            SET mitigation_status=?, decision_source=?, updated_at=?
            WHERE event_key=?
            """,
            (normalized, clean_text(decision_source) or "GMJ_FLOW", now, key),
        )
        entity_key = key
    else:
        campaign_id = clean_text(getattr(entity, "campaign_id", ""))
        cursor = conn.execute(
            """
            UPDATE security_events
            SET mitigation_status=?, decision_source=?, updated_at=?
            WHERE campaign_id=?
            """,
            (normalized, clean_text(decision_source) or "GMJ_FLOW", now, campaign_id),
        )
        entity_key = campaign_id
    changed = max(0, int(cursor.rowcount or 0))
    if changed:
        conn.execute(
            """
            INSERT INTO threat_engine_audit (
                event_type, detector, mitigation_decision_json, reason,
                non_mitigation_reason, created_at
            ) VALUES ('SECURITY_EVENT_MITIGATION_STATUS', 'policy_engine', ?, ?, 'status_sync_only', ?)
            """,
            (
                json_dump({
                    "status": normalized,
                    "decision_source": clean_text(decision_source) or "GMJ_FLOW",
                    "affected_events": changed,
                }),
                f"entity={entity_key}",
                now,
            ),
        )
    return changed


def update_security_event_mitigation_status_by_reference(
    conn: sqlite3.Connection,
    reference: str,
    status: str,
    *,
    decision_source: str = "GMJ_FLOW",
) -> int:
    """Synchronize an operational result using a canonical event key or campaign id."""
    ensure_security_event_schema(conn)
    normalized = clean_text(status).lower()
    if normalized not in MITIGATION_STATUSES:
        raise ValueError("invalid_security_event_mitigation_status")
    key = clean_text(reference)
    if not key:
        return 0
    now = utc_now_iso()
    cursor = conn.execute(
        """
        UPDATE security_events
        SET mitigation_status=?, decision_source=?, updated_at=?
        WHERE event_key=? OR campaign_id=?
        """,
        (normalized, clean_text(decision_source) or "GMJ_FLOW", now, key, key),
    )
    changed = max(0, int(cursor.rowcount or 0))
    if changed:
        conn.execute(
            """
            INSERT INTO threat_engine_audit (
                event_type, detector, mitigation_decision_json, reason,
                non_mitigation_reason, created_at
            ) VALUES ('SECURITY_EVENT_MITIGATION_STATUS', 'flowspec_lifecycle', ?, ?, 'status_sync_only', ?)
            """,
            (
                json_dump({
                    "status": normalized,
                    "decision_source": clean_text(decision_source) or "GMJ_FLOW",
                    "affected_events": changed,
                }),
                f"reference={key}",
                now,
            ),
        )
    return changed


def security_event_row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    for source, target, fallback in (
        ("network_context_json", "network_context", {}),
        ("evidence_json", "evidence", {}),
        ("score_components_json", "score_components", {}),
        ("threat_intel_json", "threat_intel", {}),
        ("ai_analysis_json", "ai_analysis", {}),
    ):
        item[target] = safe_json(item.pop(source, "{}"), fallback)
    return item


def cleanup_security_events(conn: sqlite3.Connection, retention_days: int | None = None) -> int:
    ensure_security_event_schema(conn)
    configured = retention_days if retention_days is not None else int(os.getenv("GMJFLOW_SECURITY_EVENT_RETENTION_DAYS", "3"))
    days = max(1, min(int(configured), 3650))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
    placeholders = ",".join("?" for _ in PROTECTED_RETENTION_STATUSES)
    cursor = conn.execute(
        f"DELETE FROM security_events WHERE last_seen < ? AND status NOT IN ({placeholders})",
        (cutoff, *sorted(PROTECTED_RETENTION_STATUSES)),
    )
    removed = max(0, int(cursor.rowcount or 0))
    if removed:
        conn.execute(
            """
            INSERT INTO threat_engine_audit (event_type, detector, reason, non_mitigation_reason, created_at)
            VALUES ('SECURITY_EVENT_RETENTION', 'retention_job', ?, 'retention_only_unprotected_events', ?)
            """,
            (f"removed={removed};retention_days={days}", utc_now_iso()),
        )
    return removed


def update_event_status(conn: sqlite3.Connection, event_id: int, status: str, actor: str = "manual") -> dict[str, Any] | None:
    ensure_security_event_schema(conn)
    normalized = clean_text(status).lower()
    if normalized not in EDITABLE_STATUSES:
        raise ValueError("invalid_security_event_status")
    now = utc_now_iso()
    cursor = conn.execute(
        "UPDATE security_events SET status=?, updated_at=? WHERE id=?",
        (normalized, now, int(event_id)),
    )
    if cursor.rowcount != 1:
        return None
    conn.execute(
        """
        INSERT INTO threat_engine_audit (event_type, detector, reason, non_mitigation_reason, created_at)
        VALUES ('SECURITY_EVENT_STATUS', 'manual_review', ?, 'manual_status_only_no_mitigation', ?)
        """,
        (f"event_id={int(event_id)};status={normalized};actor={clean_text(actor) or 'manual'}", now),
    )
    row = conn.execute("SELECT * FROM security_events WHERE id=?", (int(event_id),)).fetchone()
    return security_event_row(row) if row else None


def migrate_legacy_security_events(conn: sqlite3.Connection) -> int:
    ensure_security_event_schema(conn)
    migration_key = "behavioral_attack_vectors_to_security_events_v1"
    if conn.execute("SELECT 1 FROM security_event_migrations WHERE migration_key=?", (migration_key,)).fetchone():
        return 0
    try:
        rows = conn.execute("SELECT * FROM behavioral_attack_vectors ORDER BY id").fetchall()
    except sqlite3.OperationalError:
        return 0
    migrated = 0
    for raw in rows:
        item = dict(raw)
        features = safe_json(item.get("feature_json"), {})
        network = features.get("network_context") if isinstance(features.get("network_context"), dict) else {}
        score = int(item.get("detector_score") or 0)
        verdict = detector_verdict(score, persistent_windows=int(features.get("persistent_windows") or 1))
        payload = {
            "event_key": canonical_event_key(item.get("detector"), item.get("attack_type"), item.get("src_ip"), item.get("target_ip"), item.get("target_prefix"), item.get("direction"), features.get("protocol")),
            "detector": item.get("detector") or "legacy",
            "attack_type": item.get("attack_type") or "UNKNOWN_ANOMALY",
            "attack_family": attack_family(item.get("attack_type") or ""),
            "severity": _severity(score, verdict),
            "detector_score": score,
            "confidence": _confidence_percent(item.get("confidence")),
            "verdict": verdict,
            "src_ip": item.get("src_ip") or "",
            "src_prefix": network.get("src_prefix") or "",
            "target_ip": item.get("target_ip") or "",
            "target_prefix": item.get("target_prefix") or "",
            "src_role": network.get("src_role") or "UNKNOWN",
            "dst_role": network.get("dst_role") or "UNKNOWN",
            "direction": item.get("direction") or "UNKNOWN",
            "protocol": features.get("protocol") or "",
            "first_seen": item.get("first_seen") or item.get("created_at") or utc_now_iso(),
            "last_seen": item.get("last_seen") or item.get("updated_at") or utc_now_iso(),
            "created_at": item.get("created_at") or utc_now_iso(),
            "updated_at": item.get("updated_at") or utc_now_iso(),
            "recurrence_count": int(item.get("recurrence_count") or 1),
            "status": item.get("status") or "active",
            "packets": int(_feature(features, "packet_count", "packets", default=0) or 0),
            "packets_per_second": float(_feature(features, "packets_per_second", "pps", default=0) or 0),
            "bits_per_second": float(_feature(features, "bits_per_second", "bps", default=0) or 0),
            "flows": int(_feature(features, "flow_count", "flows", default=0) or 0),
            "flows_per_second": float(features.get("flows_per_second") or 0),
            "unique_sources": int(_feature(features, "unique_sources", "unique_src_ips", default=0) or 0),
            "unique_destinations": int(_feature(features, "unique_destinations", "unique_dst_ips", default=0) or 0),
            "unique_src_ports": int(features.get("unique_src_ports") or 0),
            "unique_dst_ports": int(features.get("unique_dst_ports") or 0),
            "unique_source_asns": int(_feature(features, "unique_source_asns", "unique_src_asns", default=0) or 0),
            "baseline_deviation": float(item.get("baseline_deviation") or 0),
            "input_if": int(network.get("input_if") or features.get("input_if") or 0),
            "output_if": int(network.get("output_if") or features.get("output_if") or 0),
            "sensor": network.get("sensor") or features.get("sensor") or "",
            "exporter": network.get("exporter") or features.get("exporter") or "",
            "cgnat_context": "destination_cgnat_public" if network.get("dst_is_cgnat") else "source_cgnat_public" if network.get("src_is_cgnat") else "",
            "network_context_json": json_dump(network),
            "evidence_json": json_dump({"facts": features.get("evidence") or []}),
            "score_components_json": json_dump(features.get("score_components") or {}),
            "threat_intel_json": item.get("threat_intel_json") or "{}",
            "campaign_id": item.get("campaign_id") or "",
            "mitigation_status": "not_executed",
            "decision_source": item.get("decision_source") or "GMJ_FLOW",
        }
        columns = list(payload)
        cursor = conn.execute(
            f"INSERT OR IGNORE INTO security_events ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            tuple(payload[column] for column in columns),
        )
        migrated += max(0, int(cursor.rowcount or 0))
    conn.execute(
        "INSERT INTO security_event_migrations (migration_key, applied_at) VALUES (?, ?)",
        (migration_key, utc_now_iso()),
    )
    return migrated
