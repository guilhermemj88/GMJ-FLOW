from __future__ import annotations

"""Minimal persistence for Peak Hunter events.

One lightweight row per detected peak (NOT the legacy peak_analysis rows,
which carry full result payloads and legacy mitigation fields). The peak
event stores only the facts the operator and downstream handoff need.

Retention is simple and deterministic: on ensure, rows older than
``GMJFLOW_PEAK_EVENTS_RETENTION_DAYS`` (default 30) are pruned.
"""

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

DEFAULT_RETENTION_DAYS = 30


def _retention_days() -> int:
    try:
        return max(1, int(os.getenv("GMJFLOW_PEAK_EVENTS_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS))))
    except ValueError:
        return DEFAULT_RETENTION_DAYS


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_peak_events_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS peak_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at TEXT NOT NULL,
            peak_time TEXT NOT NULL,
            sensor TEXT NOT NULL DEFAULT '',
            interface_id INTEGER,
            direction TEXT NOT NULL DEFAULT 'total',
            trigger TEXT NOT NULL DEFAULT '',
            baseline_bps REAL NOT NULL DEFAULT 0,
            peak_bps REAL NOT NULL DEFAULT 0,
            baseline_pps REAL NOT NULL DEFAULT 0,
            peak_pps REAL NOT NULL DEFAULT 0,
            delta_bps REAL NOT NULL DEFAULT 0,
            delta_pps REAL NOT NULL DEFAULT 0,
            evidence_json TEXT NOT NULL DEFAULT '{}',
            threat_verdict TEXT NOT NULL DEFAULT '',
            threat_reasons TEXT NOT NULL DEFAULT '[]',
            anomaly_id INTEGER,
            security_event_id INTEGER,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_peak_events_dedup ON peak_events (sensor, interface_id, direction, peak_time)"
    )
    # simple retention prune
    cutoff = (datetime.now(timezone.utc) - timedelta(days=_retention_days())).isoformat().replace("+00:00", "Z")
    conn.execute("DELETE FROM peak_events WHERE created_at < ?", (cutoff,))


def save_peak_event(conn: sqlite3.Connection, record: dict[str, Any]) -> int:
    ensure_peak_events_db(conn)
    evidence = record.get("evidence_json") or {}
    if not isinstance(evidence, str):
        evidence = json.dumps(evidence, sort_keys=True, default=str)
    reasons = record.get("threat_reasons") or []
    if not isinstance(reasons, str):
        reasons = json.dumps(reasons, sort_keys=True)
    cursor = conn.execute(
        """
        INSERT INTO peak_events (
            detected_at, peak_time, sensor, interface_id, direction, trigger,
            baseline_bps, peak_bps, baseline_pps, peak_pps, delta_bps, delta_pps,
            evidence_json, threat_verdict, threat_reasons, anomaly_id,
            security_event_id, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record.get("detected_at") or utc_now_iso(),
            record.get("peak_time") or "",
            record.get("sensor") or "",
            record.get("interface_id"),
            record.get("direction") or "total",
            record.get("trigger") or "",
            float(record.get("baseline_bps") or 0),
            float(record.get("peak_bps") or 0),
            float(record.get("baseline_pps") or 0),
            float(record.get("peak_pps") or 0),
            float(record.get("delta_bps") or 0),
            float(record.get("delta_pps") or 0),
            evidence,
            record.get("threat_verdict") or "",
            reasons,
            record.get("anomaly_id"),
            record.get("security_event_id"),
            record.get("created_at") or utc_now_iso(),
        ),
    )
    return int(cursor.lastrowid)


def peak_event_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["evidence_json"] = _json_value(item.get("evidence_json"), {})
    item["threat_reasons"] = _json_value(item.get("threat_reasons"), [])
    return item


def _json_value(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def list_peak_events(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    ensure_peak_events_db(conn)
    rows = conn.execute(
        "SELECT * FROM peak_events ORDER BY peak_time DESC, id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    return [peak_event_row_to_dict(row) for row in rows]


def get_peak_event(conn: sqlite3.Connection, event_id: int) -> dict[str, Any] | None:
    ensure_peak_events_db(conn)
    row = conn.execute("SELECT * FROM peak_events WHERE id = ?", (int(event_id),)).fetchone()
    return peak_event_row_to_dict(row) if row else None


def find_existing_peak_event(
    conn: sqlite3.Connection,
    sensor: str,
    interface_id: int,
    direction: str,
    peak_time: datetime,
    tolerance_seconds: int = 300,
) -> int | None:
    """Deduplicate across cycles: return the id of an already-persisted event
    for the same scope/direction whose peak_time is within tolerance."""
    ensure_peak_events_db(conn)
    peak = peak_time.astimezone(timezone.utc)
    start = (peak - timedelta(seconds=tolerance_seconds)).isoformat().replace("+00:00", "Z")
    end = (peak + timedelta(seconds=tolerance_seconds)).isoformat().replace("+00:00", "Z")
    row = conn.execute(
        """
        SELECT id FROM peak_events
        WHERE sensor = ? AND interface_id = ? AND direction = ?
          AND peak_time >= ? AND peak_time <= ?
        ORDER BY id
        LIMIT 1
        """,
        (sensor, int(interface_id), direction, start, end),
    ).fetchone()
    return int(row["id"]) if row else None


def link_peak_event(conn: sqlite3.Connection, event_id: int, anomaly_id: int | None = None, security_event_id: int | None = None) -> None:
    ensure_peak_events_db(conn)
    conn.execute(
        "UPDATE peak_events SET anomaly_id = ?, security_event_id = ? WHERE id = ?",
        (anomaly_id, security_event_id, int(event_id)),
    )
