from __future__ import annotations

"""Automatic Peak Hunter cycle (refactored pipeline).

Detect -> evidence -> threat triage -> handoff, with cross-cycle dedup via
peak_events. This module is intentionally SELF-CONTAINED: it does not import
the legacy peak_hunter_runner (jobs/dataset/negative samples), so importing it
from main never drags the legacy chain in.

All heavy dependencies (clickhouse, peak_analysis, peak_events) are imported
lazily inside the function so module import stays side-effect free.
"""

import os
import sqlite3
import threading
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

LOGGER = logging.getLogger("gmj-flow")

_CYCLE_LOCK = threading.Lock()

RUNNER_STATE: dict[str, Any] = {
    "scheduler_running": False,
    "last_tick_at": "",
    "last_error": "",
    "last_error_at": "",
    "last_results_count": 0,
}


def sqlite_connect() -> sqlite3.Connection:
    from app.services.sqlite_managed import open_managed

    conn = open_managed(os.getenv("GMJFLOW_DB_PATH", "/app/data/gmjflow.db"))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def default_scopes(conn: sqlite3.Connection) -> list[tuple[str, int, str]]:
    """Active sensors + interfaces, both directions. Bounded (SQLite only)."""
    rows = conn.execute(
        """
        SELECT s.name, si.if_index
        FROM sensors s
        JOIN sensor_interfaces si ON si.sensor_id = s.id
        WHERE s.active = 1 AND si.if_index > 0
        ORDER BY s.name, si.if_index
        """
    ).fetchall()
    scopes: list[tuple[str, int, str]] = []
    for row in rows:
        name = str(row["name"])
        if_index = int(row["if_index"])
        scopes.append((name, if_index, "receives"))
        scopes.append((name, if_index, "sends"))
    return scopes


def peak_event_record(sensor: str, interface_id: int, direction: str, entry: dict[str, Any]) -> dict[str, Any]:
    peak = entry.get("peak") or {}
    evidence = entry.get("evidence") or {}
    threat = entry.get("threat") or {}
    deltas = evidence.get("deltas") or {}
    return {
        "detected_at": utc_now_iso(),
        "peak_time": peak.get("peak_time") or "",
        "sensor": sensor,
        "interface_id": interface_id,
        "direction": direction,
        "trigger": peak.get("metric") or "",
        "baseline_bps": float(deltas.get("bps") or 0),
        "peak_bps": float(deltas.get("bps_peak") or 0),
        "baseline_pps": float(deltas.get("pps") or 0),
        "peak_pps": float(deltas.get("pps_peak") or 0),
        "delta_bps": float(deltas.get("bps_delta_pct") or 0),
        "delta_pps": float(deltas.get("pps_delta_pct") or 0),
        "evidence_json": evidence,
        "threat_verdict": threat.get("verdict") or "",
        "threat_reasons": threat.get("reasons") or [],
    }


def run_peak_hunter_cycle(
    now: datetime | None = None,
    series_fetcher: Any = None,
    evidence_executor: Any = None,
    hotset: Any = None,
    save_event: Any = None,
    handoff: Any = None,
    list_scopes: Any = None,
    conn_factory: Any = None,
    find_existing: Any = None,
    lookback_seconds: int = 900,
    detection_config: Any = None,
) -> list[dict[str, Any]]:
    """One automatic cycle over the new pipeline.

    Never overlaps (non-blocking lock), never touches flow_raw, never creates
    mitigation/dataset/drafts. Deduplicates across cycles via peak_events.
    """
    if not _CYCLE_LOCK.acquire(blocking=False):
        return []
    try:
        from app.services.peak_analysis import analyze_peak_scope
        from app.services.peak_detection import PeakDetectionConfig
        from app.services.peak_events import find_existing_peak_event, save_peak_event
        from app.services.peak_handoff import handoff_peak_event

        if series_fetcher is None:
            from app.services.peak_series import fetch_interface_aggregate_series
            series_fetcher = fetch_interface_aggregate_series
        if evidence_executor is None:
            from app.services.clickhouse import query_clickhouse
            evidence_executor = query_clickhouse
        save_event = save_event or save_peak_event
        handoff = handoff if handoff is not None else handoff_peak_event
        detection_config = detection_config or PeakDetectionConfig()
        now_dt = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        RUNNER_STATE["last_tick_at"] = utc_iso(now_dt)
        start = now_dt - timedelta(seconds=lookback_seconds)
        created: list[dict[str, Any]] = []
        with (conn_factory or sqlite_connect)() as conn:
            scopes = list_scopes(conn) if list_scopes is not None else default_scopes(conn)
            for sensor, interface_id, direction in scopes:
                try:
                    result = analyze_peak_scope(
                        sensor,
                        interface_id,
                        direction,
                        lambda s, i, d: series_fetcher(s, i, d, start, now_dt),
                        lambda s, i, d: series_fetcher(s, i, d, start, now_dt),
                        evidence_executor,
                        hotset,
                        detection_config=detection_config,
                    )
                except Exception as exc:
                    LOGGER.warning("[peak-hunter-runner] scope failed sensor=%s if=%s dir=%s error=%s", sensor, interface_id, direction, exc)
                    continue
                for entry in result.get("peaks") or []:
                    peak_time = _parse_iso((entry.get("peak") or {}).get("peak_time"))
                    if peak_time is None:
                        continue
                    if (find_existing or find_existing_peak_event)(conn, sensor, interface_id, direction, peak_time) is not None:
                        continue
                    record = peak_event_record(sensor, interface_id, direction, entry)
                    event_id = save_event(conn, record)
                    threat = entry.get("threat") or {}
                    if threat.get("handoff_recommended"):
                        handoff(conn, event_id, entry)
                    created.append({"event_id": event_id, "sensor": sensor, "interface_id": interface_id, "direction": direction})
            conn.commit()
        RUNNER_STATE["last_results_count"] = len(created)
        RUNNER_STATE["last_error"] = ""
        return created
    except Exception as exc:
        RUNNER_STATE["last_error"] = str(exc)
        RUNNER_STATE["last_error_at"] = utc_now_iso()
        LOGGER.warning("[peak-hunter-runner] cycle failed error=%s", exc)
        return []
    finally:
        _CYCLE_LOCK.release()
