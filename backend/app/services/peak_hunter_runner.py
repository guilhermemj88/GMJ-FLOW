from __future__ import annotations

import os
import sqlite3
import threading
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from app.services.clickhouse import fetch_interface_series, fetch_peak_flows, fetch_peak_hunter_interfaces
from app.services.peak_hunter import (
    PeakHunterRequest,
    analyze_peak_hunter,
    ensure_peak_analysis_db,
    metric_value_text,
    save_peak_analysis,
)


RUNNER_VERSION = "peak-hunter-runner-v1"
_RUNNER_LOCK = threading.Lock()
LOGGER = logging.getLogger("gmj-flow")
RUNNER_STATE: dict[str, Any] = {
    "scheduler_running": False,
    "last_tick_at": "",
    "last_error": "",
    "last_error_at": "",
    "last_results_count": 0,
}

SeriesFetcher = Callable[..., Any]
FlowFetcher = Callable[..., Any]
InterfaceFetcher = Callable[..., Any]


def sqlite_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(os.getenv("GMJFLOW_DB_PATH", "/app/data/gmjflow.db"))
    conn.row_factory = sqlite3.Row
    return conn


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_peak_hunter_automation_db(conn: sqlite3.Connection) -> None:
    ensure_peak_analysis_db(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS peak_hunter_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enabled INTEGER NOT NULL DEFAULT 0,
            name TEXT NOT NULL,
            sensor TEXT NOT NULL,
            interface_id INTEGER,
            direction TEXT NOT NULL DEFAULT 'both',
            metric TEXT NOT NULL DEFAULT 'packets_s',
            protocol TEXT,
            interval_minutes INTEGER NOT NULL DEFAULT 60,
            lookback_minutes INTEGER NOT NULL DEFAULT 60,
            threshold REAL,
            sensitivity TEXT NOT NULL DEFAULT 'high',
            save_negative_samples INTEGER NOT NULL DEFAULT 1,
            negative_sample_interval_runs INTEGER NOT NULL DEFAULT 6,
            min_peak_score REAL NOT NULL DEFAULT 2.0,
            min_peak_value REAL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_run_at TEXT,
            last_success_at TEXT,
            last_error_at TEXT,
            last_error TEXT NOT NULL DEFAULT '',
            runs_count INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    _ensure_peak_hunter_job_column(conn, "last_error_at", "last_error_at TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS peak_hunter_job_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            sensor TEXT NOT NULL,
            interface_id INTEGER,
            direction TEXT NOT NULL,
            metric TEXT NOT NULL,
            protocol TEXT,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            peaks_detected INTEGER NOT NULL DEFAULT 0,
            cases_saved INTEGER NOT NULL DEFAULT 0,
            negative_sample_saved INTEGER NOT NULL DEFAULT 0,
            error_message TEXT NOT NULL DEFAULT ''
        )
        """
    )
    seed_default_peak_hunter_job(conn)


def _ensure_peak_hunter_job_column(conn: sqlite3.Connection, column: str, ddl: str) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(peak_hunter_jobs)").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE peak_hunter_jobs ADD COLUMN {ddl}")


def seed_default_peak_hunter_job(conn: sqlite3.Connection) -> None:
    count = conn.execute("SELECT COUNT(*) AS count FROM peak_hunter_jobs").fetchone()["count"]
    if int(count or 0) > 0:
        return
    now = utc_now_iso()
    conn.execute(
        """
        INSERT INTO peak_hunter_jobs (
            enabled, name, sensor, interface_id, direction, metric, protocol,
            interval_minutes, lookback_minutes, threshold, sensitivity,
            save_negative_samples, negative_sample_interval_runs, min_peak_score,
            min_peak_value, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            0,
            "Default NE8000 dataset collector",
            "NE8000-BGP-FIBINET",
            None,
            "both",
            "packets_s",
            None,
            60,
            60,
            None,
            "high",
            1,
            6,
            2.0,
            None,
            now,
            now,
        ),
    )


def normalize_job_payload(data: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    base = dict(existing or {})
    base.update(data)
    direction = str(base.get("direction") or "both").strip()
    metric = str(base.get("metric") or "packets_s").strip()
    sensitivity = str(base.get("sensitivity") or "high").strip()
    if direction not in {"sends", "receives", "both"}:
        raise ValueError("direction invalida")
    if metric not in {"packets_s", "bits_s", "both"}:
        raise ValueError("metric invalida")
    if sensitivity not in {"low", "medium", "high"}:
        raise ValueError("sensitivity invalida")
    interval = max(1, int(base.get("interval_minutes") or 60))
    lookback = max(1, int(base.get("lookback_minutes") or 60))
    negative_interval = max(1, int(base.get("negative_sample_interval_runs") or 6))
    return {
        "enabled": 1 if base.get("enabled") else 0,
        "name": str(base.get("name") or "Peak Hunter automation").strip(),
        "sensor": str(base.get("sensor") or "").strip(),
        "interface_id": int(base["interface_id"]) if base.get("interface_id") not in (None, "") else None,
        "direction": direction,
        "metric": metric,
        "protocol": str(base.get("protocol") or "").strip() or None,
        "interval_minutes": interval,
        "lookback_minutes": lookback,
        "threshold": float(base["threshold"]) if base.get("threshold") not in (None, "") else None,
        "sensitivity": sensitivity,
        "save_negative_samples": 1 if base.get("save_negative_samples", True) else 0,
        "negative_sample_interval_runs": negative_interval,
        "min_peak_score": float(base.get("min_peak_score") or 0),
        "min_peak_value": float(base["min_peak_value"]) if base.get("min_peak_value") not in (None, "") else None,
    }


def row_to_job(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["enabled"] = bool(item.get("enabled"))
    item["save_negative_samples"] = bool(item.get("save_negative_samples"))
    return item


def list_peak_hunter_jobs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    ensure_peak_hunter_automation_db(conn)
    rows = conn.execute("SELECT * FROM peak_hunter_jobs ORDER BY enabled DESC, id").fetchall()
    return [row_to_job(row) for row in rows]


def get_peak_hunter_job(conn: sqlite3.Connection, job_id: int) -> dict[str, Any] | None:
    ensure_peak_hunter_automation_db(conn)
    row = conn.execute("SELECT * FROM peak_hunter_jobs WHERE id = ?", (int(job_id),)).fetchone()
    return row_to_job(row) if row else None


def create_peak_hunter_job(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
    ensure_peak_hunter_automation_db(conn)
    job = normalize_job_payload(data)
    if not job["sensor"]:
        raise ValueError("sensor obrigatorio")
    now = utc_now_iso()
    conn.execute(
        """
        INSERT INTO peak_hunter_jobs (
            enabled, name, sensor, interface_id, direction, metric, protocol,
            interval_minutes, lookback_minutes, threshold, sensitivity,
            save_negative_samples, negative_sample_interval_runs, min_peak_score,
            min_peak_value, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            job["enabled"],
            job["name"],
            job["sensor"],
            job["interface_id"],
            job["direction"],
            job["metric"],
            job["protocol"],
            job["interval_minutes"],
            job["lookback_minutes"],
            job["threshold"],
            job["sensitivity"],
            job["save_negative_samples"],
            job["negative_sample_interval_runs"],
            job["min_peak_score"],
            job["min_peak_value"],
            now,
            now,
        ),
    )
    return get_peak_hunter_job(conn, int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])) or {}


def update_peak_hunter_job(conn: sqlite3.Connection, job_id: int, data: dict[str, Any]) -> dict[str, Any]:
    current = get_peak_hunter_job(conn, job_id)
    if current is None:
        raise KeyError("job nao encontrado")
    job = normalize_job_payload(data, current)
    now = utc_now_iso()
    conn.execute(
        """
        UPDATE peak_hunter_jobs
        SET enabled = ?, name = ?, sensor = ?, interface_id = ?, direction = ?, metric = ?,
            protocol = ?, interval_minutes = ?, lookback_minutes = ?, threshold = ?,
            sensitivity = ?, save_negative_samples = ?, negative_sample_interval_runs = ?,
            min_peak_score = ?, min_peak_value = ?, updated_at = ?
        WHERE id = ?
        """,
        (
            job["enabled"],
            job["name"],
            job["sensor"],
            job["interface_id"],
            job["direction"],
            job["metric"],
            job["protocol"],
            job["interval_minutes"],
            job["lookback_minutes"],
            job["threshold"],
            job["sensitivity"],
            job["save_negative_samples"],
            job["negative_sample_interval_runs"],
            job["min_peak_score"],
            job["min_peak_value"],
            now,
            int(job_id),
        ),
    )
    return get_peak_hunter_job(conn, job_id) or {}


def delete_peak_hunter_job(conn: sqlite3.Connection, job_id: int) -> None:
    ensure_peak_hunter_automation_db(conn)
    conn.execute("DELETE FROM peak_hunter_jobs WHERE id = ?", (int(job_id),))


def list_peak_hunter_runs(conn: sqlite3.Connection, limit: int = 200) -> list[dict[str, Any]]:
    ensure_peak_hunter_automation_db(conn)
    rows = conn.execute(
        "SELECT * FROM peak_hunter_job_runs ORDER BY started_at DESC, id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    return [dict(row) for row in rows]


def mark_peak_hunter_scheduler_started() -> None:
    RUNNER_STATE["scheduler_running"] = True
    RUNNER_STATE["last_error"] = ""


def mark_peak_hunter_scheduler_stopped() -> None:
    RUNNER_STATE["scheduler_running"] = False


def peak_hunter_automation_status(conn: sqlite3.Connection, tick_seconds: int = 60) -> dict[str, Any]:
    ensure_peak_hunter_automation_db(conn)
    now = datetime.now(timezone.utc)
    jobs = [row_to_job(row) for row in conn.execute("SELECT * FROM peak_hunter_jobs ORDER BY enabled DESC, id").fetchall()]
    enabled_jobs = [job for job in jobs if job.get("enabled")]
    due_jobs = [job for job in enabled_jobs if job_is_due(job, now)]
    last_runs = list_peak_hunter_runs(conn, limit=10)
    last_error = RUNNER_STATE.get("last_error") or next((run.get("error_message") for run in last_runs if run.get("error_message")), "")
    last_tick = parse_time(RUNNER_STATE.get("last_tick_at"))
    next_tick = max(0, int(tick_seconds - (now - last_tick).total_seconds())) if last_tick else tick_seconds
    return {
        "scheduler_running": bool(RUNNER_STATE.get("scheduler_running")),
        "scheduler_status": "running" if RUNNER_STATE.get("scheduler_running") else "stopped",
        "last_tick_at": RUNNER_STATE.get("last_tick_at") or "",
        "next_tick_in_seconds": next_tick,
        "jobs_enabled": len(enabled_jobs),
        "jobs_due": len(due_jobs),
        "last_error": last_error,
        "last_runs": last_runs,
        "cases_saved": sum(int(run.get("cases_saved") or 0) for run in last_runs),
        "negative_samples_saved": sum(int(run.get("negative_sample_saved") or 0) for run in last_runs),
        "duplicates_ignored": sum(1 for run in last_runs if run.get("status") == "skipped_duplicate"),
    }


def run_due_peak_hunter_jobs(
    series_fetcher: SeriesFetcher = fetch_interface_series,
    flow_fetcher: FlowFetcher = fetch_peak_flows,
    interface_fetcher: InterfaceFetcher = fetch_peak_hunter_interfaces,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    if not _RUNNER_LOCK.acquire(blocking=False):
        return []
    try:
        now_dt = now or datetime.now(timezone.utc)
        RUNNER_STATE["last_tick_at"] = utc_iso(now_dt)
        LOGGER.info("[peak-hunter-runner] scheduler tick")
        with sqlite_connect() as conn:
            ensure_peak_hunter_automation_db(conn)
            jobs = [row_to_job(row) for row in conn.execute("SELECT * FROM peak_hunter_jobs WHERE enabled = 1").fetchall()]
            results = []
            for job in jobs:
                if not job_is_due(job, now_dt):
                    continue
                LOGGER.info("[peak-hunter-runner] job due id=%s", job.get("id"))
                results.extend(run_peak_hunter_job(conn, job, series_fetcher, flow_fetcher, interface_fetcher, now_dt))
            conn.commit()
            RUNNER_STATE["last_results_count"] = len(results)
            RUNNER_STATE["last_error"] = ""
            return results
    except Exception as exc:
        RUNNER_STATE["last_error"] = str(exc)
        RUNNER_STATE["last_error_at"] = utc_now_iso()
        LOGGER.warning("[peak-hunter-runner] run failed error=%s", exc)
        raise
    finally:
        _RUNNER_LOCK.release()


def run_peak_hunter_job_now(
    job_id: int,
    series_fetcher: SeriesFetcher = fetch_interface_series,
    flow_fetcher: FlowFetcher = fetch_peak_flows,
    interface_fetcher: InterfaceFetcher = fetch_peak_hunter_interfaces,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    with sqlite_connect() as conn:
        ensure_peak_hunter_automation_db(conn)
        job = get_peak_hunter_job(conn, job_id)
        if job is None:
            raise KeyError("job nao encontrado")
        results = run_peak_hunter_job(conn, job, series_fetcher, flow_fetcher, interface_fetcher, now or datetime.now(timezone.utc))
        conn.commit()
        return results


def job_is_due(job: dict[str, Any], now: datetime) -> bool:
    last = parse_time(job.get("last_run_at"))
    if last is None:
        return True
    return now - last >= timedelta(minutes=int(job.get("interval_minutes") or 60))


def run_peak_hunter_job(
    conn: sqlite3.Connection,
    job: dict[str, Any],
    series_fetcher: SeriesFetcher,
    flow_fetcher: FlowFetcher,
    interface_fetcher: InterfaceFetcher,
    now: datetime,
) -> list[dict[str, Any]]:
    runs = []
    run_number = int(job.get("runs_count") or 0) + 1
    interfaces = expand_job_interfaces(job, interface_fetcher)
    start = now - timedelta(minutes=int(job.get("lookback_minutes") or 60))
    directions = ["sends", "receives"] if job.get("direction") == "both" else [job.get("direction") or "sends"]
    metrics = ["packets_s", "bits_s"] if job.get("metric") == "both" else [job.get("metric") or "packets_s"]
    for interface in interfaces:
        for direction in directions:
            for metric in metrics:
                runs.append(run_job_combination(conn, job, run_number, interface, direction, metric, start, now, series_fetcher, flow_fetcher))
                run_number += 1
    last_error = next((run.get("error_message") for run in runs if run.get("error_message")), "")
    last_error_at = utc_iso(now) if last_error else None
    success = any(run.get("status") in {"success", "no_peak", "negative_sample", "skipped_duplicate"} for run in runs)
    conn.execute(
        """
        UPDATE peak_hunter_jobs
        SET runs_count = runs_count + ?,
            last_run_at = ?,
            last_success_at = CASE WHEN ? THEN ? ELSE last_success_at END,
            last_error_at = CASE WHEN ? THEN ? ELSE last_error_at END,
            last_error = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            len(runs),
            utc_iso(now),
            1 if success else 0,
            utc_iso(now),
            1 if last_error else 0,
            last_error_at,
            last_error,
            utc_now_iso(),
            int(job["id"]),
        ),
    )
    return runs


def expand_job_interfaces(job: dict[str, Any], interface_fetcher: InterfaceFetcher) -> list[dict[str, Any]]:
    if job.get("interface_id") not in (None, ""):
        return [{"interface_id": int(job["interface_id"]), "ifName": "", "ifAlias": ""}]
    rows = interface_fetcher(str(job.get("sensor") or ""))
    return [
        {"interface_id": int(row.get("interface_id") or row.get("ifIndex") or 0), "ifName": row.get("ifName") or row.get("if_name") or "", "ifAlias": row.get("ifAlias") or row.get("if_alias") or ""}
        for row in rows
        if int(row.get("interface_id") or row.get("ifIndex") or 0) > 0
    ]


def run_job_combination(
    conn: sqlite3.Connection,
    job: dict[str, Any],
    run_number: int,
    interface: dict[str, Any],
    direction: str,
    metric: str,
    start: datetime,
    end: datetime,
    series_fetcher: SeriesFetcher,
    flow_fetcher: FlowFetcher,
) -> dict[str, Any]:
    run_id = create_run(conn, job, interface, direction, metric, start, end)
    LOGGER.info("[peak-hunter-runner] run started job_id=%s run_id=%s", job.get("id"), run_id)
    cases_saved = 0
    negative_saved = 0
    status = "success"
    error_message = ""
    peaks_detected = 0
    try:
        request = PeakHunterRequest(
            sensor=str(job.get("sensor") or ""),
            interface_id=int(interface["interface_id"]),
            direction=direction,
            metric=metric,
            start_time=start,
            end_time=end,
            protocol=job.get("protocol") or None,
            threshold=job.get("threshold"),
            sensitivity=job.get("sensitivity") or "high",
        )
        result = analyze_peak_hunter(request, series_fetcher, flow_fetcher)
        peaks_detected = int(result.get("peaks_detected") or 0)
        relevant = result_has_relevant_peak(result, job)
        if relevant:
            duplicate_id = duplicate_peak_analysis_id(conn, request, result)
            if duplicate_id:
                status = "skipped_duplicate"
            else:
                save_automatic_result(conn, job, run_id, request, result, interface, False)
                cases_saved = 1
        elif should_save_negative_sample(job, run_number):
            negative_result = negative_sample_result(request, result)
            save_automatic_result(conn, job, run_id, request, negative_result, interface, True)
            cases_saved = 1
            negative_saved = 1
            status = "negative_sample"
        else:
            status = "no_peak"
    except Exception as exc:
        status = "error"
        error_message = str(exc)
        LOGGER.warning("[peak-hunter-runner] run failed error=%s", exc)
    finish_run(conn, run_id, status, peaks_detected, cases_saved, negative_saved, error_message)
    LOGGER.info("[peak-hunter-runner] cases_saved=%s negative_sample_saved=%s skipped_duplicate=%s", cases_saved, negative_saved, 1 if status == "skipped_duplicate" else 0)
    return dict(conn.execute("SELECT * FROM peak_hunter_job_runs WHERE id = ?", (run_id,)).fetchone())


def create_run(conn: sqlite3.Connection, job: dict[str, Any], interface: dict[str, Any], direction: str, metric: str, start: datetime, end: datetime) -> int:
    conn.execute(
        """
        INSERT INTO peak_hunter_job_runs (
            job_id, started_at, status, sensor, interface_id, direction, metric, protocol, start_time, end_time
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (job.get("id"), utc_now_iso(), "running", job.get("sensor"), interface.get("interface_id"), direction, metric, job.get("protocol"), utc_iso(start), utc_iso(end)),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def finish_run(conn: sqlite3.Connection, run_id: int, status: str, peaks_detected: int, cases_saved: int, negative_saved: int, error_message: str) -> None:
    conn.execute(
        """
        UPDATE peak_hunter_job_runs
        SET finished_at = ?, status = ?, peaks_detected = ?, cases_saved = ?,
            negative_sample_saved = ?, error_message = ?
        WHERE id = ?
        """,
        (utc_now_iso(), status, int(peaks_detected), int(cases_saved), int(negative_saved), error_message, int(run_id)),
    )


def result_has_relevant_peak(result: dict[str, Any], job: dict[str, Any]) -> bool:
    best = result.get("best_peak") or {}
    if not best:
        return False
    if float(best.get("score") or 0) < float(job.get("min_peak_score") or 0):
        return False
    min_value = job.get("min_peak_value")
    if min_value not in (None, "") and float(best.get("peak_value") or 0) < float(min_value):
        return False
    return True


def duplicate_peak_analysis_id(conn: sqlite3.Connection, request: PeakHunterRequest, result: dict[str, Any]) -> int | None:
    best = result.get("best_peak") or {}
    peak_time = parse_time(best.get("peak_time_utc") or best.get("peak_time") or best.get("time"))
    if peak_time is None:
        return None
    start = utc_iso(peak_time - timedelta(minutes=5))
    end = utc_iso(peak_time + timedelta(minutes=5))
    row = conn.execute(
        """
        SELECT id
        FROM peak_analysis
        WHERE sensor = ?
          AND interface_id = ?
          AND direction = ?
          AND metric = ?
          AND classification = ?
          AND peak_time_utc >= ?
          AND peak_time_utc <= ?
        ORDER BY id
        LIMIT 1
        """,
        (request.sensor, request.interface_id, request.direction, request.metric, result.get("classification") or "", start, end),
    ).fetchone()
    return int(row["id"]) if row else None


def save_automatic_result(conn: sqlite3.Connection, job: dict[str, Any], run_id: int, request: PeakHunterRequest, result: dict[str, Any], interface: dict[str, Any], negative: bool) -> None:
    best = result.get("best_peak") or {}
    baseline = result.get("baseline") or {}
    dominant = result.get("dominant_group") or best.get("dominant_group") or {}
    candidates = result.get("candidates") or best.get("candidates") or []
    record = {
        "peak_time": best.get("peak_time_utc") or result.get("end_time") or utc_now_iso(),
        "peak_time_utc": best.get("peak_time_utc") or result.get("end_time") or utc_now_iso(),
        "peak_time_local": best.get("peak_time_local") or "",
        "timezone": "America/Sao_Paulo",
        "interface_id": request.interface_id,
        "interface_name": interface.get("ifName") or "",
        "interface_alias": interface.get("ifAlias") or "",
        "sensor": request.sensor,
        "direction": request.direction,
        "metric": request.metric,
        "protocol": request.protocol or "",
        "peak_value": best.get("peak_value") or 0,
        "baseline_p95": baseline.get("p95") or 0,
        "baseline_p99": baseline.get("p99") or 0,
        "threshold_used": result.get("threshold_used") or 0,
        "score": best.get("score") or 0,
        "evidence_status": result.get("evidence_status") or best.get("evidence_status") or "",
        "classification": result.get("classification") or best.get("classification") or "",
        "mitigation_allowed": bool(result.get("mitigation_allowed")),
        "recommended_action": (result.get("recommendation") or {}).get("recommended_action") or "alert_only",
        "dominant_dst_ip": dominant.get("dst_ip") or "",
        "dominant_dst_port": dominant.get("dst_port"),
        "dominant_protocol": dominant.get("protocol") or "",
        "dominant_unique_src_count": dominant.get("unique_src_count") or len(dominant.get("unique_src_ips") or []),
        "dominant_share_packets": dominant.get("share_packets") or 0,
        "dominant_share_bits": dominant.get("share_bits") or 0,
        "dominant_group": dominant,
        "candidates": candidates,
        "candidates_json": candidates,
        "request_json": {
            "sensor": request.sensor,
            "interface_id": request.interface_id,
            "direction": request.direction,
            "metric": request.metric,
            "start_time": utc_iso(request.start_time),
            "end_time": utc_iso(request.end_time),
            "protocol": request.protocol or "",
            "sensitivity": request.sensitivity,
        },
        "result_json": result,
        "technical_report": result.get("technical_report") or "",
        "analysis_source": "automatic",
        "job_id": job.get("id"),
        "run_id": run_id,
        "is_negative_sample": negative,
        "auto_runner_version": RUNNER_VERSION,
        "monitored_interface_name": interface.get("ifName") or "",
        "monitored_interface_alias": interface.get("ifAlias") or "",
        "lookback_minutes": job.get("lookback_minutes"),
        "interval_minutes": job.get("interval_minutes"),
        "created_at": utc_now_iso(),
    }
    save_peak_analysis(conn, record)


def should_save_negative_sample(job: dict[str, Any], run_number: int) -> bool:
    return bool(job.get("save_negative_samples")) and run_number % int(job.get("negative_sample_interval_runs") or 1) == 0


def negative_sample_result(request: PeakHunterRequest, result: dict[str, Any]) -> dict[str, Any]:
    technical_report = "\n".join(
        [
            "Peak Hunter - relatorio tecnico",
            "",
            f"Nao houve pico relevante na janela analisada para sensor {request.sensor}, interface {request.interface_id}, direcao {request.direction}, metrica {request.metric}.",
            f"Janela UTC: {utc_iso(request.start_time)} ate {utc_iso(request.end_time)}.",
            "classification=no_significant_peak, evidence_status=no_peak, recommended_action=alert_only.",
            "Nenhuma mitigacao automatica foi aplicada. apply_enabled=false.",
        ]
    )
    return {
        **result,
        "classification": "no_significant_peak",
        "evidence_status": "no_peak",
        "mitigation_allowed": False,
        "candidates": [],
        "recommendation": {"recommended_action": "alert_only", "reason": "Nenhum pico relevante na janela."},
        "best_peak": {
            "peak_time_utc": utc_iso(request.end_time),
            "peak_time_local": "",
            "peak_value": 0,
            "score": 0,
            "apply_enabled": False,
        },
        "technical_report": technical_report,
    }


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
