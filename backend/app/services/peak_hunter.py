from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

from app.services.mitigation_candidates import generate_mitigation_candidates
from app.services.mitigation_playbook import load_playbook
from app.services.mitigation_validator import validate_mitigation_decision
from app.services.peak_flow_enrichment import enrich_peak_flows


FlowFetcher = Callable[["PeakHunterRequest", datetime, int], List[Dict[str, Any]]]
SeriesFetcher = Callable[["PeakHunterRequest"], List[Dict[str, Any]]]
MAX_RESPONSE_SERIES_POINTS = 1000


@dataclass
class PeakHunterRequest:
    sensor: str
    interface_id: int
    direction: str
    metric: str
    start_time: datetime
    end_time: datetime
    protocol: str | None = None
    threshold: float | None = None
    baseline: float | dict[str, Any] | None = None
    window_seconds: int = 5
    max_peaks: int = 5
    sensitivity: str = "medium"


def analyze_peak_hunter(
    request: PeakHunterRequest,
    series_fetcher: SeriesFetcher,
    flow_fetcher: FlowFetcher,
    save_history: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    series = normalize_series(series_fetcher(request), request.metric)
    response_series = downsample_series(series, MAX_RESPONSE_SERIES_POINTS)
    baseline = calculate_baseline(series, request.metric, request.baseline)
    threshold = effective_threshold(baseline, request.threshold, request.sensitivity)
    peaks = detect_local_peaks(series, request.metric, baseline, threshold, request.max_peaks)
    analyzed = []
    for peak in peaks:
        analyzed.append(_analyze_peak(request, peak, baseline, threshold, flow_fetcher))
    best = select_best_peak(analyzed)
    if save_history and best:
        save_history(history_record(request, best, baseline))
    recommendation = recommendation_for_peak(best)
    return {
        "peaks_detected": len(peaks),
        "peaks_analyzed": len(analyzed),
        "peaks": analyzed,
        "series": response_series,
        "series_points": len(series),
        "series_returned_points": len(response_series),
        "series_downsampled": len(response_series) < len(series),
        "baseline": baseline,
        "threshold_used": threshold,
        "sensitivity": normalize_sensitivity(request.sensitivity),
        "best_peak": best,
        "evidence_window_used": best.get("evidence_window_used") if best else None,
        "evidence_windows_tried": best.get("evidence_windows_tried") if best else [],
        "evidence_status": best.get("evidence_status") if best else "insufficient",
        "dominant_group": best.get("dominant_group") if best else None,
        "classification": best.get("classification") if best else "insufficient_flow_evidence",
        "top_groups": best.get("groups") if best else [],
        "top_conversations": best.get("top_conversations") if best else [],
        "top_sources": best.get("top_sources") if best else [],
        "top_destinations": best.get("top_destinations") if best else [],
        "candidates": best.get("candidates") if best else [],
        "mitigation_allowed": bool(best and best.get("mitigation_allowed")),
        "recommendation": recommendation,
    }


def _analyze_peak(
    request: PeakHunterRequest,
    peak: dict[str, Any],
    baseline: dict[str, float],
    threshold: float,
    flow_fetcher: FlowFetcher,
) -> dict[str, Any]:
    peak_time = parse_time(peak["time"])
    peak_time_utc = _format_time_utc_z(peak_time)
    peak_time_local = _format_time_local(peak_time)
    tried = []
    best_enrichment: dict[str, Any] | None = None
    selected_window = None
    for window in (5, 15, 30, 60):
        flows = flow_fetcher(request, peak_time, window)
        enrichment = enrich_peak_flows(flows, request.metric, max(window * 2, 1), request.direction)
        tried.append({"window_seconds": window, "flow_count": len(flows), "evidence_status": enrichment["evidence_status"]})
        if best_enrichment is None or _enrichment_rank(enrichment, request.metric) > _enrichment_rank(best_enrichment, request.metric):
            best_enrichment = enrichment
            selected_window = window
        if enrichment["evidence_status"] == "complete":
            best_enrichment = enrichment
            selected_window = window
            break
    best_enrichment = best_enrichment or {"evidence_status": "insufficient", "classification": "insufficient_flow_evidence", "dominant_group": None}
    candidates, mitigation_allowed = candidates_for_enrichment(request, best_enrichment)
    return {
        **peak,
        "peak_time_utc": peak_time_utc,
        "peak_time_local": peak_time_local,
        "timezone": "America/Sao_Paulo",
        "baseline_p95": baseline["p95"],
        "baseline_p99": baseline["p99"],
        "threshold_used": threshold,
        "evidence_status": best_enrichment["evidence_status"],
        "evidence_window_used": selected_window,
        "evidence_windows_tried": tried,
        "dominant_group": best_enrichment.get("dominant_group"),
        "classification": best_enrichment.get("classification") or "insufficient_flow_evidence",
        "groups": best_enrichment.get("groups") or [],
        "top_conversations": best_enrichment.get("top_conversations") or [],
        "top_sources": best_enrichment.get("top_sources") or [],
        "top_destinations": best_enrichment.get("top_destinations") or [],
        "candidates": candidates,
        "mitigation_allowed": mitigation_allowed,
        "apply_enabled": False,
    }


def normalize_series(rows: list[dict[str, Any]], metric: str) -> list[dict[str, Any]]:
    series = []
    for row in rows:
        value = float(row.get(metric) or row.get("value") or 0)
        time_value = row.get("time") or row.get("bucket") or row.get("ts")
        point = {"time": _string_time(time_value), metric: value, "value": value}
        for field in ("raw_packets", "raw_bytes", "db_sample_rate", "effective_sample_rate", "sample_rate_source"):
            if field in row:
                point[field] = row.get(field)
        series.append(point)
    return sorted(series, key=lambda item: item["time"])


def downsample_series(series: list[dict[str, Any]], max_points: int = MAX_RESPONSE_SERIES_POINTS) -> list[dict[str, Any]]:
    limit = max(int(max_points or MAX_RESPONSE_SERIES_POINTS), 1)
    if len(series) <= limit:
        return series
    if limit == 1:
        return [max(series, key=lambda item: float(item.get("value") or 0))]
    step = (len(series) - 1) / float(limit - 1)
    selected = []
    seen = set()
    for index in range(limit):
        source_index = round(index * step)
        if source_index in seen:
            continue
        seen.add(source_index)
        selected.append(series[source_index])
    peak = max(series, key=lambda item: float(item.get("value") or 0))
    if peak not in selected:
        selected[-1] = peak
        selected.sort(key=lambda item: item["time"])
    return selected


def calculate_baseline(series: list[dict[str, Any]], metric: str, baseline: float | dict[str, Any] | None = None) -> dict[str, float]:
    if isinstance(baseline, dict):
        p95 = float(baseline.get("p95") or baseline.get("baseline_p95") or 0)
        p99 = float(baseline.get("p99") or baseline.get("baseline_p99") or p95)
        return {"p95": p95, "p99": p99}
    if isinstance(baseline, (int, float)):
        return {"p95": float(baseline), "p99": float(baseline)}
    values = [float(point.get(metric) or point.get("value") or 0) for point in series]
    if not values:
        return {"p95": 0.0, "p99": 0.0}
    if len(values) < 3:
        maximum = max(values)
        return {"p95": maximum, "p99": maximum}
    ordered = sorted(values)
    return {"p95": percentile(ordered, 95), "p99": percentile(ordered, 99)}


def normalize_sensitivity(value: str | None) -> str:
    text = str(value or "medium").strip().lower()
    aliases = {
        "alta": "high",
        "high": "high",
        "media": "medium",
        "média": "medium",
        "medium": "medium",
        "baixa": "low",
        "low": "low",
    }
    return aliases.get(text, "medium")


def sensitivity_factor(value: str | None) -> float:
    return {"high": 1.5, "medium": 2.0, "low": 3.0}[normalize_sensitivity(value)]


def effective_threshold(baseline: dict[str, float], threshold: float | None, sensitivity: str | None = None) -> float:
    if threshold and float(threshold) > 0:
        return float(threshold)
    p95 = float(baseline.get("p95") or 0)
    p99 = float(baseline.get("p99") or 0)
    return max(p99, p95 * sensitivity_factor(sensitivity))


def detect_local_peaks(
    series: list[dict[str, Any]],
    metric: str,
    baseline: dict[str, float],
    threshold: float | None,
    max_peaks: int,
) -> list[dict[str, Any]]:
    peaks = []
    floor = float(threshold or 0)
    for index, point in enumerate(series):
        value = float(point.get(metric) or point.get("value") or 0)
        previous_value = float(series[index - 1].get(metric) or series[index - 1].get("value") or 0) if index > 0 else -1
        next_value = float(series[index + 1].get(metric) or series[index + 1].get("value") or 0) if index < len(series) - 1 else -1
        if value >= floor and value >= previous_value and value >= next_value:
            p95 = float(baseline.get("p95") or 0)
            score = value / p95 if p95 > 0 else value
            peak = {"peak_time": point["time"], "time": point["time"], "peak_value": value, "score": round(score, 3)}
            for field in ("raw_packets", "raw_bytes", "db_sample_rate", "effective_sample_rate", "sample_rate_source"):
                if field in point:
                    peak[field] = point.get(field)
            peaks.append(peak)
    peaks.sort(key=lambda item: (float(item["score"]), float(item["peak_value"])), reverse=True)
    return peaks[: max(int(max_peaks or 1), 1)]


def candidates_for_enrichment(request: PeakHunterRequest, enrichment: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    if enrichment.get("evidence_status") != "complete" or not enrichment.get("dominant_group"):
        return [], False
    dominant = enrichment["dominant_group"]
    incident = {
        "incident_id": f"peak-{request.interface_id}-{dominant.get('dst_ip')}",
        "suspected_template": _template_for_classification(enrichment.get("classification")),
        "direction": request.direction,
        "src_is_customer": True,
        "src_is_internal": True,
        "dst_is_customer": False,
        "dst_is_external": True,
        "protocol": dominant.get("protocol"),
        "dst_ip": dominant.get("dst_ip"),
        "dst_port": dominant.get("dst_port"),
        "dst_prefix": _ipv4_24(dominant.get("dst_ip")),
        "same_dst_24": True,
        "dominant_attack_group": {
            "dst_ip": dominant.get("dst_ip"),
            "dst_port": dominant.get("dst_port"),
            "protocol": dominant.get("protocol"),
            "total_packets": dominant.get("total_packets"),
            "total_bytes": dominant.get("total_bytes"),
            "unique_src_ips": dominant.get("unique_src_ips") or [],
        },
        "packets": dominant.get("total_packets"),
        "bytes": dominant.get("total_bytes"),
    }
    playbook = load_playbook()
    suspected_template, candidates = generate_mitigation_candidates(incident, playbook)
    for candidate in candidates:
        candidate["apply_enabled"] = False
    selected = next((candidate for candidate in candidates if candidate.get("action") != "alert_only"), None)
    if selected is None:
        return candidates, False
    validation = validate_mitigation_decision(
        {
            "recommended_candidate_index": selected.get("candidate_index", 0),
            "allow_auto": 0,
            "manual_approval_required": 1,
            "recommended_ttl": selected.get("ttl") or "2h",
        },
        candidates,
        incident,
        playbook,
        suspected_template,
    )
    return candidates, bool(validation.get("valid"))


def ensure_peak_analysis_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS peak_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peak_time TEXT,
            interface_id INTEGER,
            sensor TEXT,
            direction TEXT,
            metric TEXT,
            peak_value REAL,
            baseline_p95 REAL,
            baseline_p99 REAL,
            score REAL,
            evidence_status TEXT,
            classification TEXT,
            dominant_group TEXT,
            candidates TEXT,
            ai_summary TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    _ensure_peak_analysis_column(conn, "peak_time", "peak_time TEXT")
    _ensure_peak_analysis_column(conn, "interface_id", "interface_id INTEGER")
    _ensure_peak_analysis_column(conn, "sensor", "sensor TEXT")
    _ensure_peak_analysis_column(conn, "direction", "direction TEXT")
    _ensure_peak_analysis_column(conn, "metric", "metric TEXT")
    _ensure_peak_analysis_column(conn, "peak_value", "peak_value REAL")
    _ensure_peak_analysis_column(conn, "baseline_p95", "baseline_p95 REAL")
    _ensure_peak_analysis_column(conn, "baseline_p99", "baseline_p99 REAL")
    _ensure_peak_analysis_column(conn, "score", "score REAL")
    _ensure_peak_analysis_column(conn, "evidence_status", "evidence_status TEXT")
    _ensure_peak_analysis_column(conn, "classification", "classification TEXT")
    _ensure_peak_analysis_column(conn, "dominant_group", "dominant_group TEXT")
    _ensure_peak_analysis_column(conn, "candidates", "candidates TEXT")
    _ensure_peak_analysis_column(conn, "ai_summary", "ai_summary TEXT")
    _ensure_peak_analysis_column(conn, "created_at", "created_at TEXT")
    _copy_legacy_json_column(conn, "dominant_group_json", "dominant_group", "{}")
    _copy_legacy_json_column(conn, "candidates_json", "candidates", "[]")


def _peak_analysis_columns(conn: sqlite3.Connection) -> set[str]:
    return {str(row[1]) for row in conn.execute("PRAGMA table_info(peak_analysis)").fetchall()}


def _ensure_peak_analysis_column(conn: sqlite3.Connection, column: str, definition: str) -> None:
    if column not in _peak_analysis_columns(conn):
        conn.execute(f"ALTER TABLE peak_analysis ADD COLUMN {definition}")


def _copy_legacy_json_column(conn: sqlite3.Connection, legacy_column: str, new_column: str, empty_value: str) -> None:
    columns = _peak_analysis_columns(conn)
    if legacy_column not in columns or new_column not in columns:
        return
    conn.execute(
        f"""
        UPDATE peak_analysis
        SET {new_column} = {legacy_column}
        WHERE {legacy_column} IS NOT NULL
          AND COALESCE({new_column}, '') IN ('', ?)
        """,
        (empty_value,),
    )


def save_peak_analysis(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
    ensure_peak_analysis_db(conn)
    conn.execute(
        """
        INSERT INTO peak_analysis (
            peak_time, interface_id, sensor, direction, metric, peak_value,
            baseline_p95, baseline_p99, score, evidence_status, classification,
            dominant_group, candidates, ai_summary, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["peak_time"],
            record["interface_id"],
            record["sensor"],
            record["direction"],
            record["metric"],
            record["peak_value"],
            record["baseline_p95"],
            record["baseline_p99"],
            record["score"],
            record["evidence_status"],
            record["classification"],
            json.dumps(record.get("dominant_group") or {}, sort_keys=True),
            json.dumps(record.get("candidates") or [], sort_keys=True, default=str),
            record.get("ai_summary") or "",
            record["created_at"],
        ),
    )


def list_peak_analysis_history(
    conn: sqlite3.Connection,
    filters: dict[str, Any] | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    ensure_peak_analysis_db(conn)
    filters = filters or {}
    where = []
    values: list[Any] = []
    for column in ("sensor", "direction", "metric", "evidence_status", "classification"):
        value = str(filters.get(column) or "").strip()
        if value:
            where.append(f"{column} = ?")
            values.append(value)
    if filters.get("interface_id") not in (None, ""):
        where.append("interface_id = ?")
        values.append(int(filters["interface_id"]))
    if filters.get("start_time"):
        where.append("peak_time >= ?")
        values.append(str(filters["start_time"]))
    if filters.get("end_time"):
        where.append("peak_time <= ?")
        values.append(str(filters["end_time"]))
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    rows = conn.execute(
        f"""
        SELECT *
        FROM peak_analysis
        {where_sql}
        ORDER BY peak_time DESC, created_at DESC
        LIMIT ?
        """,
        (*values, int(limit)),
    ).fetchall()
    return [peak_analysis_row_to_dict(row) for row in rows]


def peak_analysis_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    dominant_group = _json_value(item.get("dominant_group"), {})
    candidates = _json_value(item.get("candidates"), [])
    recommendation = recommendation_for_history(item, candidates)
    peak_time = parse_optional_time(item.get("peak_time"))
    peak_time_utc = _format_time_utc_z(peak_time) if peak_time else item.get("peak_time")
    peak_time_local = _format_time_local(peak_time) if peak_time else ""
    return {
        "id": item.get("id"),
        "peak_time": item.get("peak_time"),
        "peak_time_utc": peak_time_utc,
        "peak_time_local": peak_time_local,
        "timezone": "America/Sao_Paulo",
        "sensor": item.get("sensor") or "",
        "interface_id": item.get("interface_id"),
        "direction": item.get("direction") or "",
        "metric": item.get("metric") or "",
        "peak_value": float(item.get("peak_value") or 0),
        "baseline_p95": float(item.get("baseline_p95") or 0),
        "baseline_p99": float(item.get("baseline_p99") or 0),
        "score": float(item.get("score") or 0),
        "evidence_status": item.get("evidence_status") or "",
        "classification": item.get("classification") or "",
        "dominant_group": dominant_group,
        "dominant_group_label": dominant_group_label(dominant_group),
        "candidates": candidates,
        "recommended_action": recommendation["recommended_action"],
        "recommendation": recommendation,
        "created_at": item.get("created_at"),
    }


def recommendation_for_history(item: dict[str, Any], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    if item.get("evidence_status") != "complete":
        return {"recommended_action": "alert_only", "reason": "Evidencia incompleta."}
    if any(candidate.get("action") != "alert_only" for candidate in candidates):
        return {"recommended_action": "manual_review", "reason": "Revisar candidato manualmente."}
    return {"recommended_action": "alert_only", "reason": "Sem candidato aplicavel."}


def dominant_group_label(group: dict[str, Any] | None) -> str:
    if not group:
        return "-"
    sources = group.get("unique_src_ips") or []
    source_text = ", ".join(str(item) for item in sources[:3]) if sources else "origens"
    if len(sources) > 3:
        source_text += f" +{len(sources) - 3}"
    dst = group.get("dst_ip") or "-"
    port = group.get("dst_port") or "-"
    proto = str(group.get("protocol") or "").upper() or "-"
    return f"{source_text} -> {dst}:{port} {proto}"


def anomaly_peak_hunter_prefill(anomaly: dict[str, Any]) -> dict[str, Any]:
    started = parse_optional_time(anomaly.get("started_at"))
    ended = parse_optional_time(anomaly.get("ended_at") or anomaly.get("last_seen_at"))
    detected = parse_optional_time(anomaly.get("detected_at") or anomaly.get("created_at"))
    if started and ended:
        start = started - timedelta(minutes=2)
        end = ended + timedelta(minutes=2)
    else:
        center = detected or parse_optional_time(anomaly.get("last_seen_at")) or datetime.now(timezone.utc)
        start = center - timedelta(minutes=5)
        end = center + timedelta(minutes=5)
    if end <= start:
        end = start + timedelta(minutes=10)
    metric = anomaly.get("metric_unit") or anomaly.get("metric") or "packets_s"
    if metric not in {"packets_s", "bits_s"}:
        metric = "packets_s"
    direction = anomaly.get("direction") or "sends"
    if direction not in {"sends", "receives"}:
        direction = "sends"
    return {
        "anomaly_id": anomaly.get("id"),
        "sensor": anomaly.get("sensor_name") or anomaly.get("sensor") or "",
        "interface_id": anomaly.get("interface_if_index") or anomaly.get("output_if") or anomaly.get("input_if") or None,
        "direction": direction,
        "metric": metric,
        "protocol": anomaly.get("protocol") or anomaly.get("decoder") or "",
        "start_time": start.isoformat().replace("+00:00", "Z"),
        "end_time": end.isoformat().replace("+00:00", "Z"),
        "threshold": anomaly.get("threshold_value") or None,
        "label": f"Investigando anomalia #{anomaly.get('id') or '-'}",
    }


def parse_optional_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return parse_time(value)
    except (TypeError, ValueError):
        return None


def history_record(request: PeakHunterRequest, peak: dict[str, Any], baseline: dict[str, float]) -> dict[str, Any]:
    return {
        "peak_time": peak.get("peak_time_utc") or peak.get("peak_time") or peak.get("time"),
        "interface_id": request.interface_id,
        "sensor": request.sensor,
        "direction": request.direction,
        "metric": request.metric,
        "peak_value": peak.get("peak_value") or 0,
        "baseline_p95": baseline.get("p95") or 0,
        "baseline_p99": baseline.get("p99") or 0,
        "score": peak.get("score") or 0,
        "evidence_status": peak.get("evidence_status") or "insufficient",
        "classification": peak.get("classification") or "insufficient_flow_evidence",
        "dominant_group": peak.get("dominant_group") or {},
        "candidates": peak.get("candidates") or [],
        "ai_summary": peak.get("ai_summary") or "",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def recommendation_for_peak(peak: dict[str, Any] | None) -> dict[str, Any]:
    if not peak or peak.get("evidence_status") != "complete":
        return {"recommended_action": "alert_only", "reason": "Sem evidencia de flow suficiente para identificar vetor dominante."}
    if peak.get("mitigation_allowed"):
        return {"recommended_action": "manual_review", "reason": "Candidato seguro gerado para revisao manual; aplicacao automatica desativada."}
    return {"recommended_action": "alert_only", "reason": "Grupo dominante encontrado, mas candidato nao passou na validacao."}


def select_best_peak(peaks: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not peaks:
        return None
    return sorted(peaks, key=lambda item: (item.get("evidence_status") == "complete", float(item.get("score") or 0)), reverse=True)[0]


def percentile(ordered_values: list[float], percentile_value: int) -> float:
    if not ordered_values:
        return 0.0
    index = (len(ordered_values) - 1) * (percentile_value / 100)
    lower = int(index)
    upper = min(lower + 1, len(ordered_values) - 1)
    weight = index - lower
    return ordered_values[lower] * (1 - weight) + ordered_values[upper] * weight


LOCAL_TIMEZONE = ZoneInfo("America/Sao_Paulo") if ZoneInfo is not None else timezone(timedelta(hours=-3))


def _format_time_utc_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _format_time_local(value: datetime) -> str:
    return value.astimezone(LOCAL_TIMEZONE).isoformat()


def parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _enrichment_rank(enrichment: dict[str, Any], metric: str) -> float:
    dominant = enrichment.get("dominant_group") or {}
    if not dominant:
        return 0.0
    return float(dominant.get("share_bits") if metric == "bits_s" else dominant.get("share_packets") or 0)


def _template_for_classification(classification: Any) -> str:
    text = str(classification or "")
    if text == "dns_udp_abuse_outbound":
        return "dns_udp_abuse_outbound"
    if "tcp" in text:
        return "tcp_syn_flood"
    if "icmp" in text:
        return "icmp_flood"
    return "udp_flood_outbound_cpe"


def _ipv4_24(value: Any) -> str:
    text = str(value or "").strip()
    parts = text.split(".")
    if len(parts) != 4:
        return ""
    return ".".join(parts[:3] + ["0"]) + "/24"


def _string_time(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value or "")


def _json_value(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback
