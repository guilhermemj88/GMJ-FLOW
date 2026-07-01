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
    recommendation = recommendation_for_peak(best)
    result = {
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
    result["technical_report"] = build_technical_report(request, result)
    if save_history and best:
        save_history(history_record(request, result, baseline))
    return result


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
        source_timezone = _source_timezone(row)
        time_info = _time_payload(time_value, source_timezone)
        point = {
            "raw_time_from_clickhouse": row.get("raw_time_from_clickhouse") or time_info["raw_time_from_clickhouse"],
            "time": time_info["peak_time_utc"],
            "time_utc": time_info["peak_time_utc"],
            "time_local": time_info["peak_time_local"],
            "timezone": "America/Sao_Paulo",
            "clickhouse_timezone": source_timezone,
            metric: value,
            "value": value,
        }
        for field in ("raw_packets", "raw_bytes", "db_sample_rate", "effective_sample_rate", "sample_rate_source", "clickhouse_time_type"):
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
            peak = {
                "raw_time_from_clickhouse": point.get("raw_time_from_clickhouse"),
                "peak_time": point["time"],
                "time": point["time"],
                "peak_time_utc": point.get("time_utc") or point["time"],
                "peak_time_local": point.get("time_local"),
                "timezone": "America/Sao_Paulo",
                "peak_value": value,
                "score": round(score, 3),
            }
            for field in ("raw_packets", "raw_bytes", "db_sample_rate", "effective_sample_rate", "sample_rate_source", "clickhouse_time_type", "clickhouse_timezone"):
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


def build_technical_report(request: PeakHunterRequest, result: dict[str, Any]) -> str:
    best = result.get("best_peak") or {}
    baseline = result.get("baseline") or {}
    dominant = result.get("dominant_group") or best.get("dominant_group") or {}
    candidates = result.get("candidates") or best.get("candidates") or []
    sources = dominant.get("unique_src_ips") if isinstance(dominant.get("unique_src_ips"), list) else []
    sample_rate = best.get("effective_sample_rate") or best.get("db_sample_rate") or "-"
    candidate_lines = []
    for candidate in candidates:
        candidate_lines.append(
            f"- #{candidate.get('candidate_index', '-')}: action={candidate.get('action', '-')}, "
            f"template={candidate.get('template', '-')}, ttl={candidate.get('ttl', '-')}, "
            f"manual_approval_required={candidate.get('manual_approval_required', True)}, "
            f"apply_enabled={candidate.get('apply_enabled', False)}"
        )
    if not candidate_lines:
        candidate_lines.append("- nenhum candidate gerado")
    local_time = _display_local(best.get("peak_time_local") or best.get("peak_time_utc") or best.get("peak_time"))
    utc_time = best.get("peak_time_utc") or _format_time_utc_z(parse_time(best.get("peak_time") or datetime.now(timezone.utc)))
    window_local = f"{_display_local(request.start_time)} ate {_display_local(request.end_time)}"
    window_utc = f"{_format_time_utc_z(request.start_time)} ate {_format_time_utc_z(request.end_time)}"
    direction_label = "upload" if request.direction in {"sends", "transmits", "outbound"} else "download"
    metric_value = metric_value_text(best.get("peak_value") or 0, request.metric)
    p99_value = metric_value_text(baseline.get("p99") or 0, request.metric)
    p95_value = metric_value_text(baseline.get("p95") or 0, request.metric)
    group_pps = metric_value_text(dominant.get("max_packets_s") or dominant.get("avg_packets_s") or 0, "packets_s")
    group_bps = metric_value_text(dominant.get("max_bits_s") or dominant.get("avg_bits_s") or 0, "bits_s")
    summary = (
        f"Foi detectado pico de {direction_label} {str(dominant.get('protocol') or request.protocol or '').upper() or request.metric} "
        f"na interface {request.interface_id}. O melhor pico ocorreu em {local_time} / {utc_time}, "
        f"com {metric_value}, acima do baseline p99 de {p99_value}. "
        f"A janela de evidencia de {result.get('evidence_window_used') or '-'}s mostrou grupo dominante "
        f"{str(dominant.get('protocol') or '-').upper()} para {dominant.get('dst_ip') or '-'}:{dominant.get('dst_port') or '-'}, "
        f"responsavel por {float(dominant.get('share_packets') or 0):.2f}% dos pacotes. "
        f"Foram observadas {dominant.get('unique_src_count') or len(sources)} origens. "
        f"O vetor provavel e {result.get('classification') or '-'}. "
        f"Foi gerado candidate para revisao manual, sem aplicacao automatica."
    )
    return "\n".join(
        [
            "Peak Hunter - relatorio tecnico",
            "",
            summary,
            "",
            "Contexto",
            f"- sensor: {request.sensor or '-'}",
            f"- interface: {request.interface_id}",
            f"- direcao: {request.direction}",
            f"- metrica: {request.metric}",
            f"- protocolo: {request.protocol or '-'}",
            f"- janela local: {window_local}",
            f"- janela UTC: {window_utc}",
            "",
            "Pico e baseline",
            f"- melhor pico local: {local_time}",
            f"- melhor pico UTC: {utc_time}",
            f"- valor do pico: {metric_value}",
            f"- baseline p95: {p95_value}",
            f"- baseline p99: {p99_value}",
            f"- threshold usado: {metric_value_text(result.get('threshold_used') or 0, request.metric)}",
            f"- score: {best.get('score') or '-'}",
            f"- sample_rate efetivo: {sample_rate}",
            "",
            "Evidencia de flows",
            f"- janela de evidencia usada: {result.get('evidence_window_used') or '-'}s",
            f"- status de evidencia: {result.get('evidence_status') or '-'}",
            f"- classificacao: {result.get('classification') or '-'}",
            f"- grupo dominante: {dominant_group_label(dominant)}",
            f"- principais origens: {', '.join(str(item) for item in sources[:10]) if sources else '-'}",
            f"- destino/porta/protocolo: {dominant.get('dst_ip') or '-'}:{dominant.get('dst_port') or '-'} {str(dominant.get('protocol') or '-').upper()}",
            f"- share_packets: {float(dominant.get('share_packets') or 0):.2f}%",
            f"- share_bits: {float(dominant.get('share_bits') or 0):.2f}%",
            f"- pps do grupo: {group_pps}",
            f"- bps do grupo: {group_bps}",
            "",
            "Recomendacao",
            f"- acao recomendada: {(result.get('recommendation') or {}).get('recommended_action') or '-'}",
            f"- motivo: {(result.get('recommendation') or {}).get('reason') or '-'}",
            f"- mitigation_allowed: {bool(result.get('mitigation_allowed'))} (apenas candidate seguro para revisao manual)",
            "- mitigacao automatica nao aplicada: apply_enabled=false, manual_approval_required=true, validator/playbook permanecem como camada de seguranca.",
            "",
            "Candidates",
            *candidate_lines,
        ]
    )


def metric_value_text(value: Any, metric: str) -> str:
    number = float(value or 0)
    units = [("T", 1_000_000_000_000), ("G", 1_000_000_000), ("M", 1_000_000), ("K", 1_000)]
    suffix = "bps" if metric == "bits_s" else "pps" if metric == "packets_s" else metric
    for label, factor in units:
        if abs(number) >= factor:
            return f"{number / factor:.2f} {label}{suffix}"
    return f"{number:.2f} {suffix}"


def _display_local(value: Any) -> str:
    parsed = parse_optional_time(value)
    if not parsed:
        return "-"
    local = parsed.astimezone(LOCAL_TIMEZONE)
    return local.strftime("%d/%m/%Y %H:%M:%S BRT")


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
    _ensure_peak_analysis_column(conn, "request_json", "request_json TEXT NOT NULL DEFAULT '{}'")
    _ensure_peak_analysis_column(conn, "result_json", "result_json TEXT NOT NULL DEFAULT '{}'")
    _ensure_peak_analysis_column(conn, "technical_report", "technical_report TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "peak_time_utc", "peak_time_utc TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "peak_time_local", "peak_time_local TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "timezone", "timezone TEXT NOT NULL DEFAULT 'America/Sao_Paulo'")
    _ensure_peak_analysis_column(conn, "interface_name", "interface_name TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "interface_alias", "interface_alias TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "protocol", "protocol TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "threshold_used", "threshold_used REAL NOT NULL DEFAULT 0")
    _ensure_peak_analysis_column(conn, "mitigation_allowed", "mitigation_allowed INTEGER NOT NULL DEFAULT 0")
    _ensure_peak_analysis_column(conn, "recommended_action", "recommended_action TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "dominant_dst_ip", "dominant_dst_ip TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "dominant_dst_port", "dominant_dst_port INTEGER")
    _ensure_peak_analysis_column(conn, "dominant_protocol", "dominant_protocol TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "dominant_unique_src_count", "dominant_unique_src_count INTEGER NOT NULL DEFAULT 0")
    _ensure_peak_analysis_column(conn, "dominant_share_packets", "dominant_share_packets REAL NOT NULL DEFAULT 0")
    _ensure_peak_analysis_column(conn, "dominant_share_bits", "dominant_share_bits REAL NOT NULL DEFAULT 0")
    _ensure_peak_analysis_column(conn, "candidates_json", "candidates_json TEXT NOT NULL DEFAULT '[]'")
    _ensure_peak_analysis_column(conn, "operator_label", "operator_label TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "operator_vector", "operator_vector TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "operator_best_action", "operator_best_action TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "operator_comment", "operator_comment TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "operator_confirmed_template", "operator_confirmed_template TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "operator_confirmed_ttl", "operator_confirmed_ttl TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "resolved_by_mitigation", "resolved_by_mitigation INTEGER NOT NULL DEFAULT 0")
    _ensure_peak_analysis_column(conn, "feedback_updated_at", "feedback_updated_at TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "analysis_source", "analysis_source TEXT NOT NULL DEFAULT 'manual'")
    _ensure_peak_analysis_column(conn, "job_id", "job_id INTEGER")
    _ensure_peak_analysis_column(conn, "run_id", "run_id INTEGER")
    _ensure_peak_analysis_column(conn, "is_negative_sample", "is_negative_sample INTEGER NOT NULL DEFAULT 0")
    _ensure_peak_analysis_column(conn, "duplicate_of_id", "duplicate_of_id INTEGER")
    _ensure_peak_analysis_column(conn, "auto_runner_version", "auto_runner_version TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "monitored_interface_name", "monitored_interface_name TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "monitored_interface_alias", "monitored_interface_alias TEXT NOT NULL DEFAULT ''")
    _ensure_peak_analysis_column(conn, "lookback_minutes", "lookback_minutes INTEGER")
    _ensure_peak_analysis_column(conn, "interval_minutes", "interval_minutes INTEGER")
    _copy_legacy_json_column(conn, "dominant_group_json", "dominant_group", "{}")
    _copy_legacy_json_column(conn, "candidates_json", "candidates", "[]")
    _copy_legacy_json_column(conn, "candidates", "candidates_json", "[]")


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
    columns = [
        "peak_time",
        "peak_time_utc",
        "peak_time_local",
        "timezone",
        "interface_id",
        "interface_name",
        "interface_alias",
        "sensor",
        "direction",
        "metric",
        "protocol",
        "peak_value",
        "baseline_p95",
        "baseline_p99",
        "threshold_used",
        "score",
        "evidence_status",
        "classification",
        "mitigation_allowed",
        "recommended_action",
        "dominant_dst_ip",
        "dominant_dst_port",
        "dominant_protocol",
        "dominant_unique_src_count",
        "dominant_share_packets",
        "dominant_share_bits",
        "dominant_group",
        "candidates",
        "candidates_json",
        "request_json",
        "result_json",
        "technical_report",
        "ai_summary",
        "analysis_source",
        "job_id",
        "run_id",
        "is_negative_sample",
        "duplicate_of_id",
        "auto_runner_version",
        "monitored_interface_name",
        "monitored_interface_alias",
        "lookback_minutes",
        "interval_minutes",
        "created_at",
    ]
    values = [record_value_for_db(record, column) for column in columns]
    conn.execute(
        f"""
        INSERT INTO peak_analysis ({', '.join(columns)})
        VALUES ({', '.join('?' for _ in columns)})
        """,
        values,
    )


def record_value_for_db(record: dict[str, Any], column: str) -> Any:
    if column in {"dominant_group", "request_json", "result_json"}:
        value = record.get(column)
        return value if isinstance(value, str) else json.dumps(value or {}, sort_keys=True, default=str)
    if column in {"candidates", "candidates_json"}:
        value = record.get("candidates_json") if column == "candidates_json" else record.get("candidates")
        return value if isinstance(value, str) else json.dumps(value or [], sort_keys=True, default=str)
    if column in {"mitigation_allowed", "resolved_by_mitigation", "is_negative_sample"}:
        return 1 if record.get(column) else 0
    if column == "peak_time_utc":
        return record.get("peak_time_utc") or record.get("peak_time") or ""
    if column == "peak_time_local":
        peak_time = parse_optional_time(record.get("peak_time_utc") or record.get("peak_time"))
        return record.get("peak_time_local") or (_format_time_local(peak_time) if peak_time else "")
    if column == "timezone":
        return record.get("timezone") or "America/Sao_Paulo"
    if column == "threshold_used":
        return float(record.get("threshold_used") or 0)
    if column == "recommended_action":
        return record.get("recommended_action") or recommendation_for_history(record, record.get("candidates") or []).get("recommended_action") or ""
    text_defaults = {
        "interface_name",
        "interface_alias",
        "sensor",
        "direction",
        "metric",
        "protocol",
        "evidence_status",
        "classification",
        "dominant_dst_ip",
        "dominant_protocol",
        "technical_report",
        "ai_summary",
        "analysis_source",
        "auto_runner_version",
        "monitored_interface_name",
        "monitored_interface_alias",
        "created_at",
    }
    if column in text_defaults:
        return record.get(column) or ""
    numeric_defaults = {
        "peak_value",
        "baseline_p95",
        "baseline_p99",
        "score",
        "dominant_unique_src_count",
        "dominant_share_packets",
        "dominant_share_bits",
    }
    if column in numeric_defaults:
        return record.get(column) or 0
    if column in {"interface_id", "dominant_dst_port"}:
        return record.get(column)
    if column in {"job_id", "run_id", "duplicate_of_id", "lookback_minutes", "interval_minutes"}:
        return record.get(column)
    return record.get(column)


def list_peak_analysis_history(
    conn: sqlite3.Connection,
    filters: dict[str, Any] | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    ensure_peak_analysis_db(conn)
    filters = filters or {}
    where = []
    values: list[Any] = []
    for column in ("sensor", "direction", "metric", "protocol", "evidence_status", "classification", "operator_label", "analysis_source"):
        value = str(filters.get(column) or "").strip()
        if value:
            where.append(f"{column} = ?")
            values.append(value)
    if filters.get("mitigation_allowed") not in (None, ""):
        where.append("mitigation_allowed = ?")
        values.append(1 if filters.get("mitigation_allowed") in (True, 1, "1", "true", "True", "sim", "yes") else 0)
    if filters.get("interface_id") not in (None, ""):
        where.append("interface_id = ?")
        values.append(int(filters["interface_id"]))
    if filters.get("job_id") not in (None, ""):
        where.append("job_id = ?")
        values.append(int(filters["job_id"]))
    if filters.get("run_id") not in (None, ""):
        where.append("run_id = ?")
        values.append(int(filters["run_id"]))
    if filters.get("is_negative_sample") not in (None, ""):
        where.append("is_negative_sample = ?")
        values.append(1 if filters.get("is_negative_sample") in (True, 1, "1", "true", "True", "sim", "yes") else 0)
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
    candidates = _json_value(item.get("candidates_json") or item.get("candidates"), [])
    recommendation = recommendation_for_history(item, candidates)
    peak_time = parse_optional_time(item.get("peak_time"))
    peak_time_utc = item.get("peak_time_utc") or (_format_time_utc_z(peak_time) if peak_time else item.get("peak_time"))
    peak_time_local = item.get("peak_time_local") or (_format_time_local(peak_time) if peak_time else "")
    result_json = _json_value(item.get("result_json"), {})
    request_json = _json_value(item.get("request_json"), {})
    return {
        "id": item.get("id"),
        "peak_time": item.get("peak_time"),
        "peak_time_utc": peak_time_utc,
        "peak_time_local": peak_time_local,
        "timezone": item.get("timezone") or "America/Sao_Paulo",
        "sensor": item.get("sensor") or "",
        "interface_id": item.get("interface_id"),
        "interface_name": item.get("interface_name") or "",
        "interface_alias": item.get("interface_alias") or "",
        "direction": item.get("direction") or "",
        "metric": item.get("metric") or "",
        "protocol": item.get("protocol") or "",
        "peak_value": float(item.get("peak_value") or 0),
        "baseline_p95": float(item.get("baseline_p95") or 0),
        "baseline_p99": float(item.get("baseline_p99") or 0),
        "threshold_used": float(item.get("threshold_used") or 0),
        "score": float(item.get("score") or 0),
        "evidence_status": item.get("evidence_status") or "",
        "classification": item.get("classification") or "",
        "mitigation_allowed": bool(item.get("mitigation_allowed")),
        "dominant_group": dominant_group,
        "dominant_group_label": dominant_group_label(dominant_group),
        "dominant_dst_ip": item.get("dominant_dst_ip") or dominant_group.get("dst_ip") or "",
        "dominant_dst_port": item.get("dominant_dst_port") or dominant_group.get("dst_port"),
        "dominant_protocol": item.get("dominant_protocol") or dominant_group.get("protocol") or "",
        "dominant_unique_src_count": int(item.get("dominant_unique_src_count") or dominant_group.get("unique_src_count") or 0),
        "dominant_share_packets": float(item.get("dominant_share_packets") or dominant_group.get("share_packets") or 0),
        "dominant_share_bits": float(item.get("dominant_share_bits") or dominant_group.get("share_bits") or 0),
        "candidates": candidates,
        "recommended_action": item.get("recommended_action") or recommendation["recommended_action"],
        "recommendation": recommendation,
        "technical_report": item.get("technical_report") or "",
        "request_json": request_json,
        "result_json": result_json,
        "operator_label": item.get("operator_label") or "",
        "operator_vector": item.get("operator_vector") or "",
        "operator_best_action": item.get("operator_best_action") or "",
        "operator_comment": item.get("operator_comment") or "",
        "operator_confirmed_template": item.get("operator_confirmed_template") or "",
        "operator_confirmed_ttl": item.get("operator_confirmed_ttl") or "",
        "resolved_by_mitigation": bool(item.get("resolved_by_mitigation")),
        "feedback_updated_at": item.get("feedback_updated_at") or "",
        "analysis_source": item.get("analysis_source") or "manual",
        "job_id": item.get("job_id"),
        "run_id": item.get("run_id"),
        "is_negative_sample": bool(item.get("is_negative_sample")),
        "duplicate_of_id": item.get("duplicate_of_id"),
        "auto_runner_version": item.get("auto_runner_version") or "",
        "monitored_interface_name": item.get("monitored_interface_name") or "",
        "monitored_interface_alias": item.get("monitored_interface_alias") or "",
        "lookback_minutes": item.get("lookback_minutes"),
        "interval_minutes": item.get("interval_minutes"),
        "created_at": item.get("created_at"),
    }


def get_peak_analysis_history_item(conn: sqlite3.Connection, item_id: int) -> dict[str, Any] | None:
    ensure_peak_analysis_db(conn)
    row = conn.execute("SELECT * FROM peak_analysis WHERE id = ?", (int(item_id),)).fetchone()
    return peak_analysis_row_to_dict(row) if row else None


ALLOWED_OPERATOR_LABELS = {
    "attack",
    "false_positive",
    "noise_or_unclear",
    "infected_customer",
    "normal_traffic",
    "mitigation_correct",
    "mitigation_wrong",
    "unknown",
}


def update_peak_analysis_feedback(conn: sqlite3.Connection, item_id: int, feedback: dict[str, Any]) -> dict[str, Any]:
    ensure_peak_analysis_db(conn)
    label = str(feedback.get("operator_label") or "").strip()
    if label and label not in ALLOWED_OPERATOR_LABELS:
        raise ValueError("operator_label invalido")
    values = {
        "operator_label": label,
        "operator_vector": str(feedback.get("operator_vector") or "").strip(),
        "operator_best_action": str(feedback.get("operator_best_action") or "").strip(),
        "operator_comment": str(feedback.get("operator_comment") or "").strip(),
        "operator_confirmed_template": str(feedback.get("operator_confirmed_template") or "").strip(),
        "operator_confirmed_ttl": str(feedback.get("operator_confirmed_ttl") or "").strip(),
        "resolved_by_mitigation": 1 if feedback.get("resolved_by_mitigation") else 0,
        "feedback_updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    conn.execute(
        """
        UPDATE peak_analysis
        SET operator_label = ?,
            operator_vector = ?,
            operator_best_action = ?,
            operator_comment = ?,
            operator_confirmed_template = ?,
            operator_confirmed_ttl = ?,
            resolved_by_mitigation = ?,
            feedback_updated_at = ?
        WHERE id = ?
        """,
        (
            values["operator_label"],
            values["operator_vector"],
            values["operator_best_action"],
            values["operator_comment"],
            values["operator_confirmed_template"],
            values["operator_confirmed_ttl"],
            values["resolved_by_mitigation"],
            values["feedback_updated_at"],
            int(item_id),
        ),
    )
    item = get_peak_analysis_history_item(conn, item_id)
    if item is None:
        raise KeyError("Historico nao encontrado")
    return item


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


def history_record(request: PeakHunterRequest, result: dict[str, Any], baseline: dict[str, float]) -> dict[str, Any]:
    peak = result.get("best_peak") or {}
    dominant = result.get("dominant_group") or peak.get("dominant_group") or {}
    candidates = result.get("candidates") or peak.get("candidates") or []
    recommendation = result.get("recommendation") or {}
    return {
        "peak_time": peak.get("peak_time_utc") or peak.get("peak_time") or peak.get("time"),
        "peak_time_utc": peak.get("peak_time_utc") or peak.get("peak_time") or peak.get("time"),
        "peak_time_local": peak.get("peak_time_local") or "",
        "timezone": peak.get("timezone") or "America/Sao_Paulo",
        "interface_id": request.interface_id,
        "interface_name": "",
        "interface_alias": "",
        "sensor": request.sensor,
        "direction": request.direction,
        "metric": request.metric,
        "protocol": request.protocol or "",
        "peak_value": peak.get("peak_value") or 0,
        "baseline_p95": baseline.get("p95") or 0,
        "baseline_p99": baseline.get("p99") or 0,
        "threshold_used": result.get("threshold_used") or peak.get("threshold_used") or 0,
        "score": peak.get("score") or 0,
        "evidence_status": peak.get("evidence_status") or "insufficient",
        "classification": peak.get("classification") or "insufficient_flow_evidence",
        "mitigation_allowed": bool(result.get("mitigation_allowed")),
        "recommended_action": recommendation.get("recommended_action") or "",
        "dominant_dst_ip": dominant.get("dst_ip") or "",
        "dominant_dst_port": dominant.get("dst_port"),
        "dominant_protocol": dominant.get("protocol") or "",
        "dominant_unique_src_count": dominant.get("unique_src_count") or len(dominant.get("unique_src_ips") or []),
        "dominant_share_packets": dominant.get("share_packets") or 0,
        "dominant_share_bits": dominant.get("share_bits") or 0,
        "dominant_group": dominant,
        "candidates": candidates,
        "candidates_json": candidates,
        "request_json": peak_hunter_request_to_dict(request),
        "result_json": result,
        "technical_report": result.get("technical_report") or "",
        "ai_summary": peak.get("ai_summary") or "",
        "analysis_source": "manual",
        "is_negative_sample": False,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def peak_hunter_request_to_dict(request: PeakHunterRequest) -> dict[str, Any]:
    return {
        "sensor": request.sensor,
        "interface_id": request.interface_id,
        "direction": request.direction,
        "metric": request.metric,
        "start_time": _format_time_utc_z(request.start_time),
        "end_time": _format_time_utc_z(request.end_time),
        "protocol": request.protocol or "",
        "threshold": request.threshold,
        "baseline": request.baseline,
        "window_seconds": request.window_seconds,
        "max_peaks": request.max_peaks,
        "sensitivity": request.sensitivity,
    }


def dataset_case_from_history_item(item: dict[str, Any]) -> dict[str, Any]:
    result = item.get("result_json") if isinstance(item.get("result_json"), dict) else {}
    peak = result.get("best_peak") or {
        "peak_time_utc": item.get("peak_time_utc"),
        "peak_time_local": item.get("peak_time_local"),
        "peak_value": item.get("peak_value"),
        "score": item.get("score"),
    }
    baseline = result.get("baseline") or {"p95": item.get("baseline_p95"), "p99": item.get("baseline_p99")}
    return {
        "case_id": f"peak-analysis-{item.get('id')}",
        "input": {
            "technical_report": item.get("technical_report") or "",
            "sensor": item.get("sensor") or "",
            "interface_id": item.get("interface_id"),
            "direction": item.get("direction") or "",
            "metric": item.get("metric") or "",
            "protocol": (item.get("protocol") or item.get("dominant_protocol") or "").upper(),
            "peak": peak,
            "baseline": baseline,
            "dominant_group": item.get("dominant_group") or result.get("dominant_group") or {},
            "top_groups": result.get("top_groups") or [],
            "top_conversations": result.get("top_conversations") or [],
            "candidates": item.get("candidates") or result.get("candidates") or [],
        },
        "expected_output": {
            "classification": item.get("classification") or "",
            "evidence_status": item.get("evidence_status") or "",
            "recommended_action": item.get("recommended_action") or "",
            "operator_label": item.get("operator_label") or "",
            "operator_vector": item.get("operator_vector") or "",
            "operator_best_action": item.get("operator_best_action") or "",
        },
        "metadata": {
            "created_at": item.get("created_at") or "",
            "peak_time_utc": item.get("peak_time_utc") or "",
            "peak_time_local": item.get("peak_time_local") or "",
            "timezone": item.get("timezone") or "America/Sao_Paulo",
            "analysis_source": item.get("analysis_source") or "manual",
            "job_id": item.get("job_id"),
            "run_id": item.get("run_id"),
            "is_negative_sample": bool(item.get("is_negative_sample")),
            "duplicate_of_id": item.get("duplicate_of_id"),
            "operator_comment": item.get("operator_comment") or "",
        },
    }


def export_peak_analysis_dataset(conn: sqlite3.Connection, filters: dict[str, Any] | None = None, limit: int = 1000) -> str:
    items = list_peak_analysis_history(conn, filters, limit=limit)
    return "\n".join(json.dumps(dataset_case_from_history_item(item), sort_keys=True, default=str) for item in items) + ("\n" if items else "")


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


def _time_payload(value: Any, source_timezone: str | None = None) -> dict[str, str]:
    parsed = parse_time_with_source_timezone(value, source_timezone)
    return {
        "raw_time_from_clickhouse": _raw_time_text(value),
        "peak_time_utc": _format_time_utc_z(parsed),
        "peak_time_local": _format_time_local(parsed),
        "timezone": "America/Sao_Paulo",
    }


def _format_time_utc_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _format_time_local(value: datetime) -> str:
    return value.astimezone(LOCAL_TIMEZONE).isoformat()


def parse_time(value: Any) -> datetime:
    return parse_time_with_source_timezone(value, "UTC")


def parse_time_with_source_timezone(value: Any, source_timezone: str | None = None) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo:
            return value
        return value.replace(tzinfo=_timezone_for_source(source_timezone))
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_timezone_for_source(source_timezone))


def _timezone_for_source(source_timezone: str | None) -> timezone:
    text = str(source_timezone or "").strip()
    if text == "America/Sao_Paulo":
        return LOCAL_TIMEZONE
    return timezone.utc


def _source_timezone(row: dict[str, Any]) -> str:
    explicit = str(row.get("clickhouse_timezone") or row.get("source_timezone") or "").strip()
    if explicit:
        return explicit
    type_name = str(row.get("clickhouse_time_type") or "").strip()
    if "America/Sao_Paulo" in type_name:
        return "America/Sao_Paulo"
    if "UTC" in type_name:
        return "UTC"
    return "UTC"


def _raw_time_text(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value or "")


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
