from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta
from typing import Any

import clickhouse_connect

from app.services.peak_hunter import PeakHunterRequest


SAMPLE_RATE_MODES = {"sensor_default", "per_interface", "snmp_auto"}
FLOW_SAMPLE_RATE_FALLBACK = "greatest(toFloat64(sample_rate), 1.0)"


class ClickHouseQueryError(RuntimeError):
    def __init__(self, query_context: str, message: str):
        super().__init__(message)
        self.query_context = query_context


def get_client() -> Any:
    return clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST", "clickhouse"),
        port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "flowdb"),
        connect_timeout=int(os.getenv("CLICKHOUSE_CONNECT_TIMEOUT_SECONDS", "5")),
        send_receive_timeout=int(os.getenv("CLICKHOUSE_QUERY_TIMEOUT_SECONDS", "30")),
    )


def rows_as_dicts(result: Any) -> list[dict[str, Any]]:
    if hasattr(result, "named_results"):
        return [dict(row) for row in result.named_results()]
    return [dict(row) for row in result or []]


def query_clickhouse(query: str, parameters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    return rows_as_dicts(get_client().query(query, parameters=parameters or {}))


def query_clickhouse_context(query_context: str, query: str, parameters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    try:
        return query_clickhouse(query, parameters)
    except Exception as exc:
        raise ClickHouseQueryError(query_context, str(exc)) from exc


def fetch_interface_series(request: PeakHunterRequest) -> list[dict[str, Any]]:
    direction_field = "output_if" if request.direction in {"sends", "transmits", "outbound"} else "input_if"
    sample_direction = "output" if direction_field == "output_if" else "input"
    sample_rate = peak_sample_rate_details(request.sensor, int(request.interface_id), sample_direction)
    rate_expr = sample_rate["rate_expr"]
    packets_expr = f"sum(toFloat64(packets) * ({rate_expr}))"
    bytes_expr = f"sum(toFloat64(bytes) * ({rate_expr}))"
    value_expr = f"{bytes_expr} * 8" if request.metric == "bits_s" else packets_expr
    divisor = max(int(request.window_seconds or 5), 1)
    filters = [
        "flow_time >= {start:DateTime}",
        "flow_time <= {end:DateTime}",
        f"{direction_field} = {{interface_id:UInt32}}",
    ]
    params: dict[str, Any] = {
        "start": request.start_time,
        "end": request.end_time,
        "interface_id": int(request.interface_id),
        "window_seconds": divisor,
    }
    if request.sensor:
        filters.append("sensor = {sensor:String}")
        params["sensor"] = request.sensor
    if request.protocol:
        filters.append("proto = {proto:UInt8}")
        params["proto"] = _proto_number(request.protocol)
    return query_clickhouse_context(
        "fetch_interface_series",
        f"""
        WITH toStartOfInterval(flow_time, INTERVAL {{window_seconds:UInt32}} SECOND) AS bucket
        SELECT
            bucket,
            toString(bucket) AS raw_time_from_clickhouse,
            toTypeName(bucket) AS clickhouse_time_type,
            'UTC' AS clickhouse_timezone,
            {value_expr} / {{window_seconds:Float64}} AS value,
            {packets_expr} / {{window_seconds:Float64}} AS packets_s,
            {bytes_expr} * 8 / {{window_seconds:Float64}} AS bits_s,
            sum(packets) AS raw_packets,
            sum(bytes) AS raw_bytes,
            max(sample_rate) AS db_sample_rate,
            {sample_rate['effective_select']} AS effective_sample_rate,
            '{sample_rate['source']}' AS sample_rate_source
        FROM flow_raw
        WHERE {' AND '.join(filters)}
        GROUP BY bucket
        ORDER BY bucket
        """,
        params,
    )


def fetch_learning_traffic_series(filters: dict[str, Any]) -> list[dict[str, Any]]:
    metric = str(filters.get("metric") or "packets_s").strip()
    if metric not in {"packets_s", "bits_s", "flows_s"}:
        raise ClickHouseQueryError("fetch_learning_traffic_series", "metric invalida")
    window_seconds = max(int(filters.get("window_seconds") or 60), 1)
    direction = str(filters.get("direction") or "both").strip()
    protocol = str(filters.get("protocol") or "").strip().lower()
    clauses = [
        "flow_time >= {start:DateTime}",
        "flow_time <= {end:DateTime}",
    ]
    params: dict[str, Any] = {
        "start": filters["start_time"],
        "end": filters["end_time"],
        "window_seconds": window_seconds,
    }
    sensor = str(filters.get("sensor") or "").strip()
    if sensor:
        clauses.append("sensor = {sensor:String}")
        params["sensor"] = sensor
    interface_id = filters.get("interface_id")
    if interface_id not in (None, "", "all"):
        params["interface_id"] = int(interface_id)
        if direction in {"sends", "transmits", "outbound"}:
            clauses.append("output_if = {interface_id:UInt32}")
        elif direction in {"receives", "inbound"}:
            clauses.append("input_if = {interface_id:UInt32}")
        else:
            clauses.append("(input_if = {interface_id:UInt32} OR output_if = {interface_id:UInt32})")
    if protocol and protocol not in {"any", "all"}:
        if protocol == "dns":
            clauses.append("(proto = 17 AND (src_port = 53 OR dst_port = 53))")
        else:
            clauses.append("proto = {proto:UInt8}")
            params["proto"] = _proto_number(protocol)
    src_cidr = str(filters.get("src_cidr") or "").strip()
    if src_cidr:
        if "/" in src_cidr:
            clauses.append("isIPAddressInRange(toString(src_ip), {src_cidr:String})")
            params["src_cidr"] = src_cidr
        else:
            clauses.append("toString(src_ip) = {src_cidr:String}")
            params["src_cidr"] = src_cidr
    dst_cidr = str(filters.get("dst_cidr") or "").strip()
    if dst_cidr:
        if "/" in dst_cidr:
            clauses.append("isIPAddressInRange(toString(dst_ip), {dst_cidr:String})")
            params["dst_cidr"] = dst_cidr
        else:
            clauses.append("toString(dst_ip) = {dst_cidr:String}")
            params["dst_cidr"] = dst_cidr
    zone_cidrs = [str(value).strip() for value in (filters.get("zone_cidrs") or []) if str(value).strip()]
    if zone_cidrs:
        parts = []
        for index, cidr in enumerate(zone_cidrs[:50]):
            key = f"zone_cidr_{index}"
            parts.append(f"isIPAddressInRange(toString(src_ip), {{{key}:String}})")
            parts.append(f"isIPAddressInRange(toString(dst_ip), {{{key}:String}})")
            params[key] = cidr
        clauses.append(f"({' OR '.join(parts)})")
    src_cidrs = [str(value).strip() for value in (filters.get("src_cidrs") or []) if str(value).strip()]
    if src_cidrs:
        parts = []
        for index, cidr in enumerate(src_cidrs[:50]):
            key = f"src_cidr_{index}"
            parts.append(f"isIPAddressInRange(toString(src_ip), {{{key}:String}})")
            params[key] = cidr
        clauses.append(f"({' OR '.join(parts)})")
    dst_cidrs = [str(value).strip() for value in (filters.get("dst_cidrs") or []) if str(value).strip()]
    if dst_cidrs:
        parts = []
        for index, cidr in enumerate(dst_cidrs[:50]):
            key = f"dst_cidr_{index}"
            parts.append(f"isIPAddressInRange(toString(dst_ip), {{{key}:String}})")
            params[key] = cidr
        clauses.append(f"({' OR '.join(parts)})")
    src_port = str(filters.get("src_port") or "").strip()
    if src_port:
        clauses.append("src_port = {src_port:UInt16}")
        params["src_port"] = int(src_port)
    dst_port = str(filters.get("dst_port") or "").strip()
    if dst_port:
        clauses.append("dst_port = {dst_port:UInt16}")
        params["dst_port"] = int(dst_port)
    metric_expr = {
        "packets_s": "sum(toFloat64(packets)) / {window_seconds:Float64}",
        "bits_s": "sum(toFloat64(bytes)) * 8 / {window_seconds:Float64}",
        "flows_s": "sum(toFloat64(flow_count)) / {window_seconds:Float64}",
    }[metric]
    return query_clickhouse_context(
        "fetch_learning_traffic_series",
        f"""
        WITH toStartOfInterval(flow_time, INTERVAL {{window_seconds:UInt32}} SECOND) AS bucket
        SELECT
            bucket,
            toString(bucket) AS raw_time_from_clickhouse,
            toTypeName(bucket) AS clickhouse_time_type,
            'UTC' AS clickhouse_timezone,
            {metric_expr} AS value,
            sum(toFloat64(packets)) / {{window_seconds:Float64}} AS packets_s,
            sum(toFloat64(bytes)) * 8 / {{window_seconds:Float64}} AS bits_s,
            sum(toFloat64(flow_count)) / {{window_seconds:Float64}} AS flows_s,
            sum(packets) AS raw_packets,
            sum(bytes) AS raw_bytes,
            sum(flow_count) AS raw_flows
        FROM flow_raw
        WHERE {' AND '.join(clauses)}
        GROUP BY bucket
        ORDER BY bucket
        """,
        params,
    )


def fetch_peak_flows(request: PeakHunterRequest, peak_time: datetime, window_seconds: int) -> list[dict[str, Any]]:
    direction_field = "output_if" if request.direction in {"sends", "transmits", "outbound"} else "input_if"
    sample_direction = "output" if direction_field == "output_if" else "input"
    sample_rate = peak_sample_rate_details(request.sensor, int(request.interface_id), sample_direction)
    rate_expr = sample_rate["rate_expr"]
    packets_expr = f"sum(toFloat64(packets) * ({rate_expr}))"
    bytes_expr = f"sum(toFloat64(bytes) * ({rate_expr}))"
    start = peak_time - timedelta(seconds=window_seconds)
    end = peak_time + timedelta(seconds=window_seconds)
    seconds = max(window_seconds * 2, 1)
    filters = [
        "flow_time >= {start:DateTime}",
        "flow_time <= {end:DateTime}",
        f"{direction_field} = {{interface_id:UInt32}}",
    ]
    params: dict[str, Any] = {
        "start": start,
        "end": end,
        "interface_id": int(request.interface_id),
        "seconds": seconds,
    }
    if request.sensor:
        filters.append("sensor = {sensor:String}")
        params["sensor"] = request.sensor
    if request.protocol:
        filters.append("proto = {proto:UInt8}")
        params["proto"] = _proto_number(request.protocol)
    sort_expr = "bits_s" if request.metric == "bits_s" else "packets_s"
    rows = query_clickhouse_context(
        "fetch_peak_flows",
        f"""
        SELECT
            *,
            total_packets / {{seconds:Float64}} AS packets_s,
            total_bytes * 8 / {{seconds:Float64}} AS bits_s
        FROM
        (
            SELECT
                toString(src_ip) AS src_ip,
                src_port,
                toString(dst_ip) AS dst_ip,
                dst_port,
                proto,
                any(input_if) AS flow_input_if,
                any(output_if) AS flow_output_if,
                min(flow_time) AS first_seen,
                max(flow_time) AS last_seen,
                sum(bytes) AS raw_bytes,
                sum(packets) AS raw_packets,
                max(sample_rate) AS db_sample_rate,
                {sample_rate['effective_select']} AS effective_sample_rate,
                '{sample_rate['source']}' AS sample_rate_source,
                {bytes_expr} AS total_bytes,
                {packets_expr} AS total_packets,
                sum(flow_count) AS total_flow_count
            FROM flow_raw
            WHERE {' AND '.join(filters)}
            GROUP BY src_ip, src_port, dst_ip, dst_port, proto
        )
        ORDER BY {sort_expr} DESC
        LIMIT 200
        """,
        params,
    )
    for row in rows:
        row["bytes"] = row.get("total_bytes")
        row["packets"] = row.get("total_packets")
        row["flow_count"] = row.get("total_flow_count")
        row["input_if"] = row.get("flow_input_if")
        row["output_if"] = row.get("flow_output_if")
    return rows


def fetch_peak_hunter_sensors() -> list[dict[str, Any]]:
    return query_clickhouse_context(
        "fetch_peak_hunter_sensors",
        """
        SELECT
            sensor AS sensor_name,
            any(sensor) AS sensor_id,
            max(flow_time) AS last_seen,
            count() AS row_count
        FROM flow_raw
        WHERE sensor != ''
        GROUP BY sensor
        ORDER BY last_seen DESC
        LIMIT 500
        """
    )


def fetch_peak_hunter_interfaces(sensor: str) -> list[dict[str, Any]]:
    filters = []
    params: dict[str, Any] = {}
    if sensor:
        filters.append("sensor = {sensor:String}")
        params["sensor"] = sensor
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    return query_clickhouse_context(
        "fetch_peak_hunter_interfaces",
        f"""
        SELECT
            interface_id,
            max(last_seen) AS last_seen,
            sum(rx_packets) AS rx_packets,
            sum(tx_packets) AS tx_packets,
            sum(rx_bytes) AS rx_bytes,
            sum(tx_bytes) AS tx_bytes
        FROM
        (
            SELECT
                input_if AS interface_id,
                max(flow_time) AS last_seen,
                sum(packets) AS rx_packets,
                0 AS tx_packets,
                sum(bytes) AS rx_bytes,
                0 AS tx_bytes
            FROM flow_raw
            {where}
            GROUP BY input_if
            UNION ALL
            SELECT
                output_if AS interface_id,
                max(flow_time) AS last_seen,
                0 AS rx_packets,
                sum(packets) AS tx_packets,
                0 AS rx_bytes,
                sum(bytes) AS tx_bytes
            FROM flow_raw
            {where}
            GROUP BY output_if
        )
        WHERE interface_id > 0
        GROUP BY interface_id
        ORDER BY interface_id
        LIMIT 2000
        """,
        params,
    )


def _proto_number(value: str) -> int:
    text = str(value or "").strip().lower()
    if text in {"udp", "17"}:
        return 17
    if text in {"tcp", "6"}:
        return 6
    if text in {"icmp", "1"}:
        return 1
    if text in {"gre", "47"}:
        return 47
    if text in {"esp", "50"}:
        return 50
    return int(text)


def peak_sample_rate_details(sensor: str, interface_id: int, direction: str) -> dict[str, Any]:
    config = sensor_sample_rate_config(resolve_sensor_id(sensor))
    if not config:
        return {
            "rate_expr": FLOW_SAMPLE_RATE_FALLBACK,
            "effective_select": f"max({FLOW_SAMPLE_RATE_FALLBACK})",
            "effective_sample_rate": None,
            "source": "flow_raw",
        }
    rate, source = effective_sample_rate_from_config(config, interface_id, direction)
    literal = sample_rate_literal(rate)
    return {
        "rate_expr": literal,
        "effective_select": literal,
        "effective_sample_rate": rate,
        "source": source,
    }


def resolve_sensor_id(sensor: str | None) -> int | None:
    text = _clean_text(sensor)
    if not text:
        return None
    try:
        with sqlite_connection() as conn:
            row = conn.execute(
                """
                SELECT id
                FROM sensors
                WHERE name = ? OR exporter_ip = ? OR CAST(id AS TEXT) = ?
                ORDER BY active DESC, id
                LIMIT 1
                """,
                (text, text, text),
            ).fetchone()
    except sqlite3.Error:
        return None
    return int(row["id"]) if row else None


def sensor_sample_rate_config(sensor_id: int | None) -> dict[str, Any] | None:
    if sensor_id is None:
        return None
    try:
        with sqlite_connection() as conn:
            sensor = conn.execute(
                """
                SELECT sample_rate_default_in, sample_rate_default_out, sample_rate_mode
                FROM sensors
                WHERE id = ?
                """,
                (sensor_id,),
            ).fetchone()
            if sensor is None:
                return None
            rows = conn.execute(
                """
                SELECT if_index, sample_rate_in, sample_rate_out, sample_rate_override
                FROM sensor_interfaces
                WHERE sensor_id = ?
                """,
                (sensor_id,),
            ).fetchall()
    except sqlite3.Error:
        return None
    interfaces: dict[int, dict[str, Any]] = {}
    for row in rows:
        if_index = int(row["if_index"] or 0)
        if if_index <= 0:
            continue
        interfaces[if_index] = {
            "in": max(1, int(row["sample_rate_in"] or 1)),
            "out": max(1, int(row["sample_rate_out"] or 1)),
            "override": bool(row["sample_rate_override"]),
        }
    mode = _clean_text(sensor["sample_rate_mode"]) or "sensor_default"
    if mode not in SAMPLE_RATE_MODES:
        mode = "sensor_default"
    return {
        "default_in": max(1, int(sensor["sample_rate_default_in"] or 1)),
        "default_out": max(1, int(sensor["sample_rate_default_out"] or 1)),
        "mode": mode,
        "interfaces": interfaces,
    }


def effective_sample_rate_from_config(config: dict[str, Any], if_index: int | None, direction: str) -> tuple[int, str]:
    direction_key = "out" if direction == "output" else "in"
    default_key = "default_out" if direction == "output" else "default_in"
    default_rate = max(1, int(config.get(default_key) or 1))
    interfaces = config.get("interfaces") if isinstance(config.get("interfaces"), dict) else {}
    interface = interfaces.get(int(if_index or 0))
    mode = _clean_text(config.get("mode")) or "sensor_default"
    if interface and (interface.get("override") or mode == "per_interface"):
        return max(1, int(interface.get(direction_key) or default_rate)), "interface"
    return default_rate, "sensor"


def sample_rate_literal(value: Any) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = 1
    return f"toFloat64({max(1, number)})"


def sqlite_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(os.getenv("GMJFLOW_DB_PATH", "/app/data/gmjflow.db"))
    conn.row_factory = sqlite3.Row
    return conn


def _clean_text(value: Any) -> str:
    return str(value or "").strip()
