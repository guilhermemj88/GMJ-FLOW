from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Any

import clickhouse_connect

from app.services.peak_hunter import PeakHunterRequest


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


def fetch_interface_series(request: PeakHunterRequest) -> list[dict[str, Any]]:
    direction_field = "output_if" if request.direction in {"sends", "transmits", "outbound"} else "input_if"
    value_expr = "sum(bytes) * 8" if request.metric == "bits_s" else "sum(packets)"
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
    return query_clickhouse(
        f"""
        SELECT
            toStartOfInterval(flow_time, INTERVAL {{window_seconds:UInt32}} SECOND) AS time,
            {value_expr} / {{window_seconds:Float64}} AS value,
            sum(packets) / {{window_seconds:Float64}} AS packets_s,
            sum(bytes) * 8 / {{window_seconds:Float64}} AS bits_s
        FROM flow_raw
        WHERE {' AND '.join(filters)}
        GROUP BY time
        ORDER BY time
        """,
        params,
    )


def fetch_peak_flows(request: PeakHunterRequest, peak_time: datetime, window_seconds: int) -> list[dict[str, Any]]:
    direction_field = "output_if" if request.direction in {"sends", "transmits", "outbound"} else "input_if"
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
    return query_clickhouse(
        f"""
        SELECT
            min(flow_time) AS flow_time,
            toString(src_ip) AS src_ip,
            src_port,
            toString(dst_ip) AS dst_ip,
            dst_port,
            proto,
            sum(bytes) AS bytes,
            sum(packets) AS packets,
            sum(flow_count) AS flow_count,
            sum(packets) / {{seconds:Float64}} AS packets_s,
            sum(bytes) * 8 / {{seconds:Float64}} AS bits_s,
            any(input_if) AS input_if,
            any(output_if) AS output_if
        FROM flow_raw
        WHERE {' AND '.join(filters)}
        GROUP BY src_ip, src_port, dst_ip, dst_port, proto
        ORDER BY {request.metric} DESC
        LIMIT 200
        """,
        params,
    )


def fetch_peak_hunter_sensors() -> list[dict[str, Any]]:
    return query_clickhouse(
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
    return query_clickhouse(
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
    return int(text)
