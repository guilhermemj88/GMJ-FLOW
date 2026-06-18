from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from ipaddress import IPv4Address, ip_address
from typing import Any

import clickhouse_connect
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(title="GMJ-FLOW API", version="0.1.0")

cors_origins = os.getenv("API_CORS_ORIGINS", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if cors_origins == "*" else [origin.strip() for origin in cors_origins.split(",")],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROTO_LABELS = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "58": "ICMPv6",
}

PROTO_NUMBERS = {name.lower(): int(number) for number, name in PROTO_LABELS.items()}

TCP_FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)


@lru_cache(maxsize=1)
def get_client():
    return clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST", "localhost"),
        port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "flowdb"),
    )


def utc_dt(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def resolve_range(range_minutes: int, start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    start_dt = utc_dt(start)
    end_dt = utc_dt(end)

    if start_dt is None and end_dt is None:
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(minutes=range_minutes)
    elif start_dt is None and end_dt is not None:
        start_dt = end_dt - timedelta(minutes=range_minutes)
    elif start_dt is not None and end_dt is None:
        end_dt = start_dt + timedelta(minutes=range_minutes)

    if start_dt is None or end_dt is None or start_dt >= end_dt:
        raise HTTPException(status_code=400, detail="Intervalo de tempo invalido")
    return start_dt, end_dt


def floor_minute(value: datetime) -> datetime:
    return value.replace(second=0, microsecond=0)


def ceil_minute(value: datetime) -> datetime:
    floored = floor_minute(value)
    if floored == value:
        return floored
    return floored + timedelta(minutes=1)


def iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def rows_as_dicts(result: Any) -> list[dict[str, Any]]:
    return [dict(zip(result.column_names, row)) for row in result.result_rows]


def sensor_clause(sensor: str | None, params: dict[str, Any]) -> str:
    if not sensor:
        return ""
    params["sensor"] = sensor
    return " AND sensor = {sensor:String}"


def clean_ip(value: Any) -> str:
    text = str(value or "")
    try:
        parsed = ip_address(text)
    except ValueError:
        return text
    if getattr(parsed, "ipv4_mapped", None):
        return str(parsed.ipv4_mapped)
    return str(parsed)


def clickhouse_ip_string_param(value: str, field_name: str) -> str:
    try:
        parsed = ip_address(value.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field_name} invalido") from None
    if isinstance(parsed, IPv4Address):
        return f"::ffff:{parsed}"
    return str(parsed)


def proto_name(value: Any) -> str:
    return PROTO_LABELS.get(str(value), str(value))


def parse_proto_filter(value: Any) -> int | None:
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    if text in PROTO_NUMBERS:
        return PROTO_NUMBERS[text]
    try:
        proto = int(text)
    except ValueError:
        raise HTTPException(status_code=400, detail="proto invalido") from None
    if proto < 0 or proto > 255:
        raise HTTPException(status_code=400, detail="proto fora da faixa 0-255")
    return proto


def tcp_flags_name(value: Any) -> str:
    try:
        flags = int(value)
    except (TypeError, ValueError):
        return str(value)
    names = [name for bit, name in TCP_FLAG_BITS if flags & bit]
    return ",".join(names) if names else "NONE"


def parse_tcp_flags_filter(value: Any) -> int | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        if text.lower().startswith("0x"):
            flags = int(text, 16)
        else:
            flags = int(text)
        if flags < 0 or flags > 65535:
            raise HTTPException(status_code=400, detail="tcp_flags fora da faixa 0-65535")
        return flags
    except ValueError:
        pass

    flags = 0
    by_name = {name.lower(): bit for bit, name in TCP_FLAG_BITS}
    for token in text.replace("+", ",").replace("|", ",").replace(" ", ",").split(","):
        token = token.strip().lower()
        if not token:
            continue
        if token not in by_name:
            raise HTTPException(status_code=400, detail="tcp_flags invalido")
        flags |= by_name[token]
    return flags


def label_for_dimension(dimension: str, key: str) -> str:
    if dimension in {"src_ip", "dst_ip"}:
        return clean_ip(key)
    if dimension == "proto":
        return proto_name(key)
    if dimension == "tcp_flags":
        return tcp_flags_name(key)
    if dimension == "dst_port":
        return f"Porta {key}"
    return key


def common_params(
    range_minutes: int = Query(60, ge=1, le=10080),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
) -> tuple[int, datetime | None, datetime | None, str | None]:
    return range_minutes, start, end, sensor


@app.get("/health")
def health(
    range_minutes: int = Query(60, ge=1, le=10080),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
):
    _ = (range_minutes, start, end, sensor)
    try:
        alive = get_client().ping()
    except Exception as exc:  # pragma: no cover - exposed as health detail.
        raise HTTPException(status_code=503, detail=f"ClickHouse indisponivel: {exc}") from exc
    return {"status": "ok", "clickhouse": "ok" if alive else "failed"}


def traffic_series(
    metric: str,
    range_minutes: int,
    start: datetime | None,
    end: datetime | None,
    sensor: str | None,
):
    start_dt, end_dt = resolve_range(range_minutes, start, end)
    query_start = floor_minute(start_dt)
    query_end = ceil_minute(end_dt)
    params: dict[str, Any] = {"start": query_start, "end": query_end}
    where = f"minute >= {{start:DateTime}} AND minute < {{end:DateTime}}{sensor_clause(sensor, params)}"
    result = get_client().query(
        f"""
        SELECT
            minute,
            sum(bytes) AS bytes,
            sum(packets) AS packets,
            sum(flows) AS flows
        FROM flow_1m
        WHERE {where}
        GROUP BY minute
        ORDER BY minute
        """,
        parameters=params,
    )
    values = {utc_dt(row["minute"]): row for row in rows_as_dicts(result)}

    points = []
    current = query_start
    while current < query_end:
        row = values.get(current, {"bytes": 0, "packets": 0, "flows": 0})
        bytes_value = int(row["bytes"] or 0)
        packets_value = int(row["packets"] or 0)
        point = {
            "timestamp": iso(current),
            "bytes": bytes_value,
            "packets": packets_value,
            "flows": int(row["flows"] or 0),
            "bps": round((bytes_value * 8) / 60, 2),
            "pps": round(packets_value / 60, 2),
        }
        points.append(point)
        current += timedelta(minutes=1)

    return {
        "metric": metric,
        "start": iso(start_dt),
        "end": iso(end_dt),
        "sensor": sensor,
        "series": points,
    }


@app.get("/api/traffic/bps")
def get_bps(
    range_minutes: int = Query(60, ge=1, le=10080),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
):
    return traffic_series("bps", range_minutes, start, end, sensor)


@app.get("/api/traffic/pps")
def get_pps(
    range_minutes: int = Query(60, ge=1, le=10080),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
):
    return traffic_series("pps", range_minutes, start, end, sensor)


def top_dimension(
    dimension: str,
    range_minutes: int,
    start: datetime | None,
    end: datetime | None,
    sensor: str | None,
    limit: int,
):
    start_dt, end_dt = resolve_range(range_minutes, start, end)
    query_start = floor_minute(start_dt)
    query_end = ceil_minute(end_dt)
    seconds = max(int((end_dt - start_dt).total_seconds()), 1)
    params: dict[str, Any] = {
        "dimension": dimension,
        "start": query_start,
        "end": query_end,
        "limit": limit,
    }
    where = (
        "dimension = {dimension:String} "
        "AND minute >= {start:DateTime} "
        "AND minute < {end:DateTime}"
        f"{sensor_clause(sensor, params)}"
    )
    result = get_client().query(
        f"""
        SELECT
            key,
            sum(bytes) AS bytes,
            sum(packets) AS packets,
            sum(flows) AS flows
        FROM flow_tops_1m
        WHERE {where}
        GROUP BY key
        ORDER BY bytes DESC
        LIMIT {{limit:UInt32}}
        """,
        parameters=params,
    )

    items = []
    for row in rows_as_dicts(result):
        bytes_value = int(row["bytes"] or 0)
        packets_value = int(row["packets"] or 0)
        key = str(row["key"])
        label = label_for_dimension(dimension, key)
        item = {
            "key": label if dimension in {"src_ip", "dst_ip"} else key,
            "raw_key": key,
            "label": label,
            "bytes": bytes_value,
            "packets": packets_value,
            "flows": int(row["flows"] or 0),
            "bps": round((bytes_value * 8) / seconds, 2),
            "pps": round(packets_value / seconds, 2),
        }
        if dimension == "src_ip":
            item["src_ip"] = label
        elif dimension == "dst_ip":
            item["dst_ip"] = label
        elif dimension == "proto":
            item["proto"] = int(key) if key.isdigit() else key
            item["proto_name"] = label
        elif dimension == "tcp_flags":
            item["tcp_flags"] = int(key) if key.isdigit() else key
            item["tcp_flags_name"] = label
        items.append(item)

    return {
        "dimension": dimension,
        "start": iso(start_dt),
        "end": iso(end_dt),
        "sensor": sensor,
        "items": items,
    }


@app.get("/api/tops/src-ip")
def top_src_ip(
    range_minutes: int = Query(60, ge=1, le=10080),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("src_ip", range_minutes, start, end, sensor, limit)


@app.get("/api/tops/dst-ip")
def top_dst_ip(
    range_minutes: int = Query(60, ge=1, le=10080),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("dst_ip", range_minutes, start, end, sensor, limit)


@app.get("/api/tops/ports")
def top_ports(
    range_minutes: int = Query(60, ge=1, le=10080),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("dst_port", range_minutes, start, end, sensor, limit)


@app.get("/api/tops/protocols")
def top_protocols(
    range_minutes: int = Query(60, ge=1, le=10080),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("proto", range_minutes, start, end, sensor, limit)


@app.get("/api/tops/tcp-flags")
def top_tcp_flags(
    range_minutes: int = Query(60, ge=1, le=10080),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("tcp_flags", range_minutes, start, end, sensor, limit)


@app.get("/api/flows/search")
def search_flows(
    range_minutes: int = Query(60, ge=1, le=10080),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
    ip: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    port: int | None = Query(None, ge=0, le=65535),
    src_port: int | None = Query(None, ge=0, le=65535),
    dst_port: int | None = Query(None, ge=0, le=65535),
    proto: str | None = None,
    tcp_flags: str | None = None,
    limit: int = Query(200, ge=1, le=5000),
):
    start_dt, end_dt = resolve_range(range_minutes, start, end)
    params: dict[str, Any] = {"start": start_dt, "end": end_dt, "limit": limit}
    filters = ["flow_time >= {start:DateTime}", "flow_time < {end:DateTime}"]
    if sensor:
        params["sensor"] = sensor
        filters.append("sensor = {sensor:String}")
    if ip:
        params["ip"] = clickhouse_ip_string_param(ip, "ip")
        filters.append("(toString(src_ip) = {ip:String} OR toString(dst_ip) = {ip:String})")
    if src_ip:
        params["src_ip"] = clickhouse_ip_string_param(src_ip, "src_ip")
        filters.append("toString(src_ip) = {src_ip:String}")
    if dst_ip:
        params["dst_ip"] = clickhouse_ip_string_param(dst_ip, "dst_ip")
        filters.append("toString(dst_ip) = {dst_ip:String}")
    if port is not None:
        params["port"] = port
        filters.append("(src_port = {port:UInt16} OR dst_port = {port:UInt16})")
    if src_port is not None:
        params["src_port"] = src_port
        filters.append("src_port = {src_port:UInt16}")
    if dst_port is not None:
        params["dst_port"] = dst_port
        filters.append("dst_port = {dst_port:UInt16}")
    proto_value = parse_proto_filter(proto)
    if proto_value is not None:
        params["proto"] = proto_value
        filters.append("proto = {proto:UInt8}")
    tcp_flags_value = parse_tcp_flags_filter(tcp_flags)
    if tcp_flags_value is not None:
        params["tcp_flags"] = tcp_flags_value
        filters.append("tcp_flags = {tcp_flags:UInt16}")

    result = get_client().query(
        f"""
        SELECT
            flow_time,
            sensor,
            toString(exporter_ip) AS exporter_ip,
            toString(src_ip) AS src_ip,
            toString(dst_ip) AS dst_ip,
            src_port,
            dst_port,
            proto,
            tcp_flags,
            input_if,
            output_if,
            bytes,
            packets,
            flow_type,
            sample_rate
        FROM flow_raw
        WHERE {' AND '.join(filters)}
        ORDER BY flow_time DESC
        LIMIT {{limit:UInt32}}
        """,
        parameters=params,
    )

    items = []
    for row in rows_as_dicts(result):
        row["flow_time"] = iso(row["flow_time"])
        row["exporter_ip"] = clean_ip(row["exporter_ip"])
        row["src_ip"] = clean_ip(row["src_ip"])
        row["dst_ip"] = clean_ip(row["dst_ip"])
        row["proto_name"] = proto_name(row["proto"])
        row["tcp_flags_name"] = tcp_flags_name(row["tcp_flags"])
        row["proto_label"] = row["proto_name"]
        row["tcp_flags_label"] = row["tcp_flags_name"]
        items.append(row)

    return {
        "start": iso(start_dt),
        "end": iso(end_dt),
        "sensor": sensor,
        "items": items,
    }
