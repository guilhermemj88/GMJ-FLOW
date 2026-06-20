from __future__ import annotations

import os
import sqlite3
import asyncio
import json
import logging
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from importlib import import_module
from ipaddress import IPv4Address, ip_address
from pathlib import Path
from typing import Any

import clickhouse_connect
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse


app = FastAPI(title="GMJ-FLOW API", version="0.1.0")
logger = logging.getLogger("gmj-flow")

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

SNMP_SYSTEM_OIDS = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
}

SNMP_INTERFACE_OIDS = {
    "if_index": "1.3.6.1.2.1.2.2.1.1",
    "if_descr": "1.3.6.1.2.1.2.2.1.2",
    "if_speed": "1.3.6.1.2.1.2.2.1.5",
    "if_oper_status": "1.3.6.1.2.1.2.2.1.8",
    "if_name": "1.3.6.1.2.1.31.1.1.1.1",
    "if_alias": "1.3.6.1.2.1.31.1.1.1.18",
    "if_high_speed": "1.3.6.1.2.1.31.1.1.1.15",
}

IF_OPER_STATUS_LABELS = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "notPresent",
    7: "lowerLayerDown",
}

SENSOR_COLUMNS = [
    "name",
    "visibility",
    "device_group",
    "sensor_server",
    "sensor_license",
    "listener_ip",
    "listener_port",
    "exporter_ip",
    "flow_protocol",
    "flow_version",
    "exporter_snmp_enabled",
    "ip_zone",
    "ip_validation",
    "flow_collector_enabled",
    "as_validation",
    "granularity_seconds",
    "timezone",
    "active",
    "snmp_ip",
    "snmp_port",
    "snmp_mib",
    "snmp_version",
    "snmp_community",
    "snmp_security_level",
    "snmp_security_name",
    "snmp_auth_protocol",
    "snmp_auth_passphrase",
    "snmp_privacy_protocol",
    "snmp_privacy_passphrase",
    "snmp_interface_name_mode",
    "snmp_counters_mode",
    "snmp_polling_seconds",
]

SENSOR_BOOL_COLUMNS = {"exporter_snmp_enabled", "flow_collector_enabled", "active"}

INTERFACE_COLUMNS = [
    "if_index",
    "if_name",
    "if_descr",
    "if_alias",
    "direction",
    "stats",
    "speed_in_bps",
    "speed_out_bps",
    "if_oper_status",
    "color",
    "monitor_enabled",
]

INTERFACE_BOOL_COLUMNS = {"monitor_enabled"}

WHOIS_CACHE_TTL_SECONDS = 24 * 60 * 60
WHOIS_CACHE: dict[str, dict[str, Any]] = {}
COLLECTORS_DIR = Path(os.getenv("GMJFLOW_COLLECTORS_DIR", "/app/data/collectors"))
COLLECTORS_RUNTIME_DIR = "/app/data/collectors"
COLLECTORS_COMPOSE_FILE = "docker-compose.collectors.yml"
DEFAULT_COLLECTOR_APPLY_SCRIPT = Path("scripts/apply_collectors.sh")
AUTH_ALGORITHM = "HS256"
AUTH_TOKEN_EXPIRE_HOURS = 8
AUTH_SECRET = os.getenv("GMJFLOW_AUTH_SECRET")
if not AUTH_SECRET:
    AUTH_SECRET = "gmj-flow-dev-secret-change-me"
    logger.warning("GMJFLOW_AUTH_SECRET nao definido; usando segredo de desenvolvimento.")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class SensorInterfacePayload(BaseModel):
    id: int | None = None
    if_index: int = 0
    if_name: str = ""
    if_descr: str = ""
    if_alias: str = ""
    direction: str = "Unset"
    stats: str = "Basic"
    speed_in_bps: int = 0
    speed_out_bps: int = 0
    if_oper_status: str = ""
    color: str = "#64748b"
    monitor_enabled: bool = True


class SensorPayload(BaseModel):
    name: str
    visibility: str = "show_in_reports"
    device_group: str = ""
    sensor_server: str = "console"
    sensor_license: str = "gmj-flow"
    listener_ip: str = ""
    listener_port: int = 9995
    exporter_ip: str = ""
    flow_protocol: str = "netflow"
    flow_version: str = "netflow-v9"
    exporter_snmp_enabled: bool = False
    ip_zone: str = "default"
    ip_validation: str = "off"
    flow_collector_enabled: bool = True
    as_validation: str = "off"
    granularity_seconds: int = 60
    timezone: str = "local-server"
    active: bool = True
    snmp_ip: str = ""
    snmp_port: int = 161
    snmp_mib: str = "generic"
    snmp_version: str = "2c"
    snmp_community: str = "public"
    snmp_security_level: str = "noAuthNoPriv"
    snmp_security_name: str = ""
    snmp_auth_protocol: str = ""
    snmp_auth_passphrase: str = ""
    snmp_privacy_protocol: str = ""
    snmp_privacy_passphrase: str = ""
    snmp_interface_name_mode: str = "auto"
    snmp_counters_mode: str = "auto"
    snmp_polling_seconds: int = 60
    interfaces: list[SensorInterfacePayload] = Field(default_factory=list)


class SnmpActionPayload(BaseModel):
    snmp_ip: str | None = None
    snmp_port: int | None = None
    snmp_version: str | None = None
    snmp_community: str | None = None
    snmp_security_level: str | None = None
    snmp_security_name: str | None = None
    snmp_auth_protocol: str | None = None
    snmp_auth_passphrase: str | None = None
    snmp_privacy_protocol: str | None = None
    snmp_privacy_passphrase: str | None = None
    timeout_seconds: float | None = None
    retries: int | None = None


class LoginPayload(BaseModel):
    username: str
    password: str


class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str


def get_client():
    return clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST", "localhost"),
        port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "flowdb"),
    )


def close_client(client: Any) -> None:
    for method_name in ("close", "disconnect"):
        method = getattr(client, method_name, None)
        if callable(method):
            try:
                method()
            except Exception:
                pass
            return


def query_clickhouse(query: str, parameters: dict[str, Any] | None = None) -> Any:
    client = get_client()
    try:
        return client.query(query, parameters=parameters or {})
    finally:
        close_client(client)


def ping_clickhouse() -> bool:
    client = get_client()
    try:
        return bool(client.ping())
    finally:
        close_client(client)


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


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def dump_model(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def sqlite_path() -> Path:
    return Path(os.getenv("GMJFLOW_DB_PATH", "/app/data/gmjflow.db"))


def sqlite_connection() -> sqlite3.Connection:
    path = sqlite_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def ensure_sensor_db() -> None:
    with sqlite_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                must_change_password INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sensors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                visibility TEXT NOT NULL DEFAULT 'show_in_reports',
                device_group TEXT NOT NULL DEFAULT '',
                sensor_server TEXT NOT NULL DEFAULT 'console',
                sensor_license TEXT NOT NULL DEFAULT 'gmj-flow',
                listener_ip TEXT NOT NULL DEFAULT '',
                listener_port INTEGER NOT NULL DEFAULT 9995,
                exporter_ip TEXT NOT NULL DEFAULT '',
                flow_protocol TEXT NOT NULL DEFAULT 'netflow',
                flow_version TEXT NOT NULL DEFAULT 'netflow-v9',
                exporter_snmp_enabled INTEGER NOT NULL DEFAULT 0,
                ip_zone TEXT NOT NULL DEFAULT 'default',
                ip_validation TEXT NOT NULL DEFAULT 'off',
                flow_collector_enabled INTEGER NOT NULL DEFAULT 1,
                as_validation TEXT NOT NULL DEFAULT 'off',
                granularity_seconds INTEGER NOT NULL DEFAULT 60,
                timezone TEXT NOT NULL DEFAULT 'local-server',
                active INTEGER NOT NULL DEFAULT 1,
                snmp_ip TEXT NOT NULL DEFAULT '',
                snmp_port INTEGER NOT NULL DEFAULT 161,
                snmp_mib TEXT NOT NULL DEFAULT 'generic',
                snmp_version TEXT NOT NULL DEFAULT '2c',
                snmp_community TEXT NOT NULL DEFAULT 'public',
                snmp_security_level TEXT NOT NULL DEFAULT 'noAuthNoPriv',
                snmp_security_name TEXT NOT NULL DEFAULT '',
                snmp_auth_protocol TEXT NOT NULL DEFAULT '',
                snmp_auth_passphrase TEXT NOT NULL DEFAULT '',
                snmp_privacy_protocol TEXT NOT NULL DEFAULT '',
                snmp_privacy_passphrase TEXT NOT NULL DEFAULT '',
                snmp_interface_name_mode TEXT NOT NULL DEFAULT 'auto',
                snmp_counters_mode TEXT NOT NULL DEFAULT 'auto',
                snmp_polling_seconds INTEGER NOT NULL DEFAULT 60,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sensor_interfaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sensor_id INTEGER NOT NULL,
                if_index INTEGER NOT NULL DEFAULT 0,
                if_name TEXT NOT NULL DEFAULT '',
                if_descr TEXT NOT NULL DEFAULT '',
                if_alias TEXT NOT NULL DEFAULT '',
                direction TEXT NOT NULL DEFAULT 'Unset',
                stats TEXT NOT NULL DEFAULT 'Basic',
                speed_in_bps INTEGER NOT NULL DEFAULT 0,
                speed_out_bps INTEGER NOT NULL DEFAULT 0,
                if_oper_status TEXT NOT NULL DEFAULT '',
                color TEXT NOT NULL DEFAULT '#64748b',
                monitor_enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
            )
            """
        )
        user_count = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        if int(user_count or 0) == 0:
            now = utc_now_iso()
            conn.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    role,
                    must_change_password,
                    active,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                ("admin", hash_password("admin"), "admin", 1, 1, now, now),
            )
            conn.commit()


@app.on_event("startup")
def startup() -> None:
    ensure_sensor_db()


def clean_text(value: Any) -> str:
    return str(value or "").strip()


def optional_ip(value: Any, field_name: str) -> str:
    text = clean_text(value)
    if not text:
        return ""
    try:
        return str(ip_address(text))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field_name} invalido") from None


def bounded_port(value: Any, field_name: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"{field_name} invalido") from None
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail=f"{field_name} fora da faixa 1-65535")
    return port


def non_negative_int(value: Any, field_name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"{field_name} invalido") from None
    if number < 0:
        raise HTTPException(status_code=400, detail=f"{field_name} deve ser maior ou igual a zero")
    return number


def positive_int(value: Any, field_name: str) -> int:
    number = non_negative_int(value, field_name)
    if number < 1:
        raise HTTPException(status_code=400, detail=f"{field_name} deve ser maior que zero")
    return number


def normalize_interface_payload(payload: SensorInterfacePayload) -> dict[str, Any]:
    data = dump_model(payload)
    data["if_index"] = non_negative_int(data.get("if_index"), "if_index")
    data["speed_in_bps"] = non_negative_int(data.get("speed_in_bps"), "speed_in_bps")
    data["speed_out_bps"] = non_negative_int(data.get("speed_out_bps"), "speed_out_bps")
    for field in ("if_name", "if_descr", "if_alias", "direction", "stats", "if_oper_status", "color"):
        data[field] = clean_text(data.get(field))
    data["monitor_enabled"] = 1 if data.get("monitor_enabled") else 0
    return {column: data[column] for column in INTERFACE_COLUMNS}


def normalize_sensor_payload(payload: SensorPayload) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    data = dump_model(payload)
    name = clean_text(data.get("name"))
    if not name:
        raise HTTPException(status_code=400, detail="Sensor Name obrigatorio")

    data["name"] = name
    data["listener_ip"] = optional_ip(data.get("listener_ip"), "listener_ip")
    data["exporter_ip"] = optional_ip(data.get("exporter_ip"), "exporter_ip")
    data["snmp_ip"] = optional_ip(data.get("snmp_ip"), "snmp_ip")
    data["listener_port"] = bounded_port(data.get("listener_port"), "listener_port")
    data["snmp_port"] = bounded_port(data.get("snmp_port"), "snmp_port")
    data["granularity_seconds"] = positive_int(data.get("granularity_seconds"), "granularity_seconds")
    data["snmp_polling_seconds"] = positive_int(data.get("snmp_polling_seconds"), "snmp_polling_seconds")

    for field in SENSOR_COLUMNS:
        if field in SENSOR_BOOL_COLUMNS:
            data[field] = 1 if data.get(field) else 0
        elif field not in {"listener_port", "snmp_port", "granularity_seconds", "snmp_polling_seconds"}:
            data[field] = clean_text(data.get(field))

    interfaces = [
        normalize_interface_payload(interface)
        for interface in payload.interfaces
    ]
    return {column: data[column] for column in SENSOR_COLUMNS}, interfaces


def interface_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["monitor_enabled"] = bool(item["monitor_enabled"])
    return item


def interface_display_name(interface: sqlite3.Row | dict[str, Any]) -> str:
    return (
        clean_text(interface["if_alias"])
        or clean_text(interface["if_name"])
        or clean_text(interface["if_descr"])
        or f"ifIndex {interface['if_index']}"
    )


def interface_dashboard_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = interface_row_to_dict(row)
    item["name"] = interface_display_name(item)
    return item


def sensor_row_to_dict(conn: sqlite3.Connection, row: sqlite3.Row, include_interfaces: bool = True) -> dict[str, Any]:
    item = dict(row)
    for field in SENSOR_BOOL_COLUMNS:
        item[field] = bool(item[field])
    if include_interfaces:
        interface_rows = conn.execute(
            """
            SELECT *
            FROM sensor_interfaces
            WHERE sensor_id = ?
            ORDER BY if_index, id
            """,
            (item["id"],),
        ).fetchall()
        item["interfaces"] = [interface_row_to_dict(interface_row) for interface_row in interface_rows]
    return item


def fetch_sensor(conn: sqlite3.Connection, sensor_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM sensors WHERE id = ?", (sensor_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Sensor nao encontrado")
    return sensor_row_to_dict(conn, row)


def fetch_sensor_without_interfaces(conn: sqlite3.Connection, sensor_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM sensors WHERE id = ?", (sensor_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Sensor nao encontrado")
    return sensor_row_to_dict(conn, row, include_interfaces=False)


def validate_active_sensor_listener(
    conn: sqlite3.Connection,
    sensor_data: dict[str, Any],
    sensor_id: int | None = None,
) -> None:
    if not bool(sensor_data.get("active")):
        return

    listener_port = int(sensor_data.get("listener_port") or 0)
    if listener_port < 1024 or listener_port > 65535:
        raise HTTPException(status_code=400, detail="Sensor ativo precisa usar listener_port entre 1024 e 65535")
    if not clean_text(sensor_data.get("exporter_ip")):
        raise HTTPException(status_code=400, detail="Sensor ativo precisa ter exporter_ip valido")

    params: list[Any] = [listener_port]
    filters = ["active = 1", "listener_port = ?"]
    if sensor_id is not None:
        filters.append("id <> ?")
        params.append(sensor_id)

    duplicate = conn.execute(
        f"""
        SELECT id, name
        FROM sensors
        WHERE {' AND '.join(filters)}
        LIMIT 1
        """,
        params,
    ).fetchone()
    if duplicate is not None:
        raise HTTPException(
            status_code=400,
            detail=f"Listener Port {listener_port} ja esta em uso pelo sensor ativo {duplicate['name']}",
        )


def user_row_to_public(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "username": row["username"],
        "role": row["role"],
        "must_change_password": bool(row["must_change_password"]),
    }


def fetch_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()


def fetch_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()


def create_access_token(user: sqlite3.Row | dict[str, Any]) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(hours=AUTH_TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "exp": expires_at,
    }
    return jwt.encode(payload, AUTH_SECRET, algorithm=AUTH_ALGORITHM)


def unauthorized_response() -> JSONResponse:
    return JSONResponse({"detail": "Unauthorized"}, status_code=401)


def token_user_from_request(request: Request) -> sqlite3.Row | None:
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    try:
        payload = jwt.decode(token, AUTH_SECRET, algorithms=[AUTH_ALGORITHM])
        user_id = int(payload.get("sub") or 0)
    except (JWTError, TypeError, ValueError):
        return None
    ensure_sensor_db()
    with sqlite_connection() as conn:
        user = fetch_user_by_id(conn, user_id)
    if user is None or not bool(user["active"]):
        return None
    return user


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS" or path == "/health" or path == "/api/auth/login" or not path.startswith("/api/"):
        return await call_next(request)

    user = token_user_from_request(request)
    if user is None:
        return unauthorized_response()

    request.state.user = user_row_to_public(user)
    if bool(user["must_change_password"]) and path not in {
        "/api/auth/me",
        "/api/auth/logout",
        "/api/auth/change-password",
    }:
        return JSONResponse({"detail": "Password change required"}, status_code=403)

    return await call_next(request)


def require_admin(request: Request) -> None:
    user = getattr(request.state, "user", None)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")


def collectors_dir() -> Path:
    return COLLECTORS_DIR


def collectors_compose_path() -> Path:
    return collectors_dir() / COLLECTORS_COMPOSE_FILE


def collector_sensor_runtime_dir(sensor_id: int) -> str:
    return f"{COLLECTORS_RUNTIME_DIR}/sensor-{sensor_id}"


def collector_allow_file_path(sensor_id: int) -> str:
    return f"{collector_sensor_runtime_dir(sensor_id)}/allow.lst"


def yaml_quote(value: Any) -> str:
    text = str(value)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def active_collector_sensors(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, name, exporter_ip, listener_port, active
        FROM sensors
        WHERE active = 1
        ORDER BY listener_port, id
        """
    ).fetchall()
    sensors = [dict(row) for row in rows]
    seen_ports: dict[int, str] = {}
    for sensor in sensors:
        validate_active_sensor_listener(conn, sensor, int(sensor["id"]))
        port = int(sensor["listener_port"])
        if port in seen_ports:
            raise HTTPException(status_code=400, detail=f"Listener Port {port} duplicado entre sensores ativos")
        seen_ports[port] = sensor["name"]
    return sensors


def nfacctd_config(sensor: dict[str, Any]) -> str:
    sensor_id = int(sensor["id"])
    listener_port = int(sensor["listener_port"])
    output_file = f"/var/spool/pmacct/sensor-{sensor_id}-{listener_port}.csv"
    allow_file = collector_allow_file_path(sensor_id)
    return f"""! Auto-generated by GMJ-FLOW. Do not edit manually.
debug: false
daemonize: false
files_umask: 002

nfacctd_ip: 0.0.0.0
nfacctd_port: {listener_port}
nfacctd_allow_file: {allow_file}
nfacctd_time_secs: true
nfacctd_time_new: true
timestamps_secs: true
timestamps_utc: true

plugins: print[flows]
aggregate[flows]: src_host, dst_host, src_port, dst_port, proto, tcpflags, in_iface, out_iface, timestamp_start
print_output[flows]: csv
print_output_file[flows]: {output_file}
print_output_file_append[flows]: true
print_refresh_time[flows]: 5
print_startup_delay[flows]: 1
"""


def compose_for_collectors(sensors: list[dict[str, Any]]) -> str:
    lines = [
        "# Auto-generated by GMJ-FLOW. Do not edit manually.",
        "services:",
        "  pmacct:",
        "    profiles:",
        "      - legacy-collector",
        "  pmacct-parser:",
        "    profiles:",
        "      - legacy-collector",
    ]
    for sensor in sensors:
        sensor_id = int(sensor["id"])
        port = int(sensor["listener_port"])
        sensor_service = f"pmacct-sensor-{sensor_id}"
        parser_service = f"pmacct-parser-sensor-{sensor_id}"
        output_file = f"/var/spool/pmacct/sensor-{sensor_id}-{port}.csv"
        config_file = f"{collector_sensor_runtime_dir(sensor_id)}/nfacctd.conf"
        lines.extend(
            [
                f"  {sensor_service}:",
                "    build:",
                "      context: ./collector/pmacct",
                f"    command: [\"nfacctd\", \"-f\", {yaml_quote(config_file)}]",
                "    ports:",
                f"      - {yaml_quote(f'{port}:{port}/udp')}",
                "    volumes:",
                "      - backend_data:/app/data:ro",
                "      - pmacct_spool:/var/spool/pmacct",
                "    depends_on:",
                "      clickhouse:",
                "        condition: service_healthy",
                "    restart: unless-stopped",
                f"  {parser_service}:",
                "    build:",
                "      context: ./collector/pmacct",
                "    command: [\"python3\", \"/opt/gmj-flow/parse_pmacct.py\"]",
                "    environment:",
                "      CLICKHOUSE_HOST: clickhouse",
                "      CLICKHOUSE_PORT: 8123",
                "      CLICKHOUSE_USER: ${CLICKHOUSE_USER-default}",
                "      CLICKHOUSE_PASSWORD: ${CLICKHOUSE_PASSWORD-}",
                "      CLICKHOUSE_DATABASE: ${CLICKHOUSE_DATABASE-flowdb}",
                f"      PMACCT_OUTPUT_FILE: {yaml_quote(output_file)}",
                "      PMACCT_OUTPUT_FORMAT: csv",
                "      PMACCT_CSV_DELIMITER: \",\"",
                "      PMACCT_CSV_FIELDS: src_host,dst_host,src_port,dst_port,proto,tcpflags,in_iface,out_iface,timestamp_start,packets,bytes,flows",
                f"      PMACCT_EXPORTER_IP: {yaml_quote(sensor['exporter_ip'])}",
                f"      PMACCT_SENSOR: {yaml_quote(sensor['name'])}",
                "      PMACCT_SAMPLE_RATE: 1",
                "      PMACCT_PARSER_BATCH_SIZE: ${PMACCT_PARSER_BATCH_SIZE-1000}",
                "      PMACCT_PARSER_FLUSH_SECONDS: ${PMACCT_PARSER_FLUSH_SECONDS-5}",
                "    volumes:",
                "      - pmacct_spool:/var/spool/pmacct",
                "    depends_on:",
                "      clickhouse:",
                "        condition: service_healthy",
                f"      {sensor_service}:",
                "        condition: service_started",
                "    restart: unless-stopped",
            ]
        )
    lines.extend(
        [
            "volumes:",
            "  backend_data:",
            "  pmacct_spool:",
            "",
        ]
    )
    return "\n".join(lines)


def apply_collectors_script_path() -> Path | None:
    configured = clean_text(os.getenv("GMJFLOW_APPLY_COLLECTORS_SCRIPT"))
    if configured:
        return Path(configured)
    if DEFAULT_COLLECTOR_APPLY_SCRIPT.exists():
        return DEFAULT_COLLECTOR_APPLY_SCRIPT
    return None


def run_apply_collectors_script(compose_path: Path) -> dict[str, Any]:
    script = apply_collectors_script_path()
    if script is None:
        return {
            "services_updated": False,
            "message": "Script de aplicacao nao configurado; arquivos gerados.",
            "stdout": "",
            "stderr": "",
            "returncode": None,
        }
    if not script.exists():
        return {
            "services_updated": False,
            "message": f"Script de aplicacao nao encontrado: {script}",
            "stdout": "",
            "stderr": "",
            "returncode": None,
        }
    command = ["sh", str(script), str(compose_path)] if script.suffix == ".sh" else [str(script), str(compose_path)]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except Exception as exc:
        return {
            "services_updated": False,
            "message": f"Falha ao executar script de aplicacao: {exc}",
            "stdout": "",
            "stderr": "",
            "returncode": None,
        }
    return {
        "services_updated": result.returncode == 0,
        "message": "Collectors atualizados" if result.returncode == 0 else "Script de aplicacao retornou erro",
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def replace_sensor_interfaces(conn: sqlite3.Connection, sensor_id: int, interfaces: list[dict[str, Any]], now: str) -> None:
    conn.execute("DELETE FROM sensor_interfaces WHERE sensor_id = ?", (sensor_id,))
    if not interfaces:
        return
    columns = ["sensor_id", *INTERFACE_COLUMNS, "created_at", "updated_at"]
    placeholders = ", ".join("?" for _ in columns)
    conn.executemany(
        f"INSERT INTO sensor_interfaces ({', '.join(columns)}) VALUES ({placeholders})",
        [
            [sensor_id, *[interface[column] for column in INTERFACE_COLUMNS], now, now]
            for interface in interfaces
        ],
    )


class SnmpQueryError(Exception):
    pass


def snmp_action_dict(payload: SnmpActionPayload | None) -> dict[str, Any]:
    return dump_model(payload) if payload is not None else {}


def normalize_snmp_version(value: Any) -> str:
    text = clean_text(value).lower()
    if text in {"3", "v3", "snmpv3", "snmp version 3"}:
        return "3"
    if text in {"1", "v1", "snmpv1", "snmp version 1"}:
        return "1"
    return "2c"


def snmp_config(sensor: dict[str, Any], payload: SnmpActionPayload | None) -> dict[str, Any]:
    action = snmp_action_dict(payload)
    target_ip = clean_text(action.get("snmp_ip")) or sensor.get("snmp_ip") or sensor.get("exporter_ip")
    target_ip = clean_text(target_ip)
    if not target_ip:
        raise SnmpQueryError("SNMP IP nao informado")
    try:
        target_ip = str(ip_address(target_ip))
    except ValueError:
        raise SnmpQueryError("SNMP IP invalido") from None

    target_port = action.get("snmp_port") or sensor.get("snmp_port") or 161
    try:
        target_port = int(target_port)
    except (TypeError, ValueError):
        raise SnmpQueryError("SNMP port invalido") from None
    if target_port < 1 or target_port > 65535:
        raise SnmpQueryError("SNMP port fora da faixa 1-65535")

    timeout_seconds = action.get("timeout_seconds") or os.getenv("SNMP_TIMEOUT_SECONDS", "2")
    retries = action.get("retries") if action.get("retries") is not None else os.getenv("SNMP_RETRIES", "1")
    try:
        timeout_seconds = float(timeout_seconds)
        retries = int(retries)
    except (TypeError, ValueError):
        raise SnmpQueryError("timeout/retries SNMP invalidos") from None
    timeout_seconds = max(0.5, min(timeout_seconds, 30.0))
    retries = max(0, min(retries, 5))

    return {
        "ip": target_ip,
        "port": target_port,
        "version": normalize_snmp_version(action.get("snmp_version") or sensor.get("snmp_version")),
        "community": clean_text(action.get("snmp_community")) or sensor.get("snmp_community") or "public",
        "security_level": clean_text(action.get("snmp_security_level")) or sensor.get("snmp_security_level") or "noAuthNoPriv",
        "security_name": clean_text(action.get("snmp_security_name")) or sensor.get("snmp_security_name") or "",
        "auth_protocol": clean_text(action.get("snmp_auth_protocol")) or sensor.get("snmp_auth_protocol") or "",
        "auth_passphrase": clean_text(action.get("snmp_auth_passphrase")) or sensor.get("snmp_auth_passphrase") or "",
        "privacy_protocol": clean_text(action.get("snmp_privacy_protocol")) or sensor.get("snmp_privacy_protocol") or "",
        "privacy_passphrase": clean_text(action.get("snmp_privacy_passphrase")) or sensor.get("snmp_privacy_passphrase") or "",
        "timeout_seconds": timeout_seconds,
        "retries": retries,
    }


def load_pysnmp_api():
    try:
        return import_module("pysnmp.hlapi.v3arch.asyncio")
    except ModuleNotFoundError as exc:
        raise SnmpQueryError("pysnmp nao instalado no backend") from exc


def snmp_protocol_constant(api: Any, protocol_name: str, mapping: dict[str, str], default_name: str) -> Any:
    key = clean_text(protocol_name).lower()
    attr_name = mapping.get(key, default_name)
    return getattr(api, attr_name)


def snmp_auth_data(api: Any, config: dict[str, Any]) -> Any:
    version = config["version"]
    if version in {"1", "2c"}:
        return api.CommunityData(config["community"], mpModel=0 if version == "1" else 1)

    if version != "3":
        raise SnmpQueryError(f"Versao SNMP nao suportada: {version}")

    security_name = clean_text(config.get("security_name"))
    if not security_name:
        raise SnmpQueryError("SNMPv3 Security Name obrigatorio")

    security_level = clean_text(config.get("security_level")).lower()
    auth_map = {
        "md5": "usmHMACMD5AuthProtocol",
        "sha": "usmHMACSHAAuthProtocol",
        "sha1": "usmHMACSHAAuthProtocol",
        "sha256": "usmHMAC192SHA256AuthProtocol",
    }
    privacy_map = {
        "des": "usmDESPrivProtocol",
        "aes": "usmAesCfb128Protocol",
        "aes128": "usmAesCfb128Protocol",
        "aes192": "usmAesCfb192Protocol",
        "aes256": "usmAesCfb256Protocol",
    }
    kwargs: dict[str, Any] = {
        "authProtocol": getattr(api, "usmNoAuthProtocol"),
        "privProtocol": getattr(api, "usmNoPrivProtocol"),
    }

    if security_level in {"authnopriv", "authpriv"}:
        auth_passphrase = clean_text(config.get("auth_passphrase"))
        if not auth_passphrase:
            raise SnmpQueryError("SNMPv3 Auth Passphrase obrigatoria")
        kwargs["authKey"] = auth_passphrase
        kwargs["authProtocol"] = snmp_protocol_constant(
            api,
            config.get("auth_protocol"),
            auth_map,
            "usmHMACSHAAuthProtocol",
        )

    if security_level == "authpriv":
        privacy_passphrase = clean_text(config.get("privacy_passphrase"))
        if not privacy_passphrase:
            raise SnmpQueryError("SNMPv3 Privacy Passphrase obrigatoria")
        kwargs["privKey"] = privacy_passphrase
        kwargs["privProtocol"] = snmp_protocol_constant(
            api,
            config.get("privacy_protocol"),
            privacy_map,
            "usmAesCfb128Protocol",
        )

    return api.UsmUserData(security_name, **kwargs)


async def snmp_transport(api: Any, config: dict[str, Any]) -> Any:
    return await api.UdpTransportTarget.create(
        (config["ip"], config["port"]),
        timeout=config["timeout_seconds"],
        retries=config["retries"],
    )


def snmp_value_text(value: Any) -> str:
    if value is None:
        return ""
    if hasattr(value, "prettyPrint"):
        return value.prettyPrint()
    return str(value)


def snmp_value_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        text = snmp_value_text(value)
        try:
            return int(text)
        except ValueError:
            return default


def is_snmp_exception_value(value: Any) -> bool:
    return value.__class__.__name__ in {"NoSuchObject", "NoSuchInstance", "EndOfMibView"}


def snmp_varbind_pair(var_bind: Any) -> tuple[Any, Any]:
    try:
        oid, value = var_bind
        return oid, value
    except (TypeError, ValueError):
        return var_bind[0], var_bind[1]


def check_snmp_response(error_indication: Any, error_status: Any, error_index: Any, var_binds: Any) -> None:
    if error_indication:
        raise SnmpQueryError(str(error_indication))
    if error_status:
        status = error_status.prettyPrint() if hasattr(error_status, "prettyPrint") else str(error_status)
        try:
            index = int(error_index)
        except (TypeError, ValueError):
            index = 0
        oid = ""
        if index and var_binds:
            try:
                oid = f" em {var_binds[index - 1][0]}"
            except Exception:
                oid = ""
        raise SnmpQueryError(f"{status}{oid}")


def oid_index(base_oid: str, oid: Any) -> int | None:
    oid_text = str(oid)
    prefix = f"{base_oid}."
    if not oid_text.startswith(prefix):
        return None
    suffix = oid_text[len(prefix):]
    if not suffix:
        return None
    try:
        return int(suffix.split(".")[0])
    except ValueError:
        return None


async def snmp_get_system(config: dict[str, Any]) -> dict[str, str]:
    api = load_pysnmp_api()
    snmp_engine = api.SnmpEngine()
    try:
        auth_data = snmp_auth_data(api, config)
        transport = await snmp_transport(api, config)
        context = api.ContextData()
        request_timeout = config["timeout_seconds"] * (config["retries"] + 1) + 2
        oid_names = list(SNMP_SYSTEM_OIDS.keys())
        var_binds = [
            api.ObjectType(api.ObjectIdentity(SNMP_SYSTEM_OIDS[name]))
            for name in oid_names
        ]
        response = await asyncio.wait_for(
            api.get_cmd(snmp_engine, auth_data, transport, context, *var_binds, lookupMib=False),
            timeout=request_timeout,
        )
        error_indication, error_status, error_index, response_var_binds = response
        check_snmp_response(error_indication, error_status, error_index, response_var_binds)

        result: dict[str, str] = {}
        for name, var_bind in zip(oid_names, response_var_binds):
            _oid, value = snmp_varbind_pair(var_bind)
            result[name] = "" if is_snmp_exception_value(value) else snmp_value_text(value)
        return result
    finally:
        snmp_engine.close_dispatcher()


async def snmp_walk_oid(
    api: Any,
    snmp_engine: Any,
    auth_data: Any,
    transport: Any,
    context: Any,
    base_oid: str,
    max_rows: int,
) -> dict[int, Any]:
    rows: dict[int, Any] = {}
    walker = api.bulk_walk_cmd(
        snmp_engine,
        auth_data,
        transport,
        context,
        0,
        25,
        api.ObjectType(api.ObjectIdentity(base_oid)),
        lookupMib=False,
        lexicographicMode=False,
        ignoreNonIncreasingOid=True,
        maxRows=max_rows,
    )
    async for error_indication, error_status, error_index, var_binds in walker:
        check_snmp_response(error_indication, error_status, error_index, var_binds)
        for var_bind in var_binds:
            oid, value = snmp_varbind_pair(var_bind)
            index = oid_index(base_oid, oid)
            if index is None or is_snmp_exception_value(value):
                continue
            rows[index] = value
    return rows


async def snmp_discover_interfaces(config: dict[str, Any]) -> list[dict[str, Any]]:
    api = load_pysnmp_api()
    snmp_engine = api.SnmpEngine()
    try:
        auth_data = snmp_auth_data(api, config)
        transport = await snmp_transport(api, config)
        context = api.ContextData()
        max_rows = int(os.getenv("SNMP_MAX_INTERFACES", "2048"))
        max_rows = max(1, min(max_rows, 20000))

        tables = {
            name: await snmp_walk_oid(api, snmp_engine, auth_data, transport, context, oid, max_rows)
            for name, oid in SNMP_INTERFACE_OIDS.items()
        }

        indexes = set()
        for table in tables.values():
            indexes.update(table.keys())

        interfaces: list[dict[str, Any]] = []
        for table_index in sorted(indexes):
            if_index = snmp_value_int(tables["if_index"].get(table_index), table_index)
            if if_index <= 0:
                continue
            if_descr = snmp_value_text(tables["if_descr"].get(table_index)).strip()
            raw_if_name = snmp_value_text(tables["if_name"].get(table_index)).strip()
            if_alias = snmp_value_text(tables["if_alias"].get(table_index)).strip()
            display_name = if_alias or raw_if_name or if_descr or f"if{if_index}"
            high_speed_mbps = snmp_value_int(tables["if_high_speed"].get(table_index))
            speed_bps = high_speed_mbps * 1_000_000 if high_speed_mbps > 0 else snmp_value_int(
                tables["if_speed"].get(table_index)
            )
            oper_status = snmp_value_int(tables["if_oper_status"].get(table_index))
            interfaces.append(
                {
                    "if_index": if_index,
                    "if_name": display_name,
                    "if_descr": if_descr,
                    "if_alias": if_alias,
                    "direction": "Unset",
                    "stats": "Basic",
                    "speed_in_bps": speed_bps,
                    "speed_out_bps": speed_bps,
                    "if_oper_status": IF_OPER_STATUS_LABELS.get(oper_status, str(oper_status) if oper_status else ""),
                    "color": "#64748b",
                    "monitor_enabled": True,
                }
            )
        return interfaces
    finally:
        snmp_engine.close_dispatcher()


def run_snmp(coro: Any) -> Any:
    try:
        return asyncio.run(coro)
    except asyncio.TimeoutError as exc:
        raise SnmpQueryError("timeout SNMP") from exc


def upsert_discovered_interfaces(conn: sqlite3.Connection, sensor_id: int, interfaces: list[dict[str, Any]]) -> None:
    now = utc_now_iso()
    for interface in interfaces:
        if_index = non_negative_int(interface.get("if_index"), "if_index")
        if if_index <= 0:
            continue
        updates = {
            "if_name": clean_text(interface.get("if_name")),
            "if_descr": clean_text(interface.get("if_descr")),
            "if_alias": clean_text(interface.get("if_alias")),
            "speed_in_bps": non_negative_int(interface.get("speed_in_bps"), "speed_in_bps"),
            "speed_out_bps": non_negative_int(interface.get("speed_out_bps"), "speed_out_bps"),
            "if_oper_status": clean_text(interface.get("if_oper_status")),
            "updated_at": now,
        }
        rows = conn.execute(
            """
            SELECT id
            FROM sensor_interfaces
            WHERE sensor_id = ? AND if_index = ?
            ORDER BY id
            """,
            (sensor_id, if_index),
        ).fetchall()
        if rows:
            first_id = rows[0]["id"]
            conn.execute(
                """
                UPDATE sensor_interfaces
                SET if_name = ?,
                    if_descr = ?,
                    if_alias = ?,
                    speed_in_bps = ?,
                    speed_out_bps = ?,
                    if_oper_status = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    updates["if_name"],
                    updates["if_descr"],
                    updates["if_alias"],
                    updates["speed_in_bps"],
                    updates["speed_out_bps"],
                    updates["if_oper_status"],
                    updates["updated_at"],
                    first_id,
                ),
            )
            duplicate_ids = [row["id"] for row in rows[1:]]
            if duplicate_ids:
                placeholders = ", ".join("?" for _ in duplicate_ids)
                conn.execute(f"DELETE FROM sensor_interfaces WHERE id IN ({placeholders})", duplicate_ids)
        else:
            conn.execute(
                """
                INSERT INTO sensor_interfaces (
                    sensor_id,
                    if_index,
                    if_name,
                    if_descr,
                    if_alias,
                    direction,
                    stats,
                    speed_in_bps,
                    speed_out_bps,
                    if_oper_status,
                    color,
                    monitor_enabled,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sensor_id,
                    if_index,
                    updates["if_name"],
                    updates["if_descr"],
                    updates["if_alias"],
                    clean_text(interface.get("direction")) or "Unset",
                    clean_text(interface.get("stats")) or "Basic",
                    updates["speed_in_bps"],
                    updates["speed_out_bps"],
                    updates["if_oper_status"],
                    clean_text(interface.get("color")) or "#64748b",
                    1 if interface.get("monitor_enabled", True) else 0,
                    now,
                    now,
                ),
            )


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
    if getattr(parsed, "ipv4_mapped", None):
        return f"::ffff:{parsed.ipv4_mapped}"
    return str(parsed)


def whois_ip_text(value: str) -> str:
    try:
        parsed = ip_address(value.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="ip invalido") from None
    if getattr(parsed, "ipv4_mapped", None):
        return str(parsed.ipv4_mapped)
    return str(parsed)


def is_public_ip(value: str) -> bool:
    parsed = ip_address(value)
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_multicast
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def cached_whois(ip: str) -> dict[str, Any] | None:
    item = WHOIS_CACHE.get(ip)
    if not item:
        return None
    if float(item.get("expires_at", 0)) <= time.time():
        WHOIS_CACHE.pop(ip, None)
        return None
    data = item.get("data")
    return data if isinstance(data, dict) else None


def cache_whois(ip: str, data: dict[str, Any]) -> dict[str, Any]:
    WHOIS_CACHE[ip] = {
        "expires_at": time.time() + WHOIS_CACHE_TTL_SECONDS,
        "data": data,
    }
    return data


def reverse_dns_lookup(ip: str) -> str | None:
    previous_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(3)
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
        return clean_text(hostname) or None
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)


def fetch_json_url(url: str, timeout: int = 4) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "GMJ-FLOW/0.1",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read()
    data = json.loads(payload.decode("utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ValueError("resposta invalida")
    return data


def rdap_link(data: dict[str, Any]) -> str:
    for link in data.get("links") or []:
        if not isinstance(link, dict):
            continue
        href = clean_text(link.get("href"))
        if href and (link.get("rel") == "self" or not link.get("rel")):
            return href
    return ""


def vcard_values(entity: dict[str, Any], key: str) -> list[str]:
    values = []
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return values
    for entry in vcard[1]:
        if not isinstance(entry, list) or len(entry) < 4 or entry[0] != key:
            continue
        value = entry[3]
        if isinstance(value, list):
            value = " ".join(clean_text(part) for part in value if clean_text(part))
        value_text = clean_text(value)
        if value_text:
            values.append(value_text)
    return values


def rdap_entity(entity: dict[str, Any]) -> dict[str, Any]:
    names = [*vcard_values(entity, "fn"), *vcard_values(entity, "org")]
    emails = vcard_values(entity, "email")
    return {
        "handle": clean_text(entity.get("handle")),
        "roles": [clean_text(role) for role in entity.get("roles") or [] if clean_text(role)],
        "name": names[0] if names else "",
        "email": emails[0] if emails else None,
    }


def rdap_entities(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        rdap_entity(entity)
        for entity in data.get("entities") or []
        if isinstance(entity, dict)
    ]


def rdap_organization(rdap_name: str, entities: list[dict[str, Any]]) -> str:
    for entity in entities:
        roles = {role.lower() for role in entity.get("roles") or []}
        if "registrant" in roles and clean_text(entity.get("name")):
            return clean_text(entity.get("name"))
    for entity in entities:
        name = clean_text(entity.get("name"))
        if name:
            return name
    return rdap_name


def geo_response(ip: str) -> tuple[dict[str, Any], str | None]:
    geo_url = (
        f"http://ip-api.com/json/{urllib.parse.quote(ip, safe=':.')}"
        "?fields=status,message,country,regionName,city,as,org,query"
    )
    try:
        data = fetch_json_url(geo_url, timeout=4)
    except Exception as exc:
        return {}, f"Falha ao consultar geolocalizacao: {exc}"
    if data.get("status") != "success":
        message = clean_text(data.get("message")) or "resposta sem sucesso"
        return {}, f"Falha ao consultar geolocalizacao: {message}"
    return data, None


def rdap_response(
    ip: str,
    data: dict[str, Any],
    reverse_dns: str | None,
    geo: dict[str, Any] | None = None,
    geo_message: str | None = None,
) -> dict[str, Any]:
    geo = geo or {}
    entities = rdap_entities(data)
    rdap_name = clean_text(data.get("name"))
    organization = rdap_organization(rdap_name, entities)
    if not organization:
        organization = clean_text(geo.get("org"))

    country = clean_text(geo.get("country")) or clean_text(data.get("country"))
    messages = [message for message in [geo_message] if message]

    response = {
        "ip": ip,
        "type": "public",
        "is_public": True,
        "ok": True,
        "reverse_dns": reverse_dns,
        "country": country or None,
        "region": clean_text(geo.get("regionName")) or None,
        "city": clean_text(geo.get("city")) or None,
        "asn": clean_text(geo.get("as")) or None,
        "organization": organization or None,
        "rdap_name": rdap_name or None,
        "entities": entities,
        "messages": messages,
        "message": "; ".join(messages) if messages else "",
        "raw": data,
    }
    return response


def rdap_failure_response(
    ip: str,
    reverse_dns: str | None,
    message: str,
    geo: dict[str, Any] | None = None,
    geo_message: str | None = None,
) -> dict[str, Any]:
    geo = geo or {}
    messages = [message, *([geo_message] if geo_message else [])]
    return {
        "ip": ip,
        "type": "public",
        "is_public": True,
        "ok": False,
        "reverse_dns": reverse_dns,
        "country": clean_text(geo.get("country")) or None,
        "region": clean_text(geo.get("regionName")) or None,
        "city": clean_text(geo.get("city")) or None,
        "asn": clean_text(geo.get("as")) or None,
        "organization": clean_text(geo.get("org")) or None,
        "rdap_name": None,
        "entities": [],
        "messages": messages,
        "message": "; ".join(messages),
    }


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
        alive = ping_clickhouse()
    except Exception as exc:  # pragma: no cover - exposed as health detail.
        raise HTTPException(status_code=503, detail=f"ClickHouse indisponivel: {exc}") from exc
    return {"status": "ok", "clickhouse": "ok" if alive else "failed"}


@app.post("/api/auth/login")
def auth_login(payload: LoginPayload):
    ensure_sensor_db()
    username = clean_text(payload.username)
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    with sqlite_connection() as conn:
        user = fetch_user_by_username(conn, username)
    if user is None or not bool(user["active"]) or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {
        "ok": True,
        "user": user_row_to_public(user),
        "token": create_access_token(user),
    }


@app.get("/api/auth/me")
def auth_me(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"ok": True, "user": user}


@app.post("/api/auth/logout")
def auth_logout():
    return {"ok": True}


@app.post("/api/auth/change-password")
def auth_change_password(request: Request, payload: ChangePasswordPayload):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    new_password = payload.new_password or ""
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Nova senha deve ter pelo menos 8 caracteres")
    ensure_sensor_db()
    with sqlite_connection() as conn:
        row = fetch_user_by_id(conn, int(user["id"]))
        if row is None or not bool(row["active"]):
            raise HTTPException(status_code=401, detail="Unauthorized")
        if not verify_password(payload.current_password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="Senha atual invalida")
        now = utc_now_iso()
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?,
                must_change_password = 0,
                updated_at = ?
            WHERE id = ?
            """,
            (hash_password(new_password), now, int(user["id"])),
        )
        conn.commit()
        updated = fetch_user_by_id(conn, int(user["id"]))
        if updated is None:
            raise HTTPException(status_code=401, detail="Unauthorized")
    return {
        "ok": True,
        "user": user_row_to_public(updated),
        "token": create_access_token(updated),
    }


@app.post("/api/collectors/apply")
def apply_collectors(request: Request):
    require_admin(request)
    ensure_sensor_db()
    output_dir = collectors_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    with sqlite_connection() as conn:
        sensors = active_collector_sensors(conn)

    configs = []
    for sensor in sensors:
        sensor_id = int(sensor["id"])
        port = int(sensor["listener_port"])
        sensor_dir = output_dir / f"sensor-{sensor_id}"
        sensor_dir.mkdir(parents=True, exist_ok=True)
        config_path = sensor_dir / "nfacctd.conf"
        allow_path = sensor_dir / "allow.lst"
        allow_file = collector_allow_file_path(sensor_id)
        allow_path.write_text(f"{sensor['exporter_ip']}\n", encoding="utf-8")
        config_path.write_text(nfacctd_config(sensor), encoding="utf-8")
        configs.append(
            {
                "sensor_id": sensor_id,
                "sensor": sensor["name"],
                "exporter_ip": sensor["exporter_ip"],
                "listener_port": port,
                "nfacctd_config": str(config_path),
                "allow_file": allow_file,
                "output_file": f"/var/spool/pmacct/sensor-{sensor_id}-{port}.csv",
                "services": [f"pmacct-sensor-{sensor_id}", f"pmacct-parser-sensor-{sensor_id}"],
            }
        )

    compose_path = collectors_compose_path()
    compose_path.write_text(compose_for_collectors(sensors), encoding="utf-8")
    apply_result = run_apply_collectors_script(compose_path)

    return {
        "ok": True,
        "collectors_dir": str(output_dir),
        "compose_file": str(compose_path),
        "configs_generated": configs,
        "services_updated": apply_result["services_updated"],
        "apply": apply_result,
        "errors": [] if apply_result["services_updated"] else [apply_result["message"]],
    }


@app.get("/api/ip/whois")
def ip_whois(ip: str = Query(..., min_length=2)):
    ip_text = whois_ip_text(ip)
    cached = cached_whois(ip_text)
    if cached is not None:
        return cached

    reverse_dns = reverse_dns_lookup(ip_text)

    if not is_public_ip(ip_text):
        return cache_whois(
            ip_text,
            {
                "ip": ip_text,
                "type": "private",
                "is_public": False,
                "ok": True,
                "reverse_dns": reverse_dns,
                "country": None,
                "region": None,
                "city": None,
                "asn": None,
                "organization": None,
                "message": "IP privado/local. Nao possui WHOIS publico.",
            },
        )

    geo, geo_message = geo_response(ip_text)
    rdap_url = f"https://rdap.org/ip/{urllib.parse.quote(ip_text, safe=':.')}"
    try:
        data = fetch_json_url(rdap_url, timeout=4)
    except urllib.error.HTTPError as exc:
        return rdap_failure_response(
            ip_text,
            reverse_dns,
            f"Falha ao consultar RDAP: HTTP {exc.code}",
            geo,
            geo_message,
        )
    except urllib.error.URLError as exc:
        return rdap_failure_response(
            ip_text,
            reverse_dns,
            f"Falha ao consultar RDAP: {exc.reason}",
            geo,
            geo_message,
        )
    except Exception as exc:
        return rdap_failure_response(
            ip_text,
            reverse_dns,
            f"Falha ao consultar RDAP: {exc}",
            geo,
            geo_message,
        )

    return cache_whois(ip_text, rdap_response(ip_text, data, reverse_dns, geo, geo_message))


@app.get("/api/sensors")
def list_sensors():
    ensure_sensor_db()
    with sqlite_connection() as conn:
        rows = conn.execute("SELECT * FROM sensors ORDER BY name, id").fetchall()
        return {"items": [sensor_row_to_dict(conn, row) for row in rows]}


@app.get("/api/dashboard/sensors")
def list_dashboard_sensors():
    ensure_sensor_db()
    with sqlite_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, name, exporter_ip
            FROM sensors
            WHERE active = 1
            ORDER BY name, id
            """
        ).fetchall()
        return {"items": [dict(row) for row in rows]}


@app.post("/api/sensors", status_code=201)
def create_sensor(payload: SensorPayload):
    ensure_sensor_db()
    sensor_data, interfaces = normalize_sensor_payload(payload)
    now = utc_now_iso()
    columns = [*SENSOR_COLUMNS, "created_at", "updated_at"]
    placeholders = ", ".join("?" for _ in columns)
    values = [*[sensor_data[column] for column in SENSOR_COLUMNS], now, now]

    with sqlite_connection() as conn:
        validate_active_sensor_listener(conn, sensor_data)
        cursor = conn.execute(
            f"INSERT INTO sensors ({', '.join(columns)}) VALUES ({placeholders})",
            values,
        )
        sensor_id = int(cursor.lastrowid)
        replace_sensor_interfaces(conn, sensor_id, interfaces, now)
        conn.commit()
        return fetch_sensor(conn, sensor_id)


@app.get("/api/sensors/{sensor_id}")
def get_sensor(sensor_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        return fetch_sensor(conn, sensor_id)


@app.get("/api/sensors/{sensor_id}/interfaces")
def list_sensor_interfaces(sensor_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_sensor_without_interfaces(conn, sensor_id)
        rows = conn.execute(
            """
            SELECT *
            FROM sensor_interfaces
            WHERE sensor_id = ? AND monitor_enabled = 1
            ORDER BY if_index, id
            """,
            (sensor_id,),
        ).fetchall()
        return {"items": [interface_dashboard_row_to_dict(row) for row in rows]}


@app.put("/api/sensors/{sensor_id}")
def update_sensor(sensor_id: int, payload: SensorPayload):
    ensure_sensor_db()
    sensor_data, interfaces = normalize_sensor_payload(payload)
    now = utc_now_iso()
    assignments = ", ".join(f"{column} = ?" for column in SENSOR_COLUMNS)
    values = [*[sensor_data[column] for column in SENSOR_COLUMNS], now, sensor_id]

    with sqlite_connection() as conn:
        existing = conn.execute("SELECT id FROM sensors WHERE id = ?", (sensor_id,)).fetchone()
        if existing is None:
            raise HTTPException(status_code=404, detail="Sensor nao encontrado")
        validate_active_sensor_listener(conn, sensor_data, sensor_id)
        conn.execute(
            f"UPDATE sensors SET {assignments}, updated_at = ? WHERE id = ?",
            values,
        )
        replace_sensor_interfaces(conn, sensor_id, interfaces, now)
        conn.commit()
        return fetch_sensor(conn, sensor_id)


@app.delete("/api/sensors/{sensor_id}")
def delete_sensor(sensor_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        cursor = conn.execute("DELETE FROM sensors WHERE id = ?", (sensor_id,))
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Sensor nao encontrado")
        return {"status": "deleted", "id": sensor_id}


@app.post("/api/sensors/{sensor_id}/snmp/test")
def test_sensor_snmp(sensor_id: int, payload: SnmpActionPayload | None = None):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        sensor = fetch_sensor(conn, sensor_id)

    try:
        config = snmp_config(sensor, payload)
        system = run_snmp(snmp_get_system(config))
    except SnmpQueryError as exc:
        return {"ok": False, "sensor_id": sensor_id, "message": str(exc)}
    except Exception as exc:  # pragma: no cover - defensive wrapper for external SNMP stack errors.
        return {"ok": False, "sensor_id": sensor_id, "message": f"erro SNMP: {exc}"}

    return {
        "ok": True,
        "sensor_id": sensor_id,
        "target": {"ip": config["ip"], "port": config["port"]},
        "sysName": system.get("sys_name", ""),
        "sysDescr": system.get("sys_descr", ""),
        "sysObjectID": system.get("sys_object_id", ""),
        "system": system,
    }


@app.post("/api/sensors/{sensor_id}/snmp/discover-interfaces")
def discover_sensor_interfaces(sensor_id: int, payload: SnmpActionPayload | None = None):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        sensor = fetch_sensor(conn, sensor_id)

    try:
        config = snmp_config(sensor, payload)
        interfaces = run_snmp(snmp_discover_interfaces(config))
    except SnmpQueryError as exc:
        return {"ok": False, "sensor_id": sensor_id, "message": str(exc)}
    except Exception as exc:  # pragma: no cover - defensive wrapper for external SNMP stack errors.
        return {"ok": False, "sensor_id": sensor_id, "message": f"erro SNMP: {exc}"}

    with sqlite_connection() as conn:
        _ = fetch_sensor(conn, sensor_id)
        upsert_discovered_interfaces(conn, sensor_id, interfaces)
        conn.commit()

    return {
        "ok": True,
        "sensor_id": sensor_id,
        "target": {"ip": config["ip"], "port": config["port"]},
        "interfaces": interfaces,
        "items": interfaces,
    }


def raw_flow_where(
    range_minutes: int,
    sensor: str | None,
    params: dict[str, Any],
    exporter_ip: str | None = None,
) -> str:
    safe_range_minutes = max(1, min(int(range_minutes), 10080))
    where = f"flow_time >= now() - INTERVAL {safe_range_minutes} MINUTE"
    if exporter_ip:
        params["exporter_ip"] = clickhouse_ip_string_param(exporter_ip, "exporter_ip")
        where += " AND toString(exporter_ip) = {exporter_ip:String}"
    elif sensor:
        params["sensor"] = sensor
        where += " AND sensor = {sensor:String}"
    return where


def sensor_exporter_ip(sensor_id: int) -> str:
    ensure_sensor_db()
    with sqlite_connection() as conn:
        sensor = fetch_sensor_without_interfaces(conn, sensor_id)
    exporter_ip = clean_text(sensor.get("exporter_ip"))
    if not exporter_ip:
        raise HTTPException(status_code=400, detail="Sensor sem exporter_ip configurado")
    return exporter_ip


def traffic_items(metric: str, range_minutes: int, sensor: str | None):
    params: dict[str, Any] = {}
    where = raw_flow_where(range_minutes, sensor, params)
    value_expr = "sum(bytes) * 8 / 60" if metric == "bps" else "sum(packets) / 60"
    result = query_clickhouse(
        f"""
        SELECT
            toStartOfMinute(flow_time) AS time,
            {value_expr} AS {metric}
        FROM flow_raw
        WHERE {where}
        GROUP BY time
        ORDER BY time
        """,
        params,
    )

    items = []
    for row in rows_as_dicts(result):
        items.append({"time": iso(row["time"]), metric: round(float(row[metric] or 0), 2)})
    return {"items": items}


@app.get("/api/traffic/bps")
def get_bps(
    range_minutes: int = Query(60, ge=1, le=10080),
    sensor: str | None = None,
):
    return traffic_items("bps", range_minutes, sensor)


@app.get("/api/traffic/pps")
def get_pps(
    range_minutes: int = Query(60, ge=1, le=10080),
    sensor: str | None = None,
):
    return traffic_items("pps", range_minutes, sensor)


def monitored_sensor_interfaces(
    conn: sqlite3.Connection,
    sensor_id: int,
    interface_id: int | None = None,
    if_index: int | None = None,
) -> list[dict[str, Any]]:
    filters = ["sensor_id = ?", "monitor_enabled = 1"]
    values: list[Any] = [sensor_id]
    if interface_id is not None:
        filters.append("id = ?")
        values.append(interface_id)
    if if_index is not None:
        filters.append("if_index = ?")
        values.append(if_index)

    rows = conn.execute(
        f"""
        SELECT *
        FROM sensor_interfaces
        WHERE {' AND '.join(filters)}
        ORDER BY if_index, id
        """,
        values,
    ).fetchall()
    return [interface_dashboard_row_to_dict(row) for row in rows]


def interface_traffic_items(
    metric: str,
    sensor_id: int,
    range_minutes: int,
    interface_id: int | None = None,
    if_index: int | None = None,
) -> dict[str, Any]:
    ensure_sensor_db()
    with sqlite_connection() as conn:
        sensor = fetch_sensor_without_interfaces(conn, sensor_id)
        interfaces = monitored_sensor_interfaces(conn, sensor_id, interface_id, if_index)

    exporter_ip = clean_text(sensor.get("exporter_ip"))
    if not exporter_ip:
        raise HTTPException(status_code=400, detail="Sensor sem exporter_ip configurado")

    value_expr = "sum(bytes) * 8 / 60" if metric == "bps" else "sum(packets) / 60"
    safe_range_minutes = max(1, min(int(range_minutes), 10080))
    items = []
    for interface in interfaces:
        params: dict[str, Any] = {
            "exporter_ip": clickhouse_ip_string_param(exporter_ip, "exporter_ip"),
            "if_index": int(interface["if_index"] or 0),
        }
        result = query_clickhouse(
            f"""
            SELECT
                toStartOfMinute(flow_time) AS time,
                {value_expr} AS {metric}
            FROM flow_raw
            WHERE flow_time >= now() - INTERVAL {safe_range_minutes} MINUTE
              AND toString(exporter_ip) = {{exporter_ip:String}}
              AND (input_if = {{if_index:UInt32}} OR output_if = {{if_index:UInt32}})
            GROUP BY time
            ORDER BY time
            """,
            params,
        )

        points = [
            {"time": iso(row["time"]), metric: round(float(row[metric] or 0), 2)}
            for row in rows_as_dicts(result)
        ]
        items.append(
            {
                "interface_id": interface["id"],
                "if_index": interface["if_index"],
                "interface_name": interface["name"],
                "color": interface["color"] or "#64748b",
                "points": points,
            }
        )

    return {"items": items}


@app.get("/api/traffic/interface-bps")
def get_interface_bps(
    sensor_id: int = Query(..., ge=1),
    range_minutes: int = Query(60, ge=1, le=10080),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
):
    return interface_traffic_items("bps", sensor_id, range_minutes, interface_id, if_index)


@app.get("/api/traffic/interface-pps")
def get_interface_pps(
    sensor_id: int = Query(..., ge=1),
    range_minutes: int = Query(60, ge=1, le=10080),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
):
    return interface_traffic_items("pps", sensor_id, range_minutes, interface_id, if_index)


def top_dimension(
    dimension: str,
    range_minutes: int,
    sensor: str | None,
    sensor_id: int | None,
    limit: int,
):
    seconds = max(range_minutes * 60, 1)
    params: dict[str, Any] = {"limit": limit, "seconds": seconds}
    exporter_ip = sensor_exporter_ip(sensor_id) if sensor_id is not None else None
    where = raw_flow_where(range_minutes, sensor, params, exporter_ip)

    if dimension == "src_ip":
        query = f"""
        SELECT
            toString(src_ip) AS ip,
            sum(bytes) * 8 / {{seconds:Float64}} AS bps,
            sum(packets) AS packets,
            sum(flow_count) AS flows
        FROM flow_raw
        WHERE {where}
        GROUP BY ip
        ORDER BY bps DESC
        LIMIT {{limit:UInt32}}
        """
    elif dimension == "dst_ip":
        query = f"""
        SELECT
            toString(dst_ip) AS ip,
            sum(bytes) * 8 / {{seconds:Float64}} AS bps,
            sum(packets) AS packets,
            sum(flow_count) AS flows
        FROM flow_raw
        WHERE {where}
        GROUP BY ip
        ORDER BY bps DESC
        LIMIT {{limit:UInt32}}
        """
    elif dimension == "dst_port":
        query = f"""
        SELECT
            dst_port AS port,
            proto,
            sum(bytes) * 8 / {{seconds:Float64}} AS bps,
            sum(packets) AS packets,
            sum(flow_count) AS flows
        FROM flow_raw
        WHERE {where}
        GROUP BY port, proto
        ORDER BY bps DESC
        LIMIT {{limit:UInt32}}
        """
    elif dimension == "proto":
        query = f"""
        SELECT
            proto,
            sum(bytes) * 8 / {{seconds:Float64}} AS bps,
            sum(packets) AS packets,
            sum(flow_count) AS flows
        FROM flow_raw
        WHERE {where}
        GROUP BY proto
        ORDER BY bps DESC
        LIMIT {{limit:UInt32}}
        """
    elif dimension == "tcp_flags":
        query = f"""
        SELECT
            tcp_flags,
            sum(bytes) * 8 / {{seconds:Float64}} AS bps,
            sum(packets) AS packets,
            sum(flow_count) AS flows
        FROM flow_raw
        WHERE {where}
        GROUP BY tcp_flags
        ORDER BY bps DESC
        LIMIT {{limit:UInt32}}
        """
    else:
        raise HTTPException(status_code=400, detail="dimensao invalida")

    result = query_clickhouse(query, params)
    items = []
    for row in rows_as_dicts(result):
        bps = round(float(row["bps"] or 0), 2)
        packets = int(row["packets"] or 0)
        flows = int(row["flows"] or 0)
        if dimension in {"src_ip", "dst_ip"}:
            ip = clean_ip(row["ip"])
            item = {"ip": ip, "bps": bps, "flows": flows, "packets": packets}
        elif dimension == "dst_port":
            proto = proto_name(row["proto"])
            item = {
                "port": int(row["port"] or 0),
                "proto": proto,
                "bps": bps,
                "flows": flows,
                "packets": packets,
            }
        elif dimension == "proto":
            proto = proto_name(row["proto"])
            item = {"proto": proto, "bps": bps, "flows": flows, "packets": packets}
        else:
            flags = tcp_flags_name(row["tcp_flags"])
            item = {"flags": flags, "bps": bps, "flows": flows, "packets": packets}
        items.append(item)

    return {"items": items}


@app.get("/api/tops/src-ip")
def top_src_ip(
    range_minutes: int = Query(60, ge=1, le=10080),
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("src_ip", range_minutes, sensor, sensor_id, limit)


@app.get("/api/tops/dst-ip")
def top_dst_ip(
    range_minutes: int = Query(60, ge=1, le=10080),
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("dst_ip", range_minutes, sensor, sensor_id, limit)


@app.get("/api/tops/ports")
def top_ports(
    range_minutes: int = Query(60, ge=1, le=10080),
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("dst_port", range_minutes, sensor, sensor_id, limit)


@app.get("/api/tops/protocols")
def top_protocols(
    range_minutes: int = Query(60, ge=1, le=10080),
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("proto", range_minutes, sensor, sensor_id, limit)


@app.get("/api/tops/tcp-flags")
def top_tcp_flags(
    range_minutes: int = Query(60, ge=1, le=10080),
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("tcp_flags", range_minutes, sensor, sensor_id, limit)


@app.get("/api/flows/search")
def search_flows(
    range_minutes: int = Query(60, ge=1, le=10080),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
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
    if sensor_id is not None:
        params["exporter_ip"] = clickhouse_ip_string_param(sensor_exporter_ip(sensor_id), "exporter_ip")
        filters.append("toString(exporter_ip) = {exporter_ip:String}")
    elif sensor:
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

    result = query_clickhouse(
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
        params,
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
