from __future__ import annotations

import os
import sqlite3
import asyncio
import json
import logging
import socket
import subprocess
import re
import shutil
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from importlib import import_module
from ipaddress import IPv4Address, ip_address
from pathlib import Path
from statistics import median
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

DASHBOARD_PALETTE = (
    "#0f766e",
    "#2563eb",
    "#b45309",
    "#6d28d9",
    "#15803d",
    "#b91c1c",
    "#0891b2",
    "#a16207",
    "#7c3aed",
    "#0e7490",
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

SNMP_COUNTER_OIDS = {
    "if_hc_in_octets": "1.3.6.1.2.1.31.1.1.1.6",
    "if_hc_out_octets": "1.3.6.1.2.1.31.1.1.1.10",
    "if_oper_status": SNMP_INTERFACE_OIDS["if_oper_status"],
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

CALIBRATION_METHOD = "snmp_vs_flow"
CALIBRATION_MIN_BPS = float(os.getenv("GMJFLOW_CALIBRATION_MIN_BPS", "10000"))
CALIBRATION_MIN_CONFIDENCE = float(os.getenv("GMJFLOW_CALIBRATION_MIN_CONFIDENCE", "0.6"))
SNMP_POLL_STOP = threading.Event()
SNMP_POLL_THREAD: threading.Thread | None = None

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
    "sample_rate_in",
    "sample_rate_out",
    "if_oper_status",
    "color",
    "monitor_enabled",
]

INTERFACE_BOOL_COLUMNS = {"monitor_enabled"}

WHOIS_CACHE_TTL_SECONDS = 24 * 60 * 60
WHOIS_CACHE: dict[str, dict[str, Any]] = {}
MAX_RANGE_MINUTES = int(os.getenv("GMJFLOW_MAX_RANGE_MINUTES", "259200"))
RUNTIME_DIR = Path(os.getenv("GMJFLOW_RUNTIME_DIR", "/app/runtime"))
COLLECTORS_DIR = Path(os.getenv("GMJFLOW_COLLECTORS_DIR", str(RUNTIME_DIR / "data" / "collectors")))
COLLECTORS_RUNTIME_DIR = "/app/data/collectors"
COLLECTORS_COMPOSE_FILE = "docker-compose.collectors.yml"
COLLECTORS_COMPOSE_PATH = Path(
    os.getenv("GMJFLOW_COLLECTORS_COMPOSE_PATH", str(RUNTIME_DIR / COLLECTORS_COMPOSE_FILE))
)
DEFAULT_COLLECTOR_APPLY_SCRIPT = RUNTIME_DIR / "scripts" / "apply_collectors.sh"
SERVICE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
AUTH_ALGORITHM = "HS256"
AUTH_TOKEN_EXPIRE_HOURS = 8
AUTH_SECRET = os.getenv("GMJFLOW_AUTH_SECRET")
if not AUTH_SECRET:
    AUTH_SECRET = "gmj-flow-dev-secret-change-me"
    logger.warning("GMJFLOW_AUTH_SECRET nao definido; usando segredo de desenvolvimento.")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
DATABASE_RETENTION_STOP = threading.Event()
DATABASE_RETENTION_THREAD: threading.Thread | None = None
SYSTEM_SETTING_DEFAULTS = {
    "database_retention_enabled": "1",
    "flow_retention_days": "30",
    "snmp_retention_days": "90",
    "database_last_cleanup_at": "",
    "database_cleanup_hour": "3",
}


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
    sample_rate_in: int = 1
    sample_rate_out: int = 1
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


class DatabaseRetentionPayload(BaseModel):
    enabled: bool
    retention_days: int = Field(..., ge=1, le=3650)
    snmp_retention_days: int | None = Field(None, ge=1, le=3650)
    cleanup_hour: int | None = Field(None, ge=0, le=23)


class DatabaseCleanupPayload(BaseModel):
    older_than_days: int = Field(..., ge=1, le=3650)
    optimize: bool = False
    confirm: str = ""


class DatabaseOptimizePayload(BaseModel):
    confirm: str = ""


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


def command_clickhouse(command: str, parameters: dict[str, Any] | None = None) -> Any:
    client = get_client()
    try:
        return client.command(command, parameters=parameters or {})
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
    if range_minutes < 1:
        raise HTTPException(status_code=400, detail="range_minutes deve ser maior que zero")
    if range_minutes > MAX_RANGE_MINUTES:
        raise HTTPException(
            status_code=400,
            detail=f"range_minutes nao pode exceder {MAX_RANGE_MINUTES} minutos",
        )

    start_dt = utc_dt(start)
    end_dt = utc_dt(end)
    now = datetime.now(timezone.utc)

    if end_dt is not None and end_dt > now:
        end_dt = now

    if start_dt is None and end_dt is None:
        end_dt = now
        start_dt = end_dt - timedelta(minutes=range_minutes)
    elif start_dt is None and end_dt is not None:
        start_dt = end_dt - timedelta(minutes=range_minutes)
    elif start_dt is not None and end_dt is None:
        end_dt = start_dt + timedelta(minutes=range_minutes)
        if end_dt > now:
            end_dt = now

    if start_dt is None or end_dt is None:
        raise HTTPException(status_code=400, detail="Intervalo de tempo invalido")
    if start_dt > end_dt:
        raise HTTPException(status_code=400, detail="Data inicial nao pode ser maior que a data final")
    if start_dt == end_dt:
        raise HTTPException(status_code=400, detail="Intervalo de tempo precisa ter duracao maior que zero")
    if (end_dt - start_dt).total_seconds() > MAX_RANGE_MINUTES * 60:
        raise HTTPException(
            status_code=400,
            detail=f"Periodo personalizado nao pode exceder {MAX_RANGE_MINUTES} minutos",
        )
    return start_dt, end_dt


def resolve_requested_range(
    range_minutes: int,
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> tuple[datetime, datetime]:
    return resolve_range(range_minutes, start_time or start, end_time or end)


def range_seconds(start: datetime, end: datetime) -> float:
    return max((end - start).total_seconds(), 1.0)


def flow_time_where(params: dict[str, Any], start: datetime, end: datetime) -> str:
    params["start"] = start
    params["end"] = end
    return "flow_time >= {start:DateTime} AND flow_time <= {end:DateTime}"


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


def parse_datetime_text(value: Any) -> datetime | None:
    text = clean_text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return utc_dt(parsed)


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


def ensure_sqlite_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def ensure_system_settings_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    now = utc_now_iso()
    for key, value in SYSTEM_SETTING_DEFAULTS.items():
        conn.execute(
            """
            INSERT INTO system_settings (key, value, updated_at)
            SELECT ?, ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM system_settings WHERE key = ?
            )
            """,
            (key, value, now, key),
        )


def get_system_settings(conn: sqlite3.Connection) -> dict[str, str]:
    ensure_system_settings_table(conn)
    rows = conn.execute("SELECT key, value FROM system_settings").fetchall()
    settings = {key: value for key, value in SYSTEM_SETTING_DEFAULTS.items()}
    settings.update({row["key"]: row["value"] for row in rows})
    return settings


def set_system_settings(conn: sqlite3.Connection, values: dict[str, Any]) -> None:
    ensure_system_settings_table(conn)
    now = utc_now_iso()
    for key, value in values.items():
        if key not in SYSTEM_SETTING_DEFAULTS:
            raise HTTPException(status_code=400, detail=f"Configuracao invalida: {key}")
        conn.execute(
            """
            INSERT INTO system_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (key, str(value), now),
        )


def setting_bool(settings: dict[str, str], key: str) -> bool:
    return clean_text(settings.get(key)).lower() in {"1", "true", "yes", "on"}


def setting_int(settings: dict[str, str], key: str, default: int, minimum: int = 1, maximum: int = 3650) -> int:
    try:
        value = int(settings.get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


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
                sample_rate_in INTEGER NOT NULL DEFAULT 1,
                sample_rate_out INTEGER NOT NULL DEFAULT 1,
                if_oper_status TEXT NOT NULL DEFAULT '',
                color TEXT NOT NULL DEFAULT '#64748b',
                monitor_enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
            )
            """
        )
        ensure_sqlite_column(conn, "sensor_interfaces", "sample_rate_in", "sample_rate_in INTEGER NOT NULL DEFAULT 1")
        ensure_sqlite_column(conn, "sensor_interfaces", "sample_rate_out", "sample_rate_out INTEGER NOT NULL DEFAULT 1")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS interface_snmp_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sensor_id INTEGER NOT NULL,
                if_index INTEGER NOT NULL,
                sample_time TEXT NOT NULL,
                in_octets INTEGER NOT NULL DEFAULT 0,
                out_octets INTEGER NOT NULL DEFAULT 0,
                in_bps REAL NOT NULL DEFAULT 0,
                out_bps REAL NOT NULL DEFAULT 0,
                if_oper_status TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_interface_snmp_samples_lookup
            ON interface_snmp_samples(sensor_id, if_index, sample_time)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sensor_interface_calibration (
                sensor_id INTEGER NOT NULL,
                if_index INTEGER NOT NULL,
                estimated_sample_rate_in REAL NOT NULL DEFAULT 1,
                estimated_sample_rate_out REAL NOT NULL DEFAULT 1,
                confidence REAL NOT NULL DEFAULT 0,
                last_calibrated_at TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT 'snmp_vs_flow',
                samples_used INTEGER NOT NULL DEFAULT 0,
                snmp_in_bps REAL NOT NULL DEFAULT 0,
                snmp_out_bps REAL NOT NULL DEFAULT 0,
                flow_in_bps REAL NOT NULL DEFAULT 0,
                flow_out_bps REAL NOT NULL DEFAULT 0,
                PRIMARY KEY(sensor_id, if_index),
                FOREIGN KEY(sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
            )
            """
        )
        ensure_system_settings_table(conn)
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
    start_snmp_polling_thread()
    start_database_retention_thread()


@app.on_event("shutdown")
def shutdown() -> None:
    SNMP_POLL_STOP.set()
    DATABASE_RETENTION_STOP.set()


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
    data["sample_rate_in"] = positive_int(data.get("sample_rate_in") or 1, "sample_rate_in")
    data["sample_rate_out"] = positive_int(data.get("sample_rate_out") or 1, "sample_rate_out")
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


def calibration_row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "estimated_sample_rate_in": round(float(row["estimated_sample_rate_in"] or 1), 2),
        "estimated_sample_rate_out": round(float(row["estimated_sample_rate_out"] or 1), 2),
        "confidence": round(float(row["confidence"] or 0), 3),
        "last_calibrated_at": row["last_calibrated_at"],
        "method": row["method"],
        "samples_used": int(row["samples_used"] or 0),
        "snmp_in_bps": round(float(row["snmp_in_bps"] or 0), 2),
        "snmp_out_bps": round(float(row["snmp_out_bps"] or 0), 2),
        "flow_in_bps": round(float(row["flow_in_bps"] or 0), 2),
        "flow_out_bps": round(float(row["flow_out_bps"] or 0), 2),
    }


def enrich_interface_metrics(conn: sqlite3.Connection, item: dict[str, Any], sensor_id: int) -> dict[str, Any]:
    if_index = int(item.get("if_index") or 0)
    sample = conn.execute(
        """
        SELECT sample_time, in_bps, out_bps, if_oper_status
        FROM interface_snmp_samples
        WHERE sensor_id = ? AND if_index = ?
        ORDER BY sample_time DESC
        LIMIT 1
        """,
        (sensor_id, if_index),
    ).fetchone()
    calibration = conn.execute(
        """
        SELECT *
        FROM sensor_interface_calibration
        WHERE sensor_id = ? AND if_index = ?
        """,
        (sensor_id, if_index),
    ).fetchone()
    item["snmp_in_bps"] = round(float(sample["in_bps"] or 0), 2) if sample else 0
    item["snmp_out_bps"] = round(float(sample["out_bps"] or 0), 2) if sample else 0
    item["snmp_sample_time"] = sample["sample_time"] if sample else ""
    item["snmp_if_oper_status"] = sample["if_oper_status"] if sample else ""
    item["calibration"] = calibration_row_to_dict(calibration)
    return item


def deterministic_color(key: Any) -> str:
    text = str(key or "")
    seed = 0
    for char in text:
        seed = (seed * 33 + ord(char)) % 9973
    return DASHBOARD_PALETTE[seed % len(DASHBOARD_PALETTE)]


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
        item["interfaces"] = [
            enrich_interface_metrics(conn, interface_row_to_dict(interface_row), int(item["id"]))
            for interface_row in interface_rows
        ]
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
    return COLLECTORS_COMPOSE_PATH


def collector_sensor_runtime_dir(sensor_id: int) -> str:
    return f"{COLLECTORS_RUNTIME_DIR}/sensor-{sensor_id}"


def collector_allow_file_path(sensor_id: int) -> str:
    return f"{collector_sensor_runtime_dir(sensor_id)}/allow.lst"


def yaml_quote(value: Any) -> str:
    text = str(value)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def validate_service_name(value: str) -> str:
    if not SERVICE_NAME_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Nome de servico invalido: {value}")
    return value


def active_collector_sensors(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, name, exporter_ip, listener_port, active, flow_collector_enabled
        FROM sensors
        WHERE active = 1
          AND flow_collector_enabled = 1
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
        sensor_service = validate_service_name(f"pmacct-sensor-{sensor_id}")
        parser_service = validate_service_name(f"pmacct-parser-sensor-{sensor_id}")
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
                "      - ./data/collectors:/app/data/collectors:ro",
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
            "  pmacct_spool:",
            "",
        ]
    )
    return "\n".join(lines)


def apply_collectors_script_path() -> Path | None:
    configured = clean_text(
        os.getenv("GMJFLOW_COLLECTOR_APPLY_SCRIPT")
        or os.getenv("GMJFLOW_APPLY_COLLECTORS_SCRIPT")
    )
    if configured:
        return Path(configured)
    return DEFAULT_COLLECTOR_APPLY_SCRIPT


def collector_apply_enabled() -> bool:
    return clean_text(os.getenv("GMJFLOW_ENABLE_COLLECTOR_APPLY", "false")).lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def run_apply_collectors_script(compose_path: Path) -> dict[str, Any]:
    if not collector_apply_enabled():
        return {
            "services_updated": False,
            "message": "Aplicacao automatica desativada; arquivos gerados.",
            "stdout": "",
            "stderr": "",
            "returncode": None,
        }
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
            cwd=str(RUNTIME_DIR) if RUNTIME_DIR.exists() else None,
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


async def snmp_get_interface_counters(config: dict[str, Any]) -> list[dict[str, Any]]:
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
            for name, oid in SNMP_COUNTER_OIDS.items()
        }

        indexes = set(tables["if_hc_in_octets"].keys()) | set(tables["if_hc_out_octets"].keys())
        counters: list[dict[str, Any]] = []
        for if_index in sorted(indexes):
            in_octets = snmp_value_int(tables["if_hc_in_octets"].get(if_index))
            out_octets = snmp_value_int(tables["if_hc_out_octets"].get(if_index))
            oper_status = snmp_value_int(tables["if_oper_status"].get(if_index))
            counters.append(
                {
                    "if_index": if_index,
                    "in_octets": in_octets,
                    "out_octets": out_octets,
                    "if_oper_status": IF_OPER_STATUS_LABELS.get(oper_status, str(oper_status) if oper_status else ""),
                }
            )
        return counters
    finally:
        snmp_engine.close_dispatcher()


def run_snmp(coro: Any) -> Any:
    try:
        return asyncio.run(coro)
    except asyncio.TimeoutError as exc:
        raise SnmpQueryError("timeout SNMP") from exc


def counter_bps(current_value: int, previous_value: int, elapsed_seconds: float) -> float:
    if elapsed_seconds <= 0:
        return 0.0
    delta = current_value - previous_value
    if delta < 0:
        delta += 2**64
    if delta < 0:
        return 0.0
    return max(0.0, (delta * 8) / elapsed_seconds)


def insert_snmp_counter_sample(
    conn: sqlite3.Connection,
    sensor_id: int,
    counter: dict[str, Any],
    sample_time: datetime,
) -> dict[str, Any]:
    if_index = int(counter["if_index"])
    in_octets = int(counter.get("in_octets") or 0)
    out_octets = int(counter.get("out_octets") or 0)
    previous = conn.execute(
        """
        SELECT sample_time, in_octets, out_octets
        FROM interface_snmp_samples
        WHERE sensor_id = ? AND if_index = ?
        ORDER BY sample_time DESC
        LIMIT 1
        """,
        (sensor_id, if_index),
    ).fetchone()

    in_bps = 0.0
    out_bps = 0.0
    if previous is not None:
        previous_time = parse_datetime_text(previous["sample_time"])
        if previous_time is not None:
            elapsed = (sample_time - previous_time).total_seconds()
            in_bps = counter_bps(in_octets, int(previous["in_octets"] or 0), elapsed)
            out_bps = counter_bps(out_octets, int(previous["out_octets"] or 0), elapsed)

    item = {
        "sensor_id": sensor_id,
        "if_index": if_index,
        "sample_time": iso(sample_time),
        "in_octets": in_octets,
        "out_octets": out_octets,
        "in_bps": round(in_bps, 2),
        "out_bps": round(out_bps, 2),
        "if_oper_status": clean_text(counter.get("if_oper_status")),
    }
    conn.execute(
        """
        INSERT INTO interface_snmp_samples (
            sensor_id,
            if_index,
            sample_time,
            in_octets,
            out_octets,
            in_bps,
            out_bps,
            if_oper_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            item["sensor_id"],
            item["if_index"],
            item["sample_time"],
            item["in_octets"],
            item["out_octets"],
            item["in_bps"],
            item["out_bps"],
            item["if_oper_status"],
        ),
    )
    return item


def sensor_poll_due(conn: sqlite3.Connection, sensor: dict[str, Any], now: datetime) -> bool:
    polling_seconds = max(30, min(int(sensor.get("snmp_polling_seconds") or 60), 3600))
    row = conn.execute(
        """
        SELECT MAX(sample_time) AS sample_time
        FROM interface_snmp_samples
        WHERE sensor_id = ?
        """,
        (sensor["id"],),
    ).fetchone()
    last_time = parse_datetime_text(row["sample_time"] if row else None)
    if last_time is None:
        return True
    return (now - last_time).total_seconds() >= polling_seconds


def poll_snmp_samples(sensor_id: int | None = None, force: bool = True) -> dict[str, Any]:
    ensure_sensor_db()
    now = datetime.now(timezone.utc)
    filters = ["active = 1", "exporter_snmp_enabled = 1"]
    values: list[Any] = []
    if sensor_id is not None:
        filters.append("id = ?")
        values.append(sensor_id)

    results: list[dict[str, Any]] = []
    with sqlite_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM sensors
            WHERE {' AND '.join(filters)}
            ORDER BY id
            """,
            values,
        ).fetchall()
        if sensor_id is not None and not rows:
            _ = fetch_sensor_without_interfaces(conn, sensor_id)
            raise HTTPException(status_code=400, detail="Sensor precisa estar ativo e com Exporter SNMP habilitado")
        for row in rows:
            sensor = dict(row)
            if not force and not sensor_poll_due(conn, sensor, now):
                continue
            try:
                config = snmp_config(sensor, None)
                counters = run_snmp(snmp_get_interface_counters(config))
                samples = [insert_snmp_counter_sample(conn, int(sensor["id"]), counter, now) for counter in counters]
                results.append(
                    {
                        "sensor_id": int(sensor["id"]),
                        "sensor": sensor["name"],
                        "ok": True,
                        "samples": samples,
                        "sample_count": len(samples),
                    }
                )
            except SnmpQueryError as exc:
                results.append({"sensor_id": int(sensor["id"]), "sensor": sensor["name"], "ok": False, "message": str(exc)})
            except Exception as exc:  # pragma: no cover - defensive guard for SNMP stack/runtime surprises.
                results.append({"sensor_id": int(sensor["id"]), "sensor": sensor["name"], "ok": False, "message": f"erro SNMP: {exc}"})
        conn.commit()

    return {"ok": all(item.get("ok") for item in results), "items": results}


def snmp_polling_enabled() -> bool:
    return clean_text(os.getenv("GMJFLOW_SNMP_POLLING_ENABLED", "1")).lower() not in {"0", "false", "no", "off"}


def snmp_polling_loop() -> None:
    while not SNMP_POLL_STOP.wait(15):
        try:
            poll_snmp_samples(force=False)
        except Exception as exc:  # pragma: no cover - background resilience.
            logger.warning("Falha no polling SNMP: %s", exc)


def start_snmp_polling_thread() -> None:
    global SNMP_POLL_THREAD
    if not snmp_polling_enabled():
        return
    if SNMP_POLL_THREAD is not None and SNMP_POLL_THREAD.is_alive():
        return
    SNMP_POLL_STOP.clear()
    SNMP_POLL_THREAD = threading.Thread(target=snmp_polling_loop, name="gmj-flow-snmp-poller", daemon=True)
    SNMP_POLL_THREAD.start()


def human_bytes(value: Any) -> str:
    size = float(value or 0)
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024
        unit += 1
    decimals = 0 if unit == 0 or size >= 10 else 1
    return f"{size:.{decimals}f} {units[unit]}"


def clickhouse_database_name() -> str:
    return os.getenv("CLICKHOUSE_DATABASE", "flowdb")


def clickhouse_table_sizes() -> list[dict[str, Any]]:
    result = query_clickhouse(
        """
        SELECT
            table,
            sum(rows) AS rows,
            sum(data_compressed_bytes) AS size_bytes
        FROM system.parts
        WHERE active = 1
          AND database = {database:String}
        GROUP BY table
        ORDER BY size_bytes DESC
        """,
        {"database": clickhouse_database_name()},
    )
    items = []
    for row in rows_as_dicts(result):
        size_bytes = int(row["size_bytes"] or 0)
        items.append(
            {
                "table": row["table"],
                "rows": int(row["rows"] or 0),
                "size_bytes": size_bytes,
                "size_human": human_bytes(size_bytes),
            }
        )
    return items


def clickhouse_flow_summary() -> dict[str, Any]:
    result = query_clickhouse(
        """
        SELECT
            count() AS flow_count,
            min(flow_time) AS oldest_flow_time,
            max(flow_time) AS newest_flow_time
        FROM flow_raw
        """
    )
    rows = rows_as_dicts(result)
    if not rows:
        return {"flow_count": 0, "oldest_flow_time": None, "newest_flow_time": None}
    row = rows[0]
    flow_count = int(row["flow_count"] or 0)
    if flow_count == 0:
        return {"flow_count": 0, "oldest_flow_time": None, "newest_flow_time": None}
    return {
        "flow_count": flow_count,
        "oldest_flow_time": iso(row["oldest_flow_time"]) if row["oldest_flow_time"] else None,
        "newest_flow_time": iso(row["newest_flow_time"]) if row["newest_flow_time"] else None,
    }


def clickhouse_size_summary() -> dict[str, int]:
    result = query_clickhouse(
        """
        SELECT
            sumIf(data_compressed_bytes, table = 'flow_raw') AS flow_raw_size_bytes,
            sum(data_compressed_bytes) AS clickhouse_database_size_bytes
        FROM system.parts
        WHERE active = 1
          AND database = {database:String}
        """,
        {"database": clickhouse_database_name()},
    )
    rows = rows_as_dicts(result)
    row = rows[0] if rows else {}
    return {
        "flow_raw_size_bytes": int(row.get("flow_raw_size_bytes") or 0),
        "clickhouse_database_size_bytes": int(row.get("clickhouse_database_size_bytes") or 0),
    }


def apply_flow_retention_ttl(enabled: bool, days: int) -> str:
    days = setting_int({"days": str(days)}, "days", 30)
    if enabled:
        command = f"ALTER TABLE flow_raw MODIFY TTL toDateTime(flow_time) + INTERVAL {days} DAY DELETE"
    else:
        command = "ALTER TABLE flow_raw REMOVE TTL"
    command_clickhouse(command)
    return command


def cleanup_clickhouse_flows(older_than_days: int, optimize: bool = False) -> dict[str, Any]:
    days = setting_int({"days": str(older_than_days)}, "days", 90)
    cutoff_expression = f"now() - INTERVAL {days} DAY"
    count_result = query_clickhouse(
        f"""
        SELECT count() AS count
        FROM flow_raw
        WHERE flow_time < {cutoff_expression}
        """
    )
    rows = rows_as_dicts(count_result)
    approximate_before = int(rows[0]["count"] or 0) if rows else 0
    command = f"ALTER TABLE flow_raw DELETE WHERE flow_time < {cutoff_expression}"
    command_clickhouse(command)
    optimize_command = ""
    if optimize:
        optimize_command = "OPTIMIZE TABLE flow_raw FINAL"
        command_clickhouse(optimize_command)
    return {
        "approximate_before": approximate_before,
        "older_than_days": days,
        "period_deleted": f"flow_time < {cutoff_expression}",
        "command_executed": command,
        "optimize_command": optimize_command,
        "status": "ok",
        "note": (
            "ClickHouse pode liberar espaco fisico depois dos merges."
            if not optimize
            else "OPTIMIZE FINAL solicitado; pode consumir recursos em tabelas grandes."
        ),
    }


def cleanup_sqlite_snmp_samples(older_than_days: int) -> int:
    days = setting_int({"days": str(older_than_days)}, "days", 90)
    with sqlite_connection() as conn:
        cursor = conn.execute(
            """
            DELETE FROM interface_snmp_samples
            WHERE sample_time < datetime('now', ?)
            """,
            (f"-{days} days",),
        )
        deleted = int(cursor.rowcount or 0)
        conn.commit()
    return deleted


def run_database_cleanup(
    flow_retention_days: int,
    snmp_retention_days: int | None = None,
    optimize: bool = False,
    source: str = "manual",
) -> dict[str, Any]:
    flow_result = cleanup_clickhouse_flows(flow_retention_days, optimize=optimize)
    snmp_deleted = cleanup_sqlite_snmp_samples(snmp_retention_days) if snmp_retention_days is not None else None
    cleanup_at = utc_now_iso()
    with sqlite_connection() as conn:
        set_system_settings(conn, {"database_last_cleanup_at": cleanup_at})
        conn.commit()
    return {
        "ok": True,
        "source": source,
        "cleanup_at": cleanup_at,
        "flow": flow_result,
        "snmp_deleted": snmp_deleted,
    }


def database_retention_loop() -> None:
    while not DATABASE_RETENTION_STOP.wait(60):
        try:
            ensure_sensor_db()
            now = datetime.now(timezone.utc)
            with sqlite_connection() as conn:
                settings = get_system_settings(conn)
            if not setting_bool(settings, "database_retention_enabled"):
                continue
            cleanup_hour = setting_int(settings, "database_cleanup_hour", 3, 0, 23)
            if now.hour != cleanup_hour:
                continue
            last_cleanup = parse_datetime_text(settings.get("database_last_cleanup_at"))
            if last_cleanup is not None and last_cleanup.date() == now.date():
                continue
            run_database_cleanup(
                flow_retention_days=setting_int(settings, "flow_retention_days", 30),
                snmp_retention_days=setting_int(settings, "snmp_retention_days", 90),
                optimize=False,
                source="automatic",
            )
        except Exception as exc:  # pragma: no cover - background resilience.
            logger.warning("Falha na retencao automatica: %s", exc)


def start_database_retention_thread() -> None:
    global DATABASE_RETENTION_THREAD
    if DATABASE_RETENTION_THREAD is not None and DATABASE_RETENTION_THREAD.is_alive():
        return
    DATABASE_RETENTION_STOP.clear()
    DATABASE_RETENTION_THREAD = threading.Thread(
        target=database_retention_loop,
        name="gmj-flow-database-retention",
        daemon=True,
    )
    DATABASE_RETENTION_THREAD.start()


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
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    sensor: str | None = None,
) -> tuple[int, datetime | None, datetime | None, str | None]:
    return range_minutes, start, end, sensor


@app.get("/health")
def health(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
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
    compose_path.parent.mkdir(parents=True, exist_ok=True)
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


@app.get("/api/database/status")
def database_status(request: Request):
    require_admin(request)
    settings = {key: value for key, value in SYSTEM_SETTING_DEFAULTS.items()}
    sqlite_ok = False
    clickhouse_ok = False
    flow_summary = {"flow_count": 0, "oldest_flow_time": None, "newest_flow_time": None}
    size_summary = {"flow_raw_size_bytes": 0, "clickhouse_database_size_bytes": 0}

    try:
        ensure_sensor_db()
        with sqlite_connection() as conn:
            conn.execute("SELECT 1").fetchone()
            settings = get_system_settings(conn)
            sqlite_ok = True
    except Exception as exc:
        logger.warning("Falha ao consultar status do SQLite: %s", exc)

    try:
        clickhouse_ok = ping_clickhouse()
        if clickhouse_ok:
            flow_summary = clickhouse_flow_summary()
            size_summary = clickhouse_size_summary()
    except Exception as exc:
        logger.warning("Falha ao consultar status do ClickHouse: %s", exc)
        clickhouse_ok = False

    db_path = sqlite_path()
    sqlite_size_bytes = db_path.stat().st_size if db_path.exists() else 0
    disk_root = db_path.parent if db_path.parent.exists() else Path(".")
    disk_usage = shutil.disk_usage(disk_root)
    retention_days = setting_int(settings, "flow_retention_days", 30)
    snmp_retention_days = setting_int(settings, "snmp_retention_days", 90)
    return {
        "clickhouse_ok": clickhouse_ok,
        "sqlite_ok": sqlite_ok,
        "flow_count": flow_summary["flow_count"],
        "oldest_flow_time": flow_summary["oldest_flow_time"],
        "newest_flow_time": flow_summary["newest_flow_time"],
        "flow_raw_size_bytes": size_summary["flow_raw_size_bytes"],
        "flow_raw_size_human": human_bytes(size_summary["flow_raw_size_bytes"]),
        "clickhouse_database_size_bytes": size_summary["clickhouse_database_size_bytes"],
        "clickhouse_database_size_human": human_bytes(size_summary["clickhouse_database_size_bytes"]),
        "sqlite_size_bytes": sqlite_size_bytes,
        "sqlite_size_human": human_bytes(sqlite_size_bytes),
        "disk_total_bytes": disk_usage.total,
        "disk_used_bytes": disk_usage.used,
        "disk_free_bytes": disk_usage.free,
        "disk_used_human": human_bytes(disk_usage.used),
        "disk_free_human": human_bytes(disk_usage.free),
        "disk_total_human": human_bytes(disk_usage.total),
        "retention_days": retention_days,
        "snmp_retention_days": snmp_retention_days,
        "retention_enabled": setting_bool(settings, "database_retention_enabled"),
        "database_cleanup_hour": setting_int(settings, "database_cleanup_hour", 3, 0, 23),
        "last_cleanup_at": settings.get("database_last_cleanup_at") or None,
    }


@app.get("/api/database/tables")
def database_tables(request: Request):
    require_admin(request)
    try:
        items = clickhouse_table_sizes()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"ClickHouse indisponivel: {exc}") from exc
    return {"items": items}


@app.post("/api/database/retention")
def database_retention(request: Request, payload: DatabaseRetentionPayload):
    require_admin(request)
    snmp_days = payload.snmp_retention_days or payload.retention_days
    cleanup_hour = 3 if payload.cleanup_hour is None else payload.cleanup_hour
    try:
        ttl_command = apply_flow_retention_ttl(payload.enabled, payload.retention_days)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Falha ao atualizar TTL no ClickHouse: {exc}") from exc

    ensure_sensor_db()
    with sqlite_connection() as conn:
        set_system_settings(
            conn,
            {
                "database_retention_enabled": "1" if payload.enabled else "0",
                "flow_retention_days": payload.retention_days,
                "snmp_retention_days": snmp_days,
                "database_cleanup_hour": cleanup_hour,
            },
        )
        conn.commit()
        settings = get_system_settings(conn)
    return {
        "ok": True,
        "retention_enabled": setting_bool(settings, "database_retention_enabled"),
        "retention_days": setting_int(settings, "flow_retention_days", 30),
        "snmp_retention_days": setting_int(settings, "snmp_retention_days", 90),
        "database_cleanup_hour": setting_int(settings, "database_cleanup_hour", 3, 0, 23),
        "ttl_command": ttl_command,
    }


@app.post("/api/database/cleanup")
def database_cleanup(request: Request, payload: DatabaseCleanupPayload):
    require_admin(request)
    if payload.confirm != "LIMPAR":
        raise HTTPException(status_code=400, detail="Digite LIMPAR para confirmar")
    try:
        result = run_database_cleanup(
            flow_retention_days=payload.older_than_days,
            snmp_retention_days=None,
            optimize=payload.optimize,
            source="manual",
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Falha na limpeza: {exc}") from exc
    return result


@app.post("/api/database/optimize")
def database_optimize(request: Request, payload: DatabaseOptimizePayload):
    require_admin(request)
    if payload.confirm != "OTIMIZAR":
        raise HTTPException(status_code=400, detail="Digite OTIMIZAR para confirmar")
    command = "OPTIMIZE TABLE flow_raw FINAL"
    try:
        command_clickhouse(command)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Falha ao executar OPTIMIZE: {exc}") from exc
    return {
        "ok": True,
        "command_executed": command,
        "status": "ok",
        "note": "OPTIMIZE FINAL solicitado; acompanhe uso de CPU e disco em tabelas grandes.",
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
        items = []
        for row in rows:
            item = dict(row)
            item["color"] = deterministic_color(item["id"])
            items.append(item)
        return {"items": items}


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
        return {"items": [enrich_interface_metrics(conn, interface_dashboard_row_to_dict(row), sensor_id) for row in rows]}


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


@app.post("/api/sensors/{sensor_id}/snmp/poll")
def poll_sensor_snmp(sensor_id: int):
    ensure_sensor_db()
    _ = sensor_exporter_ip(sensor_id)
    return poll_snmp_samples(sensor_id=sensor_id, force=True)


@app.get("/api/sensors/{sensor_id}/interfaces/{if_index}/calibration")
def get_interface_calibration(sensor_id: int, if_index: int):
    return calibration_detail(sensor_id, if_index)


@app.post("/api/sensors/{sensor_id}/interfaces/{if_index}/calibration/run")
def run_interface_calibration(
    sensor_id: int,
    if_index: int,
    window_minutes: int = Query(15, ge=5, le=15),
):
    poll_result = poll_snmp_samples(sensor_id=sensor_id, force=True)
    calibration = calibrate_interface_sample_rate(sensor_id, if_index, window_minutes)
    return {"ok": True, "poll": poll_result, "calibration": calibration}


@app.post("/api/sensors/{sensor_id}/interfaces/calibration/run")
def run_sensor_interfaces_calibration(
    sensor_id: int,
    window_minutes: int = Query(15, ge=5, le=15),
):
    ensure_sensor_db()
    poll_result = poll_snmp_samples(sensor_id=sensor_id, force=True)
    with sqlite_connection() as conn:
        _ = fetch_sensor_without_interfaces(conn, sensor_id)
        rows = conn.execute(
            """
            SELECT if_index
            FROM sensor_interfaces
            WHERE sensor_id = ? AND monitor_enabled = 1
            ORDER BY if_index, id
            """,
            (sensor_id,),
        ).fetchall()
    items = [calibrate_interface_sample_rate(sensor_id, int(row["if_index"]), window_minutes) for row in rows]
    return {"ok": True, "poll": poll_result, "items": items}


@app.post("/api/sensors/{sensor_id}/interfaces/{if_index}/calibration/apply")
def apply_calibration_sample_rate(sensor_id: int, if_index: int):
    return apply_interface_calibration(sensor_id, if_index)


def raw_flow_where(
    start: datetime,
    end: datetime,
    sensor: str | None,
    params: dict[str, Any],
    exporter_ip: str | None = None,
    if_index: int | None = None,
) -> str:
    where = flow_time_where(params, start, end)
    if exporter_ip:
        params["exporter_ip"] = clickhouse_ip_string_param(exporter_ip, "exporter_ip")
        where += " AND toString(exporter_ip) = {exporter_ip:String}"
    elif sensor:
        params["sensor"] = sensor
        where += " AND sensor = {sensor:String}"
    if if_index is not None:
        params["if_index"] = int(if_index)
        where += " AND (input_if = {if_index:UInt32} OR output_if = {if_index:UInt32})"
    return where


def sensor_exporter_ip(sensor_id: int) -> str:
    ensure_sensor_db()
    with sqlite_connection() as conn:
        sensor = fetch_sensor_without_interfaces(conn, sensor_id)
    exporter_ip = clean_text(sensor.get("exporter_ip"))
    if not exporter_ip:
        raise HTTPException(status_code=400, detail="Sensor sem exporter_ip configurado")
    return exporter_ip


def traffic_items(
    metric: str,
    range_minutes: int,
    sensor: str | None,
    sensor_id: int | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
):
    start_dt, end_dt = resolve_requested_range(range_minutes, start, end, start_time, end_time)
    params: dict[str, Any] = {}
    exporter_ip = sensor_exporter_ip(sensor_id) if sensor_id is not None else None
    where = raw_flow_where(start_dt, end_dt, sensor, params, exporter_ip)
    value_field = "bytes" if metric == "bps" else "packets"
    multiplier = "8" if metric == "bps" else "1"
    result = query_clickhouse(
        f"""
        SELECT
            toStartOfMinute(flow_time) AS time,
            sensor,
            sumIf({value_field}, input_if > 0) * {multiplier} / 60 AS download_{metric},
            sumIf({value_field}, output_if > 0) * {multiplier} / 60 AS upload_{metric}
        FROM flow_raw
        WHERE {where}
        GROUP BY time, sensor
        ORDER BY time, sensor
        """,
        params,
    )

    series_by_sensor: dict[str, dict[str, Any]] = {}
    for row in rows_as_dicts(result):
        sensor_name = str(row["sensor"] or "Sensor desconhecido")
        item = series_by_sensor.setdefault(
            sensor_name,
            {
                "series_type": "sensor",
                "key": sensor_name,
                "label": sensor_name,
                "sensor": sensor_name,
                "color": deterministic_color(sensor_name),
                "points": [],
            },
        )
        download_value = round(float(row[f"download_{metric}"] or 0), 2)
        upload_value = round(float(row[f"upload_{metric}"] or 0), 2)
        item["points"].append(
            {
                "time": iso(row["time"]),
                f"download_{metric}": download_value,
                f"upload_{metric}": upload_value,
                metric: round(download_value + upload_value, 2),
            }
        )
    return {"start": iso(start_dt), "end": iso(end_dt), "items": list(series_by_sensor.values())}


@app.get("/api/traffic/bps")
def get_bps(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
):
    return traffic_items("bps", range_minutes, sensor, sensor_id, start, end, start_time, end_time)


@app.get("/api/traffic/pps")
def get_pps(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
):
    return traffic_items("pps", range_minutes, sensor, sensor_id, start, end, start_time, end_time)


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


def resolve_dashboard_if_index(
    sensor_id: int | None,
    interface_id: int | None,
    if_index: int | None,
) -> int | None:
    if if_index is not None:
        return int(if_index)
    if interface_id is None:
        return None
    if sensor_id is None:
        raise HTTPException(status_code=400, detail="sensor_id e obrigatorio ao filtrar por interface_id")
    ensure_sensor_db()
    with sqlite_connection() as conn:
        row = conn.execute(
            """
            SELECT if_index
            FROM sensor_interfaces
            WHERE id = ? AND sensor_id = ?
            """,
            (interface_id, sensor_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Interface nao encontrada para o sensor informado")
    return int(row["if_index"])


def flow_interface_direction_bps(
    exporter_ip: str,
    if_index: int,
    direction: str,
    start: datetime,
    end: datetime,
) -> float:
    seconds = range_seconds(start, end)
    interface_field = "input_if" if direction == "in" else "output_if"
    params = {
        "exporter_ip": clickhouse_ip_string_param(exporter_ip, "exporter_ip"),
        "if_index": int(if_index),
        "start": start,
        "end": end,
        "seconds": seconds,
    }
    result = query_clickhouse(
        f"""
        SELECT sum(bytes) * 8 / {{seconds:Float64}} AS bps
        FROM flow_raw
        WHERE flow_time > {{start:DateTime}}
          AND flow_time <= {{end:DateTime}}
          AND toString(exporter_ip) = {{exporter_ip:String}}
          AND {interface_field} = {{if_index:UInt32}}
        """,
        params,
    )
    rows = rows_as_dicts(result)
    if not rows:
        return 0.0
    return round(float(rows[0]["bps"] or 0), 2)


def robust_ratio_estimate(ratios: list[float]) -> tuple[float, float, int]:
    clean = [ratio for ratio in ratios if ratio > 0 and ratio < 1_000_000]
    if not clean:
        return 1.0, 0.0, 0
    first_median = median(clean)
    if first_median <= 0:
        return 1.0, 0.0, 0
    filtered = [
        ratio
        for ratio in clean
        if first_median / 4 <= ratio <= first_median * 4
    ]
    if not filtered:
        filtered = clean
    estimate = float(median(filtered))
    dispersion = float(median([abs(ratio - estimate) / estimate for ratio in filtered])) if estimate > 0 else 1.0
    confidence = min(1.0, len(filtered) / 5) * max(0.0, 1.0 - min(dispersion, 1.0))
    return round(estimate, 2), round(confidence, 3), len(filtered)


def median_or_zero(values: list[float]) -> float:
    clean = [float(value) for value in values if value > 0]
    return round(float(median(clean)), 2) if clean else 0.0


def calibrate_interface_sample_rate(
    sensor_id: int,
    if_index: int,
    window_minutes: int = 15,
) -> dict[str, Any]:
    ensure_sensor_db()
    window_minutes = max(5, min(int(window_minutes), 15))
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=window_minutes + 5)

    with sqlite_connection() as conn:
        sensor = fetch_sensor_without_interfaces(conn, sensor_id)
        interface = conn.execute(
            """
            SELECT *
            FROM sensor_interfaces
            WHERE sensor_id = ? AND if_index = ?
            ORDER BY id
            LIMIT 1
            """,
            (sensor_id, if_index),
        ).fetchone()
        if interface is None:
            raise HTTPException(status_code=404, detail="Interface nao encontrada")
        exporter_ip = clean_text(sensor.get("exporter_ip"))
        if not exporter_ip:
            raise HTTPException(status_code=400, detail="Sensor sem exporter_ip configurado")

        rows = conn.execute(
            """
            SELECT sample_time, in_bps, out_bps
            FROM interface_snmp_samples
            WHERE sensor_id = ? AND if_index = ? AND sample_time >= ?
            ORDER BY sample_time ASC
            """,
            (sensor_id, if_index, iso(since)),
        ).fetchall()

    ratios_in: list[float] = []
    ratios_out: list[float] = []
    snmp_in_values: list[float] = []
    snmp_out_values: list[float] = []
    flow_in_values: list[float] = []
    flow_out_values: list[float] = []
    previous_time: datetime | None = None

    for row in rows:
        sample_time = parse_datetime_text(row["sample_time"])
        if sample_time is None:
            continue
        if previous_time is None:
            previous_time = sample_time
            continue
        if sample_time < now - timedelta(minutes=window_minutes):
            previous_time = sample_time
            continue

        snmp_in = float(row["in_bps"] or 0)
        snmp_out = float(row["out_bps"] or 0)
        flow_in = flow_interface_direction_bps(exporter_ip, if_index, "in", previous_time, sample_time)
        flow_out = flow_interface_direction_bps(exporter_ip, if_index, "out", previous_time, sample_time)

        if snmp_in >= CALIBRATION_MIN_BPS and flow_in >= CALIBRATION_MIN_BPS:
            ratios_in.append(snmp_in / flow_in)
            snmp_in_values.append(snmp_in)
            flow_in_values.append(flow_in)
        if snmp_out >= CALIBRATION_MIN_BPS and flow_out >= CALIBRATION_MIN_BPS:
            ratios_out.append(snmp_out / flow_out)
            snmp_out_values.append(snmp_out)
            flow_out_values.append(flow_out)

        previous_time = sample_time

    estimated_in, confidence_in, samples_in = robust_ratio_estimate(ratios_in)
    estimated_out, confidence_out, samples_out = robust_ratio_estimate(ratios_out)
    confidences = [value for value, count in ((confidence_in, samples_in), (confidence_out, samples_out)) if count > 0]
    confidence = round(min(confidences), 3) if confidences else 0.0
    samples_used = samples_in + samples_out
    calibrated_at = iso(now)

    result = {
        "sensor_id": sensor_id,
        "if_index": if_index,
        "estimated_sample_rate_in": estimated_in,
        "estimated_sample_rate_out": estimated_out,
        "confidence": confidence,
        "confidence_in": confidence_in,
        "confidence_out": confidence_out,
        "samples_used": samples_used,
        "samples_used_in": samples_in,
        "samples_used_out": samples_out,
        "snmp_in_bps": median_or_zero(snmp_in_values),
        "snmp_out_bps": median_or_zero(snmp_out_values),
        "flow_in_bps": median_or_zero(flow_in_values),
        "flow_out_bps": median_or_zero(flow_out_values),
        "last_calibrated_at": calibrated_at,
        "method": CALIBRATION_METHOD,
        "confidence_low": confidence < CALIBRATION_MIN_CONFIDENCE,
        "min_confidence": CALIBRATION_MIN_CONFIDENCE,
    }

    with sqlite_connection() as conn:
        conn.execute(
            """
            INSERT INTO sensor_interface_calibration (
                sensor_id,
                if_index,
                estimated_sample_rate_in,
                estimated_sample_rate_out,
                confidence,
                last_calibrated_at,
                method,
                samples_used,
                snmp_in_bps,
                snmp_out_bps,
                flow_in_bps,
                flow_out_bps
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sensor_id, if_index) DO UPDATE SET
                estimated_sample_rate_in = excluded.estimated_sample_rate_in,
                estimated_sample_rate_out = excluded.estimated_sample_rate_out,
                confidence = excluded.confidence,
                last_calibrated_at = excluded.last_calibrated_at,
                method = excluded.method,
                samples_used = excluded.samples_used,
                snmp_in_bps = excluded.snmp_in_bps,
                snmp_out_bps = excluded.snmp_out_bps,
                flow_in_bps = excluded.flow_in_bps,
                flow_out_bps = excluded.flow_out_bps
            """,
            (
                sensor_id,
                if_index,
                result["estimated_sample_rate_in"],
                result["estimated_sample_rate_out"],
                result["confidence"],
                result["last_calibrated_at"],
                result["method"],
                result["samples_used"],
                result["snmp_in_bps"],
                result["snmp_out_bps"],
                result["flow_in_bps"],
                result["flow_out_bps"],
            ),
        )
        conn.commit()

    return result


def calibration_detail(sensor_id: int, if_index: int) -> dict[str, Any]:
    ensure_sensor_db()
    with sqlite_connection() as conn:
        interface = conn.execute(
            """
            SELECT *
            FROM sensor_interfaces
            WHERE sensor_id = ? AND if_index = ?
            ORDER BY id
            LIMIT 1
            """,
            (sensor_id, if_index),
        ).fetchone()
        if interface is None:
            raise HTTPException(status_code=404, detail="Interface nao encontrada")
        item = enrich_interface_metrics(conn, interface_dashboard_row_to_dict(interface), sensor_id)
    return {
        "sensor_id": sensor_id,
        "if_index": if_index,
        "interface": item,
        "calibration": item.get("calibration"),
        "min_confidence": CALIBRATION_MIN_CONFIDENCE,
    }


def apply_interface_calibration(sensor_id: int, if_index: int) -> dict[str, Any]:
    ensure_sensor_db()
    with sqlite_connection() as conn:
        calibration = conn.execute(
            """
            SELECT *
            FROM sensor_interface_calibration
            WHERE sensor_id = ? AND if_index = ?
            """,
            (sensor_id, if_index),
        ).fetchone()
        if calibration is None:
            raise HTTPException(status_code=404, detail="Calibracao nao encontrada")
        confidence = float(calibration["confidence"] or 0)
        if confidence < CALIBRATION_MIN_CONFIDENCE:
            raise HTTPException(
                status_code=400,
                detail="Confianca baixa; revise as amostras antes de aplicar o sample_rate",
            )
        sample_rate_in = max(1, int(round(float(calibration["estimated_sample_rate_in"] or 1))))
        sample_rate_out = max(1, int(round(float(calibration["estimated_sample_rate_out"] or 1))))
        conn.execute(
            """
            UPDATE sensor_interfaces
            SET sample_rate_in = ?,
                sample_rate_out = ?,
                updated_at = ?
            WHERE sensor_id = ? AND if_index = ?
            """,
            (sample_rate_in, sample_rate_out, utc_now_iso(), sensor_id, if_index),
        )
        conn.commit()
    detail = calibration_detail(sensor_id, if_index)
    detail["applied"] = True
    detail["sample_rate_in"] = sample_rate_in
    detail["sample_rate_out"] = sample_rate_out
    return detail


def interface_traffic_items(
    metric: str,
    sensor_id: int,
    range_minutes: int,
    interface_id: int | None = None,
    if_index: int | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> dict[str, Any]:
    start_dt, end_dt = resolve_requested_range(range_minutes, start, end, start_time, end_time)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        sensor = fetch_sensor_without_interfaces(conn, sensor_id)
        interfaces = monitored_sensor_interfaces(conn, sensor_id, interface_id, if_index)

    exporter_ip = clean_text(sensor.get("exporter_ip"))
    if not exporter_ip:
        raise HTTPException(status_code=400, detail="Sensor sem exporter_ip configurado")

    value_field = "bytes" if metric == "bps" else "packets"
    multiplier = "8" if metric == "bps" else "1"
    items = []
    for interface in interfaces:
        params: dict[str, Any] = {
            "exporter_ip": clickhouse_ip_string_param(exporter_ip, "exporter_ip"),
            "if_index": int(interface["if_index"] or 0),
        }
        where = flow_time_where(params, start_dt, end_dt)
        result = query_clickhouse(
            f"""
            SELECT
                toStartOfMinute(flow_time) AS time,
                sumIf({value_field}, input_if = {{if_index:UInt32}}) * {multiplier} / 60 AS download_{metric},
                sumIf({value_field}, output_if = {{if_index:UInt32}}) * {multiplier} / 60 AS upload_{metric}
            FROM flow_raw
            WHERE {where}
              AND toString(exporter_ip) = {{exporter_ip:String}}
              AND (input_if = {{if_index:UInt32}} OR output_if = {{if_index:UInt32}})
            GROUP BY time
            ORDER BY time
            """,
            params,
        )

        points = [
            {
                "time": iso(row["time"]),
                f"download_{metric}": round(float(row[f"download_{metric}"] or 0), 2),
                f"upload_{metric}": round(float(row[f"upload_{metric}"] or 0), 2),
                metric: round(
                    float(row[f"download_{metric}"] or 0) + float(row[f"upload_{metric}"] or 0),
                    2,
                ),
            }
            for row in rows_as_dicts(result)
        ]
        items.append(
            {
                "series_type": "interface",
                "key": f"if-{interface['if_index']}",
                "label": interface["name"],
                "interface_id": interface["id"],
                "if_index": interface["if_index"],
                "interface_name": interface["name"],
                "direction": interface.get("direction") or "Unset",
                "color": interface["color"] or "#64748b",
                "points": points,
            }
        )

    return {"start": iso(start_dt), "end": iso(end_dt), "items": items}


@app.get("/api/traffic/interface-bps")
def get_interface_bps(
    sensor_id: int = Query(..., ge=1),
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
):
    return interface_traffic_items("bps", sensor_id, range_minutes, interface_id, if_index, start, end, start_time, end_time)


@app.get("/api/traffic/interface-pps")
def get_interface_pps(
    sensor_id: int = Query(..., ge=1),
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
):
    return interface_traffic_items("pps", sensor_id, range_minutes, interface_id, if_index, start, end, start_time, end_time)


def top_dimension(
    dimension: str,
    range_minutes: int,
    sensor: str | None,
    sensor_id: int | None,
    limit: int,
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    interface_id: int | None = None,
    if_index: int | None = None,
):
    start_dt, end_dt = resolve_requested_range(range_minutes, start, end, start_time, end_time)
    seconds = range_seconds(start_dt, end_dt)
    params: dict[str, Any] = {"limit": limit, "seconds": seconds}
    exporter_ip = sensor_exporter_ip(sensor_id) if sensor_id is not None else None
    resolved_if_index = resolve_dashboard_if_index(sensor_id, interface_id, if_index)
    where = raw_flow_where(start_dt, end_dt, sensor, params, exporter_ip, resolved_if_index)

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
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("src_ip", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index)


@app.get("/api/tops/dst-ip")
def top_dst_ip(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("dst_ip", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index)


@app.get("/api/tops/ports")
def top_ports(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("dst_port", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index)


@app.get("/api/tops/protocols")
def top_protocols(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("proto", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index)


@app.get("/api/tops/tcp-flags")
def top_tcp_flags(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    limit: int = Query(10, ge=1, le=100),
):
    return top_dimension("tcp_flags", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index)


def top_asn_dimension(
    dimension: str,
    range_minutes: int,
    sensor: str | None,
    sensor_id: int | None,
    limit: int,
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    interface_id: int | None = None,
    if_index: int | None = None,
):
    start_dt, end_dt = resolve_requested_range(range_minutes, start, end, start_time, end_time)
    seconds = range_seconds(start_dt, end_dt)
    params: dict[str, Any] = {"seconds": seconds}
    exporter_ip = sensor_exporter_ip(sensor_id) if sensor_id is not None else None
    resolved_if_index = resolve_dashboard_if_index(sensor_id, interface_id, if_index)
    where = raw_flow_where(start_dt, end_dt, sensor, params, exporter_ip)
    if resolved_if_index is not None:
        params["if_index"] = resolved_if_index
        if dimension == "src":
            where += " AND output_if = {if_index:UInt32}"
        else:
            where += " AND input_if = {if_index:UInt32}"

    result = query_clickhouse(
        f"""
        SELECT
            sum(bytes) * 8 / {{seconds:Float64}} AS bps,
            sum(packets) AS packets,
            sum(flow_count) AS flows
        FROM flow_raw
        WHERE {where}
        """,
        params,
    )
    rows = rows_as_dicts(result)
    if not rows:
        return {"start": iso(start_dt), "end": iso(end_dt), "items": []}
    row = rows[0]
    bps = round(float(row["bps"] or 0), 2)
    if bps <= 0:
        return {"start": iso(start_dt), "end": iso(end_dt), "items": []}
    item = {
        "rank": 1,
        "asn": "ASN indisponivel",
        "description": "Base ASN local ainda nao configurada",
        "bps": bps,
        "packets": int(row["packets"] or 0),
        "flows": int(row["flows"] or 0),
        "percent": 100.0,
    }
    return {
        "start": iso(start_dt),
        "end": iso(end_dt),
        "asn_available": False,
        "message": "ASN ainda nao resolvido; configure uma base ASN local para detalhar por prefixo/AS.",
        "items": [item][:limit],
    }


@app.get("/api/tops/asn-src")
def top_asn_src(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    limit: int = Query(15, ge=1, le=100),
):
    return top_asn_dimension("src", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index)


@app.get("/api/tops/asn-dst")
def top_asn_dst(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    limit: int = Query(15, ge=1, le=100),
):
    return top_asn_dimension("dst", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index)


@app.get("/api/flows/search")
def search_flows(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
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
    start_dt, end_dt = resolve_requested_range(range_minutes, start, end, start_time, end_time)
    params: dict[str, Any] = {"start": start_dt, "end": end_dt, "limit": limit}
    filters = ["flow_time >= {start:DateTime}", "flow_time <= {end:DateTime}"]
    if sensor_id is not None:
        params["exporter_ip"] = clickhouse_ip_string_param(sensor_exporter_ip(sensor_id), "exporter_ip")
        filters.append("toString(exporter_ip) = {exporter_ip:String}")
    elif sensor:
        params["sensor"] = sensor
        filters.append("sensor = {sensor:String}")
    resolved_if_index = resolve_dashboard_if_index(sensor_id, interface_id, if_index)
    if resolved_if_index is not None:
        params["if_index"] = resolved_if_index
        filters.append("(input_if = {if_index:UInt32} OR output_if = {if_index:UInt32})")
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
