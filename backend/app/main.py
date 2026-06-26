from __future__ import annotations

import os
import sqlite3
import asyncio
import csv
import io
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
import zlib
from datetime import datetime, timedelta, timezone
from importlib import import_module
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from pathlib import Path
from statistics import median
from typing import Any

import clickhouse_connect
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse, Response


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

FLOW_SEARCH_SORT_COLUMNS = {
    "flow_time": "flow_time",
    "sensor": "sensor",
    "exporter_ip": "exporter_ip",
    "src_ip": "toString(src_ip)",
    "src_port": "src_port",
    "dst_ip": "toString(dst_ip)",
    "dst_port": "dst_port",
    "proto": "proto",
    "tcp_flags": "tcp_flags",
    "input_if": "input_if",
    "output_if": "output_if",
    "bytes": "bytes",
    "packets": "packets",
    "flows": "flow_count",
    "bits_s": "bits_s",
    "packets_s": "packets_s",
    "sample_rate": "sample_rate_applied",
    "flow_type": "flow_type",
}

TOP_FLOW_TYPES = {
    "src_ip",
    "dst_ip",
    "conversation",
    "src_port",
    "dst_port",
    "ports",
    "proto",
    "tcp_flags",
    "input_if",
    "output_if",
    "interfaces",
    "asn_src",
    "asn_dst",
    "src_asn",
    "dst_asn",
}

TOP_FLOW_TYPE_ALIASES = {
    "protocol": "proto",
    "protocols": "proto",
    "src_asn": "asn_src",
    "dst_asn": "asn_dst",
    "asn_source": "asn_src",
    "asn_destination": "asn_dst",
}

TOP_FLOW_SORT_COLUMNS = {
    "key": "key",
    "bits_s": "bits_s",
    "packets_s": "packets_s",
    "bytes": "bytes",
    "packets": "packets",
    "flows": "flows",
    "percent": "percent_total",
    "percent_total": "percent_total",
    "first_seen": "first_seen",
    "last_seen": "last_seen",
    "duration_seconds": "duration_seconds",
}

ASN_RESOLVER_ENABLED = os.getenv("GMJFLOW_ASN_RESOLVER_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
ASN_RESOLVER_BATCH_SIZE = int(
    os.getenv(
        "GMJFLOW_ASN_RESOLVER_BATCH_SIZE",
        os.getenv("GMJFLOW_ASN_RESOLVER_MAX_IPS_PER_RUN", "20"),
    )
)
ASN_RESOLVER_INTERVAL_SECONDS = int(os.getenv("GMJFLOW_ASN_RESOLVER_INTERVAL_SECONDS", "30"))
ASN_RESOLVER_TIMEOUT_SECONDS = int(os.getenv("GMJFLOW_ASN_RESOLVER_TIMEOUT_SECONDS", "10"))
ASN_RESOLVER_MAX_ATTEMPTS = int(os.getenv("GMJFLOW_ASN_RESOLVER_MAX_ATTEMPTS", "3"))
ASN_CACHE_TTL_DAYS = int(os.getenv("GMJFLOW_ASN_CACHE_TTL_DAYS", "30"))
ASN_CACHE_TTL_SECONDS = int(os.getenv("GMJFLOW_ASN_CACHE_TTL_SECONDS", str(ASN_CACHE_TTL_DAYS * 86400)))
ASN_RESOLVER_STOP = threading.Event()
SQLITE_MIGRATION_LOCK = threading.Lock()
SENSOR_DB_READY = False
DASHBOARD_RESPONSE_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
DASHBOARD_RESPONSE_CACHE_LOCK = threading.Lock()
GEOIP_MMDB_PATH = os.getenv("GMJFLOW_GEOIP_MMDB_PATH", "/app/data/GeoLite2-City.mmdb").strip()
GEOIP_LAST_ERROR = ""

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

PROTOCOL_COLORS = {
    "TCP": "#2563eb",
    "UDP": "#16a34a",
    "ICMP": "#f59e0b",
    "ICMPv6": "#f97316",
    "TCP+SYN": "#dc2626",
    "GRE": "#0891b2",
    "ESP": "#7c3aed",
    "OTHER": "#64748b",
}

COUNTRY_CENTROIDS = {
    "BR": ("Brazil", -14.2350, -51.9253),
    "US": ("United States", 37.0902, -95.7129),
    "CA": ("Canada", 56.1304, -106.3468),
    "MX": ("Mexico", 23.6345, -102.5528),
    "AR": ("Argentina", -38.4161, -63.6167),
    "CL": ("Chile", -35.6751, -71.5430),
    "CO": ("Colombia", 4.5709, -74.2973),
    "PE": ("Peru", -9.1900, -75.0152),
    "GB": ("United Kingdom", 55.3781, -3.4360),
    "DE": ("Germany", 51.1657, 10.4515),
    "FR": ("France", 46.2276, 2.2137),
    "ES": ("Spain", 40.4637, -3.7492),
    "IT": ("Italy", 41.8719, 12.5674),
    "NL": ("Netherlands", 52.1326, 5.2913),
    "PT": ("Portugal", 39.3999, -8.2245),
    "SE": ("Sweden", 60.1282, 18.6435),
    "RU": ("Russia", 61.5240, 105.3188),
    "CN": ("China", 35.8617, 104.1954),
    "JP": ("Japan", 36.2048, 138.2529),
    "KR": ("South Korea", 35.9078, 127.7669),
    "IN": ("India", 20.5937, 78.9629),
    "SG": ("Singapore", 1.3521, 103.8198),
    "AU": ("Australia", -25.2744, 133.7751),
    "ZA": ("South Africa", -30.5595, 22.9375),
}

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
    "sample_rate_default_in",
    "sample_rate_default_out",
    "sample_rate_mode",
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
    "sample_rate_override",
    "if_oper_status",
    "color",
    "monitor_enabled",
]

INTERFACE_BOOL_COLUMNS = {"monitor_enabled", "sample_rate_override"}
SAMPLE_RATE_MODES = {"sensor_default", "per_interface", "snmp_auto"}

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
ANOMALY_DETECTION_STOP = threading.Event()
ANOMALY_DETECTION_THREAD: threading.Thread | None = None
SYSTEM_SETTING_DEFAULTS = {
    "database_retention_enabled": "1",
    "flow_retention_days": "7",
    "flow_raw_retention_days": "7",
    "flow_1m_retention_days": "30",
    "flow_tops_1m_retention_days": "15",
    "snmp_retention_days": "90",
    "database_last_cleanup_at": "",
    "database_cleanup_hour": "3",
}

ATTACK_DOMAIN_TYPES = {"any", "internal_ip", "external_ip", "prefix", "sensor", "interface"}
ATTACK_DIRECTIONS = {"receives", "sends", "both"}
ATTACK_COMPARISONS = {"over"}
ATTACK_THRESHOLD_UNITS = {"bits_s", "packets_s", "flows_s"}
ATTACK_PROTOCOLS = {"any", "tcp", "udp", "icmp", "icmpv6", "gre", "esp", "other"}
ATTACK_TCP_FLAGS = {"any", "fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr", "syn+ack", "null", "none"}
ATTACK_DECODERS = {
    "IP",
    "TCP",
    "TCP+SYN",
    "TCP+SYNACK",
    "TCP+ACK",
    "TCP+RST",
    "TCP+NULL",
    "TCP+ALL",
    "UDP",
    "ICMP",
    "DNS",
    "NTP",
    "QUIC",
    "UDP+QUIC",
    "HTTP",
    "HTTPS",
    "MAIL",
    "SIP",
    "IPSEC",
    "FRAGMENT",
    "NETBIOS",
    "MEMCACHED",
    "OTHER",
    "INVALID",
    "FLOWS",
    "FLOW+SYN",
}
ATTACK_SEVERITIES = {"info", "warning", "critical"}
ATTACK_RESPONSE_ACTIONS = {"alert_only", "response_ip", "webhook_future", "ignore"}
ATTACK_VECTOR_PRESET_TEMPLATES = [
    {
        "id": "dns-amplification",
        "name": "DNS Amplification",
        "decoder": "DNS",
        "protocol": "udp",
        "src_port": "53",
        "dst_port": "any",
        "direction": "receives",
        "threshold_unit": "bits_s",
        "threshold_value": 1_000_000_000,
        "tcp_flags": "any",
    },
    {
        "id": "ntp-amplification",
        "name": "NTP Amplification",
        "decoder": "NTP",
        "protocol": "udp",
        "src_port": "123",
        "dst_port": "any",
        "direction": "receives",
        "threshold_unit": "bits_s",
        "threshold_value": 1_000_000_000,
        "tcp_flags": "any",
    },
    {
        "id": "tcp-syn-flood",
        "name": "TCP SYN Flood",
        "decoder": "TCP+SYN",
        "protocol": "tcp",
        "src_port": "any",
        "dst_port": "any",
        "direction": "receives",
        "threshold_unit": "packets_s",
        "threshold_value": 500_000,
        "tcp_flags": "syn",
    },
    {
        "id": "udp-flood",
        "name": "UDP Flood",
        "decoder": "UDP",
        "protocol": "udp",
        "src_port": "any",
        "dst_port": "any",
        "direction": "receives",
        "threshold_unit": "bits_s",
        "threshold_value": 2_000_000_000,
        "tcp_flags": "any",
    },
    {
        "id": "https-flood",
        "name": "HTTPS Flood",
        "decoder": "HTTPS",
        "protocol": "tcp",
        "src_port": "any",
        "dst_port": "443",
        "direction": "receives",
        "threshold_unit": "packets_s",
        "threshold_value": 500_000,
        "tcp_flags": "ack",
    },
    {
        "id": "asn-source-abuse",
        "name": "ASN Source Abuse",
        "decoder": "IP",
        "protocol": "any",
        "src_port": "any",
        "dst_port": "any",
        "direction": "receives",
        "threshold_unit": "bits_s",
        "threshold_value": 1_000_000_000,
        "tcp_flags": "any",
    },
]
LEARN_DECODER_UNITS = (
    ("IP", "bits_s"),
    ("IP", "packets_s"),
    ("IP", "flows_s"),
    ("TCP", "bits_s"),
    ("TCP", "packets_s"),
    ("TCP", "flows_s"),
    ("TCP+SYN", "packets_s"),
    ("UDP", "bits_s"),
    ("UDP", "packets_s"),
    ("UDP", "flows_s"),
    ("ICMP", "bits_s"),
    ("ICMP", "packets_s"),
    ("ICMP", "flows_s"),
    ("OTHER", "bits_s"),
    ("OTHER", "packets_s"),
    ("FLOWS", "flows_s"),
)

IP_ZONE_PREFIX_TYPES = {"client", "public_cgnat", "infrastructure", "server", "cache", "transit", "other"}
DETECTION_DOMAINS = {"internal_ip", "subnet"}
DETECTION_DIRECTIONS = {"transmits", "receives", "both"}
DETECTION_METRICS = {
    "packets_s",
    "bits_s",
    "flows_s",
    "flows",
    "unique_dst_ips",
    "unique_dst_ports",
    "unique_src_ports",
}
DETECTION_COMPARISONS = {"over"}
DETECTION_RESPONSES = {"DETECTION_ONLY"}
DETECTION_WHITELIST_TYPES = {"source", "destination", "source_destination"}
DETECTION_PROTOCOLS = {
    "ALL",
    "IP/ALL",
    "IP",
    "UDP",
    "TCP",
    "TCP+SYN",
    "ICMP",
    "GRE",
    "DNS",
    "CLDAP",
    "UDP-QUIC",
    "OTHER",
}

BGP_CONNECTOR_BACKENDS = {"dry_run", "exabgp", "gobgp", "frr", "manual_export"}
BGP_CONNECTOR_ROLES = {"flowspec_mitigation", "rtbh_blackhole", "diversion_mitigation", "generic_bgp"}
BGP_MODES = {"detection_only", "dry_run", "manual_approval", "automatic"}
BGP_RESPONSE_TYPES = {"detection_only", "flowspec", "rtbh", "diversion"}
BGP_ACTIONS = {"discard", "rate_limit", "redirect", "announce_route"}
BGP_TARGET_SELECTORS = {"src_ip", "dst_ip", "src_and_dst_ip", "target_ip", "target_cidr", "anomaly_src_ip", "anomaly_dst_ip"}
BGP_PROTOCOL_SELECTORS = {"any", "manual", "anomaly_protocol", "tcp", "udp", "icmp"}
BGP_PORT_SELECTORS = {"any", "manual", "anomaly_src_port", "anomaly_dst_port", "fixed"}
BGP_TCP_FLAGS_SELECTORS = {"any", "manual", "syn", "syn_ack"}
BGP_ANNOUNCEMENT_STATUSES = {"dry_run", "pending_approval", "announced", "rejected", "withdrawn", "failed"}
BGP_ACTIVE_STATUSES = {"dry_run", "pending_approval", "announced"}
BGP_DEFAULT_MAX_DURATION_SECONDS = 3600
BGP_DEFAULT_MAX_ACTIVE_RULES = 50


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
    sample_rate_override: bool = False
    if_oper_status: str = ""
    color: str = "#64748b"
    monitor_enabled: bool = True


class InterfaceSampleRatePayload(BaseModel):
    sample_rate_in: int = Field(1, ge=1)
    sample_rate_out: int = Field(1, ge=1)
    sample_rate_override: bool = True


class SensorSampleRateApplyPayload(BaseModel):
    inherit: bool = True
    mode: str | None = None


class AsnPrefixPayload(BaseModel):
    prefix: str
    asn: int = Field(..., ge=1)
    as_name: str = ""
    country: str = ""
    source: str = "manual"


class AsnImportPayload(BaseModel):
    items: list[AsnPrefixPayload] = Field(default_factory=list)


class AsnQueueFromFlowsPayload(BaseModel):
    lookback_minutes: int = Field(60, ge=1, le=MAX_RANGE_MINUTES)
    limit: int = Field(5000, ge=1, le=50000)
    sensor_id: int | None = Field(None, ge=1)
    interface: int | None = Field(None, ge=0)
    if_index: int | None = Field(None, ge=0)


class AsnResolvePayload(BaseModel):
    limit: int = Field(1000, ge=1, le=50000)
    force: bool = False


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
    sample_rate_default_in: int = 1
    sample_rate_default_out: int = 1
    sample_rate_mode: str = "sensor_default"
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
    flow_raw_retention_days: int | None = Field(None, ge=1, le=3650)
    flow_1m_retention_days: int | None = Field(None, ge=1, le=3650)
    flow_tops_1m_retention_days: int | None = Field(None, ge=1, le=3650)
    snmp_retention_days: int | None = Field(None, ge=1, le=3650)
    cleanup_hour: int | None = Field(None, ge=0, le=23)


class DatabaseCleanupPayload(BaseModel):
    older_than_days: int = Field(..., ge=1, le=3650)
    optimize: bool = False
    confirm: str = ""
    scope: str = "raw"
    flow_raw_older_than_days: int | None = Field(None, ge=1, le=3650)
    flow_1m_older_than_days: int | None = Field(None, ge=1, le=3650)
    flow_tops_1m_older_than_days: int | None = Field(None, ge=1, le=3650)


class DatabaseOptimizePayload(BaseModel):
    confirm: str = ""


class AttackVectorTemplatePayload(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    learn_enabled: bool = True
    learn_days: int = Field(2, ge=1, le=30)
    safety_margin_percent: float = Field(20, ge=0, le=500)


class AttackVectorPayload(BaseModel):
    template_id: int = Field(..., ge=1)
    name: str
    enabled: bool = True
    domain_type: str = "any"
    target_cidr: str | None = None
    src_cidr: str | None = None
    dst_cidr: str | None = None
    src_port: str = "any"
    dst_port: str = "any"
    protocol: str = "any"
    src_asn: str = ""
    dst_asn: str = ""
    tcp_flags: str = "any"
    window_seconds: int = Field(60, ge=1, le=86400)
    sensor_id: int | None = Field(None, ge=1)
    interface_if_index: int | None = Field(None, ge=0)
    direction: str = "receives"
    decoder: str = "IP"
    comparison: str = "over"
    threshold_value: float = Field(..., gt=0)
    threshold_unit: str = "bits_s"
    severity: str = "warning"
    response_action: str = "alert_only"
    parent_enabled: bool = True


class AttackVectorLearnPayload(BaseModel):
    template_id: int = Field(..., ge=1)
    days: int = Field(2, ge=1, le=30)
    margin_percent: float = Field(20, ge=0, le=500)
    sensor_id: int | None = Field(None, ge=1)
    target_cidr: str | None = None


class AttackVectorSuggestionApplyAllPayload(BaseModel):
    template_id: int | None = Field(None, ge=1)


class AttackVectorTestPayload(BaseModel):
    lookback_seconds: int | None = Field(None, ge=1, le=86400)
    min_duration_seconds: int | None = Field(None, ge=0, le=86400)


class IpZonePayload(BaseModel):
    name: str
    description: str = ""
    active: bool = True
    detection_template_id: int | None = Field(None, ge=1)


class IpZonePrefixPayload(BaseModel):
    cidr: str
    name: str = ""
    description: str = ""
    prefix_type: str = "client"
    active: bool = True


class DetectionTemplatePayload(BaseModel):
    name: str
    description: str = ""
    active: bool = True


class DetectionRulePayload(BaseModel):
    vector: str
    domain: str = "internal_ip"
    direction: str = "transmits"
    protocol: str = "ALL"
    metric: str = "packets_s"
    comparison: str = "over"
    warning_value: float | None = Field(None, ge=0)
    critical_value: float | None = Field(None, ge=0)
    window_seconds: int = Field(60, ge=1, le=86400)
    consecutive_windows: int = Field(1, ge=1, le=1000)
    cooldown_minutes: int = Field(5, ge=0, le=1440)
    enabled: bool = True
    response: str = "DETECTION_ONLY"


class DetectionWhitelistPayload(BaseModel):
    name: str
    description: str = ""
    active: bool = True
    type: str
    src_cidr: str | None = None
    dst_cidr: str | None = None
    protocol: str | None = None
    vector: str | None = None
    zone_id: int | None = Field(None, ge=1)


class BgpConnectorPayload(BaseModel):
    name: str
    role: str = "generic_bgp"
    backend_type: str = "dry_run"
    mode: str = "dry_run"
    local_asn: int | None = Field(None, ge=1, le=4294967295)
    peer_asn: int | None = Field(None, ge=1, le=4294967295)
    peer_ip: str = ""
    router_id: str = ""
    default_next_hop: str = ""
    default_community: str = ""
    default_large_community: str = ""
    max_active_rules: int = Field(BGP_DEFAULT_MAX_ACTIVE_RULES, ge=1, le=10000)
    max_duration_seconds: int = Field(BGP_DEFAULT_MAX_DURATION_SECONDS, ge=60, le=604800)
    enabled: bool = True
    notes: str = ""


class BgpResponseProfilePayload(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    response_type: str = "flowspec"
    connector_id: int | None = Field(None, ge=1)
    approval_mode: str = "manual_approval"
    action: str = "discard"
    target_selector: str = "src_ip"
    protocol_selector: str = "anomaly_protocol"
    src_port_selector: str = "any"
    src_port_value: str = ""
    dst_port_selector: str = "any"
    dst_port_value: str = ""
    tcp_flags_selector: str = "any"
    rate_limit_bps: int | None = Field(None, ge=1)
    redirect_target: str = ""
    next_hop: str = ""
    community: str = ""
    large_community: str = ""
    require_protocol_or_port: bool = True
    allow_wide_prefix: bool = False
    max_duration_seconds: int = Field(BGP_DEFAULT_MAX_DURATION_SECONDS, ge=60, le=604800)
    default_duration_seconds: int = Field(1800, ge=60, le=604800)


class BgpProtectedPrefixPayload(BaseModel):
    cidr: str
    name: str = ""
    reason: str = ""
    enabled: bool = True
    block_rtbh: bool = True
    block_flowspec: bool = True
    block_diversion: bool = False


class BgpAnnouncementDryRunPayload(BaseModel):
    response_profile_id: int = Field(..., ge=1)
    connector_id: int | None = Field(None, ge=1)
    src_ip: str | None = None
    dst_ip: str | None = None
    target_ip: str | None = None
    target_cidr: str | None = None
    src_port: int | None = Field(None, ge=1, le=65535)
    dst_port: int | None = Field(None, ge=1, le=65535)
    protocol: str | None = None
    tcp_flags: str | None = None
    duration_seconds: int | None = Field(None, ge=60, le=604800)
    reason: str = ""


def get_client():
    return clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST", "localhost"),
        port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "flowdb"),
        connect_timeout=int(os.getenv("CLICKHOUSE_CONNECT_TIMEOUT_SECONDS", "5")),
        send_receive_timeout=int(os.getenv("CLICKHOUSE_QUERY_TIMEOUT_SECONDS", "30")),
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
    started = time.monotonic()
    try:
        return client.query(query, parameters=parameters or {})
    finally:
        elapsed = time.monotonic() - started
        if elapsed > 2:
            logger.warning("Query ClickHouse lenta %.2fs: %s", elapsed, " ".join(query.split())[:500])
        close_client(client)


def command_clickhouse(command: str, parameters: dict[str, Any] | None = None) -> Any:
    client = get_client()
    try:
        return client.command(command, parameters=parameters or {})
    finally:
        close_client(client)


CLICKHOUSE_SCHEMA_READY = False


def ensure_clickhouse_schema() -> None:
    global CLICKHOUSE_SCHEMA_READY
    if CLICKHOUSE_SCHEMA_READY:
        return
    commands = (
        "ALTER TABLE flow_raw ADD COLUMN IF NOT EXISTS src_asn UInt32 DEFAULT 0",
        "ALTER TABLE flow_raw ADD COLUMN IF NOT EXISTS dst_asn UInt32 DEFAULT 0",
        "ALTER TABLE flow_raw ADD COLUMN IF NOT EXISTS src_as_name String DEFAULT ''",
        "ALTER TABLE flow_raw ADD COLUMN IF NOT EXISTS dst_as_name String DEFAULT ''",
    )
    for command in commands:
        command_clickhouse(command)
    CLICKHOUSE_SCHEMA_READY = True


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
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError as exc:
        if "locked" not in str(exc).lower():
            raise
    conn.execute("PRAGMA synchronous=NORMAL")
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


def ensure_attack_vector_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS attack_vector_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            learn_enabled INTEGER NOT NULL DEFAULT 1,
            learn_days INTEGER NOT NULL DEFAULT 2,
            safety_margin_percent REAL NOT NULL DEFAULT 20,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS attack_vectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            domain_type TEXT NOT NULL DEFAULT 'any',
            target_cidr TEXT,
            src_cidr TEXT,
            dst_cidr TEXT,
            src_port TEXT NOT NULL DEFAULT 'any',
            dst_port TEXT NOT NULL DEFAULT 'any',
            protocol TEXT NOT NULL DEFAULT 'any',
            src_asn TEXT NOT NULL DEFAULT '',
            dst_asn TEXT NOT NULL DEFAULT '',
            tcp_flags TEXT NOT NULL DEFAULT 'any',
            window_seconds INTEGER NOT NULL DEFAULT 60,
            sensor_id INTEGER,
            interface_if_index INTEGER,
            direction TEXT NOT NULL DEFAULT 'receives',
            decoder TEXT NOT NULL DEFAULT 'IP',
            comparison TEXT NOT NULL DEFAULT 'over',
            threshold_value REAL NOT NULL,
            threshold_unit TEXT NOT NULL DEFAULT 'bits_s',
            severity TEXT NOT NULL DEFAULT 'warning',
            response_action TEXT NOT NULL DEFAULT 'alert_only',
            parent_enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(template_id) REFERENCES attack_vector_templates(id) ON DELETE CASCADE,
            FOREIGN KEY(sensor_id) REFERENCES sensors(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS attack_vector_suggestions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_id INTEGER NOT NULL,
            sensor_id INTEGER,
            interface_if_index INTEGER,
            domain_type TEXT NOT NULL DEFAULT 'any',
            target_cidr TEXT,
            direction TEXT NOT NULL DEFAULT 'receives',
            decoder TEXT NOT NULL,
            threshold_value REAL NOT NULL,
            threshold_unit TEXT NOT NULL,
            baseline_p95 REAL NOT NULL DEFAULT 0,
            baseline_p99 REAL NOT NULL DEFAULT 0,
            baseline_max REAL NOT NULL DEFAULT 0,
            baseline_average REAL NOT NULL DEFAULT 0,
            margin_percent REAL NOT NULL DEFAULT 20,
            confidence REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT '',
            applied_at TEXT,
            FOREIGN KEY(template_id) REFERENCES attack_vector_templates(id) ON DELETE CASCADE,
            FOREIGN KEY(sensor_id) REFERENCES sensors(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS anomaly_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_vector_id INTEGER,
            sensor_id INTEGER,
            interface_if_index INTEGER,
            target_ip TEXT,
            target_cidr TEXT,
            direction TEXT NOT NULL,
            decoder TEXT NOT NULL,
            severity TEXT NOT NULL,
            metric_unit TEXT NOT NULL,
            threshold_value REAL NOT NULL,
            observed_value REAL NOT NULL,
            peak_value REAL NOT NULL,
            started_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            ended_at TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            estimated_bytes INTEGER NOT NULL DEFAULT 0,
            estimated_packets INTEGER NOT NULL DEFAULT 0,
            flow_count INTEGER NOT NULL DEFAULT 0,
            summary TEXT NOT NULL DEFAULT '',
            dedupe_key TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(attack_vector_id) REFERENCES attack_vectors(id) ON DELETE SET NULL,
            FOREIGN KEY(sensor_id) REFERENCES sensors(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS anomaly_event_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            anomaly_event_id INTEGER NOT NULL,
            flow_time TEXT NOT NULL,
            sensor TEXT,
            exporter_ip TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            proto INTEGER,
            tcp_flags INTEGER,
            input_if INTEGER,
            output_if INTEGER,
            bytes INTEGER,
            packets INTEGER,
            flow_count INTEGER,
            FOREIGN KEY(anomaly_event_id) REFERENCES anomaly_events(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_vectors_template ON attack_vectors(template_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_vectors_enabled ON attack_vectors(enabled, parent_enabled)")
    ensure_sqlite_column(conn, "attack_vectors", "src_cidr", "src_cidr TEXT")
    ensure_sqlite_column(conn, "attack_vectors", "dst_cidr", "dst_cidr TEXT")
    ensure_sqlite_column(conn, "attack_vectors", "src_port", "src_port TEXT NOT NULL DEFAULT 'any'")
    ensure_sqlite_column(conn, "attack_vectors", "dst_port", "dst_port TEXT NOT NULL DEFAULT 'any'")
    ensure_sqlite_column(conn, "attack_vectors", "protocol", "protocol TEXT NOT NULL DEFAULT 'any'")
    ensure_sqlite_column(conn, "attack_vectors", "src_asn", "src_asn TEXT NOT NULL DEFAULT ''")
    ensure_sqlite_column(conn, "attack_vectors", "dst_asn", "dst_asn TEXT NOT NULL DEFAULT ''")
    ensure_sqlite_column(conn, "attack_vectors", "tcp_flags", "tcp_flags TEXT NOT NULL DEFAULT 'any'")
    ensure_sqlite_column(conn, "attack_vectors", "window_seconds", "window_seconds INTEGER NOT NULL DEFAULT 60")
    ensure_sqlite_column(conn, "attack_vector_suggestions", "interface_if_index", "interface_if_index INTEGER")
    ensure_sqlite_column(conn, "attack_vector_suggestions", "updated_at", "updated_at TEXT NOT NULL DEFAULT ''")
    conn.execute(
        """
        UPDATE attack_vector_suggestions
        SET updated_at = created_at
        WHERE updated_at = ''
        """
    )
    conn.execute(
        """
        DELETE FROM attack_vector_suggestions
        WHERE applied_at IS NULL
          AND id NOT IN (
              SELECT MAX(id)
              FROM attack_vector_suggestions
              WHERE applied_at IS NULL
              GROUP BY
                  template_id,
                  COALESCE(sensor_id, 0),
                  COALESCE(interface_if_index, 0),
                  domain_type,
                  COALESCE(target_cidr, ''),
                  direction,
                  decoder,
                  threshold_unit
          )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_vector_suggestions_template ON attack_vector_suggestions(template_id)")
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_attack_vector_suggestions_pending_key
        ON attack_vector_suggestions (
            template_id,
            COALESCE(sensor_id, 0),
            COALESCE(interface_if_index, 0),
            domain_type,
            COALESCE(target_cidr, ''),
            direction,
            decoder,
            threshold_unit
        )
        WHERE applied_at IS NULL
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_events_status ON anomaly_events(status, last_seen_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_events_dedupe ON anomaly_events(dedupe_key, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_event_flows_event ON anomaly_event_flows(anomaly_event_id)")
    seed_default_attack_vectors(conn)


def ensure_asn_db(conn: sqlite3.Connection) -> None:
    existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(asn_prefixes)").fetchall()}
    if existing_columns and "id" not in existing_columns:
        conn.execute("ALTER TABLE asn_prefixes RENAME TO asn_prefixes_legacy")
        conn.execute(
            """
            CREATE TABLE asn_prefixes (
                id INTEGER PRIMARY KEY,
                prefix TEXT NOT NULL,
                ip_version INTEGER NOT NULL,
                asn INTEGER NOT NULL,
                as_name TEXT NOT NULL DEFAULT '',
                country TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                first_seen_at TEXT,
                updated_at TEXT,
                UNIQUE(prefix, asn)
            )
            """
        )
        now = utc_now_iso()
        legacy_rows = conn.execute(
            """
            SELECT prefix, asn, as_name, source, updated_at
            FROM asn_prefixes_legacy
            WHERE COALESCE(asn, 0) > 0
            """
        ).fetchall()
        for row in legacy_rows:
            try:
                network = ip_network(clean_text(row["prefix"]), strict=False)
            except ValueError:
                continue
            conn.execute(
                """
                INSERT OR IGNORE INTO asn_prefixes (
                    prefix, ip_version, asn, as_name, country, source, first_seen_at, updated_at
                )
                VALUES (?, ?, ?, ?, '', ?, ?, ?)
                """,
                (
                    str(network),
                    network.version,
                    int(row["asn"] or 0),
                    clean_text(row["as_name"]),
                    clean_text(row["source"]),
                    clean_text(row["updated_at"]) or now,
                    clean_text(row["updated_at"]) or now,
                ),
            )
        conn.execute("DROP TABLE asn_prefixes_legacy")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asn_prefixes (
            id INTEGER PRIMARY KEY,
            prefix TEXT NOT NULL,
            ip_version INTEGER NOT NULL,
            asn INTEGER NOT NULL,
            as_name TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            first_seen_at TEXT,
            updated_at TEXT,
            UNIQUE(prefix, asn)
        )
        """
    )
    ensure_sqlite_column(conn, "asn_prefixes", "ip_version", "ip_version INTEGER NOT NULL DEFAULT 4")
    ensure_sqlite_column(conn, "asn_prefixes", "country", "country TEXT NOT NULL DEFAULT ''")
    ensure_sqlite_column(conn, "asn_prefixes", "first_seen_at", "first_seen_at TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asn_info (
            asn INTEGER PRIMARY KEY,
            as_name TEXT NOT NULL DEFAULT '',
            org_name TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            raw_json TEXT NOT NULL DEFAULT '',
            first_seen_at TEXT,
            updated_at TEXT,
            expires_at TEXT,
            last_error TEXT NOT NULL DEFAULT ''
        )
        """
    )
    ensure_sqlite_column(conn, "asn_info", "org_name", "org_name TEXT NOT NULL DEFAULT ''")
    ensure_sqlite_column(conn, "asn_info", "raw_json", "raw_json TEXT NOT NULL DEFAULT ''")
    ensure_sqlite_column(conn, "asn_info", "first_seen_at", "first_seen_at TEXT")
    ensure_sqlite_column(conn, "asn_info", "expires_at", "expires_at TEXT")
    ensure_sqlite_column(conn, "asn_info", "last_error", "last_error TEXT NOT NULL DEFAULT ''")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asn_lookup_cache (
            ip TEXT PRIMARY KEY,
            ip_version INTEGER NOT NULL,
            asn INTEGER NOT NULL DEFAULT 0,
            prefix TEXT NOT NULL DEFAULT '',
            as_name TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            resolved_at TEXT,
            expires_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asn_resolution_queue (
            ip TEXT PRIMARY KEY,
            ip_version INTEGER NOT NULL,
            asn INTEGER NOT NULL DEFAULT 0,
            priority INTEGER NOT NULL DEFAULT 100,
            first_seen_at TEXT,
            last_seen_at TEXT,
            updated_at TEXT,
            attempts INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'queued',
            last_error TEXT NOT NULL DEFAULT '',
            resolved_at TEXT
        )
        """
    )
    ensure_sqlite_column(conn, "asn_resolution_queue", "asn", "asn INTEGER NOT NULL DEFAULT 0")
    ensure_sqlite_column(conn, "asn_resolution_queue", "priority", "priority INTEGER NOT NULL DEFAULT 100")
    ensure_sqlite_column(conn, "asn_resolution_queue", "updated_at", "updated_at TEXT")
    ensure_sqlite_column(conn, "asn_resolution_queue", "resolved_at", "resolved_at TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS geo_ip_cache (
            ip_prefix TEXT PRIMARY KEY,
            ip_version INTEGER NOT NULL,
            country_code TEXT NOT NULL DEFAULT '',
            country_name TEXT NOT NULL DEFAULT '',
            region TEXT NOT NULL DEFAULT '',
            city TEXT NOT NULL DEFAULT '',
            latitude REAL,
            longitude REAL,
            asn INTEGER NOT NULL DEFAULT 0,
            as_name TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            updated_at TEXT,
            expires_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dashboard_layouts (
            id INTEGER PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT 'global',
            name TEXT NOT NULL DEFAULT 'default',
            layout_json TEXT NOT NULL DEFAULT '',
            is_default INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, name)
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_asn_prefixes_asn
        ON asn_prefixes(asn)
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_asn_prefixes_ip_version ON asn_prefixes(ip_version)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_asn_lookup_cache_expires ON asn_lookup_cache(expires_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_asn_resolution_queue_status ON asn_resolution_queue(status, priority, last_seen_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_asn_resolution_queue_asn ON asn_resolution_queue(asn)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_geo_ip_cache_expires ON geo_ip_cache(expires_at)")


def seed_default_attack_vectors(conn: sqlite3.Connection) -> None:
    now = utc_now_iso()
    row = conn.execute(
        "SELECT id FROM attack_vector_templates WHERE name = ? ORDER BY id LIMIT 1",
        ("THRESHOLD-PADRAO",),
    ).fetchone()
    if row is None:
        cursor = conn.execute(
            """
            INSERT INTO attack_vector_templates (
                name,
                description,
                enabled,
                learn_enabled,
                learn_days,
                safety_margin_percent,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "THRESHOLD-PADRAO",
                "Template inicial conservador. O ideal e rodar aprendizado automatico por 2 dias.",
                1,
                1,
                2,
                20,
                now,
                now,
            ),
        )
        template_id = int(cursor.lastrowid)
    else:
        template_id = int(row["id"])

    count = conn.execute(
        "SELECT COUNT(*) AS count FROM attack_vectors WHERE template_id = ?",
        (template_id,),
    ).fetchone()["count"]
    if int(count or 0) > 0:
        return

    defaults = [
        ("Internal IP receives IP packets warning", "internal_ip", "receives", "IP", 5_000_000, "packets_s", "warning"),
        ("Internal IP receives IP bits critical", "internal_ip", "receives", "IP", 30_000_000_000, "bits_s", "critical"),
        ("Internal IP receives TCP packets warning", "internal_ip", "receives", "TCP", 2_000_000, "packets_s", "warning"),
        ("Internal IP receives TCP bits critical", "internal_ip", "receives", "TCP", 10_000_000_000, "bits_s", "critical"),
        ("Internal IP receives TCP SYN packets warning", "internal_ip", "receives", "TCP+SYN", 1_000_000, "packets_s", "warning"),
        ("Internal IP receives UDP bits warning", "internal_ip", "receives", "UDP", 5_000_000_000, "bits_s", "warning"),
        ("Internal IP receives ICMP packets warning", "internal_ip", "receives", "ICMP", 500_000, "packets_s", "warning"),
        ("Internal IP receives flows warning", "internal_ip", "receives", "FLOWS", 300_000, "flows_s", "warning"),
    ]
    for name, domain_type, direction, decoder, value, unit, severity in defaults:
        conn.execute(
            """
            INSERT INTO attack_vectors (
                template_id,
                name,
                enabled,
                domain_type,
                target_cidr,
                src_cidr,
                dst_cidr,
                src_port,
                dst_port,
                protocol,
                src_asn,
                dst_asn,
                tcp_flags,
                window_seconds,
                sensor_id,
                interface_if_index,
                direction,
                decoder,
                comparison,
                threshold_value,
                threshold_unit,
                severity,
                response_action,
                parent_enabled,
                created_at,
                updated_at
            )
            VALUES (?, ?, 1, ?, NULL, NULL, NULL, 'any', 'any', 'any', '', '', 'any', 60, NULL, NULL, ?, ?, 'over', ?, ?, ?, 'alert_only', 1, ?, ?)
            """,
            (template_id, name, domain_type, direction, decoder, value, unit, severity, now, now),
        )


def ensure_ip_zone_detection_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS detection_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS detection_template_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_id INTEGER NOT NULL,
            vector TEXT NOT NULL,
            domain TEXT NOT NULL,
            direction TEXT NOT NULL,
            protocol TEXT,
            metric TEXT NOT NULL,
            comparison TEXT NOT NULL DEFAULT 'over',
            warning_value REAL,
            critical_value REAL,
            window_seconds INTEGER NOT NULL DEFAULT 60,
            consecutive_windows INTEGER NOT NULL DEFAULT 1,
            cooldown_minutes INTEGER NOT NULL DEFAULT 5,
            enabled INTEGER NOT NULL DEFAULT 1,
            response TEXT NOT NULL DEFAULT 'DETECTION_ONLY',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(template_id) REFERENCES detection_templates(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_zones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            detection_template_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(detection_template_id) REFERENCES detection_templates(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_zone_prefixes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_id INTEGER NOT NULL,
            cidr TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            prefix_type TEXT NOT NULL DEFAULT 'client',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(zone_id) REFERENCES ip_zones(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS detection_whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            type TEXT NOT NULL,
            src_cidr TEXT,
            dst_cidr TEXT,
            protocol TEXT,
            vector TEXT,
            zone_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(zone_id) REFERENCES ip_zones(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS security_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vector TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            zone_id INTEGER,
            zone_name TEXT,
            template_id INTEGER,
            template_name TEXT,
            rule_id INTEGER,
            prefix_id INTEGER,
            prefix_cidr TEXT,
            domain TEXT,
            direction TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            packets_s REAL,
            bits_s REAL,
            flows REAL,
            flows_s REAL,
            packets REAL,
            bytes REAL,
            unique_dst_ips INTEGER,
            unique_dst_ports INTEGER,
            unique_src_ports INTEGER,
            first_seen TEXT,
            last_seen TEXT,
            message TEXT,
            recommended_action TEXT,
            response TEXT NOT NULL DEFAULT 'DETECTION_ONLY',
            dedupe_key TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    ensure_sqlite_column(conn, "security_anomalies", "dedupe_key", "dedupe_key TEXT NOT NULL DEFAULT ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_zone_prefixes_zone ON ip_zone_prefixes(zone_id, active)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_zones_active ON ip_zones(active)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_template_rules_template ON detection_template_rules(template_id, enabled)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_whitelist_active ON detection_whitelist(active, zone_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_security_anomalies_status ON security_anomalies(status, last_seen)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_security_anomalies_dedupe ON security_anomalies(dedupe_key, status)")
    seed_default_detection_template(conn)


def seed_default_detection_template(conn: sqlite3.Connection) -> None:
    now = utc_now_iso()
    row = conn.execute(
        "SELECT id FROM detection_templates WHERE name = ? ORDER BY id LIMIT 1",
        ("CLIENTES-PUBLICOS-DEFAULT",),
    ).fetchone()
    if row is None:
        cursor = conn.execute(
            """
            INSERT INTO detection_templates (name, description, active, created_at, updated_at)
            VALUES (?, ?, 1, ?, ?)
            """,
            (
                "CLIENTES-PUBLICOS-DEFAULT",
                "Template default para deteccao informativa de IPs /32 dentro de prefixos publicos monitorados.",
                now,
                now,
            ),
        )
        template_id = int(cursor.lastrowid)
    else:
        template_id = int(row["id"])

    count = conn.execute(
        "SELECT COUNT(*) AS count FROM detection_template_rules WHERE template_id = ?",
        (template_id,),
    ).fetchone()["count"]
    if int(count or 0) > 0:
        return

    defaults = [
        ("PREFIX_INTERNAL_IP_HIGH_UDP_PPS", "internal_ip", "transmits", "UDP", "packets_s", 80_000, 150_000),
        ("PREFIX_INTERNAL_IP_TO_DST_HIGH_UDP_PPS", "internal_ip", "transmits", "UDP", "packets_s", 50_000, 120_000),
        ("PREFIX_INTERNAL_IP_HIGH_FLOW_RATE", "internal_ip", "transmits", "ALL", "flows_s", 500, 1_500),
        ("PREFIX_INTERNAL_IP_TO_DST_HIGH_FLOW_RATE", "internal_ip", "transmits", "ALL", "flows_s", 200, 800),
        ("PREFIX_SUBNET_HIGH_PPS", "subnet", "transmits", "ALL", "packets_s", 1_000_000, 3_000_000),
        ("DNS_INTERNAL_IP_HIGH_PPS", "internal_ip", "transmits", "DNS", "packets_s", 10_000, 30_000),
        ("DNS_INTERNAL_IP_HIGH_BITS", "internal_ip", "transmits", "DNS", "bits_s", 20_000_000, 50_000_000),
        ("DNS_INTERNAL_IP_TO_DST_HIGH_PPS", "internal_ip", "transmits", "DNS", "packets_s", 5_000, 15_000),
    ]
    for vector, domain, direction, protocol, metric, warning, critical in defaults:
        conn.execute(
            """
            INSERT INTO detection_template_rules (
                template_id,
                vector,
                domain,
                direction,
                protocol,
                metric,
                comparison,
                warning_value,
                critical_value,
                window_seconds,
                consecutive_windows,
                cooldown_minutes,
                enabled,
                response,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'over', ?, ?, 60, 1, 5, 1, 'DETECTION_ONLY', ?, ?)
            """,
            (template_id, vector, domain, direction, protocol, metric, warning, critical, now, now),
        )


def seed_default_bgp_response_profiles(conn: sqlite3.Connection) -> None:
    now = utc_now_iso()
    defaults = [
        {
            "name": "FLOWSPEC_BLOCK_SRC_DNS",
            "description": "Bloqueia origem que gera trafego DNS/UDP suspeito.",
            "response_type": "flowspec",
            "approval_mode": "manual_approval",
            "action": "discard",
            "target_selector": "src_ip",
            "protocol_selector": "udp",
            "dst_port_selector": "fixed",
            "dst_port_value": "53",
            "require_protocol_or_port": 1,
        },
        {
            "name": "FLOWSPEC_BLOCK_DST_DNS",
            "description": "Bloqueia destino de trafego DNS/UDP suspeito.",
            "response_type": "flowspec",
            "approval_mode": "manual_approval",
            "action": "discard",
            "target_selector": "dst_ip",
            "protocol_selector": "udp",
            "dst_port_selector": "fixed",
            "dst_port_value": "53",
            "require_protocol_or_port": 1,
        },
        {
            "name": "FLOWSPEC_BLOCK_SRC_TO_DST_UDP",
            "description": "Bloqueia fluxo UDP origem-destino a partir da anomalia.",
            "response_type": "flowspec",
            "approval_mode": "manual_approval",
            "action": "discard",
            "target_selector": "src_and_dst_ip",
            "protocol_selector": "udp",
            "dst_port_selector": "anomaly_dst_port",
            "require_protocol_or_port": 1,
        },
        {
            "name": "FLOWSPEC_BLOCK_SYN_TO_DST",
            "description": "Bloqueia SYN TCP direcionado ao destino.",
            "response_type": "flowspec",
            "approval_mode": "manual_approval",
            "action": "discard",
            "target_selector": "dst_ip",
            "protocol_selector": "tcp",
            "tcp_flags_selector": "syn",
            "require_protocol_or_port": 1,
        },
        {
            "name": "RTBH_DST_IP",
            "description": "Gera RTBH para IP de destino /32 ou /128.",
            "response_type": "rtbh",
            "approval_mode": "manual_approval",
            "action": "announce_route",
            "target_selector": "dst_ip",
            "protocol_selector": "any",
            "require_protocol_or_port": 0,
        },
        {
            "name": "RTBH_SRC_IP",
            "description": "Gera RTBH para IP de origem /32 ou /128.",
            "response_type": "rtbh",
            "approval_mode": "manual_approval",
            "action": "announce_route",
            "target_selector": "src_ip",
            "protocol_selector": "any",
            "require_protocol_or_port": 0,
        },
        {
            "name": "DIVERT_DST_TO_SCRUBBING",
            "description": "Renderiza desvio de destino para scrubbing via next-hop/redirect.",
            "response_type": "diversion",
            "approval_mode": "manual_approval",
            "action": "redirect",
            "target_selector": "dst_ip",
            "protocol_selector": "any",
            "require_protocol_or_port": 0,
        },
    ]
    for item in defaults:
        row = conn.execute("SELECT id FROM bgp_response_profiles WHERE name = ? ORDER BY id LIMIT 1", (item["name"],)).fetchone()
        if row is not None:
            continue
        conn.execute(
            """
            INSERT INTO bgp_response_profiles (
                name, description, enabled, response_type, connector_id, approval_mode, action,
                target_selector, protocol_selector, src_port_selector, src_port_value,
                dst_port_selector, dst_port_value, tcp_flags_selector, rate_limit_bps,
                redirect_target, next_hop, community, large_community, require_protocol_or_port,
                allow_wide_prefix, max_duration_seconds, default_duration_seconds, created_at, updated_at
            )
            VALUES (
                ?, ?, 1, ?, NULL, ?, ?, ?, ?, 'any', '', ?, ?, ?, NULL,
                '', '', '', '', ?, 0, ?, 1800, ?, ?
            )
            """,
            (
                item["name"],
                item["description"],
                item["response_type"],
                item["approval_mode"],
                item["action"],
                item["target_selector"],
                item["protocol_selector"],
                item.get("dst_port_selector", "any"),
                item.get("dst_port_value", ""),
                item.get("tcp_flags_selector", "any"),
                int(item.get("require_protocol_or_port", 1)),
                BGP_DEFAULT_MAX_DURATION_SECONDS,
                now,
                now,
            ),
        )


def ensure_bgp_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS bgp_connectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'generic_bgp',
            backend_type TEXT NOT NULL DEFAULT 'dry_run',
            mode TEXT NOT NULL DEFAULT 'dry_run',
            local_asn INTEGER,
            peer_asn INTEGER,
            peer_ip TEXT NOT NULL DEFAULT '',
            router_id TEXT NOT NULL DEFAULT '',
            default_next_hop TEXT NOT NULL DEFAULT '',
            default_community TEXT NOT NULL DEFAULT '',
            default_large_community TEXT NOT NULL DEFAULT '',
            max_active_rules INTEGER NOT NULL DEFAULT 50,
            max_duration_seconds INTEGER NOT NULL DEFAULT 3600,
            enabled INTEGER NOT NULL DEFAULT 1,
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS bgp_protected_prefixes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cidr TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            block_rtbh INTEGER NOT NULL DEFAULT 1,
            block_flowspec INTEGER NOT NULL DEFAULT 1,
            block_diversion INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS bgp_response_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            response_type TEXT NOT NULL DEFAULT 'flowspec',
            connector_id INTEGER,
            approval_mode TEXT NOT NULL DEFAULT 'manual_approval',
            action TEXT NOT NULL DEFAULT 'discard',
            target_selector TEXT NOT NULL DEFAULT 'src_ip',
            protocol_selector TEXT NOT NULL DEFAULT 'anomaly_protocol',
            src_port_selector TEXT NOT NULL DEFAULT 'any',
            src_port_value TEXT NOT NULL DEFAULT '',
            dst_port_selector TEXT NOT NULL DEFAULT 'any',
            dst_port_value TEXT NOT NULL DEFAULT '',
            tcp_flags_selector TEXT NOT NULL DEFAULT 'any',
            rate_limit_bps INTEGER,
            redirect_target TEXT NOT NULL DEFAULT '',
            next_hop TEXT NOT NULL DEFAULT '',
            community TEXT NOT NULL DEFAULT '',
            large_community TEXT NOT NULL DEFAULT '',
            require_protocol_or_port INTEGER NOT NULL DEFAULT 1,
            allow_wide_prefix INTEGER NOT NULL DEFAULT 0,
            max_duration_seconds INTEGER NOT NULL DEFAULT 3600,
            default_duration_seconds INTEGER NOT NULL DEFAULT 1800,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(connector_id) REFERENCES bgp_connectors(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS bgp_announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connector_id INTEGER,
            response_profile_id INTEGER,
            anomaly_id INTEGER,
            status TEXT NOT NULL DEFAULT 'dry_run',
            response_type TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL DEFAULT '',
            target_prefix TEXT NOT NULL DEFAULT '',
            src_prefix TEXT NOT NULL DEFAULT '',
            dst_prefix TEXT NOT NULL DEFAULT '',
            protocol TEXT NOT NULL DEFAULT '',
            src_port TEXT NOT NULL DEFAULT '',
            dst_port TEXT NOT NULL DEFAULT '',
            tcp_flags TEXT NOT NULL DEFAULT '',
            duration_seconds INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT,
            rendered_command TEXT NOT NULL DEFAULT '',
            validation_errors TEXT NOT NULL DEFAULT '[]',
            validation_warnings TEXT NOT NULL DEFAULT '[]',
            raw_payload TEXT NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            approved_at TEXT,
            rejected_at TEXT,
            withdrawn_at TEXT,
            FOREIGN KEY(connector_id) REFERENCES bgp_connectors(id) ON DELETE SET NULL,
            FOREIGN KEY(response_profile_id) REFERENCES bgp_response_profiles(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS bgp_announcement_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            announcement_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(announcement_id) REFERENCES bgp_announcements(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bgp_connectors_enabled ON bgp_connectors(enabled, role)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bgp_profiles_enabled ON bgp_response_profiles(enabled, response_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bgp_protected_enabled ON bgp_protected_prefixes(enabled)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bgp_announcements_status ON bgp_announcements(status, updated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bgp_announcement_events_announcement ON bgp_announcement_events(announcement_id)")
    seed_default_bgp_response_profiles(conn)


def ensure_sensor_db() -> None:
    global SENSOR_DB_READY
    if SENSOR_DB_READY:
        return
    with SQLITE_MIGRATION_LOCK, sqlite_connection() as conn:
        if SENSOR_DB_READY:
            return
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
                sample_rate_default_in INTEGER NOT NULL DEFAULT 1,
                sample_rate_default_out INTEGER NOT NULL DEFAULT 1,
                sample_rate_mode TEXT NOT NULL DEFAULT 'sensor_default',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        ensure_sqlite_column(conn, "sensors", "sample_rate_default_in", "sample_rate_default_in INTEGER NOT NULL DEFAULT 1")
        ensure_sqlite_column(conn, "sensors", "sample_rate_default_out", "sample_rate_default_out INTEGER NOT NULL DEFAULT 1")
        ensure_sqlite_column(conn, "sensors", "sample_rate_mode", "sample_rate_mode TEXT NOT NULL DEFAULT 'sensor_default'")
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
                sample_rate_override INTEGER NOT NULL DEFAULT 0,
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
        ensure_sqlite_column(conn, "sensor_interfaces", "sample_rate_override", "sample_rate_override INTEGER NOT NULL DEFAULT 0")
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
        ensure_attack_vector_db(conn)
        ensure_ip_zone_detection_db(conn)
        ensure_asn_db(conn)
        ensure_bgp_db(conn)
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
        SENSOR_DB_READY = True


@app.on_event("startup")
def startup() -> None:
    ensure_sensor_db()
    try:
        ensure_clickhouse_schema()
    except Exception as exc:
        logger.warning("Nao foi possivel aplicar migracoes ClickHouse no startup: %s", exc)
    start_snmp_polling_thread()
    start_database_retention_thread()
    start_anomaly_detection_thread()
    start_asn_resolver_thread()


@app.on_event("shutdown")
def shutdown() -> None:
    SNMP_POLL_STOP.set()
    DATABASE_RETENTION_STOP.set()
    ANOMALY_DETECTION_STOP.set()
    ASN_RESOLVER_STOP.set()


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
    data["sample_rate_override"] = 1 if data.get("sample_rate_override") else 0
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
    data["sample_rate_default_in"] = positive_int(data.get("sample_rate_default_in") or 1, "sample_rate_default_in")
    data["sample_rate_default_out"] = positive_int(data.get("sample_rate_default_out") or 1, "sample_rate_default_out")
    data["sample_rate_mode"] = clean_text(data.get("sample_rate_mode")) or "sensor_default"
    if data["sample_rate_mode"] not in SAMPLE_RATE_MODES:
        raise HTTPException(status_code=400, detail="sample_rate_mode invalido")

    for field in SENSOR_COLUMNS:
        if field in SENSOR_BOOL_COLUMNS:
            data[field] = 1 if data.get(field) else 0
        elif field not in {
            "listener_port",
            "snmp_port",
            "granularity_seconds",
            "snmp_polling_seconds",
            "sample_rate_default_in",
            "sample_rate_default_out",
        }:
            data[field] = clean_text(data.get(field))

    interfaces = [
        normalize_interface_payload(interface)
        for interface in payload.interfaces
    ]
    return {column: data[column] for column in SENSOR_COLUMNS}, interfaces


def interface_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["monitor_enabled"] = bool(item["monitor_enabled"])
    item["sample_rate_override"] = bool(item.get("sample_rate_override"))
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
    item["effective_sample_rate_in"] = get_effective_sample_rate(sensor_id, if_index, "input")
    item["effective_sample_rate_out"] = get_effective_sample_rate(sensor_id, if_index, "output")
    item["sample_rate_source"] = "interface" if item.get("sample_rate_override") else "sensor"
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
aggregate[flows]: src_host, dst_host, src_port, dst_port, proto, tcpflags, in_iface, out_iface, src_as, dst_as, timestamp_start
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
                "      PMACCT_CSV_FIELDS: src_as,dst_as,in_iface,out_iface,src_host,dst_host,src_port,dst_port,tcpflags,proto,timestamp_start,packets,bytes",
                f"      PMACCT_EXPORTER_IP: {yaml_quote(sensor['exporter_ip'])}",
                f"      PMACCT_SENSOR: {yaml_quote(sensor['name'])}",
                "      PMACCT_SAMPLE_RATE: 1",
                "      PMACCT_PARSER_BATCH_SIZE: ${PMACCT_PARSER_BATCH_SIZE-1000}",
                "      PMACCT_PARSER_FLUSH_SECONDS: ${PMACCT_PARSER_FLUSH_SECONDS-5}",
                "      PMACCT_STATE_DIR: ${PMACCT_STATE_DIR-/var/spool/pmacct/state}",
                "      PMACCT_PARSER_START_FROM_END_IF_NO_STATE: ${PMACCT_PARSER_START_FROM_END_IF_NO_STATE-true}",
                "      GMJFLOW_PMACCT_ROTATE_ENABLED: ${GMJFLOW_PMACCT_ROTATE_ENABLED-true}",
                "      GMJFLOW_PMACCT_ROTATE_MAX_MB: ${GMJFLOW_PMACCT_ROTATE_MAX_MB-100}",
                "      GMJFLOW_PMACCT_ROTATE_KEEP_DAYS: ${GMJFLOW_PMACCT_ROTATE_KEEP_DAYS-3}",
                "      GMJFLOW_PMACCT_ROTATE_COMPRESS: ${GMJFLOW_PMACCT_ROTATE_COMPRESS-true}",
                "      GMJFLOW_PMACCT_ROTATE_CHECK_SECONDS: ${GMJFLOW_PMACCT_ROTATE_CHECK_SECONDS-30}",
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


FLOW_RETENTION_TABLES = {
    "flow_raw": {"time_column": "flow_time", "setting": "flow_raw_retention_days", "default": 7},
    "flow_1m": {"time_column": "minute", "setting": "flow_1m_retention_days", "default": 30},
    "flow_tops_1m": {"time_column": "minute", "setting": "flow_tops_1m_retention_days", "default": 15},
}


def table_retention_days(settings: dict[str, str], table: str) -> int | None:
    config = FLOW_RETENTION_TABLES.get(table)
    if not config:
        return None
    if table == "flow_raw":
        return setting_int(
            settings,
            "flow_raw_retention_days",
            setting_int(settings, "flow_retention_days", int(config["default"])),
        )
    return setting_int(settings, str(config["setting"]), int(config["default"]))


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
    settings = {key: value for key, value in SYSTEM_SETTING_DEFAULTS.items()}
    try:
        with sqlite_connection() as conn:
            settings = get_system_settings(conn)
    except Exception:
        pass
    items = []
    for row in rows_as_dicts(result):
        table = clean_text(row["table"])
        size_bytes = int(row["size_bytes"] or 0)
        first_record = None
        last_record = None
        retention_days = table_retention_days(settings, table)
        config = FLOW_RETENTION_TABLES.get(table)
        if config:
            time_column = config["time_column"]
            try:
                stats = rows_as_dicts(
                    query_clickhouse(
                        f"""
                        SELECT min({time_column}) AS first_record, max({time_column}) AS last_record
                        FROM {table}
                        """
                    )
                )
                stat_row = stats[0] if stats else {}
                first_record = iso(stat_row.get("first_record")) if stat_row.get("first_record") else None
                last_record = iso(stat_row.get("last_record")) if stat_row.get("last_record") else None
            except Exception as exc:
                logger.debug("Falha ao consultar periodo da tabela %s: %s", table, exc)
        items.append(
            {
                "table": table,
                "rows": int(row["rows"] or 0),
                "size_bytes": size_bytes,
                "size_human": human_bytes(size_bytes),
                "first_record": first_record,
                "last_record": last_record,
                "retention_days": retention_days,
                "last_cleanup_at": settings.get("database_last_cleanup_at") or None,
            }
        )
    existing_tables = {item["table"] for item in items}
    for table, config in FLOW_RETENTION_TABLES.items():
        if table in existing_tables:
            continue
        first_record = None
        last_record = None
        rows_count = 0
        try:
            stats = rows_as_dicts(
                query_clickhouse(
                    f"""
                    SELECT count() AS rows, min({config['time_column']}) AS first_record, max({config['time_column']}) AS last_record
                    FROM {table}
                    """
                )
            )
            stat_row = stats[0] if stats else {}
            rows_count = int(stat_row.get("rows") or 0)
            first_record = iso(stat_row.get("first_record")) if stat_row.get("first_record") else None
            last_record = iso(stat_row.get("last_record")) if stat_row.get("last_record") else None
        except Exception:
            continue
        items.append(
            {
                "table": table,
                "rows": rows_count,
                "size_bytes": 0,
                "size_human": human_bytes(0),
                "first_record": first_record,
                "last_record": last_record,
                "retention_days": table_retention_days(settings, table),
                "last_cleanup_at": settings.get("database_last_cleanup_at") or None,
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
            sumIf(data_compressed_bytes, table = 'flow_1m') AS flow_1m_size_bytes,
            sumIf(data_compressed_bytes, table = 'flow_tops_1m') AS flow_tops_1m_size_bytes,
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
        "flow_1m_size_bytes": int(row.get("flow_1m_size_bytes") or 0),
        "flow_tops_1m_size_bytes": int(row.get("flow_tops_1m_size_bytes") or 0),
        "clickhouse_database_size_bytes": int(row.get("clickhouse_database_size_bytes") or 0),
    }


def apply_clickhouse_table_ttl(table: str, time_column: str, enabled: bool, days: int) -> str:
    days = setting_int({"days": str(days)}, "days", 30)
    if enabled:
        command = f"ALTER TABLE {table} MODIFY TTL toDateTime({time_column}) + INTERVAL {days} DAY DELETE"
    else:
        command = f"ALTER TABLE {table} REMOVE TTL"
    command_clickhouse(command)
    return command


def apply_flow_retention_ttl(
    enabled: bool,
    flow_raw_days: int,
    flow_1m_days: int | None = None,
    flow_tops_1m_days: int | None = None,
) -> dict[str, str]:
    days_by_table = {
        "flow_raw": flow_raw_days,
        "flow_1m": flow_1m_days if flow_1m_days is not None else 30,
        "flow_tops_1m": flow_tops_1m_days if flow_tops_1m_days is not None else 15,
    }
    commands = {}
    for table, config in FLOW_RETENTION_TABLES.items():
        commands[table] = apply_clickhouse_table_ttl(
            table,
            str(config["time_column"]),
            enabled,
            int(days_by_table[table]),
        )
    return commands


def cleanup_clickhouse_table(table: str, time_column: str, older_than_days: int, optimize: bool = False) -> dict[str, Any]:
    days = setting_int({"days": str(older_than_days)}, "days", 90)
    cutoff_expression = f"now() - INTERVAL {days} DAY"
    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days)
    count_result = query_clickhouse(
        f"""
        SELECT count() AS count
        FROM {table}
        WHERE {time_column} < {cutoff_expression}
        """
    )
    rows = rows_as_dicts(count_result)
    approximate_before = int(rows[0]["count"] or 0) if rows else 0
    command = f"ALTER TABLE {table} DELETE WHERE {time_column} < {cutoff_expression}"
    command_clickhouse(command)
    optimize_command = ""
    if optimize:
        optimize_command = f"OPTIMIZE TABLE {table} FINAL"
        command_clickhouse(optimize_command)
    return {
        "table": table,
        "approximate_before": approximate_before,
        "approximate_deleted": approximate_before,
        "older_than_days": days,
        "period_start": None,
        "period_end": iso(cutoff_dt),
        "period_deleted": f"{time_column} < {cutoff_expression}",
        "command_executed": command,
        "optimize_command": optimize_command,
        "optimize_executed": bool(optimize_command),
        "status": "ok",
        "note": (
            "ClickHouse pode liberar espaco fisico depois dos merges."
            if not optimize
            else "OPTIMIZE FINAL solicitado; pode consumir recursos em tabelas grandes."
        ),
    }


def cleanup_clickhouse_flows(older_than_days: int, optimize: bool = False) -> dict[str, Any]:
    return cleanup_clickhouse_table("flow_raw", "flow_time", older_than_days, optimize)


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


def sqlite_older_than_expr(column: str) -> str:
    return f"julianday(replace(replace({column}, 'T', ' '), 'Z', '')) < julianday('now', ?)"


def cleanup_sqlite_learning_anomalies(older_than_days: int) -> dict[str, int]:
    days = setting_int({"days": str(older_than_days)}, "days", 90)
    cutoff = f"-{days} days"
    with sqlite_connection() as conn:
        ensure_attack_vector_db(conn)
        flows_cursor = conn.execute(
            f"""
            DELETE FROM anomaly_event_flows
            WHERE anomaly_event_id IN (
                SELECT id FROM anomaly_events
                WHERE {sqlite_older_than_expr('last_seen_at')}
            )
            """,
            (cutoff,),
        )
        events_cursor = conn.execute(
            f"""
            DELETE FROM anomaly_events
            WHERE {sqlite_older_than_expr('last_seen_at')}
            """,
            (cutoff,),
        )
        suggestions_cursor = conn.execute(
            f"""
            DELETE FROM attack_vector_suggestions
            WHERE COALESCE(applied_at, '') = ''
              AND {sqlite_older_than_expr('updated_at')}
            """,
            (cutoff,),
        )
        conn.commit()
    return {
        "anomaly_event_flows": int(flows_cursor.rowcount or 0),
        "anomaly_events": int(events_cursor.rowcount or 0),
        "attack_vector_suggestions": int(suggestions_cursor.rowcount or 0),
    }


def run_database_cleanup(
    flow_retention_days: int,
    snmp_retention_days: int | None = None,
    optimize: bool = False,
    source: str = "manual",
    scope: str = "raw",
    flow_1m_retention_days: int | None = None,
    flow_tops_1m_retention_days: int | None = None,
) -> dict[str, Any]:
    scope = clean_text(scope).lower() or "raw"
    if scope not in {"raw", "raw_aggregates", "all"}:
        raise HTTPException(status_code=400, detail="scope invalido")
    clickhouse_results = {
        "flow_raw": cleanup_clickhouse_table("flow_raw", "flow_time", flow_retention_days, optimize=optimize)
    }
    if scope in {"raw_aggregates", "all"}:
        clickhouse_results["flow_1m"] = cleanup_clickhouse_table(
            "flow_1m",
            "minute",
            flow_1m_retention_days if flow_1m_retention_days is not None else flow_retention_days,
            optimize=optimize,
        )
        clickhouse_results["flow_tops_1m"] = cleanup_clickhouse_table(
            "flow_tops_1m",
            "minute",
            flow_tops_1m_retention_days if flow_tops_1m_retention_days is not None else flow_retention_days,
            optimize=optimize,
        )
    snmp_deleted = cleanup_sqlite_snmp_samples(snmp_retention_days) if scope == "all" and snmp_retention_days is not None else None
    learning_anomaly_deleted = (
        cleanup_sqlite_learning_anomalies(snmp_retention_days or flow_retention_days)
        if scope == "all"
        else None
    )
    cleanup_at = utc_now_iso()
    with sqlite_connection() as conn:
        set_system_settings(conn, {"database_last_cleanup_at": cleanup_at})
        conn.commit()
    return {
        "ok": True,
        "source": source,
        "scope": scope,
        "cleanup_at": cleanup_at,
        "older_than_days": flow_retention_days,
        "period_end": clickhouse_results["flow_raw"].get("period_end"),
        "optimize_executed": any(bool(item.get("optimize_command")) for item in clickhouse_results.values()),
        "tables": list(clickhouse_results.values()),
        "flow": clickhouse_results["flow_raw"],
        "clickhouse": clickhouse_results,
        "snmp_deleted": snmp_deleted,
        "learning_anomaly_deleted": learning_anomaly_deleted,
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
                flow_retention_days=table_retention_days(settings, "flow_raw") or 7,
                flow_1m_retention_days=table_retention_days(settings, "flow_1m") or 30,
                flow_tops_1m_retention_days=table_retention_days(settings, "flow_tops_1m") or 15,
                snmp_retention_days=setting_int(settings, "snmp_retention_days", 90),
                optimize=False,
                source="automatic",
                scope="all",
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


def parse_asn_text(value: Any) -> tuple[int, str]:
    text = clean_text(value)
    if not text:
        return 0, ""
    match = re.search(r"\bAS\s*(\d+)\b\s*(.*)", text, flags=re.IGNORECASE)
    if match:
        return int(match.group(1)), clean_text(match.group(2))
    try:
        return int(text), ""
    except ValueError:
        return 0, text


def normalize_prefix(value: str) -> str:
    text = clean_text(value)
    try:
        return str(ip_network(text, strict=False))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"prefixo ASN invalido: {text}") from None


def upsert_asn_info(
    conn: sqlite3.Connection,
    asn: int,
    as_name: str = "",
    country: str = "",
    source: str = "",
    org_name: str = "",
    raw_json: dict[str, Any] | None = None,
    last_error: str = "",
) -> None:
    number = int(asn or 0)
    if number <= 0:
        return
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=max(60, ASN_CACHE_TTL_SECONDS))
    raw_text = ""
    if raw_json is not None:
        raw_text = json.dumps(raw_json, ensure_ascii=False, sort_keys=True)[:20000]
    conn.execute(
        """
        INSERT INTO asn_info (
            asn, as_name, org_name, country, source, raw_json,
            first_seen_at, updated_at, expires_at, last_error
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(asn) DO UPDATE SET
            as_name = CASE WHEN excluded.as_name <> '' THEN excluded.as_name ELSE asn_info.as_name END,
            org_name = CASE WHEN excluded.org_name <> '' THEN excluded.org_name ELSE asn_info.org_name END,
            country = CASE WHEN excluded.country <> '' THEN excluded.country ELSE asn_info.country END,
            source = CASE WHEN excluded.source <> '' THEN excluded.source ELSE asn_info.source END,
            raw_json = CASE WHEN excluded.raw_json <> '' THEN excluded.raw_json ELSE asn_info.raw_json END,
            updated_at = excluded.updated_at,
            expires_at = excluded.expires_at,
            last_error = excluded.last_error
        """,
        (
            number,
            clean_text(as_name),
            clean_text(org_name),
            clean_text(country).upper(),
            clean_text(source),
            raw_text,
            now.isoformat(),
            now.isoformat(),
            expires.isoformat(),
            clean_text(last_error),
        ),
    )


def upsert_asn_prefix(conn: sqlite3.Connection, prefix: str, asn: int, as_name: str, source: str, country: str = "") -> None:
    normalized_prefix = normalize_prefix(prefix)
    network = ip_network(normalized_prefix, strict=False)
    now = utc_now_iso()
    conn.execute(
        """
        INSERT INTO asn_prefixes (prefix, ip_version, asn, as_name, country, source, first_seen_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(prefix, asn) DO UPDATE SET
            ip_version = excluded.ip_version,
            as_name = excluded.as_name,
            country = excluded.country,
            source = excluded.source,
            updated_at = excluded.updated_at
        """,
        (
            normalized_prefix,
            network.version,
            int(asn),
            clean_text(as_name),
            clean_text(country).upper(),
            clean_text(source),
            now,
            now,
        ),
    )
    upsert_asn_info(conn, int(asn), as_name, country, source)


def asn_host_prefix(ip: str) -> str:
    parsed = ip_address(ip)
    if isinstance(parsed, IPv4Address):
        return f"{parsed}/32"
    if isinstance(parsed, IPv6Address):
        return f"{parsed}/128"
    return f"{ip}/32"


def lookup_asn_prefix(ip: str) -> dict[str, Any] | None:
    ip_text = clean_ip(ip)
    try:
        parsed = ip_address(ip_text)
    except ValueError:
        return None
    ensure_sensor_db()
    with sqlite_connection() as conn:
        rows = conn.execute(
            """
            SELECT prefix, asn, as_name, country, source, updated_at
            FROM asn_prefixes
            WHERE asn > 0 AND ip_version = ?
            """
            ,
            (parsed.version,),
        ).fetchall()
    best: tuple[int, sqlite3.Row] | None = None
    for row in rows:
        try:
            network = ip_network(row["prefix"], strict=False)
        except ValueError:
            continue
        if parsed.version != network.version or parsed not in network:
            continue
        if best is None or network.prefixlen > best[0]:
            best = (network.prefixlen, row)
    if best is None:
        return None
    row = best[1]
    return {
        "asn": int(row["asn"] or 0),
        "as_name": clean_text(row["as_name"]),
        "country": clean_text(row["country"]).upper(),
        "source": clean_text(row["source"]),
        "prefix": clean_text(row["prefix"]),
        "updated_at": clean_text(row["updated_at"]),
    }


def lookup_asn_cache(ip: str) -> dict[str, Any] | None:
    ip_text = clean_ip(ip)
    try:
        parsed = ip_address(ip_text)
    except ValueError:
        return None
    now = datetime.now(timezone.utc)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        row = conn.execute(
            """
            SELECT ip, asn, prefix, as_name, country, source, resolved_at, expires_at
            FROM asn_lookup_cache
            WHERE ip = ? AND ip_version = ?
            """,
            (ip_text, parsed.version),
        ).fetchone()
    if row is None:
        return None
    expires_at = clean_text(row["expires_at"])
    if expires_at:
        try:
            expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if expires <= now:
                return None
        except ValueError:
            return None
    asn = int(row["asn"] or 0)
    if asn <= 0:
        return None
    return {
        "asn": asn,
        "as_name": clean_text(row["as_name"]),
        "country": clean_text(row["country"]).upper(),
        "prefix": clean_text(row["prefix"]),
        "source": clean_text(row["source"]) or "cache",
        "resolved_at": clean_text(row["resolved_at"]),
    }


def upsert_asn_lookup_cache(
    conn: sqlite3.Connection,
    ip: str,
    asn: int,
    prefix: str = "",
    as_name: str = "",
    country: str = "",
    source: str = "",
) -> None:
    ip_text = clean_ip(ip)
    parsed = ip_address(ip_text)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=max(60, ASN_CACHE_TTL_SECONDS))
    conn.execute(
        """
        INSERT INTO asn_lookup_cache (
            ip, ip_version, asn, prefix, as_name, country, source, resolved_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            ip_version = excluded.ip_version,
            asn = excluded.asn,
            prefix = excluded.prefix,
            as_name = excluded.as_name,
            country = excluded.country,
            source = excluded.source,
            resolved_at = excluded.resolved_at,
            expires_at = excluded.expires_at
        """,
        (
            ip_text,
            parsed.version,
            int(asn or 0),
            clean_text(prefix),
            clean_text(as_name),
            clean_text(country).upper(),
            clean_text(source),
            now.isoformat(),
            expires.isoformat(),
        ),
    )


def queue_asn_resolution(conn: sqlite3.Connection, ip: str, status: str = "queued", error: str = "") -> bool:
    ip_text = clean_ip(ip)
    parsed = ip_address(ip_text)
    now = utc_now_iso()
    cursor = conn.execute(
        """
        INSERT INTO asn_resolution_queue (
            ip, ip_version, asn, priority, first_seen_at, last_seen_at, updated_at, attempts, status, last_error
        )
        VALUES (?, ?, 0, 100, ?, ?, ?, 0, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            last_seen_at = excluded.last_seen_at,
            updated_at = excluded.updated_at,
            status = CASE
                WHEN asn_resolution_queue.status = 'resolved' AND excluded.status IN ('queued', 'pending') THEN asn_resolution_queue.status
                ELSE excluded.status
            END,
            last_error = excluded.last_error
        """,
        (ip_text, parsed.version, now, now, now, clean_text(status) or "queued", clean_text(error)),
    )
    return cursor.rowcount > 0


def queue_asn_info_resolution(conn: sqlite3.Connection, asn: int, priority: int = 50) -> bool:
    number = int(asn or 0)
    if number <= 0:
        return False
    now = utc_now_iso()
    key = f"AS{number}"
    cursor = conn.execute(
        """
        INSERT INTO asn_resolution_queue (
            ip, ip_version, asn, priority, first_seen_at, last_seen_at, updated_at, attempts, status, last_error
        )
        VALUES (?, 0, ?, ?, ?, ?, ?, 0, 'queued', '')
        ON CONFLICT(ip) DO UPDATE SET
            asn = excluded.asn,
            priority = MIN(asn_resolution_queue.priority, excluded.priority),
            last_seen_at = excluded.last_seen_at,
            updated_at = excluded.updated_at,
            status = CASE
                WHEN asn_resolution_queue.status = 'resolved' THEN asn_resolution_queue.status
                ELSE 'queued'
            END
        """,
        (key, number, int(priority), now, now, now),
    )
    return cursor.rowcount > 0


def resolve_asn_for_ip(ip: str) -> dict[str, Any]:
    ip_text = clean_ip(ip)
    try:
        parsed = ip_address(ip_text)
    except ValueError:
        return {"ip": ip_text, "asn": 0, "as_name": "", "country": "", "prefix": "", "source": "unresolved"}
    cached = lookup_asn_cache(ip_text)
    if cached:
        return {"ip": ip_text, **cached}
    prefix = lookup_asn_prefix(ip_text)
    if prefix:
        with sqlite_connection() as conn:
            ensure_asn_db(conn)
            upsert_asn_lookup_cache(
                conn,
                ip_text,
                int(prefix["asn"] or 0),
                prefix.get("prefix") or "",
                prefix.get("as_name") or "",
                prefix.get("country") or "",
                prefix.get("source") or "local_prefix_db",
            )
            conn.commit()
        return {"ip": ip_text, **prefix, "source": prefix.get("source") or "local_prefix_db"}
    if parsed.is_global:
        with sqlite_connection() as conn:
            ensure_asn_db(conn)
            queue_asn_resolution(conn, ip_text)
            conn.commit()
    return {"ip": ip_text, "asn": 0, "as_name": "", "country": "", "prefix": "", "source": "unresolved"}


def asn_label(asn: int) -> str:
    return f"AS{int(asn)}" if int(asn or 0) > 0 else "ASN indisponivel"


def usable_asn_name(value: Any, asn: int = 0) -> str:
    text = clean_text(value)
    if not text:
        return ""
    upper = text.upper().replace(" ", "")
    number = int(asn or 0)
    bad_values = {"-", "N/D", "ND", "ASN", "AS", "ASNINDISPONIVEL", "ASNINDISPONIVEL"}
    if upper in bad_values:
        return ""
    if number > 0 and upper in {f"AS{number}", f"ASN{number}"}:
        return ""
    if re.fullmatch(r"ASN?\d+", upper):
        return ""
    return text


def asn_display_name(asn: int, *values: Any) -> str:
    number = int(asn or 0)
    for value in values:
        name = usable_asn_name(value, number)
        if name:
            return name
    return asn_label(number)


def lookup_asn_info(asn: int) -> dict[str, Any] | None:
    number = int(asn or 0)
    if number <= 0:
        return None
    ensure_sensor_db()
    with sqlite_connection() as conn:
        ensure_asn_db(conn)
        row = conn.execute(
            """
            SELECT asn, as_name, org_name, country, source, updated_at, expires_at, last_error
            FROM asn_info
            WHERE asn = ?
            """,
            (number,),
        ).fetchone()
    if row is None:
        return None
    expires_at = clean_text(row["expires_at"])
    if expires_at:
        try:
            if datetime.fromisoformat(expires_at.replace("Z", "+00:00")) <= datetime.now(timezone.utc):
                return None
        except ValueError:
            pass
    return {
        "asn": number,
        "as_name": clean_text(row["as_name"]),
        "org_name": clean_text(row["org_name"]),
        "country": clean_text(row["country"]).upper(),
        "source": clean_text(row["source"]),
        "updated_at": clean_text(row["updated_at"]),
        "expires_at": expires_at,
        "last_error": clean_text(row["last_error"]),
    }


def queue_missing_asn_info(asn: int, priority: int = 80) -> None:
    number = int(asn or 0)
    if number <= 0:
        return
    try:
        with sqlite_connection() as conn:
            ensure_asn_db(conn)
            queue_asn_info_resolution(conn, number, priority=priority)
            conn.commit()
    except Exception as exc:
        logger.debug("Falha ao enfileirar AS%s para resolucao: %s", number, exc)


def country_geo(country_code: str, fallback_name: str = "") -> dict[str, Any]:
    code = clean_text(country_code).upper()
    if code in COUNTRY_CENTROIDS:
        name, lat, lon = COUNTRY_CENTROIDS[code]
        return {"country_code": code, "country_name": name, "latitude": lat, "longitude": lon}
    return {
        "country_code": code,
        "country_name": clean_text(fallback_name) or code or "N/D",
        "latitude": None,
        "longitude": None,
    }


def lookup_geo_cache(ip: str) -> dict[str, Any] | None:
    ip_text = clean_ip(ip)
    try:
        parsed = ip_address(ip_text)
    except ValueError:
        return None
    prefix = asn_host_prefix(ip_text)
    now = datetime.now(timezone.utc)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        ensure_asn_db(conn)
        row = conn.execute(
            """
            SELECT *
            FROM geo_ip_cache
            WHERE ip_prefix = ? AND ip_version = ?
            """,
            (prefix, parsed.version),
        ).fetchone()
    if row is None:
        return None
    expires_at = clean_text(row["expires_at"])
    if expires_at:
        try:
            if datetime.fromisoformat(expires_at.replace("Z", "+00:00")) <= now:
                return None
        except ValueError:
            return None
    return dict(row)


def upsert_geo_cache(conn: sqlite3.Connection, ip: str, item: dict[str, Any]) -> None:
    ip_text = clean_ip(ip)
    parsed = ip_address(ip_text)
    prefix = clean_text(item.get("ip_prefix")) or asn_host_prefix(ip_text)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=30)
    conn.execute(
        """
        INSERT INTO geo_ip_cache (
            ip_prefix, ip_version, country_code, country_name, region, city,
            latitude, longitude, asn, as_name, source, updated_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip_prefix) DO UPDATE SET
            ip_version = excluded.ip_version,
            country_code = excluded.country_code,
            country_name = excluded.country_name,
            region = excluded.region,
            city = excluded.city,
            latitude = excluded.latitude,
            longitude = excluded.longitude,
            asn = excluded.asn,
            as_name = excluded.as_name,
            source = excluded.source,
            updated_at = excluded.updated_at,
            expires_at = excluded.expires_at
        """,
        (
            prefix,
            parsed.version,
            clean_text(item.get("country_code")).upper(),
            clean_text(item.get("country_name")),
            clean_text(item.get("region")),
            clean_text(item.get("city")),
            item.get("latitude"),
            item.get("longitude"),
            int(item.get("asn") or 0),
            clean_text(item.get("as_name")),
            clean_text(item.get("source")),
            now.isoformat(),
            expires.isoformat(),
        ),
    )


def maxmind_geo_lookup(ip: str) -> dict[str, Any] | None:
    global GEOIP_LAST_ERROR
    if not GEOIP_MMDB_PATH or not Path(GEOIP_MMDB_PATH).exists():
        GEOIP_LAST_ERROR = "GeoIP database not configured"
        return None
    try:
        geoip2_database = import_module("geoip2.database")
    except Exception as exc:
        GEOIP_LAST_ERROR = f"geoip2 unavailable: {exc}"
        return None
    try:
        with geoip2_database.Reader(GEOIP_MMDB_PATH) as reader:
            response = reader.city(ip)
    except Exception as exc:
        GEOIP_LAST_ERROR = clean_text(exc)
        logger.debug("GeoLite2 sem resposta para %s: %s", ip, exc)
        return None
    GEOIP_LAST_ERROR = ""
    country_code = clean_text(getattr(response.country, "iso_code", "")).upper()
    country_name = clean_text(getattr(response.country, "name", ""))
    return {
        "country_code": country_code,
        "country_name": country_name,
        "region": clean_text(getattr(response.subdivisions.most_specific, "name", "")),
        "city": clean_text(getattr(response.city, "name", "")),
        "latitude": getattr(response.location, "latitude", None),
        "longitude": getattr(response.location, "longitude", None),
        "source": "maxmind",
    }


def geo_lookup_ip(ip: str, asn: int = 0, as_name: str = "") -> dict[str, Any]:
    ip_text = clean_ip(ip)
    try:
        parsed = ip_address(ip_text)
    except ValueError:
        return {
            "ip": ip_text,
            "country_code": "",
            "country_name": "N/D",
            "latitude": None,
            "longitude": None,
            "asn": int(asn or 0),
            "as_name": clean_text(as_name),
            "source": "invalid",
        }
    try:
        cached = lookup_geo_cache(ip_text)
    except Exception as exc:
        logger.debug("Falha ao consultar geo_ip_cache para %s: %s", ip_text, exc)
        cached = None
    if cached:
        cached["ip"] = ip_text
        return cached
    item = maxmind_geo_lookup(ip_text) if parsed.is_global else None
    try:
        resolved_asn = lookup_asn_info(asn) if int(asn or 0) > 0 else None
    except Exception as exc:
        logger.debug("Falha ao consultar ASN %s para GeoIP: %s", asn, exc)
        resolved_asn = None
    if item is None:
        if resolved_asn is None and parsed.is_global:
            try:
                resolved = resolve_asn_for_ip(ip_text)
                if int(resolved.get("asn") or 0) > 0:
                    try:
                        resolved_asn = lookup_asn_info(int(resolved["asn"])) or resolved
                    except Exception:
                        resolved_asn = resolved
                    asn = int(resolved["asn"])
                    as_name = clean_text(resolved.get("as_name"))
            except Exception as exc:
                logger.debug("Falha ao resolver ASN para GeoIP %s: %s", ip_text, exc)
        country_code = clean_text((resolved_asn or {}).get("country")).upper()
        geo = country_geo(country_code)
        item = {
            **geo,
            "region": "",
            "city": "",
            "source": "asn-cache" if country_code else "unresolved",
        }
    item["ip"] = ip_text
    item["asn"] = int(asn or (resolved_asn or {}).get("asn") or 0)
    item["as_name"] = clean_text(as_name) or clean_text((resolved_asn or {}).get("as_name")) or clean_text((resolved_asn or {}).get("org_name"))
    if not clean_text(item.get("country_name")) and clean_text(item.get("country_code")):
        item.update(country_geo(clean_text(item.get("country_code"))))
    try:
        with sqlite_connection() as conn:
            ensure_asn_db(conn)
            upsert_geo_cache(conn, ip_text, item)
            conn.commit()
    except Exception as exc:
        logger.debug("Falha ao atualizar geo_ip_cache para %s: %s", ip_text, exc)
    return item


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
    username = clean_text(payload.username)
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        with sqlite_connection() as conn:
            user = fetch_user_by_username(conn, username)
    except sqlite3.OperationalError as exc:
        message = str(exc).lower()
        if "locked" in message or "no such table" in message:
            raise HTTPException(status_code=503, detail="Banco local temporariamente indisponivel; tente novamente.") from exc
        raise
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


def sqlite_bool(value: Any) -> bool:
    return bool(int(value or 0))


def normalize_choice(value: Any, allowed: set[str], field_name: str) -> str:
    text = clean_text(value)
    if text not in allowed:
        raise HTTPException(status_code=400, detail=f"{field_name} invalido")
    return text


def normalize_target_cidr(value: Any, field_name: str = "target_cidr") -> str | None:
    text = clean_text(value)
    if not text:
        return None
    try:
        if "/" not in text:
            parsed_ip = ip_address(text)
            text = f"{parsed_ip}/32" if isinstance(parsed_ip, IPv4Address) else f"{parsed_ip}/128"
        return str(ip_network(text, strict=False))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field_name} invalido") from None


def clickhouse_cidr_string_param(value: str, field_name: str = "target_cidr") -> str:
    try:
        network = ip_network(value, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field_name} invalido") from None
    if network.version == 4:
        return f"::ffff:{network.network_address}/{network.prefixlen + 96}"
    return str(network)


def normalize_ip_filter_for_clickhouse(value: Any, field_name: str) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    try:
        if "/" in text:
            network = ip_network(text, strict=False)
        else:
            parsed_ip = ip_address(text)
            suffix = 32 if isinstance(parsed_ip, IPv4Address) else 128
            network = ip_network(f"{parsed_ip}/{suffix}", strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field_name} invalido. Use IP ou CIDR valido.") from None
    return clickhouse_cidr_string_param(str(network), field_name)


def build_ip_condition(column: str, value: Any, params: dict[str, Any], key: str, field_name: str) -> str:
    cidr = normalize_ip_filter_for_clickhouse(value, field_name)
    if not cidr:
        return ""
    params[key] = cidr
    return f"isIPAddressInRange(toString({column}), {{{key}:String}})"


def parse_port_filter(value: Any, field_name: str) -> tuple[str, int, int | None] | None:
    text = clean_text(value)
    if not text:
        return None
    if text == "*" or text.lower() == "any":
        return None
    if "-" in text:
        parts = text.split("-", 1)
        if len(parts) != 2 or not parts[0].strip().isdigit() or not parts[1].strip().isdigit():
            raise HTTPException(status_code=400, detail=f"{field_name} invalida. Use porta unica ou range, ex: 80 ou 3000-4000.")
        start = int(parts[0].strip())
        end = int(parts[1].strip())
        if start < 0 or end > 65535:
            raise HTTPException(status_code=400, detail=f"{field_name} invalida. A porta deve estar entre 0 e 65535.")
        if start > end:
            raise HTTPException(status_code=400, detail=f"{field_name} invalida. O inicio do range deve ser menor ou igual ao fim.")
        if start == 0 and end == 65535:
            return None
        return ("range", start, end)
    if not text.isdigit():
        raise HTTPException(status_code=400, detail=f"{field_name} invalida. Use porta unica ou range, ex: 80 ou 3000-4000.")
    port = int(text)
    if port < 0 or port > 65535:
        raise HTTPException(status_code=400, detail=f"{field_name} invalida. A porta deve estar entre 0 e 65535.")
    return ("single", port, None)


def build_port_condition(column: str, value: Any, params: dict[str, Any], key: str, field_name: str) -> str:
    parsed = parse_port_filter(value, field_name)
    if parsed is None:
        return ""
    kind, start, end = parsed
    if kind == "single":
        params[key] = start
        return f"{column} = {{{key}:UInt16}}"
    params[f"{key}_start"] = start
    params[f"{key}_end"] = int(end or start)
    return f"({column} >= {{{key}_start:UInt16}} AND {column} <= {{{key}_end:UInt16}})"


def build_any_port_condition(value: Any, params: dict[str, Any], key: str, field_name: str) -> str:
    parsed = parse_port_filter(value, field_name)
    if parsed is None:
        return ""
    kind, start, end = parsed
    if kind == "single":
        params[key] = start
        return f"(src_port = {{{key}:UInt16}} OR dst_port = {{{key}:UInt16}})"
    params[f"{key}_start"] = start
    params[f"{key}_end"] = int(end or start)
    return (
        f"((src_port >= {{{key}_start:UInt16}} AND src_port <= {{{key}_end:UInt16}}) "
        f"OR (dst_port >= {{{key}_start:UInt16}} AND dst_port <= {{{key}_end:UInt16}}))"
    )


def normalize_optional_cidr(value: Any, field_name: str) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    try:
        return str(ip_network(text, strict=False))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field_name} invalido") from None


def normalize_required_cidr(value: Any, field_name: str = "cidr") -> str:
    text = clean_text(value)
    if not text:
        raise HTTPException(status_code=400, detail=f"{field_name} obrigatorio")
    try:
        return str(ip_network(text, strict=False))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field_name} invalido") from None


def normalize_detection_protocol(value: Any, allow_empty: bool = False) -> str:
    text = clean_text(value).upper().replace("_", "-")
    if not text:
        return "" if allow_empty else "ALL"
    aliases = {
        "*": "ALL",
        "ANY": "ALL",
        "IP": "ALL",
        "IP/ALL": "ALL",
        "TCP-SYN": "TCP+SYN",
        "QUIC": "UDP-QUIC",
        "UDP+QUIC": "UDP-QUIC",
    }
    normalized = aliases.get(text, text)
    if normalized not in DETECTION_PROTOCOLS and normalized != "ALL":
        raise HTTPException(status_code=400, detail="protocol invalido")
    return normalized


def normalize_detection_vector(value: Any) -> str:
    vector = clean_text(value).upper().replace(" ", "_")
    if not vector:
        raise HTTPException(status_code=400, detail="vector obrigatorio")
    return vector


def fetch_detection_template_row(conn: sqlite3.Connection, template_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM detection_templates WHERE id = ?", (template_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Template de deteccao nao encontrado")
    return row


def fetch_ip_zone_row(conn: sqlite3.Connection, zone_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM ip_zones WHERE id = ?", (zone_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="IP Zone nao encontrada")
    return row


def fetch_ip_zone_prefix_row(conn: sqlite3.Connection, zone_id: int, prefix_id: int) -> sqlite3.Row:
    row = conn.execute(
        """
        SELECT *
        FROM ip_zone_prefixes
        WHERE id = ? AND zone_id = ?
        """,
        (prefix_id, zone_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Prefixo da IP Zone nao encontrado")
    return row


def fetch_detection_rule_row(conn: sqlite3.Connection, template_id: int, rule_id: int) -> sqlite3.Row:
    row = conn.execute(
        """
        SELECT *
        FROM detection_template_rules
        WHERE id = ? AND template_id = ?
        """,
        (rule_id, template_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Regra de deteccao nao encontrada")
    return row


def fetch_detection_whitelist_row(conn: sqlite3.Connection, whitelist_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM detection_whitelist WHERE id = ?", (whitelist_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Whitelist de deteccao nao encontrada")
    return row


def detection_template_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "name": item["name"],
        "description": item.get("description") or "",
        "active": sqlite_bool(item.get("active")),
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
        "rule_count": int(item.get("rule_count") or 0),
        "zone_count": int(item.get("zone_count") or 0),
    }


def detection_rule_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "template_id": int(item["template_id"]),
        "vector": item["vector"],
        "domain": item["domain"],
        "direction": item["direction"],
        "protocol": item.get("protocol") or "ALL",
        "metric": item["metric"],
        "comparison": item["comparison"],
        "warning_value": float(item["warning_value"]) if item.get("warning_value") is not None else None,
        "critical_value": float(item["critical_value"]) if item.get("critical_value") is not None else None,
        "window_seconds": int(item.get("window_seconds") or 60),
        "consecutive_windows": int(item.get("consecutive_windows") or 1),
        "cooldown_minutes": int(item.get("cooldown_minutes") or 5),
        "enabled": sqlite_bool(item.get("enabled")),
        "response": item.get("response") or "DETECTION_ONLY",
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


def ip_zone_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    prefix_count = int(item.get("prefix_count") or 0)
    total_prefix_count = int(item.get("total_prefix_count") or prefix_count)
    return {
        "id": int(item["id"]),
        "name": item["name"],
        "description": item.get("description") or "",
        "active": sqlite_bool(item.get("active")),
        "detection_template_id": int(item["detection_template_id"]) if item.get("detection_template_id") is not None else None,
        "detection_template_name": item.get("detection_template_name") or item.get("template_name") or "",
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
        "prefix_count": prefix_count,
        "active_prefix_count": int(item.get("active_prefix_count") or prefix_count),
        "total_prefix_count": total_prefix_count,
    }


def ip_zone_prefix_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "zone_id": int(item["zone_id"]),
        "zone_name": item.get("zone_name") or "",
        "cidr": item["cidr"],
        "name": item.get("name") or "",
        "description": item.get("description") or "",
        "prefix_type": item.get("prefix_type") or "client",
        "active": sqlite_bool(item.get("active")),
        "detection_template_id": int(item["detection_template_id"]) if item.get("detection_template_id") is not None else None,
        "detection_template_name": item.get("detection_template_name") or "",
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


def detection_whitelist_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "name": item["name"],
        "description": item.get("description") or "",
        "active": sqlite_bool(item.get("active")),
        "type": item["type"],
        "src_cidr": item.get("src_cidr") or "",
        "dst_cidr": item.get("dst_cidr") or "",
        "protocol": item.get("protocol") or "",
        "vector": item.get("vector") or "",
        "zone_id": int(item["zone_id"]) if item.get("zone_id") is not None else None,
        "zone_name": item.get("zone_name") or "",
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


def normalize_ip_zone_payload(conn: sqlite3.Connection, payload: IpZonePayload) -> dict[str, Any]:
    data = dump_model(payload)
    name = clean_text(data.get("name"))
    if not name:
        raise HTTPException(status_code=400, detail="Nome da IP Zone obrigatorio")
    template_id = data.get("detection_template_id")
    if template_id is not None:
        _ = fetch_detection_template_row(conn, int(template_id))
    return {
        "name": name,
        "description": clean_text(data.get("description")),
        "active": 1 if data.get("active") else 0,
        "detection_template_id": int(template_id) if template_id is not None else None,
    }


def normalize_ip_zone_prefix_payload(payload: IpZonePrefixPayload) -> dict[str, Any]:
    data = dump_model(payload)
    prefix_type = clean_text(data.get("prefix_type") or "client").lower()
    if prefix_type not in IP_ZONE_PREFIX_TYPES:
        raise HTTPException(status_code=400, detail="prefix_type invalido")
    return {
        "cidr": normalize_required_cidr(data.get("cidr")),
        "name": clean_text(data.get("name")),
        "description": clean_text(data.get("description")),
        "prefix_type": prefix_type,
        "active": 1 if data.get("active") else 0,
    }


def normalize_detection_template_payload(payload: DetectionTemplatePayload) -> dict[str, Any]:
    data = dump_model(payload)
    name = clean_text(data.get("name"))
    if not name:
        raise HTTPException(status_code=400, detail="Nome do template obrigatorio")
    return {
        "name": name,
        "description": clean_text(data.get("description")),
        "active": 1 if data.get("active") else 0,
    }


def normalize_detection_rule_payload(payload: DetectionRulePayload) -> dict[str, Any]:
    data = dump_model(payload)
    domain = normalize_choice(clean_text(data.get("domain")).lower() or "internal_ip", DETECTION_DOMAINS, "domain")
    direction = normalize_choice(clean_text(data.get("direction")).lower() or "transmits", DETECTION_DIRECTIONS, "direction")
    metric = normalize_choice(clean_text(data.get("metric")).lower() or "packets_s", DETECTION_METRICS, "metric")
    comparison = normalize_choice(clean_text(data.get("comparison")).lower() or "over", DETECTION_COMPARISONS, "comparison")
    response = normalize_choice(clean_text(data.get("response")).upper() or "DETECTION_ONLY", DETECTION_RESPONSES, "response")
    warning_value = data.get("warning_value")
    critical_value = data.get("critical_value")
    if warning_value is None and critical_value is None:
        raise HTTPException(status_code=400, detail="warning_value ou critical_value obrigatorio")
    if warning_value is not None and critical_value is not None and float(critical_value) < float(warning_value):
        raise HTTPException(status_code=400, detail="critical_value deve ser maior ou igual ao warning_value")
    return {
        "vector": normalize_detection_vector(data.get("vector")),
        "domain": domain,
        "direction": direction,
        "protocol": normalize_detection_protocol(data.get("protocol")),
        "metric": metric,
        "comparison": comparison,
        "warning_value": float(warning_value) if warning_value is not None else None,
        "critical_value": float(critical_value) if critical_value is not None else None,
        "window_seconds": positive_int(data.get("window_seconds") or 60, "window_seconds"),
        "consecutive_windows": positive_int(data.get("consecutive_windows") or 1, "consecutive_windows"),
        "cooldown_minutes": non_negative_int(data.get("cooldown_minutes") or 0, "cooldown_minutes"),
        "enabled": 1 if data.get("enabled") else 0,
        "response": response,
    }


def normalize_detection_whitelist_payload(conn: sqlite3.Connection, payload: DetectionWhitelistPayload) -> dict[str, Any]:
    data = dump_model(payload)
    name = clean_text(data.get("name"))
    if not name:
        raise HTTPException(status_code=400, detail="Nome da whitelist obrigatorio")
    whitelist_type = normalize_choice(clean_text(data.get("type")).lower(), DETECTION_WHITELIST_TYPES, "type")
    src_cidr = normalize_optional_cidr(data.get("src_cidr"), "src_cidr")
    dst_cidr = normalize_optional_cidr(data.get("dst_cidr"), "dst_cidr")
    if whitelist_type == "source" and not src_cidr:
        raise HTTPException(status_code=400, detail="src_cidr obrigatorio para whitelist source")
    if whitelist_type == "destination" and not dst_cidr:
        raise HTTPException(status_code=400, detail="dst_cidr obrigatorio para whitelist destination")
    if whitelist_type == "source_destination" and (not src_cidr or not dst_cidr):
        raise HTTPException(status_code=400, detail="src_cidr e dst_cidr obrigatorios para whitelist source_destination")
    zone_id = data.get("zone_id")
    if zone_id is not None:
        _ = fetch_ip_zone_row(conn, int(zone_id))
    protocol = normalize_detection_protocol(data.get("protocol"), allow_empty=True)
    return {
        "name": name,
        "description": clean_text(data.get("description")),
        "active": 1 if data.get("active") else 0,
        "type": whitelist_type,
        "src_cidr": src_cidr,
        "dst_cidr": dst_cidr,
        "protocol": protocol or None,
        "vector": normalize_detection_vector(data.get("vector")) if clean_text(data.get("vector")) else None,
        "zone_id": int(zone_id) if zone_id is not None else None,
    }


def fetch_ip_zone(
    conn: sqlite3.Connection,
    zone_id: int,
    include_prefixes: bool = False,
    include_inactive_prefixes: bool = False,
) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT
            z.*,
            t.name AS detection_template_name,
            COUNT(CASE WHEN p.active = 1 THEN p.id END) AS prefix_count,
            COUNT(CASE WHEN p.active = 1 THEN p.id END) AS active_prefix_count,
            COUNT(p.id) AS total_prefix_count
        FROM ip_zones z
        LEFT JOIN detection_templates t ON t.id = z.detection_template_id
        LEFT JOIN ip_zone_prefixes p ON p.zone_id = z.id
        WHERE z.id = ?
        GROUP BY z.id
        """,
        (zone_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="IP Zone nao encontrada")
    item = ip_zone_row_to_dict(row)
    if include_prefixes:
        active_filter = "" if include_inactive_prefixes else "AND p.active = 1"
        prefix_rows = conn.execute(
            f"""
            SELECT
                p.*,
                z.name AS zone_name,
                z.detection_template_id,
                t.name AS detection_template_name
            FROM ip_zone_prefixes p
            JOIN ip_zones z ON z.id = p.zone_id
            LEFT JOIN detection_templates t ON t.id = z.detection_template_id
            WHERE p.zone_id = ?
              {active_filter}
            ORDER BY p.active DESC, p.cidr, p.id
            """,
            (zone_id,),
        ).fetchall()
        item["prefixes"] = [ip_zone_prefix_row_to_dict(prefix_row) for prefix_row in prefix_rows]
    return item


def fetch_detection_template(conn: sqlite3.Connection, template_id: int, include_rules: bool = False) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT
            t.*,
            COUNT(DISTINCT r.id) AS rule_count,
            COUNT(DISTINCT z.id) AS zone_count
        FROM detection_templates t
        LEFT JOIN detection_template_rules r ON r.template_id = t.id
        LEFT JOIN ip_zones z ON z.detection_template_id = t.id
        WHERE t.id = ?
        GROUP BY t.id
        """,
        (template_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Template de deteccao nao encontrado")
    item = detection_template_row_to_dict(row)
    if include_rules:
        rows = conn.execute(
            """
            SELECT *
            FROM detection_template_rules
            WHERE template_id = ?
            ORDER BY enabled DESC, vector, id
            """,
            (template_id,),
        ).fetchall()
        item["rules"] = [detection_rule_row_to_dict(rule_row) for rule_row in rows]
    return item


def bgp_json_loads(value: Any, fallback: Any) -> Any:
    try:
        return json.loads(clean_text(value) or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def bgp_connector_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "name": item["name"],
        "role": item.get("role") or "generic_bgp",
        "backend_type": item.get("backend_type") or "dry_run",
        "mode": item.get("mode") or "dry_run",
        "local_asn": item.get("local_asn"),
        "peer_asn": item.get("peer_asn"),
        "peer_ip": item.get("peer_ip") or "",
        "router_id": item.get("router_id") or "",
        "default_next_hop": item.get("default_next_hop") or "",
        "default_community": item.get("default_community") or "",
        "default_large_community": item.get("default_large_community") or "",
        "max_active_rules": int(item.get("max_active_rules") or BGP_DEFAULT_MAX_ACTIVE_RULES),
        "max_duration_seconds": int(item.get("max_duration_seconds") or BGP_DEFAULT_MAX_DURATION_SECONDS),
        "enabled": sqlite_bool(item.get("enabled")),
        "notes": item.get("notes") or "",
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


def bgp_response_profile_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "name": item["name"],
        "description": item.get("description") or "",
        "enabled": sqlite_bool(item.get("enabled")),
        "response_type": item.get("response_type") or "flowspec",
        "connector_id": item.get("connector_id"),
        "approval_mode": item.get("approval_mode") or "manual_approval",
        "action": item.get("action") or "discard",
        "target_selector": item.get("target_selector") or "src_ip",
        "protocol_selector": item.get("protocol_selector") or "anomaly_protocol",
        "src_port_selector": item.get("src_port_selector") or "any",
        "src_port_value": item.get("src_port_value") or "",
        "dst_port_selector": item.get("dst_port_selector") or "any",
        "dst_port_value": item.get("dst_port_value") or "",
        "tcp_flags_selector": item.get("tcp_flags_selector") or "any",
        "rate_limit_bps": item.get("rate_limit_bps"),
        "redirect_target": item.get("redirect_target") or "",
        "next_hop": item.get("next_hop") or "",
        "community": item.get("community") or "",
        "large_community": item.get("large_community") or "",
        "require_protocol_or_port": sqlite_bool(item.get("require_protocol_or_port")),
        "allow_wide_prefix": sqlite_bool(item.get("allow_wide_prefix")),
        "max_duration_seconds": int(item.get("max_duration_seconds") or BGP_DEFAULT_MAX_DURATION_SECONDS),
        "default_duration_seconds": int(item.get("default_duration_seconds") or 1800),
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


def bgp_protected_prefix_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "cidr": item["cidr"],
        "name": item.get("name") or "",
        "reason": item.get("reason") or "",
        "enabled": sqlite_bool(item.get("enabled")),
        "block_rtbh": sqlite_bool(item.get("block_rtbh")),
        "block_flowspec": sqlite_bool(item.get("block_flowspec")),
        "block_diversion": sqlite_bool(item.get("block_diversion")),
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


def bgp_announcement_row_to_dict(row: sqlite3.Row | dict[str, Any], include_events: bool = False, conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    item = dict(row)
    result = {
        "id": int(item["id"]),
        "connector_id": item.get("connector_id"),
        "response_profile_id": item.get("response_profile_id"),
        "anomaly_id": item.get("anomaly_id"),
        "status": item.get("status") or "dry_run",
        "response_type": item.get("response_type") or "",
        "action": item.get("action") or "",
        "target_prefix": item.get("target_prefix") or "",
        "src_prefix": item.get("src_prefix") or "",
        "dst_prefix": item.get("dst_prefix") or "",
        "protocol": item.get("protocol") or "",
        "src_port": item.get("src_port") or "",
        "dst_port": item.get("dst_port") or "",
        "tcp_flags": item.get("tcp_flags") or "",
        "duration_seconds": int(item.get("duration_seconds") or 0),
        "expires_at": item.get("expires_at"),
        "rendered_command": item.get("rendered_command") or "",
        "validation_errors": bgp_json_loads(item.get("validation_errors"), []),
        "validation_warnings": bgp_json_loads(item.get("validation_warnings"), []),
        "raw_payload": bgp_json_loads(item.get("raw_payload"), {}),
        "created_by": item.get("created_by") or "",
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
        "approved_at": item.get("approved_at"),
        "rejected_at": item.get("rejected_at"),
        "withdrawn_at": item.get("withdrawn_at"),
        "connector_name": item.get("connector_name") or "",
        "response_profile_name": item.get("response_profile_name") or "",
    }
    if include_events and conn is not None:
        event_rows = conn.execute(
            "SELECT * FROM bgp_announcement_events WHERE announcement_id = ? ORDER BY id",
            (result["id"],),
        ).fetchall()
        result["events"] = [
            {
                "id": int(event["id"]),
                "event_type": event["event_type"],
                "message": event["message"],
                "payload": bgp_json_loads(event["payload_json"], {}),
                "created_by": event["created_by"],
                "created_at": event["created_at"],
            }
            for event in event_rows
        ]
    return result


def normalize_bgp_port_text(value: Any, field_name: str = "port") -> str:
    text = clean_text(value)
    if not text or text.lower() == "any":
        return ""
    if re.match(r"^\d{1,5}$", text):
        port = int(text)
        if 1 <= port <= 65535:
            return str(port)
    raise HTTPException(status_code=400, detail=f"{field_name} invalido")


def normalize_bgp_protocol(value: Any) -> str:
    text = clean_text(value).lower()
    if not text or text in {"any", "all", "ip"}:
        return ""
    if text.isdigit():
        return PROTO_LABELS.get(text, text).lower()
    normalized = {"tcp+syn": "tcp", "dns": "udp", "udp-quic": "udp"}.get(text.replace("_", "-"), text)
    if normalized in {"tcp", "udp", "icmp", "icmpv6", "gre"}:
        return normalized
    raise HTTPException(status_code=400, detail="protocol invalido")


def normalize_bgp_host_or_cidr(value: Any, field_name: str = "target") -> str:
    text = clean_text(value)
    if not text:
        raise HTTPException(status_code=400, detail=f"{field_name} obrigatorio")
    try:
        if "/" in text:
            return str(ip_network(text, strict=False))
        parsed = ip_address(text)
        suffix = 32 if isinstance(parsed, IPv4Address) else 128
        return str(ip_network(f"{parsed}/{suffix}", strict=False))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field_name} invalido") from None


def bgp_connector_payload_to_values(payload: BgpConnectorPayload) -> dict[str, Any]:
    name = clean_text(payload.name)
    if not name:
        raise HTTPException(status_code=400, detail="name obrigatorio")
    return {
        "name": name,
        "role": normalize_choice(payload.role, BGP_CONNECTOR_ROLES, "role"),
        "backend_type": normalize_choice(payload.backend_type, BGP_CONNECTOR_BACKENDS, "backend_type"),
        "mode": normalize_choice(payload.mode, BGP_MODES, "mode"),
        "local_asn": payload.local_asn,
        "peer_asn": payload.peer_asn,
        "peer_ip": optional_ip(payload.peer_ip, "peer_ip") if clean_text(payload.peer_ip) else "",
        "router_id": optional_ip(payload.router_id, "router_id") if clean_text(payload.router_id) else "",
        "default_next_hop": optional_ip(payload.default_next_hop, "default_next_hop") if clean_text(payload.default_next_hop) else "",
        "default_community": clean_text(payload.default_community),
        "default_large_community": clean_text(payload.default_large_community),
        "max_active_rules": int(payload.max_active_rules),
        "max_duration_seconds": int(payload.max_duration_seconds),
        "enabled": 1 if payload.enabled else 0,
        "notes": clean_text(payload.notes),
    }


def bgp_profile_payload_to_values(payload: BgpResponseProfilePayload) -> dict[str, Any]:
    name = clean_text(payload.name)
    if not name:
        raise HTTPException(status_code=400, detail="name obrigatorio")
    max_duration = int(payload.max_duration_seconds)
    return {
        "name": name,
        "description": clean_text(payload.description),
        "enabled": 1 if payload.enabled else 0,
        "response_type": normalize_choice(payload.response_type, BGP_RESPONSE_TYPES, "response_type"),
        "connector_id": payload.connector_id,
        "approval_mode": normalize_choice(payload.approval_mode, BGP_MODES, "approval_mode"),
        "action": normalize_choice(payload.action, BGP_ACTIONS, "action"),
        "target_selector": normalize_choice(payload.target_selector, BGP_TARGET_SELECTORS, "target_selector"),
        "protocol_selector": normalize_choice(payload.protocol_selector, BGP_PROTOCOL_SELECTORS, "protocol_selector"),
        "src_port_selector": normalize_choice(payload.src_port_selector, BGP_PORT_SELECTORS, "src_port_selector"),
        "src_port_value": normalize_bgp_port_text(payload.src_port_value, "src_port_value"),
        "dst_port_selector": normalize_choice(payload.dst_port_selector, BGP_PORT_SELECTORS, "dst_port_selector"),
        "dst_port_value": normalize_bgp_port_text(payload.dst_port_value, "dst_port_value"),
        "tcp_flags_selector": normalize_choice(payload.tcp_flags_selector, BGP_TCP_FLAGS_SELECTORS, "tcp_flags_selector"),
        "rate_limit_bps": payload.rate_limit_bps,
        "redirect_target": clean_text(payload.redirect_target),
        "next_hop": clean_text(payload.next_hop),
        "community": clean_text(payload.community),
        "large_community": clean_text(payload.large_community),
        "require_protocol_or_port": 1 if payload.require_protocol_or_port else 0,
        "allow_wide_prefix": 1 if payload.allow_wide_prefix else 0,
        "max_duration_seconds": max_duration,
        "default_duration_seconds": min(int(payload.default_duration_seconds), max_duration),
    }


def fetch_bgp_connector(conn: sqlite3.Connection, connector_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM bgp_connectors WHERE id = ?", (connector_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Conector BGP nao encontrado")
    return bgp_connector_row_to_dict(row)


def fetch_bgp_profile(conn: sqlite3.Connection, profile_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM bgp_response_profiles WHERE id = ?", (profile_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Perfil de resposta BGP nao encontrado")
    return bgp_response_profile_row_to_dict(row)


def resolve_bgp_port(selector: str, fixed_value: str, manual_value: Any) -> str:
    if selector == "fixed":
        return normalize_bgp_port_text(fixed_value)
    if selector in {"manual", "anomaly_src_port", "anomaly_dst_port"}:
        return normalize_bgp_port_text(manual_value)
    return ""


def candidate_from_bgp_payload(payload: BgpAnnouncementDryRunPayload, profile: dict[str, Any]) -> dict[str, Any]:
    selector = profile["target_selector"]
    src_prefix = ""
    dst_prefix = ""
    target_prefix = ""
    if selector in {"src_ip", "anomaly_src_ip"} and payload.src_ip:
        src_prefix = normalize_bgp_host_or_cidr(payload.src_ip, "src_ip")
    elif selector in {"dst_ip", "anomaly_dst_ip"} and payload.dst_ip:
        dst_prefix = normalize_bgp_host_or_cidr(payload.dst_ip, "dst_ip")
    elif selector == "src_and_dst_ip":
        if payload.src_ip:
            src_prefix = normalize_bgp_host_or_cidr(payload.src_ip, "src_ip")
        if payload.dst_ip:
            dst_prefix = normalize_bgp_host_or_cidr(payload.dst_ip, "dst_ip")
    elif selector in {"target_ip", "target_cidr"} and (payload.target_cidr or payload.target_ip):
        target_prefix = normalize_bgp_host_or_cidr(payload.target_cidr or payload.target_ip, "target_cidr")
    target_prefix = target_prefix or dst_prefix or src_prefix

    protocol = ""
    protocol_selector = profile["protocol_selector"]
    if protocol_selector in {"tcp", "udp", "icmp"}:
        protocol = protocol_selector
    elif protocol_selector in {"manual", "anomaly_protocol"}:
        protocol = normalize_bgp_protocol(payload.protocol)
    duration = int(payload.duration_seconds or profile["default_duration_seconds"])
    return {
        "response_profile_id": profile["id"],
        "connector_id": payload.connector_id or profile.get("connector_id"),
        "response_type": profile["response_type"],
        "action": profile["action"],
        "target_prefix": target_prefix,
        "src_prefix": src_prefix,
        "dst_prefix": dst_prefix,
        "protocol": protocol,
        "src_port": resolve_bgp_port(profile["src_port_selector"], profile["src_port_value"], payload.src_port),
        "dst_port": resolve_bgp_port(profile["dst_port_selector"], profile["dst_port_value"], payload.dst_port),
        "tcp_flags": profile["tcp_flags_selector"] if profile["tcp_flags_selector"] in {"syn", "syn_ack"} else clean_text(payload.tcp_flags).lower(),
        "duration_seconds": duration,
        "reason": clean_text(payload.reason),
        "raw_payload": dump_model(payload),
    }


def bgp_prefix_overlaps(a: str, b: str) -> bool:
    try:
        left = ip_network(a, strict=False)
        right = ip_network(b, strict=False)
    except ValueError:
        return False
    return left.version == right.version and left.overlaps(right)


def validate_mitigation_candidate(candidate: dict[str, Any], connector: dict[str, Any] | None, response_profile: dict[str, Any]) -> dict[str, list[str]]:
    ensure_sensor_db()
    errors: list[str] = []
    warnings: list[str] = []
    if connector is None:
        errors.append("Conector BGP ausente ou nao selecionado.")
    elif not connector.get("enabled"):
        errors.append("Conector BGP desativado.")
    if not response_profile:
        errors.append("Perfil de resposta ausente.")
    elif not response_profile.get("enabled"):
        errors.append("Perfil de resposta desativado.")
    if connector and connector.get("mode") == "detection_only":
        errors.append("Conector em detection_only.")
    if response_profile and response_profile.get("approval_mode") == "detection_only":
        errors.append("Perfil em detection_only.")

    prefixes = [clean_text(candidate.get(key)) for key in ("target_prefix", "src_prefix", "dst_prefix") if clean_text(candidate.get(key))]
    if not prefixes:
        errors.append("Alvo da mitigacao vazio ou invalido.")
    for prefix in prefixes:
        try:
            ip_network(prefix, strict=False)
        except ValueError:
            errors.append(f"Prefixo invalido: {prefix}")

    response_type = clean_text(candidate.get("response_type"))
    if response_type == "rtbh" and prefixes:
        target = clean_text(candidate.get("target_prefix")) or prefixes[0]
        try:
            network = ip_network(target, strict=False)
            if not response_profile.get("allow_wide_prefix") and network.prefixlen != network.max_prefixlen:
                errors.append("RTBH bloqueado: prefixo precisa ser /32 em IPv4 ou /128 em IPv6.")
        except ValueError:
            pass
    if response_type == "flowspec":
        has_scope = bool(candidate.get("src_prefix") or candidate.get("dst_prefix"))
        has_proto_or_port = bool(candidate.get("protocol") or candidate.get("src_port") or candidate.get("dst_port") or candidate.get("tcp_flags"))
        if not has_scope:
            errors.append("FlowSpec amplo bloqueado: informe origem e/ou destino.")
        if response_profile.get("require_protocol_or_port") and not has_proto_or_port:
            errors.append("FlowSpec amplo bloqueado: protocolo, porta ou flags sao obrigatorios.")
        if candidate.get("action") == "discard":
            for prefix in prefixes:
                try:
                    network = ip_network(prefix, strict=False)
                    if not response_profile.get("allow_wide_prefix") and network.prefixlen <= (24 if network.version == 4 else 64):
                        errors.append(f"FlowSpec discard amplo bloqueado para {prefix}.")
                except ValueError:
                    pass

    duration = int(candidate.get("duration_seconds") or 0)
    max_duration = min(
        int(response_profile.get("max_duration_seconds") or BGP_DEFAULT_MAX_DURATION_SECONDS),
        int(connector.get("max_duration_seconds") or BGP_DEFAULT_MAX_DURATION_SECONDS) if connector else BGP_DEFAULT_MAX_DURATION_SECONDS,
    )
    if duration <= 0:
        errors.append("Duracao invalida.")
    elif duration > max_duration:
        errors.append(f"Duracao excede o maximo permitido ({max_duration}s).")
    if connector and clean_text(connector.get("peer_ip")):
        peer_ip = ip_address(connector["peer_ip"])
        for prefix in prefixes:
            try:
                if peer_ip in ip_network(prefix, strict=False):
                    errors.append("Alvo contem o IP do peer BGP.")
            except ValueError:
                pass

    with sqlite_connection() as conn:
        for row in conn.execute("SELECT * FROM bgp_protected_prefixes WHERE enabled = 1").fetchall():
            protected = bgp_protected_prefix_row_to_dict(row)
            if response_type == "rtbh" and not protected["block_rtbh"]:
                continue
            if response_type == "flowspec" and not protected["block_flowspec"]:
                continue
            if response_type == "diversion" and not protected["block_diversion"]:
                continue
            for prefix in prefixes:
                if bgp_prefix_overlaps(prefix, protected["cidr"]):
                    errors.append(f"Prefixo protegido bloqueia mitigacao: {protected['cidr']}")
        active_statuses = sorted(BGP_ACTIVE_STATUSES)
        placeholders = ",".join("?" for _ in active_statuses)
        if connector:
            active_count = conn.execute(
                f"SELECT COUNT(*) AS count FROM bgp_announcements WHERE connector_id = ? AND status IN ({placeholders})",
                (connector["id"], *active_statuses),
            ).fetchone()["count"]
            if int(active_count or 0) >= int(connector.get("max_active_rules") or BGP_DEFAULT_MAX_ACTIVE_RULES):
                errors.append("Limite de regras ativas do conector excedido.")
        duplicate = conn.execute(
            f"""
            SELECT id FROM bgp_announcements
            WHERE status IN ({placeholders})
              AND COALESCE(connector_id, 0) = ?
              AND response_type = ?
              AND action = ?
              AND target_prefix = ?
              AND src_prefix = ?
              AND dst_prefix = ?
              AND protocol = ?
              AND src_port = ?
              AND dst_port = ?
              AND tcp_flags = ?
            LIMIT 1
            """,
            (
                *active_statuses,
                int(connector["id"]) if connector else 0,
                response_type,
                clean_text(candidate.get("action")),
                clean_text(candidate.get("target_prefix")),
                clean_text(candidate.get("src_prefix")),
                clean_text(candidate.get("dst_prefix")),
                clean_text(candidate.get("protocol")),
                clean_text(candidate.get("src_port")),
                clean_text(candidate.get("dst_port")),
                clean_text(candidate.get("tcp_flags")),
            ),
        ).fetchone()
        if duplicate is not None:
            errors.append(f"Ja existe mitigacao equivalente ativa: #{duplicate['id']}")
    if connector and connector.get("backend_type") != "dry_run":
        warnings.append("Backend configurado nao sera acionado nesta fase; somente dry-run foi implementado.")
    if response_profile.get("approval_mode") == "automatic":
        warnings.append("Automatico desativado na Fase 1; dry-run/manual approval apenas.")
    return {"errors": sorted(set(errors)), "warnings": sorted(set(warnings))}


def render_bgp_announcement(candidate: dict[str, Any], connector: dict[str, Any], response_profile: dict[str, Any]) -> str:
    response_type = candidate.get("response_type")
    action = candidate.get("action")
    target = candidate.get("target_prefix") or candidate.get("dst_prefix") or candidate.get("src_prefix")
    if response_type == "rtbh":
        next_hop = clean_text(response_profile.get("next_hop")) or clean_text(connector.get("default_next_hop")) or "0.0.0.0"
        community = clean_text(response_profile.get("community")) or clean_text(connector.get("default_community"))
        community_part = f" community [ {community} ]" if community else ""
        return f"announce route {target} next-hop {next_hop}{community_part}"
    if response_type == "diversion":
        next_hop = clean_text(response_profile.get("next_hop")) or clean_text(response_profile.get("redirect_target")) or clean_text(connector.get("default_next_hop")) or "0.0.0.0"
        return f"announce route {target} next-hop {next_hop}"
    lines = ["flow route {", "match {"]
    if candidate.get("src_prefix"):
        lines.append(f"source {candidate['src_prefix']};")
    if candidate.get("dst_prefix"):
        lines.append(f"destination {candidate['dst_prefix']};")
    if candidate.get("protocol"):
        lines.append(f"protocol {candidate['protocol']};")
    if candidate.get("src_port"):
        lines.append(f"source-port ={candidate['src_port']};")
    if candidate.get("dst_port"):
        lines.append(f"destination-port ={candidate['dst_port']};")
    if candidate.get("tcp_flags"):
        lines.append(f"tcp-flags {candidate['tcp_flags'].replace('_', '+')};")
    lines.extend(["}", "then {"])
    if action == "rate_limit" and response_profile.get("rate_limit_bps"):
        lines.append(f"rate-limit {int(response_profile['rate_limit_bps'])};")
    elif action == "redirect":
        lines.append(f"redirect {clean_text(response_profile.get('redirect_target')) or clean_text(response_profile.get('next_hop'))};")
    else:
        lines.append("discard;")
    lines.extend(["}", "}"])
    return "\n".join(lines)


def bgp_event(conn: sqlite3.Connection, announcement_id: int, event_type: str, message: str, payload: dict[str, Any] | None = None, created_by: str = "api") -> None:
    conn.execute(
        """
        INSERT INTO bgp_announcement_events (announcement_id, event_type, message, payload_json, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (announcement_id, event_type, message, json.dumps(payload or {}, sort_keys=True), created_by, utc_now_iso()),
    )


def bgp_current_user(request: Request) -> str:
    user = getattr(request.state, "user", None) or {}
    return clean_text(user.get("username")) or clean_text(user.get("role")) or "api"


def create_bgp_announcement(conn: sqlite3.Connection, candidate: dict[str, Any], connector: dict[str, Any], profile: dict[str, Any], validation: dict[str, list[str]], created_by: str, anomaly_id: int | None = None) -> dict[str, Any]:
    now = utc_now_iso()
    duration = int(candidate.get("duration_seconds") or 0)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=duration)).isoformat().replace("+00:00", "Z") if duration else None
    rendered = render_bgp_announcement(candidate, connector, profile)
    cursor = conn.execute(
        """
        INSERT INTO bgp_announcements (
            connector_id, response_profile_id, anomaly_id, status, response_type, action,
            target_prefix, src_prefix, dst_prefix, protocol, src_port, dst_port, tcp_flags,
            duration_seconds, expires_at, rendered_command, validation_errors, validation_warnings,
            raw_payload, created_by, created_at, updated_at
        )
        VALUES (?, ?, ?, 'dry_run', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            connector["id"], profile["id"], anomaly_id, candidate.get("response_type") or "", candidate.get("action") or "",
            candidate.get("target_prefix") or "", candidate.get("src_prefix") or "", candidate.get("dst_prefix") or "",
            candidate.get("protocol") or "", candidate.get("src_port") or "", candidate.get("dst_port") or "",
            candidate.get("tcp_flags") or "", duration, expires_at, rendered,
            json.dumps(validation["errors"], sort_keys=True), json.dumps(validation["warnings"], sort_keys=True),
            json.dumps(candidate.get("raw_payload") or {}, sort_keys=True, default=str), created_by, now, now,
        ),
    )
    announcement_id = int(cursor.lastrowid)
    bgp_event(conn, announcement_id, "dry_run_created", "Dry-run BGP gerado. Nenhum anuncio real foi enviado.", validation, created_by)
    row = conn.execute(
        """
        SELECT a.*, c.name AS connector_name, p.name AS response_profile_name
        FROM bgp_announcements a
        LEFT JOIN bgp_connectors c ON c.id = a.connector_id
        LEFT JOIN bgp_response_profiles p ON p.id = a.response_profile_id
        WHERE a.id = ?
        """,
        (announcement_id,),
    ).fetchone()
    return bgp_announcement_row_to_dict(row, include_events=True, conn=conn)


def candidate_from_anomaly(conn: sqlite3.Connection, anomaly_id: int, payload: BgpAnnouncementDryRunPayload, profile: dict[str, Any]) -> dict[str, Any]:
    base = dump_model(payload)
    if anomaly_id < 0:
        group = next(
            (
                item
                for status_filter in ("active", "history")
                for item in consolidated_security_anomaly_groups(status_filter)
                if int(item["event"]["id"]) == anomaly_id
            ),
            None,
        )
        if group is None:
            raise HTTPException(status_code=404, detail="Anomalia nao encontrada")
        event = group["event"]
        details = sorted(group["items"], key=lambda item: float(item.get("bits_s") or item.get("packets_s") or 0), reverse=True)
        detail = details[0] if details else {}
        base.update({
            "src_ip": detail.get("src_ip") or event.get("target_ip"),
            "dst_ip": detail.get("dst_ip") or event.get("target_ip"),
            "target_ip": event.get("target_ip"),
            "target_cidr": event.get("target_cidr"),
            "protocol": detail.get("protocol") or event.get("decoder"),
            "dst_port": 53 if clean_text(detail.get("protocol")).upper() == "DNS" else None,
        })
    else:
        row = conn.execute("SELECT * FROM anomaly_events WHERE id = ?", (anomaly_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Anomalia nao encontrada")
        event = anomaly_event_row_to_dict(row)
        flow = conn.execute(
            "SELECT * FROM anomaly_event_flows WHERE anomaly_event_id = ? ORDER BY bytes DESC, packets DESC LIMIT 1",
            (anomaly_id,),
        ).fetchone()
        if flow is not None:
            flow_dict = dict(flow)
            base.update({
                "src_ip": clean_ip(flow_dict.get("src_ip")) or event.get("target_ip"),
                "dst_ip": clean_ip(flow_dict.get("dst_ip")) or event.get("target_ip"),
                "src_port": flow_dict.get("src_port") or None,
                "dst_port": flow_dict.get("dst_port") or None,
                "protocol": proto_name(flow_dict.get("proto")),
            })
        base["target_ip"] = base.get("target_ip") or event.get("target_ip")
        base["target_cidr"] = base.get("target_cidr") or event.get("target_cidr")
    merged = BgpAnnouncementDryRunPayload(**base)
    candidate = candidate_from_bgp_payload(merged, profile)
    candidate["raw_payload"] = {**candidate["raw_payload"], "anomaly_id": anomaly_id}
    return candidate


@app.get("/api/bgp/connectors")
def list_bgp_connectors(request: Request, include_disabled: bool = False):
    require_admin(request)
    ensure_sensor_db()
    where = "" if include_disabled else "WHERE enabled = 1"
    with sqlite_connection() as conn:
        rows = conn.execute(f"SELECT * FROM bgp_connectors {where} ORDER BY name, id").fetchall()
    return {"items": [bgp_connector_row_to_dict(row) for row in rows]}


@app.post("/api/bgp/connectors", status_code=201)
def create_bgp_connector(request: Request, payload: BgpConnectorPayload):
    require_admin(request)
    ensure_sensor_db()
    values = bgp_connector_payload_to_values(payload)
    now = utc_now_iso()
    with sqlite_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO bgp_connectors (
                name, role, backend_type, mode, local_asn, peer_asn, peer_ip, router_id,
                default_next_hop, default_community, default_large_community, max_active_rules,
                max_duration_seconds, enabled, notes, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (values["name"], values["role"], values["backend_type"], values["mode"], values["local_asn"], values["peer_asn"], values["peer_ip"], values["router_id"], values["default_next_hop"], values["default_community"], values["default_large_community"], values["max_active_rules"], values["max_duration_seconds"], values["enabled"], values["notes"], now, now),
        )
        conn.commit()
        return fetch_bgp_connector(conn, int(cursor.lastrowid))


@app.get("/api/bgp/connectors/{connector_id}")
def get_bgp_connector(request: Request, connector_id: int):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        return fetch_bgp_connector(conn, connector_id)


@app.put("/api/bgp/connectors/{connector_id}")
def update_bgp_connector(request: Request, connector_id: int, payload: BgpConnectorPayload):
    require_admin(request)
    ensure_sensor_db()
    values = bgp_connector_payload_to_values(payload)
    now = utc_now_iso()
    with sqlite_connection() as conn:
        fetch_bgp_connector(conn, connector_id)
        conn.execute(
            """
            UPDATE bgp_connectors
            SET name = ?, role = ?, backend_type = ?, mode = ?, local_asn = ?, peer_asn = ?,
                peer_ip = ?, router_id = ?, default_next_hop = ?, default_community = ?,
                default_large_community = ?, max_active_rules = ?, max_duration_seconds = ?,
                enabled = ?, notes = ?, updated_at = ?
            WHERE id = ?
            """,
            (values["name"], values["role"], values["backend_type"], values["mode"], values["local_asn"], values["peer_asn"], values["peer_ip"], values["router_id"], values["default_next_hop"], values["default_community"], values["default_large_community"], values["max_active_rules"], values["max_duration_seconds"], values["enabled"], values["notes"], now, connector_id),
        )
        conn.commit()
        return fetch_bgp_connector(conn, connector_id)


@app.delete("/api/bgp/connectors/{connector_id}")
def delete_bgp_connector(request: Request, connector_id: int):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        fetch_bgp_connector(conn, connector_id)
        count = conn.execute("SELECT COUNT(*) AS count FROM bgp_announcements WHERE connector_id = ?", (connector_id,)).fetchone()["count"]
        if int(count or 0) > 0:
            conn.execute("UPDATE bgp_connectors SET enabled = 0, updated_at = ? WHERE id = ?", (utc_now_iso(), connector_id))
            conn.commit()
            return {"ok": True, "disabled": True}
        conn.execute("DELETE FROM bgp_connectors WHERE id = ?", (connector_id,))
        conn.commit()
        return {"ok": True, "deleted": True}


@app.get("/api/bgp/response-profiles")
def list_bgp_response_profiles(request: Request, include_disabled: bool = True):
    require_admin(request)
    ensure_sensor_db()
    where = "" if include_disabled else "WHERE enabled = 1"
    with sqlite_connection() as conn:
        rows = conn.execute(f"SELECT * FROM bgp_response_profiles {where} ORDER BY name, id").fetchall()
    return {"items": [bgp_response_profile_row_to_dict(row) for row in rows]}


@app.post("/api/bgp/response-profiles", status_code=201)
def create_bgp_response_profile(request: Request, payload: BgpResponseProfilePayload):
    require_admin(request)
    ensure_sensor_db()
    values = bgp_profile_payload_to_values(payload)
    now = utc_now_iso()
    columns = ("name", "description", "enabled", "response_type", "connector_id", "approval_mode", "action", "target_selector", "protocol_selector", "src_port_selector", "src_port_value", "dst_port_selector", "dst_port_value", "tcp_flags_selector", "rate_limit_bps", "redirect_target", "next_hop", "community", "large_community", "require_protocol_or_port", "allow_wide_prefix", "max_duration_seconds", "default_duration_seconds")
    with sqlite_connection() as conn:
        if values["connector_id"]:
            fetch_bgp_connector(conn, int(values["connector_id"]))
        cursor = conn.execute(
            f"INSERT INTO bgp_response_profiles ({', '.join(columns)}, created_at, updated_at) VALUES ({', '.join('?' for _ in columns)}, ?, ?)",
            tuple(values[key] for key in columns) + (now, now),
        )
        conn.commit()
        return fetch_bgp_profile(conn, int(cursor.lastrowid))


@app.get("/api/bgp/response-profiles/{profile_id}")
def get_bgp_response_profile(request: Request, profile_id: int):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        return fetch_bgp_profile(conn, profile_id)


@app.put("/api/bgp/response-profiles/{profile_id}")
def update_bgp_response_profile(request: Request, profile_id: int, payload: BgpResponseProfilePayload):
    require_admin(request)
    ensure_sensor_db()
    values = bgp_profile_payload_to_values(payload)
    columns = ("name", "description", "enabled", "response_type", "connector_id", "approval_mode", "action", "target_selector", "protocol_selector", "src_port_selector", "src_port_value", "dst_port_selector", "dst_port_value", "tcp_flags_selector", "rate_limit_bps", "redirect_target", "next_hop", "community", "large_community", "require_protocol_or_port", "allow_wide_prefix", "max_duration_seconds", "default_duration_seconds")
    with sqlite_connection() as conn:
        fetch_bgp_profile(conn, profile_id)
        if values["connector_id"]:
            fetch_bgp_connector(conn, int(values["connector_id"]))
        conn.execute(
            f"UPDATE bgp_response_profiles SET {', '.join(f'{column} = ?' for column in columns)}, updated_at = ? WHERE id = ?",
            tuple(values[key] for key in columns) + (utc_now_iso(), profile_id),
        )
        conn.commit()
        return fetch_bgp_profile(conn, profile_id)


@app.delete("/api/bgp/response-profiles/{profile_id}")
def delete_bgp_response_profile(request: Request, profile_id: int):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        fetch_bgp_profile(conn, profile_id)
        count = conn.execute("SELECT COUNT(*) AS count FROM bgp_announcements WHERE response_profile_id = ?", (profile_id,)).fetchone()["count"]
        if int(count or 0) > 0:
            conn.execute("UPDATE bgp_response_profiles SET enabled = 0, updated_at = ? WHERE id = ?", (utc_now_iso(), profile_id))
            conn.commit()
            return {"ok": True, "disabled": True}
        conn.execute("DELETE FROM bgp_response_profiles WHERE id = ?", (profile_id,))
        conn.commit()
        return {"ok": True, "deleted": True}


@app.get("/api/bgp/protected-prefixes")
def list_bgp_protected_prefixes(request: Request, include_disabled: bool = True):
    require_admin(request)
    ensure_sensor_db()
    where = "" if include_disabled else "WHERE enabled = 1"
    with sqlite_connection() as conn:
        rows = conn.execute(f"SELECT * FROM bgp_protected_prefixes {where} ORDER BY cidr, id").fetchall()
    return {"items": [bgp_protected_prefix_row_to_dict(row) for row in rows]}


@app.post("/api/bgp/protected-prefixes", status_code=201)
def create_bgp_protected_prefix(request: Request, payload: BgpProtectedPrefixPayload):
    require_admin(request)
    ensure_sensor_db()
    now = utc_now_iso()
    with sqlite_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO bgp_protected_prefixes (cidr, name, reason, enabled, block_rtbh, block_flowspec, block_diversion, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (normalize_required_cidr(payload.cidr), clean_text(payload.name), clean_text(payload.reason), 1 if payload.enabled else 0, 1 if payload.block_rtbh else 0, 1 if payload.block_flowspec else 0, 1 if payload.block_diversion else 0, now, now),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM bgp_protected_prefixes WHERE id = ?", (int(cursor.lastrowid),)).fetchone()
        return bgp_protected_prefix_row_to_dict(row)


@app.put("/api/bgp/protected-prefixes/{prefix_id}")
def update_bgp_protected_prefix(request: Request, prefix_id: int, payload: BgpProtectedPrefixPayload):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        row = conn.execute("SELECT * FROM bgp_protected_prefixes WHERE id = ?", (prefix_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Prefixo protegido nao encontrado")
        conn.execute(
            "UPDATE bgp_protected_prefixes SET cidr = ?, name = ?, reason = ?, enabled = ?, block_rtbh = ?, block_flowspec = ?, block_diversion = ?, updated_at = ? WHERE id = ?",
            (normalize_required_cidr(payload.cidr), clean_text(payload.name), clean_text(payload.reason), 1 if payload.enabled else 0, 1 if payload.block_rtbh else 0, 1 if payload.block_flowspec else 0, 1 if payload.block_diversion else 0, utc_now_iso(), prefix_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM bgp_protected_prefixes WHERE id = ?", (prefix_id,)).fetchone()
        return bgp_protected_prefix_row_to_dict(row)


@app.delete("/api/bgp/protected-prefixes/{prefix_id}")
def delete_bgp_protected_prefix(request: Request, prefix_id: int):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        row = conn.execute("SELECT * FROM bgp_protected_prefixes WHERE id = ?", (prefix_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Prefixo protegido nao encontrado")
        conn.execute("DELETE FROM bgp_protected_prefixes WHERE id = ?", (prefix_id,))
        conn.commit()
    return {"ok": True}


@app.get("/api/bgp/announcements")
def list_bgp_announcements(request: Request, status: str | None = None, limit: int = Query(200, ge=1, le=1000)):
    require_admin(request)
    ensure_sensor_db()
    params: list[Any] = []
    where = ""
    if status:
        if status not in BGP_ANNOUNCEMENT_STATUSES:
            raise HTTPException(status_code=400, detail="status invalido")
        where = "WHERE a.status = ?"
        params.append(status)
    with sqlite_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT a.*, c.name AS connector_name, p.name AS response_profile_name
            FROM bgp_announcements a
            LEFT JOIN bgp_connectors c ON c.id = a.connector_id
            LEFT JOIN bgp_response_profiles p ON p.id = a.response_profile_id
            {where}
            ORDER BY a.updated_at DESC, a.id DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()
    return {"items": [bgp_announcement_row_to_dict(row) for row in rows]}


@app.get("/api/bgp/announcements/{announcement_id}")
def get_bgp_announcement(request: Request, announcement_id: int):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        row = conn.execute(
            """
            SELECT a.*, c.name AS connector_name, p.name AS response_profile_name
            FROM bgp_announcements a
            LEFT JOIN bgp_connectors c ON c.id = a.connector_id
            LEFT JOIN bgp_response_profiles p ON p.id = a.response_profile_id
            WHERE a.id = ?
            """,
            (announcement_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Dry-run BGP nao encontrado")
        return bgp_announcement_row_to_dict(row, include_events=True, conn=conn)


@app.post("/api/bgp/announcements/dry-run", status_code=201)
def create_bgp_dry_run(request: Request, payload: BgpAnnouncementDryRunPayload):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        profile = fetch_bgp_profile(conn, payload.response_profile_id)
        connector_id = payload.connector_id or profile.get("connector_id")
        if not connector_id:
            raise HTTPException(status_code=400, detail="connector_id obrigatorio para este perfil")
        connector = fetch_bgp_connector(conn, int(connector_id))
        candidate = candidate_from_bgp_payload(payload, profile)
        validation = validate_mitigation_candidate(candidate, connector, profile)
        item = create_bgp_announcement(conn, candidate, connector, profile, validation, bgp_current_user(request))
        conn.commit()
        return item


@app.post("/api/bgp/announcements/from-anomaly/{anomaly_id}/dry-run", status_code=201)
def create_bgp_dry_run_from_anomaly(request: Request, anomaly_id: int, payload: BgpAnnouncementDryRunPayload):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        profile = fetch_bgp_profile(conn, payload.response_profile_id)
        connector_id = payload.connector_id or profile.get("connector_id")
        if not connector_id:
            raise HTTPException(status_code=400, detail="connector_id obrigatorio para este perfil")
        connector = fetch_bgp_connector(conn, int(connector_id))
        candidate = candidate_from_anomaly(conn, anomaly_id, payload, profile)
        candidate["connector_id"] = connector["id"]
        validation = validate_mitigation_candidate(candidate, connector, profile)
        item = create_bgp_announcement(conn, candidate, connector, profile, validation, bgp_current_user(request), anomaly_id=anomaly_id)
        conn.commit()
        return item


def update_bgp_announcement_status(request: Request, announcement_id: int, status: str, event_type: str, message: str) -> dict[str, Any]:
    require_admin(request)
    ensure_sensor_db()
    now = utc_now_iso()
    column = {"pending_approval": "approved_at", "rejected": "rejected_at", "withdrawn": "withdrawn_at"}[status]
    with sqlite_connection() as conn:
        row = conn.execute("SELECT * FROM bgp_announcements WHERE id = ?", (announcement_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Dry-run BGP nao encontrado")
        if row["status"] == "announced":
            raise HTTPException(status_code=400, detail="Fase 1 nao executa anuncios reais")
        conn.execute(f"UPDATE bgp_announcements SET status = ?, updated_at = ?, {column} = ? WHERE id = ?", (status, now, now, announcement_id))
        bgp_event(conn, announcement_id, event_type, message, {}, bgp_current_user(request))
        conn.commit()
        row = conn.execute(
            """
            SELECT a.*, c.name AS connector_name, p.name AS response_profile_name
            FROM bgp_announcements a
            LEFT JOIN bgp_connectors c ON c.id = a.connector_id
            LEFT JOIN bgp_response_profiles p ON p.id = a.response_profile_id
            WHERE a.id = ?
            """,
            (announcement_id,),
        ).fetchone()
        return bgp_announcement_row_to_dict(row, include_events=True, conn=conn)


@app.post("/api/bgp/announcements/{announcement_id}/approve")
def approve_bgp_announcement(request: Request, announcement_id: int):
    return update_bgp_announcement_status(request, announcement_id, "pending_approval", "approved_for_manual_review", "Dry-run aprovado para revisao manual. Nenhum anuncio real foi enviado.")


@app.post("/api/bgp/announcements/{announcement_id}/reject")
def reject_bgp_announcement(request: Request, announcement_id: int):
    return update_bgp_announcement_status(request, announcement_id, "rejected", "rejected", "Dry-run BGP rejeitado.")


@app.post("/api/bgp/announcements/{announcement_id}/withdraw")
def withdraw_bgp_announcement(request: Request, announcement_id: int):
    return update_bgp_announcement_status(request, announcement_id, "withdrawn", "withdrawn", "Dry-run marcado como withdrawn. Nenhum withdraw real foi enviado.")


@app.get("/api/ip-zones")
def list_ip_zones():
    ensure_sensor_db()
    with sqlite_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                z.*,
                t.name AS detection_template_name,
                COUNT(CASE WHEN p.active = 1 THEN p.id END) AS prefix_count,
                COUNT(CASE WHEN p.active = 1 THEN p.id END) AS active_prefix_count,
                COUNT(p.id) AS total_prefix_count
            FROM ip_zones z
            LEFT JOIN detection_templates t ON t.id = z.detection_template_id
            LEFT JOIN ip_zone_prefixes p ON p.zone_id = z.id
            GROUP BY z.id
            ORDER BY z.active DESC, z.name, z.id
            """
        ).fetchall()
        return {"items": [ip_zone_row_to_dict(row) for row in rows]}


@app.post("/api/ip-zones", status_code=201)
def create_ip_zone(payload: IpZonePayload):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        data = normalize_ip_zone_payload(conn, payload)
        now = utc_now_iso()
        cursor = conn.execute(
            """
            INSERT INTO ip_zones (name, description, active, detection_template_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (data["name"], data["description"], data["active"], data["detection_template_id"], now, now),
        )
        conn.commit()
        return fetch_ip_zone(conn, int(cursor.lastrowid), include_prefixes=True)


@app.get("/api/ip-zones/{zone_id}")
def get_ip_zone(zone_id: int, include_inactive: bool = False):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        return fetch_ip_zone(conn, zone_id, include_prefixes=True, include_inactive_prefixes=include_inactive)


@app.put("/api/ip-zones/{zone_id}")
def update_ip_zone(zone_id: int, payload: IpZonePayload):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_ip_zone_row(conn, zone_id)
        data = normalize_ip_zone_payload(conn, payload)
        now = utc_now_iso()
        conn.execute(
            """
            UPDATE ip_zones
            SET name = ?,
                description = ?,
                active = ?,
                detection_template_id = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (data["name"], data["description"], data["active"], data["detection_template_id"], now, zone_id),
        )
        conn.commit()
        return fetch_ip_zone(conn, zone_id, include_prefixes=True)


@app.delete("/api/ip-zones/{zone_id}")
def delete_ip_zone(zone_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_ip_zone_row(conn, zone_id)
        now = utc_now_iso()
        conn.execute("UPDATE ip_zones SET active = 0, updated_at = ? WHERE id = ?", (now, zone_id))
        conn.commit()
        return {"status": "disabled", "id": zone_id}


@app.post("/api/ip-zones/{zone_id}/activate")
def activate_ip_zone(zone_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_ip_zone_row(conn, zone_id)
        conn.execute("UPDATE ip_zones SET active = 1, updated_at = ? WHERE id = ?", (utc_now_iso(), zone_id))
        conn.commit()
        return fetch_ip_zone(conn, zone_id, include_prefixes=True)


@app.delete("/api/ip-zones/{zone_id}/purge")
def purge_ip_zone(zone_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        zone = fetch_ip_zone_row(conn, zone_id)
        anomaly_count = conn.execute(
            "SELECT COUNT(*) AS count FROM security_anomalies WHERE zone_id = ?",
            (zone_id,),
        ).fetchone()["count"]
        if int(anomaly_count or 0) > 0:
            raise HTTPException(
                status_code=409,
                detail="Esta zona possui historico/anomalias. Para preservar o historico, desative a zona em vez de excluir.",
            )
        conn.execute("DELETE FROM ip_zone_prefixes WHERE zone_id = ?", (zone_id,))
        conn.execute("DELETE FROM ip_zones WHERE id = ?", (zone_id,))
        conn.commit()
        return {"status": "purged", "id": zone_id, "name": zone["name"]}


@app.get("/api/ip-zones/{zone_id}/prefixes")
def list_ip_zone_prefixes(zone_id: int, include_inactive: bool = False):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_ip_zone_row(conn, zone_id)
        active_filter = "" if include_inactive else "AND p.active = 1"
        rows = conn.execute(
            f"""
            SELECT
                p.*,
                z.name AS zone_name,
                z.detection_template_id,
                t.name AS detection_template_name
            FROM ip_zone_prefixes p
            JOIN ip_zones z ON z.id = p.zone_id
            LEFT JOIN detection_templates t ON t.id = z.detection_template_id
            WHERE p.zone_id = ?
              {active_filter}
            ORDER BY p.active DESC, p.cidr, p.id
            """,
            (zone_id,),
        ).fetchall()
        return {"items": [ip_zone_prefix_row_to_dict(row) for row in rows]}


@app.post("/api/ip-zones/{zone_id}/prefixes", status_code=201)
def create_ip_zone_prefix(zone_id: int, payload: IpZonePrefixPayload):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_ip_zone_row(conn, zone_id)
        data = normalize_ip_zone_prefix_payload(payload)
        now = utc_now_iso()
        cursor = conn.execute(
            """
            INSERT INTO ip_zone_prefixes (
                zone_id, cidr, name, description, prefix_type, active, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (zone_id, data["cidr"], data["name"], data["description"], data["prefix_type"], data["active"], now, now),
        )
        conn.commit()
        return ip_zone_prefix_row_to_dict(
            conn.execute(
                """
                SELECT
                    p.*,
                    z.name AS zone_name,
                    z.detection_template_id,
                    t.name AS detection_template_name
                FROM ip_zone_prefixes p
                JOIN ip_zones z ON z.id = p.zone_id
                LEFT JOIN detection_templates t ON t.id = z.detection_template_id
                WHERE p.id = ?
                """,
                (int(cursor.lastrowid),),
            ).fetchone()
        )


@app.put("/api/ip-zones/{zone_id}/prefixes/{prefix_id}")
def update_ip_zone_prefix(zone_id: int, prefix_id: int, payload: IpZonePrefixPayload):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_ip_zone_prefix_row(conn, zone_id, prefix_id)
        data = normalize_ip_zone_prefix_payload(payload)
        now = utc_now_iso()
        conn.execute(
            """
            UPDATE ip_zone_prefixes
            SET cidr = ?,
                name = ?,
                description = ?,
                prefix_type = ?,
                active = ?,
                updated_at = ?
            WHERE id = ? AND zone_id = ?
            """,
            (data["cidr"], data["name"], data["description"], data["prefix_type"], data["active"], now, prefix_id, zone_id),
        )
        conn.commit()
        return ip_zone_prefix_row_to_dict(
            conn.execute(
                """
                SELECT
                    p.*,
                    z.name AS zone_name,
                    z.detection_template_id,
                    t.name AS detection_template_name
                FROM ip_zone_prefixes p
                JOIN ip_zones z ON z.id = p.zone_id
                LEFT JOIN detection_templates t ON t.id = z.detection_template_id
                WHERE p.id = ?
                """,
                (prefix_id,),
            ).fetchone()
        )


@app.delete("/api/ip-zones/{zone_id}/prefixes/{prefix_id}")
def delete_ip_zone_prefix(zone_id: int, prefix_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_ip_zone_prefix_row(conn, zone_id, prefix_id)
        conn.execute(
            "UPDATE ip_zone_prefixes SET active = 0, updated_at = ? WHERE id = ? AND zone_id = ?",
            (utc_now_iso(), prefix_id, zone_id),
        )
        conn.commit()
        return {"status": "disabled", "id": prefix_id}


@app.post("/api/ip-zones/{zone_id}/prefixes/{prefix_id}/activate")
def activate_ip_zone_prefix(zone_id: int, prefix_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_ip_zone_prefix_row(conn, zone_id, prefix_id)
        conn.execute(
            "UPDATE ip_zone_prefixes SET active = 1, updated_at = ? WHERE id = ? AND zone_id = ?",
            (utc_now_iso(), prefix_id, zone_id),
        )
        conn.commit()
        return ip_zone_prefix_row_to_dict(
            conn.execute(
                """
                SELECT
                    p.*,
                    z.name AS zone_name,
                    z.detection_template_id,
                    t.name AS detection_template_name
                FROM ip_zone_prefixes p
                JOIN ip_zones z ON z.id = p.zone_id
                LEFT JOIN detection_templates t ON t.id = z.detection_template_id
                WHERE p.id = ?
                """,
                (prefix_id,),
            ).fetchone()
        )


@app.delete("/api/ip-zones/{zone_id}/prefixes/{prefix_id}/purge")
def purge_ip_zone_prefix(zone_id: int, prefix_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        prefix = fetch_ip_zone_prefix_row(conn, zone_id, prefix_id)
        conn.execute("DELETE FROM ip_zone_prefixes WHERE id = ? AND zone_id = ?", (prefix_id, zone_id))
        conn.commit()
        return {"status": "purged", "id": prefix_id, "cidr": prefix["cidr"], "zone_id": zone_id}


@app.get("/api/ip-zones/{zone_id}/flow-coverage")
def ip_zone_flow_coverage(
    zone_id: int,
    range_minutes: int = Query(120, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor_id: int | None = Query(None, ge=1),
):
    ensure_sensor_db()
    ensure_clickhouse_schema()
    start_dt, end_dt = resolve_requested_range(range_minutes, start, end, start_time, end_time)
    seconds = range_seconds(start_dt, end_dt)
    with sqlite_connection() as conn:
        zone_row = fetch_ip_zone_row(conn, zone_id)
        prefix_rows = conn.execute(
            """
            SELECT *
            FROM ip_zone_prefixes
            WHERE zone_id = ?
              AND active = 1
            ORDER BY cidr, id
            """,
            (zone_id,),
        ).fetchall()
    active_prefixes = [ip_zone_prefix_row_to_dict(row) for row in prefix_rows]
    params: dict[str, Any] = {"start": start_dt, "end": end_dt, "seconds": seconds}
    filters = ["flow_time >= {start:DateTime}", "flow_time <= {end:DateTime}"]
    sensor_name = ""
    exporter_ip = ""
    if sensor_id is not None:
        with sqlite_connection() as conn:
            sensor = fetch_sensor_without_interfaces(conn, sensor_id)
        sensor_name = clean_text(sensor.get("name"))
        exporter_ip = clean_text(sensor.get("exporter_ip"))
        sensor_filters = []
        if sensor_name:
            params["sensor_name"] = sensor_name
            sensor_filters.append("sensor = {sensor_name:String}")
        if exporter_ip:
            params["exporter_ip"] = clickhouse_ip_string_param(exporter_ip, "exporter_ip")
            sensor_filters.append("toString(exporter_ip) = {exporter_ip:String}")
        if not sensor_filters:
            raise HTTPException(status_code=400, detail="Sensor sem nome ou exporter_ip configurado")
        filters.append(f"({' OR '.join(sensor_filters)})")
    base_where = " AND ".join(filters)
    src_filter, dst_filter = cidr_membership_filters_for_clickhouse(
        [prefix["cidr"] for prefix in active_prefixes],
        params,
        "coverage_zone",
    )
    input_factor = clickhouse_sample_rate_expr(sensor_id, "input", None)
    output_factor = clickhouse_sample_rate_expr(sensor_id, "output", None)
    auto_factor = clickhouse_sample_rate_expr(sensor_id, "auto", None)
    src_row_bytes_expr = corrected_value_expr("bytes", output_factor)
    src_row_packets_expr = corrected_value_expr("packets", output_factor)
    dst_row_bytes_expr = corrected_value_expr("bytes", input_factor)
    dst_row_packets_expr = corrected_value_expr("packets", input_factor)
    auto_row_bytes_expr = corrected_value_expr("bytes", auto_factor)
    auto_row_packets_expr = corrected_value_expr("packets", auto_factor)

    def coverage_query(sql: str) -> list[dict[str, Any]]:
        try:
            return rows_as_dicts(query_clickhouse(sql, params))
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Falha em /api/ip-zones/%s/flow-coverage", zone_id)
            raise HTTPException(
                status_code=502,
                detail=f"Falha ao consultar cobertura de flow no ClickHouse: {exc}",
            ) from exc

    summary_rows = coverage_query(
        f"""
        SELECT
            sumIf({src_row_bytes_expr}, {src_filter}) AS bytes_src_in_zone,
            sumIf({dst_row_bytes_expr}, {dst_filter}) AS bytes_dst_in_zone,
            sumIf({src_row_packets_expr}, {src_filter}) AS packets_src_in_zone,
            sumIf({dst_row_packets_expr}, {dst_filter}) AS packets_dst_in_zone,
            sumIf(flow_count, {src_filter}) AS total_flows_src_in_zone,
            sumIf(flow_count, {dst_filter}) AS total_flows_dst_in_zone,
            sumIf({src_row_bytes_expr}, {src_filter}) * 8 / {{seconds:Float64}} AS total_bps_src_in_zone,
            sumIf({dst_row_bytes_expr}, {dst_filter}) * 8 / {{seconds:Float64}} AS total_bps_dst_in_zone
        FROM flow_raw
        WHERE {base_where}
        """
    )
    summary = summary_rows[0] if summary_rows else {}

    def numeric_row_items(result_rows: list[dict[str, Any]], include_ip: bool = False) -> list[dict[str, Any]]:
        items = []
        for row in result_rows:
            item = {
                "bps": round(float(row.get("bps") or 0), 2),
                "bytes": int(float(row.get("total_bytes") if row.get("total_bytes") is not None else row.get("bytes") or 0)),
                "packets": int(float(row.get("total_packets") if row.get("total_packets") is not None else row.get("packets") or 0)),
                "flows": int(row.get("flows") or 0),
            }
            if include_ip:
                item["ip"] = clean_ip(row.get("ip"))
            else:
                item["input_if"] = int(row.get("input_if") or 0)
                item["output_if"] = int(row.get("output_if") or 0)
            items.append(item)
        return items

    def top_input_output(where_filter: str, row_bytes_expr: str, row_packets_expr: str) -> list[dict[str, Any]]:
        rows = coverage_query(
            f"""
            SELECT
                input_if,
                output_if,
                sum({row_bytes_expr}) AS total_bytes,
                sum({row_packets_expr}) AS total_packets,
                sum(flow_count) AS flows,
                sum({row_bytes_expr}) * 8 / {{seconds:Float64}} AS bps
            FROM flow_raw
            WHERE {base_where} AND {where_filter}
            GROUP BY input_if, output_if
            ORDER BY bps DESC
            LIMIT 10
            """
        )
        return numeric_row_items(rows)

    def top_ips(column: str, where_filter: str, row_bytes_expr: str, row_packets_expr: str) -> list[dict[str, Any]]:
        rows = coverage_query(
            f"""
            SELECT
                toString({column}) AS ip,
                sum({row_bytes_expr}) AS total_bytes,
                sum({row_packets_expr}) AS total_packets,
                sum(flow_count) AS flows,
                sum({row_bytes_expr}) * 8 / {{seconds:Float64}} AS bps
            FROM flow_raw
            WHERE {base_where} AND {where_filter}
            GROUP BY ip
            ORDER BY bps DESC
            LIMIT 10
            """
        )
        return numeric_row_items(rows, include_ip=True)

    src_bps = round(float(summary.get("total_bps_src_in_zone") or 0), 2)
    dst_bps = round(float(summary.get("total_bps_dst_in_zone") or 0), 2)
    warnings: list[str] = []
    if not active_prefixes:
        warnings.append("Esta zona nao possui prefixos ativos para diagnosticar.")
    if dst_bps > 0 and src_bps < dst_bps * 0.01:
        warnings.append(
            "A coleta esta vendo muito mais trafego entrando na zona do que saindo, considerando os prefixos cadastrados. "
            "Se outro sistema mostra upload, verifique se ele calcula por interface, por outro bloco/pool ou por outro ponto de coleta."
        )
    if src_bps > 0 and dst_bps < src_bps * 0.01:
        warnings.append(
            "A coleta esta vendo muito mais trafego saindo da zona do que entrando, considerando os prefixos cadastrados."
        )

    return {
        "zone_id": zone_id,
        "zone_name": clean_text(zone_row["name"]),
        "zone_active": bool(zone_row["active"]),
        "sensor_id": sensor_id,
        "sensor": sensor_name,
        "exporter_ip": exporter_ip,
        "start": iso(start_dt),
        "end": iso(end_dt),
        "range_minutes": range_minutes,
        "active_prefixes": active_prefixes,
        "total_bps_src_in_zone": src_bps,
        "total_bps_dst_in_zone": dst_bps,
        "total_bytes_src_in_zone": int(float(summary.get("bytes_src_in_zone") or 0)),
        "total_bytes_dst_in_zone": int(float(summary.get("bytes_dst_in_zone") or 0)),
        "total_packets_src_in_zone": int(float(summary.get("packets_src_in_zone") or 0)),
        "total_packets_dst_in_zone": int(float(summary.get("packets_dst_in_zone") or 0)),
        "total_flows_src_in_zone": int(summary.get("total_flows_src_in_zone") or 0),
        "total_flows_dst_in_zone": int(summary.get("total_flows_dst_in_zone") or 0),
        "top_input_output_general": top_input_output("1 = 1", auto_row_bytes_expr, auto_row_packets_expr),
        "top_input_output_when_src_in_zone": top_input_output(src_filter, src_row_bytes_expr, src_row_packets_expr),
        "top_input_output_when_dst_in_zone": top_input_output(dst_filter, dst_row_bytes_expr, dst_row_packets_expr),
        "top_src_ips_in_zone": top_ips("src_ip", src_filter, src_row_bytes_expr, src_row_packets_expr),
        "top_dst_ips_in_zone": top_ips("dst_ip", dst_filter, dst_row_bytes_expr, dst_row_packets_expr),
        "warnings": warnings,
    }


@app.get("/api/detection/templates")
def list_detection_templates():
    ensure_sensor_db()
    with sqlite_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                t.*,
                COUNT(DISTINCT r.id) AS rule_count,
                COUNT(DISTINCT z.id) AS zone_count
            FROM detection_templates t
            LEFT JOIN detection_template_rules r ON r.template_id = t.id
            LEFT JOIN ip_zones z ON z.detection_template_id = t.id
            GROUP BY t.id
            ORDER BY t.active DESC, t.name, t.id
            """
        ).fetchall()
        return {"items": [detection_template_row_to_dict(row) for row in rows]}


@app.post("/api/detection/templates", status_code=201)
def create_detection_template(payload: DetectionTemplatePayload):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        data = normalize_detection_template_payload(payload)
        now = utc_now_iso()
        cursor = conn.execute(
            """
            INSERT INTO detection_templates (name, description, active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (data["name"], data["description"], data["active"], now, now),
        )
        conn.commit()
        return fetch_detection_template(conn, int(cursor.lastrowid), include_rules=True)


@app.get("/api/detection/templates/{template_id}")
def get_detection_template(template_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        return fetch_detection_template(conn, template_id, include_rules=True)


@app.put("/api/detection/templates/{template_id}")
def update_detection_template(template_id: int, payload: DetectionTemplatePayload):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_detection_template_row(conn, template_id)
        data = normalize_detection_template_payload(payload)
        now = utc_now_iso()
        conn.execute(
            """
            UPDATE detection_templates
            SET name = ?,
                description = ?,
                active = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (data["name"], data["description"], data["active"], now, template_id),
        )
        conn.commit()
        return fetch_detection_template(conn, template_id, include_rules=True)


@app.delete("/api/detection/templates/{template_id}")
def delete_detection_template(template_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_detection_template_row(conn, template_id)
        conn.execute(
            "UPDATE detection_templates SET active = 0, updated_at = ? WHERE id = ?",
            (utc_now_iso(), template_id),
        )
        conn.commit()
        return {"status": "disabled", "id": template_id}


@app.get("/api/detection/templates/{template_id}/rules")
def list_detection_rules(template_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_detection_template_row(conn, template_id)
        rows = conn.execute(
            """
            SELECT *
            FROM detection_template_rules
            WHERE template_id = ?
            ORDER BY enabled DESC, vector, id
            """,
            (template_id,),
        ).fetchall()
        return {"items": [detection_rule_row_to_dict(row) for row in rows]}


@app.post("/api/detection/templates/{template_id}/rules", status_code=201)
def create_detection_rule(template_id: int, payload: DetectionRulePayload):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_detection_template_row(conn, template_id)
        data = normalize_detection_rule_payload(payload)
        now = utc_now_iso()
        cursor = conn.execute(
            """
            INSERT INTO detection_template_rules (
                template_id,
                vector,
                domain,
                direction,
                protocol,
                metric,
                comparison,
                warning_value,
                critical_value,
                window_seconds,
                consecutive_windows,
                cooldown_minutes,
                enabled,
                response,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                template_id,
                data["vector"],
                data["domain"],
                data["direction"],
                data["protocol"],
                data["metric"],
                data["comparison"],
                data["warning_value"],
                data["critical_value"],
                data["window_seconds"],
                data["consecutive_windows"],
                data["cooldown_minutes"],
                data["enabled"],
                data["response"],
                now,
                now,
            ),
        )
        conn.commit()
        return detection_rule_row_to_dict(fetch_detection_rule_row(conn, template_id, int(cursor.lastrowid)))


@app.put("/api/detection/templates/{template_id}/rules/{rule_id}")
def update_detection_rule(template_id: int, rule_id: int, payload: DetectionRulePayload):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_detection_rule_row(conn, template_id, rule_id)
        data = normalize_detection_rule_payload(payload)
        now = utc_now_iso()
        conn.execute(
            """
            UPDATE detection_template_rules
            SET vector = ?,
                domain = ?,
                direction = ?,
                protocol = ?,
                metric = ?,
                comparison = ?,
                warning_value = ?,
                critical_value = ?,
                window_seconds = ?,
                consecutive_windows = ?,
                cooldown_minutes = ?,
                enabled = ?,
                response = ?,
                updated_at = ?
            WHERE id = ? AND template_id = ?
            """,
            (
                data["vector"],
                data["domain"],
                data["direction"],
                data["protocol"],
                data["metric"],
                data["comparison"],
                data["warning_value"],
                data["critical_value"],
                data["window_seconds"],
                data["consecutive_windows"],
                data["cooldown_minutes"],
                data["enabled"],
                data["response"],
                now,
                rule_id,
                template_id,
            ),
        )
        conn.commit()
        return detection_rule_row_to_dict(fetch_detection_rule_row(conn, template_id, rule_id))


@app.delete("/api/detection/templates/{template_id}/rules/{rule_id}")
def delete_detection_rule(template_id: int, rule_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_detection_rule_row(conn, template_id, rule_id)
        conn.execute(
            "UPDATE detection_template_rules SET enabled = 0, updated_at = ? WHERE id = ? AND template_id = ?",
            (utc_now_iso(), rule_id, template_id),
        )
        conn.commit()
        return {"status": "disabled", "id": rule_id}


@app.get("/api/detection/whitelist")
def list_detection_whitelist():
    ensure_sensor_db()
    with sqlite_connection() as conn:
        rows = conn.execute(
            """
            SELECT w.*, z.name AS zone_name
            FROM detection_whitelist w
            LEFT JOIN ip_zones z ON z.id = w.zone_id
            ORDER BY w.active DESC, w.name, w.id
            """
        ).fetchall()
        return {"items": [detection_whitelist_row_to_dict(row) for row in rows]}


@app.post("/api/detection/whitelist", status_code=201)
def create_detection_whitelist(payload: DetectionWhitelistPayload):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        data = normalize_detection_whitelist_payload(conn, payload)
        now = utc_now_iso()
        cursor = conn.execute(
            """
            INSERT INTO detection_whitelist (
                name,
                description,
                active,
                type,
                src_cidr,
                dst_cidr,
                protocol,
                vector,
                zone_id,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["name"],
                data["description"],
                data["active"],
                data["type"],
                data["src_cidr"],
                data["dst_cidr"],
                data["protocol"],
                data["vector"],
                data["zone_id"],
                now,
                now,
            ),
        )
        conn.commit()
        row = conn.execute(
            """
            SELECT w.*, z.name AS zone_name
            FROM detection_whitelist w
            LEFT JOIN ip_zones z ON z.id = w.zone_id
            WHERE w.id = ?
            """,
            (int(cursor.lastrowid),),
        ).fetchone()
        return detection_whitelist_row_to_dict(row)


@app.put("/api/detection/whitelist/{whitelist_id}")
def update_detection_whitelist(whitelist_id: int, payload: DetectionWhitelistPayload):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_detection_whitelist_row(conn, whitelist_id)
        data = normalize_detection_whitelist_payload(conn, payload)
        now = utc_now_iso()
        conn.execute(
            """
            UPDATE detection_whitelist
            SET name = ?,
                description = ?,
                active = ?,
                type = ?,
                src_cidr = ?,
                dst_cidr = ?,
                protocol = ?,
                vector = ?,
                zone_id = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                data["name"],
                data["description"],
                data["active"],
                data["type"],
                data["src_cidr"],
                data["dst_cidr"],
                data["protocol"],
                data["vector"],
                data["zone_id"],
                now,
                whitelist_id,
            ),
        )
        conn.commit()
        row = conn.execute(
            """
            SELECT w.*, z.name AS zone_name
            FROM detection_whitelist w
            LEFT JOIN ip_zones z ON z.id = w.zone_id
            WHERE w.id = ?
            """,
            (whitelist_id,),
        ).fetchone()
        return detection_whitelist_row_to_dict(row)


@app.delete("/api/detection/whitelist/{whitelist_id}")
def delete_detection_whitelist(whitelist_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_detection_whitelist_row(conn, whitelist_id)
        conn.execute(
            "UPDATE detection_whitelist SET active = 0, updated_at = ? WHERE id = ?",
            (utc_now_iso(), whitelist_id),
        )
        conn.commit()
        return {"status": "disabled", "id": whitelist_id}


def detection_protocol_condition(protocol: str) -> str:
    protocol = normalize_detection_protocol(protocol)
    mapping = {
        "ALL": "1 = 1",
        "UDP": "proto = 17",
        "TCP": "proto = 6",
        "TCP+SYN": "proto = 6 AND bitAnd(tcp_flags, 2) != 0",
        "ICMP": "proto IN (1, 58)",
        "GRE": "proto = 47",
        "DNS": "proto IN (6, 17) AND (src_port = 53 OR dst_port = 53)",
        "CLDAP": "proto = 17 AND (src_port = 389 OR dst_port = 389)",
        "UDP-QUIC": "proto = 17 AND (src_port IN (443, 8443) OR dst_port IN (443, 8443))",
        "OTHER": decoder_clickhouse_condition("OTHER"),
    }
    return mapping.get(protocol, "1 = 1")


def detection_protocol_label_expr(protocol: str) -> str:
    protocol = normalize_detection_protocol(protocol)
    if protocol == "ALL":
        return decoder_label_expr()
    return f"'{protocol}'"


def detection_rule_grouping(rule: dict[str, Any]) -> str:
    vector = clean_text(rule.get("vector")).upper()
    if rule.get("domain") == "internal_ip" and "_TO_DST_" in vector:
        return "internal_ip_to_dst"
    return clean_text(rule.get("domain")) or "internal_ip"


def detection_direction_sql(direction: str, prefix_param: str) -> tuple[str, str, str, str]:
    src_match = f"isIPAddressInRange(toString(src_ip), {{{prefix_param}:String}})"
    dst_match = f"isIPAddressInRange(toString(dst_ip), {{{prefix_param}:String}})"
    direction = clean_text(direction).lower() or "transmits"
    if direction == "receives":
        return dst_match, "''", "toString(dst_ip)", "toString(dst_ip)"
    if direction == "both":
        return f"({src_match} OR {dst_match})", "toString(src_ip)", "toString(dst_ip)", f"if({src_match}, toString(src_ip), toString(dst_ip))"
    return src_match, "toString(src_ip)", "''", "toString(src_ip)"


def normalize_zone_direction(value: Any) -> str:
    text = clean_text(value).lower()
    aliases = {
        "out": "transmits",
        "upload": "transmits",
        "sends": "transmits",
        "saindo": "transmits",
        "in": "receives",
        "download": "receives",
        "entrando": "receives",
        "envolving": "both",
        "envolvendo": "both",
        "all": "both",
    }
    normalized = aliases.get(text, text or "both")
    if normalized not in DETECTION_DIRECTIONS:
        raise HTTPException(status_code=400, detail="zone_direction invalida")
    return normalized


def cidr_membership_filters_for_clickhouse(cidrs: list[str], params: dict[str, Any], prefix: str) -> tuple[str, str]:
    src_parts = []
    dst_parts = []
    for index, cidr in enumerate(cidrs):
        key = f"{prefix}_cidr_{index}"
        params[key] = clickhouse_cidr_string_param(cidr, "cidr")
        src_parts.append(f"isIPAddressInRange(toString(src_ip), {{{key}:String}})")
        dst_parts.append(f"isIPAddressInRange(toString(dst_ip), {{{key}:String}})")
    src_filter = f"({' OR '.join(src_parts)})" if src_parts else "0 = 1"
    dst_filter = f"({' OR '.join(dst_parts)})" if dst_parts else "0 = 1"
    return src_filter, dst_filter


def ip_zone_clickhouse_membership_filters(zone_id: int | None, params: dict[str, Any], prefix: str) -> tuple[str, str]:
    if zone_id is None:
        return "", ""
    ensure_sensor_db()
    with sqlite_connection() as conn:
        zone = conn.execute("SELECT id FROM ip_zones WHERE id = ? AND active = 1", (zone_id,)).fetchone()
        if zone is None:
            raise HTTPException(status_code=404, detail="IP Zone ativa nao encontrada")
        rows = conn.execute(
            """
            SELECT cidr
            FROM ip_zone_prefixes
            WHERE zone_id = ?
              AND active = 1
            ORDER BY id
            """,
            (zone_id,),
        ).fetchall()
    return cidr_membership_filters_for_clickhouse([row["cidr"] for row in rows], params, prefix)


def zone_edge_filters(src_filter: str, dst_filter: str) -> tuple[str, str, str]:
    transmits_filter = f"(({src_filter}) AND NOT ({dst_filter}))"
    receives_filter = f"(({dst_filter}) AND NOT ({src_filter}))"
    both_filter = f"({transmits_filter} OR {receives_filter})"
    return transmits_filter, receives_filter, both_filter


def ip_zone_clickhouse_filter(zone_id: int | None, zone_direction: str, params: dict[str, Any], prefix: str) -> str:
    if zone_id is None:
        return ""
    direction = normalize_zone_direction(zone_direction)
    src_filter, dst_filter = ip_zone_clickhouse_membership_filters(zone_id, params, prefix)
    transmits_filter, receives_filter, both_filter = zone_edge_filters(src_filter, dst_filter)
    if direction == "transmits":
        return transmits_filter
    if direction == "receives":
        return receives_filter
    return both_filter


def build_zone_flow_filter(zone_id: int | None, zone_direction: str, params: dict[str, Any], prefix: str) -> str:
    return ip_zone_clickhouse_filter(zone_id, zone_direction, params, prefix)


def metric_expression_for_detection(metric: str) -> str:
    mapping = {
        "packets_s": "packets_s",
        "bits_s": "bits_s",
        "flows_s": "flows_s",
        "flows": "flows",
        "unique_dst_ips": "unique_dst_ips",
        "unique_dst_ports": "unique_dst_ports",
        "unique_src_ports": "unique_src_ports",
    }
    return mapping.get(metric, "packets_s")


def active_detection_whitelist(conn: sqlite3.Connection, zone_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT w.*, z.name AS zone_name
        FROM detection_whitelist w
        LEFT JOIN ip_zones z ON z.id = w.zone_id
        WHERE w.active = 1
          AND (w.zone_id IS NULL OR w.zone_id = ?)
        ORDER BY w.zone_id DESC, w.id
        """,
        (zone_id,),
    ).fetchall()
    return [detection_whitelist_row_to_dict(row) for row in rows]


def cidr_contains_ip(cidr: str, ip_text: str) -> bool:
    cidr_text = clean_text(cidr)
    ip_clean = clean_ip(ip_text)
    if not cidr_text or not ip_clean:
        return False
    try:
        parsed_ip = ip_address(ip_clean)
        parsed_network = ip_network(cidr_text, strict=False)
    except ValueError:
        return False
    return parsed_ip in parsed_network


def candidate_matches_whitelist(candidate: dict[str, Any], whitelist: dict[str, Any]) -> bool:
    wl_protocol = normalize_detection_protocol(whitelist.get("protocol"), allow_empty=True)
    if wl_protocol and wl_protocol != "ALL" and wl_protocol != normalize_detection_protocol(candidate.get("protocol")):
        return False
    wl_vector = clean_text(whitelist.get("vector")).upper()
    if wl_vector and wl_vector != clean_text(candidate.get("vector")).upper():
        return False
    wl_zone_id = whitelist.get("zone_id")
    if wl_zone_id is not None and int(wl_zone_id) != int(candidate.get("zone_id") or 0):
        return False
    whitelist_type = whitelist.get("type")
    if whitelist_type == "source":
        return cidr_contains_ip(whitelist.get("src_cidr") or "", candidate.get("src_ip") or candidate.get("internal_ip") or "")
    if whitelist_type == "destination":
        return cidr_contains_ip(whitelist.get("dst_cidr") or "", candidate.get("dst_ip") or "")
    if whitelist_type == "source_destination":
        return (
            cidr_contains_ip(whitelist.get("src_cidr") or "", candidate.get("src_ip") or candidate.get("internal_ip") or "")
            and cidr_contains_ip(whitelist.get("dst_cidr") or "", candidate.get("dst_ip") or "")
        )
    return False


def apply_detection_whitelist(items: list[dict[str, Any]], whitelist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    filtered = []
    for item in items:
        if any(candidate_matches_whitelist(item, entry) for entry in whitelist):
            continue
        filtered.append(item)
    return filtered


def query_detection_rule_candidates(
    zone: dict[str, Any],
    template: dict[str, Any],
    rule: dict[str, Any],
    prefix: dict[str, Any],
    start_dt: datetime,
    end_dt: datetime,
    sensor_id: int | None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    warning = rule.get("warning_value")
    critical = rule.get("critical_value")
    warning_threshold = float(warning if warning is not None else critical or 0)
    if warning_threshold <= 0:
        return []

    prefix_param = "prefix_cidr"
    membership_filter, src_expr, dst_expr, internal_expr = detection_direction_sql(rule["direction"], prefix_param)
    grouping = detection_rule_grouping(rule)
    if grouping == "subnet":
        src_expr = "''"
        dst_expr = "''"
        internal_expr = "''"
    elif grouping == "internal_ip_to_dst" and rule["direction"] == "transmits":
        dst_expr = "toString(dst_ip)"

    window_seconds = max(1, int(rule.get("window_seconds") or 60))
    protocol_expr = detection_protocol_label_expr(rule.get("protocol") or "ALL")
    protocol_filter = detection_protocol_condition(rule.get("protocol") or "ALL")
    params: dict[str, Any] = {
        prefix_param: clickhouse_cidr_string_param(prefix["cidr"], "cidr"),
        "start": start_dt,
        "end": end_dt,
        "limit": max(1, int(limit)),
    }
    filters = [
        "flow_time >= {start:DateTime}",
        "flow_time <= {end:DateTime}",
        membership_filter,
        protocol_filter,
    ]
    if sensor_id is not None:
        params["exporter_ip"] = clickhouse_ip_string_param(sensor_exporter_ip(int(sensor_id)), "exporter_ip")
        filters.append("toString(exporter_ip) = {exporter_ip:String}")
    where = " AND ".join(f"({item})" for item in filters if item)
    factor_expr = clickhouse_sample_rate_expr(sensor_id, "auto")
    metric_alias = metric_expression_for_detection(rule["metric"])
    group_columns = "bucket, src_ip, dst_ip, internal_ip, protocol"
    result = query_clickhouse(
        f"""
        WITH grouped AS (
            SELECT
                toStartOfInterval(flow_time, INTERVAL {window_seconds} SECOND) AS bucket,
                {src_expr} AS src_ip,
                {dst_expr} AS dst_ip,
                {internal_expr} AS internal_ip,
                {protocol_expr} AS protocol,
                {corrected_sum_expr("bytes", factor_expr)} AS bytes,
                {corrected_sum_expr("packets", factor_expr)} AS packets,
                sum(flow_count) AS flows,
                uniqExact(toString(dst_ip)) AS unique_dst_ips,
                uniqExact(dst_port) AS unique_dst_ports,
                uniqExact(src_port) AS unique_src_ports,
                min(flow_time) AS first_seen,
                max(flow_time) AS last_seen
            FROM flow_raw
            WHERE {where}
            GROUP BY {group_columns}
        )
        SELECT
            src_ip,
            dst_ip,
            internal_ip,
            protocol,
            bytes,
            packets,
            flows,
            bytes * 8 / {float(window_seconds)} AS bits_s,
            packets / {float(window_seconds)} AS packets_s,
            flows / {float(window_seconds)} AS flows_s,
            unique_dst_ips,
            unique_dst_ports,
            unique_src_ports,
            first_seen,
            last_seen,
            {metric_alias} AS metric_value
        FROM grouped
        ORDER BY metric_value DESC
        LIMIT {{limit:UInt32}}
        """,
        params,
    )
    items = []
    for row in rows_as_dicts(result):
        metric_value = float(row.get("metric_value") or 0)
        if not comparison_matches(metric_value, warning_threshold, rule.get("comparison") or "over"):
            continue
        severity = "critical" if critical is not None and comparison_matches(metric_value, float(critical), rule.get("comparison") or "over") else "warning"
        first_seen = row.get("first_seen")
        last_seen = row.get("last_seen")
        item = {
            "zone_id": int(zone["id"]),
            "zone_name": zone["name"],
            "template_id": int(template["id"]),
            "template_name": template["name"],
            "rule_id": int(rule["id"]),
            "prefix_id": int(prefix["id"]),
            "prefix_cidr": prefix["cidr"],
            "domain": rule["domain"],
            "direction": rule["direction"],
            "vector": rule["vector"],
            "severity": severity,
            "src_ip": clean_ip(row.get("src_ip")),
            "dst_ip": clean_ip(row.get("dst_ip")),
            "internal_ip": clean_ip(row.get("internal_ip")),
            "protocol": clean_text(row.get("protocol")) or normalize_detection_protocol(rule.get("protocol")),
            "packets_s": round(float(row.get("packets_s") or 0), 2),
            "bits_s": round(float(row.get("bits_s") or 0), 2),
            "flows": int(row.get("flows") or 0),
            "flows_s": round(float(row.get("flows_s") or 0), 2),
            "packets": int(float(row.get("packets") or 0)),
            "bytes": int(float(row.get("bytes") or 0)),
            "unique_dst_ips": int(row.get("unique_dst_ips") or 0),
            "unique_dst_ports": int(row.get("unique_dst_ports") or 0),
            "unique_src_ports": int(row.get("unique_src_ports") or 0),
            "first_seen": iso(first_seen) if isinstance(first_seen, datetime) else clean_text(first_seen),
            "last_seen": iso(last_seen) if isinstance(last_seen, datetime) else clean_text(last_seen),
            "threshold_warning": float(warning_threshold),
            "threshold_critical": float(critical) if critical is not None else None,
            "metric": rule["metric"],
            "metric_value": round(metric_value, 2),
            "response": rule.get("response") or "DETECTION_ONLY",
        }
        items.append(item)
    return items


def security_anomaly_dedupe_key(candidate: dict[str, Any]) -> str:
    if candidate.get("domain") == "subnet":
        target = str(candidate.get("prefix_id") or "")
    elif candidate.get("dst_ip"):
        target = f"{candidate.get('src_ip') or candidate.get('internal_ip') or ''}>{candidate.get('dst_ip') or ''}"
    else:
        target = candidate.get("src_ip") or candidate.get("dst_ip") or candidate.get("internal_ip") or ""
    return "|".join(
        [
            clean_text(candidate.get("vector")),
            str(candidate.get("zone_id") or ""),
            target,
            clean_text(candidate.get("protocol")),
        ]
    )


def security_anomaly_message(candidate: dict[str, Any]) -> str:
    src_ip = candidate.get("src_ip") or candidate.get("internal_ip") or "N/D"
    packets_s = format_metric(candidate.get("packets_s") or 0, "packets_s")
    bits_s = format_metric(candidate.get("bits_s") or 0, "bits_s")
    protocol = candidate.get("protocol") or "ALL"
    if "DNS" in clean_text(candidate.get("vector")).upper() or protocol == "DNS":
        return (
            f"Possivel abuso DNS detectado: o IP {src_ip}, pertencente a zona {candidate.get('zone_name')}, "
            f"transmitiu {packets_s} ou {bits_s} em trafego DNS."
        )
    if candidate.get("domain") == "subnet":
        return (
            f"O prefixo {candidate.get('prefix_cidr')}, pertencente a zona {candidate.get('zone_name')}, "
            f"transmitiu {packets_s} em {protocol}, acima do limite configurado."
        )
    if candidate.get("dst_ip"):
        return (
            f"O IP {src_ip}, pertencente a zona {candidate.get('zone_name')} e ao prefixo {candidate.get('prefix_cidr')}, "
            f"transmitiu {packets_s} para {candidate.get('dst_ip')} em {protocol}, acima do limite configurado."
        )
    return (
        f"O IP {src_ip}, pertencente a zona {candidate.get('zone_name')} e ao prefixo {candidate.get('prefix_cidr')}, "
        f"transmitiu {packets_s} em {protocol}, acima do limite configurado."
    )


def upsert_security_anomaly(conn: sqlite3.Connection, candidate: dict[str, Any]) -> str:
    now = utc_now_iso()
    dedupe_key = security_anomaly_dedupe_key(candidate)
    existing = conn.execute(
        """
        SELECT *
        FROM security_anomalies
        WHERE dedupe_key = ?
          AND status = 'active'
        ORDER BY id DESC
        LIMIT 1
        """,
        (dedupe_key,),
    ).fetchone()
    message = security_anomaly_message(candidate)
    recommended_action = "Verificar origem, cliente e destino. Nenhum bloqueio automatico foi aplicado."
    values = (
        candidate["vector"],
        candidate["severity"],
        candidate["zone_id"],
        candidate["zone_name"],
        candidate["template_id"],
        candidate["template_name"],
        candidate["rule_id"],
        candidate["prefix_id"],
        candidate["prefix_cidr"],
        candidate["domain"],
        candidate["direction"],
        candidate.get("src_ip") or candidate.get("internal_ip") or "",
        candidate.get("dst_ip") or "",
        candidate.get("protocol") or "",
        candidate.get("packets_s") or 0,
        candidate.get("bits_s") or 0,
        candidate.get("flows") or 0,
        candidate.get("flows_s") or 0,
        candidate.get("packets") or 0,
        candidate.get("bytes") or 0,
        candidate.get("unique_dst_ips") or 0,
        candidate.get("unique_dst_ports") or 0,
        candidate.get("unique_src_ports") or 0,
        candidate.get("first_seen") or now,
        candidate.get("last_seen") or now,
        message,
        recommended_action,
        candidate.get("response") or "DETECTION_ONLY",
        dedupe_key,
    )
    if existing is None:
        conn.execute(
            """
            INSERT INTO security_anomalies (
                vector,
                severity,
                zone_id,
                zone_name,
                template_id,
                template_name,
                rule_id,
                prefix_id,
                prefix_cidr,
                domain,
                direction,
                src_ip,
                dst_ip,
                protocol,
                packets_s,
                bits_s,
                flows,
                flows_s,
                packets,
                bytes,
                unique_dst_ips,
                unique_dst_ports,
                unique_src_ports,
                first_seen,
                last_seen,
                message,
                recommended_action,
                response,
                dedupe_key,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (*values, now, now),
        )
        return "created"
    conn.execute(
        """
        UPDATE security_anomalies
        SET vector = ?,
            severity = ?,
            zone_id = ?,
            zone_name = ?,
            template_id = ?,
            template_name = ?,
            rule_id = ?,
            prefix_id = ?,
            prefix_cidr = ?,
            domain = ?,
            direction = ?,
            src_ip = ?,
            dst_ip = ?,
            protocol = ?,
            packets_s = ?,
            bits_s = ?,
            flows = ?,
            flows_s = ?,
            packets = ?,
            bytes = ?,
            unique_dst_ips = ?,
            unique_dst_ports = ?,
            unique_src_ports = ?,
            first_seen = ?,
            last_seen = ?,
            message = ?,
            recommended_action = ?,
            response = ?,
            dedupe_key = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (*values, now, int(existing["id"])),
    )
    return "updated"


def security_anomaly_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "vector": item["vector"],
        "severity": item["severity"],
        "status": item.get("status") or "active",
        "zone_id": int(item["zone_id"]) if item.get("zone_id") is not None else None,
        "zone_name": item.get("zone_name") or "",
        "template_id": int(item["template_id"]) if item.get("template_id") is not None else None,
        "template_name": item.get("template_name") or "",
        "rule_id": int(item["rule_id"]) if item.get("rule_id") is not None else None,
        "prefix_id": int(item["prefix_id"]) if item.get("prefix_id") is not None else None,
        "prefix_cidr": item.get("prefix_cidr") or "",
        "domain": item.get("domain") or "",
        "direction": item.get("direction") or "",
        "src_ip": item.get("src_ip") or "",
        "dst_ip": item.get("dst_ip") or "",
        "protocol": item.get("protocol") or "",
        "packets_s": float(item.get("packets_s") or 0),
        "bits_s": float(item.get("bits_s") or 0),
        "flows": float(item.get("flows") or 0),
        "flows_s": float(item.get("flows_s") or 0),
        "packets": float(item.get("packets") or 0),
        "bytes": float(item.get("bytes") or 0),
        "unique_dst_ips": int(item.get("unique_dst_ips") or 0),
        "unique_dst_ports": int(item.get("unique_dst_ports") or 0),
        "unique_src_ports": int(item.get("unique_src_ports") or 0),
        "first_seen": item.get("first_seen") or "",
        "last_seen": item.get("last_seen") or "",
        "message": item.get("message") or "",
        "recommended_action": item.get("recommended_action") or "",
        "response": item.get("response") or "DETECTION_ONLY",
        "created_at": item.get("created_at") or "",
        "updated_at": item.get("updated_at") or "",
    }


def detection_candidates_payload(
    range_minutes: int,
    sensor_id: int | None,
    zone_id: int,
    vector_filter: set[str] | None = None,
    rule_id: int | None = None,
    template_id: int | None = None,
    create_anomalies: bool = False,
) -> dict[str, Any]:
    ensure_sensor_db()
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(minutes=max(1, int(range_minutes)))
    warnings: list[str] = []
    anomaly_actions: dict[str, int] = {"created": 0, "updated": 0}
    with sqlite_connection() as conn:
        zone_row = conn.execute(
            """
            SELECT z.*, t.name AS detection_template_name
            FROM ip_zones z
            LEFT JOIN detection_templates t ON t.id = z.detection_template_id
            WHERE z.id = ? AND z.active = 1
            """,
            (zone_id,),
        ).fetchone()
        if zone_row is None:
            raise HTTPException(status_code=404, detail="IP Zone ativa nao encontrada")
        zone = ip_zone_row_to_dict(zone_row)
        prefix_rows = conn.execute(
            """
            SELECT
                p.*,
                z.name AS zone_name,
                z.detection_template_id,
                t.name AS detection_template_name
            FROM ip_zone_prefixes p
            JOIN ip_zones z ON z.id = p.zone_id
            LEFT JOIN detection_templates t ON t.id = z.detection_template_id
            WHERE p.zone_id = ?
              AND p.active = 1
            ORDER BY p.cidr, p.id
            """,
            (zone_id,),
        ).fetchall()
        prefixes = [ip_zone_prefix_row_to_dict(row) for row in prefix_rows]
        if not prefixes:
            return {
                "items": [],
                "warnings": ["IP Zone sem prefixos ativos"],
                "start": iso(start_dt),
                "end": iso(end_dt),
                "zone_id": zone_id,
                "zone": zone,
                "prefixes": [],
                "rules": [],
            }
        zone_template_id = zone.get("detection_template_id")
        if zone_template_id is None:
            return {
                "items": [],
                "warnings": ["IP Zone sem template vinculado"],
                "start": iso(start_dt),
                "end": iso(end_dt),
                "zone_id": zone_id,
                "zone": zone,
                "prefixes": prefixes,
                "rules": [],
            }
        if template_id is not None and int(template_id) != int(zone_template_id):
            return {
                "items": [],
                "warnings": ["Template filtrado nao esta associado a IP Zone selecionada"],
                "start": iso(start_dt),
                "end": iso(end_dt),
                "zone_id": zone_id,
                "zone": zone,
                "prefixes": prefixes,
                "rules": [],
                "filters": {"template_id": template_id, "rule_id": rule_id, "vector": sorted(vector_filter or [])},
            }
        template_row = conn.execute(
            "SELECT * FROM detection_templates WHERE id = ? AND active = 1",
            (int(zone_template_id),),
        ).fetchone()
        if template_row is None:
            return {
                "items": [],
                "warnings": ["Template vinculado esta inativo ou nao existe"],
                "start": iso(start_dt),
                "end": iso(end_dt),
                "zone_id": zone_id,
                "zone": zone,
                "prefixes": prefixes,
                "rules": [],
            }
        template = detection_template_row_to_dict(template_row)
        rule_filters = ["template_id = ?"]
        rule_values: list[Any] = [int(zone_template_id)]
        if rule_id is not None:
            rule_filters.append("id = ?")
            rule_values.append(int(rule_id))
        else:
            rule_filters.append("enabled = 1")
        rule_rows = conn.execute(
            f"""
            SELECT *
            FROM detection_template_rules
            WHERE {' AND '.join(rule_filters)}
            ORDER BY id
            """,
            rule_values,
        ).fetchall()
        rules = [detection_rule_row_to_dict(row) for row in rule_rows]
        if vector_filter:
            rules = [rule for rule in rules if rule["vector"].lower() in vector_filter]
        whitelist = active_detection_whitelist(conn, zone_id)

    items: list[dict[str, Any]] = []
    for prefix in prefixes:
        for rule in rules:
            try:
                items.extend(query_detection_rule_candidates(zone, template, rule, prefix, start_dt, end_dt, sensor_id))
            except Exception as exc:
                warning = f"Falha ao executar {rule['vector']} em {prefix['cidr']}: {clean_text(exc)}"
                logger.warning(warning)
                warnings.append(warning)
    items = apply_detection_whitelist(items, whitelist)
    items = sorted(items, key=lambda item: float(item.get("metric_value") or 0), reverse=True)

    if create_anomalies and items:
        with sqlite_connection() as conn:
            for item in items:
                action = upsert_security_anomaly(conn, item)
                anomaly_actions[action] = anomaly_actions.get(action, 0) + 1
            conn.commit()

    return {
        "start": iso(start_dt),
        "end": iso(end_dt),
        "zone_id": zone_id,
        "sensor_id": sensor_id,
        "zone": zone,
        "template": template,
        "prefixes": prefixes,
        "rules": rules,
        "filters": {
            "template_id": template_id,
            "rule_id": rule_id,
            "vector": sorted(vector_filter or []),
        },
        "items": items,
        "warnings": warnings,
        "anomalies": anomaly_actions if create_anomalies else None,
    }


@app.get("/api/security/vectors/candidates")
def security_vector_candidates(
    range_minutes: int = Query(30, ge=1, le=MAX_RANGE_MINUTES),
    sensor_id: int | None = Query(None, ge=1),
    zone_id: int = Query(..., ge=1),
    rule_id: int | None = Query(None, ge=1),
    vector: str | None = None,
    template_id: int | None = Query(None, ge=1),
    create_anomalies: bool = False,
):
    vector_filter = {normalize_detection_vector(vector).lower()} if clean_text(vector) else None
    return detection_candidates_payload(
        range_minutes,
        sensor_id,
        zone_id,
        vector_filter=vector_filter,
        rule_id=rule_id,
        template_id=template_id,
        create_anomalies=create_anomalies,
    )


@app.get("/api/security/vectors/prefix-internal-ip-high-pps/candidates")
def security_vector_prefix_internal_ip_high_pps_candidates(
    range_minutes: int = Query(30, ge=1, le=MAX_RANGE_MINUTES),
    sensor_id: int | None = Query(None, ge=1),
    zone_id: int = Query(..., ge=1),
    create_anomalies: bool = False,
):
    return detection_candidates_payload(
        range_minutes,
        sensor_id,
        zone_id,
        vector_filter={"prefix_internal_ip_high_udp_pps"},
        create_anomalies=create_anomalies,
    )


@app.get("/api/security/vectors/prefix-internal-ip-to-dst-high-pps/candidates")
def security_vector_prefix_internal_ip_to_dst_high_pps_candidates(
    range_minutes: int = Query(30, ge=1, le=MAX_RANGE_MINUTES),
    sensor_id: int | None = Query(None, ge=1),
    zone_id: int = Query(..., ge=1),
    create_anomalies: bool = False,
):
    return detection_candidates_payload(
        range_minutes,
        sensor_id,
        zone_id,
        vector_filter={"prefix_internal_ip_to_dst_high_udp_pps"},
        create_anomalies=create_anomalies,
    )


@app.get("/api/security/vectors/dns-internal-ip-high-pps/candidates")
def security_vector_dns_internal_ip_high_pps_candidates(
    range_minutes: int = Query(30, ge=1, le=MAX_RANGE_MINUTES),
    sensor_id: int | None = Query(None, ge=1),
    zone_id: int = Query(..., ge=1),
    create_anomalies: bool = False,
):
    return detection_candidates_payload(
        range_minutes,
        sensor_id,
        zone_id,
        vector_filter={"dns_internal_ip_high_pps"},
        create_anomalies=create_anomalies,
    )


def security_anomaly_filters(
    zone_id: int | None,
    prefix_id: int | None,
    vector: str | None,
    severity: str | None,
    protocol: str | None,
    src_ip: str | None,
    dst_ip: str | None,
) -> tuple[str, list[Any]]:
    filters: list[str] = []
    values: list[Any] = []
    if zone_id is not None:
        filters.append("zone_id = ?")
        values.append(zone_id)
    if prefix_id is not None:
        filters.append("prefix_id = ?")
        values.append(prefix_id)
    if clean_text(vector):
        filters.append("vector = ?")
        values.append(normalize_detection_vector(vector))
    if clean_text(severity):
        filters.append("severity = ?")
        values.append(clean_text(severity).lower())
    if clean_text(protocol):
        filters.append("protocol = ?")
        values.append(normalize_detection_protocol(protocol))
    if clean_text(src_ip):
        filters.append("src_ip = ?")
        values.append(clean_ip(src_ip))
    if clean_text(dst_ip):
        filters.append("dst_ip = ?")
        values.append(clean_ip(dst_ip))
    return (" AND " + " AND ".join(filters)) if filters else "", values


@app.get("/api/security/anomalies/summary")
def security_anomalies_summary():
    ensure_sensor_db()
    with sqlite_connection() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS active_count,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN severity = 'warning' THEN 1 ELSE 0 END) AS warning_count
            FROM security_anomalies
            WHERE status = 'active'
            """
        ).fetchone()
    return {
        "active_count": int(row["active_count"] or 0) if row else 0,
        "critical_count": int(row["critical_count"] or 0) if row else 0,
        "warning_count": int(row["warning_count"] or 0) if row else 0,
    }


@app.get("/api/security/anomalies/active")
def list_security_anomalies_active(
    zone_id: int | None = Query(None, ge=1),
    prefix_id: int | None = Query(None, ge=1),
    vector: str | None = None,
    severity: str | None = None,
    protocol: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
):
    return list_security_anomalies("active", zone_id, prefix_id, vector, severity, protocol, src_ip, dst_ip, limit)


@app.get("/api/security/anomalies/history")
def list_security_anomalies_history(
    zone_id: int | None = Query(None, ge=1),
    prefix_id: int | None = Query(None, ge=1),
    vector: str | None = None,
    severity: str | None = None,
    protocol: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
):
    return list_security_anomalies("history", zone_id, prefix_id, vector, severity, protocol, src_ip, dst_ip, limit)


def list_security_anomalies(
    status_group: str,
    zone_id: int | None,
    prefix_id: int | None,
    vector: str | None,
    severity: str | None,
    protocol: str | None,
    src_ip: str | None,
    dst_ip: str | None,
    limit: int,
) -> dict[str, Any]:
    ensure_sensor_db()
    extra_where, values = security_anomaly_filters(zone_id, prefix_id, vector, severity, protocol, src_ip, dst_ip)
    status_where = "status = 'active'" if status_group == "active" else "status <> 'active'"
    with sqlite_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM security_anomalies
            WHERE {status_where}
              {extra_where}
            ORDER BY last_seen DESC, id DESC
            LIMIT ?
            """,
            [*values, limit],
        ).fetchall()
    return {"items": [security_anomaly_row_to_dict(row) for row in rows]}


@app.post("/api/security/anomalies/{anomaly_id}/ack")
def acknowledge_security_anomaly(anomaly_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        row = conn.execute("SELECT id FROM security_anomalies WHERE id = ?", (anomaly_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Anomalia nao encontrada")
        conn.execute(
            "UPDATE security_anomalies SET status = 'acknowledged', updated_at = ? WHERE id = ?",
            (utc_now_iso(), anomaly_id),
        )
        conn.commit()
    return {"status": "acknowledged", "id": anomaly_id}


@app.post("/api/security/anomalies/{anomaly_id}/close")
def close_security_anomaly(anomaly_id: int):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        row = conn.execute("SELECT id FROM security_anomalies WHERE id = ?", (anomaly_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Anomalia nao encontrada")
        conn.execute(
            "UPDATE security_anomalies SET status = 'closed', updated_at = ? WHERE id = ?",
            (utc_now_iso(), anomaly_id),
        )
        conn.commit()
    return {"status": "closed", "id": anomaly_id}


def normalize_attack_port_filter(value: Any, field_name: str) -> str:
    text = clean_text(value).lower()
    if not text or text in {"any", "*"}:
        return "any"
    normalized: list[str] = []
    for raw_token in text.split(","):
        token = raw_token.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = [part.strip() for part in token.split("-", 1)]
            if not start_text.isdigit() or not end_text.isdigit():
                raise HTTPException(status_code=400, detail=f"{field_name} invalido")
            start = int(start_text)
            end = int(end_text)
            if start > end or start < 0 or end > 65535:
                raise HTTPException(status_code=400, detail=f"{field_name} fora da faixa 0-65535")
            normalized.append(f"{start}-{end}")
            continue
        if not token.isdigit():
            raise HTTPException(status_code=400, detail=f"{field_name} invalido")
        port = int(token)
        if port < 0 or port > 65535:
            raise HTTPException(status_code=400, detail=f"{field_name} fora da faixa 0-65535")
        normalized.append(str(port))
    return ",".join(normalized) if normalized else "any"


def normalize_attack_asn_filter(value: Any, field_name: str) -> str:
    text = clean_text(value).upper().replace(" ", "")
    if not text:
        return ""
    normalized: list[str] = []
    for raw_token in text.split(","):
        token = raw_token.strip()
        if not token:
            continue
        if token.startswith("AS"):
            token = token[2:]
        if not token.isdigit():
            raise HTTPException(status_code=400, detail=f"{field_name} invalido")
        asn = int(token)
        if asn <= 0 or asn > 4294967295:
            raise HTTPException(status_code=400, detail=f"{field_name} fora da faixa")
        normalized.append(str(asn))
    return ",".join(normalized)


def normalize_attack_protocol_filter(value: Any) -> str:
    text = clean_text(value).lower()
    if not text:
        return "any"
    if text in ATTACK_PROTOCOLS:
        return text
    proto = parse_proto_filter(text)
    return str(proto)


def normalize_attack_tcp_flags_filter(value: Any) -> str:
    text = clean_text(value).lower().replace("synack", "syn+ack")
    if not text or text in {"any", "*"}:
        return "any"
    if text in {"none", "null"}:
        return "null"
    if text in ATTACK_TCP_FLAGS:
        return text
    _ = parse_tcp_flags_filter(text)
    return text.upper()


def attack_vector_template_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "description": row["description"],
        "enabled": sqlite_bool(row["enabled"]),
        "learn_enabled": sqlite_bool(row["learn_enabled"]),
        "learn_days": int(row["learn_days"] or 2),
        "safety_margin_percent": float(row["safety_margin_percent"] or 0),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "vector_count": int(row["vector_count"] or 0) if "vector_count" in row.keys() else 0,
    }


def attack_vector_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "template_id": int(item["template_id"]),
        "template_name": item.get("template_name", ""),
        "name": item["name"],
        "enabled": sqlite_bool(item["enabled"]),
        "domain_type": item["domain_type"],
        "target_cidr": item.get("target_cidr"),
        "src_cidr": item.get("src_cidr"),
        "dst_cidr": item.get("dst_cidr"),
        "src_port": item.get("src_port") or "any",
        "dst_port": item.get("dst_port") or "any",
        "protocol": item.get("protocol") or "any",
        "src_asn": item.get("src_asn") or "",
        "dst_asn": item.get("dst_asn") or "",
        "tcp_flags": item.get("tcp_flags") or "any",
        "window_seconds": int(item.get("window_seconds") or 60),
        "sensor_id": int(item["sensor_id"]) if item.get("sensor_id") is not None else None,
        "sensor_name": item.get("sensor_name") or "",
        "interface_if_index": int(item["interface_if_index"]) if item.get("interface_if_index") is not None else None,
        "direction": item["direction"],
        "decoder": item["decoder"],
        "comparison": item["comparison"],
        "threshold_value": float(item["threshold_value"] or 0),
        "threshold_unit": item["threshold_unit"],
        "severity": item["severity"],
        "response_action": item["response_action"],
        "parent_enabled": sqlite_bool(item["parent_enabled"]),
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


def attack_vector_suggestion_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "template_id": int(item["template_id"]),
        "sensor_id": int(item["sensor_id"]) if item.get("sensor_id") is not None else None,
        "sensor_name": item.get("sensor_name") or "",
        "interface_if_index": int(item["interface_if_index"]) if item.get("interface_if_index") is not None else None,
        "domain_type": item["domain_type"],
        "target_cidr": item.get("target_cidr"),
        "direction": item["direction"],
        "decoder": item["decoder"],
        "threshold_value": round(float(item["threshold_value"] or 0), 2),
        "threshold_unit": item["threshold_unit"],
        "baseline_p95": round(float(item["baseline_p95"] or 0), 2),
        "baseline_p99": round(float(item["baseline_p99"] or 0), 2),
        "baseline_max": round(float(item["baseline_max"] or 0), 2),
        "baseline_average": round(float(item.get("baseline_average") or 0), 2),
        "margin_percent": round(float(item["margin_percent"] or 0), 2),
        "confidence": round(float(item["confidence"] or 0), 3),
        "created_at": item["created_at"],
        "updated_at": item.get("updated_at") or item["created_at"],
        "applied_at": item.get("applied_at"),
    }


def anomaly_event_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item["id"]),
        "attack_vector_id": int(item["attack_vector_id"]) if item.get("attack_vector_id") is not None else None,
        "attack_vector_name": item.get("attack_vector_name") or "",
        "sensor_id": int(item["sensor_id"]) if item.get("sensor_id") is not None else None,
        "sensor_name": item.get("sensor_name") or "",
        "interface_if_index": int(item["interface_if_index"]) if item.get("interface_if_index") is not None else None,
        "target_ip": item.get("target_ip") or "",
        "target_cidr": item.get("target_cidr") or "",
        "direction": item["direction"],
        "decoder": item["decoder"],
        "severity": item["severity"],
        "metric_unit": item["metric_unit"],
        "threshold_value": float(item["threshold_value"] or 0),
        "observed_value": float(item["observed_value"] or 0),
        "peak_value": float(item["peak_value"] or 0),
        "started_at": item["started_at"],
        "last_seen_at": item["last_seen_at"],
        "ended_at": item.get("ended_at"),
        "status": item["status"],
        "estimated_bytes": int(item["estimated_bytes"] or 0),
        "estimated_packets": int(item["estimated_packets"] or 0),
        "flow_count": int(item["flow_count"] or 0),
        "summary": item["summary"],
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


def fetch_attack_vector_template(conn: sqlite3.Connection, template_id: int) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT t.*, COUNT(v.id) AS vector_count
        FROM attack_vector_templates t
        LEFT JOIN attack_vectors v ON v.template_id = t.id
        WHERE t.id = ?
        GROUP BY t.id
        """,
        (template_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Template nao encontrado")
    return attack_vector_template_row_to_dict(row)


def fetch_attack_vector(conn: sqlite3.Connection, vector_id: int) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT
            v.*,
            t.name AS template_name,
            s.name AS sensor_name
        FROM attack_vectors v
        LEFT JOIN attack_vector_templates t ON t.id = v.template_id
        LEFT JOIN sensors s ON s.id = v.sensor_id
        WHERE v.id = ?
        """,
        (vector_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Vetor de ataque nao encontrado")
    return attack_vector_row_to_dict(row)


def normalize_attack_vector_template_payload(payload: AttackVectorTemplatePayload) -> dict[str, Any]:
    data = dump_model(payload)
    name = clean_text(data.get("name"))
    if not name:
        raise HTTPException(status_code=400, detail="Nome do template obrigatorio")
    return {
        "name": name,
        "description": clean_text(data.get("description")),
        "enabled": 1 if data.get("enabled") else 0,
        "learn_enabled": 1 if data.get("learn_enabled") else 0,
        "learn_days": positive_int(data.get("learn_days") or 2, "learn_days"),
        "safety_margin_percent": float(data.get("safety_margin_percent") or 0),
    }


def normalize_attack_vector_payload(conn: sqlite3.Connection, payload: AttackVectorPayload) -> dict[str, Any]:
    data = dump_model(payload)
    _ = fetch_attack_vector_template(conn, int(data["template_id"]))
    name = clean_text(data.get("name"))
    if not name:
        raise HTTPException(status_code=400, detail="Nome do vetor obrigatorio")
    domain_type = normalize_choice(data.get("domain_type") or "any", ATTACK_DOMAIN_TYPES, "domain_type")
    direction = normalize_choice(data.get("direction") or "receives", ATTACK_DIRECTIONS, "direction")
    decoder = clean_text(data.get("decoder") or "IP").upper()
    if decoder not in ATTACK_DECODERS:
        raise HTTPException(status_code=400, detail="decoder invalido")
    comparison = normalize_choice(data.get("comparison") or "over", ATTACK_COMPARISONS, "comparison")
    threshold_unit = normalize_choice(data.get("threshold_unit") or "bits_s", ATTACK_THRESHOLD_UNITS, "threshold_unit")
    severity = normalize_choice(data.get("severity") or "warning", ATTACK_SEVERITIES, "severity")
    response_action = normalize_choice(
        data.get("response_action") or "alert_only",
        ATTACK_RESPONSE_ACTIONS,
        "response_action",
    )
    target_cidr = normalize_target_cidr(data.get("target_cidr"))
    src_cidr = normalize_optional_cidr(data.get("src_cidr"), "src_cidr")
    dst_cidr = normalize_optional_cidr(data.get("dst_cidr"), "dst_cidr")
    src_port = normalize_attack_port_filter(data.get("src_port"), "src_port")
    dst_port = normalize_attack_port_filter(data.get("dst_port"), "dst_port")
    protocol = normalize_attack_protocol_filter(data.get("protocol"))
    src_asn = normalize_attack_asn_filter(data.get("src_asn"), "src_asn")
    dst_asn = normalize_attack_asn_filter(data.get("dst_asn"), "dst_asn")
    tcp_flags = normalize_attack_tcp_flags_filter(data.get("tcp_flags"))
    window_seconds = positive_int(data.get("window_seconds") or 60, "window_seconds")
    if window_seconds > 86400:
        raise HTTPException(status_code=400, detail="window_seconds fora da faixa 1-86400")
    sensor_id = data.get("sensor_id")
    interface_if_index = data.get("interface_if_index")
    if domain_type == "prefix" and not target_cidr:
        raise HTTPException(status_code=400, detail="target_cidr obrigatorio para dominio prefix")
    if domain_type in {"sensor", "interface"} and sensor_id is None:
        raise HTTPException(status_code=400, detail="sensor_id obrigatorio para este dominio")
    if domain_type == "interface" and interface_if_index is None:
        raise HTTPException(status_code=400, detail="interface_if_index obrigatorio para dominio interface")
    if sensor_id is not None:
        _ = fetch_sensor_without_interfaces(conn, int(sensor_id))
    if interface_if_index is not None:
        interface_if_index = non_negative_int(interface_if_index, "interface_if_index")
        if sensor_id is not None:
            row = conn.execute(
                """
                SELECT id
                FROM sensor_interfaces
                WHERE sensor_id = ? AND if_index = ?
                LIMIT 1
                """,
                (int(sensor_id), int(interface_if_index)),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Interface nao encontrada para o sensor informado")
    return {
        "template_id": int(data["template_id"]),
        "name": name,
        "enabled": 1 if data.get("enabled") else 0,
        "domain_type": domain_type,
        "target_cidr": target_cidr,
        "src_cidr": src_cidr,
        "dst_cidr": dst_cidr,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "src_asn": src_asn,
        "dst_asn": dst_asn,
        "tcp_flags": tcp_flags,
        "window_seconds": window_seconds,
        "sensor_id": int(sensor_id) if sensor_id is not None else None,
        "interface_if_index": int(interface_if_index) if interface_if_index is not None else None,
        "direction": direction,
        "decoder": decoder,
        "comparison": comparison,
        "threshold_value": float(data.get("threshold_value") or 0),
        "threshold_unit": threshold_unit,
        "severity": severity,
        "response_action": response_action,
        "parent_enabled": 1 if data.get("parent_enabled", True) else 0,
    }


def decoder_clickhouse_condition(decoder: str) -> str:
    decoder = clean_text(decoder).upper()
    port = "(src_port IN ({ports}) OR dst_port IN ({ports}))"
    known_conditions = [
        "proto IN (1, 58, 50, 51)",
        "((src_port = 53 OR dst_port = 53) AND proto IN (6, 17))",
        "((src_port = 123 OR dst_port = 123) AND proto = 17)",
        "((src_port IN (443, 8443) OR dst_port IN (443, 8443)) AND proto = 17)",
        "((src_port IN (80, 443, 25, 465, 587, 110, 995, 143, 993, 5060, 5061, 11211, 137, 138, 139) OR dst_port IN (80, 443, 25, 465, 587, 110, 995, 143, 993, 5060, 5061, 11211, 137, 138, 139)) AND proto IN (6, 17))",
        "((src_port IN (500, 4500) OR dst_port IN (500, 4500)) AND proto = 17)",
    ]
    mapping = {
        "IP": "1 = 1",
        "FLOWS": "1 = 1",
        "TCP": "proto = 6",
        "TCP+ALL": "proto = 6",
        "TCP+SYN": "proto = 6 AND bitAnd(tcp_flags, 2) != 0",
        "FLOW+SYN": "proto = 6 AND bitAnd(tcp_flags, 2) != 0",
        "TCP+SYNACK": "proto = 6 AND bitAnd(tcp_flags, 18) = 18",
        "TCP+ACK": "proto = 6 AND bitAnd(tcp_flags, 16) != 0",
        "TCP+RST": "proto = 6 AND bitAnd(tcp_flags, 4) != 0",
        "TCP+NULL": "proto = 6 AND tcp_flags = 0",
        "UDP": "proto = 17",
        "ICMP": "proto IN (1, 58)",
        "DNS": "proto IN (6, 17) AND (src_port = 53 OR dst_port = 53)",
        "NTP": "proto = 17 AND (src_port = 123 OR dst_port = 123)",
        "QUIC": "proto = 17 AND (src_port IN (443, 8443) OR dst_port IN (443, 8443))",
        "UDP+QUIC": "proto = 17 AND (src_port IN (443, 8443) OR dst_port IN (443, 8443))",
        "HTTP": "proto = 6 AND (src_port = 80 OR dst_port = 80)",
        "HTTPS": "proto = 6 AND (src_port = 443 OR dst_port = 443)",
        "MAIL": f"proto = 6 AND {port.format(ports='25, 465, 587, 110, 995, 143, 993')}",
        "SIP": "proto IN (6, 17) AND (src_port IN (5060, 5061) OR dst_port IN (5060, 5061))",
        "IPSEC": "proto IN (50, 51) OR (proto = 17 AND (src_port IN (500, 4500) OR dst_port IN (500, 4500)))",
        "MEMCACHED": "proto IN (6, 17) AND (src_port = 11211 OR dst_port = 11211)",
        "NETBIOS": "proto IN (6, 17) AND (src_port IN (137, 138, 139) OR dst_port IN (137, 138, 139))",
        "FRAGMENT": "0 = 1",
        "INVALID": "0 = 1",
        "OTHER": f"NOT ({' OR '.join(known_conditions)} OR proto IN (6, 17))",
    }
    return mapping.get(decoder, "0 = 1")


def classify_flow_decoder(flow: dict[str, Any]) -> str:
    """Return the primary GMJ-FLOW decoder label for one normalized flow row."""
    proto = int(flow.get("proto") or 0)
    flags = int(flow.get("tcp_flags") or 0)
    src_port = int(flow.get("src_port") or 0)
    dst_port = int(flow.get("dst_port") or 0)
    ports = {src_port, dst_port}
    if proto in {50, 51} or (proto == 17 and ports & {500, 4500}):
        return "IPSEC"
    if proto in {6, 17} and 53 in ports:
        return "DNS"
    if proto == 17 and 123 in ports:
        return "NTP"
    if proto == 17 and ports & {443, 8443}:
        return "UDP+QUIC"
    if proto == 6 and 80 in ports:
        return "HTTP"
    if proto == 6 and 443 in ports:
        return "HTTPS"
    if proto == 6 and ports & {25, 465, 587, 110, 995, 143, 993}:
        return "MAIL"
    if proto in {6, 17} and ports & {5060, 5061}:
        return "SIP"
    if proto in {6, 17} and 11211 in ports:
        return "MEMCACHED"
    if proto in {6, 17} and ports & {137, 138, 139}:
        return "NETBIOS"
    if proto in {1, 58}:
        return "ICMP"
    if proto == 6 and flags == 0:
        return "TCP+NULL"
    if proto == 6 and flags & 18 == 18:
        return "TCP+SYNACK"
    if proto == 6 and flags & 2:
        return "TCP+SYN"
    if proto == 6 and flags & 4:
        return "TCP+RST"
    if proto == 6 and flags & 16:
        return "TCP+ACK"
    if proto == 6:
        return "TCP"
    if proto == 17:
        return "UDP"
    return "OTHER"


def append_attack_port_filter(
    filters: list[str],
    params: dict[str, Any],
    column: str,
    value: Any,
    prefix: str,
) -> None:
    text = normalize_attack_port_filter(value, prefix)
    if text == "any":
        return
    parts: list[str] = []
    for index, token in enumerate(text.split(",")):
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start_key = f"{prefix}_start_{index}"
            end_key = f"{prefix}_end_{index}"
            params[start_key] = int(start_text)
            params[end_key] = int(end_text)
            parts.append(f"{column} BETWEEN {{{start_key}:UInt16}} AND {{{end_key}:UInt16}}")
        else:
            key = f"{prefix}_{index}"
            params[key] = int(token)
            parts.append(f"{column} = {{{key}:UInt16}}")
    if parts:
        filters.append(f"({' OR '.join(parts)})")


def append_attack_asn_filter(
    filters: list[str],
    params: dict[str, Any],
    column: str,
    value: Any,
    prefix: str,
) -> None:
    text = normalize_attack_asn_filter(value, prefix)
    if not text:
        return
    parts: list[str] = []
    for index, token in enumerate(text.split(",")):
        key = f"{prefix}_{index}"
        params[key] = int(token)
        parts.append(f"{column} = {{{key}:UInt32}}")
    if parts:
        filters.append(f"({' OR '.join(parts)})")


def append_attack_protocol_filter(filters: list[str], params: dict[str, Any], value: Any) -> None:
    protocol = normalize_attack_protocol_filter(value)
    if protocol == "any":
        return
    if protocol == "other":
        filters.append("proto NOT IN (1, 6, 17, 47, 50, 58)")
        return
    if protocol == "icmp":
        filters.append("proto IN (1, 58)")
        return
    proto = parse_proto_filter(protocol)
    if proto is not None:
        params["attack_protocol"] = proto
        filters.append("proto = {attack_protocol:UInt8}")


def append_attack_tcp_flags_filter(filters: list[str], params: dict[str, Any], value: Any) -> None:
    flags_text = normalize_attack_tcp_flags_filter(value)
    if flags_text == "any":
        return
    if flags_text == "null":
        filters.append("tcp_flags = 0")
        return
    flags = parse_tcp_flags_filter(flags_text)
    if flags is None:
        return
    params["attack_tcp_flags"] = flags
    if flags == 0:
        filters.append("tcp_flags = 0")
    else:
        filters.append("bitAnd(tcp_flags, {attack_tcp_flags:UInt16}) = {attack_tcp_flags:UInt16}")


def append_attack_vector_filters(
    vector: dict[str, Any],
    start: datetime,
    end: datetime,
    params: dict[str, Any],
) -> str:
    filters = [flow_time_where(params, start, end)]
    sensor_id = vector.get("sensor_id")
    if sensor_id is not None:
        params["exporter_ip"] = clickhouse_ip_string_param(sensor_exporter_ip(int(sensor_id)), "exporter_ip")
        filters.append("toString(exporter_ip) = {exporter_ip:String}")

    if_index = vector.get("interface_if_index")
    if if_index is not None:
        params["if_index"] = int(if_index)
        direction = vector.get("direction")
        if direction == "receives":
            filters.append("input_if = {if_index:UInt32}")
        elif direction == "sends":
            filters.append("output_if = {if_index:UInt32}")
        else:
            filters.append("(input_if = {if_index:UInt32} OR output_if = {if_index:UInt32})")

    target_cidr = clean_text(vector.get("target_cidr"))
    if target_cidr:
        params["target_cidr"] = clickhouse_cidr_string_param(target_cidr)
        direction = vector.get("direction")
        if direction == "receives":
            filters.append("isIPAddressInRange(toString(dst_ip), {target_cidr:String})")
        elif direction == "sends":
            filters.append("isIPAddressInRange(toString(src_ip), {target_cidr:String})")
        else:
            filters.append(
                "(isIPAddressInRange(toString(src_ip), {target_cidr:String}) "
                "OR isIPAddressInRange(toString(dst_ip), {target_cidr:String}))"
            )

    src_cidr = clean_text(vector.get("src_cidr"))
    if src_cidr:
        params["src_cidr"] = clickhouse_cidr_string_param(src_cidr, "src_cidr")
        filters.append("isIPAddressInRange(toString(src_ip), {src_cidr:String})")

    dst_cidr = clean_text(vector.get("dst_cidr"))
    if dst_cidr:
        params["dst_cidr"] = clickhouse_cidr_string_param(dst_cidr, "dst_cidr")
        filters.append("isIPAddressInRange(toString(dst_ip), {dst_cidr:String})")

    append_attack_port_filter(filters, params, "src_port", vector.get("src_port"), "src_port")
    append_attack_port_filter(filters, params, "dst_port", vector.get("dst_port"), "dst_port")
    append_attack_protocol_filter(filters, params, vector.get("protocol"))
    append_attack_asn_filter(filters, params, "src_asn", vector.get("src_asn"), "src_asn")
    append_attack_asn_filter(filters, params, "dst_asn", vector.get("dst_asn"), "dst_asn")
    append_attack_tcp_flags_filter(filters, params, vector.get("tcp_flags"))

    decoder_condition = decoder_clickhouse_condition(vector.get("decoder") or "IP")
    filters.append(f"({decoder_condition})")
    return " AND ".join(filters)


def target_expression_for_vector(vector: dict[str, Any]) -> str:
    domain_type = vector.get("domain_type")
    direction = vector.get("direction")
    target_cidr = clean_text(vector.get("target_cidr"))
    if domain_type in {"sensor", "interface", "any"} and not target_cidr:
        return "''"
    if direction == "sends":
        return "toString(src_ip)"
    if direction == "both":
        if target_cidr:
            return "if(isIPAddressInRange(toString(dst_ip), {target_cidr:String}), toString(dst_ip), toString(src_ip))"
        return "toString(dst_ip)"
    return "toString(dst_ip)"


def is_internal_ip_text(value: str) -> bool:
    text = clean_ip(value)
    if not text:
        return False
    try:
        parsed = ip_address(text)
    except ValueError:
        return False
    return bool(parsed.is_private or parsed.is_loopback or parsed.is_link_local)


def vector_target_matches_domain(vector: dict[str, Any], target_ip: str) -> bool:
    domain_type = vector.get("domain_type")
    if domain_type == "internal_ip" and not clean_text(vector.get("target_cidr")):
        return is_internal_ip_text(target_ip)
    if domain_type == "external_ip" and not clean_text(vector.get("target_cidr")):
        return bool(target_ip) and not is_internal_ip_text(target_ip)
    return True


def percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percent
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def metric_value_from_row(row: dict[str, Any], unit: str) -> float:
    if unit == "packets_s":
        return float(row.get("packets_s") or 0)
    if unit == "flows_s":
        return float(row.get("flows_s") or 0)
    return float(row.get("bits_s") or 0)


def metric_alias_for_unit(unit: str) -> str:
    if unit == "packets_s":
        return "packets_s"
    if unit == "flows_s":
        return "flows_s"
    return "bits_s"


def sample_rate_direction_for_vector(vector: dict[str, Any]) -> str:
    direction = vector.get("direction")
    if direction == "receives":
        return "input"
    if direction == "sends":
        return "output"
    return "auto"


def comparison_matches(observed: float, threshold: float, comparison: str) -> bool:
    if comparison == "over":
        return observed > threshold
    return False


def anomaly_min_duration_seconds(override: int | None = None) -> int:
    if override is not None:
        return max(int(override), 0)
    try:
        return max(int(os.getenv("GMJFLOW_ANOMALY_MIN_DURATION_SECONDS", "30")), 0)
    except ValueError:
        return 30


def clickhouse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return utc_dt(value)
    return parse_datetime_text(value)


def min_duration_pending(row: dict[str, Any], end_dt: datetime, min_duration_seconds: int) -> bool:
    if min_duration_seconds <= 0:
        return False
    first_seen = clickhouse_datetime(row.get("first_seen_at"))
    if first_seen is None:
        return False
    return (end_dt - first_seen).total_seconds() < min_duration_seconds


def attack_vector_where_summary(vector: dict[str, Any], start_dt: datetime, end_dt: datetime, where: str) -> str:
    parts = [
        f"flow_time={iso(start_dt)}..{iso(end_dt)}",
        f"domain_type={vector.get('domain_type') or 'any'}",
        f"target_cidr={clean_text(vector.get('target_cidr')) or 'none'}",
        f"src_cidr={clean_text(vector.get('src_cidr')) or 'none'}",
        f"dst_cidr={clean_text(vector.get('dst_cidr')) or 'none'}",
        f"src_port={clean_text(vector.get('src_port')) or 'any'}",
        f"dst_port={clean_text(vector.get('dst_port')) or 'any'}",
        f"protocol={clean_text(vector.get('protocol')) or 'any'}",
        f"src_asn={clean_text(vector.get('src_asn')) or 'none'}",
        f"dst_asn={clean_text(vector.get('dst_asn')) or 'none'}",
        f"tcp_flags={clean_text(vector.get('tcp_flags')) or 'any'}",
        f"window_seconds={int(vector.get('window_seconds') or 60)}",
        f"direction={vector.get('direction') or 'receives'}",
        f"decoder={vector.get('decoder') or 'IP'}",
        f"where={where}",
    ]
    if vector.get("sensor_id") is not None:
        parts.append(f"sensor_id={vector.get('sensor_id')}")
    if vector.get("interface_if_index") is not None:
        parts.append(f"interface_if_index={vector.get('interface_if_index')}")
    return "; ".join(parts)


def format_metric(value: Any, unit: str) -> str:
    number = float(value or 0)
    if unit == "bits_s":
        units = ("bps", "Kbps", "Mbps", "Gbps", "Tbps")
        index = 0
        while number >= 1000 and index < len(units) - 1:
            number /= 1000
            index += 1
        return f"{number:.1f} {units[index]}" if number < 10 and index else f"{number:.0f} {units[index]}"
    if unit == "packets_s":
        units = ("pps", "Kpps", "Mpps", "Gpps")
    else:
        units = ("flows/s", "K flows/s", "M flows/s", "G flows/s")
    index = 0
    while number >= 1000 and index < len(units) - 1:
        number /= 1000
        index += 1
    return f"{number:.1f} {units[index]}" if number < 10 and index else f"{number:.0f} {units[index]}"


def anomaly_summary(vector: dict[str, Any], target_ip: str, observed: float, threshold: float, started_at: str) -> str:
    target = target_ip or vector.get("target_cidr") or "escopo configurado"
    direction = {"receives": "recebido", "sends": "enviado", "both": "recebido/enviado"}.get(
        vector.get("direction"),
        vector.get("direction"),
    )
    metric = format_metric(observed, vector.get("threshold_unit"))
    limit = format_metric(threshold, vector.get("threshold_unit"))
    return (
        f"Possivel anomalia {vector.get('decoder')} detectada em {target}. "
        f"O trafego {direction} atingiu {metric}, acima do limite configurado de {limit}. "
        f"Inicio em {started_at}."
    )


def query_learn_series(
    decoder: str,
    unit: str,
    direction: str,
    sensor_id: int | None,
    interface_if_index: int | None,
    target_cidr: str | None,
    start_dt: datetime,
    end_dt: datetime,
) -> list[float]:
    params: dict[str, Any] = {}
    vector_like = {
        "sensor_id": sensor_id,
        "interface_if_index": interface_if_index,
        "target_cidr": target_cidr,
        "direction": direction,
        "decoder": decoder,
    }
    where = append_attack_vector_filters(vector_like, start_dt, end_dt, params)
    if not vector_like["target_cidr"]:
        where += " AND input_if > 0" if direction == "receives" else " AND output_if > 0"
    rate_expr = clickhouse_sample_rate_expr(sensor_id, sample_rate_direction_for_vector(vector_like), interface_if_index)
    result = query_clickhouse(
        f"""
        SELECT
            toStartOfMinute(flow_time) AS bucket,
            {corrected_sum_expr("bytes", rate_expr)} * 8 / 60 AS bits_s,
            {corrected_sum_expr("packets", rate_expr)} / 60 AS packets_s,
            sum(flow_count) / 60 AS flows_s
        FROM flow_raw
        WHERE {where}
        GROUP BY bucket
        ORDER BY bucket
        """,
        params,
    )
    values = []
    for row in rows_as_dicts(result):
        value = metric_value_from_row(row, unit)
        if value > 0:
            values.append(value)
    return values


def learn_sensor_targets(payload: AttackVectorLearnPayload) -> list[dict[str, Any]]:
    with sqlite_connection() as conn:
        if payload.sensor_id is not None:
            sensor = fetch_sensor_without_interfaces(conn, int(payload.sensor_id))
            return [{"sensor_id": sensor["id"], "sensor_name": sensor["name"]}]
        rows = conn.execute(
            """
            SELECT id, name
            FROM sensors
            WHERE active = 1
              AND flow_collector_enabled = 1
              AND exporter_ip <> ''
            ORDER BY name, id
            """
        ).fetchall()
        if rows:
            return [{"sensor_id": int(row["id"]), "sensor_name": row["name"]} for row in rows]
    return [{"sensor_id": None, "sensor_name": ""}]


def low_metric_floor(unit: str) -> float:
    if unit == "bits_s":
        return 1_000.0
    return 1.0


def fetch_attack_vector_suggestion(conn: sqlite3.Connection, suggestion_id: int) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT a.*, s.name AS sensor_name
        FROM attack_vector_suggestions a
        LEFT JOIN sensors s ON s.id = a.sensor_id
        WHERE a.id = ?
        """,
        (suggestion_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Sugestao nao encontrada")
    return attack_vector_suggestion_row_to_dict(row)


def upsert_attack_vector_suggestion(conn: sqlite3.Connection, suggestion: dict[str, Any]) -> dict[str, Any]:
    key = (
        int(suggestion["template_id"]),
        int(suggestion["sensor_id"] or 0),
        int(suggestion["interface_if_index"] or 0),
        suggestion["domain_type"],
        suggestion["target_cidr"] or "",
        suggestion["direction"],
        suggestion["decoder"],
        suggestion["threshold_unit"],
    )
    row = conn.execute(
        """
        SELECT id
        FROM attack_vector_suggestions
        WHERE applied_at IS NULL
          AND template_id = ?
          AND COALESCE(sensor_id, 0) = ?
          AND COALESCE(interface_if_index, 0) = ?
          AND domain_type = ?
          AND COALESCE(target_cidr, '') = ?
          AND direction = ?
          AND decoder = ?
          AND threshold_unit = ?
        LIMIT 1
        """,
        key,
    ).fetchone()
    if row is not None:
        suggestion_id = int(row["id"])
        conn.execute(
            """
            UPDATE attack_vector_suggestions
            SET threshold_value = ?,
                baseline_p95 = ?,
                baseline_p99 = ?,
                baseline_max = ?,
                baseline_average = ?,
                margin_percent = ?,
                confidence = ?,
                created_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                suggestion["threshold_value"],
                suggestion["baseline_p95"],
                suggestion["baseline_p99"],
                suggestion["baseline_max"],
                suggestion["baseline_average"],
                suggestion["margin_percent"],
                suggestion["confidence"],
                suggestion["created_at"],
                suggestion["updated_at"],
                suggestion_id,
            ),
        )
    else:
        cursor = conn.execute(
            """
            INSERT INTO attack_vector_suggestions (
                template_id,
                sensor_id,
                interface_if_index,
                domain_type,
                target_cidr,
                direction,
                decoder,
                threshold_value,
                threshold_unit,
                baseline_p95,
                baseline_p99,
                baseline_max,
                baseline_average,
                margin_percent,
                confidence,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                suggestion["template_id"],
                suggestion["sensor_id"],
                suggestion["interface_if_index"],
                suggestion["domain_type"],
                suggestion["target_cidr"],
                suggestion["direction"],
                suggestion["decoder"],
                suggestion["threshold_value"],
                suggestion["threshold_unit"],
                suggestion["baseline_p95"],
                suggestion["baseline_p99"],
                suggestion["baseline_max"],
                suggestion["baseline_average"],
                suggestion["margin_percent"],
                suggestion["confidence"],
                suggestion["created_at"],
                suggestion["updated_at"],
            ),
        )
        suggestion_id = int(cursor.lastrowid)
    return fetch_attack_vector_suggestion(conn, suggestion_id)


def threshold_unit_name_token(unit: str) -> str:
    if unit == "bits_s":
        return "bits"
    if unit == "packets_s":
        return "packets"
    if unit == "flows_s":
        return "flows"
    return clean_text(unit) or "metric"


def learn_attack_vector_suggestions(payload: AttackVectorLearnPayload) -> list[dict[str, Any]]:
    ensure_sensor_db()
    target_cidr = normalize_target_cidr(payload.target_cidr)
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(days=payload.days)
    suggestions: list[dict[str, Any]] = []

    with sqlite_connection() as conn:
        template = fetch_attack_vector_template(conn, payload.template_id)
    if not template.get("learn_enabled"):
        return []

    domain_type = "prefix" if target_cidr else "any"
    sensor_targets = learn_sensor_targets(payload)
    for sensor in sensor_targets:
        sensor_id = sensor["sensor_id"]
        interface_if_index = None
        for direction in ("receives", "sends"):
            for decoder, unit in LEARN_DECODER_UNITS:
                try:
                    values = query_learn_series(
                        decoder,
                        unit,
                        direction,
                        sensor_id,
                        interface_if_index,
                        target_cidr,
                        start_dt,
                        end_dt,
                    )
                except Exception as exc:
                    logger.warning(
                        "Falha ao aprender baseline sensor=%s %s/%s/%s: %s",
                        sensor_id,
                        direction,
                        decoder,
                        unit,
                        exc,
                    )
                    continue
                if not values:
                    continue
                p95 = percentile(values, 0.95)
                p99 = percentile(values, 0.99)
                maximum = max(values)
                average = sum(values) / len(values)
                if maximum < low_metric_floor(unit) and average < low_metric_floor(unit):
                    continue
                suggested = maximum * (1 + payload.margin_percent / 100)
                expected_points = max(payload.days * 24 * 60, 1)
                confidence = min(1.0, max(0.2, len(values) / expected_points))
                now = utc_now_iso()
                suggestion = {
                    "template_id": payload.template_id,
                    "sensor_id": sensor_id,
                    "interface_if_index": interface_if_index,
                    "domain_type": domain_type,
                    "target_cidr": target_cidr,
                    "direction": direction,
                    "decoder": decoder,
                    "threshold_value": suggested,
                    "threshold_unit": unit,
                    "baseline_p95": p95,
                    "baseline_p99": p99,
                    "baseline_max": maximum,
                    "baseline_average": average,
                    "margin_percent": payload.margin_percent,
                    "confidence": confidence,
                    "created_at": now,
                    "updated_at": now,
                }
                with sqlite_connection() as conn:
                    suggestions.append(upsert_attack_vector_suggestion(conn, suggestion))
                    conn.commit()
    return suggestions


def apply_attack_vector_suggestion(conn: sqlite3.Connection, suggestion_id: int) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT a.*, s.name AS sensor_name
        FROM attack_vector_suggestions a
        LEFT JOIN sensors s ON s.id = a.sensor_id
        WHERE a.id = ?
        """,
        (suggestion_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Sugestao nao encontrada")
    suggestion = attack_vector_suggestion_row_to_dict(row)
    now = utc_now_iso()
    sensor_label = suggestion.get("sensor_name") or (
        f"sensor-{suggestion['sensor_id']}" if suggestion.get("sensor_id") is not None else "Global"
    )
    unit_token = threshold_unit_name_token(suggestion["threshold_unit"])
    name = f"{sensor_label} {suggestion['decoder']} {suggestion['direction']} {unit_token} warning"
    cursor = conn.execute(
        """
        INSERT INTO attack_vectors (
            template_id,
            name,
            enabled,
            domain_type,
            target_cidr,
            sensor_id,
            interface_if_index,
            direction,
            decoder,
            comparison,
            threshold_value,
            threshold_unit,
            severity,
            response_action,
            parent_enabled,
            created_at,
            updated_at
        )
        VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, 'over', ?, ?, 'warning', 'alert_only', 1, ?, ?)
        """,
        (
            suggestion["template_id"],
            name,
            suggestion["domain_type"],
            suggestion["target_cidr"],
            suggestion["sensor_id"],
            suggestion["interface_if_index"],
            suggestion["direction"],
            suggestion["decoder"],
            suggestion["threshold_value"],
            suggestion["threshold_unit"],
            now,
            now,
        ),
    )
    conn.execute(
        "UPDATE attack_vector_suggestions SET applied_at = ?, updated_at = ? WHERE id = ?",
        (now, now, suggestion_id),
    )
    vector_id = int(cursor.lastrowid)
    return fetch_attack_vector(conn, vector_id)


def active_attack_vectors(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT
            v.*,
            t.name AS template_name,
            s.name AS sensor_name
        FROM attack_vectors v
        JOIN attack_vector_templates t ON t.id = v.template_id
        LEFT JOIN sensors s ON s.id = v.sensor_id
        WHERE v.enabled = 1
          AND v.parent_enabled = 1
          AND t.enabled = 1
        ORDER BY v.id
        """
    ).fetchall()
    return [attack_vector_row_to_dict(row) for row in rows]


def query_vector_recent_traffic(
    vector: dict[str, Any],
    start_dt: datetime,
    end_dt: datetime,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    seconds = range_seconds(start_dt, end_dt)
    params: dict[str, Any] = {"seconds": seconds, "limit": max(int(limit), 1)}
    where = append_attack_vector_filters(vector, start_dt, end_dt, params)
    target_expr = target_expression_for_vector(vector)
    order_metric = metric_alias_for_unit(vector.get("threshold_unit") or "bits_s")
    if_index = vector.get("interface_if_index")
    rate_expr = clickhouse_sample_rate_expr(
        vector.get("sensor_id"),
        sample_rate_direction_for_vector(vector),
        int(if_index) if if_index is not None else None,
    )
    result = query_clickhouse(
        f"""
        SELECT
            {target_expr} AS target_ip,
            {corrected_sum_expr("bytes", rate_expr)} AS total_bytes,
            {corrected_sum_expr("packets", rate_expr)} AS total_packets,
            sum(flow_count) AS total_flows,
            min(flow_time) AS first_seen_at,
            max(flow_time) AS last_seen_at,
            {corrected_sum_expr("bytes", rate_expr)} * 8 / {{seconds:Float64}} AS bits_s,
            {corrected_sum_expr("packets", rate_expr)} / {{seconds:Float64}} AS packets_s,
            sum(flow_count) / {{seconds:Float64}} AS flows_s
        FROM flow_raw
        WHERE {where}
        GROUP BY target_ip
        ORDER BY {order_metric} DESC
        LIMIT {{limit:UInt32}}
        """,
        params,
    )
    items = []
    for row in rows_as_dicts(result):
        row["target_ip"] = clean_ip(row.get("target_ip"))
        row["total_bytes"] = int(row.get("total_bytes") or 0)
        row["total_packets"] = int(row.get("total_packets") or 0)
        row["flow_count"] = int(row.get("total_flows") or 0)
        row["estimated_bytes"] = row["total_bytes"]
        row["estimated_packets"] = row["total_packets"]
        if vector_target_matches_domain(vector, row["target_ip"]):
            items.append(row)
    return items


def query_vector_sample_rows(
    vector: dict[str, Any],
    start_dt: datetime,
    end_dt: datetime,
    target_ip: str = "",
    limit: int = 10,
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"limit": max(int(limit), 1)}
    where = sample_flow_where_for_event(vector, clean_ip(target_ip), start_dt, end_dt, params)
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
            flow_count
        FROM flow_raw
        WHERE {where}
        ORDER BY flow_time DESC, bytes DESC
        LIMIT {{limit:UInt32}}
        """,
        params,
    )
    rows = []
    for row in rows_as_dicts(result):
        item = {
            "flow_time": iso(row["flow_time"]) if isinstance(row.get("flow_time"), datetime) else clean_text(row.get("flow_time")),
            "sensor": row.get("sensor"),
            "exporter_ip": clean_ip(row.get("exporter_ip")),
            "src_ip": clean_ip(row.get("src_ip")),
            "dst_ip": clean_ip(row.get("dst_ip")),
            "src_port": int(row.get("src_port") or 0),
            "dst_port": int(row.get("dst_port") or 0),
            "proto": int(row.get("proto") or 0),
            "proto_name": proto_name(row.get("proto")),
            "tcp_flags": int(row.get("tcp_flags") or 0),
            "input_if": int(row.get("input_if") or 0),
            "output_if": int(row.get("output_if") or 0),
            "bytes": int(row.get("bytes") or 0),
            "packets": int(row.get("packets") or 0),
            "flow_count": int(row.get("flow_count") or 0),
        }
        item["decoder"] = classify_flow_decoder(item)
        rows.append(item)
    return rows


def anomaly_dedupe_key(vector: dict[str, Any], target_ip: str) -> str:
    return "|".join(
        [
            str(vector.get("id")),
            target_ip or "",
            str(vector.get("sensor_id") or ""),
            str(vector.get("interface_if_index") or ""),
            vector.get("decoder") or "",
            vector.get("direction") or "",
        ]
    )


def sample_flow_where_for_event(
    vector: dict[str, Any],
    target_ip: str,
    start_dt: datetime,
    end_dt: datetime,
    params: dict[str, Any],
) -> str:
    where = append_attack_vector_filters(vector, start_dt, end_dt, params)
    if target_ip:
        params["target_ip"] = clickhouse_ip_string_param(target_ip, "target_ip")
        direction = vector.get("direction")
        if direction == "receives":
            where += " AND toString(dst_ip) = {target_ip:String}"
        elif direction == "sends":
            where += " AND toString(src_ip) = {target_ip:String}"
        else:
            where += " AND (toString(src_ip) = {target_ip:String} OR toString(dst_ip) = {target_ip:String})"
    return where


def attack_vector_test_result(
    vector: dict[str, Any],
    lookback_seconds: int,
    min_duration_seconds: int,
    sample_limit: int = 10,
) -> dict[str, Any]:
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(seconds=max(int(lookback_seconds), 1))
    summary_params: dict[str, Any] = {"seconds": range_seconds(start_dt, end_dt)}
    where = append_attack_vector_filters(vector, start_dt, end_dt, summary_params)
    rows = query_vector_recent_traffic(vector, start_dt, end_dt, limit=1)
    row = rows[0] if rows else {}
    threshold = float(vector.get("threshold_value") or 0)
    unit = vector.get("threshold_unit") or "bits_s"
    observed = metric_value_from_row(row, unit) if row else 0.0
    matched = comparison_matches(observed, threshold, vector.get("comparison") or "over")
    pending_min_duration = bool(row) and matched and min_duration_pending(row, end_dt, min_duration_seconds)

    reason_parts: list[str] = []
    if not vector.get("enabled"):
        reason_parts.append("vetor desativado")
    if not vector.get("parent_enabled"):
        reason_parts.append("template desativado")
    if not row:
        reason_parts.append("nenhum flow encontrado")
    elif pending_min_duration:
        reason_parts.append("matched=true, aguardando duracao minima")
    elif matched:
        reason_parts.append("observed_value acima do threshold")
    else:
        reason_parts.append("observed_value abaixo ou igual ao threshold")

    target_ip = clean_ip(row.get("target_ip")) if row else ""
    sample_rows = query_vector_sample_rows(vector, start_dt, end_dt, target_ip, sample_limit) if row else []
    return {
        "vector_id": int(vector["id"]),
        "enabled": bool(vector.get("enabled")),
        "parent_enabled": bool(vector.get("parent_enabled")),
        "domain_type": vector.get("domain_type"),
        "target_cidr": vector.get("target_cidr"),
        "src_cidr": vector.get("src_cidr"),
        "dst_cidr": vector.get("dst_cidr"),
        "src_port": vector.get("src_port"),
        "dst_port": vector.get("dst_port"),
        "protocol": vector.get("protocol"),
        "src_asn": vector.get("src_asn"),
        "dst_asn": vector.get("dst_asn"),
        "tcp_flags": vector.get("tcp_flags"),
        "window_seconds": vector.get("window_seconds"),
        "direction": vector.get("direction"),
        "decoder": vector.get("decoder"),
        "threshold_value": threshold,
        "threshold_unit": unit,
        "lookback_seconds": int(lookback_seconds),
        "min_duration_seconds": int(min_duration_seconds),
        "flow_count": int(row.get("flow_count") or 0),
        "total_bytes": int(row.get("total_bytes") or 0),
        "total_packets": int(row.get("total_packets") or 0),
        "observed_value": observed,
        "matched": matched,
        "reason": "; ".join(reason_parts),
        "clickhouse_where_summary": attack_vector_where_summary(vector, start_dt, end_dt, where),
        "sample_rows": sample_rows,
    }


def save_anomaly_flow_samples(
    conn: sqlite3.Connection,
    event_id: int,
    vector: dict[str, Any],
    target_ip: str,
    start_dt: datetime,
    end_dt: datetime,
    limit: int = 20,
) -> None:
    if limit <= 0:
        return
    params: dict[str, Any] = {"limit": limit}
    where = sample_flow_where_for_event(vector, target_ip, start_dt, end_dt, params)
    try:
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
                flow_count
            FROM flow_raw
            WHERE {where}
            ORDER BY bytes DESC
            LIMIT {{limit:UInt32}}
            """,
            params,
        )
    except Exception as exc:
        logger.warning("Falha ao salvar amostra de flows da anomalia %s: %s", event_id, exc)
        return
    for row in rows_as_dicts(result):
        conn.execute(
            """
            INSERT INTO anomaly_event_flows (
                anomaly_event_id,
                flow_time,
                sensor,
                exporter_ip,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto,
                tcp_flags,
                input_if,
                output_if,
                bytes,
                packets,
                flow_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                iso(row["flow_time"]),
                row.get("sensor"),
                clean_ip(row.get("exporter_ip")),
                clean_ip(row.get("src_ip")),
                clean_ip(row.get("dst_ip")),
                int(row.get("src_port") or 0),
                int(row.get("dst_port") or 0),
                int(row.get("proto") or 0),
                int(row.get("tcp_flags") or 0),
                int(row.get("input_if") or 0),
                int(row.get("output_if") or 0),
                int(row.get("bytes") or 0),
                int(row.get("packets") or 0),
                int(row.get("flow_count") or 0),
            ),
        )


def upsert_anomaly_event(
    conn: sqlite3.Connection,
    vector: dict[str, Any],
    traffic: dict[str, Any],
    start_dt: datetime,
    end_dt: datetime,
) -> str:
    if vector.get("response_action") == "ignore":
        logger.info("Anomalia ignorada por response_action=ignore vetor=%s", vector.get("id"))
        return "ignored"
    target_ip = clean_ip(traffic.get("target_ip"))
    observed = metric_value_from_row(traffic, vector["threshold_unit"])
    threshold = float(vector["threshold_value"] or 0)
    now = iso(end_dt)
    dedupe_key = anomaly_dedupe_key(vector, target_ip)
    row = conn.execute(
        """
        SELECT *
        FROM anomaly_events
        WHERE dedupe_key = ? AND status = 'active'
        ORDER BY id DESC
        LIMIT 1
        """,
        (dedupe_key,),
    ).fetchone()
    estimated_bytes = int(traffic.get("total_bytes") or traffic.get("estimated_bytes") or 0)
    estimated_packets = int(traffic.get("total_packets") or traffic.get("estimated_packets") or 0)
    flow_count = int(traffic.get("flow_count") or 0)
    if row is None:
        started_at = now
        summary = anomaly_summary(vector, target_ip, observed, threshold, started_at)
        cursor = conn.execute(
            """
            INSERT INTO anomaly_events (
                attack_vector_id,
                sensor_id,
                interface_if_index,
                target_ip,
                target_cidr,
                direction,
                decoder,
                severity,
                metric_unit,
                threshold_value,
                observed_value,
                peak_value,
                started_at,
                last_seen_at,
                status,
                estimated_bytes,
                estimated_packets,
                flow_count,
                summary,
                dedupe_key,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                vector["id"],
                vector.get("sensor_id"),
                vector.get("interface_if_index"),
                target_ip,
                vector.get("target_cidr"),
                vector["direction"],
                vector["decoder"],
                vector["severity"],
                vector["threshold_unit"],
                threshold,
                observed,
                observed,
                started_at,
                now,
                estimated_bytes,
                estimated_packets,
                flow_count,
                summary,
                dedupe_key,
                now,
                now,
            ),
        )
        event_id = int(cursor.lastrowid)
        action = "created"
        logger.info(
            "Anomalia criada event_id=%s vetor=%s decoder=%s observed_value=%.6f threshold=%.6f",
            event_id,
            vector.get("id"),
            vector.get("decoder"),
            observed,
            threshold,
        )
    else:
        event_id = int(row["id"])
        peak = max(float(row["peak_value"] or 0), observed)
        summary = anomaly_summary(vector, target_ip, peak, threshold, row["started_at"])
        conn.execute(
            """
            UPDATE anomaly_events
            SET observed_value = ?,
                peak_value = ?,
                last_seen_at = ?,
                estimated_bytes = estimated_bytes + ?,
                estimated_packets = estimated_packets + ?,
                flow_count = flow_count + ?,
                summary = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (observed, peak, now, estimated_bytes, estimated_packets, flow_count, summary, now, event_id),
        )
        action = "updated"
        logger.info(
            "Anomalia atualizada event_id=%s vetor=%s decoder=%s observed_value=%.6f threshold=%.6f",
            event_id,
            vector.get("id"),
            vector.get("decoder"),
            observed,
            threshold,
        )

    sample_count = conn.execute(
        "SELECT COUNT(*) AS count FROM anomaly_event_flows WHERE anomaly_event_id = ?",
        (event_id,),
    ).fetchone()["count"]
    save_anomaly_flow_samples(
        conn,
        event_id,
        vector,
        target_ip,
        start_dt,
        end_dt,
        max(0, min(20, 100 - int(sample_count or 0))),
    )
    return action


def close_stale_anomaly_events(conn: sqlite3.Connection, now: datetime) -> int:
    close_after = int(os.getenv("GMJFLOW_ANOMALY_CLOSE_AFTER_SECONDS", "120"))
    cutoff = iso(now - timedelta(seconds=max(close_after, 1)))
    stale_rows = conn.execute(
        """
        SELECT id, attack_vector_id, decoder
        FROM anomaly_events
        WHERE status = 'active'
          AND last_seen_at < ?
        """,
        (cutoff,),
    ).fetchall()
    cursor = conn.execute(
        """
        UPDATE anomaly_events
        SET status = 'ended',
            ended_at = ?,
            updated_at = ?
        WHERE status = 'active'
          AND last_seen_at < ?
        """,
        (iso(now), iso(now), cutoff),
    )
    closed = int(cursor.rowcount or 0)
    for row in stale_rows:
        logger.info(
            "Anomalia encerrada event_id=%s vetor=%s decoder=%s",
            row["id"],
            row["attack_vector_id"],
            row["decoder"],
        )
    if closed:
        logger.info("Anomalias encerradas por inatividade=%s", closed)
    return closed


def detect_anomalies_once() -> dict[str, Any]:
    ensure_sensor_db()
    lookback = int(os.getenv("GMJFLOW_ANOMALY_LOOKBACK_SECONDS", "60"))
    min_duration = anomaly_min_duration_seconds()
    default_lookback = max(lookback, min_duration, 1)
    end_dt = datetime.now(timezone.utc)
    checked = 0
    triggered = 0
    errors: list[str] = []
    with sqlite_connection() as conn:
        vectors = active_attack_vectors(conn)
        logger.info("Worker de anomalias avaliando %s vetores ativos", len(vectors))
        for vector in vectors:
            checked += 1
            vector_window = max(int(vector.get("window_seconds") or default_lookback), min_duration, 1)
            start_dt = end_dt - timedelta(seconds=vector_window)
            try:
                rows = query_vector_recent_traffic(vector, start_dt, end_dt)
            except Exception as exc:
                message = f"vetor {vector['id']}: {exc}"
                errors.append(message)
                logger.warning("Falha ao detectar anomalia %s", message)
                continue
            for row in rows:
                observed = metric_value_from_row(row, vector["threshold_unit"])
                threshold = float(vector["threshold_value"] or 0)
                matched = comparison_matches(observed, threshold, vector.get("comparison") or "over")
                logger.info(
                    "Worker anomalias vetor=%s decoder=%s observed_value=%.6f threshold=%.6f matched=%s",
                    vector.get("id"),
                    vector.get("decoder"),
                    observed,
                    threshold,
                    matched,
                )
                if matched and min_duration_pending(row, end_dt, min_duration):
                    logger.info(
                        "Worker anomalias vetor=%s matched=true aguardando duracao minima=%ss",
                        vector.get("id"),
                        min_duration,
                    )
                    continue
                if matched:
                    triggered += 1
                    action = upsert_anomaly_event(conn, vector, row, start_dt, end_dt)
                    logger.info(
                        "Worker anomalias vetor=%s decoder=%s anomalia_%s",
                        vector.get("id"),
                        vector.get("decoder"),
                        action,
                    )
        closed = close_stale_anomaly_events(conn, end_dt)
        conn.commit()
    return {"ok": True, "checked": checked, "triggered": triggered, "closed": closed, "errors": errors}


def anomaly_detection_enabled() -> bool:
    return clean_text(os.getenv("GMJFLOW_ANOMALY_DETECTION_ENABLED", "true")).lower() not in {"0", "false", "no", "off"}


def anomaly_detection_loop() -> None:
    interval = int(os.getenv("GMJFLOW_ANOMALY_INTERVAL_SECONDS", "30"))
    interval = max(interval, 5)
    while not ANOMALY_DETECTION_STOP.wait(interval):
        try:
            detect_anomalies_once()
        except Exception as exc:  # pragma: no cover - background resilience.
            logger.warning("Falha no worker de anomalias: %s", exc)


def start_anomaly_detection_thread() -> None:
    global ANOMALY_DETECTION_THREAD
    if not anomaly_detection_enabled():
        return
    if ANOMALY_DETECTION_THREAD is not None and ANOMALY_DETECTION_THREAD.is_alive():
        return
    ANOMALY_DETECTION_STOP.clear()
    ANOMALY_DETECTION_THREAD = threading.Thread(
        target=anomaly_detection_loop,
        name="gmj-flow-anomaly-detector",
        daemon=True,
    )
    ANOMALY_DETECTION_THREAD.start()


@app.get("/api/attack-vector-templates")
def list_attack_vector_templates(request: Request):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        rows = conn.execute(
            """
            SELECT t.*, COUNT(v.id) AS vector_count
            FROM attack_vector_templates t
            LEFT JOIN attack_vectors v ON v.template_id = t.id
            GROUP BY t.id
            ORDER BY t.name
            """
        ).fetchall()
    return {"items": [attack_vector_template_row_to_dict(row) for row in rows]}


@app.post("/api/attack-vector-templates", status_code=201)
def create_attack_vector_template(request: Request, payload: AttackVectorTemplatePayload):
    require_admin(request)
    ensure_sensor_db()
    data = normalize_attack_vector_template_payload(payload)
    now = utc_now_iso()
    with sqlite_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO attack_vector_templates (
                name,
                description,
                enabled,
                learn_enabled,
                learn_days,
                safety_margin_percent,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["name"],
                data["description"],
                data["enabled"],
                data["learn_enabled"],
                data["learn_days"],
                data["safety_margin_percent"],
                now,
                now,
            ),
        )
        conn.commit()
        return fetch_attack_vector_template(conn, int(cursor.lastrowid))


@app.put("/api/attack-vector-templates/{template_id}")
def update_attack_vector_template(request: Request, template_id: int, payload: AttackVectorTemplatePayload):
    require_admin(request)
    ensure_sensor_db()
    data = normalize_attack_vector_template_payload(payload)
    now = utc_now_iso()
    with sqlite_connection() as conn:
        _ = fetch_attack_vector_template(conn, template_id)
        conn.execute(
            """
            UPDATE attack_vector_templates
            SET name = ?,
                description = ?,
                enabled = ?,
                learn_enabled = ?,
                learn_days = ?,
                safety_margin_percent = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                data["name"],
                data["description"],
                data["enabled"],
                data["learn_enabled"],
                data["learn_days"],
                data["safety_margin_percent"],
                now,
                template_id,
            ),
        )
        conn.execute(
            "UPDATE attack_vectors SET parent_enabled = ?, updated_at = ? WHERE template_id = ?",
            (data["enabled"], now, template_id),
        )
        conn.commit()
        return fetch_attack_vector_template(conn, template_id)


@app.delete("/api/attack-vector-templates/{template_id}")
def delete_attack_vector_template(request: Request, template_id: int):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_attack_vector_template(conn, template_id)
        conn.execute("DELETE FROM attack_vector_templates WHERE id = ?", (template_id,))
        conn.commit()
    return {"ok": True}


@app.post("/api/attack-vector-templates/{template_id}/duplicate", status_code=201)
def duplicate_attack_vector_template(request: Request, template_id: int):
    require_admin(request)
    ensure_sensor_db()
    now = utc_now_iso()
    with sqlite_connection() as conn:
        template = fetch_attack_vector_template(conn, template_id)
        cursor = conn.execute(
            """
            INSERT INTO attack_vector_templates (
                name,
                description,
                enabled,
                learn_enabled,
                learn_days,
                safety_margin_percent,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"{template['name']} (copia)",
                template["description"],
                1 if template["enabled"] else 0,
                1 if template["learn_enabled"] else 0,
                template["learn_days"],
                template["safety_margin_percent"],
                now,
                now,
            ),
        )
        new_template_id = int(cursor.lastrowid)
        rows = conn.execute("SELECT * FROM attack_vectors WHERE template_id = ?", (template_id,)).fetchall()
        for row in rows:
            vector = attack_vector_row_to_dict(row)
            conn.execute(
                """
                INSERT INTO attack_vectors (
                    template_id,
                    name,
                    enabled,
                    domain_type,
                    target_cidr,
                    src_cidr,
                    dst_cidr,
                    src_port,
                    dst_port,
                    protocol,
                    src_asn,
                    dst_asn,
                    tcp_flags,
                    window_seconds,
                    sensor_id,
                    interface_if_index,
                    direction,
                    decoder,
                    comparison,
                    threshold_value,
                    threshold_unit,
                    severity,
                    response_action,
                    parent_enabled,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_template_id,
                    vector["name"],
                    1 if vector["enabled"] else 0,
                    vector["domain_type"],
                    vector["target_cidr"],
                    vector["src_cidr"],
                    vector["dst_cidr"],
                    vector["src_port"],
                    vector["dst_port"],
                    vector["protocol"],
                    vector["src_asn"],
                    vector["dst_asn"],
                    vector["tcp_flags"],
                    vector["window_seconds"],
                    vector["sensor_id"],
                    vector["interface_if_index"],
                    vector["direction"],
                    vector["decoder"],
                    vector["comparison"],
                    vector["threshold_value"],
                    vector["threshold_unit"],
                    vector["severity"],
                    vector["response_action"],
                    1 if template["enabled"] else 0,
                    now,
                    now,
                ),
            )
        conn.commit()
        return fetch_attack_vector_template(conn, new_template_id)


@app.get("/api/attack-vectors/templates")
def list_attack_vector_presets(request: Request):
    require_admin(request)
    defaults = {
        "enabled": True,
        "domain_type": "any",
        "target_cidr": None,
        "src_cidr": None,
        "dst_cidr": None,
        "src_asn": "",
        "dst_asn": "",
        "comparison": "over",
        "severity": "warning",
        "response_action": "alert_only",
        "window_seconds": 60,
    }
    return {"items": [{**defaults, **item} for item in ATTACK_VECTOR_PRESET_TEMPLATES]}


@app.get("/api/attack-vectors")
def list_attack_vectors(request: Request, template_id: int | None = Query(None, ge=1)):
    require_admin(request)
    ensure_sensor_db()
    filters = []
    values: list[Any] = []
    if template_id is not None:
        filters.append("v.template_id = ?")
        values.append(template_id)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with sqlite_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT
                v.*,
                t.name AS template_name,
                s.name AS sensor_name
            FROM attack_vectors v
            LEFT JOIN attack_vector_templates t ON t.id = v.template_id
            LEFT JOIN sensors s ON s.id = v.sensor_id
            {where}
            ORDER BY v.template_id, v.id
            """,
            values,
        ).fetchall()
    return {"items": [attack_vector_row_to_dict(row) for row in rows]}


@app.post("/api/attack-vectors", status_code=201)
def create_attack_vector(request: Request, payload: AttackVectorPayload):
    require_admin(request)
    ensure_sensor_db()
    now = utc_now_iso()
    with sqlite_connection() as conn:
        data = normalize_attack_vector_payload(conn, payload)
        cursor = conn.execute(
            """
            INSERT INTO attack_vectors (
                template_id,
                name,
                enabled,
                domain_type,
                target_cidr,
                src_cidr,
                dst_cidr,
                src_port,
                dst_port,
                protocol,
                src_asn,
                dst_asn,
                tcp_flags,
                window_seconds,
                sensor_id,
                interface_if_index,
                direction,
                decoder,
                comparison,
                threshold_value,
                threshold_unit,
                severity,
                response_action,
                parent_enabled,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["template_id"],
                data["name"],
                data["enabled"],
                data["domain_type"],
                data["target_cidr"],
                data["src_cidr"],
                data["dst_cidr"],
                data["src_port"],
                data["dst_port"],
                data["protocol"],
                data["src_asn"],
                data["dst_asn"],
                data["tcp_flags"],
                data["window_seconds"],
                data["sensor_id"],
                data["interface_if_index"],
                data["direction"],
                data["decoder"],
                data["comparison"],
                data["threshold_value"],
                data["threshold_unit"],
                data["severity"],
                data["response_action"],
                data["parent_enabled"],
                now,
                now,
            ),
        )
        conn.commit()
        return fetch_attack_vector(conn, int(cursor.lastrowid))


@app.post("/api/attack-vectors/{vector_id}/test")
def test_attack_vector(
    request: Request,
    vector_id: int,
    payload: AttackVectorTestPayload | None = None,
    lookback_seconds: int | None = Query(None, ge=1, le=86400),
    min_duration_seconds: int | None = Query(None, ge=0, le=86400),
):
    require_admin(request)
    ensure_sensor_db()
    payload = payload or AttackVectorTestPayload()
    try:
        default_lookback = int(os.getenv("GMJFLOW_ANOMALY_LOOKBACK_SECONDS", "60"))
    except ValueError:
        default_lookback = 60
    effective_min_duration = anomaly_min_duration_seconds(
        min_duration_seconds if min_duration_seconds is not None else payload.min_duration_seconds
    )
    with sqlite_connection() as conn:
        vector = fetch_attack_vector(conn, vector_id)
    effective_lookback = lookback_seconds or payload.lookback_seconds or vector.get("window_seconds") or default_lookback
    return attack_vector_test_result(
        vector,
        max(int(effective_lookback), 1),
        effective_min_duration,
    )


@app.put("/api/attack-vectors/{vector_id}")
def update_attack_vector(request: Request, vector_id: int, payload: AttackVectorPayload):
    require_admin(request)
    ensure_sensor_db()
    now = utc_now_iso()
    with sqlite_connection() as conn:
        _ = fetch_attack_vector(conn, vector_id)
        data = normalize_attack_vector_payload(conn, payload)
        conn.execute(
            """
            UPDATE attack_vectors
            SET template_id = ?,
                name = ?,
                enabled = ?,
                domain_type = ?,
                target_cidr = ?,
                src_cidr = ?,
                dst_cidr = ?,
                src_port = ?,
                dst_port = ?,
                protocol = ?,
                src_asn = ?,
                dst_asn = ?,
                tcp_flags = ?,
                window_seconds = ?,
                sensor_id = ?,
                interface_if_index = ?,
                direction = ?,
                decoder = ?,
                comparison = ?,
                threshold_value = ?,
                threshold_unit = ?,
                severity = ?,
                response_action = ?,
                parent_enabled = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                data["template_id"],
                data["name"],
                data["enabled"],
                data["domain_type"],
                data["target_cidr"],
                data["src_cidr"],
                data["dst_cidr"],
                data["src_port"],
                data["dst_port"],
                data["protocol"],
                data["src_asn"],
                data["dst_asn"],
                data["tcp_flags"],
                data["window_seconds"],
                data["sensor_id"],
                data["interface_if_index"],
                data["direction"],
                data["decoder"],
                data["comparison"],
                data["threshold_value"],
                data["threshold_unit"],
                data["severity"],
                data["response_action"],
                data["parent_enabled"],
                now,
                vector_id,
            ),
        )
        conn.commit()
        return fetch_attack_vector(conn, vector_id)


@app.delete("/api/attack-vectors/{vector_id}")
def delete_attack_vector(request: Request, vector_id: int):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        _ = fetch_attack_vector(conn, vector_id)
        conn.execute("DELETE FROM attack_vectors WHERE id = ?", (vector_id,))
        conn.commit()
    return {"ok": True}


@app.post("/api/attack-vectors/{vector_id}/duplicate", status_code=201)
def duplicate_attack_vector(request: Request, vector_id: int):
    require_admin(request)
    ensure_sensor_db()
    now = utc_now_iso()
    with sqlite_connection() as conn:
        vector = fetch_attack_vector(conn, vector_id)
        cursor = conn.execute(
            """
            INSERT INTO attack_vectors (
                template_id,
                name,
                enabled,
                domain_type,
                target_cidr,
                src_cidr,
                dst_cidr,
                src_port,
                dst_port,
                protocol,
                src_asn,
                dst_asn,
                tcp_flags,
                window_seconds,
                sensor_id,
                interface_if_index,
                direction,
                decoder,
                comparison,
                threshold_value,
                threshold_unit,
                severity,
                response_action,
                parent_enabled,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                vector["template_id"],
                f"{vector['name']} (copia)",
                1 if vector["enabled"] else 0,
                vector["domain_type"],
                vector["target_cidr"],
                vector["src_cidr"],
                vector["dst_cidr"],
                vector["src_port"],
                vector["dst_port"],
                vector["protocol"],
                vector["src_asn"],
                vector["dst_asn"],
                vector["tcp_flags"],
                vector["window_seconds"],
                vector["sensor_id"],
                vector["interface_if_index"],
                vector["direction"],
                vector["decoder"],
                vector["comparison"],
                vector["threshold_value"],
                vector["threshold_unit"],
                vector["severity"],
                vector["response_action"],
                1 if vector["parent_enabled"] else 0,
                now,
                now,
            ),
        )
        conn.commit()
        return fetch_attack_vector(conn, int(cursor.lastrowid))


@app.post("/api/attack-vectors/learn")
def learn_attack_vectors(request: Request, payload: AttackVectorLearnPayload):
    require_admin(request)
    suggestions = learn_attack_vector_suggestions(payload)
    return {"ok": True, "items": suggestions, "count": len(suggestions)}


@app.get("/api/attack-vector-suggestions")
def list_attack_vector_suggestions(
    request: Request,
    template_id: int | None = Query(None, ge=1),
    unapplied_only: bool = True,
):
    require_admin(request)
    ensure_sensor_db()
    filters = []
    values: list[Any] = []
    if template_id is not None:
        filters.append("template_id = ?")
        values.append(template_id)
    if unapplied_only:
        filters.append("applied_at IS NULL")
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with sqlite_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT a.*, s.name AS sensor_name
            FROM attack_vector_suggestions a
            LEFT JOIN sensors s ON s.id = a.sensor_id
            {where}
            ORDER BY a.created_at DESC, a.id DESC
            LIMIT 500
            """,
            values,
        ).fetchall()
    return {"items": [attack_vector_suggestion_row_to_dict(row) for row in rows]}


@app.post("/api/attack-vector-suggestions/apply-all")
def apply_all_attack_vector_suggestions(
    request: Request,
    payload: AttackVectorSuggestionApplyAllPayload | None = None,
):
    require_admin(request)
    ensure_sensor_db()
    filters = ["applied_at IS NULL"]
    values: list[Any] = []
    template_id = payload.template_id if payload is not None else None
    if template_id is not None:
        filters.append("template_id = ?")
        values.append(template_id)
    with sqlite_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT id
            FROM attack_vector_suggestions
            WHERE {' AND '.join(filters)}
            ORDER BY id
            """,
            values,
        ).fetchall()
        vectors = [apply_attack_vector_suggestion(conn, int(row["id"])) for row in rows]
        conn.commit()
    return {"ok": True, "items": vectors, "count": len(vectors)}


@app.post("/api/attack-vector-suggestions/{suggestion_id}/apply")
def apply_attack_vector_suggestion_endpoint(request: Request, suggestion_id: int):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        vector = apply_attack_vector_suggestion(conn, suggestion_id)
        conn.commit()
    return vector


def severity_rank(value: Any) -> int:
    return {"info": 0, "warning": 1, "critical": 2}.get(clean_text(value).lower(), 0)


def consolidated_security_anomaly_id(key: tuple[Any, ...]) -> int:
    text = "|".join(clean_text(item) for item in key)
    return -int(zlib.crc32(text.encode("utf-8")) % 2_000_000_000 + 1)


def security_consolidation_key(item: dict[str, Any], include_status: bool = False) -> tuple[Any, ...]:
    key: tuple[Any, ...] = (
        item.get("zone_id") or 0,
        item.get("template_id") or 0,
        item.get("rule_id") or 0,
        clean_text(item.get("protocol") or "ALL"),
        clean_text(item.get("direction") or ""),
        clean_text(item.get("vector") or ""),
    )
    if include_status:
        key = (*key, clean_text(item.get("status") or "active"))
    return key


def consolidated_security_anomaly_groups(status_filter: str) -> list[dict[str, Any]]:
    status_where = "status = 'active'" if status_filter == "active" else "status <> 'active'"
    with sqlite_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM security_anomalies
            WHERE {status_where}
            ORDER BY last_seen DESC, updated_at DESC, id DESC
            """
        ).fetchall()
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        item = security_anomaly_row_to_dict(row)
        key = security_consolidation_key(item, include_status=status_filter != "active")
        group = groups.setdefault(key, {"key": key, "items": []})
        group["items"].append(item)
    consolidated: list[dict[str, Any]] = []
    for group in groups.values():
        items = group["items"]
        if not items:
            continue
        representative = max(items, key=lambda item: (severity_rank(item.get("severity")), float(item.get("packets_s") or 0), float(item.get("bits_s") or 0)))
        first_seen_values = [parse_datetime_text(item.get("first_seen")) for item in items]
        last_seen_values = [parse_datetime_text(item.get("last_seen")) for item in items]
        first_seen_values = [value for value in first_seen_values if value is not None]
        last_seen_values = [value for value in last_seen_values if value is not None]
        started_at = iso(min(first_seen_values)) if first_seen_values else clean_text(representative.get("created_at")) or utc_now_iso()
        last_seen_at = iso(max(last_seen_values)) if last_seen_values else clean_text(representative.get("updated_at")) or started_at
        status = clean_text(representative.get("status") or ("active" if status_filter == "active" else "closed"))
        peak_packets = max(float(item.get("packets_s") or 0) for item in items)
        peak_bits = max(float(item.get("bits_s") or 0) for item in items)
        peak_flows = max(float(item.get("flows_s") or item.get("flows") or 0) for item in items)
        if peak_packets > 0:
            metric_unit = "packets_s"
            peak_value = peak_packets
            observed_value = sum(float(item.get("packets_s") or 0) for item in items)
        elif peak_bits > 0:
            metric_unit = "bits_s"
            peak_value = peak_bits
            observed_value = sum(float(item.get("bits_s") or 0) for item in items)
        else:
            metric_unit = "flows_s"
            peak_value = peak_flows
            observed_value = sum(float(item.get("flows_s") or item.get("flows") or 0) for item in items)
        src_ips = {clean_ip(item.get("src_ip")) for item in items if clean_text(item.get("src_ip"))}
        dst_ips = {clean_ip(item.get("dst_ip")) for item in items if clean_text(item.get("dst_ip"))}
        zone_name = clean_text(representative.get("zone_name")) or "IP Zone"
        decoder = clean_text(representative.get("protocol")) or "ALL"
        vector = clean_text(representative.get("vector")) or clean_text(representative.get("template_name")) or "Deteccao IP Zone"
        affected_count = len(src_ips or dst_ips) or len(items)
        summary = f"{decoder} detectado em {affected_count} IPs da zona {zone_name}"
        event = {
            "id": consolidated_security_anomaly_id(group["key"]),
            "source": "security_anomalies",
            "security_anomaly_ids": [int(item["id"]) for item in items],
            "attack_vector_id": None,
            "attack_vector_name": vector,
            "sensor_id": None,
            "sensor_name": "Deteccoes IP Zone",
            "interface_if_index": None,
            "target_ip": representative.get("dst_ip") or representative.get("src_ip") or "",
            "target_cidr": representative.get("prefix_cidr") or "",
            "direction": clean_text(representative.get("direction")) or "-",
            "decoder": decoder,
            "severity": max((clean_text(item.get("severity")) or "info" for item in items), key=severity_rank),
            "metric_unit": metric_unit,
            "threshold_value": 0.0,
            "observed_value": observed_value,
            "peak_value": peak_value,
            "started_at": started_at,
            "last_seen_at": last_seen_at,
            "ended_at": None if status == "active" else last_seen_at,
            "status": status,
            "estimated_bytes": int(sum(float(item.get("bytes") or 0) for item in items)),
            "estimated_packets": int(sum(float(item.get("packets") or 0) for item in items)),
            "flow_count": int(sum(float(item.get("flows") or 0) for item in items)),
            "summary": summary,
            "created_at": min((clean_text(item.get("created_at")) for item in items if clean_text(item.get("created_at"))), default=started_at),
            "updated_at": max((clean_text(item.get("updated_at")) for item in items if clean_text(item.get("updated_at"))), default=last_seen_at),
            "detail_count": len(items),
            "unique_src_ips": len(src_ips),
            "unique_dst_ips": len(dst_ips),
        }
        consolidated.append({"event": event, "items": items, "key": group["key"]})
    return consolidated


def anomaly_list(status_filter: str, limit: int) -> list[dict[str, Any]]:
    ensure_sensor_db()
    if status_filter == "active":
        where = "e.status = 'active'"
    else:
        where = "e.status <> 'active'"
    with sqlite_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT
                e.*,
                v.name AS attack_vector_name,
                s.name AS sensor_name
            FROM anomaly_events e
            LEFT JOIN attack_vectors v ON v.id = e.attack_vector_id
            LEFT JOIN sensors s ON s.id = e.sensor_id
            WHERE {where}
            ORDER BY e.last_seen_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    items = [anomaly_event_row_to_dict(row) for row in rows]
    items.extend(group["event"] for group in consolidated_security_anomaly_groups(status_filter))
    return sorted(items, key=lambda item: parse_datetime_text(item.get("last_seen_at")) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)[:limit]


@app.get("/api/anomalies/summary")
def anomaly_summary_endpoint(request: Request):
    require_admin(request)
    ensure_sensor_db()
    with sqlite_connection() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS active_count,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN severity = 'warning' THEN 1 ELSE 0 END) AS warning_count
            FROM anomaly_events
            WHERE status = 'active'
            """
        ).fetchone()
    consolidated = [group["event"] for group in consolidated_security_anomaly_groups("active")]
    return {
        "active_count": int(row["active_count"] or 0) + len(consolidated),
        "critical_count": int(row["critical_count"] or 0) + sum(1 for item in consolidated if item.get("severity") == "critical"),
        "warning_count": int(row["warning_count"] or 0) + sum(1 for item in consolidated if item.get("severity") == "warning"),
        "security_consolidated_count": len(consolidated),
    }


@app.get("/api/anomalies/active")
def active_anomalies(request: Request, limit: int = Query(200, ge=1, le=1000)):
    require_admin(request)
    return {"items": anomaly_list("active", limit)}


@app.get("/api/anomalies/history")
def anomaly_history(request: Request, limit: int = Query(200, ge=1, le=1000)):
    require_admin(request)
    return {"items": anomaly_list("history", limit)}


@app.get("/api/anomalies/{event_id}")
def anomaly_detail(request: Request, event_id: int):
    require_admin(request)
    ensure_sensor_db()
    if event_id < 0:
        group = next(
            (
                item
                for status_filter in ("active", "history")
                for item in consolidated_security_anomaly_groups(status_filter)
                if int(item["event"]["id"]) == event_id
            ),
            None,
        )
        if group is None:
            raise HTTPException(status_code=404, detail="Anomalia nao encontrada")
        event = group["event"]
        details = group["items"]
        conversations = {}
        points_by_time: dict[str, dict[str, Any]] = {}
        for item in details:
            key = f"{item.get('src_ip') or '-'} -> {item.get('dst_ip') or '-'} {item.get('protocol') or 'ALL'}"
            conversation = conversations.setdefault(
                key,
                {"conversation": key, "bytes": 0, "packets": 0, "flow_count": 0},
            )
            conversation["bytes"] += int(float(item.get("bytes") or 0))
            conversation["packets"] += int(float(item.get("packets") or 0))
            conversation["flow_count"] += int(float(item.get("flows") or 0))
            minute = clean_text(item.get("last_seen") or item.get("updated_at"))[:16]
            point = points_by_time.setdefault(minute, {"time": minute, "bits_s": 0.0, "packets_s": 0.0, "flows_s": 0.0})
            point["bits_s"] += float(item.get("bits_s") or 0)
            point["packets_s"] += float(item.get("packets_s") or 0)
            point["flows_s"] += float(item.get("flows_s") or item.get("flows") or 0)
        return {
            "event": event,
            "flows": [
                {
                    **item,
                    "flow_time": item.get("last_seen") or item.get("updated_at") or item.get("created_at"),
                    "src_port": 0,
                    "dst_port": 0,
                    "proto_name": item.get("protocol") or "ALL",
                }
                for item in details
            ],
            "security_anomalies": details,
            "top_conversations": sorted(conversations.values(), key=lambda item: item["bytes"], reverse=True)[:20],
            "metric_points": sorted(points_by_time.values(), key=lambda item: item["time"]),
        }
    with sqlite_connection() as conn:
        row = conn.execute(
            """
            SELECT
                e.*,
                v.name AS attack_vector_name,
                s.name AS sensor_name
            FROM anomaly_events e
            LEFT JOIN attack_vectors v ON v.id = e.attack_vector_id
            LEFT JOIN sensors s ON s.id = e.sensor_id
            WHERE e.id = ?
            """,
            (event_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Anomalia nao encontrada")
        event = anomaly_event_row_to_dict(row)
        flow_rows = conn.execute(
            """
            SELECT *
            FROM anomaly_event_flows
            WHERE anomaly_event_id = ?
            ORDER BY bytes DESC, flow_time DESC
            LIMIT 200
            """,
            (event_id,),
        ).fetchall()
    flows = []
    conversations: dict[str, dict[str, Any]] = {}
    points_by_minute: dict[str, dict[str, Any]] = {}
    for row in flow_rows:
        flow = dict(row)
        flow["src_ip"] = clean_ip(flow.get("src_ip"))
        flow["dst_ip"] = clean_ip(flow.get("dst_ip"))
        flow["exporter_ip"] = clean_ip(flow.get("exporter_ip"))
        flow["proto_name"] = proto_name(flow.get("proto"))
        flow["decoder"] = classify_flow_decoder(flow)
        flows.append(flow)
        key = f"{flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} {flow['proto_name']}"
        item = conversations.setdefault(
            key,
            {"conversation": key, "bytes": 0, "packets": 0, "flow_count": 0},
        )
        item["bytes"] += int(flow.get("bytes") or 0)
        item["packets"] += int(flow.get("packets") or 0)
        item["flow_count"] += int(flow.get("flow_count") or 0)
        minute = clean_text(flow.get("flow_time"))[:16]
        point = points_by_minute.setdefault(minute, {"time": minute, "bytes": 0, "packets": 0, "flow_count": 0})
        point["bytes"] += int(flow.get("bytes") or 0)
        point["packets"] += int(flow.get("packets") or 0)
        point["flow_count"] += int(flow.get("flow_count") or 0)
    top_conversations = sorted(conversations.values(), key=lambda item: item["bytes"], reverse=True)[:20]
    metric_points = []
    for point in sorted(points_by_minute.values(), key=lambda item: item["time"]):
        metric_points.append(
            {
                "time": point["time"],
                "bits_s": point["bytes"] * 8 / 60,
                "packets_s": point["packets"] / 60,
                "flows_s": point["flow_count"] / 60,
            }
        )
    return {
        "event": event,
        "flows": flows,
        "top_conversations": top_conversations,
        "metric_points": metric_points,
    }


@app.post("/api/anomalies/{event_id}/ack")
def acknowledge_anomaly(request: Request, event_id: int):
    require_admin(request)
    ensure_sensor_db()
    now = utc_now_iso()
    if event_id < 0:
        group = next(
            (
                item
                for status_filter in ("active", "history")
                for item in consolidated_security_anomaly_groups(status_filter)
                if int(item["event"]["id"]) == event_id
            ),
            None,
        )
        if group is None:
            raise HTTPException(status_code=404, detail="Anomalia nao encontrada")
        ids = [int(item["id"]) for item in group["items"]]
        with sqlite_connection() as conn:
            placeholders = ",".join("?" for _ in ids)
            conn.execute(
                f"UPDATE security_anomalies SET status = 'acknowledged', updated_at = ? WHERE id IN ({placeholders})",
                [now, *ids],
            )
            conn.commit()
        return {"ok": True}
    with sqlite_connection() as conn:
        row = conn.execute("SELECT id FROM anomaly_events WHERE id = ?", (event_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Anomalia nao encontrada")
        conn.execute(
            """
            UPDATE anomaly_events
            SET status = 'acknowledged',
                ended_at = COALESCE(ended_at, ?),
                updated_at = ?
            WHERE id = ?
            """,
            (now, now, event_id),
        )
        conn.commit()
    return {"ok": True}


@app.post("/api/anomalies/{event_id}/close")
def close_anomaly(request: Request, event_id: int):
    require_admin(request)
    ensure_sensor_db()
    now = utc_now_iso()
    if event_id < 0:
        group = next(
            (
                item
                for status_filter in ("active", "history")
                for item in consolidated_security_anomaly_groups(status_filter)
                if int(item["event"]["id"]) == event_id
            ),
            None,
        )
        if group is None:
            raise HTTPException(status_code=404, detail="Anomalia nao encontrada")
        ids = [int(item["id"]) for item in group["items"]]
        with sqlite_connection() as conn:
            placeholders = ",".join("?" for _ in ids)
            conn.execute(
                f"UPDATE security_anomalies SET status = 'closed', updated_at = ? WHERE id IN ({placeholders})",
                [now, *ids],
            )
            conn.commit()
        return {"ok": True}
    with sqlite_connection() as conn:
        row = conn.execute("SELECT id FROM anomaly_events WHERE id = ?", (event_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Anomalia nao encontrada")
        conn.execute(
            """
            UPDATE anomaly_events
            SET status = 'ended',
                ended_at = COALESCE(ended_at, ?),
                updated_at = ?
            WHERE id = ?
            """,
            (now, now, event_id),
        )
        conn.commit()
    return {"ok": True}


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


def pmacct_state_dir() -> Path:
    return Path(os.getenv("PMACCT_STATE_DIR", "/var/spool/pmacct/state"))


def pmacct_spool_dir() -> Path:
    return Path(os.getenv("PMACCT_SPOOL_DIR", "/var/spool/pmacct"))


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def pmacct_status_for_file(output_file: str) -> dict[str, Any]:
    output_path = Path(output_file)
    state_dir = pmacct_state_dir()
    status_path = state_dir / f"{output_path.name}.status.json"
    offset_path = state_dir / f"{output_path.name}.offset.json"
    status = read_json_object(status_path)
    checkpoint = read_json_object(offset_path)
    payload = {**checkpoint, **status}
    payload["file"] = clean_text(payload.get("file")) or str(output_path)
    status_issue = ""
    if output_path.exists():
        try:
            stat = output_path.stat()
            offset = int(payload.get("offset") or 0)
            payload["file_size_mb"] = round(stat.st_size / 1024 / 1024, 3)
            payload["inode"] = getattr(stat, "st_ino", 0)
            payload["lag_bytes"] = max(0, stat.st_size - offset)
        except OSError as exc:
            status_issue = f"spool stat failed: {exc}"
    elif not pmacct_spool_dir().exists():
        status_issue = "spool volume not mounted in backend"
    else:
        status_issue = "spool csv not found in backend"
    if not status and checkpoint:
        payload["parser_status"] = "checkpoint sem status"
    elif not status and not checkpoint:
        payload["parser_status"] = status_issue or "sem status"
    if status_issue:
        payload["status_issue"] = status_issue
        payload["last_error"] = clean_text(payload.get("last_error")) or status_issue
    return payload


def pmacct_output_file_from_state_name(path: Path) -> str:
    name = path.name
    if name.endswith(".status.json"):
        name = name[: -len(".status.json")]
    elif name.endswith(".offset.json"):
        name = name[: -len(".offset.json")]
    return str(pmacct_spool_dir() / name)


@app.get("/api/collectors/ingestion/status")
def collectors_ingestion_status(request: Request):
    require_admin(request)
    ensure_sensor_db()
    items = []
    with sqlite_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, name, listener_port, exporter_ip
            FROM sensors
            WHERE active = 1 AND flow_collector_enabled = 1
            ORDER BY id
            """
        ).fetchall()
    seen_files = set()
    for row in rows:
        output_file = f"/var/spool/pmacct/sensor-{int(row['id'])}-{int(row['listener_port'])}.csv"
        status = pmacct_status_for_file(output_file)
        seen_files.add(output_file)
        file_size_mb = status.get("file_size_mb")
        offset = int(status.get("offset") or 0)
        inode = int(status.get("inode") or 0)
        lag_bytes = int(status.get("lag_bytes") or 0)
        items.append(
            {
                "sensor_id": int(row["id"]),
                "sensor": row["name"],
                "exporter_ip": row["exporter_ip"],
                "file": status.get("file") or output_file,
                "file_size_mb": file_size_mb if file_size_mb is not None else 0,
                "rotate_max_mb": status.get("rotate_max_mb"),
                "offset": offset,
                "inode": inode,
                "lag_bytes": lag_bytes,
                "last_line_ts": status.get("last_line_ts") or "",
                "last_insert_at": status.get("last_insert_at") or "",
                "last_flow_time": status.get("last_flow_time") or "",
                "rows_read_last_cycle": int(status.get("rows_read_last_cycle") or 0),
                "rows_inserted_last_cycle": int(status.get("rows_inserted_last_cycle") or 0),
                "rows_skipped_last_cycle": int(status.get("rows_skipped_last_cycle") or 0),
                "parser_status": status.get("parser_status") or "sem status",
                "status_issue": status.get("status_issue") or "",
                "last_error": status.get("last_error") or "",
                "last_rotation": status.get("last_rotation"),
                "updated_at": status.get("updated_at") or "",
            }
        )
    state_paths = []
    if pmacct_state_dir().exists():
        state_paths.extend(pmacct_state_dir().glob("*.status.json"))
        state_paths.extend(pmacct_state_dir().glob("*.offset.json"))
    for status_path in state_paths:
        output_file = pmacct_output_file_from_state_name(status_path)
        if not output_file or output_file in seen_files:
            continue
        seen_files.add(output_file)
        status = pmacct_status_for_file(output_file)
        items.append(
            {
                "sensor_id": None,
                "sensor": status.get("sensor") or Path(output_file).stem,
                "exporter_ip": status.get("exporter_ip") or "",
                "file": output_file,
                "file_size_mb": status.get("file_size_mb") or 0,
                "rotate_max_mb": status.get("rotate_max_mb"),
                "offset": int(status.get("offset") or 0),
                "inode": int(status.get("inode") or 0),
                "lag_bytes": int(status.get("lag_bytes") or 0),
                "last_line_ts": status.get("last_line_ts") or "",
                "last_insert_at": status.get("last_insert_at") or "",
                "last_flow_time": status.get("last_flow_time") or "",
                "rows_read_last_cycle": int(status.get("rows_read_last_cycle") or 0),
                "rows_inserted_last_cycle": int(status.get("rows_inserted_last_cycle") or 0),
                "rows_skipped_last_cycle": int(status.get("rows_skipped_last_cycle") or 0),
                "parser_status": status.get("parser_status") or "ok",
                "status_issue": status.get("status_issue") or "",
                "last_error": status.get("last_error") or "",
                "last_rotation": status.get("last_rotation"),
                "updated_at": status.get("updated_at") or "",
            }
        )
    return {"items": items}


@app.get("/api/database/status")
def database_status(request: Request):
    require_admin(request)
    settings = {key: value for key, value in SYSTEM_SETTING_DEFAULTS.items()}
    sqlite_ok = False
    clickhouse_ok = False
    flow_summary = {"flow_count": 0, "oldest_flow_time": None, "newest_flow_time": None}
    size_summary = {
        "flow_raw_size_bytes": 0,
        "flow_1m_size_bytes": 0,
        "flow_tops_1m_size_bytes": 0,
        "clickhouse_database_size_bytes": 0,
    }

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
    flow_raw_retention_days = table_retention_days(settings, "flow_raw") or 7
    flow_1m_retention_days = table_retention_days(settings, "flow_1m") or 30
    flow_tops_1m_retention_days = table_retention_days(settings, "flow_tops_1m") or 15
    retention_days = flow_raw_retention_days
    snmp_retention_days = setting_int(settings, "snmp_retention_days", 90)
    return {
        "clickhouse_ok": clickhouse_ok,
        "sqlite_ok": sqlite_ok,
        "flow_count": flow_summary["flow_count"],
        "oldest_flow_time": flow_summary["oldest_flow_time"],
        "newest_flow_time": flow_summary["newest_flow_time"],
        "flow_raw_size_bytes": size_summary["flow_raw_size_bytes"],
        "flow_raw_size_human": human_bytes(size_summary["flow_raw_size_bytes"]),
        "flow_1m_size_bytes": size_summary["flow_1m_size_bytes"],
        "flow_1m_size_human": human_bytes(size_summary["flow_1m_size_bytes"]),
        "flow_tops_1m_size_bytes": size_summary["flow_tops_1m_size_bytes"],
        "flow_tops_1m_size_human": human_bytes(size_summary["flow_tops_1m_size_bytes"]),
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
        "flow_raw_retention_days": flow_raw_retention_days,
        "flow_1m_retention_days": flow_1m_retention_days,
        "flow_tops_1m_retention_days": flow_tops_1m_retention_days,
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
    flow_raw_days = payload.flow_raw_retention_days or payload.retention_days
    flow_1m_days = payload.flow_1m_retention_days or 30
    flow_tops_days = payload.flow_tops_1m_retention_days or 15
    snmp_days = payload.snmp_retention_days or 90
    cleanup_hour = 3 if payload.cleanup_hour is None else payload.cleanup_hour
    try:
        ttl_command = apply_flow_retention_ttl(payload.enabled, flow_raw_days, flow_1m_days, flow_tops_days)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Falha ao atualizar TTL no ClickHouse: {exc}") from exc

    ensure_sensor_db()
    with sqlite_connection() as conn:
        set_system_settings(
            conn,
            {
                "database_retention_enabled": "1" if payload.enabled else "0",
                "flow_retention_days": flow_raw_days,
                "flow_raw_retention_days": flow_raw_days,
                "flow_1m_retention_days": flow_1m_days,
                "flow_tops_1m_retention_days": flow_tops_days,
                "snmp_retention_days": snmp_days,
                "database_cleanup_hour": cleanup_hour,
            },
        )
        conn.commit()
        settings = get_system_settings(conn)
    return {
        "ok": True,
        "retention_enabled": setting_bool(settings, "database_retention_enabled"),
        "retention_days": table_retention_days(settings, "flow_raw") or 7,
        "flow_raw_retention_days": table_retention_days(settings, "flow_raw") or 7,
        "flow_1m_retention_days": table_retention_days(settings, "flow_1m") or 30,
        "flow_tops_1m_retention_days": table_retention_days(settings, "flow_tops_1m") or 15,
        "snmp_retention_days": setting_int(settings, "snmp_retention_days", 90),
        "database_cleanup_hour": setting_int(settings, "database_cleanup_hour", 3, 0, 23),
        "ttl_command": ttl_command,
    }


@app.post("/api/database/cleanup")
def database_cleanup(request: Request, payload: DatabaseCleanupPayload):
    require_admin(request)
    if clean_text(payload.confirm).strip() != "LIMPAR":
        raise HTTPException(status_code=400, detail="Digite LIMPAR no campo de confirmacao para executar a limpeza.")
    try:
        result = run_database_cleanup(
            flow_retention_days=payload.flow_raw_older_than_days or payload.older_than_days,
            flow_1m_retention_days=payload.flow_1m_older_than_days or payload.older_than_days,
            flow_tops_1m_retention_days=payload.flow_tops_1m_older_than_days or payload.older_than_days,
            snmp_retention_days=payload.older_than_days if clean_text(payload.scope).lower() == "all" else None,
            optimize=payload.optimize,
            source="manual",
            scope=payload.scope,
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


def rdap_autnum_urls(asn: int) -> list[str]:
    number = int(asn)
    return [
        f"https://rdap.org/autnum/{number}",
        f"https://rdap.arin.net/registry/autnum/{number}",
        f"https://rdap.lacnic.net/rdap/autnum/{number}",
        f"https://rdap.db.ripe.net/autnum/{number}",
        f"https://rdap.apnic.net/autnum/{number}",
        f"https://rdap.afrinic.net/rdap/autnum/{number}",
    ]


def resolve_asn_number(asn: int) -> dict[str, Any] | None:
    number = int(asn or 0)
    if number <= 0:
        return None
    last_error = ""
    for url in rdap_autnum_urls(number):
        try:
            data = fetch_json_url(url, timeout=ASN_RESOLVER_TIMEOUT_SECONDS)
        except Exception as exc:
            last_error = clean_text(exc)
            continue
        name = clean_text(data.get("name")) or clean_text(data.get("handle"))
        entities = rdap_entities(data)
        org_name = rdap_organization(name, entities)
        country = clean_text(data.get("country")).upper()
        if not country:
            for entity in data.get("entities") or []:
                if not isinstance(entity, dict):
                    continue
                for value in vcard_values(entity, "adr"):
                    tokens = [token.strip() for token in re.split(r"[,\n]", value) if token.strip()]
                    if tokens:
                        maybe_country = tokens[-1]
                        if 2 <= len(maybe_country) <= 3:
                            country = maybe_country.upper()
                            break
                if country:
                    break
        return {
            "asn": number,
            "as_name": name or org_name,
            "org_name": org_name,
            "country": country,
            "source": "rdap",
            "raw_json": data,
            "last_error": "",
        }
    return {
        "asn": number,
        "as_name": "",
        "org_name": "",
        "country": "",
        "source": "rdap",
        "raw_json": None,
        "last_error": last_error or "ASN nao resolvido via RDAP",
    }


def parse_cymru_response(payload: str) -> list[dict[str, Any]]:
    items = []
    for line in payload.splitlines():
        if "|" not in line or line.strip().lower().startswith("as "):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 7:
            continue
        try:
            asn = int(parts[0])
        except ValueError:
            continue
        ip_text = clean_text(parts[1])
        prefix = clean_text(parts[2])
        country = clean_text(parts[3]).upper()
        registry = clean_text(parts[4])
        as_name = clean_text(parts[6])
        if not ip_text or asn <= 0:
            continue
        items.append(
            {
                "ip": ip_text,
                "asn": asn,
                "prefix": prefix,
                "country": country,
                "as_name": as_name,
                "source": f"cymru-{registry}".strip("-"),
            }
        )
    return items


def resolve_ips_to_asn(ips: list[str]) -> list[dict[str, Any]]:
    public_ips = []
    seen = set()
    for ip_text in ips:
        cleaned = clean_ip(ip_text)
        if cleaned in seen:
            continue
        try:
            if not is_public_ip(cleaned):
                continue
        except ValueError:
            continue
        seen.add(cleaned)
        public_ips.append(cleaned)
    if not public_ips:
        return []
    query = "begin\nverbose\n" + "\n".join(public_ips) + "\nend\n"
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=ASN_RESOLVER_TIMEOUT_SECONDS) as sock:
            sock.settimeout(ASN_RESOLVER_TIMEOUT_SECONDS)
            sock.sendall(query.encode("ascii", errors="ignore"))
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        payload = b"".join(chunks).decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Falha ao resolver ASN em lote via Team Cymru: %s", exc)
        return []
    return parse_cymru_response(payload)


def asn_queue_from_flows(
    lookback_minutes: int,
    limit: int,
    sensor_id: int | None = None,
    interface: int | None = None,
    if_index: int | None = None,
) -> dict[str, Any]:
    ensure_clickhouse_schema()
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(minutes=lookback_minutes)
    selected_if_index = if_index if if_index is not None else interface
    params: dict[str, Any] = {"limit": limit}
    exporter_ip = sensor_exporter_ip(sensor_id) if sensor_id is not None else None
    where = raw_flow_where(start_dt, end_dt, None, params, exporter_ip, selected_if_index)
    asn_candidates: list[tuple[int, int]] = []
    for asn_field in ("src_asn", "dst_asn"):
        result = query_clickhouse(
            f"""
            SELECT toUInt32({asn_field}) AS asn, sum(bytes) AS bytes
            FROM flow_raw
            WHERE {where} AND {asn_field} > 0
            GROUP BY asn
            ORDER BY bytes DESC
            LIMIT {{limit:UInt32}}
            """,
            params,
        )
        asn_candidates.extend((int(row["asn"] or 0), int(row["bytes"] or 0)) for row in rows_as_dicts(result))
    candidates: list[tuple[str, int]] = []
    for ip_field, asn_field in (("src_ip", "src_asn"), ("dst_ip", "dst_asn")):
        result = query_clickhouse(
            f"""
            SELECT toString({ip_field}) AS ip, sum(bytes) AS bytes
            FROM flow_raw
            WHERE {where} AND {asn_field} = 0
            GROUP BY ip
            ORDER BY bytes DESC
            LIMIT {{limit:UInt32}}
            """,
            params,
        )
        candidates.extend((clean_ip(row["ip"]), int(row["bytes"] or 0)) for row in rows_as_dicts(result))

    queued = 0
    queued_asns = 0
    skipped = 0
    skipped_asns = 0
    errors: list[str] = []
    seen: set[str] = set()
    seen_asns: set[int] = set()
    with sqlite_connection() as conn:
        ensure_asn_db(conn)
        for asn, _bytes in sorted(asn_candidates, key=lambda item: item[1], reverse=True):
            if asn <= 0 or asn in seen_asns or len(seen_asns) >= limit:
                continue
            seen_asns.add(asn)
            info = conn.execute(
                """
                SELECT asn, as_name, org_name, expires_at
                FROM asn_info
                WHERE asn = ?
                """,
                (asn,),
            ).fetchone()
            if info and (clean_text(info["as_name"]) or clean_text(info["org_name"])):
                skipped_asns += 1
                continue
            if queue_asn_info_resolution(conn, asn, priority=20):
                queued_asns += 1
        for ip_text, _bytes in sorted(candidates, key=lambda item: item[1], reverse=True):
            if ip_text in seen or len(seen) >= limit:
                continue
            seen.add(ip_text)
            try:
                parsed = ip_address(ip_text)
                if not parsed.is_global:
                    skipped += 1
                    continue
                if lookup_asn_cache(ip_text) or lookup_asn_prefix(ip_text):
                    skipped += 1
                    continue
                if queue_asn_resolution(conn, ip_text):
                    queued += 1
            except Exception as exc:
                errors.append(f"{ip_text}: {exc}")
        conn.commit()
    return {
        "ok": True,
        "start": iso(start_dt),
        "end": iso(end_dt),
        "candidates": len(seen),
        "asn_candidates": len(seen_asns),
        "queued": queued,
        "queued_asns": queued_asns,
        "skipped": skipped,
        "skipped_asns": skipped_asns,
        "errors": errors,
    }


def process_asn_resolution_queue(limit: int, force: bool = False) -> dict[str, Any]:
    now = utc_now_iso()
    limit = max(1, min(int(limit or ASN_RESOLVER_BATCH_SIZE), 50000))
    result = {
        "ok": True,
        "items_processed": 0,
        "ips_processed": 0,
        "asns_processed": 0,
        "resolved": 0,
        "unresolved": 0,
        "failed": 0,
        "asn_info_updated": 0,
        "prefixes_inserted": 0,
        "cache_updated": 0,
        "errors": [],
    }
    with sqlite_connection() as conn:
        ensure_asn_db(conn)
        statuses = ("queued", "pending", "stale", "failed") if not force else ("queued", "pending", "stale", "resolved", "failed")
        placeholders = ", ".join("?" for _ in statuses)
        rows = conn.execute(
            f"""
            SELECT ip, asn, attempts
            FROM asn_resolution_queue
            WHERE status IN ({placeholders})
              AND (? = 1 OR attempts < ?)
            ORDER BY priority ASC, last_seen_at DESC
            LIMIT ?
            """,
            (*statuses, 1 if force else 0, ASN_RESOLVER_MAX_ATTEMPTS, limit),
        ).fetchall()

        unresolved_ips: list[str] = []
        for row in rows:
            key = clean_text(row["ip"])
            asn = int(row["asn"] or 0)
            if asn <= 0:
                match = re.match(r"^AS(\d+)$", key, flags=re.IGNORECASE)
                if match:
                    asn = int(match.group(1))
            if asn <= 0:
                continue
            result["items_processed"] += 1
            result["asns_processed"] += 1
            conn.execute(
                """
                UPDATE asn_resolution_queue
                SET status = 'resolving', attempts = attempts + 1, updated_at = ?
                WHERE ip = ?
                """,
                (now, key),
            )
            try:
                resolved_asn = resolve_asn_number(asn)
                if resolved_asn and (clean_text(resolved_asn.get("as_name")) or clean_text(resolved_asn.get("org_name"))):
                    upsert_asn_info(
                        conn,
                        asn,
                        clean_text(resolved_asn.get("as_name")),
                        clean_text(resolved_asn.get("country")),
                        clean_text(resolved_asn.get("source")) or "rdap",
                        clean_text(resolved_asn.get("org_name")),
                        resolved_asn.get("raw_json") if isinstance(resolved_asn.get("raw_json"), dict) else None,
                    )
                    conn.execute(
                        """
                        UPDATE asn_resolution_queue
                        SET status = 'resolved', updated_at = ?, resolved_at = ?, last_error = ''
                        WHERE ip = ?
                        """,
                        (now, now, key),
                    )
                    result["resolved"] += 1
                    result["asn_info_updated"] += 1
                else:
                    error = clean_text((resolved_asn or {}).get("last_error")) or "ASN sem descricao RDAP"
                    conn.execute(
                        """
                        UPDATE asn_resolution_queue
                        SET status = CASE WHEN attempts >= ? THEN 'failed' ELSE 'queued' END,
                            updated_at = ?,
                            last_error = ?
                        WHERE ip = ?
                        """,
                        (ASN_RESOLVER_MAX_ATTEMPTS, now, error, key),
                    )
                    result["failed"] += 1
                    result["errors"].append(f"AS{asn}: {error}")
            except Exception as exc:
                error = clean_text(exc)
                conn.execute(
                    """
                    UPDATE asn_resolution_queue
                    SET status = CASE WHEN attempts >= ? THEN 'failed' ELSE 'queued' END,
                        updated_at = ?,
                        last_error = ?
                    WHERE ip = ?
                    """,
                    (ASN_RESOLVER_MAX_ATTEMPTS, now, error, key),
                )
                result["failed"] += 1
                result["errors"].append(f"AS{asn}: {error}")

        for row in rows:
            if re.match(r"^AS\d+$", clean_text(row["ip"]), flags=re.IGNORECASE):
                continue
            ip_text = clean_ip(row["ip"])
            result["ips_processed"] += 1
            result["items_processed"] += 1
            try:
                resolved = lookup_asn_cache(ip_text) or lookup_asn_prefix(ip_text)
                if resolved and int(resolved.get("asn") or 0) > 0:
                    upsert_asn_lookup_cache(
                        conn,
                        ip_text,
                        int(resolved["asn"]),
                        resolved.get("prefix") or "",
                        resolved.get("as_name") or "",
                        resolved.get("country") or "",
                        resolved.get("source") or "local_prefix_db",
                    )
                    conn.execute(
                        """
                        UPDATE asn_resolution_queue
                        SET status = 'resolved', attempts = attempts + 1, updated_at = ?, resolved_at = ?, last_error = ''
                        WHERE ip = ?
                        """,
                        (now, now, ip_text),
                    )
                    result["resolved"] += 1
                    result["cache_updated"] += 1
                else:
                    unresolved_ips.append(ip_text)
            except Exception as exc:
                conn.execute(
                    """
                    UPDATE asn_resolution_queue
                    SET status = CASE WHEN attempts >= ? THEN 'failed' ELSE 'queued' END,
                        attempts = attempts + 1,
                        updated_at = ?,
                        last_error = ?
                    WHERE ip = ?
                    """,
                    (ASN_RESOLVER_MAX_ATTEMPTS, now, clean_text(exc), ip_text),
                )
                result["errors"].append(f"{ip_text}: {exc}")

        provider_items = resolve_ips_to_asn(unresolved_ips[:limit])
        provider_by_ip = {clean_ip(item.get("ip")): item for item in provider_items if clean_text(item.get("ip"))}
        for ip_text in unresolved_ips:
            item = provider_by_ip.get(ip_text)
            if item and int(item.get("asn") or 0) > 0:
                prefix = clean_text(item.get("prefix")) or asn_host_prefix(ip_text)
                upsert_asn_prefix(
                    conn,
                    prefix,
                    int(item["asn"]),
                    clean_text(item.get("as_name")),
                    clean_text(item.get("source")) or "provider",
                    clean_text(item.get("country")),
                )
                queue_asn_info_resolution(conn, int(item["asn"]), priority=60)
                upsert_asn_lookup_cache(
                    conn,
                    ip_text,
                    int(item["asn"]),
                    prefix,
                    clean_text(item.get("as_name")),
                    clean_text(item.get("country")),
                    clean_text(item.get("source")) or "provider",
                )
                conn.execute(
                    """
                    UPDATE asn_resolution_queue
                    SET status = 'resolved', attempts = attempts + 1, updated_at = ?, resolved_at = ?, last_error = ''
                    WHERE ip = ?
                    """,
                    (now, now, ip_text),
                )
                result["resolved"] += 1
                result["prefixes_inserted"] += 1
                result["cache_updated"] += 1
            else:
                conn.execute(
                    """
                    UPDATE asn_resolution_queue
                    SET status = CASE WHEN attempts >= ? THEN 'failed' ELSE 'queued' END,
                        attempts = attempts + 1,
                        updated_at = ?,
                        last_error = ?
                    WHERE ip = ?
                    """,
                    (ASN_RESOLVER_MAX_ATTEMPTS, now, "ASN ainda nao resolvido por base/cache local", ip_text),
                )
                result["unresolved"] += 1
        conn.commit()
    return result


def asn_resolver_loop() -> None:
    while not ASN_RESOLVER_STOP.is_set():
        try:
            process_asn_resolution_queue(ASN_RESOLVER_BATCH_SIZE, False)
        except Exception as exc:
            logger.warning("Falha no job de resolucao ASN: %s", exc)
        ASN_RESOLVER_STOP.wait(max(5, ASN_RESOLVER_INTERVAL_SECONDS))


def start_asn_resolver_thread() -> None:
    if not ASN_RESOLVER_ENABLED:
        return
    thread = threading.Thread(target=asn_resolver_loop, name="gmj-flow-asn-resolver", daemon=True)
    thread.start()


@app.get("/api/asn/status")
def asn_status():
    ensure_sensor_db()
    with sqlite_connection() as conn:
        ensure_asn_db(conn)
        prefixes = conn.execute("SELECT COUNT(*) AS count, MAX(updated_at) AS updated_at FROM asn_prefixes").fetchone()
        info = conn.execute("SELECT COUNT(*) AS count, MAX(updated_at) AS updated_at FROM asn_info").fetchone()
        cache = conn.execute("SELECT COUNT(*) AS count, MAX(resolved_at) AS updated_at FROM asn_lookup_cache").fetchone()
        pending = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM asn_resolution_queue
            WHERE status IN ('queued', 'pending', 'stale', 'resolving')
            """
        ).fetchone()
        queue_rows = conn.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM asn_resolution_queue
            GROUP BY status
            """
        ).fetchall()
        error_row = conn.execute(
            """
            SELECT last_error
            FROM asn_resolution_queue
            WHERE last_error <> ''
            ORDER BY updated_at DESC
            LIMIT 1
            """
        ).fetchone()
    queue_counts = {clean_text(row["status"]): int(row["count"] or 0) for row in queue_rows}
    last_update = max(
        clean_text(prefixes["updated_at"] if prefixes else ""),
        clean_text(info["updated_at"] if info else ""),
        clean_text(cache["updated_at"] if cache else ""),
    )
    return {
        "total_prefixes": int(prefixes["count"] or 0) if prefixes else 0,
        "total_asn_info": int(info["count"] or 0) if info else 0,
        "total_cache": int(cache["count"] or 0) if cache else 0,
        "total_pending": int(pending["count"] or 0) if pending else 0,
        "queued": queue_counts.get("queued", 0) + queue_counts.get("pending", 0) + queue_counts.get("stale", 0),
        "resolving": queue_counts.get("resolving", 0),
        "resolved": queue_counts.get("resolved", 0),
        "failed": queue_counts.get("failed", 0),
        "last_update": last_update,
        "last_error": clean_text(error_row["last_error"] if error_row else ""),
        "resolver_enabled": ASN_RESOLVER_ENABLED,
        "resolver_interval_seconds": ASN_RESOLVER_INTERVAL_SECONDS,
        "resolver_batch_size": ASN_RESOLVER_BATCH_SIZE,
        "resolver_max_attempts": ASN_RESOLVER_MAX_ATTEMPTS,
        "cache_ttl_days": ASN_CACHE_TTL_DAYS,
    }


@app.get("/api/asn/info")
def asn_info_endpoint(asns: str = Query(..., min_length=1)):
    ensure_sensor_db()
    numbers = []
    for token in re.split(r"[,;\s]+", clean_text(asns)):
        if not token:
            continue
        number_text = token.upper().removeprefix("AS")
        try:
            number = int(number_text)
        except ValueError:
            continue
        if number > 0 and number not in numbers:
            numbers.append(number)
    if not numbers:
        raise HTTPException(status_code=400, detail="Informe ao menos um ASN valido")
    items = []
    queued = 0
    with sqlite_connection() as conn:
        ensure_asn_db(conn)
        for number in numbers[:500]:
            info = lookup_asn_info(number)
            if info:
                items.append(info)
                continue
            if queue_asn_info_resolution(conn, number, priority=20):
                queued += 1
            items.append(
                {
                    "asn": number,
                    "as_name": "",
                    "org_name": "",
                    "country": "",
                    "source": "queued",
                    "updated_at": "",
                    "last_error": "",
                }
            )
        conn.commit()
    return {"items": items, "queued": queued}


@app.post("/api/asn/import")
def import_asn_prefixes(payload: AsnImportPayload):
    ensure_sensor_db()
    if not payload.items:
        raise HTTPException(status_code=400, detail="Nenhum prefixo informado")
    with sqlite_connection() as conn:
        ensure_asn_db(conn)
        for item in payload.items:
            upsert_asn_prefix(conn, item.prefix, item.asn, item.as_name, item.source, item.country)
        conn.commit()
    return {"ok": True, "imported": len(payload.items)}


@app.post("/api/asn/queue-from-flows")
def queue_asns_from_flows(payload: AsnQueueFromFlowsPayload):
    return asn_queue_from_flows(
        payload.lookback_minutes,
        payload.limit,
        payload.sensor_id,
        payload.interface,
        payload.if_index,
    )


@app.post("/api/asn/resolve")
def resolve_asn_queue(payload: AsnResolvePayload | None = None):
    item = payload or AsnResolvePayload()
    return process_asn_resolution_queue(item.limit, item.force)


@app.post("/api/asn/resolve-pending")
def resolve_pending_asns(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor: str | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    limit: int = Query(25, ge=1, le=200),
):
    start_dt, end_dt = resolve_requested_range(range_minutes, start, end, start_time, end_time)
    lookback = max(1, int((end_dt - start_dt).total_seconds() / 60))
    resolved_if_index = resolve_dashboard_if_index(sensor_id, interface_id, if_index)
    queue_result = asn_queue_from_flows(lookback, limit, sensor_id, resolved_if_index, resolved_if_index)
    resolve_result = process_asn_resolution_queue(limit, False)
    return {"ok": True, "queue": queue_result, **resolve_result, "resolved_count": resolve_result["resolved"]}


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


@app.put("/api/sensors/{sensor_id}/interfaces/{if_index}/sample-rate")
def update_interface_sample_rate(sensor_id: int, if_index: int, payload: InterfaceSampleRatePayload):
    ensure_sensor_db()
    with sqlite_connection() as conn:
        row = conn.execute(
            """
            SELECT id
            FROM sensor_interfaces
            WHERE sensor_id = ? AND if_index = ?
            ORDER BY id
            LIMIT 1
            """,
            (sensor_id, if_index),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Interface nao encontrada")
        conn.execute(
            """
            UPDATE sensor_interfaces
            SET sample_rate_in = ?,
                sample_rate_out = ?,
                sample_rate_override = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                payload.sample_rate_in,
                payload.sample_rate_out,
                1 if payload.sample_rate_override else 0,
                utc_now_iso(),
                row["id"],
            ),
        )
        conn.commit()
    detail = calibration_detail(sensor_id, if_index)
    detail["applied"] = True
    detail["sample_rate_in"] = payload.sample_rate_in
    detail["sample_rate_out"] = payload.sample_rate_out
    detail["sample_rate_override"] = payload.sample_rate_override
    return detail


@app.post("/api/sensors/{sensor_id}/sample-rate/apply-default-to-interfaces")
def apply_sensor_sample_rate_to_interfaces(
    sensor_id: int,
    payload: SensorSampleRateApplyPayload | None = None,
):
    requested_mode = clean_text(payload.mode).lower() if payload is not None else ""
    inherit = requested_mode != "copy" if requested_mode in {"inherit", "copy"} else (True if payload is None else bool(payload.inherit))
    ensure_sensor_db()
    with sqlite_connection() as conn:
        sensor = fetch_sensor_without_interfaces(conn, sensor_id)
        default_in = max(1, int(sensor.get("sample_rate_default_in") or 1))
        default_out = max(1, int(sensor.get("sample_rate_default_out") or 1))
        now = utc_now_iso()
        if inherit:
            cursor = conn.execute(
                """
                UPDATE sensor_interfaces
                SET sample_rate_override = 0,
                    updated_at = ?
                WHERE sensor_id = ?
                """,
                (now, sensor_id),
            )
        else:
            cursor = conn.execute(
                """
                UPDATE sensor_interfaces
                SET sample_rate_in = ?,
                    sample_rate_out = ?,
                    sample_rate_override = 1,
                    updated_at = ?
                WHERE sensor_id = ?
                """,
                (default_in, default_out, now, sensor_id),
            )
        conn.commit()
        rows = conn.execute(
            """
            SELECT *
            FROM sensor_interfaces
            WHERE sensor_id = ?
            ORDER BY if_index, id
            """,
            (sensor_id,),
        ).fetchall()
        items = [enrich_interface_metrics(conn, interface_dashboard_row_to_dict(row), sensor_id) for row in rows]
    return {
        "ok": True,
        "sensor_id": sensor_id,
        "inherit": inherit,
        "mode": "inherit" if inherit else "copy",
        "affected": int(cursor.rowcount or 0),
        "sample_rate_default_in": default_in,
        "sample_rate_default_out": default_out,
        "items": items,
    }


@app.get("/api/sensors/{sensor_id}/interfaces/{if_index}/diagnostics")
def interface_diagnostics(sensor_id: int, if_index: int):
    ensure_sensor_db()
    now = datetime.now(timezone.utc)
    start_5m = now - timedelta(minutes=5)
    start_10m = now - timedelta(minutes=10)
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
        item = enrich_interface_metrics(conn, interface_dashboard_row_to_dict(interface), sensor_id)

    exporter_ip = clean_text(sensor.get("exporter_ip"))
    if not exporter_ip:
        raise HTTPException(status_code=400, detail="Sensor sem exporter_ip configurado")
    params = {
        "exporter_ip": clickhouse_ip_string_param(exporter_ip, "exporter_ip"),
        "if_index": int(if_index),
        "start_5m": start_5m,
        "start_10m": start_10m,
        "end": now,
    }
    result = query_clickhouse(
        """
        SELECT
            max(flow_time) AS last_flow_time,
            countIf(flow_time >= {start_5m:DateTime}) AS flows_5m,
            countIf(flow_time >= {start_10m:DateTime}) AS flows_10m,
            min(sample_rate) AS min_sample_rate_detected,
            max(sample_rate) AS max_sample_rate_detected,
            any(flow_type) AS flow_type,
            sumIf(bytes, flow_time >= {start_5m:DateTime} AND input_if = {if_index:UInt32}) * 8 / 300 AS raw_in_bps_5m,
            sumIf(bytes, flow_time >= {start_5m:DateTime} AND output_if = {if_index:UInt32}) * 8 / 300 AS raw_out_bps_5m
        FROM flow_raw
        WHERE flow_time >= {start_10m:DateTime}
          AND flow_time <= {end:DateTime}
          AND toString(exporter_ip) = {exporter_ip:String}
          AND (input_if = {if_index:UInt32} OR output_if = {if_index:UInt32})
        """,
        params,
    )
    rows = rows_as_dicts(result)
    row = rows[0] if rows else {}
    detected_sample_rate = int(row.get("max_sample_rate_detected") or row.get("min_sample_rate_detected") or 1)
    sample_rate_in = get_effective_sample_rate(sensor_id, if_index, "input", detected_sample_rate)
    sample_rate_out = get_effective_sample_rate(sensor_id, if_index, "output", detected_sample_rate)
    raw_in_bps = float(row.get("raw_in_bps_5m") or 0)
    raw_out_bps = float(row.get("raw_out_bps_5m") or 0)
    corrected_in_bps = raw_in_bps * sample_rate_in
    corrected_out_bps = raw_out_bps * sample_rate_out
    snmp_in_bps = float(item.get("snmp_in_bps") or 0)
    snmp_out_bps = float(item.get("snmp_out_bps") or 0)
    return {
        "sensor_id": sensor_id,
        "sensor": sensor.get("name"),
        "exporter_ip": exporter_ip,
        "listener_port": sensor.get("listener_port"),
        "flow_version": sensor.get("flow_version"),
        "if_index": if_index,
        "interface": item,
        "sample_rate_configured": {
            "in": sample_rate_in,
            "out": sample_rate_out,
            "source": item.get("sample_rate_source") or "sensor",
        },
        "sample_rate_detected": {
            "min": int(row.get("min_sample_rate_detected") or 0),
            "max": int(row.get("max_sample_rate_detected") or 0),
        },
        "last_flow_time": iso(row["last_flow_time"]) if row.get("last_flow_time") else "",
        "flows_5m": int(row.get("flows_5m") or 0),
        "flows_10m": int(row.get("flows_10m") or 0),
        "raw_bps_5m": {"in": round(raw_in_bps, 2), "out": round(raw_out_bps, 2)},
        "corrected_bps_5m": {"in": round(corrected_in_bps, 2), "out": round(corrected_out_bps, 2)},
        "snmp_bps": {"in": round(snmp_in_bps, 2), "out": round(snmp_out_bps, 2)},
        "snmp_flow_factor": {
            "in": round(snmp_in_bps / raw_in_bps, 2) if raw_in_bps > 0 else 0,
            "out": round(snmp_out_bps / raw_out_bps, 2) if raw_out_bps > 0 else 0,
        },
        "confidence": item.get("calibration", {}).get("confidence") if item.get("calibration") else 0,
        "flow_type": clean_text(row.get("flow_type")),
    }


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


def sensor_sample_rate_config(sensor_id: int | None) -> dict[str, Any] | None:
    if sensor_id is None:
        return None
    ensure_sensor_db()
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
    mode = clean_text(sensor["sample_rate_mode"]) or "sensor_default"
    if mode not in SAMPLE_RATE_MODES:
        mode = "sensor_default"
    return {
        "default_in": max(1, int(sensor["sample_rate_default_in"] or 1)),
        "default_out": max(1, int(sensor["sample_rate_default_out"] or 1)),
        "mode": mode,
        "interfaces": interfaces,
    }


def effective_sample_rate_from_config(
    config: dict[str, Any] | None,
    if_index: int | None,
    direction: str,
    fallback: int = 1,
) -> int:
    if not config:
        return max(1, int(fallback or 1))
    direction_key = "out" if direction == "output" else "in"
    default_key = "default_out" if direction == "output" else "default_in"
    default_rate = max(1, int(config.get(default_key) or 1))
    interfaces = config.get("interfaces") if isinstance(config.get("interfaces"), dict) else {}
    interface = interfaces.get(int(if_index or 0))
    mode = clean_text(config.get("mode")) or "sensor_default"
    if interface and (interface.get("override") or mode == "per_interface"):
        return max(1, int(interface.get(direction_key) or default_rate))
    return default_rate


def get_effective_sample_rate(sensor_id: int | None, if_index: int | None, direction: str, fallback: int = 1) -> int:
    return effective_sample_rate_from_config(sensor_sample_rate_config(sensor_id), if_index, direction, fallback)


def clickhouse_ipv6_literal(value: Any) -> str:
    ip_text = clean_ip(value)
    parsed = ip_address(ip_text)
    if isinstance(parsed, IPv4Address):
        ip_text = f"::ffff:{parsed}"
    escaped = ip_text.replace("'", "''")
    return f"toIPv6('{escaped}')"


def sensor_sample_rate_configs() -> list[dict[str, Any]]:
    ensure_sensor_db()
    with sqlite_connection() as conn:
        sensors = conn.execute(
            """
            SELECT id, exporter_ip, sample_rate_default_in, sample_rate_default_out, sample_rate_mode
            FROM sensors
            WHERE active = 1 AND exporter_ip <> ''
            """
        ).fetchall()
        interface_rows = conn.execute(
            """
            SELECT sensor_id, if_index, sample_rate_in, sample_rate_out, sample_rate_override
            FROM sensor_interfaces
            WHERE if_index > 0
            """
        ).fetchall()
    interfaces_by_sensor: dict[int, dict[int, dict[str, Any]]] = {}
    for row in interface_rows:
        sensor_interfaces = interfaces_by_sensor.setdefault(int(row["sensor_id"]), {})
        sensor_interfaces[int(row["if_index"])] = {
            "in": max(1, int(row["sample_rate_in"] or 1)),
            "out": max(1, int(row["sample_rate_out"] or 1)),
            "override": bool(row["sample_rate_override"]),
        }
    configs = []
    for sensor in sensors:
        mode = clean_text(sensor["sample_rate_mode"]) or "sensor_default"
        if mode not in SAMPLE_RATE_MODES:
            mode = "sensor_default"
        configs.append(
            {
                "sensor_id": int(sensor["id"]),
                "exporter_ip": clean_text(sensor["exporter_ip"]),
                "default_in": max(1, int(sensor["sample_rate_default_in"] or 1)),
                "default_out": max(1, int(sensor["sample_rate_default_out"] or 1)),
                "mode": mode,
                "interfaces": interfaces_by_sensor.get(int(sensor["id"]), {}),
            }
        )
    return configs


def sample_rate_literal(value: Any) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = 1
    return f"toFloat64({max(1, number)})"


def clickhouse_sample_rate_expr(
    sensor_id: int | None,
    direction: str = "auto",
    if_index: int | None = None,
) -> str:
    fallback = "greatest(toFloat64(sample_rate), 1.0)"
    config = sensor_sample_rate_config(sensor_id)
    if not config and sensor_id is None:
        sensor_configs = sensor_sample_rate_configs()
        conditions: list[str] = []
        for sensor_config in sensor_configs:
            try:
                exporter_condition = f"exporter_ip = {clickhouse_ipv6_literal(sensor_config['exporter_ip'])}"
            except ValueError:
                continue
            interfaces = sensor_config.get("interfaces") if isinstance(sensor_config.get("interfaces"), dict) else {}
            for index in interfaces:
                if if_index is not None and int(index) != int(if_index):
                    continue
                if direction == "input":
                    rate = effective_sample_rate_from_config(sensor_config, index, "input")
                    conditions.append(f"{exporter_condition} AND input_if = {int(index)}, {sample_rate_literal(rate)}")
                elif direction == "output":
                    rate = effective_sample_rate_from_config(sensor_config, index, "output")
                    conditions.append(f"{exporter_condition} AND output_if = {int(index)}, {sample_rate_literal(rate)}")
                else:
                    rate_in = effective_sample_rate_from_config(sensor_config, index, "input")
                    rate_out = effective_sample_rate_from_config(sensor_config, index, "output")
                    conditions.append(f"{exporter_condition} AND input_if = {int(index)}, {sample_rate_literal(rate_in)}")
                    conditions.append(f"{exporter_condition} AND output_if = {int(index)}, {sample_rate_literal(rate_out)}")
            if direction == "input":
                conditions.append(f"{exporter_condition} AND input_if > 0, {sample_rate_literal(sensor_config['default_in'])}")
            elif direction == "output":
                conditions.append(f"{exporter_condition} AND output_if > 0, {sample_rate_literal(sensor_config['default_out'])}")
            else:
                conditions.append(f"{exporter_condition} AND input_if > 0, {sample_rate_literal(sensor_config['default_in'])}")
                conditions.append(f"{exporter_condition} AND output_if > 0, {sample_rate_literal(sensor_config['default_out'])}")
        return f"multiIf({', '.join(conditions)}, {fallback})" if conditions else fallback
    if not config:
        return fallback
    conditions: list[str] = []

    def add_condition(field: str, index: int, rate: int) -> None:
        conditions.append(f"{field} = {int(index)}, {sample_rate_literal(rate)}")

    interfaces = config.get("interfaces") if isinstance(config.get("interfaces"), dict) else {}
    for index in interfaces:
        if if_index is not None and int(index) != int(if_index):
            continue
        if direction == "input":
            add_condition("input_if", index, effective_sample_rate_from_config(config, index, "input"))
        elif direction == "output":
            add_condition("output_if", index, effective_sample_rate_from_config(config, index, "output"))
        else:
            add_condition("input_if", index, effective_sample_rate_from_config(config, index, "input"))
            add_condition("output_if", index, effective_sample_rate_from_config(config, index, "output"))

    if direction == "input":
        default_fallback = sample_rate_literal(config["default_in"])
    elif direction == "output":
        default_fallback = sample_rate_literal(config["default_out"])
    else:
        default_fallback = (
            f"multiIf(input_if > 0, {sample_rate_literal(config['default_in'])}, "
            f"output_if > 0, {sample_rate_literal(config['default_out'])}, {fallback})"
        )
    return f"multiIf({', '.join(conditions)}, {default_fallback})" if conditions else default_fallback


def corrected_value_expr(value_field: str, factor_expr: str) -> str:
    return f"toFloat64({value_field}) * ({factor_expr})"


def corrected_sum_expr(value_field: str, factor_expr: str) -> str:
    return f"sum({corrected_value_expr(value_field, factor_expr)})"


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
    cache_key = dashboard_cache_key(
        f"traffic:{metric}",
        {
            "range_minutes": range_minutes,
            "start": start or start_time or "",
            "end": end or end_time or "",
            "sensor": sensor,
            "sensor_id": sensor_id,
        },
    )
    cached = dashboard_cache_get(cache_key, dashboard_cache_ttl(range_minutes))
    if cached:
        return cached
    params: dict[str, Any] = {}
    exporter_ip = sensor_exporter_ip(sensor_id) if sensor_id is not None else None
    where = raw_flow_where(start_dt, end_dt, sensor, params, exporter_ip)
    value_field = "bytes" if metric == "bps" else "packets"
    multiplier = "8" if metric == "bps" else "1"
    input_factor = clickhouse_sample_rate_expr(sensor_id, "input")
    output_factor = clickhouse_sample_rate_expr(sensor_id, "output")
    result = query_clickhouse(
        f"""
        SELECT
            toStartOfMinute(flow_time) AS time,
            sensor,
            sumIf({corrected_value_expr(value_field, input_factor)}, input_if > 0) * {multiplier} / 60 AS download_{metric},
            sumIf({corrected_value_expr(value_field, output_factor)}, output_if > 0) * {multiplier} / 60 AS upload_{metric}
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
    return dashboard_cache_set(cache_key, {"start": iso(start_dt), "end": iso(end_dt), "items": list(series_by_sensor.values())})


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
                sample_rate_override = 1,
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
    detail["sample_rate_override"] = True
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
        selected_if_index = int(interface["if_index"] or 0)
        input_factor = clickhouse_sample_rate_expr(sensor_id, "input", selected_if_index)
        output_factor = clickhouse_sample_rate_expr(sensor_id, "output", selected_if_index)
        params: dict[str, Any] = {
            "exporter_ip": clickhouse_ip_string_param(exporter_ip, "exporter_ip"),
            "if_index": selected_if_index,
        }
        where = flow_time_where(params, start_dt, end_dt)
        result = query_clickhouse(
            f"""
            SELECT
                toStartOfMinute(flow_time) AS time,
                sumIf({corrected_value_expr(value_field, input_factor)}, input_if = {{if_index:UInt32}}) * {multiplier} / 60 AS download_{metric},
                sumIf({corrected_value_expr(value_field, output_factor)}, output_if = {{if_index:UInt32}}) * {multiplier} / 60 AS upload_{metric}
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


def decoder_label_expr() -> str:
    return (
        "multiIf("
        "proto = 6 AND bitAnd(tcp_flags, 2) != 0 AND bitAnd(tcp_flags, 16) = 0, 'TCP+SYN', "
        "proto = 6, 'TCP', "
        "proto = 17, 'UDP', "
        "proto = 1, 'ICMP', "
        "proto = 58, 'ICMPv6', "
        "proto = 47, 'GRE', "
        "proto = 50, 'ESP', "
        "'OTHER')"
    )


def dashboard_series_color(group: str, group_by: str, fallback: int = 0) -> str:
    if group_by == "protocol":
        return PROTOCOL_COLORS.get(clean_text(group).upper(), PROTOCOL_COLORS["OTHER"])
    return DASHBOARD_PALETTE[fallback % len(DASHBOARD_PALETTE)]


def interface_label_map(sensor_id: int | None) -> dict[int, dict[str, Any]]:
    if sensor_id is None:
        return {}
    ensure_sensor_db()
    with sqlite_connection() as conn:
        rows = conn.execute(
            """
            SELECT if_index, if_name, if_alias, color
            FROM sensor_interfaces
            WHERE sensor_id = ?
            """,
            (sensor_id,),
        ).fetchall()
    mapping = {}
    for row in rows:
        label = clean_text(row["if_alias"]) or clean_text(row["if_name"]) or f"ifIndex {int(row['if_index'] or 0)}"
        mapping[int(row["if_index"] or 0)] = {"label": label, "color": clean_text(row["color"]) or ""}
    return mapping


def dashboard_series_payload(
    range_minutes: int,
    sensor_id: int | None,
    interface_id: int | None,
    if_index: int | None,
    direction: str,
    group_by: str,
    metric: str,
    start: datetime | None,
    end: datetime | None,
    start_time: datetime | None,
    end_time: datetime | None,
    limit: int,
    zone_id: int | None = None,
    zone_direction: str = "both",
) -> dict[str, Any]:
    ensure_clickhouse_schema()
    group_by = clean_text(group_by).lower() or "total"
    if group_by not in {"total", "protocol", "interface"}:
        raise HTTPException(status_code=400, detail="group_by invalido")
    metric = clean_text(metric).lower() or "bits_s"
    if metric not in {"bits_s", "packets_s"}:
        raise HTTPException(status_code=400, detail="metric invalida")
    direction = clean_text(direction).lower() or "both"
    if direction not in {"both", "download", "upload"}:
        raise HTTPException(status_code=400, detail="direction invalida")
    context = flow_query_context(
        range_minutes,
        start,
        end,
        start_time,
        end_time,
        None,
        sensor_id,
        interface_id,
        if_index,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        "both",
    )
    start_dt = context["start"]
    end_dt = context["end"]
    cache_key = dashboard_cache_key(
        "dashboard-series",
        {
            "range_minutes": range_minutes,
            "start": start or start_time or "",
            "end": end or end_time or "",
            "sensor_id": sensor_id,
            "interface_id": interface_id,
            "if_index": if_index,
            "direction": direction,
            "group_by": group_by,
            "metric": metric,
            "limit": limit,
            "zone_id": zone_id,
            "zone_direction": zone_direction,
        },
    )
    cached = dashboard_cache_get(cache_key, dashboard_cache_ttl(range_minutes))
    if cached:
        return cached

    value_field = "bytes" if metric == "bits_s" else "packets"
    multiplier = "8" if metric == "bits_s" else "1"
    input_factor = clickhouse_sample_rate_expr(sensor_id, "input", context["resolved_if_index"])
    output_factor = clickhouse_sample_rate_expr(sensor_id, "output", context["resolved_if_index"])
    params = dict(context["params"])
    resolved_if_index = context["resolved_if_index"]
    input_condition = "input_if > 0"
    output_condition = "output_if > 0"
    if resolved_if_index is not None:
        params["series_if_index"] = int(resolved_if_index)
        input_condition = "input_if = {series_if_index:UInt32}"
        output_condition = "output_if = {series_if_index:UInt32}"

    if group_by == "protocol":
        input_group = decoder_label_expr()
        output_group = decoder_label_expr()
    elif group_by == "interface":
        input_group = "toString(input_if)"
        output_group = "toString(output_if)"
    else:
        input_group = "'Total'"
        output_group = "'Total'"

    selects = []
    base_where = context["where"]
    if zone_id is not None:
        zone_direction_normalized = normalize_zone_direction(zone_direction)
        zone_src_filter, zone_dst_filter = ip_zone_clickhouse_membership_filters(zone_id, params, "series_zone")
        zone_upload_filter, zone_download_filter, _zone_both_filter = zone_edge_filters(zone_src_filter, zone_dst_filter)
        zone_input_group = input_group
        zone_output_group = output_group
        if group_by == "interface":
            zone_input_group = "toString(input_if)"
            zone_output_group = "toString(output_if)"
        if zone_direction_normalized in {"both", "receives"}:
            selects.append(
                f"""
                SELECT
                    toStartOfMinute(flow_time) AS ts,
                    {zone_input_group} AS group_key,
                    'download' AS flow_direction,
                    sum({corrected_value_expr(value_field, input_factor)}) * {multiplier} / 60 AS value
                FROM flow_raw
                WHERE {base_where} AND {zone_download_filter} AND {input_condition}
                GROUP BY ts, group_key
                """
            )
        if zone_direction_normalized in {"both", "transmits"}:
            selects.append(
                f"""
                SELECT
                    toStartOfMinute(flow_time) AS ts,
                    {zone_output_group} AS group_key,
                    'upload' AS flow_direction,
                    sum({corrected_value_expr(value_field, output_factor)}) * {multiplier} / 60 AS value
                FROM flow_raw
                WHERE {base_where} AND {zone_upload_filter} AND {output_condition}
                GROUP BY ts, group_key
                """
            )
    else:
        if direction in {"both", "download"}:
            selects.append(
                f"""
                SELECT
                    toStartOfMinute(flow_time) AS ts,
                    {input_group} AS group_key,
                    'download' AS flow_direction,
                    sum({corrected_value_expr(value_field, input_factor)}) * {multiplier} / 60 AS value
                FROM flow_raw
                WHERE {base_where} AND {input_condition}
                GROUP BY ts, group_key
                """
            )
        if direction in {"both", "upload"}:
            selects.append(
                f"""
                SELECT
                    toStartOfMinute(flow_time) AS ts,
                    {output_group} AS group_key,
                    'upload' AS flow_direction,
                    sum({corrected_value_expr(value_field, output_factor)}) * {multiplier} / 60 AS value
                FROM flow_raw
                WHERE {base_where} AND {output_condition}
                GROUP BY ts, group_key
                """
            )
    if not selects:
        return dashboard_cache_set(
            cache_key,
            {
                "start": iso(start_dt),
                "end": iso(end_dt),
                "metric": metric,
                "group_by": group_by,
                "direction": direction,
                "series": [],
                "items": [],
            },
        )
    result = query_clickhouse(" UNION ALL ".join(selects) + " ORDER BY ts, group_key, flow_direction", params)
    rows = rows_as_dicts(result)
    totals: dict[str, float] = {}
    for row in rows:
        totals[clean_text(row["group_key"])] = totals.get(clean_text(row["group_key"]), 0.0) + float(row["value"] or 0)
    allowed_groups = {
        group
        for group, _value in sorted(totals.items(), key=lambda item: item[1], reverse=True)[: max(1, limit)]
    }
    if group_by == "total":
        allowed_groups = set(totals)
    interface_map = interface_label_map(sensor_id)
    series_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        group = clean_text(row["group_key"]) or "N/D"
        if group not in allowed_groups:
            group = "Outras"
        flow_direction = clean_text(row["flow_direction"])
        key = (group, flow_direction)
        index = len(series_by_key)
        label = group
        color = dashboard_series_color(group, group_by, index)
        if group_by == "interface" and group.isdigit():
            iface = interface_map.get(int(group), {})
            label = clean_text(iface.get("label")) or f"ifIndex {group}"
            color = clean_text(iface.get("color")) or deterministic_color(group)
        direction_label = (
            "Entrada da zona" if zone_id is not None and flow_direction == "download"
            else "Saida da zona" if zone_id is not None and flow_direction == "upload"
            else "Download" if flow_direction == "download"
            else "Upload"
        )
        item = series_by_key.setdefault(
            key,
            {
                "name": f"{label} {direction_label}",
                "group": group,
                "label": label,
                "direction": flow_direction,
                "color": color,
                "points": [],
            },
        )
        item["points"].append({"ts": iso(row["ts"]), "value": round(float(row["value"] or 0), 2)})
    if zone_id is not None and group_by == "total":
        expected_zone_directions = {
            "both": ("download", "upload"),
            "receives": ("download",),
            "transmits": ("upload",),
        }[normalize_zone_direction(zone_direction)]
        for flow_direction in expected_zone_directions:
            key = ("Total", flow_direction)
            if key in series_by_key:
                continue
            direction_label = "Entrada da zona" if flow_direction == "download" else "Saida da zona"
            series_by_key[key] = {
                "name": f"Total {direction_label}",
                "group": "Total",
                "label": "Total",
                "direction": flow_direction,
                "color": dashboard_series_color("Total", group_by, len(series_by_key)),
                "points": [
                    {"ts": iso(start_dt), "value": 0.0},
                    {"ts": iso(end_dt), "value": 0.0},
                ],
            }
    payload = {
        "start": iso(start_dt),
        "end": iso(end_dt),
        "metric": metric,
        "group_by": group_by,
        "direction": direction,
        "series": list(series_by_key.values()),
        "items": list(series_by_key.values()),
    }
    return dashboard_cache_set(cache_key, payload)


@app.get("/api/dashboard/series")
def dashboard_series(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    direction: str = "both",
    group_by: str = "total",
    metric: str = "bits_s",
    limit: int = Query(12, ge=1, le=50),
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
):
    return dashboard_series_payload(
        range_minutes,
        sensor_id,
        interface_id,
        if_index,
        direction,
        group_by,
        metric,
        start,
        end,
        start_time,
        end_time,
        limit,
        zone_id,
        zone_direction,
    )


def duration_human(seconds: int) -> str:
    seconds = max(0, int(seconds or 0))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def top_conversations_payload(
    range_minutes: int,
    sensor_id: int | None,
    interface_id: int | None,
    if_index: int | None,
    direction: str,
    proto: str | None,
    limit: int,
    sort_by: str = "bits_s",
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    zone_id: int | None = None,
    zone_direction: str = "both",
) -> dict[str, Any]:
    sort_by = clean_text(sort_by).lower() or "bits_s"
    order_columns = {
        "bits_s": "bits_s",
        "packets_s": "packets_s",
        "pps": "packets_s",
        "flows": "flows",
        "packets": "packets",
    }
    if sort_by not in order_columns:
        raise HTTPException(status_code=400, detail="sort_by invalido")
    context = flow_query_context(
        range_minutes,
        start,
        end,
        start_time,
        end_time,
        None,
        sensor_id,
        interface_id,
        if_index,
        None,
        None,
        None,
        None,
        None,
        None,
        proto,
        None,
        None,
        direction,
    )
    start_dt = context["start"]
    end_dt = context["end"]
    seconds = range_seconds(start_dt, end_dt)
    params = dict(context["params"])
    params.update({"seconds": seconds, "limit": limit})
    zone_filter = build_zone_flow_filter(zone_id, zone_direction, params, "conversation_zone")
    where = f"{context['where']} AND {zone_filter}" if zone_filter else context["where"]
    factor_expr = clickhouse_sample_rate_expr(sensor_id, context["rate_direction"], context["resolved_if_index"])
    bytes_value = corrected_value_expr("bytes", factor_expr)
    packets_value = corrected_value_expr("packets", factor_expr)
    result = query_clickhouse(
        f"""
        WITH
            base AS (
                SELECT
                    toString(src_ip) AS src_ip,
                    toString(dst_ip) AS dst_ip,
                    src_port,
                    dst_port,
                    proto,
                    any(src_asn) AS src_asn,
                    any(dst_asn) AS dst_asn,
                    any(src_as_name) AS src_as_name,
                    any(dst_as_name) AS dst_as_name,
                    sum({bytes_value}) AS bytes,
                    sum({packets_value}) AS packets,
                    sum(flow_count) AS flows,
                    min(flow_time) AS first_seen,
                    max(flow_time) AS last_seen
                FROM flow_raw
                WHERE {where}
                GROUP BY src_ip, dst_ip, src_port, dst_port, proto
            ),
            totals AS (
                SELECT sum(bytes) AS total_bytes
                FROM base
            )
        SELECT
            base.*,
            concat(src_ip, ':', toString(src_port), ' -> ', dst_ip, ':', toString(dst_port)) AS key,
            bytes * 8 / {{seconds:Float64}} AS bits_s,
            packets / {{seconds:Float64}} AS packets_s,
            if(total_bytes > 0, bytes / total_bytes * 100, 0) AS percent_total,
            dateDiff('second', first_seen, last_seen) AS duration_seconds
        FROM base
        CROSS JOIN totals
        ORDER BY {order_columns[sort_by]} DESC
        LIMIT {{limit:UInt32}}
        """,
        params,
    )
    items = []
    for index, row in enumerate(rows_as_dicts(result), start=1):
        src_asn = int(row.get("src_asn") or 0)
        dst_asn = int(row.get("dst_asn") or 0)
        src_info = lookup_asn_info(src_asn) if src_asn > 0 else None
        dst_info = lookup_asn_info(dst_asn) if dst_asn > 0 else None
        if src_asn > 0 and not src_info:
            queue_missing_asn_info(src_asn)
        if dst_asn > 0 and not dst_info:
            queue_missing_asn_info(dst_asn)
        duration = int(row.get("duration_seconds") or 0)
        items.append(
            {
                "rank": index,
                "key": clean_text(row.get("key")),
                "src_ip": clean_ip(row.get("src_ip")),
                "dst_ip": clean_ip(row.get("dst_ip")),
                "src_port": int(row.get("src_port") or 0),
                "dst_port": int(row.get("dst_port") or 0),
                "protocol": proto_name(row.get("proto")),
                "decoder": proto_name(row.get("proto")),
                "bits_s": round(float(row.get("bits_s") or 0), 2),
                "packets_s": round(float(row.get("packets_s") or 0), 2),
                "bytes": int(float(row.get("bytes") or 0)),
                "packets": int(float(row.get("packets") or 0)),
                "flows": int(row.get("flows") or 0),
                "percent": round(float(row.get("percent_total") or 0), 2),
                "first_seen": iso(row.get("first_seen")),
                "last_seen": iso(row.get("last_seen")),
                "duration_seconds": duration,
                "duration_human": duration_human(duration),
                "src_asn": asn_label(src_asn),
                "dst_asn": asn_label(dst_asn),
                "src_as_name": clean_text(row.get("src_as_name")) or clean_text((src_info or {}).get("as_name")),
                "dst_as_name": clean_text(row.get("dst_as_name")) or clean_text((dst_info or {}).get("as_name")),
            }
        )
    return {"start": iso(start_dt), "end": iso(end_dt), "sort_by": sort_by, "items": items}


@app.get("/api/dashboard/top-conversations")
@app.get("/api/tops/conversations")
def dashboard_top_conversations(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    direction: str = "both",
    protocol: str | None = None,
    proto: str | None = None,
    sort_by: str = "bits_s",
    limit: int = Query(10, ge=1, le=100),
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
):
    return top_conversations_payload(
        range_minutes,
        sensor_id,
        interface_id,
        if_index,
        direction,
        proto or protocol,
        limit,
        sort_by,
        start,
        end,
        start_time,
        end_time,
        zone_id,
        zone_direction,
    )


@app.get("/api/dashboard/top-syn")
def dashboard_top_syn(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    direction: str = "both",
    mode: str = "src",
    limit: int = Query(10, ge=1, le=100),
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
):
    mode = clean_text(mode).lower()
    if mode not in {"src", "dst"}:
        raise HTTPException(status_code=400, detail="mode invalido")
    context = flow_query_context(
        range_minutes,
        start,
        end,
        start_time,
        end_time,
        None,
        sensor_id,
        interface_id,
        if_index,
        None,
        None,
        None,
        None,
        None,
        None,
        "6",
        None,
        None,
        direction,
    )
    start_dt = context["start"]
    end_dt = context["end"]
    seconds = range_seconds(start_dt, end_dt)
    params = dict(context["params"])
    params.update({"seconds": seconds, "limit": limit})
    zone_filter = build_zone_flow_filter(zone_id, zone_direction, params, "syn_zone")
    where = f"{context['where']} AND {zone_filter}" if zone_filter else context["where"]
    factor_expr = clickhouse_sample_rate_expr(sensor_id, context["rate_direction"], context["resolved_if_index"])
    ip_col = "src_ip" if mode == "src" else "dst_ip"
    asn_col = "src_asn" if mode == "src" else "dst_asn"
    as_name_col = "src_as_name" if mode == "src" else "dst_as_name"
    bytes_value = corrected_value_expr("bytes", factor_expr)
    packets_value = corrected_value_expr("packets", factor_expr)
    result = query_clickhouse(
        f"""
        WITH
            base AS (
                SELECT
                    toString({ip_col}) AS ip,
                    any({asn_col}) AS asn,
                    any({as_name_col}) AS as_name,
                    sum({bytes_value}) AS bytes,
                    sum({packets_value}) AS packets,
                    sum(flow_count) AS flows
                FROM flow_raw
                WHERE {where}
                  AND bitAnd(tcp_flags, 2) != 0
                  AND bitAnd(tcp_flags, 16) = 0
                GROUP BY ip
            ),
            totals AS (SELECT sum(packets) AS total_packets FROM base)
        SELECT
            base.*,
            bytes * 8 / {{seconds:Float64}} AS bits_s,
            packets / {{seconds:Float64}} AS packets_s,
            if(total_packets > 0, packets / total_packets * 100, 0) AS percent_total
        FROM base
        CROSS JOIN totals
        ORDER BY packets_s DESC
        LIMIT {{limit:UInt32}}
        """,
        params,
    )
    items = []
    for index, row in enumerate(rows_as_dicts(result), start=1):
        asn = int(row.get("asn") or 0)
        info = lookup_asn_info(asn) if asn > 0 else None
        if asn > 0 and not info:
            queue_missing_asn_info(asn)
        country = clean_text((info or {}).get("country")).upper() or "N/D"
        items.append(
            {
                "rank": index,
                "ip": clean_ip(row.get("ip")),
                "asn": asn_label(asn),
                "asn_number": asn,
                "as_name": clean_text(row.get("as_name")) or clean_text((info or {}).get("as_name")) or "-",
                "country": country,
                "packets_s": round(float(row.get("packets_s") or 0), 2),
                "packets": int(float(row.get("packets") or 0)),
                "bits_s": round(float(row.get("bits_s") or 0), 2),
                "bytes": int(float(row.get("bytes") or 0)),
                "flows": int(row.get("flows") or 0),
                "percent": round(float(row.get("percent_total") or 0), 2),
            }
        )
    return {"start": iso(start_dt), "end": iso(end_dt), "mode": mode, "items": items}


def add_geo_filters(
    filters: list[str],
    params: dict[str, Any],
    src_asn: int | None,
    dst_asn: int | None,
    src_cidr: str | None,
    dst_cidr: str | None,
) -> None:
    if src_asn is not None:
        params["geo_src_asn"] = int(src_asn)
        filters.append("src_asn = {geo_src_asn:UInt32}")
    if dst_asn is not None:
        params["geo_dst_asn"] = int(dst_asn)
        filters.append("dst_asn = {geo_dst_asn:UInt32}")
    src_condition = build_ip_condition("src_ip", src_cidr, params, "geo_src_cidr", "IP/CIDR origem")
    if src_condition:
        filters.append(src_condition)
    dst_condition = build_ip_condition("dst_ip", dst_cidr, params, "geo_dst_cidr", "IP/CIDR destino")
    if dst_condition:
        filters.append(dst_condition)


def geo_float(value: Any, minimum: float = -180, maximum: float = 180) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if minimum <= number <= maximum else None


def geo_coord_key(lat: float | None, lon: float | None) -> str:
    if lat is None or lon is None:
        return "no-coord"
    return f"{lat:.4f},{lon:.4f}"


def geo_city_label(geo: dict[str, Any]) -> str:
    city = clean_text(geo.get("city"))
    region = clean_text(geo.get("region"))
    country_code = clean_text(geo.get("country_code")).upper()
    country_name = clean_text(geo.get("country_name"))
    if city and country_code:
        return f"{city}, {country_code}"
    if city:
        return city
    if region and country_code:
        return f"{region}, {country_code}"
    return country_name or country_code or "N/D"


def geo_endpoint_identity(
    group_by: str,
    ip_text: str,
    asn: int,
    as_name: str,
    geo: dict[str, Any],
) -> dict[str, Any]:
    asn_number = int(asn or geo.get("asn") or 0)
    country_code = clean_text(geo.get("country_code")).upper()
    country_name = clean_text(geo.get("country_name"))
    city = clean_text(geo.get("city"))
    region = clean_text(geo.get("region"))
    lat = geo_float(geo.get("latitude"), -90, 90)
    lon = geo_float(geo.get("longitude"), -180, 180)
    asn_name = asn_display_name(asn_number, as_name, geo.get("as_name"))

    if group_by == "country":
        country = country_geo(country_code, country_name)
        lat = geo_float(country.get("latitude"), -90, 90)
        lon = geo_float(country.get("longitude"), -180, 180)
        label = clean_text(country.get("country_name")) or country_code or "N/D"
        identity = f"country:{country_code or label}"
    elif group_by == "asn":
        label = asn_name
        identity = f"asn:{asn_number}" if asn_number > 0 else f"asn:ND:{country_code or clean_ip(ip_text) or geo_coord_key(lat, lon)}"
    elif group_by == "ip":
        label = clean_ip(ip_text) or "N/D"
        identity = f"ip:{label}"
    else:
        label = geo_city_label(geo)
        identity = f"city:{label}:{country_code}:{geo_coord_key(lat, lon)}"

    return {
        "id": identity,
        "label": label,
        "lat": lat,
        "lon": lon,
        "ip": clean_ip(ip_text),
        "asn": asn_number,
        "asn_label": asn_label(asn_number),
        "asn_name": "" if asn_name == asn_label(asn_number) else asn_name,
        "city": city,
        "region": region,
        "country": country_name,
        "country_code": country_code,
    }


def geo_endpoint_country_label(endpoint: dict[str, Any]) -> str:
    return clean_text(endpoint.get("country")) or clean_text(endpoint.get("country_code")) or "N/D"


def ip_matches_filter(ip_text: str, value: Any) -> bool:
    cidr = normalize_ip_filter_for_clickhouse(value, "IP/CIDR")
    if not cidr:
        return True
    try:
        parsed_ip = ip_address(clean_ip(ip_text))
        network = ip_network(cidr, strict=False)
        if parsed_ip.version == 4 and network.version == 6 and str(network.network_address).startswith("::ffff:"):
            parsed_ip = ip_address(f"::ffff:{parsed_ip}")
        return parsed_ip in network
    except ValueError:
        return False


def geo_anomaly_time(row: dict[str, Any]) -> datetime | None:
    return parse_datetime_text(row.get("last_seen")) or parse_datetime_text(row.get("updated_at")) or parse_datetime_text(row.get("created_at"))


def anomaly_ip_asn(ip_text: str) -> tuple[int, str]:
    if not clean_text(ip_text):
        return 0, ""
    resolved = resolve_asn_for_ip(clean_ip(ip_text))
    asn = int(resolved.get("asn") or 0)
    return asn, clean_text(resolved.get("as_name"))


def anomaly_matches_geo_filters(
    anomaly: dict[str, Any],
    start_dt: datetime,
    end_dt: datetime,
    src_cidr: str | None,
    dst_cidr: str | None,
    src_asn: int | None,
    dst_asn: int | None,
) -> tuple[bool, int, str, int, str]:
    seen_at = geo_anomaly_time(anomaly)
    if seen_at is not None and (seen_at < start_dt or seen_at > end_dt):
        return False, 0, "", 0, ""
    if clean_text(src_cidr) and not ip_matches_filter(anomaly.get("src_ip") or "", src_cidr):
        return False, 0, "", 0, ""
    if clean_text(dst_cidr) and not ip_matches_filter(anomaly.get("dst_ip") or "", dst_cidr):
        return False, 0, "", 0, ""
    src_asn_number, src_as_name = anomaly_ip_asn(anomaly.get("src_ip") or "")
    dst_asn_number, dst_as_name = anomaly_ip_asn(anomaly.get("dst_ip") or "")
    if src_asn is not None and src_asn_number != int(src_asn):
        return False, src_asn_number, src_as_name, dst_asn_number, dst_as_name
    if dst_asn is not None and dst_asn_number != int(dst_asn):
        return False, src_asn_number, src_as_name, dst_asn_number, dst_as_name
    return True, src_asn_number, src_as_name, dst_asn_number, dst_as_name


@app.get("/api/geo/anomalies")
def geo_anomalies(
    mode: str = "active",
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor_id: int | None = Query(None, ge=1),
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
    src_ip: str | None = None,
    dst_ip: str | None = None,
    src_cidr: str | None = None,
    dst_cidr: str | None = None,
    src_asn: int | None = Query(None, ge=1),
    dst_asn: int | None = Query(None, ge=1),
    asn_src: int | None = Query(None, ge=1),
    asn_dst: int | None = Query(None, ge=1),
    proto: str | None = None,
    protocol: str | None = None,
    src_port: int | None = Query(None, ge=0, le=65535),
    dst_port: int | None = Query(None, ge=0, le=65535),
    severity: str | None = None,
    vector: str | None = None,
    status: str | None = None,
    metric: str = "bits_s",
    group_by: str = "city",
    limit: int = Query(20, ge=1, le=500),
    top_n: int | None = Query(None, ge=1, le=500),
):
    _ = sensor_id, src_port, dst_port
    ensure_sensor_db()
    mode = clean_text(mode).lower() or "active"
    if mode not in {"active", "history"}:
        raise HTTPException(status_code=400, detail="mode invalido")
    metric = clean_text(metric).lower() or "bits_s"
    if metric == "flows":
        metric = "flows_s"
    if metric not in {"bits_s", "packets_s", "flows_s"}:
        raise HTTPException(status_code=400, detail="metric invalida")
    group_by = clean_text(group_by).lower() or "city"
    if group_by not in {"city", "country", "asn", "ip"}:
        raise HTTPException(status_code=400, detail="group_by invalido")
    requested_limit = int(top_n or limit)
    start_dt, end_dt = resolve_requested_range(range_minutes, start, end, start_time, end_time)
    filters: list[str] = []
    values: list[Any] = []
    if mode == "active":
        filters.append("status = 'active'")
    else:
        if clean_text(status):
            filters.append("status = ?")
            values.append(clean_text(status).lower())
        else:
            filters.append("status <> 'active'")
    if zone_id is not None:
        filters.append("zone_id = ?")
        values.append(zone_id)
    requested_zone_direction = normalize_zone_direction(zone_direction)
    if requested_zone_direction != "both":
        filters.append("direction = ?")
        values.append(requested_zone_direction)
    if clean_text(severity):
        filters.append("severity = ?")
        values.append(clean_text(severity).lower())
    if clean_text(vector):
        filters.append("vector = ?")
        values.append(clean_text(vector))
    protocol_filter = normalize_detection_protocol(proto or protocol, allow_empty=True)
    if protocol_filter and protocol_filter != "ALL":
        filters.append("protocol = ?")
        values.append(protocol_filter)
    source_filter = clean_text(src_cidr or src_ip)
    destination_filter = clean_text(dst_cidr or dst_ip)
    where = " AND ".join(filters) if filters else "1 = 1"
    with sqlite_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM security_anomalies
            WHERE {where}
            ORDER BY last_seen DESC, updated_at DESC, id DESC
            """,
            values,
        ).fetchall()

    edge_groups: dict[tuple[str, str], dict[str, Any]] = {}
    node_groups: dict[str, dict[str, Any]] = {}
    total_anomalies = 0
    total_bits_s = 0.0
    total_packets_s = 0.0
    total_flows_s = 0.0
    for row in rows:
        anomaly = security_anomaly_row_to_dict(row)
        matches, src_asn_number, src_as_name, dst_asn_number, dst_as_name = anomaly_matches_geo_filters(
            anomaly,
            start_dt,
            end_dt,
            source_filter,
            destination_filter,
            asn_src or src_asn,
            asn_dst or dst_asn,
        )
        if not matches:
            continue
        total_anomalies += 1
        bits_s = float(anomaly.get("bits_s") or 0)
        packets_s = float(anomaly.get("packets_s") or 0)
        flows_s = float(anomaly.get("flows_s") or anomaly.get("flows") or 0)
        total_bits_s += bits_s
        total_packets_s += packets_s
        total_flows_s += flows_s
        src_geo = geo_lookup_ip(anomaly.get("src_ip") or "", src_asn_number, src_as_name)
        dst_geo = geo_lookup_ip(anomaly.get("dst_ip") or "", dst_asn_number, dst_as_name)
        src_endpoint = geo_endpoint_identity(group_by, anomaly.get("src_ip") or "", src_asn_number, src_as_name, src_geo)
        dst_endpoint = geo_endpoint_identity(group_by, anomaly.get("dst_ip") or "", dst_asn_number, dst_as_name, dst_geo)
        for endpoint, side in ((src_endpoint, "src"), (dst_endpoint, "dst")):
            node = node_groups.setdefault(
                endpoint["id"],
                {
                    "id": endpoint["id"],
                    "type": group_by,
                    "label": endpoint["label"],
                    "country_code": endpoint["country_code"],
                    "country": geo_endpoint_country_label(endpoint),
                    "city": endpoint["city"],
                    "region": endpoint["region"],
                    "lat": endpoint["lat"],
                    "lon": endpoint["lon"],
                    "asn": endpoint["asn"] or None,
                    "asn_label": endpoint["asn_label"],
                    "asn_name": endpoint["asn_name"],
                    "bits_s": 0.0,
                    "packets_s": 0.0,
                    "flows_s": 0.0,
                    "flows": 0,
                    "sources": 0,
                    "destinations": 0,
                },
            )
            node["bits_s"] += bits_s
            node["packets_s"] += packets_s
            node["flows_s"] += flows_s
            node["flows"] += int(round(flows_s))
            node["sources" if side == "src" else "destinations"] += 1
        edge_key = (src_endpoint["id"], dst_endpoint["id"])
        metric_value = {"bits_s": bits_s, "packets_s": packets_s, "flows_s": flows_s}[metric]
        edge = edge_groups.setdefault(
            edge_key,
            {
                "src": src_endpoint["id"],
                "dst": dst_endpoint["id"],
                "src_label": src_endpoint["label"],
                "dst_label": dst_endpoint["label"],
                "src_ip": src_endpoint["ip"],
                "dst_ip": dst_endpoint["ip"],
                "src_city": src_endpoint["city"],
                "src_region": src_endpoint["region"],
                "src_country": geo_endpoint_country_label(src_endpoint),
                "src_country_code": src_endpoint["country_code"],
                "dst_city": dst_endpoint["city"],
                "dst_region": dst_endpoint["region"],
                "dst_country": geo_endpoint_country_label(dst_endpoint),
                "dst_country_code": dst_endpoint["country_code"],
                "src_lat": src_endpoint["lat"],
                "src_lon": src_endpoint["lon"],
                "dst_lat": dst_endpoint["lat"],
                "dst_lon": dst_endpoint["lon"],
                "severity": anomaly.get("severity") or "",
                "vector": anomaly.get("vector") or "",
                "rule": anomaly.get("template_name") or anomaly.get("vector") or "",
                "status": anomaly.get("status") or "",
                "bits_s": 0.0,
                "packets_s": 0.0,
                "flows_s": 0.0,
                "flows": 0,
                "packets": 0,
                "bytes": 0,
                "top_protocol": anomaly.get("protocol") or "ALL",
                "src_port": 0,
                "dst_port": 0,
                "top_asn_src": src_asn_number,
                "top_asn_dst": dst_asn_number,
                "top_asn_src_name": src_endpoint["asn_name"] or src_as_name,
                "top_asn_dst_name": dst_endpoint["asn_name"] or dst_as_name,
                "_top_metric_value": metric_value,
            },
        )
        if metric_value > float(edge.get("_top_metric_value") or 0):
            edge["severity"] = anomaly.get("severity") or ""
            edge["vector"] = anomaly.get("vector") or ""
            edge["rule"] = anomaly.get("template_name") or anomaly.get("vector") or ""
            edge["status"] = anomaly.get("status") or ""
            edge["top_protocol"] = anomaly.get("protocol") or "ALL"
            edge["_top_metric_value"] = metric_value
        edge["bits_s"] += bits_s
        edge["packets_s"] += packets_s
        edge["flows_s"] += flows_s
        edge["flows"] += int(round(flows_s))
        edge["packets"] += int(float(anomaly.get("packets") or 0))
        edge["bytes"] += int(float(anomaly.get("bytes") or 0))

    nodes = []
    for item in node_groups.values():
        item["bits_s"] = round(float(item["bits_s"]), 2)
        item["packets_s"] = round(float(item["packets_s"]), 2)
        item["flows_s"] = round(float(item["flows_s"]), 2)
        nodes.append(item)
    edges = []
    for item in sorted(edge_groups.values(), key=lambda edge: float(edge.get(metric) or 0), reverse=True)[:requested_limit]:
        item["bits_s"] = round(float(item["bits_s"]), 2)
        item["packets_s"] = round(float(item["packets_s"]), 2)
        item["flows_s"] = round(float(item["flows_s"]), 2)
        item["has_coordinates"] = all(item.get(key) is not None for key in ("src_lat", "src_lon", "dst_lat", "dst_lon"))
        item.pop("_top_metric_value", None)
        edges.append(item)
    complete_count = sum(1 for edge in edges if edge.get("has_coordinates"))
    countries = {
        clean_text(edge.get(key)).upper()
        for edge in edges
        for key in ("src_country_code", "dst_country_code")
        if clean_text(edge.get(key))
    }
    missing_geo = max(0, len(edges) - complete_count)
    summary = {
        "total_bits_s": round(total_bits_s, 2),
        "total_packets_s": round(total_packets_s, 2),
        "total_flows_s": round(total_flows_s, 2),
        "total_anomalies": total_anomalies,
        "countries_active": len(countries),
        "routes_active": len(edges),
        "routes_located": complete_count,
        "missing_geo": missing_geo,
    }
    return {
        "start": iso(start_dt),
        "end": iso(end_dt),
        "mode": mode,
        "source": "anomalies",
        "metric": "flows" if metric == "flows_s" else metric,
        "group_by": group_by,
        "requested_top_n": requested_limit,
        "summary": summary,
        "total_routes": len(edges),
        "complete_route_count": complete_count,
        "incomplete_route_count": missing_geo,
        "localized_routes": complete_count,
        "unlocalized_routes": missing_geo,
        "active_countries": len(countries),
        "nodes": nodes,
        "edges": edges,
        "items": edges,
        "geoip_source": "maxmind" if GEOIP_MMDB_PATH and Path(GEOIP_MMDB_PATH).exists() else "local-cache",
        "warning": "" if GEOIP_MMDB_PATH and Path(GEOIP_MMDB_PATH).exists() else "GeoIP database not configured",
    }


@app.get("/api/geo/status")
def geo_status():
    mmdb_path = GEOIP_MMDB_PATH
    mmdb_found = bool(mmdb_path and Path(mmdb_path).exists())
    cached_ips = 0
    cached_prefixes = 0
    last_update_at = ""
    try:
        ensure_sensor_db()
        with sqlite_connection() as conn:
            ensure_asn_db(conn)
            geo_row = conn.execute(
                "SELECT COUNT(*) AS count, MAX(updated_at) AS updated_at FROM geo_ip_cache"
            ).fetchone()
            prefix_row = conn.execute(
                "SELECT COUNT(*) AS count, MAX(updated_at) AS updated_at FROM asn_prefixes"
            ).fetchone()
            cached_ips = int(geo_row["count"] or 0) if geo_row else 0
            cached_prefixes = int(prefix_row["count"] or 0) if prefix_row else 0
            last_update_at = max(
                clean_text(geo_row["updated_at"] if geo_row else ""),
                clean_text(prefix_row["updated_at"] if prefix_row else ""),
            )
    except Exception as exc:
        logger.debug("Falha ao montar geo/status: %s", exc)
        last_error = clean_text(exc)
    else:
        last_error = (GEOIP_LAST_ERROR or "GeoIP database not configured") if not mmdb_found else ""
    return {
        "enabled": mmdb_found or cached_ips > 0 or cached_prefixes > 0,
        "mmdb_found": mmdb_found,
        "mmdb_path": mmdb_path,
        "cached_ips": cached_ips,
        "cached_prefixes": cached_prefixes,
        "last_error": last_error,
        "last_update_at": last_update_at,
    }


@app.get("/api/geo/flows")
def geo_flows(
    range_minutes: int = Query(60, ge=1, le=MAX_RANGE_MINUTES),
    start: datetime | None = None,
    end: datetime | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sensor_id: int | None = Query(None, ge=1),
    interface_id: int | None = Query(None, ge=1),
    if_index: int | None = Query(None, ge=0),
    direction: str = "both",
    protocol: str | None = None,
    proto: str | None = None,
    decoder: str | None = None,
    asn_src: int | None = Query(None, ge=1),
    asn_dst: int | None = Query(None, ge=1),
    src_asn: int | None = Query(None, ge=1),
    dst_asn: int | None = Query(None, ge=1),
    src_ip: str | None = None,
    dst_ip: str | None = None,
    src_cidr: str | None = None,
    dst_cidr: str | None = None,
    src_port: int | None = Query(None, ge=0, le=65535),
    dst_port: int | None = Query(None, ge=0, le=65535),
    metric: str = "bits_s",
    group_by: str = "city",
    top_n: int = Query(20, ge=1, le=500),
    limit: int | None = Query(None, ge=1, le=500),
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
):
    ensure_clickhouse_schema()
    metric = clean_text(metric).lower() or "bits_s"
    if metric not in {"bits_s", "packets_s", "flows"}:
        raise HTTPException(status_code=400, detail="metric invalida")
    group_by = clean_text(group_by).lower() or "city"
    if group_by not in {"city", "country", "asn", "ip"}:
        raise HTTPException(status_code=400, detail="group_by invalido")
    requested_top_n = int(limit or top_n)
    src_filter = clean_text(src_cidr or src_ip)
    dst_filter = clean_text(dst_cidr or dst_ip)
    context = flow_query_context(
        range_minutes,
        start,
        end,
        start_time,
        end_time,
        None,
        sensor_id,
        interface_id,
        if_index,
        None,
        None,
        None,
        None,
        src_port,
        dst_port,
        proto or protocol,
        None,
        decoder,
        direction,
    )
    start_dt = context["start"]
    end_dt = context["end"]
    cache_key = dashboard_cache_key(
        "geo-flows",
        {
            "range_minutes": range_minutes,
            "start": start or start_time or "",
            "end": end or end_time or "",
            "sensor_id": sensor_id,
            "interface_id": interface_id,
            "if_index": if_index,
            "direction": direction,
            "protocol": proto or protocol or "",
            "decoder": decoder or "",
            "asn_src": asn_src or src_asn or "",
            "asn_dst": asn_dst or dst_asn or "",
            "src_cidr": src_filter,
            "dst_cidr": dst_filter,
            "src_port": src_port or "",
            "dst_port": dst_port or "",
            "metric": metric,
            "group_by": group_by,
            "top_n": requested_top_n,
            "zone_id": zone_id,
            "zone_direction": zone_direction,
        },
    )
    ttl = 10 if range_minutes <= 15 else 30 if range_minutes <= 60 else 60
    cached = dashboard_cache_get(cache_key, ttl)
    if cached:
        return cached
    seconds = range_seconds(start_dt, end_dt)
    params = dict(context["params"])
    fetch_limit = min(max(int(requested_top_n) * 20, 500), 5000)
    params.update({"seconds": seconds, "limit": fetch_limit})
    filters = [context["where"]]
    add_geo_filters(filters, params, asn_src or src_asn, asn_dst or dst_asn, src_filter, dst_filter)
    zone_filter = build_zone_flow_filter(zone_id, zone_direction, params, "geo_zone")
    if zone_filter:
        filters.append(zone_filter)
    where = " AND ".join(f"({item})" for item in filters if item)
    factor_expr = clickhouse_sample_rate_expr(sensor_id, context["rate_direction"], context["resolved_if_index"])
    order_expr = {"bits_s": "bits_s", "packets_s": "packets_s", "flows": "flows"}[metric]
    top_order_expr = {"bits_s": "total_bytes", "packets_s": "total_packets", "flows": "total_flows"}[metric]
    row_bytes_expr = corrected_value_expr("bytes", factor_expr)
    row_packets_expr = corrected_value_expr("packets", factor_expr)
    has_strong_filter = any(
        [
            src_filter,
            dst_filter,
            asn_src or src_asn,
            asn_dst or dst_asn,
            zone_id,
            interface_id,
            if_index is not None,
            src_port is not None,
            dst_port is not None,
            clean_text(proto or protocol or decoder),
            clean_text(direction).lower() in {"download", "upload"},
        ]
    )
    if range_seconds(start_dt, end_dt) > 360 * 60 and not has_strong_filter:
        warning = "Consulta muito ampla. Reduza o periodo, aplique filtros ou aumente o Top."
        return dashboard_cache_set(
            cache_key,
            {
                "start": iso(start_dt),
                "end": iso(end_dt),
                "source": "flows",
                "metric": metric,
                "group_by": group_by,
                "requested_top_n": requested_top_n,
                "summary": {
                    "total_bits_s": 0.0,
                    "total_packets_s": 0.0,
                    "total_flows_s": 0.0,
                    "total_anomalies": 0,
                    "countries_active": 0,
                    "routes_active": 0,
                    "routes_located": 0,
                    "missing_geo": 0,
                },
                "total_routes": 0,
                "complete_route_count": 0,
                "incomplete_route_count": 0,
                "localized_routes": 0,
                "unlocalized_routes": 0,
                "active_countries": 0,
                "nodes": [],
                "edges": [],
                "items": [],
                "geoip_source": "maxmind" if GEOIP_MMDB_PATH and Path(GEOIP_MMDB_PATH).exists() else "local-cache",
                "warning": warning,
            },
        )
    try:
        result = query_clickhouse(
            f"""
            SELECT
                src_ip,
                dst_ip,
                src_asn,
                dst_asn,
                src_as_name,
                dst_as_name,
                top_protocol,
                total_bytes AS bytes,
                total_packets AS packets,
                total_bytes * 8 / {{seconds:Float64}} AS bits_s,
                total_packets / {{seconds:Float64}} AS packets_s,
                total_flows AS flows
            FROM (
                SELECT
                    toString(src_ip) AS src_ip,
                    toString(dst_ip) AS dst_ip,
                    toUInt32(src_asn) AS src_asn,
                    toUInt32(dst_asn) AS dst_asn,
                    {decoder_label_expr()} AS top_protocol,
                    sum({row_bytes_expr}) AS total_bytes,
                    sum({row_packets_expr}) AS total_packets,
                    sum(flow_count) AS total_flows,
                    any(src_as_name) AS src_as_name,
                    any(dst_as_name) AS dst_as_name
                FROM flow_raw
                WHERE {where}
                GROUP BY src_ip, dst_ip, src_asn, dst_asn, top_protocol
                ORDER BY {top_order_expr} DESC
                LIMIT {{limit:UInt32}}
            ) AS top_candidates
            ORDER BY {order_expr} DESC
            """,
            params,
        )
    except Exception as exc:
        error_text = clean_text(exc)
        if "MEMORY_LIMIT_EXCEEDED" in error_text or "code: 241" in error_text or "code 241" in error_text:
            warning = "Consulta muito ampla. Reduza o periodo, aplique filtros ou aumente o Top."
        else:
            warning = f"Erro ao consultar ClickHouse: {error_text}"
        logger.exception("Falha em /api/geo/flows: %s", warning)
        return {
            "start": iso(start_dt),
            "end": iso(end_dt),
            "source": "flows",
            "metric": metric,
            "group_by": group_by,
            "requested_top_n": requested_top_n,
            "summary": {
                "total_bits_s": 0.0,
                "total_packets_s": 0.0,
                "total_flows_s": 0.0,
                "total_anomalies": 0,
                "countries_active": 0,
                "routes_active": 0,
                "routes_located": 0,
                "missing_geo": 0,
            },
            "total_routes": 0,
            "complete_route_count": 0,
            "incomplete_route_count": 0,
            "localized_routes": 0,
            "unlocalized_routes": 0,
            "active_countries": 0,
            "nodes": [],
            "edges": [],
            "items": [],
            "geoip_source": "maxmind" if GEOIP_MMDB_PATH and Path(GEOIP_MMDB_PATH).exists() else "local-cache",
            "warning": warning,
        }
    edge_groups: dict[tuple[str, str], dict[str, Any]] = {}
    node_groups: dict[str, dict[str, Any]] = {}
    for row in rows_as_dicts(result):
        try:
            src_geo = geo_lookup_ip(row["src_ip"], int(row.get("src_asn") or 0), clean_text(row.get("src_as_name")))
            dst_geo = geo_lookup_ip(row["dst_ip"], int(row.get("dst_asn") or 0), clean_text(row.get("dst_as_name")))
        except Exception as exc:
            logger.warning("Falha ao geolocalizar linha de flow: %s", exc)
            continue
        src_asn = int(row.get("src_asn") or 0)
        dst_asn = int(row.get("dst_asn") or 0)
        src_endpoint = geo_endpoint_identity(
            group_by,
            clean_ip(row.get("src_ip")),
            src_asn,
            clean_text(row.get("src_as_name")),
            src_geo,
        )
        dst_endpoint = geo_endpoint_identity(
            group_by,
            clean_ip(row.get("dst_ip")),
            dst_asn,
            clean_text(row.get("dst_as_name")),
            dst_geo,
        )
        for endpoint, side in (
            (src_endpoint, "src"),
            (dst_endpoint, "dst"),
        ):
            node = node_groups.setdefault(
                endpoint["id"],
                {
                    "id": endpoint["id"],
                    "type": group_by,
                    "label": endpoint["label"],
                    "country_code": endpoint["country_code"],
                    "country": geo_endpoint_country_label(endpoint),
                    "city": endpoint["city"],
                    "region": endpoint["region"],
                    "lat": endpoint["lat"],
                    "lon": endpoint["lon"],
                    "asn": endpoint["asn"] or None,
                    "asn_label": endpoint["asn_label"],
                    "asn_name": endpoint["asn_name"],
                    "bits_s": 0.0,
                    "packets_s": 0.0,
                    "bytes": 0,
                    "packets": 0,
                    "flows": 0,
                    "sources": 0,
                    "destinations": 0,
                },
            )
            if node.get("lat") is None and endpoint.get("lat") is not None:
                node["lat"] = endpoint["lat"]
                node["lon"] = endpoint["lon"]
            node["bits_s"] += float(row.get("bits_s") or 0)
            node["packets_s"] += float(row.get("packets_s") or 0)
            node["bytes"] += int(float(row.get("bytes") or 0))
            node["packets"] += int(float(row.get("packets") or 0))
            node["flows"] += int(row.get("flows") or 0)
            node["sources" if side == "src" else "destinations"] += 1
        edge_key = (src_endpoint["id"], dst_endpoint["id"])
        metric_value = float(row.get(order_expr) or 0)
        edge = edge_groups.setdefault(
            edge_key,
            {
                "src": src_endpoint["id"],
                "dst": dst_endpoint["id"],
                "src_label": src_endpoint["label"],
                "dst_label": dst_endpoint["label"],
                "src_ip": src_endpoint["ip"],
                "dst_ip": dst_endpoint["ip"],
                "src_city": src_endpoint["city"],
                "src_region": src_endpoint["region"],
                "src_country": geo_endpoint_country_label(src_endpoint),
                "src_country_code": src_endpoint["country_code"],
                "dst_city": dst_endpoint["city"],
                "dst_region": dst_endpoint["region"],
                "dst_country": geo_endpoint_country_label(dst_endpoint),
                "dst_country_code": dst_endpoint["country_code"],
                "src_lat": src_endpoint["lat"],
                "src_lon": src_endpoint["lon"],
                "dst_lat": dst_endpoint["lat"],
                "dst_lon": dst_endpoint["lon"],
                "bits_s": 0.0,
                "packets_s": 0.0,
                "bytes": 0,
                "packets": 0,
                "flows": 0,
                "top_protocol": clean_text(row.get("top_protocol")) or "OTHER",
                "top_asn_src": src_asn,
                "top_asn_dst": dst_asn,
                "top_asn_src_name": src_endpoint["asn_name"],
                "top_asn_dst_name": dst_endpoint["asn_name"],
                "_top_metric_value": metric_value,
            },
        )
        if metric_value > float(edge.get("_top_metric_value") or 0):
            edge["top_protocol"] = clean_text(row.get("top_protocol")) or "OTHER"
            edge["top_asn_src"] = src_asn
            edge["top_asn_dst"] = dst_asn
            edge["top_asn_src_name"] = src_endpoint["asn_name"]
            edge["top_asn_dst_name"] = dst_endpoint["asn_name"]
            edge["_top_metric_value"] = metric_value
        edge["bits_s"] += float(row.get("bits_s") or 0)
        edge["packets_s"] += float(row.get("packets_s") or 0)
        edge["bytes"] += int(float(row.get("bytes") or 0))
        edge["packets"] += int(float(row.get("packets") or 0))
        edge["flows"] += int(row.get("flows") or 0)
    nodes = []
    for item in node_groups.values():
        item["bits_s"] = round(float(item["bits_s"]), 2)
        item["packets_s"] = round(float(item["packets_s"]), 2)
        nodes.append(item)
    edges = []
    for item in sorted(edge_groups.values(), key=lambda edge: float(edge.get(order_expr) or 0), reverse=True)[:top_n]:
        item["bits_s"] = round(float(item["bits_s"]), 2)
        item["packets_s"] = round(float(item["packets_s"]), 2)
        item["has_coordinates"] = all(
            item.get(key) is not None
            for key in ("src_lat", "src_lon", "dst_lat", "dst_lon")
        )
        item.pop("_top_metric_value", None)
        edges.append(item)
    complete_count = sum(1 for edge in edges if edge.get("has_coordinates"))
    countries = {
        clean_text(edge.get(key)).upper()
        for edge in edges
        for key in ("src_country_code", "dst_country_code")
        if clean_text(edge.get(key))
    }
    summary = {
        "total_bits_s": round(sum(float(edge.get("bits_s") or 0) for edge in edges), 2),
        "total_packets_s": round(sum(float(edge.get("packets_s") or 0) for edge in edges), 2),
        "total_flows_s": round(sum(float(edge.get("flows") or 0) for edge in edges) / seconds, 2) if seconds > 0 else 0.0,
        "total_anomalies": 0,
        "countries_active": len(countries),
        "routes_active": len(edges),
        "routes_located": complete_count,
        "missing_geo": max(0, len(edges) - complete_count),
    }
    payload = {
        "start": iso(start_dt),
        "end": iso(end_dt),
        "source": "flows",
        "metric": metric,
        "group_by": group_by,
        "requested_top_n": requested_top_n,
        "summary": summary,
        "total_routes": len(edges),
        "complete_route_count": complete_count,
        "incomplete_route_count": max(0, len(edges) - complete_count),
        "localized_routes": complete_count,
        "unlocalized_routes": max(0, len(edges) - complete_count),
        "active_countries": len(countries),
        "nodes": nodes,
        "edges": edges,
        "items": edges,
        "geoip_source": "maxmind" if GEOIP_MMDB_PATH and Path(GEOIP_MMDB_PATH).exists() else "local-cache",
        "warning": "" if GEOIP_MMDB_PATH and Path(GEOIP_MMDB_PATH).exists() else "GeoIP database not configured",
    }
    return dashboard_cache_set(cache_key, payload)


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
    zone_id: int | None = None,
    zone_direction: str = "both",
):
    start_dt, end_dt = resolve_requested_range(range_minutes, start, end, start_time, end_time)
    cache_key = dashboard_cache_key(
        f"top:{dimension}",
        {
            "range_minutes": range_minutes,
            "start": start or start_time or "",
            "end": end or end_time or "",
            "sensor": sensor,
            "sensor_id": sensor_id,
            "interface_id": interface_id,
            "if_index": if_index,
            "limit": limit,
            "zone_id": zone_id,
            "zone_direction": zone_direction,
        },
    )
    cached = dashboard_cache_get(cache_key, dashboard_cache_ttl(range_minutes))
    if cached:
        return cached
    seconds = range_seconds(start_dt, end_dt)
    params: dict[str, Any] = {"limit": limit, "seconds": seconds}
    exporter_ip = sensor_exporter_ip(sensor_id) if sensor_id is not None else None
    resolved_if_index = resolve_dashboard_if_index(sensor_id, interface_id, if_index)
    where = raw_flow_where(start_dt, end_dt, sensor, params, exporter_ip, resolved_if_index)
    zone_filter = build_zone_flow_filter(zone_id, zone_direction, params, "top_zone")
    if zone_filter:
        where += f" AND {zone_filter}"
    factor_expr = clickhouse_sample_rate_expr(sensor_id, "auto", resolved_if_index)
    bytes_sum = corrected_sum_expr("bytes", factor_expr)
    packets_sum = corrected_sum_expr("packets", factor_expr)

    if dimension == "src_ip":
        query = f"""
        SELECT
            toString(src_ip) AS ip,
            {bytes_sum} * 8 / {{seconds:Float64}} AS bps,
            {packets_sum} AS packets,
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
            {bytes_sum} * 8 / {{seconds:Float64}} AS bps,
            {packets_sum} AS packets,
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
            {bytes_sum} * 8 / {{seconds:Float64}} AS bps,
            {packets_sum} AS packets,
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
            {bytes_sum} * 8 / {{seconds:Float64}} AS bps,
            {packets_sum} AS packets,
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
            {bytes_sum} * 8 / {{seconds:Float64}} AS bps,
            {packets_sum} AS packets,
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

    return dashboard_cache_set(cache_key, {"items": items})


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
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
):
    return top_dimension("src_ip", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index, zone_id, zone_direction)


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
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
):
    return top_dimension("dst_ip", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index, zone_id, zone_direction)


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
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
):
    return top_dimension("dst_port", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index, zone_id, zone_direction)


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
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
):
    return top_dimension("proto", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index, zone_id, zone_direction)


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
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
):
    return top_dimension("tcp_flags", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index, zone_id, zone_direction)


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
    zone_id: int | None = None,
    zone_direction: str = "both",
):
    ensure_clickhouse_schema()
    start_dt, end_dt = resolve_requested_range(range_minutes, start, end, start_time, end_time)
    seconds = range_seconds(start_dt, end_dt)
    params: dict[str, Any] = {"seconds": seconds, "limit": limit}
    exporter_ip = sensor_exporter_ip(sensor_id) if sensor_id is not None else None
    resolved_if_index = resolve_dashboard_if_index(sensor_id, interface_id, if_index)
    where = raw_flow_where(start_dt, end_dt, sensor, params, exporter_ip)
    rate_direction = "auto"
    if zone_id is not None:
        requested_zone_direction = normalize_zone_direction(zone_direction)
        if requested_zone_direction == "both":
            asn_zone_direction = "transmits" if dimension == "src" else "receives"
        else:
            asn_zone_direction = requested_zone_direction
        zone_filter = build_zone_flow_filter(zone_id, asn_zone_direction, params, "asn_zone")
        if zone_filter:
            where += f" AND {zone_filter}"
        if asn_zone_direction == "transmits":
            asn_col = "dst_asn"
            as_name_col = "dst_as_name"
            ip_col = "dst_ip"
            rate_direction = "output"
            if resolved_if_index is not None:
                params["if_index"] = resolved_if_index
                where += " AND output_if = {if_index:UInt32}"
        else:
            asn_col = "src_asn"
            as_name_col = "src_as_name"
            ip_col = "src_ip"
            rate_direction = "input"
            if resolved_if_index is not None:
                params["if_index"] = resolved_if_index
                where += " AND input_if = {if_index:UInt32}"
    else:
        if resolved_if_index is not None:
            params["if_index"] = resolved_if_index
            if dimension == "src":
                where += " AND output_if = {if_index:UInt32}"
                rate_direction = "output"
            else:
                where += " AND input_if = {if_index:UInt32}"
                rate_direction = "input"
        asn_col = "src_asn" if dimension == "src" else "dst_asn"
        as_name_col = "src_as_name" if dimension == "src" else "dst_as_name"
        ip_col = "src_ip" if dimension == "src" else "dst_ip"

    factor_expr = clickhouse_sample_rate_expr(sensor_id, rate_direction, resolved_if_index)
    bytes_sum = corrected_sum_expr("bytes", factor_expr)
    packets_sum = corrected_sum_expr("packets", factor_expr)
    result = query_clickhouse(
        f"""
        SELECT
            toUInt32({asn_col}) AS asn,
            any({as_name_col}) AS as_name,
            {bytes_sum} * 8 / {{seconds:Float64}} AS bps,
            {packets_sum} AS packets,
            sum(flow_count) AS flows
        FROM flow_raw
        WHERE {where} AND {asn_col} > 0
        GROUP BY asn
        ORDER BY bps DESC
        LIMIT {{limit:UInt32}}
        """,
        params,
    )
    items = []
    for index, row in enumerate(rows_as_dicts(result), start=1):
        asn = int(row["asn"] or 0)
        if asn <= 0:
            continue
        asn_info = lookup_asn_info(asn) or {}
        if not asn_info:
            queue_missing_asn_info(asn)
        display_name = asn_display_name(
            asn,
            asn_info.get("as_name"),
            asn_info.get("org_name"),
            row.get("as_name"),
        )
        items.append(
            {
                "rank": index,
                "asn": asn_label(asn),
                "asn_number": asn,
                "display_name": display_name,
                "description": display_name if display_name != asn_label(asn) else "-",
                "org_name": clean_text(asn_info.get("org_name")),
                "country": clean_text(asn_info.get("country")).upper() or "N/D",
                "source": "flow",
                "bps": round(float(row["bps"] or 0), 2),
                "packets": int(float(row["packets"] or 0)),
                "flows": int(row["flows"] or 0),
                "percent": 0.0,
            }
        )

    ip_result = query_clickhouse(
        f"""
        SELECT
            toString({ip_col}) AS ip,
            {bytes_sum} * 8 / {{seconds:Float64}} AS bps,
            {packets_sum} AS packets,
            sum(flow_count) AS flows
        FROM flow_raw
        WHERE {where} AND {asn_col} = 0
        GROUP BY ip
        ORDER BY bps DESC
        LIMIT 200
        """,
        params,
    )
    grouped = {int(item["asn_number"]): item for item in items}
    for row in rows_as_dicts(ip_result):
        resolved = resolve_asn_for_ip(clean_ip(row["ip"]))
        asn = int(resolved.get("asn") or 0)
        if asn <= 0:
            continue
        asn_info = lookup_asn_info(asn) or {}
        display_name = asn_display_name(
            asn,
            asn_info.get("as_name"),
            asn_info.get("org_name"),
            resolved.get("as_name"),
        )
        item = grouped.setdefault(
            asn,
            {
                "asn": asn_label(asn),
                "asn_number": asn,
                "display_name": display_name,
                "description": display_name if display_name != asn_label(asn) else "-",
                "org_name": clean_text(asn_info.get("org_name")),
                "country": clean_text(asn_info.get("country")).upper() or clean_text(resolved.get("country")).upper() or "N/D",
                "source": clean_text(resolved.get("source")) or "local-cache",
                "bps": 0.0,
                "packets": 0,
                "flows": 0,
                "percent": 0.0,
            },
        )
        item["bps"] = round(float(item.get("bps") or 0) + float(row["bps"] or 0), 2)
        item["packets"] = int(item.get("packets") or 0) + int(float(row["packets"] or 0))
        item["flows"] = int(item.get("flows") or 0) + int(row["flows"] or 0)
    items = sorted(grouped.values(), key=lambda item: float(item.get("bps") or 0), reverse=True)[:limit]
    for index, item in enumerate(items, start=1):
        item["rank"] = index

    if not items:
        ip_result = query_clickhouse(
            f"""
            SELECT
                toString({ip_col}) AS ip,
                {bytes_sum} * 8 / {{seconds:Float64}} AS bps,
                {packets_sum} AS packets,
                sum(flow_count) AS flows
            FROM flow_raw
            WHERE {where}
            GROUP BY ip
            ORDER BY bps DESC
            LIMIT 200
            """,
            params,
        )
        grouped: dict[int, dict[str, Any]] = {}
        for row in rows_as_dicts(ip_result):
            ip_text = clean_ip(row["ip"])
            try:
                if not is_public_ip(ip_text):
                    continue
            except ValueError:
                continue
            asn_info = lookup_asn_prefix(ip_text)
            if not asn_info:
                continue
            asn = int(asn_info["asn"] or 0)
            resolved_info = lookup_asn_info(asn) or {}
            display_name = asn_display_name(
                asn,
                resolved_info.get("as_name"),
                resolved_info.get("org_name"),
                asn_info.get("as_name"),
            )
            item = grouped.setdefault(
                asn,
                {
                    "asn": asn_label(asn),
                    "asn_number": asn,
                    "display_name": display_name,
                    "description": display_name if display_name != asn_label(asn) else "-",
                    "org_name": clean_text(resolved_info.get("org_name")),
                    "country": clean_text(resolved_info.get("country")).upper() or clean_text(asn_info.get("country")).upper() or "N/D",
                    "source": asn_info.get("source") or "local-cache",
                    "bps": 0.0,
                    "packets": 0,
                    "flows": 0,
                    "percent": 0.0,
                },
            )
            item["bps"] += float(row["bps"] or 0)
            item["packets"] += int(float(row["packets"] or 0))
            item["flows"] += int(row["flows"] or 0)
        items = sorted(grouped.values(), key=lambda item: item["bps"], reverse=True)[:limit]
        for index, item in enumerate(items, start=1):
            item["rank"] = index
            item["bps"] = round(float(item["bps"] or 0), 2)

    total_result = query_clickhouse(
        f"""
        SELECT {bytes_sum} * 8 / {{seconds:Float64}} AS bps
        FROM flow_raw
        WHERE {where}
        """,
        params,
    )
    total_rows = rows_as_dicts(total_result)
    total_bps = float(total_rows[0]["bps"] or 0) if total_rows else sum(float(item["bps"] or 0) for item in items)
    for item in items:
        item["percent"] = round(float(item["bps"] or 0) * 100 / total_bps, 2) if total_bps > 0 else 0.0

    if items:
        return {
            "start": iso(start_dt),
            "end": iso(end_dt),
            "asn_available": True,
            "message": "ASN resolvido pelo flow/IPFIX ou pela base ASN local.",
            "items": items[:limit],
        }

    bps = round(total_bps, 2)
    if bps <= 0:
        return {"start": iso(start_dt), "end": iso(end_dt), "asn_available": False, "items": []}
    item = {
        "rank": 1,
        "asn": "ASN indisponivel",
        "description": "Sem ASN no flow e sem prefixo correspondente na base local",
        "country": "N/D",
        "bps": bps,
        "packets": 0,
        "flows": 0,
        "percent": 100.0,
    }
    return {
        "start": iso(start_dt),
        "end": iso(end_dt),
        "asn_available": False,
        "message": "ASN ausente no flow/IPFIX e nao encontrado na base local. Use Resolver ASNs pendentes ou importe uma base de prefixos.",
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
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
):
    return top_asn_dimension("src", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index, zone_id, zone_direction)


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
    zone_id: int | None = Query(None, ge=1),
    zone_direction: str = "both",
):
    return top_asn_dimension("dst", range_minutes, sensor, sensor_id, limit, start, end, start_time, end_time, interface_id, if_index, zone_id, zone_direction)


def flow_query_context(
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
    port: Any | None = None,
    src_port: Any | None = None,
    dst_port: Any | None = None,
    proto: str | None = None,
    tcp_flags: str | None = None,
    decoder: str | None = None,
    direction: str = "both",
) -> dict[str, Any]:
    start_dt, end_dt = resolve_requested_range(range_minutes, start, end, start_time, end_time)
    params: dict[str, Any] = {"start": start_dt, "end": end_dt}
    filters = ["flow_time >= {start:DateTime}", "flow_time <= {end:DateTime}"]
    if sensor_id is not None:
        params["exporter_ip"] = clickhouse_ip_string_param(sensor_exporter_ip(sensor_id), "exporter_ip")
        filters.append("toString(exporter_ip) = {exporter_ip:String}")
    elif sensor:
        params["sensor"] = sensor
        filters.append("sensor = {sensor:String}")
    resolved_if_index = resolve_dashboard_if_index(sensor_id, interface_id, if_index)
    direction = clean_text(direction).lower() or "both"
    if direction not in {"both", "upload", "download"}:
        raise HTTPException(status_code=400, detail="direction invalida")
    rate_direction = "auto"
    if direction == "upload":
        rate_direction = "output"
        if resolved_if_index is not None:
            params["if_index"] = resolved_if_index
            filters.append("output_if = {if_index:UInt32}")
        else:
            filters.append("output_if > 0")
    elif direction == "download":
        rate_direction = "input"
        if resolved_if_index is not None:
            params["if_index"] = resolved_if_index
            filters.append("input_if = {if_index:UInt32}")
        else:
            filters.append("input_if > 0")
    elif resolved_if_index is not None:
        params["if_index"] = resolved_if_index
        filters.append("(input_if = {if_index:UInt32} OR output_if = {if_index:UInt32})")
    if ip:
        src_ip_condition = build_ip_condition("src_ip", ip, params, "ip_src", "IP")
        dst_ip_condition = build_ip_condition("dst_ip", ip, params, "ip_dst", "IP")
        filters.append(f"({src_ip_condition} OR {dst_ip_condition})")
    if src_ip:
        filters.append(build_ip_condition("src_ip", src_ip, params, "src_ip", "SRC IP"))
    if dst_ip:
        filters.append(build_ip_condition("dst_ip", dst_ip, params, "dst_ip", "DST IP"))
    port_condition = build_any_port_condition(port, params, "port", "Porta")
    if port_condition:
        filters.append(port_condition)
    src_port_condition = build_port_condition("src_port", src_port, params, "src_port", "SRC porta")
    if src_port_condition:
        filters.append(src_port_condition)
    dst_port_condition = build_port_condition("dst_port", dst_port, params, "dst_port", "DST porta")
    if dst_port_condition:
        filters.append(dst_port_condition)
    proto_text = clean_text(proto).lower()
    proto_value = None if proto_text == "other" else parse_proto_filter(proto)
    if proto_text == "other":
        filters.append("proto NOT IN (1, 6, 17, 47, 50, 58)")
    decoder_text = clean_text(decoder).upper()
    decoder_proto: int | None = None
    if decoder_text in {"TCP", "TCP+SYN", "TCP+SYNACK", "TCP+ACK", "TCP+RST", "TCP+NULL", "TCP+ALL", "HTTP", "HTTPS"}:
        decoder_proto = 6
    elif decoder_text in {"UDP", "DNS", "NTP", "QUIC", "UDP+QUIC", "SIP", "NETBIOS", "MEMCACHED"}:
        decoder_proto = 17
    elif decoder_text == "ICMP":
        decoder_proto = 1
    elif decoder_text == "GRE":
        decoder_proto = 47
    elif decoder_text in {"ESP", "IPSEC"}:
        decoder_proto = 50
    if proto_value is None and decoder_proto is not None:
        proto_value = decoder_proto
    if proto_value is not None:
        params["proto"] = proto_value
        filters.append("proto = {proto:UInt8}")
    tcp_flags_value = parse_tcp_flags_filter(tcp_flags)
    if tcp_flags_value is None and decoder_text.startswith("TCP+"):
        decoder_flag = decoder_text.split("+", 1)[1]
        if decoder_flag == "SYNACK":
            tcp_flags_value = 0x12
        elif decoder_flag == "NULL":
            tcp_flags_value = 0
        elif decoder_flag != "ALL":
            tcp_flags_value = parse_tcp_flags_filter(decoder_flag)
    if tcp_flags_value is not None:
        params["tcp_flags"] = tcp_flags_value
        filters.append("tcp_flags = {tcp_flags:UInt16}")
    decoder_ports = {
        "DNS": 53,
        "NTP": 123,
        "HTTP": 80,
        "HTTPS": 443,
        "QUIC": 443,
        "UDP+QUIC": 443,
        "SIP": 5060,
        "NETBIOS": 137,
        "MEMCACHED": 11211,
    }
    if decoder_text in decoder_ports and port is None and src_port is None and dst_port is None:
        params["decoder_port"] = decoder_ports[decoder_text]
        filters.append("(src_port = {decoder_port:UInt16} OR dst_port = {decoder_port:UInt16})")

    return {
        "start": start_dt,
        "end": end_dt,
        "params": params,
        "where": " AND ".join(filters),
        "resolved_if_index": resolved_if_index,
        "rate_direction": rate_direction,
    }


def sort_direction(value: str | None) -> str:
    return "ASC" if clean_text(value).lower() == "asc" else "DESC"


def dashboard_cache_ttl(range_minutes: int) -> int:
    if range_minutes <= 5:
        return 5
    if range_minutes <= 60:
        return 15
    return 60


def dashboard_cache_key(name: str, values: dict[str, Any]) -> str:
    normalized = []
    for key in sorted(values):
        value = values[key]
        if isinstance(value, datetime):
            value = iso(value)
        normalized.append((key, value))
    return json.dumps([name, normalized], sort_keys=True, default=str)


def dashboard_cache_get(key: str, ttl: int) -> dict[str, Any] | None:
    now = time.monotonic()
    with DASHBOARD_RESPONSE_CACHE_LOCK:
        item = DASHBOARD_RESPONSE_CACHE.get(key)
        if not item:
            return None
        created, payload = item
        age = now - created
        if age > ttl:
            DASHBOARD_RESPONSE_CACHE.pop(key, None)
            return None
    cached_payload = dict(payload)
    cached_payload["cached"] = True
    cached_payload["cache_age_seconds"] = round(age, 2)
    return cached_payload


def dashboard_cache_set(key: str, payload: dict[str, Any]) -> dict[str, Any]:
    stored = dict(payload)
    stored["cached"] = False
    stored["cache_age_seconds"] = 0
    with DASHBOARD_RESPONSE_CACHE_LOCK:
        DASHBOARD_RESPONSE_CACHE[key] = (time.monotonic(), stored)
        if len(DASHBOARD_RESPONSE_CACHE) > 256:
            oldest = sorted(DASHBOARD_RESPONSE_CACHE, key=lambda cache_key: DASHBOARD_RESPONSE_CACHE[cache_key][0])[:64]
            for cache_key in oldest:
                DASHBOARD_RESPONSE_CACHE.pop(cache_key, None)
    return dict(stored)


def search_flows_payload(
    range_minutes: int,
    start: datetime | None,
    end: datetime | None,
    start_time: datetime | None,
    end_time: datetime | None,
    sensor: str | None,
    sensor_id: int | None,
    interface_id: int | None,
    if_index: int | None,
    ip: str | None,
    src_ip: str | None,
    dst_ip: str | None,
    port: Any | None,
    src_port: Any | None,
    dst_port: Any | None,
    proto: str | None,
    tcp_flags: str | None,
    decoder: str | None,
    limit: int,
    order_by: str,
    order_dir: str,
) -> dict[str, Any]:
    ensure_clickhouse_schema()
    context = flow_query_context(
        range_minutes,
        start,
        end,
        start_time,
        end_time,
        sensor,
        sensor_id,
        interface_id,
        if_index,
        ip,
        src_ip,
        dst_ip,
        port,
        src_port,
        dst_port,
        proto,
        tcp_flags,
        decoder,
        "both",
    )
    start_dt = context["start"]
    end_dt = context["end"]
    seconds = range_seconds(start_dt, end_dt)
    params = dict(context["params"])
    params.update({"limit": limit, "seconds": seconds})
    factor_expr = clickhouse_sample_rate_expr(sensor_id, "auto", context["resolved_if_index"])
    bytes_value = corrected_value_expr("bytes", factor_expr)
    packets_value = corrected_value_expr("packets", factor_expr)
    sort_column = FLOW_SEARCH_SORT_COLUMNS.get(order_by, "flow_time")
    direction_sql = sort_direction(order_dir)

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
            bytes AS raw_bytes,
            packets AS raw_packets,
            round({bytes_value}) AS bytes,
            round({packets_value}) AS packets,
            flow_count,
            {bytes_value} * 8 / {{seconds:Float64}} AS bits_s,
            {packets_value} / {{seconds:Float64}} AS packets_s,
            flow_type,
            sample_rate,
            {factor_expr} AS sample_rate_applied,
            src_asn,
            dst_asn,
            src_as_name,
            dst_as_name
        FROM flow_raw
        WHERE {context["where"]}
        ORDER BY {sort_column} {direction_sql}
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
        row["bytes"] = int(float(row.get("bytes") or 0))
        row["packets"] = int(float(row.get("packets") or 0))
        row["raw_bytes"] = int(row.get("raw_bytes") or 0)
        row["raw_packets"] = int(row.get("raw_packets") or 0)
        row["flow_count"] = int(row.get("flow_count") or 0)
        row["bits_s"] = round(float(row.get("bits_s") or 0), 2)
        row["packets_s"] = round(float(row.get("packets_s") or 0), 2)
        row["sample_rate_applied"] = round(float(row.get("sample_rate_applied") or 1), 2)
        items.append(row)

    return {
        "start": iso(start_dt),
        "end": iso(end_dt),
        "sensor": sensor,
        "order_by": order_by,
        "order_dir": direction_sql.lower(),
        "items": items,
    }


def flows_csv_response(payload: dict[str, Any]) -> Response:
    output = io.StringIO()
    fields = [
        "flow_time",
        "sensor",
        "exporter_ip",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "proto_name",
        "tcp_flags_name",
        "input_if",
        "output_if",
        "bytes",
        "packets",
        "flow_count",
        "bits_s",
        "packets_s",
        "sample_rate_applied",
        "flow_type",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for item in payload.get("items") or []:
        writer.writerow(item)
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=gmj-flow-search.csv"},
    )


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
    port: str | None = None,
    src_port: str | None = None,
    dst_port: str | None = None,
    proto: str | None = None,
    tcp_flags: str | None = None,
    decoder: str | None = None,
    limit: int = Query(200, ge=1, le=5000),
    order_by: str = "flow_time",
    order_dir: str = "desc",
    format: str | None = None,
):
    payload = search_flows_payload(
        range_minutes,
        start,
        end,
        start_time,
        end_time,
        sensor,
        sensor_id,
        interface_id,
        if_index,
        ip,
        src_ip,
        dst_ip,
        port,
        src_port,
        dst_port,
        proto,
        tcp_flags,
        decoder,
        limit,
        order_by,
        order_dir,
    )
    if clean_text(format).lower() == "csv":
        return flows_csv_response(payload)
    return payload


def top_flow_items_from_rows(
    rows: list[dict[str, Any]],
    top_type: str,
) -> list[dict[str, Any]]:
    def safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default

    def safe_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def row_protocol_label(row: dict[str, Any]) -> str:
        raw_value = (
            row.get("protocol")
            or row.get("proto")
            or row.get("decoder")
            or row.get("sample_proto")
            or "OTHER"
        )
        text = clean_text(raw_value)
        if not text:
            return "OTHER"
        if text.lower() in PROTO_NUMBERS:
            return PROTO_LABELS.get(str(PROTO_NUMBERS[text.lower()]), text.upper())
        try:
            proto_number = int(float(text))
        except ValueError:
            return text.upper()
        if proto_number in {1, 6, 17, 47, 50}:
            return PROTO_LABELS[str(proto_number)]
        return f"IP{proto_number}" if 0 <= proto_number <= 255 else "OTHER"

    items = []
    for index, row in enumerate(rows, start=1):
        try:
            protocol_label = row_protocol_label(row)
            key = clean_text(row.get("key")) or "N/D"
            if top_type in {"src_ip", "dst_ip"}:
                key = clean_ip(key) or "N/D"
            elif top_type == "proto":
                key = protocol_label
            elif top_type == "tcp_flags":
                key = tcp_flags_name(row.get("tcp_flags") if "tcp_flags" in row else key)
            elif top_type in {"asn_src", "asn_dst"}:
                asn = safe_int(row.get("asn"))
                key = asn_label(asn) if asn > 0 else "N/D"
            src_port_value = row.get("src_port") if row.get("src_port") is not None else row.get("sample_src_port")
            dst_port_value = row.get("dst_port") if row.get("dst_port") is not None else row.get("sample_dst_port")
            item = {
                "rank": index,
                "key": key,
                "src_ip": clean_ip(row.get("src_ip")) if row.get("src_ip") is not None else "",
                "dst_ip": clean_ip(row.get("dst_ip")) if row.get("dst_ip") is not None else "",
                "src_port": safe_int(src_port_value),
                "dst_port": safe_int(dst_port_value),
                "protocol": protocol_label,
                "decoder": protocol_label,
                "bits_s": round(safe_float(row.get("bits_s")), 2),
                "packets_s": round(safe_float(row.get("packets_s")), 2),
                "bytes": safe_int(row.get("bytes")),
                "packets": safe_int(row.get("packets")),
                "flows": safe_int(row.get("flows")),
                "percent": round(safe_float(row.get("percent_total") or row.get("percent")), 2),
                "first_seen": iso(row.get("first_seen")) if row.get("first_seen") else "",
                "last_seen": iso(row.get("last_seen")) if row.get("last_seen") else "",
                "duration_seconds": safe_int(row.get("duration_seconds")),
            }
            item["duration_human"] = duration_human(item["duration_seconds"])
            if top_type in {"src_port", "dst_port", "ports"}:
                item["proto"] = protocol_label
                item["protocol"] = protocol_label
                item["decoder"] = protocol_label
                item["port"] = safe_int(row.get("port"))
                item["key"] = f"{item['proto']}/{item['port']}"
            elif top_type != "conversation":
                item["src_port"] = 0
                item["dst_port"] = 0
            if top_type == "conversation":
                item["src_ip"] = clean_ip(row.get("src_ip")) or "N/D"
                item["dst_ip"] = clean_ip(row.get("dst_ip")) or "N/D"
                item["key"] = (
                    f"{item['src_ip']}:{item['src_port']} -> "
                    f"{item['dst_ip']}:{item['dst_port']}"
                )
            if top_type in {"input_if", "output_if"}:
                item["if_index"] = safe_int(row.get("if_index"))
                item["key"] = f"ifIndex {item['if_index']}"
            if top_type in {"asn_src", "asn_dst"}:
                item["description"] = clean_text(row.get("as_name")) or "-"
                item["country"] = clean_text(row.get("country")).upper() or "N/D"
            items.append(item)
        except Exception as exc:
            logger.warning("Ignorando linha invalida em /api/flows/top (%s): %s", top_type, exc)
    return items


@app.get("/api/flows/top")
def top_flows(
    top_type: str = Query("src_ip"),
    direction: str = Query("both"),
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
    port: str | None = None,
    src_port: str | None = None,
    dst_port: str | None = None,
    proto: str | None = None,
    tcp_flags: str | None = None,
    decoder: str | None = None,
    limit: int = Query(10, ge=1, le=100),
    order_by: str = "bits_s",
    order_dir: str = "desc",
):
    ensure_clickhouse_schema()
    top_type = clean_text(top_type).lower().replace("-", "_")
    top_type = TOP_FLOW_TYPE_ALIASES.get(top_type, top_type)
    if top_type not in TOP_FLOW_TYPES:
        raise HTTPException(status_code=400, detail="top_type invalido")
    if order_by not in TOP_FLOW_SORT_COLUMNS:
        order_by = "bits_s"
    context = flow_query_context(
        range_minutes,
        start,
        end,
        start_time,
        end_time,
        sensor,
        sensor_id,
        interface_id,
        if_index,
        ip,
        src_ip,
        dst_ip,
        port,
        src_port,
        dst_port,
        proto,
        tcp_flags,
        decoder,
        direction,
    )
    start_dt = context["start"]
    end_dt = context["end"]
    seconds = range_seconds(start_dt, end_dt)
    params = dict(context["params"])
    params.update({"seconds": seconds, "limit": limit})
    direction_sql = sort_direction(order_dir)
    order_expr = TOP_FLOW_SORT_COLUMNS[order_by]
    factor_expr = clickhouse_sample_rate_expr(
        sensor_id,
        context["rate_direction"],
        context["resolved_if_index"],
    )

    def final_top_query(raw_sql: str, select_cols: str, group_by: str) -> str:
        return f"""
        WITH
            base AS (
                SELECT
                    {select_cols},
                    any(raw_proto) AS sample_proto,
                    any(raw_src_port) AS sample_src_port,
                    any(raw_dst_port) AS sample_dst_port,
                    min(flow_time) AS first_seen,
                    max(flow_time) AS last_seen,
                    sum(bytes_value) AS bytes,
                    sum(packets_value) AS packets,
                    sum(flow_count) AS flows
                FROM (
                    {raw_sql}
                )
                GROUP BY {group_by}
            ),
            totals AS (
                SELECT
                    sum(bytes) AS total_bytes,
                    sum(packets) AS total_packets,
                    sum(flows) AS total_flows
                FROM base
            )
        SELECT
            base.*,
            bytes * 8 / {{seconds:Float64}} AS bits_s,
            packets / {{seconds:Float64}} AS packets_s,
            if(total_bytes > 0, bytes / total_bytes * 100, 0) AS percent_total,
            dateDiff('second', first_seen, last_seen) AS duration_seconds
        FROM base
        CROSS JOIN totals
        ORDER BY {order_expr} {direction_sql}
        LIMIT {{limit:UInt32}}
        """

    def raw_select(dimension_cols: str, rate_expr: str = factor_expr, where: str | None = None) -> str:
        return f"""
            SELECT
                {dimension_cols},
                {corrected_value_expr('bytes', rate_expr)} AS bytes_value,
                {corrected_value_expr('packets', rate_expr)} AS packets_value,
                flow_count,
                flow_time,
                src_port AS raw_src_port,
                dst_port AS raw_dst_port,
                proto AS raw_proto
            FROM flow_raw
            WHERE {where or context["where"]}
        """

    if top_type in {"asn_src", "asn_dst"}:
        ip_col = "src_ip" if top_type == "asn_src" else "dst_ip"
        asn_col = "src_asn" if top_type == "asn_src" else "dst_asn"
        as_name_col = "src_as_name" if top_type == "asn_src" else "dst_as_name"
        params["asn_ip_limit"] = max(200, min(5000, limit * 50))
        query = final_top_query(
            raw_select(
                f"toString({ip_col}) AS ip, toUInt32({asn_col}) AS flow_asn, {as_name_col} AS flow_as_name",
            ),
            "ip, flow_asn, any(flow_as_name) AS flow_as_name",
            "ip, flow_asn",
        ).replace("LIMIT {limit:UInt32}", "LIMIT {asn_ip_limit:UInt32}")
        result_rows = rows_as_dicts(query_clickhouse(query, params))
        grouped: dict[int, dict[str, Any]] = {}
        unresolved = {
            "asn": 0,
            "key": "0",
            "as_name": "ASN indisponivel",
            "country": "N/D",
            "bytes": 0.0,
            "packets": 0.0,
            "flows": 0,
            "bits_s": 0.0,
            "packets_s": 0.0,
            "percent_total": 0.0,
        }
        for row in result_rows:
            asn = int(row.get("flow_asn") or 0)
            as_name = clean_text(row.get("flow_as_name"))
            country = ""
            source = "flow"
            if asn > 0:
                info = lookup_asn_info(asn)
                if info:
                    as_name = as_name or clean_text(info.get("as_name"))
                    country = clean_text(info.get("country"))
                    source = clean_text(info.get("source")) or "flow"
                elif not as_name:
                    queue_missing_asn_info(asn)
            else:
                resolved = resolve_asn_for_ip(clean_ip(row.get("ip")))
                asn = int(resolved.get("asn") or 0)
                as_name = clean_text(resolved.get("as_name"))
                country = clean_text(resolved.get("country"))
                source = clean_text(resolved.get("source")) or "unresolved"
            target = unresolved if asn <= 0 else grouped.setdefault(
                asn,
                {
                    "asn": asn,
                    "key": str(asn),
                    "as_name": as_name or "-",
                    "country": country.upper() or "N/D",
                    "source": source,
                    "bytes": 0.0,
                    "packets": 0.0,
                    "flows": 0,
                    "bits_s": 0.0,
                    "packets_s": 0.0,
                    "percent_total": 0.0,
                },
            )
            if target is not unresolved:
                target["as_name"] = target.get("as_name") or as_name or "-"
                target["country"] = (target.get("country") if target.get("country") != "N/D" else country.upper()) or "N/D"
            target["bytes"] += float(row.get("bytes") or 0)
            target["packets"] += float(row.get("packets") or 0)
            target["flows"] += int(row.get("flows") or 0)
            target["bits_s"] += float(row.get("bits_s") or 0)
            target["packets_s"] += float(row.get("packets_s") or 0)
            target["percent_total"] += float(row.get("percent_total") or 0)
        grouped_rows = list(grouped.values())
        if unresolved["bytes"] > 0:
            grouped_rows.append(unresolved)
        reverse = direction_sql == "DESC"
        if order_by == "key":
            grouped_rows.sort(key=lambda item: item["key"], reverse=reverse)
        else:
            grouped_rows.sort(key=lambda item: float(item.get(order_by if order_by != "percent" else "percent_total") or 0), reverse=reverse)
        result_rows = grouped_rows[:limit]
    else:
        if top_type == "src_ip":
            raw_sql = raw_select("toString(src_ip) AS key")
            select_expr = "key"
            group_by = "key"
        elif top_type == "dst_ip":
            raw_sql = raw_select("toString(dst_ip) AS key")
            select_expr = "key"
            group_by = "key"
        elif top_type == "conversation":
            raw_sql = raw_select(
                "toString(src_ip) AS src_ip, toString(dst_ip) AS dst_ip, "
                "src_port, dst_port, proto, "
                "concat(toString(src_ip), ':', toString(src_port), ' -> ', toString(dst_ip), ':', toString(dst_port)) AS key"
            )
            select_expr = "src_ip, dst_ip, src_port, dst_port, proto, key"
            group_by = "src_ip, dst_ip, src_port, dst_port, proto, key"
        elif top_type == "src_port":
            raw_sql = raw_select("src_port AS port, proto, toString(src_port) AS key")
            select_expr = "port, proto, key"
            group_by = "port, proto, key"
        elif top_type == "dst_port":
            raw_sql = raw_select("dst_port AS port, proto, toString(dst_port) AS key")
            select_expr = "port, proto, key"
            group_by = "port, proto, key"
        elif top_type == "ports":
            raw_sql = f"""
                {raw_select("src_port AS port, proto, toString(src_port) AS key")}
                UNION ALL
                {raw_select("dst_port AS port, proto, toString(dst_port) AS key")}
            """
            select_expr = "port, proto, key"
            group_by = "port, proto, key"
        elif top_type == "proto":
            raw_sql = raw_select("proto, toString(proto) AS key")
            select_expr = "proto, key"
            group_by = "proto, key"
        elif top_type == "tcp_flags":
            raw_sql = raw_select("tcp_flags, toString(tcp_flags) AS key")
            select_expr = "tcp_flags, key"
            group_by = "tcp_flags, key"
        elif top_type == "input_if":
            raw_sql = raw_select("input_if AS if_index, toString(input_if) AS key")
            select_expr = "if_index, key"
            group_by = "if_index, key"
        elif top_type == "output_if":
            raw_sql = raw_select("output_if AS if_index, toString(output_if) AS key")
            select_expr = "if_index, key"
            group_by = "if_index, key"
        else:
            raw_sql = f"""
                {raw_select("concat('Download if ', toString(input_if)) AS key", clickhouse_sample_rate_expr(sensor_id, "input", context["resolved_if_index"]), f"{context['where']} AND input_if > 0")}
                UNION ALL
                {raw_select("concat('Upload if ', toString(output_if)) AS key", clickhouse_sample_rate_expr(sensor_id, "output", context["resolved_if_index"]), f"{context['where']} AND output_if > 0")}
            """
            select_expr = "key"
            group_by = "key"
        result_rows = rows_as_dicts(query_clickhouse(final_top_query(raw_sql, select_expr, group_by), params))

    items = top_flow_items_from_rows(result_rows, top_type)
    return {
        "start": iso(start_dt),
        "end": iso(end_dt),
        "top_type": top_type,
        "direction": clean_text(direction).lower() or "both",
        "order_by": order_by,
        "order_dir": direction_sql.lower(),
        "items": items,
    }
