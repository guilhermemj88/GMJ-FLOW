"""Configurable flow codec registry (service/traffic classification).

A codec is a *classification* of a flow, never a whitelist and never a verdict:
it does not change Attack Vectors, scores, or mitigation in this phase.

Matching semantics:
- ``protocol``: ``ANY`` or an IP protocol name (TCP/UDP/ICMP/ICMPV6/GRE/ESP/AH).
- ``source_port`` / ``destination_port``: ``NULL`` or ``0`` = ANY, otherwise exact.
- ``direction``: reuses Network Assets ``SERVICE_DIRECTIONS`` vocabulary.
- ``tcp_flags``: ``NULL``/``0`` = ANY, otherwise a bitmask the flow must satisfy.
- ``icmp_type`` / ``icmp_code``: ``NULL`` = ANY, otherwise exact (0 is literal).
- ``source_role`` / ``destination_role`` / ``provider``: empty = ANY.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Iterable, Mapping, Sequence

from app.services.network_assets import SERVICE_DIRECTIONS, NETWORK_ROLES
from app.services.threat_intelligence import clean_text, sqlite_connection, utc_now_iso

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------
PROTOCOL_ANY = "ANY"

PROTOCOL_BY_NAME = {
    "ANY": 0,
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
    "ICMPV6": 58,
    "GRE": 47,
    "ESP": 50,
    "AH": 51,
}

PROTOCOL_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPV6", 47: "GRE", 50: "ESP", 51: "AH"}

FLOW_CODEC_PROTOCOLS = frozenset(PROTOCOL_BY_NAME.keys())

# Direction is derived from Network Assets roles when a flow has no explicit
# direction and contexts are provided.
_CUSTOMER_ROLES = {"CUSTOMER_PUBLIC", "CGNAT_POOL"}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_port(value: Any) -> int | None:
    """Normalize a port spec: None/0/'' -> None (ANY); else 0..65535."""
    if value is None or value == "":
        return None
    port = _safe_int(value, default=-1)
    if port < 0 or port > 65535:
        raise ValueError(f"porta inválida: {value}")
    return port if port > 0 else None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return _safe_int(value)


# ---------------------------------------------------------------------------
# Schema + seed
# ---------------------------------------------------------------------------
def ensure_flow_codecs_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS flow_codecs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            protocol TEXT NOT NULL DEFAULT 'ANY',
            source_port INTEGER,
            destination_port INTEGER,
            direction TEXT NOT NULL DEFAULT 'ANY',
            tcp_flags INTEGER,
            icmp_type INTEGER,
            icmp_code INTEGER,
            source_role TEXT NOT NULL DEFAULT '',
            destination_role TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL DEFAULT '',
            specificity_priority INTEGER NOT NULL DEFAULT 0,
            exclusive_group TEXT NOT NULL DEFAULT '',
            consume_traffic INTEGER NOT NULL DEFAULT 0,
            builtin INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )


def flow_codec_row_to_dict(row: Mapping[str, Any] | sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item.get("id") or 0),
        "name": clean_text(item.get("name")),
        "display_name": clean_text(item.get("display_name")),
        "description": clean_text(item.get("description")),
        "protocol": clean_text(item.get("protocol")).upper() or PROTOCOL_ANY,
        "source_port": item.get("source_port"),
        "destination_port": item.get("destination_port"),
        "direction": clean_text(item.get("direction")).upper() or "ANY",
        "tcp_flags": item.get("tcp_flags"),
        "icmp_type": item.get("icmp_type"),
        "icmp_code": item.get("icmp_code"),
        "source_role": clean_text(item.get("source_role")).upper(),
        "destination_role": clean_text(item.get("destination_role")).upper(),
        "provider": clean_text(item.get("provider")).upper(),
        "specificity_priority": int(item.get("specificity_priority") or 0),
        "exclusive_group": clean_text(item.get("exclusive_group")),
        "consume_traffic": int(item.get("consume_traffic") or 0),
        "builtin": int(item.get("builtin") or 0),
        "active": int(item.get("active") or 0),
        "created_at": clean_text(item.get("created_at")),
        "updated_at": clean_text(item.get("updated_at")),
    }


# (name, display_name, protocol, source_port, destination_port, direction,
#  specificity_priority, exclusive_group, consume_traffic, description)
#
# Description is classification guidance only: a codec match is never a
# whitelist, never a verdict and never an authorization. The port-443 codecs
# explicitly state that context (not the port alone) decides the signal.
BUILTIN_CODECS: tuple[tuple[str, str, str, int | None, int | None, str, int, str, int, str], ...] = (
    ("DNS_QUERY_UDP", "DNS query (UDP)", "UDP", None, 53, "ANY", 100, "UDP_SERVICE", 1,
     "Identifica consulta DNS via UDP (destino 53). Classificação de tráfego, não whitelist nem veredito."),
    ("DNS_RESPONSE_UDP", "DNS response (UDP)", "UDP", 53, None, "ANY", 100, "UDP_SERVICE", 1,
     "Identifica resposta DNS via UDP (origem 53)."),
    ("DNS_QUERY_TCP", "DNS query (TCP)", "TCP", None, 53, "ANY", 100, "TCP_SERVICE", 1,
     "Identifica consulta DNS via TCP (destino 53)."),
    ("DNS_RESPONSE_TCP", "DNS response (TCP)", "TCP", 53, None, "ANY", 100, "TCP_SERVICE", 1,
     "Identifica resposta DNS via TCP (origem 53)."),
    ("NTP_QUERY", "NTP query", "UDP", None, 123, "ANY", 90, "UDP_SERVICE", 1,
     "Identifica consulta NTP via UDP (destino 123)."),
    ("NTP_RESPONSE", "NTP response", "UDP", 123, None, "ANY", 90, "UDP_SERVICE", 1,
     "Identifica resposta NTP via UDP (origem 123)."),
    ("SSDP_QUERY", "SSDP query", "UDP", None, 1900, "ANY", 80, "UDP_SERVICE", 1,
     "Identifica consulta SSDP via UDP (destino 1900)."),
    ("SSDP_RESPONSE", "SSDP response", "UDP", 1900, None, "ANY", 80, "UDP_SERVICE", 1,
     "Identifica resposta SSDP via UDP (origem 1900)."),
    ("CLDAP_QUERY", "CLDAP query", "UDP", None, 389, "ANY", 80, "UDP_SERVICE", 1,
     "Identifica consulta CLDAP via UDP (destino 389)."),
    ("CLDAP_RESPONSE", "CLDAP response", "UDP", 389, None, "ANY", 80, "UDP_SERVICE", 1,
     "Identifica resposta CLDAP via UDP (origem 389)."),
    ("CHARGEN_QUERY", "CHARGEN query", "UDP", None, 19, "ANY", 70, "UDP_SERVICE", 1,
     "Identifica consulta CHARGEN via UDP (destino 19)."),
    ("CHARGEN_RESPONSE", "CHARGEN response", "UDP", 19, None, "ANY", 70, "UDP_SERVICE", 1,
     "Identifica resposta CHARGEN via UDP (origem 19)."),
    ("SNMP_QUERY", "SNMP query", "UDP", None, 161, "ANY", 70, "UDP_SERVICE", 1,
     "Identifica consulta SNMP via UDP (destino 161)."),
    ("SNMP_RESPONSE", "SNMP response", "UDP", 161, None, "ANY", 70, "UDP_SERVICE", 1,
     "Identifica resposta SNMP via UDP (origem 161)."),
    ("MEMCACHED_QUERY", "Memcached query", "UDP", None, 11211, "ANY", 70, "UDP_SERVICE", 1,
     "Identifica consulta Memcached via UDP (destino 11211)."),
    ("MEMCACHED_RESPONSE", "Memcached response", "UDP", 11211, None, "ANY", 70, "UDP_SERVICE", 1,
     "Identifica resposta Memcached via UDP (origem 11211)."),
    ("QUIC_CLIENT", "QUIC client", "UDP", None, 443, "ANY", 90, "UDP_SERVICE", 1,
     "Identifica tráfego UDP com destino 443 (cliente QUIC). Apenas classificação por porta; não implica legitimidade."),
    ("QUIC_RETURN", "QUIC return", "UDP", 443, None, "ANY", 90, "UDP_SERVICE", 1,
     "Identifica tráfego compatível com retorno QUIC por porta (UDP origem 443). Não implica legitimidade sem contexto de Network Asset / Expected Service."),
    ("HTTP_CLIENT", "HTTP client", "TCP", None, 80, "ANY", 90, "TCP_SERVICE", 1,
     "Identifica tráfego TCP com destino 80 (cliente HTTP)."),
    ("HTTP_RETURN", "HTTP return", "TCP", 80, None, "ANY", 90, "TCP_SERVICE", 1,
     "Identifica retorno TCP de serviço HTTP (origem 80). ACK/PSH+ACK e direção são usados em contexto comportamental."),
    ("HTTPS_CLIENT", "HTTPS client", "TCP", None, 443, "ANY", 90, "TCP_SERVICE", 1,
     "Identifica tráfego TCP com destino 443 (cliente HTTPS). Não reduz score por si só."),
    ("HTTPS_RETURN", "HTTPS return", "TCP", 443, None, "ANY", 90, "TCP_SERVICE", 1,
     "Identifica retorno TCP de serviço HTTPS (origem 443). ACK/PSH+ACK e direção são usados em contexto comportamental."),
)


def seed_builtin_flow_codecs(conn: sqlite3.Connection) -> int:
    """Idempotent seed of builtin codecs. Returns number of rows inserted.

    Existing builtin rows get their description backfilled only when empty, so
    operator-edited metadata (display_name/description/active) is preserved.
    """
    ensure_flow_codecs_schema(conn)
    inserted = 0
    now = utc_now_iso()
    for name, display_name, protocol, src, dst, direction, priority, group, consume, description in BUILTIN_CODECS:
        exists = conn.execute("SELECT id FROM flow_codecs WHERE name = ?", (name,)).fetchone()
        if exists is not None:
            conn.execute(
                """
                UPDATE flow_codecs SET description = ?
                WHERE name = ? AND builtin = 1 AND (description IS NULL OR description = '')
                """,
                (description, name),
            )
            continue
        conn.execute(
            """
            INSERT INTO flow_codecs (
                name, display_name, description, protocol, source_port, destination_port,
                direction, tcp_flags, icmp_type, icmp_code, source_role, destination_role,
                provider, specificity_priority, exclusive_group, consume_traffic, builtin,
                active, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, '', '', '', ?, ?, ?, 1, 1, ?, ?)
            """,
            (name, display_name, description, protocol, src, dst, direction, priority, group, consume, now, now),
        )
        inserted += 1
    return inserted


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------
def list_flow_codecs(conn: sqlite3.Connection, *, active_only: bool = False) -> list[dict[str, Any]]:
    sql = "SELECT * FROM flow_codecs"
    if active_only:
        sql += " WHERE active = 1"
    sql += " ORDER BY specificity_priority DESC, id ASC"
    return [flow_codec_row_to_dict(row) for row in conn.execute(sql).fetchall()]


def get_flow_codec(conn: sqlite3.Connection, codec_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM flow_codecs WHERE id = ?", (int(codec_id),)).fetchone()
    return flow_codec_row_to_dict(row) if row is not None else None


def _normalize_codec_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    name = clean_text(payload.get("name"))
    if not name:
        raise ValueError("name é obrigatório")
    protocol = clean_text(payload.get("protocol")).upper() or PROTOCOL_ANY
    if protocol not in FLOW_CODEC_PROTOCOLS:
        raise ValueError(f"protocolo inválido: {protocol}")
    direction = clean_text(payload.get("direction")).upper() or "ANY"
    if direction not in SERVICE_DIRECTIONS:
        raise ValueError(f"direção inválida: {direction}")
    source_role = clean_text(payload.get("source_role")).upper()
    if source_role and source_role not in NETWORK_ROLES:
        raise ValueError(f"source_role inválido: {source_role}")
    destination_role = clean_text(payload.get("destination_role")).upper()
    if destination_role and destination_role not in NETWORK_ROLES:
        raise ValueError(f"destination_role inválido: {destination_role}")
    priority = _safe_int(payload.get("specificity_priority"), default=0)
    return {
        "name": name,
        "display_name": clean_text(payload.get("display_name")),
        "description": clean_text(payload.get("description")),
        "protocol": protocol,
        "source_port": _safe_port(payload.get("source_port")),
        "destination_port": _safe_port(payload.get("destination_port")),
        "direction": direction,
        "tcp_flags": _optional_int(payload.get("tcp_flags")),
        "icmp_type": _optional_int(payload.get("icmp_type")),
        "icmp_code": _optional_int(payload.get("icmp_code")),
        "source_role": source_role,
        "destination_role": destination_role,
        "provider": clean_text(payload.get("provider")).upper(),
        "specificity_priority": priority,
        "exclusive_group": clean_text(payload.get("exclusive_group")),
        "consume_traffic": 1 if payload.get("consume_traffic") else 0,
        "active": int(payload.get("active") if payload.get("active") is not None else 1),
    }


def _name_conflicts(conn: sqlite3.Connection, name: str, exclude_id: int | None = None) -> bool:
    sql = "SELECT id FROM flow_codecs WHERE name = ?"
    params: tuple[Any, ...] = (name,)
    if exclude_id is not None:
        sql += " AND id != ?"
        params = (name, int(exclude_id))
    return conn.execute(sql, params).fetchone() is not None


def create_flow_codec(conn: sqlite3.Connection, payload: Mapping[str, Any]) -> dict[str, Any]:
    fields = _normalize_codec_payload(payload)
    if _name_conflicts(conn, fields["name"]):
        raise ValueError("já existe um codec com esse nome")
    now = utc_now_iso()
    cursor = conn.execute(
        """
        INSERT INTO flow_codecs (
            name, display_name, description, protocol, source_port, destination_port,
            direction, tcp_flags, icmp_type, icmp_code, source_role, destination_role,
            provider, specificity_priority, exclusive_group, consume_traffic, builtin,
            active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
        """,
        (
            fields["name"], fields["display_name"], fields["description"], fields["protocol"],
            fields["source_port"], fields["destination_port"], fields["direction"],
            fields["tcp_flags"], fields["icmp_type"], fields["icmp_code"],
            fields["source_role"], fields["destination_role"], fields["provider"],
            fields["specificity_priority"], fields["exclusive_group"], fields["consume_traffic"],
            fields["active"], now, now,
        ),
    )
    return get_flow_codec(conn, int(cursor.lastrowid)) or {}


def update_flow_codec(
    conn: sqlite3.Connection,
    codec_id: int,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    existing = get_flow_codec(conn, codec_id)
    if existing is None:
        raise LookupError("codec não encontrado")
    fields = _normalize_codec_payload(payload)
    if _name_conflicts(conn, fields["name"], exclude_id=codec_id):
        raise ValueError("já existe um codec com esse nome")
    if existing["builtin"]:
        # Builtin identity is protected; only metadata/activation are editable.
        # Only identity keys *explicitly provided* and actually changed block.
        identity_keys = {
            "name", "protocol", "source_port", "destination_port", "direction",
            "tcp_flags", "icmp_type", "icmp_code", "source_role", "destination_role", "provider",
        }
        changed = [
            key for key in identity_keys
            if key in payload and fields.get(key) != existing.get(key)
        ]
        if changed:
            raise ValueError(f"codec builtin não permite alterar identidade: {', '.join(sorted(changed))}")
    # Merge: fields not present in the payload keep their existing value.
    merged = dict(existing)
    provided_keys = set(payload.keys())
    for key, value in fields.items():
        if key in provided_keys:
            merged[key] = value
    now = utc_now_iso()
    conn.execute(
        """
        UPDATE flow_codecs SET
            name = ?, display_name = ?, description = ?, protocol = ?, source_port = ?,
            destination_port = ?, direction = ?, tcp_flags = ?, icmp_type = ?, icmp_code = ?,
            source_role = ?, destination_role = ?, provider = ?, specificity_priority = ?,
            exclusive_group = ?, consume_traffic = ?, active = ?, updated_at = ?
        WHERE id = ?
        """,
        (
            merged["name"], merged["display_name"], merged["description"], merged["protocol"],
            merged["source_port"], merged["destination_port"], merged["direction"],
            merged["tcp_flags"], merged["icmp_type"], merged["icmp_code"],
            merged["source_role"], merged["destination_role"], merged["provider"],
            merged["specificity_priority"], merged["exclusive_group"], merged["consume_traffic"],
            merged["active"], now, int(codec_id),
        ),
    )
    return get_flow_codec(conn, codec_id) or {}


def delete_flow_codec(conn: sqlite3.Connection, codec_id: int) -> tuple[bool, str]:
    existing = get_flow_codec(conn, codec_id)
    if existing is None:
        return False, "not_found"
    if existing["builtin"]:
        return False, "builtin_protected"
    conn.execute("DELETE FROM flow_codecs WHERE id = ?", (int(codec_id),))
    return True, "deleted"


def duplicate_flow_codec(conn: sqlite3.Connection, codec_id: int) -> dict[str, Any]:
    existing = get_flow_codec(conn, codec_id)
    if existing is None:
        raise LookupError("codec não encontrado")
    now = utc_now_iso()
    name = clean_text(existing["name"])
    base = name
    index = 1
    while _name_conflicts(conn, name):
        index += 1
        name = f"{base}_COPY_{index}"
    cursor = conn.execute(
        """
        INSERT INTO flow_codecs (
            name, display_name, description, protocol, source_port, destination_port,
            direction, tcp_flags, icmp_type, icmp_code, source_role, destination_role,
            provider, specificity_priority, exclusive_group, consume_traffic, builtin,
            active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
        """,
        (
            name, existing["display_name"], existing["description"], existing["protocol"],
            existing["source_port"], existing["destination_port"], existing["direction"],
            existing["tcp_flags"], existing["icmp_type"], existing["icmp_code"],
            existing["source_role"], existing["destination_role"], existing["provider"],
            existing["specificity_priority"], existing["exclusive_group"], existing["consume_traffic"],
            existing["active"], now, now,
        ),
    )
    return get_flow_codec(conn, int(cursor.lastrowid)) or {}


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------
def _flow_get(flow: Any, key: str, mapping: bool | None = None) -> Any:
    if isinstance(flow, Mapping):
        return flow.get(key)
    return getattr(flow, key, None)


def _flow_protocol(flow: Any) -> int:
    raw = _flow_get(flow, "protocol")
    if raw is None:
        return 0
    if isinstance(raw, str):
        return PROTOCOL_BY_NAME.get(clean_text(raw).upper(), 0)
    return _safe_int(raw)


def _flow_direction(flow: Any, source_context: Mapping[str, Any] | None, destination_context: Mapping[str, Any] | None) -> str:
    explicit = _flow_get(flow, "direction")
    if explicit is not None and clean_text(explicit):
        return clean_text(explicit).upper()
    src_role = clean_text((source_context or {}).get("role")).upper()
    dst_role = clean_text((destination_context or {}).get("role")).upper()
    if dst_role in _CUSTOMER_ROLES:
        return "TO_CUSTOMERS"
    if src_role in _CUSTOMER_ROLES:
        return "FROM_CUSTOMERS"
    return "ANY"


def _port_matches(spec: Any, observed: Any) -> bool:
    if spec is None or _safe_int(spec) <= 0:
        return True
    return _safe_int(spec) == _safe_int(observed)


def _context_role(context: Mapping[str, Any] | None) -> str:
    return clean_text((context or {}).get("role")).upper()


def _context_provider(context: Mapping[str, Any] | None) -> str:
    return clean_text((context or {}).get("provider")).upper()


def match_flow_codec(
    flow: Any,
    codec: Mapping[str, Any],
    source_context: Mapping[str, Any] | None = None,
    destination_context: Mapping[str, Any] | None = None,
) -> bool:
    """True when `flow` is compatible with the codec's classification tuple."""
    codec_protocol = clean_text(codec.get("protocol")).upper() or PROTOCOL_ANY
    if codec_protocol != PROTOCOL_ANY and PROTOCOL_BY_NAME.get(codec_protocol) != _flow_protocol(flow):
        return False
    src_port = _flow_get(flow, "src_port") if not isinstance(flow, Mapping) else _flow_get(flow, "source_port")
    dst_port = _flow_get(flow, "dst_port") if not isinstance(flow, Mapping) else _flow_get(flow, "destination_port")
    if not _port_matches(codec.get("source_port"), src_port):
        return False
    if not _port_matches(codec.get("destination_port"), dst_port):
        return False
    codec_direction = clean_text(codec.get("direction")).upper() or "ANY"
    observed_direction = _flow_direction(flow, source_context, destination_context)
    if codec_direction != "ANY" and codec_direction != observed_direction:
        return False
    tcp_flags = codec.get("tcp_flags")
    if tcp_flags is not None and _safe_int(tcp_flags) != 0:
        observed_flags = _safe_int(_flow_get(flow, "tcp_flags"))
        if observed_flags & _safe_int(tcp_flags) != _safe_int(tcp_flags):
            return False
    icmp_type = codec.get("icmp_type")
    if icmp_type is not None and _safe_int(icmp_type) != _safe_int(_flow_get(flow, "icmp_type")):
        return False
    icmp_code = codec.get("icmp_code")
    if icmp_code is not None and _safe_int(icmp_code) != _safe_int(_flow_get(flow, "icmp_code")):
        return False
    source_role = clean_text(codec.get("source_role")).upper()
    if source_role and source_role != _context_role(source_context):
        return False
    destination_role = clean_text(codec.get("destination_role")).upper()
    if destination_role and destination_role != _context_role(destination_context):
        return False
    provider = clean_text(codec.get("provider")).upper()
    if provider and provider != _context_provider(source_context):
        return False
    return True


def _codec_specificity(codec: Mapping[str, Any]) -> int:
    count = 0
    if clean_text(codec.get("protocol")).upper() not in {"", PROTOCOL_ANY}:
        count += 1
    if codec.get("source_port") is not None and _safe_int(codec.get("source_port")) > 0:
        count += 1
    if codec.get("destination_port") is not None and _safe_int(codec.get("destination_port")) > 0:
        count += 1
    if clean_text(codec.get("direction")).upper() not in {"", "ANY"}:
        count += 1
    if codec.get("tcp_flags") is not None and _safe_int(codec.get("tcp_flags")) != 0:
        count += 1
    if codec.get("icmp_type") is not None:
        count += 1
    if codec.get("icmp_code") is not None:
        count += 1
    if clean_text(codec.get("source_role")):
        count += 1
    if clean_text(codec.get("destination_role")):
        count += 1
    if clean_text(codec.get("provider")):
        count += 1
    return count


def classify_flow_codecs(
    flow: Any,
    codecs: Sequence[Mapping[str, Any]],
    source_context: Mapping[str, Any] | None = None,
    destination_context: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return all active matching codecs, ordered by priority then specificity.

    Multiple matches are all returned (no silent single-codec selection)."""
    matches = [
        codec
        for codec in codecs
        if int(codec.get("active", 1)) == 1
        and match_flow_codec(flow, codec, source_context, destination_context)
    ]
    matches.sort(
        key=lambda codec: (
            -_safe_int(codec.get("specificity_priority")),
            -_codec_specificity(codec),
            _safe_int(codec.get("id")),
        )
    )
    return [dict(codec) for codec in matches]


def flow_codec_options() -> dict[str, Any]:
    """Static option lists so the frontend does not hardcode vocabularies."""
    return {
        "protocols": sorted(FLOW_CODEC_PROTOCOLS),
        "directions": sorted(SERVICE_DIRECTIONS),
        "roles": sorted(NETWORK_ROLES),
        "exclusive_groups": sorted({group for group in (
            codec[7] for codec in BUILTIN_CODECS
        ) if group}),
    }


__all__ = [
    "PROTOCOL_ANY",
    "PROTOCOL_BY_NAME",
    "PROTOCOL_NAMES",
    "FLOW_CODEC_PROTOCOLS",
    "BUILTIN_CODECS",
    "ensure_flow_codecs_schema",
    "seed_builtin_flow_codecs",
    "flow_codec_row_to_dict",
    "list_flow_codecs",
    "get_flow_codec",
    "create_flow_codec",
    "update_flow_codec",
    "delete_flow_codec",
    "duplicate_flow_codec",
    "match_flow_codec",
    "classify_flow_codecs",
    "flow_codec_options",
]
