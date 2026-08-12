from __future__ import annotations

import sqlite3
from dataclasses import asdict, dataclass
from ipaddress import ip_address, ip_network
from typing import Any, Callable, Iterable, Mapping

from app.services.threat_intelligence import clean_text, safe_json, sqlite_connection


CUSTOMER = "CUSTOMER"
CGNAT_PUBLIC = "CGNAT_PUBLIC"
INFRASTRUCTURE = "INFRASTRUCTURE"
MANAGEMENT = "MANAGEMENT"
TRANSIT = "TRANSIT"
PEERING = "PEERING"
EXTERNAL = "EXTERNAL"
UNKNOWN = "UNKNOWN"

NETWORK_ROLES = {
    CUSTOMER,
    CGNAT_PUBLIC,
    INFRASTRUCTURE,
    MANAGEMENT,
    TRANSIT,
    PEERING,
    EXTERNAL,
    UNKNOWN,
}
LOCAL_ROLES = {CUSTOMER, CGNAT_PUBLIC, INFRASTRUCTURE, MANAGEMENT}
EDGE_ROLES = {TRANSIT, PEERING}

PREFIX_TYPE_ROLES = {
    "client": CUSTOMER,
    "public_cgnat": CGNAT_PUBLIC,
    "infrastructure": INFRASTRUCTURE,
    "server": INFRASTRUCTURE,
    "cache": INFRASTRUCTURE,
    "transit": TRANSIT,
    "management": MANAGEMENT,
    "peering": PEERING,
}

CONTEXT_TYPE_ROLES = {
    "CGNAT": CGNAT_PUBLIC,
    "CGNAT_PUBLIC": CGNAT_PUBLIC,
    "INTERNAL": INFRASTRUCTURE,
    "INFRASTRUCTURE": INFRASTRUCTURE,
    "BRAS": INFRASTRUCTURE,
    "MANAGEMENT": MANAGEMENT,
    "TRANSIT": TRANSIT,
    "PEERING": PEERING,
    "INTERNET": EXTERNAL,
    "EXTERNAL": EXTERNAL,
    "CUSTOMER": CUSTOMER,
}


@dataclass(frozen=True)
class NetworkContext:
    src_role: str = UNKNOWN
    dst_role: str = UNKNOWN
    src_is_cgnat: bool = False
    dst_is_cgnat: bool = False
    src_prefix: str = ""
    dst_prefix: str = ""
    traffic_direction: str = UNKNOWN
    input_if: int = 0
    output_if: int = 0
    sensor: str = ""
    exporter: str = ""
    matched_context: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _safe_network(value: Any):
    try:
        return ip_network(clean_text(value), strict=False)
    except ValueError:
        return None


def _safe_ip(value: Any):
    try:
        parsed = ip_address(clean_text(value))
    except ValueError:
        return None
    if parsed.version == 6 and parsed.ipv4_mapped:
        return parsed.ipv4_mapped
    return parsed


def _direction(src_role: str, dst_role: str, interface_role: str = "") -> str:
    src_local = src_role in LOCAL_ROLES
    dst_local = dst_role in LOCAL_ROLES
    src_remote = src_role in {EXTERNAL, *EDGE_ROLES}
    dst_remote = dst_role in {EXTERNAL, *EDGE_ROLES}
    if src_local and dst_local:
        return "INTERNAL"
    if src_local and dst_remote:
        return "OUTBOUND"
    if src_remote and dst_local:
        return "INBOUND"
    if src_remote and dst_remote:
        return "EXTERNAL"
    if src_local and dst_role == UNKNOWN:
        return "OUTBOUND" if interface_role in {EXTERNAL, *EDGE_ROLES} else UNKNOWN
    if dst_local and src_role == UNKNOWN:
        return "INBOUND" if interface_role in {EXTERNAL, *EDGE_ROLES} else UNKNOWN
    return UNKNOWN


class NetworkContextEngine:
    """Resolve endpoint roles without changing detector scores by role alone."""

    def __init__(self, connection_factory: Callable[[], sqlite3.Connection] = sqlite_connection) -> None:
        self.connection_factory = connection_factory

    @staticmethod
    def _best_match(ip_value: Any, prefixes: Iterable[tuple[Any, str, str]]) -> tuple[str, str]:
        parsed = _safe_ip(ip_value)
        if parsed is None:
            return UNKNOWN, ""
        matches = [item for item in prefixes if item[0] is not None and item[0].version == parsed.version and parsed in item[0]]
        if not matches:
            # A syntactically valid address outside registered networks is external.
            # This deliberately avoids the old and unsafe INTERNAL fallback.
            return EXTERNAL, ""
        network, role, _name = max(matches, key=lambda item: item[0].prefixlen)
        return role, str(network)

    def _registered_prefixes(self, conn: sqlite3.Connection) -> list[tuple[Any, str, str]]:
        prefixes: list[tuple[Any, str, str]] = []
        try:
            rows = conn.execute(
                """
                SELECT p.cidr, p.prefix_type, z.name, z.subscriber_addressing_mode
                FROM ip_zone_prefixes p
                JOIN ip_zones z ON z.id = p.zone_id
                WHERE p.active = 1 AND z.active = 1
                """
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
        for row in rows:
            item = dict(row) if isinstance(row, sqlite3.Row) else {
                "cidr": row[0], "prefix_type": row[1], "name": row[2], "subscriber_addressing_mode": row[3]
            }
            prefix_type = clean_text(item.get("prefix_type")).lower()
            role = PREFIX_TYPE_ROLES.get(prefix_type, UNKNOWN)
            if role == CUSTOMER and clean_text(item.get("subscriber_addressing_mode")).lower() == "cgnat" and prefix_type == "public_cgnat":
                role = CGNAT_PUBLIC
            network = _safe_network(item.get("cidr"))
            if network is not None:
                prefixes.append((network, role, clean_text(item.get("name"))))

        try:
            rows = conn.execute(
                "SELECT DISTINCT public_ip, private_ip FROM cgnat_port_mappings WHERE active = 1"
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
        for row in rows:
            public_ip = row["public_ip"] if isinstance(row, sqlite3.Row) else row[0]
            private_ip = row["private_ip"] if isinstance(row, sqlite3.Row) else row[1]
            for value, role in ((public_ip, CGNAT_PUBLIC), (private_ip, CUSTOMER)):
                parsed = _safe_ip(value)
                if parsed is not None:
                    suffix = 32 if parsed.version == 4 else 128
                    prefixes.append((ip_network(f"{parsed}/{suffix}"), role, "CGNAT mapping"))
        return prefixes

    @staticmethod
    def _context_matches(row: Mapping[str, Any], sensor: str, exporter: str, input_if: int, output_if: int) -> bool:
        comparisons = (
            (clean_text(row.get("sensor_name")), clean_text(sensor)),
            (clean_text(row.get("exporter_ip")), clean_text(exporter)),
        )
        if any(expected and expected != actual for expected, actual in comparisons):
            return False
        for key, actual in (("input_if", input_if), ("output_if", output_if)):
            expected = row.get(key)
            if expected is not None and int(expected) != int(actual or 0):
                return False
        return True

    def resolve(
        self,
        src_ip: Any,
        dst_ip: Any,
        input_if: Any = 0,
        output_if: Any = 0,
        *,
        sensor: Any = "",
        exporter: Any = "",
        conn: sqlite3.Connection | None = None,
    ) -> NetworkContext:
        connection = conn or self.connection_factory()
        try:
            prefixes = self._registered_prefixes(connection)
            matched_context = ""
            interface_role = ""
            try:
                rows = connection.execute(
                    "SELECT * FROM threat_network_contexts WHERE enabled = 1 ORDER BY id"
                ).fetchall()
            except sqlite3.OperationalError:
                rows = []
            for raw in rows:
                row = dict(raw) if isinstance(raw, sqlite3.Row) else dict(raw)
                role = CONTEXT_TYPE_ROLES.get(clean_text(row.get("context_type")).upper(), UNKNOWN)
                for value in safe_json(row.get("protected_ranges_json"), []):
                    network = _safe_network(value)
                    if network is not None:
                        prefixes.append((network, role, clean_text(row.get("name"))))
                if self._context_matches(row, clean_text(sensor), clean_text(exporter), int(input_if or 0), int(output_if or 0)):
                    matched_context = clean_text(row.get("name"))
                    interface_role = role

            src_role, src_prefix = self._best_match(src_ip, prefixes)
            dst_role, dst_prefix = self._best_match(dst_ip, prefixes)
            return NetworkContext(
                src_role=src_role,
                dst_role=dst_role,
                src_is_cgnat=src_role == CGNAT_PUBLIC,
                dst_is_cgnat=dst_role == CGNAT_PUBLIC,
                src_prefix=src_prefix,
                dst_prefix=dst_prefix,
                traffic_direction=_direction(src_role, dst_role, interface_role),
                input_if=int(input_if or 0),
                output_if=int(output_if or 0),
                sensor=clean_text(sensor),
                exporter=clean_text(exporter),
                matched_context=matched_context,
            )
        finally:
            # Connection lifetime belongs to the supplied factory, matching the
            # repository's existing sqlite_connection usage pattern.
            pass


def resolve_network_context(
    src_ip: Any,
    dst_ip: Any,
    input_if: Any = 0,
    output_if: Any = 0,
    *,
    sensor: Any = "",
    exporter: Any = "",
    connection_factory: Callable[[], sqlite3.Connection] = sqlite_connection,
) -> dict[str, Any]:
    return NetworkContextEngine(connection_factory).resolve(
        src_ip,
        dst_ip,
        input_if,
        output_if,
        sensor=sensor,
        exporter=exporter,
    ).as_dict()
