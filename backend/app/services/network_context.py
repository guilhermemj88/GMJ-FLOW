from __future__ import annotations

import sqlite3
from dataclasses import dataclass
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
        return {
            "src_role": self.src_role,
            "dst_role": self.dst_role,
            "src_is_cgnat": self.src_is_cgnat,
            "dst_is_cgnat": self.dst_is_cgnat,
            "src_prefix": self.src_prefix,
            "dst_prefix": self.dst_prefix,
            "traffic_direction": self.traffic_direction,
            "input_if": self.input_if,
            "output_if": self.output_if,
            "sensor": self.sensor,
            "exporter": self.exporter,
            "matched_context": self.matched_context,
        }


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


def _prefix_entry(network: Any, role: str, name: str) -> tuple[Any, str, str]:
    return (network, role, name)


class _TrieNode:
    """One node of a binary LPM trie (one child per address bit)."""

    __slots__ = ("zero", "one", "role", "name", "network")

    def __init__(self) -> None:
        self.zero: "_TrieNode | None" = None
        self.one: "_TrieNode | None" = None
        self.role: str | None = None
        self.name: str | None = None
        self.network: Any = None


def _trie_insert(root: _TrieNode, network: Any, role: str, name: str) -> None:
    node = root
    addr = int(network.network_address)
    bits = network.max_prefixlen
    # Walk the MOST significant bits of the address (MSB -> LSB), one node per
    # prefix bit, so the trie depth equals the prefix length.
    for bit in range(bits - 1, bits - 1 - network.prefixlen, -1):
        if (addr >> bit) & 1:
            if node.one is None:
                node.one = _TrieNode()
            node = node.one
        else:
            if node.zero is None:
                node.zero = _TrieNode()
            node = node.zero
    # First-wins on equal prefix length: preserves the original list tie-break
    # (max(matches, key=prefixlen) returns the first max).
    if node.role is None:
        node.role = role
        node.name = name
        node.network = network


def _build_trie(prefixes: Iterable[tuple[Any, str, str]]) -> tuple[_TrieNode, _TrieNode]:
    v4 = _TrieNode()
    v6 = _TrieNode()
    for entry in prefixes:
        network, role, name = entry[0], entry[1], entry[2]
        root = v4 if network.version == 4 else v6
        _trie_insert(root, network, role, name)
    return v4, v6


def _trie_match(v4_root: _TrieNode, v6_root: _TrieNode, ip_value: Any) -> tuple[str, str]:
    """Longest-prefix match via the trie (O(32)/O(128) per address)."""
    parsed = _safe_ip(ip_value)
    if parsed is None:
        return UNKNOWN, ""
    version = parsed.version
    root = v4_root if version == 4 else v6_root
    key = int(parsed)
    bits = 32 if version == 4 else 128
    node = root
    best_role = node.role
    best_network = node.network
    for bit in range(bits - 1, -1, -1):
        node = node.one if (key >> bit) & 1 else node.zero
        if node is None:
            break
        if node.role is not None:
            best_role = node.role
            best_network = node.network
    if best_role is None:
        # A syntactically valid address outside registered networks is external.
        # This deliberately avoids the old and unsafe INTERNAL fallback.
        return EXTERNAL, ""
    return best_role, str(best_network)


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
                prefixes.append(_prefix_entry(network, role, clean_text(item.get("name"))))

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
                    prefixes.append(_prefix_entry(ip_network(f"{parsed}/{suffix}"), role, "CGNAT mapping"))
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

    def prepare_resolver(self) -> Callable[..., NetworkContext]:
        """Load control-plane context once and return the canonical local resolver.

        The returned callable performs no SQLite access.  It is intended for a
        bounded runtime cycle that needs to classify many flow observations.
        """
        connection = self.connection_factory()
        try:
            prefixes = self._registered_prefixes(connection)
            try:
                rows = connection.execute(
                    "SELECT * FROM threat_network_contexts WHERE enabled = 1 ORDER BY id"
                ).fetchall()
            except sqlite3.OperationalError:
                rows = []

            contexts: list[tuple[Mapping[str, Any], str]] = []
            for raw in rows:
                row = dict(raw) if isinstance(raw, sqlite3.Row) else dict(raw)
                role = CONTEXT_TYPE_ROLES.get(
                    clean_text(row.get("context_type")).upper(), UNKNOWN
                )
                for value in safe_json(row.get("protected_ranges_json"), []):
                    network = _safe_network(value)
                    if network is not None:
                        prefixes.append(
                            _prefix_entry(network, role, clean_text(row.get("name")))
                        )
                contexts.append((row, role))
        finally:
            connection.close()

        frozen_prefixes = tuple(prefixes)
        frozen_contexts = tuple(contexts)
        v4_trie, v6_trie = _build_trie(frozen_prefixes)

        def resolve(
            src_ip: Any,
            dst_ip: Any,
            input_if: Any = 0,
            output_if: Any = 0,
            *,
            sensor: Any = "",
            exporter: Any = "",
        ) -> NetworkContext:
            matched_context = ""
            interface_role = ""
            for row, role in frozen_contexts:
                if self._context_matches(
                    row, clean_text(sensor), clean_text(exporter),
                    int(input_if or 0), int(output_if or 0),
                ):
                    matched_context = clean_text(row.get("name"))
                    interface_role = role
            src_role, src_prefix = _trie_match(v4_trie, v6_trie, src_ip)
            dst_role, dst_prefix = _trie_match(v4_trie, v6_trie, dst_ip)
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

        return resolve

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
        owns_connection = conn is None
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
                        prefixes.append(_prefix_entry(network, role, clean_text(row.get("name"))))
                if self._context_matches(row, clean_text(sensor), clean_text(exporter), int(input_if or 0), int(output_if or 0)):
                    matched_context = clean_text(row.get("name"))
                    interface_role = role

            v4_trie, v6_trie = _build_trie(prefixes)
            src_role, src_prefix = _trie_match(v4_trie, v6_trie, src_ip)
            dst_role, dst_prefix = _trie_match(v4_trie, v6_trie, dst_ip)
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
            if owns_connection and connection is not None:
                connection.close()


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
