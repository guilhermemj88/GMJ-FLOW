from __future__ import annotations

import math
import sqlite3
import threading
from ipaddress import ip_address, ip_network
from typing import Any, Callable, Iterable, Mapping

from app.services.threat_intelligence import (
    clean_text,
    safe_json,
    sqlite_connection,
    utc_now_iso,
)

# ---------------------------------------------------------------------------
# Semantic roles (semantic classification of an IP/subnet).
# ---------------------------------------------------------------------------
CUSTOMER_PUBLIC = "CUSTOMER_PUBLIC"
CGNAT_POOL = "CGNAT_POOL"
CDN_CACHE = "CDN_CACHE"
DNS_RESOLVER = "DNS_RESOLVER"
DOWNSTREAM_ISP = "DOWNSTREAM_ISP"
SERVER_INFRA = "SERVER_INFRA"
NETWORK_INFRA = "NETWORK_INFRA"
PEERING_INFRA = "PEERING_INFRA"
OTHER = "OTHER"

NETWORK_ROLES = {
    CUSTOMER_PUBLIC,
    CGNAT_POOL,
    CDN_CACHE,
    DNS_RESOLVER,
    DOWNSTREAM_ISP,
    SERVER_INFRA,
    NETWORK_INFRA,
    PEERING_INFRA,
    OTHER,
}

# ---------------------------------------------------------------------------
# Addressing modes — orthogonal to role. A DOWNSTREAM_ISP may, for example,
# receive a public block and run CGNAT over it (CGNAT_NON_DETERMINISTIC).
# ---------------------------------------------------------------------------
DIRECT_PUBLIC = "DIRECT_PUBLIC"
CGNAT_DETERMINISTIC = "CGNAT_DETERMINISTIC"
CGNAT_NON_DETERMINISTIC = "CGNAT_NON_DETERMINISTIC"
NAT = "NAT"
MIXED = "MIXED"
NONE = "NONE"

ADDRESSING_MODES = {
    DIRECT_PUBLIC,
    CGNAT_DETERMINISTIC,
    CGNAT_NON_DETERMINISTIC,
    NAT,
    MIXED,
    NONE,
}

# ---------------------------------------------------------------------------
# Provenance of an asset row.
# ---------------------------------------------------------------------------
SOURCE_MANUAL = "manual"
SOURCE_CGNAT_POOL = "cgnat_pool"
SOURCE_IMPORT = "import"
SOURCE_SYSTEM = "system"

SOURCE_TYPES = {SOURCE_MANUAL, SOURCE_CGNAT_POOL, SOURCE_IMPORT, SOURCE_SYSTEM}

# Direction vocabulary for expected services.
SERVICE_DIRECTIONS = {"TO_CUSTOMERS", "FROM_CUSTOMERS", "INBOUND", "OUTBOUND", "ANY"}


def _role_text(value: Any) -> str:
    role = clean_text(value).upper()
    return role if role in NETWORK_ROLES else OTHER


def _mode_text(value: Any) -> str:
    mode = clean_text(value).upper()
    return mode if mode in ADDRESSING_MODES else NONE


def _source_text(value: Any) -> str:
    source = clean_text(value).lower()
    return source if source in SOURCE_TYPES else SOURCE_MANUAL


def ensure_network_assets_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS network_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prefix TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT 'OTHER',
            addressing_mode TEXT NOT NULL DEFAULT 'NONE',
            provider TEXT NOT NULL DEFAULT '',
            zone_id INTEGER,
            active INTEGER NOT NULL DEFAULT 1,
            source_type TEXT NOT NULL DEFAULT 'manual',
            source_id INTEGER,
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_network_assets_prefix
        ON network_assets(prefix)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS network_asset_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT '',
            source_port INTEGER,
            destination_port INTEGER,
            direction TEXT NOT NULL DEFAULT 'ANY',
            description TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(asset_id) REFERENCES network_assets(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_network_asset_services_asset
        ON network_asset_services(asset_id)
        """
    )
    invalidate_network_asset_cache()


def network_asset_row_to_dict(row: Mapping[str, Any] | sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    return {
        "id": int(item.get("id") or 0),
        "prefix": clean_text(item.get("prefix")),
        "name": clean_text(item.get("name")),
        "role": _role_text(item.get("role")),
        "addressing_mode": _mode_text(item.get("addressing_mode")),
        "provider": clean_text(item.get("provider")),
        "zone_id": item.get("zone_id"),
        "active": int(item.get("active") or 0),
        "source_type": _source_text(item.get("source_type")),
        "source_id": item.get("source_id"),
        "notes": clean_text(item.get("notes")),
        "created_at": clean_text(item.get("created_at")),
        "updated_at": clean_text(item.get("updated_at")),
    }


def _cgnat_pool_asset(row: Mapping[str, Any] | sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    mode = clean_text(item.get("mode")).lower()
    addressing_mode = CGNAT_DETERMINISTIC if mode == "deterministic" else CGNAT_NON_DETERMINISTIC
    return {
        "id": None,
        "prefix": clean_text(item.get("prefix")),
        "name": clean_text(item.get("name")),
        "role": CGNAT_POOL,
        "addressing_mode": addressing_mode,
        "provider": "",
        "zone_id": None,
        "active": int(item.get("active") or 0),
        "source_type": SOURCE_CGNAT_POOL,
        "source_id": int(item.get("id") or 0),
        "notes": clean_text(item.get("notes")),
        "created_at": clean_text(item.get("created_at")),
        "updated_at": clean_text(item.get("updated_at")),
    }


def list_network_assets(conn: sqlite3.Connection, *, include_cgnat: bool = True) -> list[dict[str, Any]]:
    """All semantic assets. CGNAT pools are projected (role=CGNAT_POOL,
    source_type=cgnat_pool, source_id=cgnat_pools.id) — never duplicated as a
    second source of truth."""
    assets: list[dict[str, Any]] = []
    rows = conn.execute(
        "SELECT * FROM network_assets ORDER BY active DESC, prefix"
    ).fetchall()
    for row in rows:
        assets.append(network_asset_row_to_dict(row))
    if include_cgnat:
        try:
            cgnat_rows = conn.execute(
                "SELECT id, name, prefix, mode, active, notes, created_at, updated_at "
                "FROM cgnat_pools ORDER BY active DESC, prefix"
            ).fetchall()
        except sqlite3.OperationalError:
            cgnat_rows = []
        for row in cgnat_rows:
            assets.append(_cgnat_pool_asset(row))
    return assets


def fetch_network_asset(conn: sqlite3.Connection, asset_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM network_assets WHERE id = ?", (int(asset_id),)).fetchone()
    return network_asset_row_to_dict(row) if row is not None else None


def upsert_network_asset(conn: sqlite3.Connection, payload: Mapping[str, Any], asset_id: int | None = None) -> dict[str, Any]:
    prefix = clean_text(payload.get("prefix"))
    if not prefix:
        raise ValueError("prefix é obrigatório")
    try:
        network = ip_network(prefix, strict=False)
    except ValueError as exc:
        raise ValueError(f"prefix inválido: {prefix}") from exc
    prefix = str(network)
    now = utc_now_iso()
    name = clean_text(payload.get("name"))
    role = _role_text(payload.get("role"))
    addressing_mode = _mode_text(payload.get("addressing_mode"))
    provider = clean_text(payload.get("provider"))
    notes = clean_text(payload.get("notes"))
    zone_id = payload.get("zone_id")
    source_type = _source_text(payload.get("source_type"))
    source_id = payload.get("source_id")
    active = int(payload.get("active") if payload.get("active") is not None else 1)
    existing = None
    if asset_id is not None:
        existing = conn.execute(
            "SELECT id FROM network_assets WHERE id = ?", (int(asset_id),)
        ).fetchone()
    if existing is None:
        existing = conn.execute(
            "SELECT id FROM network_assets WHERE prefix = ?", (prefix,)
        ).fetchone()
    if existing is not None:
        conn.execute(
            """
            UPDATE network_assets
            SET prefix = ?, name = ?, role = ?, addressing_mode = ?, provider = ?, zone_id = ?,
                active = ?, source_type = ?, source_id = ?, notes = ?, updated_at = ?
            WHERE id = ?
            """,
            (prefix, name, role, addressing_mode, provider, zone_id, active, source_type, source_id, notes, now, int(existing["id"])),
        )
        asset_id = int(existing["id"])
    else:
        cursor = conn.execute(
            """
            INSERT INTO network_assets (
                prefix, name, role, addressing_mode, provider, zone_id, active,
                source_type, source_id, notes, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (prefix, name, role, addressing_mode, provider, zone_id, active, source_type, source_id, notes, now, now),
        )
        asset_id = int(cursor.lastrowid)
    invalidate_network_asset_cache()
    return fetch_network_asset(conn, asset_id) or {}


def delete_network_asset(conn: sqlite3.Connection, asset_id: int) -> bool:
    cursor = conn.execute("DELETE FROM network_assets WHERE id = ?", (int(asset_id),))
    changed = cursor.rowcount > 0
    invalidate_network_asset_cache()
    return changed


def list_network_asset_services(conn: sqlite3.Connection, asset_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM network_asset_services WHERE asset_id = ? ORDER BY id",
        (int(asset_id),),
    ).fetchall()
    services: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        services.append(
            {
                "id": int(item.get("id") or 0),
                "asset_id": int(item.get("asset_id") or 0),
                "protocol": clean_text(item.get("protocol")),
                "source_port": item.get("source_port"),
                "destination_port": item.get("destination_port"),
                "direction": clean_text(item.get("direction")).upper() or "ANY",
                "description": clean_text(item.get("description")),
                "enabled": int(item.get("enabled") or 0),
            }
        )
    return services


def replace_network_asset_services(
    conn: sqlite3.Connection,
    asset_id: int,
    services: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    now = utc_now_iso()
    conn.execute("DELETE FROM network_asset_services WHERE asset_id = ?", (int(asset_id),))
    for service in services or []:
        direction = clean_text(service.get("direction")).upper() or "ANY"
        if direction not in SERVICE_DIRECTIONS:
            direction = "ANY"
        conn.execute(
            """
            INSERT INTO network_asset_services (
                asset_id, protocol, source_port, destination_port, direction,
                description, enabled, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(asset_id),
                clean_text(service.get("protocol")),
                service.get("source_port"),
                service.get("destination_port"),
                direction,
                clean_text(service.get("description")),
                int(service.get("enabled") if service.get("enabled") is not None else 1),
                now,
                now,
            ),
        )
    return list_network_asset_services(conn, asset_id)


# ---------------------------------------------------------------------------
# Longest-prefix-match resolver with an in-memory, generation-based cache.
# ---------------------------------------------------------------------------
_cache_lock = threading.RLock()
_cache_generation = 0


def invalidate_network_asset_cache() -> None:
    global _cache_generation
    with _cache_lock:
        _cache_generation += 1


def _safe_network(value: Any) -> Any | None:
    try:
        return ip_network(clean_text(value), strict=False)
    except ValueError:
        return None


def _safe_ip(value: Any) -> Any | None:
    try:
        parsed = ip_address(clean_text(value))
    except ValueError:
        return None
    if parsed.version == 6 and parsed.ipv4_mapped:
        return parsed.ipv4_mapped
    return parsed


class NetworkAssetResolver:
    """Longest-prefix-match over network_assets + projected CGNAT pools.

    The compiled prefix table and per-asset service lists are cached in memory;
    `invalidate_network_asset_cache()` is called whenever prefixes or CGNAT
    pools change, so detection never pays one SQLite query per flow.
    """

    def __init__(self, connection_factory: Callable[[], sqlite3.Connection] = sqlite_connection) -> None:
        self.connection_factory = connection_factory
        self._lock = threading.Lock()
        self._generation = -1
        self._entries: list[tuple[Any, dict[str, Any]]] = []
        self._services: dict[str, list[dict[str, Any]]] = {}

    @staticmethod
    def _load(conn: sqlite3.Connection) -> tuple[list[tuple[Any, dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
        conn.row_factory = sqlite3.Row
        entries: list[tuple[Any, dict[str, Any]]] = []
        services: dict[str, list[dict[str, Any]]] = {}
        try:
            asset_rows = conn.execute(
                "SELECT * FROM network_assets WHERE active = 1"
            ).fetchall()
        except sqlite3.OperationalError:
            asset_rows = []
        for row in asset_rows:
            asset = network_asset_row_to_dict(row)
            network = _safe_network(asset["prefix"])
            if network is not None:
                entries.append((network, asset))
                services[str(network)] = list_network_asset_services(conn, int(asset["id"]))
        try:
            cgnat_rows = conn.execute(
                "SELECT id, name, prefix, mode, active, notes, created_at, updated_at "
                "FROM cgnat_pools WHERE active = 1"
            ).fetchall()
        except sqlite3.OperationalError:
            cgnat_rows = []
        for row in cgnat_rows:
            asset = _cgnat_pool_asset(row)
            network = _safe_network(asset["prefix"])
            if network is not None:
                entries.append((network, asset))
        # Sort ascending by prefix length so the first match from the reversed
        # scan is the most specific (longest) prefix.
        entries.sort(key=lambda item: item[0].prefixlen)
        return entries, services

    def _compiled(self) -> tuple[list[tuple[Any, dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
        with self._lock:
            if self._generation == _cache_generation:
                return self._entries, self._services
        conn = self.connection_factory()
        try:
            entries, services = self._load(conn)
        finally:
            conn.close()
        with self._lock:
            self._generation = _cache_generation
            self._entries = entries
            self._services = services
        return entries, services

    def resolve(self, ip: Any, zone_id: Any = None) -> dict[str, Any]:
        parsed = _safe_ip(ip)
        if parsed is None:
            return self._unmatched(clean_text(ip))
        entries, services = self._compiled()
        matches = [
            (network, asset)
            for network, asset in entries
            if network.version == parsed.version and parsed in network
        ]
        if not matches:
            return self._unmatched(str(parsed))
        best_prefixlen = matches[-1][0].prefixlen
        best_at_prefix = [item for item in matches if item[0].prefixlen == best_prefixlen]
        manual_best = [item for item in best_at_prefix if item[1].get("source_type") != SOURCE_CGNAT_POOL]
        # At equal specificity a manual asset wins the semantic role over a
        # projected CGNAT pool; CGNAT still supplies the addressing context.
        primary = manual_best[-1] if manual_best else best_at_prefix[-1]
        cgnat = next(
            (item for item in reversed(matches) if item[1].get("source_type") == SOURCE_CGNAT_POOL),
            None,
        )
        parent = next(
            (item for item in reversed(matches) if item[0].prefixlen < best_prefixlen),
            None,
        )
        network, asset = primary
        role = asset.get("role") or OTHER
        name = asset.get("name") or ""
        provider = asset.get("provider") or ""
        if cgnat is not None:
            addressing_mode = cgnat[1].get("addressing_mode") or NONE
            is_cgnat = True
            cgnat_pool_id = cgnat[1].get("source_id")
        else:
            addressing_mode = asset.get("addressing_mode") or NONE
            is_cgnat = False
            cgnat_pool_id = None
        context_sources: list[str] = []
        if asset.get("source_type") and asset.get("source_type") != SOURCE_CGNAT_POOL:
            context_sources.append(asset.get("source_type"))
        if is_cgnat and SOURCE_CGNAT_POOL not in context_sources:
            context_sources.append(SOURCE_CGNAT_POOL)
        return {
            "matched": True,
            "ip": str(parsed),
            "prefix": str(network),
            "prefix_length": network.prefixlen,
            "name": name,
            "role": role,
            "addressing_mode": addressing_mode,
            "provider": provider,
            "zone_id": asset.get("zone_id"),
            "source_type": asset.get("source_type") or "",
            "source_id": asset.get("source_id"),
            "is_cgnat": is_cgnat,
            "cgnat_pool_id": cgnat_pool_id,
            "context_sources": context_sources,
            "expected_services": services.get(str(network), []),
            "parent": (
                {
                    "prefix": str(parent[0]),
                    "prefix_length": parent[0].prefixlen,
                    "name": parent[1].get("name") or "",
                    "role": parent[1].get("role") or OTHER,
                }
                if parent is not None
                else None
            ),
        }

    @staticmethod
    def _unmatched(ip_text: str) -> dict[str, Any]:
        return {
            "matched": False,
            "ip": clean_text(ip_text),
            "prefix": "",
            "prefix_length": 0,
            "name": "",
            "role": OTHER,
            "addressing_mode": NONE,
            "provider": "",
            "zone_id": None,
            "source_type": "",
            "source_id": None,
            "is_cgnat": False,
            "cgnat_pool_id": None,
            "context_sources": [],
            "expected_services": [],
            "parent": None,
        }


_shared_resolver: NetworkAssetResolver | None = None


def network_asset_resolver() -> NetworkAssetResolver:
    global _shared_resolver
    if _shared_resolver is None:
        _shared_resolver = NetworkAssetResolver()
    return _shared_resolver


def resolve_network_context(ip: Any, zone_id: Any = None) -> dict[str, Any]:
    """Central single-IP semantic resolver (longest prefix match).

    Returns role/addressing_mode/provider/source_type/expected_services for a
    single address. Detection code should use this instead of re-implementing
    prefix logic per detector.
    """
    return network_asset_resolver().resolve(ip, zone_id)


def target_role_distribution(
    ips: Iterable[Any],
    resolver: Callable[[Any], dict[str, Any]] | None = None,
    *,
    weights: Mapping[str, float] | None = None,
    max_lookups: int = 2000,
) -> dict[str, float]:
    """Role composition of a set of destination addresses.

    Weights (optional) are indexed by the normalized ip string; when omitted
    every distinct address contributes equally. Lookups are bounded and the
    resolver is expected to be cached — this never issues one query per flow
    for millions of flows.
    """
    resolve = resolver or resolve_network_context
    counter: dict[str, float] = {}
    total = 0.0
    for value in list(dict.fromkeys(ips))[:max_lookups]:
        context = resolve(value)
        role = clean_text(context.get("role")).upper() or OTHER
        weight = 1.0
        if weights is not None:
            weight = float(weights.get(clean_text(context.get("ip")) or clean_text(value), 1.0) or 1.0)
        counter[role] = counter.get(role, 0.0) + weight
        total += weight
    if not total:
        return {}
    return {role: round(count / total, 4) for role, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))}


def shannon_entropy(counts: Mapping[Any, float]) -> float:
    """Normalized Shannon entropy in [0, 1]."""
    total = float(sum(counts.values()))
    if total <= 0 or len(counts) <= 1:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        if count <= 0:
            continue
        probability = float(count) / total
        entropy -= probability * math.log2(probability)
    maximum = math.log2(len(counts))
    return round(entropy / maximum, 4) if maximum else 0.0


def expected_services_match(
    context: Mapping[str, Any],
    protocol: str,
    source_port: Any,
    destination_port: Any,
    direction: str = "ANY",
) -> bool:
    """True when the observed tuple is compatible with an expected service of
    the asset. This is context only — it never suppresses detection by itself.
    """
    services = context.get("expected_services") or []
    if not services:
        return False
    proto = clean_text(protocol).lower()
    for service in services:
        if not service.get("enabled", 1):
            continue
        svc_proto = clean_text(service.get("protocol")).lower()
        if svc_proto and svc_proto not in {"any", "all", proto}:
            continue
        if service.get("source_port") is not None and safe_int(service.get("source_port")) != safe_int(source_port):
            continue
        if service.get("destination_port") is not None and safe_int(service.get("destination_port")) != safe_int(destination_port):
            continue
        svc_direction = clean_text(service.get("direction")).upper() or "ANY"
        if svc_direction not in {"ANY", clean_text(direction).upper()}:
            continue
        return True
    return False


def safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


__all__ = [
    "CUSTOMER_PUBLIC",
    "CGNAT_POOL",
    "CDN_CACHE",
    "DNS_RESOLVER",
    "DOWNSTREAM_ISP",
    "SERVER_INFRA",
    "NETWORK_INFRA",
    "PEERING_INFRA",
    "OTHER",
    "NETWORK_ROLES",
    "DIRECT_PUBLIC",
    "CGNAT_DETERMINISTIC",
    "CGNAT_NON_DETERMINISTIC",
    "NAT",
    "MIXED",
    "NONE",
    "ADDRESSING_MODES",
    "SOURCE_MANUAL",
    "SOURCE_CGNAT_POOL",
    "SOURCE_IMPORT",
    "SOURCE_SYSTEM",
    "ensure_network_assets_schema",
    "network_asset_row_to_dict",
    "list_network_assets",
    "fetch_network_asset",
    "upsert_network_asset",
    "delete_network_asset",
    "list_network_asset_services",
    "replace_network_asset_services",
    "NetworkAssetResolver",
    "network_asset_resolver",
    "resolve_network_context",
    "target_role_distribution",
    "shannon_entropy",
    "expected_services_match",
    "invalidate_network_asset_cache",
]
