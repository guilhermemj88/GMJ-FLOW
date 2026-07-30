from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any


PREFIX_ADDRESS_FAMILIES = {"ipv4", "ipv6", "both"}
PREFIX_MATCH_SIDES = {"source", "destination", "either", "both"}
PREFIX_GROUP_SIDES = {"source", "destination"}
PREFIX_DIRECTIONS = {
    "",
    "both",
    "upload",
    "download",
    "input",
    "output",
    "transmits",
    "receives",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _optional_positive_int(value: Any, field: str) -> int | None:
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError("%s deve ser um inteiro positivo" % field)
    if parsed < 1:
        raise ValueError("%s deve ser um inteiro positivo" % field)
    return parsed


def _max_preview(version: int) -> int:
    name = (
        "GMJ_FLOW_PREFIX_PREVIEW_MAX_IPV4"
        if version == 4
        else "GMJ_FLOW_PREFIX_PREVIEW_MAX_IPV6"
    )
    default = 65536 if version == 4 else 4096
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, 1_000_000))


def ensure_prefix_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS prefixes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            cidr TEXT NOT NULL UNIQUE,
            address_family TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            description TEXT NOT NULL DEFAULT '',
            customer_id INTEGER,
            group_id INTEGER,
            zone_id INTEGER,
            default_split_prefix_length INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_prefixes_enabled_family "
        "ON prefixes(enabled, address_family, name)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_prefixes_customer "
        "ON prefixes(customer_id, group_id, zone_id)"
    )


def prefix_row_to_dict(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "cidr": str(row["cidr"]),
        "address_family": str(row["address_family"]),
        "enabled": bool(row["enabled"]),
        "description": str(row["description"] or ""),
        "customer_id": (
            int(row["customer_id"]) if row["customer_id"] is not None else None
        ),
        "group_id": (
            int(row["group_id"]) if row["group_id"] is not None else None
        ),
        "zone_id": (
            int(row["zone_id"]) if row["zone_id"] is not None else None
        ),
        "default_split_prefix_length": int(
            row["default_split_prefix_length"]
        ),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def normalize_prefix_payload(
    payload: Any,
    *,
    current: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("prefixo deve ser um objeto")
    base = current or {}
    name = str(payload.get("name", base.get("name", ""))).strip()
    if not name:
        raise ValueError("name é obrigatório")
    if len(name) > 120:
        raise ValueError("name excede 120 caracteres")
    raw_cidr = str(payload.get("cidr", base.get("cidr", ""))).strip()
    try:
        network = ip_network(raw_cidr, strict=False)
    except ValueError:
        raise ValueError("CIDR IPv4 ou IPv6 inválido")
    address_family = "ipv4" if network.version == 4 else "ipv6"
    declared_family = str(
        payload.get("address_family", base.get("address_family", address_family))
    ).strip().lower()
    if declared_family not in {address_family, ""}:
        raise ValueError("address_family diverge do CIDR")
    default_length_value = payload.get(
        "default_split_prefix_length",
        base.get("default_split_prefix_length"),
    )
    if default_length_value in (None, ""):
        default_length = max(network.prefixlen, 24 if network.version == 4 else 64)
    else:
        try:
            default_length = int(default_length_value)
        except (TypeError, ValueError):
            raise ValueError("default_split_prefix_length inválido")
    if not network.prefixlen <= default_length <= network.max_prefixlen:
        raise ValueError(
            "default_split_prefix_length deve ficar entre /%s e /%s"
            % (network.prefixlen, network.max_prefixlen)
        )
    description = str(
        payload.get("description", base.get("description", ""))
    ).strip()
    if len(description) > 500:
        raise ValueError("description excede 500 caracteres")
    return {
        "name": name,
        "cidr": str(network),
        "address_family": address_family,
        "enabled": _bool(payload.get("enabled", base.get("enabled", True))),
        "description": description,
        "customer_id": _optional_positive_int(
            payload.get("customer_id", base.get("customer_id")),
            "customer_id",
        ),
        "group_id": _optional_positive_int(
            payload.get("group_id", base.get("group_id")),
            "group_id",
        ),
        "zone_id": _optional_positive_int(
            payload.get("zone_id", base.get("zone_id")),
            "zone_id",
        ),
        "default_split_prefix_length": default_length,
    }


def list_prefixes(
    conn: sqlite3.Connection,
    *,
    enabled: bool | None = None,
    address_family: str = "",
    search: str = "",
    offset: int = 0,
    limit: int = 100,
) -> dict[str, Any]:
    ensure_prefix_schema(conn)
    filters: list[str] = []
    params: list[Any] = []
    if enabled is not None:
        filters.append("enabled = ?")
        params.append(int(enabled))
    family = str(address_family or "").strip().lower()
    if family and family not in {"ipv4", "ipv6"}:
        raise ValueError("address_family deve ser ipv4 ou ipv6")
    if family:
        filters.append("address_family = ?")
        params.append(family)
    query_search = str(search or "").strip()
    if query_search:
        filters.append("(name LIKE ? OR cidr LIKE ? OR description LIKE ?)")
        wildcard = "%%%s%%" % query_search
        params.extend([wildcard, wildcard, wildcard])
    where = "WHERE %s" % " AND ".join(filters) if filters else ""
    total = int(
        conn.execute(
            "SELECT count(*) AS total FROM prefixes %s" % where,
            params,
        ).fetchone()["total"]
    )
    safe_offset = max(0, int(offset))
    safe_limit = max(1, min(int(limit), 500))
    rows = conn.execute(
        """
        SELECT *
        FROM prefixes
        %s
        ORDER BY enabled DESC, name COLLATE NOCASE, id
        LIMIT ? OFFSET ?
        """
        % where,
        [*params, safe_limit, safe_offset],
    ).fetchall()
    return {
        "items": [prefix_row_to_dict(row) for row in rows],
        "total": total,
        "offset": safe_offset,
        "limit": safe_limit,
    }


def get_prefix(conn: sqlite3.Connection, prefix_id: int) -> dict[str, Any] | None:
    ensure_prefix_schema(conn)
    row = conn.execute(
        "SELECT * FROM prefixes WHERE id = ?",
        (int(prefix_id),),
    ).fetchone()
    return prefix_row_to_dict(row) if row is not None else None


def create_prefix(
    conn: sqlite3.Connection,
    payload: dict[str, Any],
) -> dict[str, Any]:
    ensure_prefix_schema(conn)
    normalized = normalize_prefix_payload(payload)
    now = _utc_now()
    try:
        cursor = conn.execute(
            """
            INSERT INTO prefixes (
                name, cidr, address_family, enabled, description,
                customer_id, group_id, zone_id,
                default_split_prefix_length, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                normalized["name"],
                normalized["cidr"],
                normalized["address_family"],
                int(normalized["enabled"]),
                normalized["description"],
                normalized["customer_id"],
                normalized["group_id"],
                normalized["zone_id"],
                normalized["default_split_prefix_length"],
                now,
                now,
            ),
        )
    except sqlite3.IntegrityError:
        raise ValueError("já existe um prefixo com este CIDR")
    return get_prefix(conn, int(cursor.lastrowid)) or {}


def update_prefix(
    conn: sqlite3.Connection,
    prefix_id: int,
    payload: dict[str, Any],
) -> dict[str, Any]:
    current = get_prefix(conn, prefix_id)
    if current is None:
        raise LookupError("prefixo não encontrado")
    normalized = normalize_prefix_payload(payload, current=current)
    try:
        conn.execute(
            """
            UPDATE prefixes
            SET name = ?, cidr = ?, address_family = ?, enabled = ?,
                description = ?, customer_id = ?, group_id = ?, zone_id = ?,
                default_split_prefix_length = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                normalized["name"],
                normalized["cidr"],
                normalized["address_family"],
                int(normalized["enabled"]),
                normalized["description"],
                normalized["customer_id"],
                normalized["group_id"],
                normalized["zone_id"],
                normalized["default_split_prefix_length"],
                _utc_now(),
                int(prefix_id),
            ),
        )
    except sqlite3.IntegrityError:
        raise ValueError("já existe um prefixo com este CIDR")
    return get_prefix(conn, prefix_id) or {}


def preview_subnets(
    cidr: Any,
    prefix_length: Any,
    *,
    offset: int = 0,
    limit: int = 100,
    contains_ip: Any = None,
    contains_cidr: Any = None,
) -> dict[str, Any]:
    try:
        network = ip_network(str(cidr or "").strip(), strict=False)
    except ValueError:
        raise ValueError("CIDR IPv4 ou IPv6 inválido")
    try:
        requested_length = int(prefix_length)
    except (TypeError, ValueError):
        raise ValueError("prefix_length inválido")
    if not network.prefixlen <= requested_length <= network.max_prefixlen:
        raise ValueError(
            "prefix_length deve ficar entre /%s e /%s"
            % (network.prefixlen, network.max_prefixlen)
        )
    total = 1 << (requested_length - network.prefixlen)
    containing = None
    if contains_ip not in (None, "") and contains_cidr not in (None, ""):
        raise ValueError("use contains_ip ou contains_cidr, não ambos")
    if contains_cidr not in (None, ""):
        try:
            candidate = ip_network(
                str(contains_cidr).strip(),
                strict=False,
            )
        except ValueError:
            raise ValueError("contains_cidr inválido")
        if (
            candidate.version != network.version
            or candidate.prefixlen != requested_length
            or not candidate.subnet_of(network)
        ):
            raise ValueError(
                "contains_cidr deve ser um subprefixo /%s do bloco informado"
                % requested_length
            )
        containing = str(candidate)
    if contains_ip not in (None, ""):
        try:
            address = ip_address(str(contains_ip).strip())
        except ValueError:
            raise ValueError("contains_ip inválido")
        if address.version != network.version or address not in network:
            raise ValueError("contains_ip não pertence ao bloco informado")
        containing = str(
            ip_network(
                "%s/%s" % (address, requested_length),
                strict=False,
            )
        )
    maximum = _max_preview(network.version)
    if total > maximum and containing is None:
        raise ValueError(
            "expansão excessiva: %s sub-redes; limite configurado: %s. "
            "Use contains_ip para localizar uma sub-rede sem expandir o bloco."
            % (total, maximum)
        )
    safe_offset = max(0, int(offset))
    safe_limit = max(1, min(int(limit), 500))
    page_end = min(total, safe_offset + safe_limit)
    step = 1 << (network.max_prefixlen - requested_length)
    base = int(network.network_address)
    items = (
        [containing]
        if containing is not None
        else [
            str(
                ip_network(
                    "%s/%s"
                    % (
                        ip_address(base + index * step),
                        requested_length,
                    ),
                    strict=False,
                )
            )
            for index in range(safe_offset, page_end)
        ]
    )
    last_address = ip_address(base + (total - 1) * step)
    return {
        "cidr": str(network),
        "address_family": "ipv4" if network.version == 4 else "ipv6",
        "prefix_length": requested_length,
        "total": total,
        "start": str(
            ip_network(
                "%s/%s" % (network.network_address, requested_length),
                strict=False,
            )
        ),
        "end": str(
            ip_network(
                "%s/%s" % (last_address, requested_length),
                strict=False,
            )
        ),
        "items": items,
        "offset": safe_offset,
        "limit": safe_limit,
        "next_offset": (
            page_end if containing is None and page_end < total else None
        ),
        "max_expansion": maximum,
        "direct_lookup": containing is not None,
        "lookup": (
            "cidr"
            if contains_cidr not in (None, "")
            else "ip"
            if contains_ip not in (None, "")
            else None
        ),
    }


def normalize_prefix_filter(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    cidr = str(source.get("cidr") or "").strip()
    if cidr.lower() in {"all", "*", "todos"}:
        cidr = ""
    network = None
    if cidr:
        try:
            network = ip_network(cidr, strict=False)
        except ValueError:
            raise ValueError("prefix_filter.cidr inválido")
        cidr = str(network)
    prefix_id = _optional_positive_int(
        source.get("prefix_id"),
        "prefix_filter.prefix_id",
    )
    start_text = str(source.get("start_ip") or "").strip()
    end_text = str(source.get("end_ip") or "").strip()
    if bool(start_text) != bool(end_text):
        raise ValueError(
            "prefix_filter.start_ip e end_ip devem ser informados juntos"
        )
    start_address = end_address = None
    if start_text:
        try:
            start_address = ip_address(start_text)
            end_address = ip_address(end_text)
        except ValueError:
            raise ValueError("prefix_filter contém range inválido")
        if start_address.version != end_address.version:
            raise ValueError("range não pode misturar IPv4 e IPv6")
        if int(start_address) > int(end_address):
            raise ValueError("start_ip deve ser menor ou igual a end_ip")
        start_text, end_text = str(start_address), str(end_address)
    if network is not None and start_address is not None:
        raise ValueError("use CIDR/prefix_id ou range, não ambos")
    family = str(source.get("address_family") or "both").strip().lower()
    if family not in PREFIX_ADDRESS_FAMILIES:
        raise ValueError("prefix_filter.address_family inválido")
    effective_version = (
        network.version
        if network is not None
        else start_address.version
        if start_address is not None
        else None
    )
    if effective_version and family not in {
        "both",
        "ipv4" if effective_version == 4 else "ipv6",
    }:
        raise ValueError("address_family diverge do CIDR/range")
    match_side = str(source.get("match_side") or "either").strip().lower()
    if match_side not in PREFIX_MATCH_SIDES:
        raise ValueError("prefix_filter.match_side inválido")
    direction = str(source.get("direction") or "").strip().lower()
    if direction not in PREFIX_DIRECTIONS:
        raise ValueError("prefix_filter.direction inválido")
    enabled_default = bool(cidr or prefix_id or start_text)
    return {
        "enabled": _bool(source.get("enabled", enabled_default)),
        "cidr": cidr or None,
        "prefix_id": prefix_id,
        "start_ip": start_text or None,
        "end_ip": end_text or None,
        "address_family": family,
        "match_side": match_side,
        "direction": direction or None,
        "temporary": _bool(source.get("temporary", False)),
    }


def normalize_prefix_grouping(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    try:
        ipv4_length = int(source.get("ipv4_prefix_length", 24))
        ipv6_length = int(source.get("ipv6_prefix_length", 64))
        top_n = int(source.get("top_n", 10))
    except (TypeError, ValueError):
        raise ValueError("prefix_grouping contém valor numérico inválido")
    if not 0 <= ipv4_length <= 32:
        raise ValueError("ipv4_prefix_length deve ficar entre 0 e 32")
    if not 0 <= ipv6_length <= 128:
        raise ValueError("ipv6_prefix_length deve ficar entre 0 e 128")
    if not 1 <= top_n <= 100:
        raise ValueError("prefix_grouping.top_n deve ficar entre 1 e 100")
    side = str(source.get("side") or "destination").strip().lower()
    if side not in PREFIX_GROUP_SIDES:
        raise ValueError("prefix_grouping.side inválido")
    return {
        "enabled": _bool(source.get("enabled", False)),
        "ipv4_prefix_length": ipv4_length,
        "ipv6_prefix_length": ipv6_length,
        "side": side,
        "top_n": top_n,
        "include_empty": _bool(source.get("include_empty", False)),
    }


def resolve_prefix_filter(
    conn: sqlite3.Connection,
    value: Any,
) -> dict[str, Any]:
    normalized = normalize_prefix_filter(value)
    prefix_id = normalized.get("prefix_id")
    if prefix_id is not None:
        item = get_prefix(conn, int(prefix_id))
        if item is None:
            raise ValueError("prefix_filter.prefix_id não encontrado")
        if not item["enabled"]:
            raise ValueError("prefix_filter.prefix_id está desabilitado")
        if normalized.get("cidr") and normalized["cidr"] != item["cidr"]:
            raise ValueError("prefix_filter.cidr diverge do prefixo cadastrado")
        normalized["cidr"] = item["cidr"]
        normalized["address_family"] = item["address_family"]
        normalized["prefix_name"] = item["name"]
    return normalized


def prefix_context_signature(
    prefix_filter: Any,
    prefix_grouping: Any,
) -> str:
    payload = {
        "prefix_filter": normalize_prefix_filter(prefix_filter),
        "prefix_grouping": normalize_prefix_grouping(prefix_grouping),
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
