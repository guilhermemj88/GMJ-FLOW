from __future__ import annotations

from datetime import datetime, timezone
import json
import sqlite3
from typing import Any, Iterable

from app.services.threat_intelligence import clean_text


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone() is not None


def _not_expired(value: Any) -> bool:
    expires_at = clean_text(value)
    if not expires_at:
        return True
    try:
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > datetime.now(timezone.utc)


def _usable_name(value: Any, asn: int) -> str:
    text = clean_text(value)
    if not text:
        return ""
    normalized = text.upper().replace(" ", "")
    if normalized in {"-", "N/D", "ND", "ASN", "AS", "ASNINDISPONIVEL"}:
        return ""
    if normalized in {f"AS{asn}", f"ASN{asn}"}:
        return ""
    return text


def _canonical_record(raw: Any) -> dict[str, Any] | None:
    row = dict(raw)
    asn = int(row.get("asn") or 0)
    if not asn or not _not_expired(row.get("expires_at")):
        return None
    try:
        rdap = json.loads(clean_text(row.get("raw_json")) or "{}")
    except (TypeError, ValueError):
        rdap = {}
    return {
        "asn": asn,
        "as_name": clean_text(row.get("as_name")),
        "org_name": clean_text(row.get("org_name")),
        "country": clean_text(row.get("country")).upper(),
        "source": clean_text(row.get("source")),
        "updated_at": clean_text(row.get("updated_at")),
        "expires_at": clean_text(row.get("expires_at")),
        "last_error": clean_text(row.get("last_error")),
        "rdap": rdap if isinstance(rdap, dict) else {},
    }


def lookup_cached_asn_record(conn: sqlite3.Connection, asn: Any) -> dict[str, Any] | None:
    """Return the canonical record used by the existing ASN info endpoint."""
    try:
        number = int(asn or 0)
    except (TypeError, ValueError):
        return None
    if number <= 0 or not _table_exists(conn, "asn_info"):
        return None
    row = conn.execute(
        """
        SELECT asn, as_name, org_name, country, source, raw_json,
               updated_at, expires_at, last_error
        FROM asn_info WHERE asn=?
        """,
        (number,),
    ).fetchone()
    return _canonical_record(row) if row is not None else None


def cached_asn_information(conn: sqlite3.Connection, asns: Iterable[Any]) -> dict[int, dict[str, Any]]:
    """Read the existing ASN resolver/cache tables without queueing or external lookup.

    ``asn_info`` is the resolver's canonical organization record. Existing IP
    and prefix caches are read-only fallbacks for older installations.
    """
    parsed_numbers: set[int] = set()
    for value in asns:
        try:
            number = int(value or 0)
        except (TypeError, ValueError):
            continue
        if number > 0:
            parsed_numbers.add(number)
    numbers = sorted(parsed_numbers)[:1000]
    if not numbers:
        return {}
    placeholders = ",".join("?" for _ in numbers)
    result: dict[int, dict[str, Any]] = {}

    if _table_exists(conn, "asn_info"):
        rows = conn.execute(
            f"""
            SELECT asn, as_name, org_name, country, source, raw_json,
                   updated_at, expires_at, last_error
            FROM asn_info WHERE asn IN ({placeholders})
            """,
            numbers,
        ).fetchall()
        for raw in rows:
            record = _canonical_record(raw)
            if record is None:
                continue
            asn = int(record["asn"])
            result[asn] = {
                "asn": asn,
                "organization": _usable_name(record.get("org_name"), asn) or _usable_name(record.get("as_name"), asn),
                "as_name": _usable_name(record.get("as_name"), asn),
                "country": record["country"],
                "source": record["source"] or "asn_info",
                "updated_at": record["updated_at"],
            }

    for table, timestamp_column in (("asn_lookup_cache", "resolved_at"), ("asn_prefixes", "updated_at")):
        if not _table_exists(conn, table):
            continue
        expiry = ", expires_at" if table == "asn_lookup_cache" else ""
        rows = conn.execute(
            f"""
            SELECT asn, as_name, country, source, {timestamp_column} AS updated_at{expiry}
            FROM {table}
            WHERE asn IN ({placeholders}) AND asn > 0
            ORDER BY updated_at DESC
            """,
            numbers,
        ).fetchall()
        for raw in rows:
            row = dict(raw)
            asn = int(row.get("asn") or 0)
            if not asn or (table == "asn_lookup_cache" and not _not_expired(row.get("expires_at"))):
                continue
            current = result.setdefault(
                asn,
                {"asn": asn, "organization": "", "as_name": "", "country": "", "source": "", "updated_at": ""},
            )
            name = _usable_name(row.get("as_name"), asn)
            if not current["organization"]:
                current["organization"] = name
            if not current["as_name"]:
                current["as_name"] = name
            if not current["country"]:
                current["country"] = clean_text(row.get("country")).upper()
            if not current["source"]:
                current["source"] = clean_text(row.get("source")) or table
            if not current["updated_at"]:
                current["updated_at"] = clean_text(row.get("updated_at"))
    return result


def enrich_asn_rows_from_local_cache(
    conn: sqlite3.Connection,
    rows: Iterable[dict[str, Any]],
    *,
    asn_key: str,
    organization_key: str = "organization",
    country_key: str = "country",
) -> list[dict[str, Any]]:
    items = [dict(item) for item in rows]
    cached = cached_asn_information(conn, (item.get(asn_key) for item in items))
    for item in items:
        try:
            number = int(item.get(asn_key) or 0)
        except (TypeError, ValueError):
            number = 0
        info = cached.get(number, {})
        if not clean_text(item.get(organization_key)):
            item[organization_key] = clean_text(info.get("organization"))
        if not clean_text(item.get(country_key)):
            item[country_key] = clean_text(info.get("country"))
        item["asn_resolution_source"] = clean_text(info.get("source")) if info else ""
    return items
