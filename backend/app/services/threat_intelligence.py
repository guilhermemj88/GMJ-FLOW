from __future__ import annotations

import json
import logging
import os
import socket
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Any, Callable, Iterable, Mapping


from app.services.sqlite_managed import open_managed


LOGGER = logging.getLogger("gmj-flow")

ACTIVE = "ACTIVE"
WAITING_SYNC = "WAITING_SYNC"
DEGRADED = "DEGRADED"
AUTH_ERROR = "AUTH_ERROR"
RATE_LIMITED = "RATE_LIMITED"
ERROR = "ERROR"
DISABLED = "DISABLED"
# Kept as import-compatible legacy names. New persisted/provider-facing states use
# ACTIVE/WAITING_SYNC/ERROR and never infer liveness from a separate health-check.
ONLINE = "ONLINE"
OFFLINE = "OFFLINE"
PROVIDER_STATUSES = {
    ACTIVE, WAITING_SYNC, DEGRADED, AUTH_ERROR, RATE_LIMITED, ERROR, DISABLED,
    ONLINE, OFFLINE,
}

GREYNOISE = "GREYNOISE"
CEREAL2 = "CEREAL2"
TEAM_CYMRU = "TEAM_CYMRU"
FEODO = "FEODO"
BLOCKLIST_DE = "BLOCKLIST_DE"
INTEL_SOURCES = {GREYNOISE, CEREAL2, TEAM_CYMRU, FEODO, BLOCKLIST_DE}

DEFAULT_INTERVALS = {
    GREYNOISE: 8 * 60 * 60,
    CEREAL2: 15 * 60,
    TEAM_CYMRU: 4 * 60 * 60,
    FEODO: 15 * 60,
    BLOCKLIST_DE: 15 * 60,
}

GREYNOISE_QUERIES = (
    'last_seen:1d classification:"malicious"',
    'last_seen:1d classification:"suspicious"',
)

ConnectionFactory = Callable[[], sqlite3.Connection]
UrlOpener = Callable[..., Any]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def clean_text(value: Any) -> str:
    return str(value or "").strip()


def safe_json(value: Any, fallback: Any) -> Any:
    if isinstance(value, type(fallback)):
        return value
    try:
        decoded = json.loads(clean_text(value))
        return decoded if isinstance(decoded, type(fallback)) else fallback
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)


def sqlite_connection() -> sqlite3.Connection:
    path = Path(os.getenv("GMJFLOW_DB_PATH", "/app/data/gmjflow.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = open_managed(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    try:
        conn.execute("PRAGMA journal_mode = WAL")
    except sqlite3.OperationalError:
        pass
    return conn


def ensure_threat_intel_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS threat_intel_providers (
            provider TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'DISABLED',
            last_success TEXT,
            last_error TEXT NOT NULL DEFAULT '',
            last_sync TEXT,
            last_sync_duration_ms INTEGER NOT NULL DEFAULT 0,
            next_sync TEXT,
            item_count INTEGER NOT NULL DEFAULT 0,
            credential_configured INTEGER NOT NULL DEFAULT 0,
            sync_interval_seconds INTEGER NOT NULL,
            config_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS threat_intel_indicators (
            provider TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            ip TEXT NOT NULL DEFAULT '',
            network TEXT NOT NULL DEFAULT '',
            classification TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL DEFAULT '',
            asn INTEGER NOT NULL DEFAULT 0,
            organization TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT '',
            country_code TEXT NOT NULL DEFAULT '',
            city TEXT NOT NULL DEFAULT '',
            spoofable INTEGER NOT NULL DEFAULT 0,
            vpn INTEGER NOT NULL DEFAULT 0,
            tor INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            botnet_family TEXT NOT NULL DEFAULT '',
            recency_seconds INTEGER,
            tags_json TEXT NOT NULL DEFAULT '[]',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            sync_token TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(provider, indicator_type, ip, network)
        );

        CREATE TABLE IF NOT EXISTS threat_intel_bogons (
            provider TEXT NOT NULL DEFAULT 'TEAM_CYMRU',
            kind TEXT NOT NULL,
            prefix TEXT NOT NULL,
            ip_version INTEGER NOT NULL,
            prefix_length INTEGER NOT NULL,
            start_bin BLOB NOT NULL,
            end_bin BLOB NOT NULL,
            sync_token TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(provider, kind, prefix)
        );

        CREATE TABLE IF NOT EXISTS external_attack_observations (
            provider TEXT NOT NULL,
            external_id TEXT NOT NULL,
            observation_type TEXT NOT NULL DEFAULT 'EXTERNAL_ATTACK_OBSERVATION',
            observed_at TEXT NOT NULL,
            country TEXT NOT NULL DEFAULT '',
            country_code TEXT NOT NULL DEFAULT '',
            target_prefix TEXT NOT NULL,
            target_asn INTEGER NOT NULL DEFAULT 0,
            target_organization TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL DEFAULT '',
            protocol TEXT NOT NULL DEFAULT '',
            target_port INTEGER,
            duration_seconds INTEGER NOT NULL DEFAULT 0,
            stream_sequence INTEGER NOT NULL DEFAULT 0,
            sync_token TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(provider, external_id)
        );

        CREATE TABLE IF NOT EXISTS threat_intel_sync_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL,
            pages INTEGER NOT NULL DEFAULT 0,
            items_processed INTEGER NOT NULL DEFAULT 0,
            items_active INTEGER NOT NULL DEFAULT 0,
            phase TEXT NOT NULL DEFAULT '',
            endpoint TEXT NOT NULL DEFAULT '',
            error_message TEXT NOT NULL DEFAULT '',
            duration_ms INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS threat_network_contexts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            sensor_name TEXT NOT NULL DEFAULT '',
            exporter_ip TEXT NOT NULL DEFAULT '',
            input_if INTEGER,
            output_if INTEGER,
            context_type TEXT NOT NULL,
            protected_ranges_json TEXT NOT NULL DEFAULT '[]',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_threat_indicators_ip
            ON threat_intel_indicators(ip, active, provider);
        CREATE INDEX IF NOT EXISTS idx_threat_indicators_map
            ON threat_intel_indicators(active, country_code, provider, classification);
        CREATE INDEX IF NOT EXISTS idx_threat_bogons_range
            ON threat_intel_bogons(ip_version, start_bin, end_bin, active);
        CREATE INDEX IF NOT EXISTS idx_external_attacks_target_time
            ON external_attack_observations(target_prefix, observed_at, active);
        CREATE INDEX IF NOT EXISTS idx_threat_sync_audit_provider
            ON threat_intel_sync_audit(provider, id DESC);
        CREATE INDEX IF NOT EXISTS idx_threat_network_context_lookup
            ON threat_network_contexts(enabled, sensor_name, exporter_ip, input_if, output_if);
        """
    )
    audit_columns = {
        row["name"] if isinstance(row, sqlite3.Row) else row[1]
        for row in conn.execute("PRAGMA table_info(threat_intel_sync_audit)").fetchall()
    }
    if "phase" not in audit_columns:
        conn.execute("ALTER TABLE threat_intel_sync_audit ADD COLUMN phase TEXT NOT NULL DEFAULT ''")
    if "endpoint" not in audit_columns:
        conn.execute("ALTER TABLE threat_intel_sync_audit ADD COLUMN endpoint TEXT NOT NULL DEFAULT ''")
    conn.execute("UPDATE threat_intel_providers SET status=? WHERE status='ONLINE'", (ACTIVE,))
    conn.execute(
        """
        UPDATE threat_intel_providers
        SET status=CASE
            WHEN last_sync IS NULL AND last_error='' THEN ?
            WHEN last_error<>'' THEN ?
            ELSE ? END
        WHERE status='OFFLINE'
        """,
        (WAITING_SYNC, ERROR, WAITING_SYNC),
    )
    now = utc_now_iso()
    defaults = (
        (GREYNOISE, "GreyNoise", int(bool(os.getenv("GREYNOISE_API_KEY", "").strip()))),
        (CEREAL2, "Cereal2", 1),
        (TEAM_CYMRU, "Team Cymru", 1),
        (FEODO, "Feodo Tracker", 1),
        (BLOCKLIST_DE, "Blocklist.de", 0),
    )
    for provider, display_name, public_default in defaults:
        env_enabled = os.getenv(f"GMJFLOW_THREAT_INTEL_{provider}_ENABLED")
        enabled = public_default if env_enabled is None else int(env_enabled.strip().lower() in {"1", "true", "yes", "on"})
        interval = int(os.getenv(f"GMJFLOW_THREAT_INTEL_{provider}_INTERVAL_SECONDS", str(DEFAULT_INTERVALS[provider])))
        credential = int(bool(os.getenv("GREYNOISE_API_KEY", "").strip())) if provider == GREYNOISE else 1
        conn.execute(
            """
            INSERT INTO threat_intel_providers (
                provider, display_name, enabled, status, credential_configured,
                sync_interval_seconds, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider) DO UPDATE SET
                display_name = excluded.display_name,
                credential_configured = excluded.credential_configured,
                sync_interval_seconds = CASE
                    WHEN threat_intel_providers.sync_interval_seconds <= 0 THEN excluded.sync_interval_seconds
                    ELSE threat_intel_providers.sync_interval_seconds END,
                updated_at = excluded.updated_at
            """,
            (provider, display_name, enabled, DISABLED if not enabled else WAITING_SYNC, credential, interval, now),
        )


class ThreatIntelError(RuntimeError):
    status = DEGRADED

    def __init__(
        self,
        message: str,
        *,
        phase: str = "",
        endpoint: str = "",
        pages: int = 0,
        items_processed: int = 0,
    ) -> None:
        super().__init__(message)
        self.phase = clean_text(phase)
        self.endpoint = clean_text(endpoint)
        self.pages = max(0, int(pages))
        self.items_processed = max(0, int(items_processed))


class ThreatIntelAuthError(ThreatIntelError):
    status = AUTH_ERROR


class ThreatIntelRateLimitError(ThreatIntelError):
    status = RATE_LIMITED


class ThreatIntelOfflineError(ThreatIntelError):
    status = ERROR


@dataclass
class SyncResult:
    provider: str
    status: str
    pages: int = 0
    items_processed: int = 0
    item_count: int = 0
    duration_ms: int = 0
    error: str = ""
    phase: str = ""
    endpoint: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status,
            "pages": self.pages,
            "items_processed": self.items_processed,
            "item_count": self.item_count,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "phase": self.phase,
            "endpoint": self.endpoint,
        }


class ThreatIntelProvider(ABC):
    provider = ""
    display_name = ""
    requires_credential = False

    def __init__(self, connection_factory: ConnectionFactory, opener: UrlOpener | None = None) -> None:
        self.connection_factory = connection_factory
        self.opener = opener or urllib.request.urlopen

    @property
    def provider_status(self) -> str:
        return clean_text(self.status().get("status")) or WAITING_SYNC

    @property
    def last_success(self) -> str | None:
        return self.status().get("last_success")

    @property
    def last_error(self) -> str:
        return clean_text(self.status().get("last_error"))

    @property
    def last_sync(self) -> str | None:
        return self.status().get("last_sync")

    @property
    def item_count(self) -> int:
        return int(self.status().get("item_count") or 0)

    def status(self) -> dict[str, Any]:
        with self.connection_factory() as conn:
            ensure_threat_intel_schema(conn)
            row = conn.execute(
                "SELECT * FROM threat_intel_providers WHERE provider = ?", (self.provider,)
            ).fetchone()
            return dict(row) if row is not None else {}

    def enabled(self) -> bool:
        return bool(self.status().get("enabled"))

    def credential_configured(self) -> bool:
        return not self.requires_credential or bool(os.getenv("GREYNOISE_API_KEY", "").strip())

    def _request(self, url: str, *, headers: Mapping[str, str] | None = None, timeout: int | None = None) -> bytes:
        request_headers = {"Accept": "application/json", "User-Agent": "GMJ-FLOW/1.0"}
        request_headers.update(dict(headers or {}))
        request = urllib.request.Request(url, headers=request_headers, method="GET")
        try:
            with self.opener(request, timeout=timeout or self.timeout_seconds()) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise ThreatIntelAuthError(f"HTTP {exc.code}: credencial rejeitada") from None
            if exc.code == 429:
                raise ThreatIntelRateLimitError("HTTP 429: limite do provider atingido") from None
            if 500 <= exc.code < 600:
                raise ThreatIntelOfflineError(f"HTTP {exc.code}: provider indisponivel") from None
            raise ThreatIntelError(f"HTTP {exc.code}: requisicao rejeitada") from None
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            raise ThreatIntelOfflineError(clean_text(getattr(exc, "reason", exc)) or "provider indisponivel") from None

    def _request_json(self, url: str, *, headers: Mapping[str, str] | None = None) -> Any:
        payload = self._request(url, headers=headers)
        try:
            return json.loads(payload.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ThreatIntelError(f"JSON invalido: {exc.msg}") from None

    def timeout_seconds(self) -> int:
        return max(2, min(int(os.getenv("GMJFLOW_THREAT_INTEL_HTTP_TIMEOUT_SECONDS", "30")), 120))

    def _upsert_indicators(self, items: Iterable[dict[str, Any]], sync_token: str) -> int:
        rows = []
        now = utc_now_iso()
        for item in items:
            ip_text = clean_text(item.get("ip"))
            network = clean_text(item.get("network"))
            if not ip_text and not network:
                continue
            rows.append(
                (
                    self.provider,
                    clean_text(item.get("indicator_type")) or "IP",
                    ip_text,
                    network,
                    clean_text(item.get("classification")),
                    clean_text(item.get("actor")),
                    int(item.get("asn") or 0),
                    clean_text(item.get("organization")),
                    clean_text(item.get("country")),
                    clean_text(item.get("country_code")).upper(),
                    clean_text(item.get("city")),
                    int(bool(item.get("spoofable"))),
                    int(bool(item.get("vpn"))),
                    int(bool(item.get("tor"))),
                    clean_text(item.get("first_seen")) or None,
                    clean_text(item.get("last_seen")) or None,
                    clean_text(item.get("botnet_family")),
                    item.get("recency_seconds"),
                    json_dump(item.get("tags") or []),
                    json_dump(item.get("metadata") or {}),
                    sync_token,
                    now,
                )
            )
        if not rows:
            return 0
        with self.connection_factory() as conn:
            conn.executemany(
                """
                INSERT INTO threat_intel_indicators (
                    provider, indicator_type, ip, network, classification, actor, asn,
                    organization, country, country_code, city, spoofable, vpn, tor,
                    first_seen, last_seen, botnet_family, recency_seconds, tags_json,
                    metadata_json, sync_token, active, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(provider, indicator_type, ip, network) DO UPDATE SET
                    classification=excluded.classification, actor=excluded.actor, asn=excluded.asn,
                    organization=excluded.organization, country=excluded.country,
                    country_code=excluded.country_code, city=excluded.city,
                    spoofable=excluded.spoofable, vpn=excluded.vpn, tor=excluded.tor,
                    first_seen=COALESCE(excluded.first_seen, threat_intel_indicators.first_seen),
                    last_seen=excluded.last_seen, botnet_family=excluded.botnet_family,
                    recency_seconds=excluded.recency_seconds, tags_json=excluded.tags_json,
                    metadata_json=excluded.metadata_json, sync_token=excluded.sync_token,
                    active=1, updated_at=excluded.updated_at
                """,
                rows,
            )
            conn.commit()
        return len(rows)

    def _complete_indicator_sync(self, sync_token: str) -> int:
        with self.connection_factory() as conn:
            conn.execute(
                "UPDATE threat_intel_indicators SET active = 0 WHERE provider = ? AND sync_token <> ?",
                (self.provider, sync_token),
            )
            count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM threat_intel_indicators WHERE provider = ? AND active = 1",
                    (self.provider,),
                ).fetchone()[0]
            )
            conn.commit()
        return count

    @abstractmethod
    def normalize(self, raw: Mapping[str, Any]) -> dict[str, Any] | None:
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def sync(self) -> SyncResult:
        raise NotImplementedError

    def lookup_ip(self, ip: str, context: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        try:
            normalized = str(ip_address(ip))
        except ValueError:
            return []
        with self.connection_factory() as conn:
            rows = conn.execute(
                """
                SELECT * FROM threat_intel_indicators
                WHERE provider = ? AND ip = ? AND active = 1
                ORDER BY last_seen DESC
                """,
                (self.provider, normalized),
            ).fetchall()
        return [indicator_row(item) for item in rows]


def greynoise_tag(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, str):
        return {"slug": raw, "name": raw, "category": "", "intention": "", "recommend_block": False, "cves": []}
    if not isinstance(raw, Mapping):
        return None
    return {
        "slug": clean_text(raw.get("slug") or raw.get("id") or raw.get("name")),
        "name": clean_text(raw.get("name") or raw.get("slug")),
        "category": clean_text(raw.get("category")),
        "intention": clean_text(raw.get("intention")),
        "recommend_block": bool(raw.get("recommend_block")),
        "cves": [clean_text(item) for item in (raw.get("cves") or []) if clean_text(item)],
    }


class GreyNoiseProvider(ThreatIntelProvider):
    provider = GREYNOISE
    display_name = "GreyNoise"
    requires_credential = True

    def api_key(self) -> str:
        return os.getenv("GREYNOISE_API_KEY", "").strip()

    def normalize(self, raw: Mapping[str, Any]) -> dict[str, Any] | None:
        scanner = raw.get("internet_scanner_intelligence")
        source = scanner if isinstance(scanner, Mapping) else raw
        metadata = source.get("metadata") if isinstance(source.get("metadata"), Mapping) else {}
        location = source.get("location") if isinstance(source.get("location"), Mapping) else metadata
        ip_text = clean_text(raw.get("ip") or source.get("ip"))
        try:
            ip_text = str(ip_address(ip_text))
        except ValueError:
            return None
        tags = [tag for tag in (greynoise_tag(value) for value in (source.get("tags") or [])) if tag]
        asn_value = clean_text(source.get("asn") or metadata.get("asn")).upper().replace("AS", "")
        return {
            "indicator_type": "IP",
            "ip": ip_text,
            "classification": clean_text(source.get("classification")).lower(),
            "actor": clean_text(source.get("actor")),
            "asn": int(asn_value) if asn_value.isdigit() else 0,
            "organization": clean_text(source.get("organization") or metadata.get("organization")),
            "country": clean_text(location.get("country") or location.get("country_name")),
            "country_code": clean_text(location.get("country_code")),
            "city": clean_text(location.get("city")),
            "spoofable": bool(source.get("spoofable")),
            "vpn": bool(source.get("vpn")),
            "tor": bool(source.get("tor")),
            "last_seen": clean_text(source.get("last_seen")) or None,
            "tags": tags,
            "metadata": {},
        }

    def _query_page(self, query: str, scroll: str = "") -> Mapping[str, Any]:
        if not self.api_key():
            raise ThreatIntelAuthError("GREYNOISE_API_KEY nao configurada")
        params = {"query": query, "size": "1000", "exclude_raw": "true"}
        if scroll:
            params["scroll"] = scroll
        base = os.getenv("GREYNOISE_GNQL_URL", "https://api.greynoise.io/v3/gnql").strip()
        result = self._request_json(
            f"{base}?{urllib.parse.urlencode(params)}",
            headers={"key": self.api_key()},
        )
        if not isinstance(result, Mapping):
            raise ThreatIntelError("Resposta GNQL nao e um objeto")
        return result

    def health_check(self) -> dict[str, Any]:
        started = time.monotonic()
        page = self._query_page('last_seen:1d classification:"malicious"')
        return {
            "ok": True,
            "status": ACTIVE,
            "latency_ms": int((time.monotonic() - started) * 1000),
            "sample_count": len(page.get("data") or []),
        }

    def sync(self) -> SyncResult:
        started = time.monotonic()
        token = uuid.uuid4().hex
        pages = processed = 0
        for query in GREYNOISE_QUERIES:
            scroll = ""
            seen_scrolls: set[str] = set()
            while True:
                payload = self._query_page(query, scroll)
                raw_items = payload.get("data") or []
                if not isinstance(raw_items, list):
                    raise ThreatIntelError("Campo data GNQL invalido")
                page_items = [item for item in (self.normalize(raw) for raw in raw_items if isinstance(raw, Mapping)) if item]
                processed += self._upsert_indicators(page_items, token)
                pages += 1
                metadata = payload.get("request_metadata") if isinstance(payload.get("request_metadata"), Mapping) else {}
                complete = bool(metadata.get("complete", True))
                next_scroll = clean_text(metadata.get("scroll"))
                if complete or not next_scroll:
                    break
                if next_scroll in seen_scrolls:
                    raise ThreatIntelError("Cursor GNQL repetido")
                seen_scrolls.add(next_scroll)
                scroll = next_scroll
        active = self._complete_indicator_sync(token)
        return SyncResult(self.provider, ACTIVE, pages, processed, active, int((time.monotonic() - started) * 1000))


class Cereal2Provider(ThreatIntelProvider):
    provider = CEREAL2
    display_name = "Cereal2"

    @property
    def base_url(self) -> str:
        return os.getenv("CEREAL2_BASE_URL", "https://cereal2.botnet.cl").strip().rstrip("/")

    def normalize(self, raw: Mapping[str, Any]) -> dict[str, Any] | None:
        ip_text = clean_text(raw.get("ip"))
        try:
            ip_text = str(ip_address(ip_text))
        except ValueError:
            return None
        last_seen = clean_text(raw.get("last_seen")) or None
        recency = None
        if last_seen:
            try:
                seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                recency = max(0, int((utc_now() - seen.astimezone(timezone.utc)).total_seconds()))
            except ValueError:
                pass
        return {
            "indicator_type": "C2",
            "ip": ip_text,
            "classification": "c2",
            "asn": int(raw.get("asn") or 0),
            "organization": clean_text(raw.get("asn_name")),
            "country_code": clean_text(raw.get("country_code")),
            "first_seen": clean_text(raw.get("first_seen")) or None,
            "last_seen": last_seen,
            "botnet_family": clean_text(raw.get("botnet_family") or raw.get("family")),
            "recency_seconds": recency,
            "tags": [],
            "metadata": {},
        }

    def normalize_attack(self, raw: Mapping[str, Any]) -> dict[str, Any] | None:
        target = raw.get("target") if isinstance(raw.get("target"), Mapping) else {}
        attack = raw.get("attack") if isinstance(raw.get("attack"), Mapping) else {}
        prefix = clean_text(target.get("prefix"))
        try:
            prefix = str(ip_network(prefix, strict=False))
        except ValueError:
            return None
        return {
            "external_id": clean_text(raw.get("id")) or f"seq-{int(raw.get('stream_seq') or 0)}",
            "observed_at": clean_text(raw.get("observed_at")) or utc_now_iso(),
            "country": clean_text(target.get("country_name")),
            "country_code": clean_text(target.get("country_code")).upper(),
            "target_prefix": prefix,
            "target_asn": int(target.get("asn") or 0),
            "target_organization": clean_text(target.get("asn_name")),
            "method": clean_text(attack.get("method_label")),
            "protocol": clean_text(attack.get("protocol")).lower(),
            "target_port": int(attack["target_port"]) if attack.get("target_port") is not None else None,
            "duration_seconds": int(attack.get("duration_seconds") or 0),
            "stream_sequence": int(raw.get("stream_seq") or 0),
        }

    def _upsert_attacks(self, items: Iterable[dict[str, Any]], sync_token: str) -> int:
        rows = []
        now = utc_now_iso()
        for item in items:
            rows.append(
                (
                    self.provider, item["external_id"], item["observed_at"], item["country"],
                    item["country_code"], item["target_prefix"], item["target_asn"],
                    item["target_organization"], item["method"], item["protocol"],
                    item["target_port"], item["duration_seconds"], item["stream_sequence"],
                    sync_token, now,
                )
            )
        if not rows:
            return 0
        with self.connection_factory() as conn:
            conn.executemany(
                """
                INSERT INTO external_attack_observations (
                    provider, external_id, observed_at, country, country_code, target_prefix,
                    target_asn, target_organization, method, protocol, target_port,
                    duration_seconds, stream_sequence, sync_token, active, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(provider, external_id) DO UPDATE SET
                    observed_at=excluded.observed_at, country=excluded.country,
                    country_code=excluded.country_code, target_prefix=excluded.target_prefix,
                    target_asn=excluded.target_asn, target_organization=excluded.target_organization,
                    method=excluded.method, protocol=excluded.protocol,
                    target_port=excluded.target_port, duration_seconds=excluded.duration_seconds,
                    stream_sequence=excluded.stream_sequence, sync_token=excluded.sync_token,
                    active=1, updated_at=excluded.updated_at
                """,
                rows,
            )
            conn.commit()
        return len(rows)

    def health_check(self) -> dict[str, Any]:
        started = time.monotonic()
        payload = self._request_json(f"{self.base_url}/api/v1/c2")
        required = {"schema_version", "last_updated", "count", "entries"}
        if not isinstance(payload, Mapping) or not required.issubset(payload) or not isinstance(payload.get("entries"), list):
            raise ThreatIntelError("Resposta Cereal2 C2 incompleta", phase="health_check", endpoint="/api/v1/c2")
        return {
            "ok": True,
            "status": ACTIVE,
            "latency_ms": int((time.monotonic() - started) * 1000),
        }

    def _phase_json(
        self,
        url: str,
        *,
        phase: str,
        endpoint: str,
        pages: int,
        items_processed: int,
    ) -> Any:
        try:
            return self._request_json(url)
        except ThreatIntelError as exc:
            exc.phase = exc.phase or phase
            exc.endpoint = exc.endpoint or endpoint
            exc.pages = max(exc.pages, pages)
            exc.items_processed = max(exc.items_processed, items_processed)
            raise

    @staticmethod
    def _invalid_response(
        message: str,
        *,
        phase: str,
        endpoint: str,
        pages: int,
        items_processed: int,
    ) -> ThreatIntelError:
        return ThreatIntelError(
            message,
            phase=phase,
            endpoint=endpoint,
            pages=pages,
            items_processed=items_processed,
        )

    def sync(self) -> SyncResult:
        started = time.monotonic()
        token = uuid.uuid4().hex
        pages = staged = 0
        c2_endpoint = "/api/v1/c2"
        c2_payload = self._phase_json(
            f"{self.base_url}{c2_endpoint}",
            phase="c2_snapshot",
            endpoint=c2_endpoint,
            pages=pages,
            items_processed=staged,
        )
        required_c2 = {"schema_version", "last_updated", "count", "entries"}
        if not isinstance(c2_payload, Mapping) or not required_c2.issubset(c2_payload):
            raise self._invalid_response(
                "Resposta Cereal2 C2 incompleta",
                phase="c2_snapshot",
                endpoint=c2_endpoint,
                pages=pages,
                items_processed=staged,
            )
        c2_entries = c2_payload["entries"]
        try:
            expected_c2_count = int(c2_payload["count"])
        except (TypeError, ValueError):
            expected_c2_count = -1
        if not isinstance(c2_entries, list) or expected_c2_count != len(c2_entries):
            raise self._invalid_response(
                "Snapshot Cereal2 C2 inconsistente",
                phase="c2_snapshot",
                endpoint=c2_endpoint,
                pages=pages,
                items_processed=staged,
            )
        normalized_c2 = [self.normalize(raw) for raw in c2_entries if isinstance(raw, Mapping)]
        if len(normalized_c2) != len(c2_entries) or any(item is None for item in normalized_c2):
            raise self._invalid_response(
                "Snapshot Cereal2 C2 contem entrada invalida",
                phase="c2_snapshot",
                endpoint=c2_endpoint,
                pages=pages,
                items_processed=staged,
            )
        c2_items = [item for item in normalized_c2 if item is not None]
        staged += len(c2_items)
        pages += 1

        cursor = ""
        seen: set[str] = set()
        attack_items: dict[str, dict[str, Any]] = {}
        attack_endpoint = "/api/v1/attacks"
        configured_page_size = int(os.getenv("GMJFLOW_CEREAL2_ATTACK_PAGE_SIZE", "200"))
        configured_max_pages = int(os.getenv("GMJFLOW_CEREAL2_ATTACK_MAX_PAGES", "20"))
        page_size = 200 if configured_page_size <= 0 else min(configured_page_size, 200)
        max_pages = 20 if configured_max_pages <= 0 else min(configured_max_pages, 1000)
        watermark = ""
        for attack_page in range(1, max_pages + 1):
            params = {"limit": str(page_size)}
            if cursor:
                params["cursor"] = cursor
            phase = f"attacks_page_{attack_page}"
            payload = self._phase_json(
                f"{self.base_url}{attack_endpoint}?{urllib.parse.urlencode(params)}",
                phase=phase,
                endpoint=attack_endpoint,
                pages=pages,
                items_processed=staged,
            )
            required_attack = {"events", "next_cursor", "watermark"}
            if not isinstance(payload, Mapping) or not required_attack.issubset(payload):
                raise self._invalid_response(
                    "Resposta Cereal2 attacks incompleta",
                    phase=phase,
                    endpoint=attack_endpoint,
                    pages=pages,
                    items_processed=staged,
                )
            events = payload["events"]
            current_watermark = clean_text(payload["watermark"])
            if not isinstance(events, list) or not current_watermark or (watermark and watermark != current_watermark):
                raise self._invalid_response(
                    "Resposta Cereal2 attacks inconsistente",
                    phase=phase,
                    endpoint=attack_endpoint,
                    pages=pages,
                    items_processed=staged,
                )
            watermark = current_watermark
            normalized = [self.normalize_attack(raw) for raw in events if isinstance(raw, Mapping)]
            if len(normalized) != len(events) or any(item is None for item in normalized):
                raise self._invalid_response(
                    "Pagina Cereal2 attacks contem evento invalido",
                    phase=phase,
                    endpoint=attack_endpoint,
                    pages=pages,
                    items_processed=staged,
                )
            for item in normalized:
                if item is not None:
                    attack_items[item["external_id"]] = item
            staged += len(normalized)
            pages += 1
            next_cursor = clean_text(payload["next_cursor"])
            if not next_cursor or not events:
                break
            if next_cursor == cursor or next_cursor in seen:
                raise self._invalid_response(
                    "Cursor Cereal2 attacks repetido",
                    phase=phase,
                    endpoint=attack_endpoint,
                    pages=pages,
                    items_processed=staged,
                )
            seen.add(next_cursor)
            cursor = next_cursor

        # No provider state is mutated until the complete snapshot and all accepted
        # attack pages have passed structural validation.
        processed = self._upsert_indicators(c2_items, token)
        processed += self._upsert_attacks(attack_items.values(), token)
        active_indicators = self._complete_indicator_sync(token)
        with self.connection_factory() as conn:
            # Attack telemetry is append-oriented. Retain a bounded operational history.
            cutoff = (utc_now() - timedelta(days=max(1, int(os.getenv("GMJFLOW_CEREAL2_ATTACK_RETENTION_DAYS", "30"))))).isoformat().replace("+00:00", "Z")
            conn.execute("UPDATE external_attack_observations SET active = 0 WHERE provider = ? AND observed_at < ?", (self.provider, cutoff))
            attack_count = int(conn.execute("SELECT COUNT(*) FROM external_attack_observations WHERE provider = ? AND active = 1", (self.provider,)).fetchone()[0])
            conn.commit()
        return SyncResult(self.provider, ACTIVE, pages, processed, active_indicators + attack_count, int((time.monotonic() - started) * 1000))


class FeodoProvider(ThreatIntelProvider):
    provider = FEODO
    display_name = "Feodo Tracker"

    @property
    def feed_url(self) -> str:
        return os.getenv("FEODO_FEED_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist.json").strip()

    def normalize(self, raw: Mapping[str, Any]) -> dict[str, Any] | None:
        ip_text = clean_text(raw.get("ip_address") or raw.get("ip"))
        try:
            ip_text = str(ip_address(ip_text))
        except ValueError:
            return None
        asn_value = clean_text(raw.get("as_number") or raw.get("asn")).upper().replace("AS", "")
        return {
            "indicator_type": "C2",
            "ip": ip_text,
            "classification": "c2",
            "asn": int(asn_value) if asn_value.isdigit() else 0,
            "organization": clean_text(raw.get("as_name")),
            "country_code": clean_text(raw.get("country")),
            "first_seen": clean_text(raw.get("first_seen")) or None,
            "last_seen": clean_text(raw.get("last_online") or raw.get("last_seen")) or None,
            "botnet_family": clean_text(raw.get("malware")),
            "tags": [],
            "metadata": {
                "port": int(raw.get("port") or 0),
                "status": clean_text(raw.get("status")),
            },
        }

    def health_check(self) -> dict[str, Any]:
        started = time.monotonic()
        payload = self._request_json(self.feed_url)
        return {"ok": isinstance(payload, list), "status": ACTIVE, "latency_ms": int((time.monotonic() - started) * 1000)}

    def sync(self) -> SyncResult:
        started = time.monotonic()
        payload = self._request_json(self.feed_url)
        if not isinstance(payload, list):
            raise ThreatIntelError("Resposta Feodo invalida")
        token = uuid.uuid4().hex
        items = [item for item in (self.normalize(raw) for raw in payload if isinstance(raw, Mapping)) if item]
        processed = self._upsert_indicators(items, token)
        active = self._complete_indicator_sync(token)
        return SyncResult(self.provider, ACTIVE, 1, processed, active, int((time.monotonic() - started) * 1000))


class TeamCymruProvider(ThreatIntelProvider):
    provider = TEAM_CYMRU
    display_name = "Team Cymru"

    FEEDS = (
        ("BOGON", "https://team-cymru.org/Services/Bogons/bogon-bn-agg.txt"),
        ("FULLBOGON", "https://team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"),
        ("FULLBOGON", "https://team-cymru.org/Services/Bogons/fullbogons-ipv6.txt"),
    )

    def normalize(self, raw: Mapping[str, Any]) -> dict[str, Any] | None:
        prefix = clean_text(raw.get("prefix"))
        try:
            network = ip_network(prefix, strict=False)
        except ValueError:
            return None
        return {
            "prefix": str(network),
            "kind": clean_text(raw.get("kind")) or "FULLBOGON",
            "ip_version": network.version,
            "prefix_length": network.prefixlen,
            "start_bin": network.network_address.packed,
            "end_bin": network.broadcast_address.packed,
        }

    def health_check(self) -> dict[str, Any]:
        started = time.monotonic()
        payload = self._request(self.FEEDS[0][1])
        ok = any(line and not line.startswith(b"#") for line in payload.splitlines())
        return {"ok": ok, "status": ACTIVE if ok else DEGRADED, "latency_ms": int((time.monotonic() - started) * 1000)}

    def sync(self) -> SyncResult:
        started = time.monotonic()
        token = uuid.uuid4().hex
        pages = processed = 0
        now = utc_now_iso()
        for kind, default_url in self.FEEDS:
            env_name = f"TEAM_CYMRU_{kind}_{'IPV6' if default_url.endswith('ipv6.txt') else 'IPV4'}_URL"
            body = self._request(os.getenv(env_name, default_url).strip())
            rows = []
            for raw_line in body.decode("utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                item = self.normalize({"prefix": line, "kind": kind})
                if item:
                    rows.append(
                        (
                            self.provider, item["kind"], item["prefix"], item["ip_version"],
                            item["prefix_length"], item["start_bin"], item["end_bin"], token, now,
                        )
                    )
                if len(rows) >= 2000:
                    processed += self._upsert_bogons(rows)
                    rows = []
            processed += self._upsert_bogons(rows)
            pages += 1
        with self.connection_factory() as conn:
            conn.execute("UPDATE threat_intel_bogons SET active = 0 WHERE provider = ? AND sync_token <> ?", (self.provider, token))
            active = int(conn.execute("SELECT COUNT(*) FROM threat_intel_bogons WHERE provider = ? AND active = 1", (self.provider,)).fetchone()[0])
            conn.commit()
        return SyncResult(self.provider, ACTIVE, pages, processed, active, int((time.monotonic() - started) * 1000))

    def _upsert_bogons(self, rows: list[tuple[Any, ...]]) -> int:
        if not rows:
            return 0
        with self.connection_factory() as conn:
            conn.executemany(
                """
                INSERT INTO threat_intel_bogons (
                    provider, kind, prefix, ip_version, prefix_length,
                    start_bin, end_bin, sync_token, active, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(provider, kind, prefix) DO UPDATE SET
                    ip_version=excluded.ip_version, prefix_length=excluded.prefix_length,
                    start_bin=excluded.start_bin, end_bin=excluded.end_bin,
                    sync_token=excluded.sync_token, active=1, updated_at=excluded.updated_at
                """,
                rows,
            )
            conn.commit()
        return len(rows)

    def lookup_ip(self, ip: str, context: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        try:
            parsed = ip_address(ip)
        except ValueError:
            return []
        packed = parsed.packed
        with self.connection_factory() as conn:
            rows = conn.execute(
                """
                SELECT kind, prefix, prefix_length
                FROM threat_intel_bogons
                WHERE provider = ? AND ip_version = ? AND active = 1
                  AND start_bin <= ? AND end_bin >= ?
                ORDER BY CASE kind WHEN 'BOGON' THEN 0 ELSE 1 END, prefix_length DESC
                """,
                (self.provider, parsed.version, packed, packed),
            ).fetchall()
        context_type = clean_text((context or {}).get("context_type")).upper()
        internal_context = context_type in {"INTERNAL", "CGNAT", "BRAS", "MANAGEMENT"}
        transit_context = context_type in {"TRANSIT", "INTERNET", "EXTERNAL"}
        special_internal = parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed in ip_network("100.64.0.0/10")
        return [
            {
                "provider": self.provider,
                "indicator_type": row["kind"],
                "ip": str(parsed),
                "network": row["prefix"],
                "classification": (
                    "context_normal" if special_internal and internal_context
                    else "context_unknown" if special_internal and not transit_context
                    else "anomalous_source"
                ),
                "spoofing_likelihood": (
                    0 if special_internal and (internal_context or not transit_context)
                    else (90 if row["kind"] == "BOGON" else 65)
                ),
                "network_context": context_type or "UNKNOWN",
            }
            for row in rows
        ]


class BlocklistDeProvider(ThreatIntelProvider):
    provider = BLOCKLIST_DE
    display_name = "Blocklist.de"

    @property
    def feed_url(self) -> str:
        return os.getenv("BLOCKLIST_DE_FEED_URL", "https://lists.blocklist.de/lists/all.txt").strip()

    def normalize(self, raw: Mapping[str, Any]) -> dict[str, Any] | None:
        raise ThreatIntelError("BLOCKLIST_DE ainda nao implementado")

    def health_check(self) -> dict[str, Any]:
        raise ThreatIntelError("BLOCKLIST_DE ainda nao implementado")

    def sync(self) -> SyncResult:
        raise ThreatIntelError("BLOCKLIST_DE ainda nao implementado")


def indicator_row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    item["spoofable"] = bool(item.get("spoofable"))
    item["vpn"] = bool(item.get("vpn"))
    item["tor"] = bool(item.get("tor"))
    item["active"] = bool(item.get("active"))
    item["tags"] = safe_json(item.pop("tags_json", "[]"), [])
    item["metadata"] = safe_json(item.pop("metadata_json", "{}"), {})
    return item


class ThreatIntelManager:
    """Failure-isolated registry and scheduler for external intelligence providers."""

    def __init__(self, connection_factory: ConnectionFactory = sqlite_connection, opener: UrlOpener | None = None) -> None:
        self.connection_factory = connection_factory
        self.providers: dict[str, ThreatIntelProvider] = {
            GREYNOISE: GreyNoiseProvider(connection_factory, opener),
            CEREAL2: Cereal2Provider(connection_factory, opener),
            TEAM_CYMRU: TeamCymruProvider(connection_factory, opener),
            FEODO: FeodoProvider(connection_factory, opener),
            BLOCKLIST_DE: BlocklistDeProvider(connection_factory, opener),
        }
        self._sync_locks = {name: Lock() for name in self.providers}
        self._stop = Event()
        self._thread: Thread | None = None

    def ensure_schema(self) -> None:
        with self.connection_factory() as conn:
            ensure_threat_intel_schema(conn)
            conn.commit()

    def provider(self, name: str) -> ThreatIntelProvider:
        key = clean_text(name).upper()
        if key not in self.providers:
            raise KeyError(f"provider desconhecido: {key}")
        return self.providers[key]

    @staticmethod
    def _usable_item_count(conn: sqlite3.Connection, provider: str) -> int:
        if provider == TEAM_CYMRU:
            return int(conn.execute(
                "SELECT COUNT(*) FROM threat_intel_bogons WHERE provider=? AND active=1",
                (provider,),
            ).fetchone()[0])
        indicator_count = int(conn.execute(
            "SELECT COUNT(*) FROM threat_intel_indicators WHERE provider=? AND active=1",
            (provider,),
        ).fetchone()[0])
        if provider != CEREAL2:
            return indicator_count
        attack_count = int(conn.execute(
            "SELECT COUNT(*) FROM external_attack_observations WHERE provider=? AND active=1",
            (provider,),
        ).fetchone()[0])
        return indicator_count + attack_count

    @staticmethod
    def _semantic_status(item: Mapping[str, Any], usable_count: int) -> str:
        if not bool(item.get("enabled")):
            return DISABLED
        stored = clean_text(item.get("status")).upper()
        if stored == AUTH_ERROR:
            return AUTH_ERROR
        if stored == RATE_LIMITED:
            return RATE_LIMITED
        if clean_text(item.get("last_error")):
            return DEGRADED if usable_count > 0 else ERROR
        if usable_count > 0:
            return ACTIVE
        return WAITING_SYNC

    def statuses(self) -> list[dict[str, Any]]:
        self.ensure_schema()
        with self.connection_factory() as conn:
            rows = conn.execute("SELECT * FROM threat_intel_providers ORDER BY provider").fetchall()
            items = []
            for row in rows:
                item = dict(row)
                item["enabled"] = bool(item.get("enabled"))
                item["credential_configured"] = bool(item.get("credential_configured"))
                item["config"] = safe_json(item.pop("config_json", "{}"), {})
                usable_count = self._usable_item_count(conn, clean_text(item.get("provider")))
                item["item_count"] = usable_count
                item["data_usable"] = usable_count > 0
                item["status"] = self._semantic_status(item, usable_count)
                items.append(item)
        return items

    def _persist_outcome(self, result: SyncResult, started_at: str, error_status: str = "") -> SyncResult:
        completed = utc_now_iso()
        requested_status = error_status or result.status
        next_sync = (utc_now() + timedelta(seconds=self.interval_seconds(result.provider))).isoformat().replace("+00:00", "Z")
        credential_configured = int(self.provider(result.provider).credential_configured())
        with self.connection_factory() as conn:
            usable_count = self._usable_item_count(conn, result.provider)
            if requested_status in {ACTIVE, ONLINE}:
                status = ACTIVE
            elif requested_status in {AUTH_ERROR, RATE_LIMITED}:
                status = requested_status
            else:
                status = DEGRADED if usable_count > 0 else ERROR
            result.item_count = usable_count
            conn.execute(
                """
                UPDATE threat_intel_providers SET
                    status=?, last_sync=?, last_success=CASE WHEN ? = 'ACTIVE' THEN ? ELSE last_success END,
                    last_error=?, last_sync_duration_ms=?, next_sync=?, item_count=?,
                    credential_configured=?, updated_at=?
                WHERE provider=?
                """,
                (
                    status, completed, status, completed, result.error, result.duration_ms, next_sync,
                    result.item_count, credential_configured, completed,
                    result.provider,
                ),
            )
            conn.execute(
                """
                INSERT INTO threat_intel_sync_audit (
                    provider, started_at, completed_at, status, pages, items_processed,
                    items_active, phase, endpoint, error_message, duration_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.provider, started_at, completed, status, result.pages,
                    result.items_processed, result.item_count, result.phase, result.endpoint,
                    result.error, result.duration_ms,
                ),
            )
            conn.commit()
        result.status = status
        return result

    def interval_seconds(self, provider: str) -> int:
        with self.connection_factory() as conn:
            row = conn.execute("SELECT sync_interval_seconds FROM threat_intel_providers WHERE provider = ?", (provider,)).fetchone()
        return max(60, int(row[0] if row else DEFAULT_INTERVALS[provider]))

    def sync(self, provider: str) -> dict[str, Any]:
        self.ensure_schema()
        instance = self.provider(provider)
        status = next(item for item in self.statuses() if item["provider"] == instance.provider)
        if not bool(status.get("enabled")):
            return SyncResult(instance.provider, DISABLED, error="provider desabilitado", item_count=int(status.get("item_count") or 0)).as_dict()
        if instance.requires_credential and not instance.credential_configured():
            result = SyncResult(instance.provider, AUTH_ERROR, error="credencial nao configurada", item_count=int(status.get("item_count") or 0))
            return self._persist_outcome(result, utc_now_iso(), AUTH_ERROR).as_dict()
        lock = self._sync_locks[instance.provider]
        if not lock.acquire(blocking=False):
            return SyncResult(instance.provider, DEGRADED, error="sync ja em andamento", item_count=int(status.get("item_count") or 0)).as_dict()
        started_at = utc_now_iso()
        started = time.monotonic()
        try:
            result = instance.sync()
            return self._persist_outcome(result, started_at).as_dict()
        except ThreatIntelError as exc:
            result = SyncResult(
                instance.provider, exc.status, pages=exc.pages, items_processed=exc.items_processed,
                duration_ms=int((time.monotonic() - started) * 1000),
                error=clean_text(exc), item_count=int(status.get("item_count") or 0),
                phase=exc.phase, endpoint=exc.endpoint,
            )
            LOGGER.warning("THREAT_INTEL_SYNC_FAILED provider=%s status=%s error=%s", instance.provider, exc.status, exc)
            return self._persist_outcome(result, started_at, exc.status).as_dict()
        except Exception as exc:  # A provider failure must never escape into the threat engine.
            result = SyncResult(
                instance.provider, ERROR, duration_ms=int((time.monotonic() - started) * 1000),
                error=clean_text(exc) or exc.__class__.__name__, item_count=int(status.get("item_count") or 0),
                phase="provider_sync",
            )
            LOGGER.exception("THREAT_INTEL_SYNC_FAILED provider=%s", instance.provider)
            return self._persist_outcome(result, started_at, ERROR).as_dict()
        finally:
            lock.release()

    def health_check(self, provider: str) -> dict[str, Any]:
        self.ensure_schema()
        instance = self.provider(provider)
        if not instance.enabled():
            return {"provider": instance.provider, "ok": False, "status": DISABLED, "error": "provider desabilitado"}
        if instance.requires_credential and not instance.credential_configured():
            return {"provider": instance.provider, "ok": False, "status": AUTH_ERROR, "error": "credencial nao configurada"}
        try:
            return {"provider": instance.provider, **instance.health_check(), "error": ""}
        except ThreatIntelError as exc:
            cached = next(item for item in self.statuses() if item["provider"] == instance.provider)
            check_status = exc.status if exc.status in {AUTH_ERROR, RATE_LIMITED} else DEGRADED if cached["data_usable"] else ERROR
            return {"provider": instance.provider, "ok": False, "status": check_status, "error": clean_text(exc)}
        except Exception as exc:
            cached = next(item for item in self.statuses() if item["provider"] == instance.provider)
            return {"provider": instance.provider, "ok": False, "status": DEGRADED if cached["data_usable"] else ERROR, "error": clean_text(exc)}

    def set_enabled(self, provider: str, enabled: bool) -> dict[str, Any]:
        instance = self.provider(provider)
        now = utc_now_iso()
        with self.connection_factory() as conn:
            ensure_threat_intel_schema(conn)
            usable_count = self._usable_item_count(conn, instance.provider)
            next_status = ACTIVE if enabled and usable_count > 0 else WAITING_SYNC if enabled else DISABLED
            conn.execute(
                "UPDATE threat_intel_providers SET enabled=?, status=?, updated_at=? WHERE provider=?",
                (int(enabled), next_status, now, instance.provider),
            )
            conn.commit()
        return next(item for item in self.statuses() if item["provider"] == instance.provider)

    def resolve_network_context(self, context: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
        supplied = dict(context or {})
        sensor = clean_text(supplied.get("sensor"))
        exporter_ip = clean_text(supplied.get("exporter_ip"))
        input_if = supplied.get("input_if")
        output_if = supplied.get("output_if")
        with self.connection_factory() as conn:
            rows = conn.execute(
                """
                SELECT * FROM threat_network_contexts
                WHERE enabled=1
                  AND (sensor_name='' OR sensor_name=?)
                  AND (exporter_ip='' OR exporter_ip=?)
                  AND (input_if IS NULL OR input_if=?)
                  AND (output_if IS NULL OR output_if=?)
                ORDER BY
                  (CASE WHEN sensor_name<>'' THEN 1 ELSE 0 END
                   + CASE WHEN exporter_ip<>'' THEN 1 ELSE 0 END
                   + CASE WHEN input_if IS NOT NULL THEN 1 ELSE 0 END
                   + CASE WHEN output_if IS NOT NULL THEN 1 ELSE 0 END) DESC,
                  id DESC
                LIMIT 1
                """,
                (sensor, exporter_ip, input_if, output_if),
            ).fetchone()
        if rows is None:
            return None
        item = dict(rows)
        item["protected_ranges"] = safe_json(item.pop("protected_ranges_json", "[]"), [])
        item["enabled"] = bool(item.get("enabled"))
        return item

    def lookup_ip(self, ip: str, context: Mapping[str, Any] | None = None) -> dict[str, Any]:
        matches: list[dict[str, Any]] = []
        errors: dict[str, str] = {}
        effective_context = dict(context or {})
        resolved_context = self.resolve_network_context(effective_context)
        if resolved_context is not None:
            effective_context["context_type"] = resolved_context["context_type"]
        for name, provider in self.providers.items():
            try:
                if provider.enabled():
                    matches.extend(provider.lookup_ip(ip, effective_context))
            except Exception as exc:
                errors[name] = clean_text(exc) or exc.__class__.__name__
        return {
            "ip": clean_text(ip),
            "matches": matches,
            "intel_sources": sorted({item["provider"] for item in matches}),
            "provider_errors": errors,
            "network_context": resolved_context or {"context_type": clean_text(effective_context.get("context_type")).upper() or "UNKNOWN"},
        }

    def external_attack_matches(
        self,
        target_prefix: str,
        protocol: str,
        observed_at: str,
        window_seconds: int = 300,
    ) -> list[dict[str, Any]]:
        try:
            local_network = ip_network(target_prefix, strict=False)
            center = datetime.fromisoformat(clean_text(observed_at).replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return []
        start = (center - timedelta(seconds=max(1, window_seconds))).isoformat().replace("+00:00", "Z")
        end = (center + timedelta(seconds=max(1, window_seconds))).isoformat().replace("+00:00", "Z")
        with self.connection_factory() as conn:
            rows = conn.execute(
                """
                SELECT * FROM external_attack_observations
                WHERE active=1 AND observed_at BETWEEN ? AND ?
                  AND (? = '' OR protocol = ?)
                ORDER BY observed_at DESC LIMIT 1000
                """,
                (start, end, clean_text(protocol).lower(), clean_text(protocol).lower()),
            ).fetchall()
        matches = []
        for row in rows:
            try:
                external_network = ip_network(row["target_prefix"], strict=False)
            except ValueError:
                continue
            if external_network.version == local_network.version and external_network.overlaps(local_network):
                matches.append(dict(row))
        return matches

    def map_aggregates(
        self,
        *,
        group_by: str = "country",
        provider: str = "",
        classification: str = "",
        tag: str = "",
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        dimensions = {
            "country": "country_code",
            "asn": "CAST(asn AS TEXT)",
            "organization": "organization",
            "ip": "ip",
        }
        key_expr = dimensions.get(group_by, dimensions["country"])
        filters = ["active = 1"]
        values: list[Any] = []
        if clean_text(provider):
            filters.append("provider = ?")
            values.append(clean_text(provider).upper())
        if clean_text(classification):
            filters.append("classification = ?")
            values.append(clean_text(classification).lower())
        if clean_text(tag):
            filters.append("lower(tags_json) LIKE ?")
            values.append(f"%{clean_text(tag).lower()}%")
        filters.append(f"TRIM({key_expr}) <> ''")
        where_clause = " AND ".join(filters)
        result_limit = max(1, min(int(limit), 2000))
        with self.connection_factory() as conn:
            rows = conn.execute(
                f"""
                SELECT {key_expr} AS key,
                       COUNT(*) AS count,
                       COUNT(DISTINCT CASE WHEN ip <> '' THEN ip ELSE network END) AS unique_ips
                FROM threat_intel_indicators
                WHERE {where_clause}
                GROUP BY {key_expr}
                ORDER BY count DESC, key
                LIMIT ?
                """,
                (*values, result_limit),
            ).fetchall()
            if not rows:
                return []
            keys = [clean_text(row["key"]) for row in rows]
            detail_rows: list[sqlite3.Row] = []
            for start in range(0, len(keys), 500):
                key_batch = keys[start:start + 500]
                placeholders = ",".join("?" for _ in key_batch)
                detail_rows.extend(
                    conn.execute(
                        f"""
                        SELECT {key_expr} AS key, country_code, country, city, asn,
                               organization, provider, classification, botnet_family, tags_json,
                               COUNT(*) AS count,
                               COUNT(DISTINCT CASE WHEN ip <> '' THEN ip ELSE network END) AS unique_ips
                        FROM threat_intel_indicators
                        WHERE {where_clause} AND {key_expr} IN ({placeholders})
                        GROUP BY {key_expr}, country_code, country, city, asn, organization,
                                 provider, classification, botnet_family, tags_json
                        """,
                        (*values, *key_batch),
                    ).fetchall()
                )

        details: dict[str, dict[str, Any]] = {}
        for row in detail_rows:
            key = clean_text(row["key"])
            bucket = details.setdefault(
                key,
                {
                    "locations": {},
                    "organizations": {},
                    "tags": {},
                    "providers": {},
                    "classifications": {},
                    "asns": {},
                },
            )
            weight = max(1, int(row["unique_ips"] or row["count"] or 0))
            location = (
                clean_text(row["country_code"]).upper(),
                clean_text(row["country"]),
                clean_text(row["city"]),
            )
            bucket["locations"][location] = bucket["locations"].get(location, 0) + weight
            organization = clean_text(row["organization"]) or "Desconhecida"
            bucket["organizations"][organization] = bucket["organizations"].get(organization, 0) + weight
            provider_name = clean_text(row["provider"]).upper()
            bucket["providers"][provider_name] = bucket["providers"].get(provider_name, 0) + weight
            classification_name = clean_text(row["classification"]).lower() or "unknown"
            bucket["classifications"][classification_name] = bucket["classifications"].get(classification_name, 0) + weight
            asn = int(row["asn"] or 0)
            if asn:
                bucket["asns"][asn] = bucket["asns"].get(asn, 0) + weight
            tags = safe_json(row["tags_json"], [])
            for tag_item in tags if isinstance(tags, list) else []:
                if isinstance(tag_item, Mapping):
                    tag_name = clean_text(tag_item.get("name") or tag_item.get("slug"))
                else:
                    tag_name = clean_text(tag_item)
                if tag_name:
                    bucket["tags"][tag_name] = bucket["tags"].get(tag_name, 0) + weight
            family = clean_text(row["botnet_family"])
            if family:
                bucket["tags"][family] = bucket["tags"].get(family, 0) + weight

        def top_values(counter: Mapping[Any, int], maximum: int = 5) -> list[dict[str, Any]]:
            return [
                {"name": str(name), "count": int(count)}
                for name, count in sorted(counter.items(), key=lambda item: (-item[1], str(item[0]).lower()))[:maximum]
            ]

        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            key = clean_text(item["key"])
            bucket = details.get(key, {})
            locations = bucket.get("locations", {})
            location = max(locations, key=lambda value: (locations[value], value)) if locations else ("", "", "")
            organizations = bucket.get("organizations", {})
            classifications = bucket.get("classifications", {})
            asns = bucket.get("asns", {})
            predominant = max(classifications, key=lambda value: (classifications[value], value)) if classifications else "unknown"
            predominant_org = max(organizations, key=lambda value: (organizations[value], value)) if organizations else ""
            predominant_asn = max(asns, key=lambda value: (asns[value], value)) if asns else 0
            if group_by == "country":
                label = location[1] or location[0] or key
            elif group_by == "asn":
                label = f"AS{key} — {predominant_org}" if predominant_org else f"AS{key}"
            else:
                label = key
            items.append(
                {
                    **item,
                    "label": label,
                    "country_code": location[0],
                    "country": location[1],
                    "city": location[2],
                    "asn": int(key) if group_by == "asn" and key.isdigit() else predominant_asn,
                    "organization": key if group_by == "organization" else predominant_org,
                    "providers": [entry["name"] for entry in top_values(bucket.get("providers", {}), 10)],
                    "top_organizations": top_values(organizations),
                    "top_tags": top_values(bucket.get("tags", {})),
                    "classification": predominant,
                    "predominant_classification": predominant,
                    "classification_breakdown": top_values(classifications),
                }
            )
        return items

    def audit(self, provider: str = "", limit: int = 100) -> list[dict[str, Any]]:
        with self.connection_factory() as conn:
            if clean_text(provider):
                rows = conn.execute(
                    "SELECT * FROM threat_intel_sync_audit WHERE provider=? ORDER BY id DESC LIMIT ?",
                    (clean_text(provider).upper(), max(1, min(int(limit), 1000))),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM threat_intel_sync_audit ORDER BY id DESC LIMIT ?",
                    (max(1, min(int(limit), 1000)),),
                ).fetchall()
        return [dict(row) for row in rows]

    def run_due_syncs(self) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        now = utc_now()
        for status in self.statuses():
            if not status["enabled"]:
                continue
            next_sync_text = clean_text(status.get("next_sync"))
            due = not next_sync_text
            if next_sync_text:
                try:
                    due = datetime.fromisoformat(next_sync_text.replace("Z", "+00:00")) <= now
                except ValueError:
                    due = True
            if due:
                results[status["provider"]] = self.sync(status["provider"])
        return results

    def start(self) -> None:
        self.ensure_schema()
        if os.getenv("GMJFLOW_THREAT_INTEL_SCHEDULER_ENABLED", "true").strip().lower() not in {"1", "true", "yes", "on"}:
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            initial_delay = max(1, int(os.getenv("GMJFLOW_THREAT_INTEL_INITIAL_DELAY_SECONDS", "15")))
            if self._stop.wait(initial_delay):
                return
            while not self._stop.is_set():
                try:
                    self.run_due_syncs()
                except Exception as exc:
                    LOGGER.warning("THREAT_INTEL_SCHEDULER_FAILED error=%s", exc)
                self._stop.wait(60)

        self._thread = Thread(target=loop, name="gmj-flow-threat-intel", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2)


THREAT_INTEL_MANAGER = ThreatIntelManager()
