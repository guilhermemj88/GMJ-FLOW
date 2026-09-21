"""Active IOC Hot Set - local data plane for O(1) lookups of active Threat
Intelligence indicators (P1 infrastructure only).

Design
------
SQLite (control plane / source of truth)
    -> normalize (IPv4/IPv6 canonicalization, provider merge, semantic tiers)
    -> immutable :class:`IocSnapshot`
    -> atomic reference swap
    -> lock-free reads via :meth:`ActiveIocHotSet.lookup`

Constraints
-----------
- ``lookup(ip)`` NEVER touches SQLite, ClickHouse, any provider HTTP API or
  any other external service. It is a pure in-memory operation.
- Snapshots are immutable. A failed refresh never replaces the last known
  good snapshot; an empty *valid* snapshot (zero active IOC read
  successfully) is distinct from a refresh failure.
- Provider information is preserved per indicator (no silent single-provider
  wins). Semantic tier/category come from ``threat_intelligence``.
- This module makes no decisions: it only answers "is this IP an active IOC
  and what metadata exists". It never whitelists by port, 443, CDN, GGC or
  expected service - those contexts belong to other layers.

Thread model
------------
Readers take a reference to the current immutable snapshot (atomic under the
CPython GIL) and never acquire a lock. Refreshes build a NEW snapshot and
swap the reference; a small lock guards refresh state only.

Configuration
-------------
- ``GMJFLOW_TI_HOTSET_ENABLED``         default "false" (opt-in; P1 not deployed)
- ``GMJFLOW_TI_HOTSET_REFRESH_SECONDS`` default 60

The P2 outbound detector consumes this module from a separate side channel.
Events, policy integration, UI and mitigation remain out of scope.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv6Address, ip_address, ip_network
from typing import Any, Callable, Mapping, Optional

from app.services.threat_intelligence import (
    clean_text,
    safe_json,
    semantic_category,
    semantic_tier,
    sqlite_connection,
    utc_now_iso,
)

LOGGER = logging.getLogger("gmj-flow")

ConnectionFactory = Callable[[], sqlite3.Connection]

DEFAULT_ENABLED = False
DEFAULT_REFRESH_SECONDS = 60


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def normalize_ip(value: Any) -> Optional[int]:
    """Return a canonical integer key for an IPv4/IPv6 address, or None.

    IPv4-mapped IPv6 addresses are unwrapped to IPv4 so that
    ``1.2.3.4`` and ``::ffff:1.2.3.4`` share the same key.
    """
    text = clean_text(value)
    if not text:
        return None
    try:
        parsed = ip_address(text)
    except ValueError:
        return None
    if isinstance(parsed, IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return int(parsed)


@dataclass(frozen=True)
class ProviderMatch:
    """One provider's normalized view of a single indicator."""

    provider: str
    indicator_type: str
    classification: str
    category: str
    tier: int
    botnet_family: str = ""
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class IocEntry:
    """Aggregated metadata for one exact IP or one network IOC.

    ``semantic_tier`` is the best (lowest) tier across providers; provider
    lists are preserved so future layers can apply provider-specific policy.
    """

    ip: str
    matches: tuple[ProviderMatch, ...]
    providers: tuple[str, ...]
    threat_types: tuple[str, ...]
    categories: tuple[str, ...]
    semantic_tier: int
    botnet_family: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class IocSnapshot:
    """Immutable snapshot of active indicators.

    ``exact`` maps canonical integer keys to entries (O(1) exact lookup).
    ``networks_v4/v6`` hold network IOCs sorted by prefix length descending
    so the first containing network is the most specific one.
    """

    generation: int
    built_at: str
    exact: Mapping[int, IocEntry]
    networks_v4: tuple[tuple[Any, IocEntry], ...]
    networks_v6: tuple[tuple[Any, IocEntry], ...]
    indicator_count_exact: int
    indicator_count_network: int
    provider_count: int

    @staticmethod
    def empty() -> "IocSnapshot":
        return IocSnapshot(0, "", {}, (), (), 0, 0, 0)

    def lookup_key(self, key: int) -> Optional[IocEntry]:
        """Pure in-memory lookup by canonical integer key (lock-free).

        Used by the P3 shadow detector to pin one immutable snapshot per
        cycle: callers capture ``hotset.snapshot()`` once and resolve every
        destination against that same snapshot.
        """
        entry = self.exact.get(key)
        if entry is not None:
            return entry
        networks = self.networks_v4 if key <= 0xFFFFFFFF else self.networks_v6
        for network, net_entry in networks:
            if int(network.network_address) <= key <= int(network.broadcast_address):
                return net_entry
        return None


class _Counter:
    """Best-effort lock-free counter (metrics only, not exact accounting)."""

    __slots__ = ("value",)

    def __init__(self) -> None:
        self.value = 0

    def increment(self, amount: int = 1) -> None:
        self.value += amount

    def get(self) -> int:
        return self.value


class _RefreshFlight:
    """One in-progress refresh and the result shared with its followers."""

    __slots__ = ("done", "result")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.result = False


def _row_dict(row: Any) -> Mapping[str, Any]:
    if isinstance(row, Mapping):
        return row
    if isinstance(row, sqlite3.Row):
        return dict(row)
    return {
        "provider": row[0],
        "indicator_type": row[1],
        "ip": row[2],
        "network": row[3],
        "classification": row[4],
        "botnet_family": row[5],
        "tags_json": row[6],
    }


def _finalize_entry(ip_text: str, matches: list[ProviderMatch]) -> IocEntry:
    providers = tuple(sorted({item.provider for item in matches}))
    threat_types = tuple(sorted({item.classification for item in matches}))
    categories = tuple(sorted({item.category for item in matches}))
    best_tier = min(item.tier for item in matches)
    family = next((item.botnet_family for item in matches if item.botnet_family), "")
    tags = tuple(sorted({tag for item in matches for tag in item.tags}))
    return IocEntry(
        ip=ip_text,
        matches=tuple(matches),
        providers=providers,
        threat_types=threat_types,
        categories=categories,
        semantic_tier=best_tier,
        botnet_family=family,
        tags=tags,
    )


def build_snapshot(conn: sqlite3.Connection, generation: int) -> IocSnapshot:
    """Read ACTIVE indicators of ENABLED providers and normalize them into an
    immutable snapshot.

    Raises on database errors so the caller can keep the last known good
    snapshot. An empty result set (zero active indicators, successful read)
    is a VALID empty snapshot.
    """
    provider_rows = conn.execute(
        "SELECT provider FROM threat_intel_providers WHERE enabled = 1"
    ).fetchall()
    enabled_providers = sorted(
        {clean_text(_row_dict(row).get("provider")).upper() for row in provider_rows} - {""}
    )
    if not enabled_providers:
        return IocSnapshot(
            generation, utc_now_iso(), {}, (), (), 0, 0, 0,
        )

    placeholders = ",".join("?" for _ in enabled_providers)
    rows = conn.execute(
        f"""
        SELECT provider, indicator_type, ip, network, classification,
               botnet_family, tags_json
        FROM threat_intel_indicators
        WHERE active = 1 AND provider IN ({placeholders})
        """,
        tuple(enabled_providers),
    ).fetchall()

    exact_buckets: dict[int, list[ProviderMatch]] = {}
    network_buckets: dict[Any, list[ProviderMatch]] = {}
    for raw in rows:
        row = _row_dict(raw)
        provider = clean_text(row.get("provider")).upper()
        if not provider:
            continue
        classification = clean_text(row.get("classification")).lower()
        indicator_type = clean_text(row.get("indicator_type")).upper()
        tier = semantic_tier(classification)
        category = semantic_category(classification)
        botnet_family = clean_text(row.get("botnet_family"))
        raw_tags = safe_json(row.get("tags_json"), [])
        tags = tuple(clean_text(tag) for tag in raw_tags if clean_text(tag))
        match = ProviderMatch(
            provider=provider,
            indicator_type=indicator_type,
            classification=classification,
            category=category,
            tier=tier,
            botnet_family=botnet_family,
            tags=tags,
        )
        key = normalize_ip(row.get("ip"))
        if key is not None:
            exact_buckets.setdefault(key, []).append(match)
            continue
        network_text = clean_text(row.get("network"))
        if not network_text:
            continue  # malformed row without ip or network: skip safely
        try:
            network = ip_network(network_text, strict=False)
        except ValueError:
            continue  # malformed network: skip safely
        network_buckets.setdefault(network, []).append(match)

    exact: dict[int, IocEntry] = {}
    for key, matches in exact_buckets.items():
        exact[key] = _finalize_entry(str(ip_address(key)), matches)

    networks_v4 = sorted(
        ((network, _finalize_entry(str(network), matches)) for network, matches in network_buckets.items() if network.version == 4),
        key=lambda item: item[0].prefixlen,
        reverse=True,
    )
    networks_v6 = sorted(
        ((network, _finalize_entry(str(network), matches)) for network, matches in network_buckets.items() if network.version == 6),
        key=lambda item: item[0].prefixlen,
        reverse=True,
    )

    return IocSnapshot(
        generation=generation,
        built_at=utc_now_iso(),
        exact=exact,
        networks_v4=tuple(networks_v4),
        networks_v6=tuple(networks_v6),
        indicator_count_exact=len(exact),
        indicator_count_network=len(networks_v4) + len(networks_v6),
        provider_count=len(enabled_providers),
    )


def _age_seconds(built_at: str) -> Optional[float]:
    if not built_at:
        return None
    try:
        parsed = datetime.fromisoformat(built_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, time.time() - parsed.timestamp())
    except ValueError:
        return None


class ActiveIocHotSet:
    """Thread-safe active indicator hot set with lock-free reads.

    Usage::

        hotset = ActiveIocHotSet(connection_factory, refresh_seconds=60)
        hotset.refresh()                       # explicit rebuild + atomic swap
        entry = hotset.lookup("1.2.3.4")       # IocEntry | None
        hotset.start()                         # optional background refresher
        hotset.status()                        # observability dict
        hotset.stop()
    """

    def __init__(
        self,
        connection_factory: Optional[ConnectionFactory] = None,
        *,
        refresh_seconds: Optional[int] = None,
        enabled: Optional[bool] = None,
        stale_after_seconds: Optional[float] = None,
    ) -> None:
        self._connection_factory = connection_factory or sqlite_connection
        self._refresh_seconds = (
            refresh_seconds
            if refresh_seconds is not None
            else _env_int("GMJFLOW_TI_HOTSET_REFRESH_SECONDS", DEFAULT_REFRESH_SECONDS)
        )
        self._enabled = (
            enabled if enabled is not None else _env_bool("GMJFLOW_TI_HOTSET_ENABLED", DEFAULT_ENABLED)
        )
        self._stale_after = (
            stale_after_seconds
            if stale_after_seconds is not None
            else max(10.0, float(self._refresh_seconds) * 3.0)
        )

        self._current: IocSnapshot = IocSnapshot.empty()
        self._generation = 0

        self._state_lock = threading.Lock()  # guards refresh state only, never lookup
        self._refresh_flight: Optional[_RefreshFlight] = None
        self._refresh_coalesced_total = 0
        self._last_refresh_attempt = ""
        self._last_refresh_success = ""
        self._last_error = ""
        self._refresh_failures = _Counter()
        self._last_success_generation = 0
        self._snapshot_built_at = ""

        self._lookup_count = _Counter()
        self._lookup_hits = _Counter()
        self._lookup_misses = _Counter()
        self._lookup_latency_ns_sum = _Counter()
        self._lookup_latency_ns_max = 0

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def generation(self) -> int:
        return self._current.generation

    def snapshot(self) -> IocSnapshot:
        """Return the current immutable snapshot reference (no lock, no copy).

        Refresh continues to build and publish a NEW snapshot in parallel;
        callers holding a reference keep reading the same generation.
        """
        return self._current

    def lookup(self, ip: Any) -> Optional[IocEntry]:
        """Local O(1) lookup. Returns None on miss or malformed input.

        Never touches SQLite/ClickHouse/provider APIs; never acquires a lock.
        """
        start_ns = time.perf_counter_ns()
        try:
            self._lookup_count.increment()
            key = normalize_ip(ip)
            if key is None:
                self._lookup_misses.increment()
                return None
            entry = self._current.lookup_key(key)
            if entry is not None:
                self._lookup_hits.increment()
                return entry
            self._lookup_misses.increment()
            return None
        finally:
            latency_ns = time.perf_counter_ns() - start_ns
            self._lookup_latency_ns_sum.increment(latency_ns)
            self._lookup_latency_ns_max = max(self._lookup_latency_ns_max, latency_ns)

    def refresh(self) -> bool:
        """Rebuild from SQLite and atomically swap. Returns True on success.

        On failure the current snapshot (last known good) is kept untouched.
        """
        with self._state_lock:
            flight = self._refresh_flight
            if flight is None:
                flight = _RefreshFlight()
                self._refresh_flight = flight
                self._last_refresh_attempt = utc_now_iso()
                leader = True
            else:
                self._refresh_coalesced_total += 1
                leader = False

        if not leader:
            flight.done.wait()
            return flight.result

        result = False
        try:
            try:
                conn = self._connection_factory()
                try:
                    snapshot = build_snapshot(conn, self._current.generation + 1)
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
            except Exception as exc:
                LOGGER.warning("active ioc hot set refresh failed: %s", exc)
                with self._state_lock:
                    self._refresh_failures.increment()
                    self._last_error = f"{exc.__class__.__name__}: {clean_text(exc)}"[:500]
                return False
            self._current = snapshot  # atomic swap: immutable object reference
            with self._state_lock:
                self._last_refresh_success = utc_now_iso()
                self._last_error = ""
                self._last_success_generation = snapshot.generation
                self._snapshot_built_at = snapshot.built_at
            result = True
            return True
        finally:
            with self._state_lock:
                flight.result = result
                self._refresh_flight = None
                flight.done.set()

    def start(self) -> None:
        """Start the optional background refresher (no-op when disabled)."""
        if not self._enabled:
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self.refresh()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, name="gmj-flow-ioc-hotset", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)
        self._thread = None

    def _loop(self) -> None:
        while not self._stop_event.wait(self._refresh_seconds):
            self.refresh()

    def status(self) -> dict[str, Any]:
        with self._state_lock:
            last_attempt = self._last_refresh_attempt
            last_success = self._last_refresh_success
            last_error = self._last_error
            refresh_in_progress = self._refresh_flight is not None
            refresh_coalesced_total = self._refresh_coalesced_total
            failures = self._refresh_failures.get()
            last_success_generation = self._last_success_generation
            built_at = self._snapshot_built_at
        snapshot = self._current
        age = _age_seconds(built_at)
        total_lookups = self._lookup_count.get()
        latency_sum = self._lookup_latency_ns_sum.get()
        avg_latency_ns = (latency_sum // total_lookups) if total_lookups else 0
        stale = self._enabled and (age is None or age > self._stale_after)
        return {
            "enabled": self._enabled,
            "snapshot_generation": snapshot.generation,
            "indicator_count_exact": snapshot.indicator_count_exact,
            "indicator_count_network": snapshot.indicator_count_network,
            "provider_count": snapshot.provider_count,
            "last_refresh_attempt": last_attempt,
            "last_refresh_success": last_success,
            "snapshot_built_at": built_at,
            "snapshot_age_seconds": round(age, 3) if age is not None else None,
            "refresh_in_progress": refresh_in_progress,
            "refresh_coalesced_total": refresh_coalesced_total,
            "last_success_generation": last_success_generation,
            "refresh_failures": failures,
            "last_error": last_error,
            "lookup_count": total_lookups,
            "lookup_hits": self._lookup_hits.get(),
            "lookup_misses": self._lookup_misses.get(),
            "lookup_latency_ns_avg": int(avg_latency_ns),
            "lookup_latency_ns_max": int(self._lookup_latency_ns_max),
            "stale": bool(stale),
        }


__all__ = [
    "ActiveIocHotSet",
    "IocEntry",
    "IocSnapshot",
    "ProviderMatch",
    "build_snapshot",
    "normalize_ip",
]