"""P3 outbound IOC shadow aggregation (in-memory, detect-only).

The P2 detector produces per-cycle :class:`OutboundIocCandidate` objects for
outbound flows whose destination matched an active IOC.  P3 aggregates those
candidates across cycles into a bounded, expiring, in-memory shadow model of
"client <-> IOC" relationships.  It never persists anything, never touches
policy/severity/mitigation, and never creates a UI.

Design
------
- Sliding window: a relationship is ACTIVE while ``now - last_seen < window``.
  Expiration is evaluated at the end of every ingest cycle using an injectable
  clock (no scattered ``datetime.now()`` calls; tests control time).  A
  sliding window is preferred over a tumbling bucket because flow timestamps
  arrive continuously and the question "is this client still talking to this
  IOC within the last 5 minutes" has no natural bucket boundary; sliding is
  also deterministic and cheaper than a timing wheel for the expected
  cardinality (documented complexity: O(active) per cycle).
- Aggregate key: ``(internal_identity, external_ioc)``.  For direct CUSTOMER
  sources ``internal_identity`` is ``src_ip``.  For CGNAT_PUBLIC sources the
  subscriber is resolved ONLY after the IOC hit (P2 candidates are, by
  construction, already IOC hits) and only then.  On RESOLVED the identity is
  the subscriber id (fallback private IP, fallback public IP) because the
  subscriber id is the stable, persistable account identifier while the
  private IP is DHCP-assigned and may change between sessions.  On
  UNRESOLVED/AMBIGUOUS/ERROR the public CGNAT IP is kept with an explicit
  resolution status marker.
- CGNAT resolution uses the FLOW timestamp (never ``now()``).  A per-cycle
  prepared resolver opens ONE SQLite connection, ensures the CGNAT schema
  once, and reuses the canonical ``resolve_cgnat_subscriber`` for every lookup
  (no per-hit connection open, no per-hit schema ensure).  Results are memoized
  by ``(public_ip, src_port, protocol, flow_time_bucket)`` so a mapping change
  is never masked across a bucket boundary; ERROR results are never memoized.
- Provider/classification/category metadata is unioned across hits; a flow hit
  is counted once regardless of how many providers share the IOC.
- Bounded memory: per-relationship sets are capped; the relationship table is
  capped with deterministic oldest-first eviction implemented with a min-heap
  and bounded admission (a candidate that is not newer than the oldest active
  relationship is not materialised at all); a globally-seen IOC set is also
  capped for observability only.
"""

from __future__ import annotations

import heapq
import logging
import os
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Optional

from app.services.cgnat_mapping import ensure_cgnat_schema, resolve_cgnat_subscriber
from app.services.network_context import CGNAT_PUBLIC
from app.services.outbound_ioc_detector import OutboundIocCandidate
from app.services.threat_intelligence import clean_text, sqlite_connection

LOGGER = logging.getLogger("gmj-flow")

FEATURE_FLAG = "GMJFLOW_OUTBOUND_IOC_AGGREGATION_ENABLED"
WINDOW_ENV = "GMJFLOW_OUTBOUND_IOC_AGGREGATION_WINDOW_SECONDS"
MAX_RELATIONSHIPS_ENV = "GMJFLOW_OUTBOUND_IOC_AGGREGATION_MAX_RELATIONSHIPS"
SET_LIMIT_ENV = "GMJFLOW_OUTBOUND_IOC_AGGREGATION_SET_LIMIT"
CACHE_SIZE_ENV = "GMJFLOW_OUTBOUND_IOC_AGGREGATION_CGNAT_CACHE_SIZE"

DEFAULT_WINDOW_SECONDS = 300
DEFAULT_MAX_RELATIONSHIPS = 100_000
DEFAULT_SET_LIMIT = 50
DEFAULT_CACHE_SIZE = 10_000

RESOLVED = "RESOLVED"
AMBIGUOUS = "AMBIGUOUS"
UNRESOLVED = "UNRESOLVED"
ERROR = "ERROR"
NOT_APPLICABLE = "NOT_APPLICABLE"

IDENTITY_CUSTOMER_IP = "CUSTOMER_IP"
IDENTITY_CGNAT_SUBSCRIBER = "CGNAT_SUBSCRIBER"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _epoch(value: datetime) -> float:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


def _candidate_epoch(candidate: OutboundIocCandidate, fallback: float) -> float:
    try:
        parsed = datetime.fromisoformat(candidate.timestamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (ValueError, AttributeError):
        return fallback


_PROTOCOL_NAMES = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}


def _protocol_name(value: Any) -> str:
    """Map an IANA protocol number (or name) to a CGNAT resolver protocol name."""
    try:
        num = int(value)
    except (TypeError, ValueError):
        text = clean_text(value).lower()
        return text if text in {"tcp", "udp", "icmp", "icmpv6", "any"} else "any"
    return _PROTOCOL_NAMES.get(num, "any")


@dataclass(frozen=True)
class CgnatResolution:
    status: str
    public_ip: str = ""
    private_ip: str = ""
    subscriber_id: str = ""
    subscriber_name: str = ""
    confidence: float = 0.0
    source_type: str = ""
    pool_name: str = ""
    error: str = ""
    port_start: int = 0
    port_end: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class OutboundIocRelationship:
    internal_identity: str
    external_ioc: str
    identity_kind: str
    first_seen: str
    last_seen: str
    first_seen_epoch: float
    last_seen_epoch: float
    hit_count: int
    flows: int
    packets: int
    bytes: int
    protocols: set[int] = field(default_factory=set)
    src_ports: set[int] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    sensors: set[str] = field(default_factory=set)
    providers: set[str] = field(default_factory=set)
    indicator_types: set[str] = field(default_factory=set)
    classifications: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)
    botnet_families: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    signal_class: str = "LOWER_SIGNAL"
    semantic_tier: int = 99
    cgnat: CgnatResolution = field(
        default_factory=lambda: CgnatResolution(status=NOT_APPLICABLE)
    )
    set_truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "internal_identity": self.internal_identity,
            "external_ioc": self.external_ioc,
            "identity_kind": self.identity_kind,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hit_count": self.hit_count,
            "flows": self.flows,
            "packets": self.packets,
            "bytes": self.bytes,
            "protocols": sorted(self.protocols),
            "src_ports": sorted(self.src_ports),
            "dst_ports": sorted(self.dst_ports),
            "sensors": sorted(self.sensors),
            "providers": sorted(self.providers),
            "indicator_types": sorted(self.indicator_types),
            "classifications": sorted(self.classifications),
            "categories": sorted(self.categories),
            "botnet_families": sorted(self.botnet_families),
            "tags": sorted(self.tags),
            "signal_class": self.signal_class,
            "semantic_tier": self.semantic_tier,
            "cgnat": self.cgnat.as_dict(),
            "set_truncated": self.set_truncated,
        }


@dataclass(frozen=True)
class OutboundIocClientSummary:
    internal_identity: str
    unique_ioc_count: int
    total_hits: int
    total_flows: int
    total_packets: int
    total_bytes: int
    relationship_count: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OutboundIocAggregationCycle:
    relationships: tuple[OutboundIocRelationship, ...]
    client_summaries: tuple[OutboundIocClientSummary, ...]
    metrics: Mapping[str, Any]

    def summary(self) -> dict[str, Any]:
        return dict(self.metrics)


class _PreparedCgnatResolver:
    """One SQLite connection reused for a whole ingest cycle.

    Schema is ensured once per cycle (not per resolution); the canonical
    ``resolve_cgnat_subscriber`` performs every lookup with ``ensure_schema``
    disabled so the prepared path is semantically identical to the original.
    """

    __slots__ = ("_conn", "_closed")

    def __init__(self, connection_factory: Callable[..., sqlite3.Connection]) -> None:
        self._conn = connection_factory()
        self._conn.row_factory = sqlite3.Row
        ensure_cgnat_schema(self._conn)
        self._closed = False

    def resolve(
        self, public_ip: Any, src_port: Any, protocol: Any, timestamp: Any
    ) -> dict[str, Any]:
        return resolve_cgnat_subscriber(
            self._conn, public_ip, src_port, protocol, timestamp, ensure_schema=False
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._conn.close()
        except Exception:
            pass


class _CgnatCache:
    """Bounded TTL memo for CGNAT resolutions keyed by flow-time bucket."""

    __slots__ = ("_entries", "_max_size", "_ttl", "hits", "misses", "evictions")

    def __init__(self, max_size: int, ttl_seconds: float) -> None:
        self._entries: dict[tuple[Any, ...], tuple[float, CgnatResolution]] = {}
        self._max_size = max_size
        self._ttl = ttl_seconds
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, key: tuple[Any, ...], now_epoch: float) -> Optional[CgnatResolution]:
        item = self._entries.get(key)
        if item is None:
            self.misses += 1
            return None
        inserted, value = item
        if now_epoch - inserted > self._ttl:
            del self._entries[key]
            self.misses += 1
            return None
        self.hits += 1
        return value

    def put(self, key: tuple[Any, ...], value: CgnatResolution, now_epoch: float) -> None:
        if key in self._entries:
            self._entries[key] = (now_epoch, value)
            return
        if len(self._entries) >= self._max_size:
            self._evict(now_epoch)
        self._entries[key] = (now_epoch, value)

    def _evict(self, now_epoch: float) -> None:
        expired = [
            key
            for key, (inserted, _) in self._entries.items()
            if now_epoch - inserted > self._ttl
        ]
        for key in expired:
            del self._entries[key]
            self.evictions += 1
        if len(self._entries) >= self._max_size:
            self.evictions += len(self._entries)
            self._entries.clear()


class OutboundIocAggregator:
    """Sliding-window, in-memory aggregator of outbound IOC shadow candidates."""

    def __init__(
        self,
        connection_factory: Callable[..., Any] = sqlite_connection,
        *,
        enabled: Optional[bool] = None,
        window_seconds: Optional[int] = None,
        clock: Optional[Callable[[], datetime]] = None,
        max_relationships: Optional[int] = None,
        set_limit: Optional[int] = None,
        cgnat_cache_size: Optional[int] = None,
        cgnat_resolver: Optional[Callable[..., Mapping[str, Any]]] = None,
    ) -> None:
        self.connection_factory = connection_factory
        self._enabled_override = enabled
        self._window_seconds = (
            window_seconds
            if window_seconds is not None
            else _env_int(WINDOW_ENV, DEFAULT_WINDOW_SECONDS, 60)
        )
        self._clock = clock or _utc_now
        self._max_relationships = (
            max_relationships
            if max_relationships is not None
            else _env_int(MAX_RELATIONSHIPS_ENV, DEFAULT_MAX_RELATIONSHIPS, 1_000)
        )
        self._set_limit = (
            set_limit
            if set_limit is not None
            else _env_int(SET_LIMIT_ENV, DEFAULT_SET_LIMIT, 1)
        )
        cache_size = (
            cgnat_cache_size
            if cgnat_cache_size is not None
            else _env_int(CACHE_SIZE_ENV, DEFAULT_CACHE_SIZE, 1_000)
        )
        self._cgnat_resolver = cgnat_resolver
        self._cache = _CgnatCache(cache_size, float(self._window_seconds))
        self._relationships: dict[tuple[str, str], OutboundIocRelationship] = {}
        self._heap: list[tuple[float, tuple[str, str]]] = []
        self._seen_iocs: set[str] = set()
        self._seen_iocs_truncated = False
        self._lock = threading.Lock()
        self._totals: dict[str, Any] = {
            "cycles": 0,
            "hits_ingested": 0,
            "new_relationships": 0,
            "expired_relationships": 0,
            "relationships_evicted": 0,
            "admission_skipped": 0,
            "cgnat_resolution_attempts": 0,
            "cgnat_resolution_resolved": 0,
            "cgnat_resolution_ambiguous": 0,
            "cgnat_resolution_unresolved": 0,
            "cgnat_resolution_errors": 0,
            "cgnat_cache_hits": 0,
            "cgnat_cache_misses": 0,
            "cgnat_db_connections": 0,
            "cgnat_schema_prepares": 0,
            "cgnat_queries": 0,
            "set_truncations": 0,
            "cycle_errors": 0,
            "last_error": "",
            "aggregation_cycle_ms": 0.0,
            "expiration_ms": 0.0,
            "cap_enforcement_ms": 0.0,
        }

    @property
    def enabled(self) -> bool:
        if self._enabled_override is not None:
            return bool(self._enabled_override)
        return _env_bool(FEATURE_FLAG, False)

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def _empty_metrics(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "window_seconds": self._window_seconds,
            "candidates_ingested": 0,
            "hits_ingested": 0,
            "new_relationships": 0,
            "expired_relationships": 0,
            "relationships_evicted": 0,
            "admission_skipped": 0,
            "active_relationships": 0,
            "active_clients": 0,
            "unique_ioc_current": 0,
            "cgnat_resolution_attempts": 0,
            "cgnat_resolution_resolved": 0,
            "cgnat_resolution_ambiguous": 0,
            "cgnat_resolution_unresolved": 0,
            "cgnat_resolution_errors": 0,
            "cgnat_cache_hits": 0,
            "cgnat_cache_misses": 0,
            "cgnat_db_connections": 0,
            "cgnat_schema_prepares": 0,
            "cgnat_queries": 0,
            "set_truncations": 0,
            "aggregation_cycle_ms": 0.0,
            "expiration_ms": 0.0,
            "cap_enforcement_ms": 0.0,
        }

    def _prepare_cgnat_resolver(self) -> _PreparedCgnatResolver:
        return _PreparedCgnatResolver(self.connection_factory)

    def _resolve_cgnat(
        self,
        candidate: OutboundIocCandidate,
        now_epoch: float,
        resolver: Optional[_PreparedCgnatResolver],
    ) -> CgnatResolution:
        public_ip = candidate.src_ip
        src_port = int(candidate.src_port or 0)
        protocol_text = _protocol_name(candidate.protocol)
        timestamp = candidate.timestamp
        flow_epoch = _candidate_epoch(candidate, now_epoch)
        bucket = int(flow_epoch // self._window_seconds)
        key = (public_ip, src_port, protocol_text, bucket)
        cached = self._cache.get(key, now_epoch)
        if cached is not None:
            return cached

        resolution: CgnatResolution
        try:
            if self._cgnat_resolver is not None:
                result = self._cgnat_resolver(
                    public_ip, src_port, protocol_text, timestamp
                )
            elif resolver is not None:
                result = resolver.resolve(
                    public_ip, src_port, protocol_text, timestamp
                )
            else:
                raise RuntimeError("cgnat_resolver_unavailable")
        except Exception as exc:
            resolution = CgnatResolution(
                status=ERROR,
                public_ip=public_ip,
                error=f"{exc.__class__.__name__}: {clean_text(exc)}"[:200],
            )
        else:
            if result.get("ambiguous"):
                resolution = CgnatResolution(status=AMBIGUOUS, public_ip=public_ip)
            elif result.get("matched"):
                resolution = CgnatResolution(
                    status=RESOLVED,
                    public_ip=public_ip,
                    private_ip=clean_text(result.get("private_ip")),
                    subscriber_id=clean_text(result.get("subscriber_id")),
                    subscriber_name=clean_text(result.get("subscriber_name")),
                    confidence=float(result.get("confidence") or 0),
                    source_type=clean_text(result.get("source_type")),
                    pool_name=clean_text(result.get("pool_name")),
                    port_start=int(result.get("port_start") or 0),
                    port_end=int(result.get("port_end") or 0),
                )
            else:
                resolution = CgnatResolution(
                    status=UNRESOLVED,
                    public_ip=public_ip,
                    error=clean_text(result.get("error")),
                )
        # Never memoize ERROR: a transient SQLite failure must be retried.
        if resolution.status != ERROR:
            self._cache.put(key, resolution, now_epoch)
        return resolution

    @staticmethod
    def _identity(
        candidate: OutboundIocCandidate, resolution: CgnatResolution
    ) -> tuple[str, str]:
        if candidate.src_role == CGNAT_PUBLIC:
            if resolution.status == RESOLVED:
                identity = (
                    resolution.subscriber_id
                    or resolution.private_ip
                    or candidate.src_ip
                )
                return identity, IDENTITY_CGNAT_SUBSCRIBER
            return candidate.src_ip, f"CGNAT_PUBLIC_{resolution.status}"
        return candidate.src_ip, IDENTITY_CUSTOMER_IP

    @staticmethod
    def _bounded_add(values: set, value: Any, limit: int) -> bool:
        if value in values:
            return False
        if len(values) >= limit:
            return True
        values.add(value)
        return False

    def _merge_sets(
        self, relationship: OutboundIocRelationship, candidate: OutboundIocCandidate
    ) -> bool:
        limit = self._set_limit
        truncated = relationship.set_truncated

        def add(values: set, value: Any) -> None:
            nonlocal truncated
            if value and self._bounded_add(values, value, limit):
                truncated = True

        add(relationship.protocols, int(candidate.protocol or 0))
        add(relationship.src_ports, int(candidate.src_port or 0))
        add(relationship.dst_ports, int(candidate.dst_port or 0))
        add(relationship.sensors, clean_text(candidate.sensor))
        for item in candidate.providers:
            add(relationship.providers, item)
        for item in candidate.indicator_types:
            add(relationship.indicator_types, item)
        for item in candidate.classifications:
            add(relationship.classifications, item)
        for item in candidate.categories:
            add(relationship.categories, item)
        add(relationship.botnet_families, clean_text(candidate.botnet_family))
        for item in candidate.tags:
            add(relationship.tags, item)
        relationship.set_truncated = truncated
        return truncated

    def _merge(
        self,
        relationship: Optional[OutboundIocRelationship],
        candidate: OutboundIocCandidate,
        resolution: CgnatResolution,
        kind: str,
        identity: str,
        now_epoch: float,
    ) -> OutboundIocRelationship:
        ts = _candidate_epoch(candidate, now_epoch)
        if relationship is None:
            return OutboundIocRelationship(
                internal_identity=identity,
                external_ioc=candidate.dst_ip,
                identity_kind=kind,
                first_seen=candidate.timestamp,
                last_seen=candidate.timestamp,
                first_seen_epoch=ts,
                last_seen_epoch=ts,
                hit_count=1,
                flows=max(1, int(candidate.flow_count or 1)),
                packets=int(candidate.packets or 0),
                bytes=int(candidate.bytes or 0),
                protocols={int(candidate.protocol or 0)},
                src_ports={int(candidate.src_port or 0)}
                if int(candidate.src_port or 0)
                else set(),
                dst_ports={int(candidate.dst_port or 0)}
                if int(candidate.dst_port or 0)
                else set(),
                sensors={clean_text(candidate.sensor)}
                if clean_text(candidate.sensor)
                else set(),
                providers=set(candidate.providers),
                indicator_types=set(candidate.indicator_types),
                classifications=set(candidate.classifications),
                categories=set(candidate.categories),
                botnet_families={clean_text(candidate.botnet_family)}
                if clean_text(candidate.botnet_family)
                else set(),
                tags=set(candidate.tags),
                signal_class=candidate.signal_class,
                semantic_tier=int(candidate.semantic_tier or 99),
                cgnat=resolution,
                set_truncated=False,
            )

        relationship.hit_count += 1
        relationship.flows += max(1, int(candidate.flow_count or 1))
        relationship.packets += int(candidate.packets or 0)
        relationship.bytes += int(candidate.bytes or 0)
        if ts < relationship.first_seen_epoch:
            relationship.first_seen_epoch = ts
            relationship.first_seen = candidate.timestamp
        if ts > relationship.last_seen_epoch:
            relationship.last_seen_epoch = ts
            relationship.last_seen = candidate.timestamp
        self._merge_sets(relationship, candidate)
        if candidate.signal_class == "HIGH_VALUE":
            relationship.signal_class = "HIGH_VALUE"
        relationship.semantic_tier = min(
            relationship.semantic_tier, int(candidate.semantic_tier or 99)
        )
        if relationship.cgnat.status != RESOLVED and resolution.status == RESOLVED:
            relationship.cgnat = resolution
        elif (
            relationship.cgnat.status == RESOLVED
            and resolution.status == RESOLVED
            and resolution.confidence > relationship.cgnat.confidence
        ):
            relationship.cgnat = resolution
        return relationship

    def _rebuild_heap(self) -> None:
        self._heap = [
            (rel.last_seen_epoch, key)
            for key, rel in self._relationships.items()
        ]
        heapq.heapify(self._heap)

    def _heap_peek_valid(self) -> Optional[tuple[float, tuple[str, str]]]:
        while self._heap:
            epoch, key = self._heap[0]
            rel = self._relationships.get(key)
            if rel is not None and rel.last_seen_epoch == epoch:
                return epoch, key
            heapq.heappop(self._heap)
        return None

    def _evict_one(self) -> bool:
        top = self._heap_peek_valid()
        if top is None:
            return False
        _, key = top
        heapq.heappop(self._heap)
        del self._relationships[key]
        return True

    def _summaries(self) -> tuple[OutboundIocClientSummary, ...]:
        by_identity: dict[str, dict[str, Any]] = {}
        for rel in self._relationships.values():
            item = by_identity.setdefault(
                rel.internal_identity,
                {
                    "iocs": set(),
                    "hits": 0,
                    "flows": 0,
                    "packets": 0,
                    "bytes": 0,
                    "count": 0,
                },
            )
            item["iocs"].add(rel.external_ioc)
            item["hits"] += rel.hit_count
            item["flows"] += rel.flows
            item["packets"] += rel.packets
            item["bytes"] += rel.bytes
            item["count"] += 1
        return tuple(
            OutboundIocClientSummary(
                internal_identity=identity,
                unique_ioc_count=len(item["iocs"]),
                total_hits=item["hits"],
                total_flows=item["flows"],
                total_packets=item["packets"],
                total_bytes=item["bytes"],
                relationship_count=item["count"],
            )
            for identity, item in by_identity.items()
        )

    def ingest(
        self,
        candidates: Iterable[OutboundIocCandidate],
        now: Optional[datetime] = None,
    ) -> OutboundIocAggregationCycle:
        """Merge one cycle of P2 candidates into the sliding window."""
        if not self.enabled:
            return OutboundIocAggregationCycle((), (), {"enabled": False})

        started = time.perf_counter()
        now_dt = now or self._clock()
        now_epoch = _epoch(now_dt)
        metrics = self._empty_metrics()

        candidate_list = list(candidates)
        metrics["candidates_ingested"] = len(candidate_list)
        metrics["hits_ingested"] = len(candidate_list)

        new_relationships = 0
        cgnat_resolved = 0
        cgnat_ambiguous = 0
        cgnat_unresolved = 0
        cgnat_errors = 0
        set_truncations = 0
        evicted = 0
        admission_skipped = 0
        cgnat_queries = 0
        cache_hits_before = self._cache.hits
        cache_misses_before = self._cache.misses

        # Prepare one CGNAT resolver only if the cycle actually needs one.
        needs_cgnat = self._cgnat_resolver is None and any(
            getattr(candidate, "src_role", None) == CGNAT_PUBLIC
            for candidate in candidate_list
        )
        resolver: Optional[_PreparedCgnatResolver] = None
        if needs_cgnat:
            metrics["cgnat_db_connections"] += 1
            metrics["cgnat_schema_prepares"] += 1
            try:
                resolver = self._prepare_cgnat_resolver()
            except Exception:
                LOGGER.exception("outbound_ioc_cgnat_resolver_prepare_failed")
                resolver = None

        try:
            with self._lock:
                self._rebuild_heap()
                for candidate in candidate_list:
                    resolution = CgnatResolution(status=NOT_APPLICABLE)
                    if candidate.src_role == CGNAT_PUBLIC:
                        metrics["cgnat_resolution_attempts"] += 1
                        resolution = self._resolve_cgnat(
                            candidate, now_epoch, resolver
                        )
                        cgnat_queries += 1
                        if resolution.status == RESOLVED:
                            cgnat_resolved += 1
                        elif resolution.status == AMBIGUOUS:
                            cgnat_ambiguous += 1
                        elif resolution.status == ERROR:
                            cgnat_errors += 1
                        else:
                            cgnat_unresolved += 1
                    identity, kind = self._identity(candidate, resolution)
                    key = (identity, candidate.dst_ip)
                    relationship = self._relationships.get(key)
                    if relationship is None:
                        # Bounded admission: do not materialise a relationship
                        # that would be evicted immediately (oldest-first).
                        ts = _candidate_epoch(candidate, now_epoch)
                        if len(self._relationships) >= self._max_relationships:
                            top = self._heap_peek_valid()
                            if top is not None and ts <= top[0]:
                                admission_skipped += 1
                                continue
                            self._evict_one()
                            evicted += 1
                        self._relationships[key] = self._merge(
                            None, candidate, resolution, kind, identity, now_epoch
                        )
                        heapq.heappush(
                            self._heap,
                            (self._relationships[key].last_seen_epoch, key),
                        )
                        new_relationships += 1
                    else:
                        was_truncated = bool(relationship.set_truncated)
                        self._relationships[key] = self._merge(
                            relationship, candidate, resolution, kind, identity, now_epoch
                        )
                        heapq.heappush(
                            self._heap,
                            (self._relationships[key].last_seen_epoch, key),
                        )
                        if (
                            self._relationships[key].set_truncated
                            and not was_truncated
                        ):
                            set_truncations += 1

                cap_started = time.perf_counter()
                # Safety net: len must never exceed the cap (bounded admission
                # keeps it at or below, but guard against drift).
                overflow = len(self._relationships) - self._max_relationships
                if overflow > 0:
                    for _ in range(overflow):
                        if not self._evict_one():
                            break
                        evicted += 1
                metrics["cap_enforcement_ms"] = round(
                    (time.perf_counter() - cap_started) * 1000.0, 3
                )

                exp_started = time.perf_counter()
                threshold = now_epoch - self._window_seconds
                expired = [
                    key
                    for key, rel in self._relationships.items()
                    if rel.last_seen_epoch < threshold
                ]
                for key in expired:
                    del self._relationships[key]
                metrics["expiration_ms"] = round(
                    (time.perf_counter() - exp_started) * 1000.0, 3
                )
                metrics["expired_relationships"] = len(expired)

                summaries = self._summaries()
                cycle_ms = round((time.perf_counter() - started) * 1000.0, 3)
                metrics["aggregation_cycle_ms"] = cycle_ms
                metrics["new_relationships"] = new_relationships
                metrics["active_relationships"] = len(self._relationships)
                metrics["active_clients"] = len(summaries)
                metrics["unique_ioc_current"] = len(
                    {rel.external_ioc for rel in self._relationships.values()}
                )
                metrics["relationships_evicted"] = evicted
                metrics["admission_skipped"] = admission_skipped
                metrics["cgnat_resolution_resolved"] = cgnat_resolved
                metrics["cgnat_resolution_ambiguous"] = cgnat_ambiguous
                metrics["cgnat_resolution_unresolved"] = cgnat_unresolved
                metrics["cgnat_resolution_errors"] = cgnat_errors
                metrics["cgnat_cache_hits"] = self._cache.hits - cache_hits_before
                metrics["cgnat_cache_misses"] = self._cache.misses - cache_misses_before
                metrics["cgnat_queries"] = cgnat_queries
                metrics["set_truncations"] = set_truncations

                self._totals["cycles"] += 1
                self._totals["hits_ingested"] += len(candidate_list)
                self._totals["new_relationships"] += new_relationships
                self._totals["expired_relationships"] += len(expired)
                self._totals["relationships_evicted"] += evicted
                self._totals["admission_skipped"] += admission_skipped
                self._totals["cgnat_resolution_attempts"] += metrics[
                    "cgnat_resolution_attempts"
                ]
                self._totals["cgnat_resolution_resolved"] += cgnat_resolved
                self._totals["cgnat_resolution_ambiguous"] += cgnat_ambiguous
                self._totals["cgnat_resolution_unresolved"] += cgnat_unresolved
                self._totals["cgnat_resolution_errors"] += cgnat_errors
                self._totals["cgnat_cache_hits"] = self._cache.hits
                self._totals["cgnat_cache_misses"] = self._cache.misses
                self._totals["cgnat_db_connections"] += metrics["cgnat_db_connections"]
                self._totals["cgnat_schema_prepares"] += metrics["cgnat_schema_prepares"]
                self._totals["cgnat_queries"] += cgnat_queries
                self._totals["set_truncations"] += set_truncations
                self._totals["aggregation_cycle_ms"] = cycle_ms
                self._totals["expiration_ms"] = metrics["expiration_ms"]
                self._totals["cap_enforcement_ms"] = metrics["cap_enforcement_ms"]

                for rel in self._relationships.values():
                    if len(self._seen_iocs) >= self._max_relationships * 2:
                        self._seen_iocs_truncated = True
                        break
                    self._seen_iocs.add(rel.external_ioc)

                # Rebuild the heap for the next cycle so stale entries do not
                # accumulate across cycles.
                self._rebuild_heap()

                relationships = tuple(self._relationships.values())
        finally:
            if resolver is not None:
                resolver.close()

        return OutboundIocAggregationCycle(relationships, summaries, metrics)

    def status(self) -> dict[str, Any]:
        with self._lock:
            active_relationships = len(self._relationships)
            active_clients = len(
                {rel.internal_identity for rel in self._relationships.values()}
            )
            unique_ioc_current = len(
                {rel.external_ioc for rel in self._relationships.values()}
            )
            totals = dict(self._totals)
        totals["enabled"] = self.enabled
        totals["window_seconds"] = self._window_seconds
        totals["active_relationships"] = active_relationships
        totals["active_clients"] = active_clients
        totals["unique_ioc_current"] = unique_ioc_current
        totals["unique_ioc_total"] = len(self._seen_iocs)
        totals["unique_ioc_total_truncated"] = self._seen_iocs_truncated
        return totals


__all__ = [
    "FEATURE_FLAG",
    "OutboundIocAggregator",
    "OutboundIocRelationship",
    "OutboundIocClientSummary",
    "OutboundIocAggregationCycle",
    "CgnatResolution",
    "RESOLVED",
    "AMBIGUOUS",
    "UNRESOLVED",
    "ERROR",
    "NOT_APPLICABLE",
]
