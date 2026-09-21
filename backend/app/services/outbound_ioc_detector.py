"""Detect-only outbound destination IOC shadow detector (P2).

The detector is a side channel: it does not change AttackVector, policy,
security events, or mitigation.  Network roles come from NetworkContextEngine
and IOC evidence comes only from ActiveIocHotSet.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from ipaddress import IPv6Address, ip_address
from typing import Any, Callable, Iterable, Mapping

from app.services.active_ioc_hotset import ActiveIocHotSet, IocEntry, normalize_ip
from app.services.network_context import (
    CGNAT_PUBLIC,
    CUSTOMER,
    EXTERNAL,
    NetworkContext,
    NetworkContextEngine,
)
from app.services.threat_intelligence import clean_text, sqlite_connection

LOGGER = logging.getLogger("gmj-flow")

FEATURE_FLAG = "GMJFLOW_OUTBOUND_IOC_SHADOW_ENABLED"
ELIGIBLE_SOURCE_ROLES = frozenset({CUSTOMER, CGNAT_PUBLIC})
HIGH_VALUE_CATEGORIES = frozenset(
    {"c2", "botnet", "ddos", "malware", "compromised", "reputation_malicious"}
)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _canonical_ip(value: Any) -> str:
    try:
        parsed = ip_address(clean_text(value))
    except ValueError:
        return ""
    if isinstance(parsed, IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return str(parsed)


def _timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        parsed = value
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return clean_text(value)


@dataclass(frozen=True)
class OutboundIocCandidate:
    timestamp: str
    sensor: str
    direction: str
    src_ip: str
    dst_ip: str
    src_role: str
    dst_role: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    bytes: int
    flow_count: int
    ioc_matched: bool
    ioc_ip: str
    semantic_tier: int
    signal_class: str
    providers: tuple[str, ...]
    indicator_types: tuple[str, ...]
    classifications: tuple[str, ...]
    categories: tuple[str, ...]
    botnet_family: str
    tags: tuple[str, ...]
    network_context: Mapping[str, Any]
    subscriber_resolution_available: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OutboundIocCycleResult:
    enabled: bool
    candidates: tuple[OutboundIocCandidate, ...]
    metrics: Mapping[str, Any]

    def summary(self) -> dict[str, Any]:
        return {"enabled": self.enabled, **dict(self.metrics)}


class OutboundIocShadowDetector:
    """Per-cycle destination IOC detector with unique-destination lookup dedup."""

    def __init__(
        self,
        connection_factory: Callable[..., Any] = sqlite_connection,
        *,
        hotset: Any = None,
        network_context: Any = None,
        enabled: bool | None = None,
    ) -> None:
        self._enabled_override = enabled
        self.hotset = hotset or ActiveIocHotSet(connection_factory, enabled=True)
        self.network_context = network_context or NetworkContextEngine(connection_factory)
        self._status_lock = threading.Lock()
        self._totals: dict[str, Any] = {
            "cycles": 0,
            "observations_seen": 0,
            "outbound_eligible": 0,
            "unique_destinations_checked": 0,
            "hotset_hits": 0,
            "hotset_misses": 0,
            "candidates_total": 0,
            "c2_candidates": 0,
            "botnet_candidates": 0,
            "malware_candidates": 0,
            "reputation_malicious_candidates": 0,
            "lower_signal_candidates": 0,
            "candidate_errors": 0,
            "cycle_duration_ms": 0.0,
            "lookup_duration_ms": 0.0,
            "truncated": False,
            "destinations_skipped": 0,
        }

    @property
    def enabled(self) -> bool:
        if self._enabled_override is not None:
            return bool(self._enabled_override)
        return _env_bool(FEATURE_FLAG, False)

    def start(self) -> None:
        if not self.enabled:
            return
        try:
            self.hotset.start()
        except Exception:
            LOGGER.exception("outbound_ioc_hotset_start_failed")

    def stop(self) -> None:
        try:
            self.hotset.stop()
        except Exception:
            LOGGER.exception("outbound_ioc_hotset_stop_failed")

    def status(self) -> dict[str, Any]:
        with self._status_lock:
            return {"enabled": self.enabled, **self._totals}

    @staticmethod
    def _context_for(resolver: Callable[..., NetworkContext], observation: Any) -> NetworkContext:
        return resolver(
            observation.src_ip,
            observation.dst_ip,
            observation.input_if,
            observation.output_if,
            sensor=observation.sensor,
            exporter=observation.exporter_ip,
        )

    @staticmethod
    def _entry_semantics(entry: IocEntry) -> dict[str, Any]:
        indicator_types = tuple(sorted({item.indicator_type for item in entry.matches}))
        categories = tuple(sorted(set(entry.categories)))
        high_value = bool(set(categories) & HIGH_VALUE_CATEGORIES)
        return {
            "providers": tuple(entry.providers),
            "indicator_types": indicator_types,
            "classifications": tuple(entry.threat_types),
            "categories": categories,
            "semantic_tier": int(entry.semantic_tier),
            "signal_class": "HIGH_VALUE" if high_value else "LOWER_SIGNAL",
            "botnet_family": entry.botnet_family,
            "tags": tuple(entry.tags),
        }

    @staticmethod
    def _candidate_key(
        observation: Any,
        context: NetworkContext,
        src_ip: str,
        dst_ip: str,
        ts: str,
    ) -> tuple[Any, ...]:
        return (
            ts,
            clean_text(observation.sensor),
            src_ip,
            dst_ip,
            int(observation.src_port or 0),
            int(observation.dst_port or 0),
            int(observation.protocol or 0),
            context.src_role,
            context.dst_role,
        )

    def _finish_cycle(
        self,
        started: float,
        metrics: dict[str, Any],
        candidates: Iterable[OutboundIocCandidate] = (),
    ) -> OutboundIocCycleResult:
        candidate_tuple = tuple(candidates)
        metrics["cycle_duration_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
        metrics["candidates_total"] = len(candidate_tuple)
        for candidate in candidate_tuple:
            categories = set(candidate.categories)
            indicator_types = set(candidate.indicator_types)
            if "c2" in categories or "C2" in indicator_types:
                metrics["c2_candidates"] += 1
            if categories & {"botnet", "ddos"}:
                metrics["botnet_candidates"] += 1
            if categories & {"malware", "compromised"}:
                metrics["malware_candidates"] += 1
            if "reputation_malicious" in categories:
                metrics["reputation_malicious_candidates"] += 1
            if candidate.signal_class == "LOWER_SIGNAL":
                metrics["lower_signal_candidates"] += 1

        cumulative_keys = (
            "cycles",
            "observations_seen",
            "outbound_eligible",
            "unique_destinations_checked",
            "hotset_hits",
            "hotset_misses",
            "candidates_total",
            "c2_candidates",
            "botnet_candidates",
            "malware_candidates",
            "reputation_malicious_candidates",
            "lower_signal_candidates",
            "candidate_errors",
            "destinations_skipped",
        )
        metrics["cycles"] = 1
        with self._status_lock:
            for key in cumulative_keys:
                self._totals[key] += metrics[key]
            self._totals["cycle_duration_ms"] = metrics["cycle_duration_ms"]
            self._totals["lookup_duration_ms"] = metrics["lookup_duration_ms"]
            self._totals["truncated"] = bool(metrics["truncated"])

        if candidate_tuple or metrics["candidate_errors"]:
            LOGGER.info(
                "OUTBOUND_IOC_SHADOW observations=%s eligible=%s unique_dst=%s "
                "hits=%s candidates=%s c2=%s botnet=%s malware=%s lower=%s errors=%s",
                metrics["observations_seen"],
                metrics["outbound_eligible"],
                metrics["unique_destinations_checked"],
                metrics["hotset_hits"],
                metrics["candidates_total"],
                metrics["c2_candidates"],
                metrics["botnet_candidates"],
                metrics["malware_candidates"],
                metrics["lower_signal_candidates"],
                metrics["candidate_errors"],
            )
        return OutboundIocCycleResult(True, candidate_tuple, metrics)

    def detect(self, observations: Iterable[Any]) -> OutboundIocCycleResult:
        """Return shadow candidates without persistence or policy side effects."""
        if not self.enabled:
            return OutboundIocCycleResult(False, (), {
                "cycles": 0,
                "observations_seen": 0,
                "outbound_eligible": 0,
                "unique_destinations_checked": 0,
                "hotset_hits": 0,
                "hotset_misses": 0,
                "candidates_total": 0,
                "c2_candidates": 0,
                "botnet_candidates": 0,
                "malware_candidates": 0,
                "reputation_malicious_candidates": 0,
                "lower_signal_candidates": 0,
                "candidate_errors": 0,
                "cycle_duration_ms": 0.0,
                "lookup_duration_ms": 0.0,
                "truncated": False,
                "destinations_skipped": 0,
            })

        started = time.perf_counter()
        metrics: dict[str, Any] = {
            "cycles": 0,
            "observations_seen": 0,
            "outbound_eligible": 0,
            "unique_destinations_checked": 0,
            "hotset_hits": 0,
            "hotset_misses": 0,
            "candidates_total": 0,
            "c2_candidates": 0,
            "botnet_candidates": 0,
            "malware_candidates": 0,
            "reputation_malicious_candidates": 0,
            "lower_signal_candidates": 0,
            "candidate_errors": 0,
            "cycle_duration_ms": 0.0,
            "lookup_duration_ms": 0.0,
            "truncated": False,
            "destinations_skipped": 0,
        }
        try:
            resolver = self.network_context.prepare_resolver()
        except Exception:
            metrics["candidate_errors"] += 1
            LOGGER.exception("outbound_ioc_network_context_prepare_failed")
            return self._finish_cycle(started, metrics)

        by_destination: dict[str, list[tuple[Any, NetworkContext]]] = {}
        for observation in observations:
            metrics["observations_seen"] += 1
            src_ip = _canonical_ip(getattr(observation, "src_ip", ""))
            dst_ip = _canonical_ip(getattr(observation, "dst_ip", ""))
            if not src_ip or not dst_ip:
                metrics["candidate_errors"] += 1
                continue
            try:
                context = self._context_for(resolver, observation)
            except Exception:
                metrics["candidate_errors"] += 1
                continue
            if (
                context.traffic_direction != "OUTBOUND"
                or context.src_role not in ELIGIBLE_SOURCE_ROLES
                or context.dst_role != EXTERNAL
            ):
                continue
            metrics["outbound_eligible"] += 1
            by_destination.setdefault(dst_ip, []).append(
                (observation, context, src_ip, _timestamp(observation.observed_at))
            )

        matches: dict[str, IocEntry] = {}
        hotset = self.hotset
        # Pin one immutable snapshot for the whole cycle so a refresh that
        # publishes a new generation mid-cycle cannot produce a mixed A/B
        # view (P2.1 review observation). Fallback keeps per-destination
        # lookup for test doubles without a snapshot accessor.
        fixed_snapshot = None
        try:
            snapshot_accessor = getattr(hotset, "snapshot", None)
            if callable(snapshot_accessor):
                fixed_snapshot = snapshot_accessor()
        except Exception:
            fixed_snapshot = None

        lookup_started = time.perf_counter()
        for dst_ip in by_destination:
            metrics["unique_destinations_checked"] += 1
            try:
                if fixed_snapshot is not None:
                    key = normalize_ip(dst_ip)
                    entry = fixed_snapshot.lookup_key(key) if key is not None else None
                else:
                    entry = hotset.lookup(dst_ip)
            except Exception:
                metrics["candidate_errors"] += 1
                continue
            if entry is None:
                metrics["hotset_misses"] += 1
            else:
                metrics["hotset_hits"] += 1
                matches[dst_ip] = entry
        metrics["lookup_duration_ms"] = round(
            (time.perf_counter() - lookup_started) * 1000.0, 3
        )

        aggregates: dict[tuple[Any, ...], dict[str, Any]] = {}
        for dst_ip, entry in matches.items():
            semantics = self._entry_semantics(entry)
            for observation, context, src_ip, ts in by_destination[dst_ip]:
                key = self._candidate_key(observation, context, src_ip, dst_ip, ts)
                aggregate = aggregates.get(key)
                if aggregate is None:
                    aggregates[key] = {
                        "observation": observation,
                        "context": context,
                        "entry": entry,
                        "semantics": semantics,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "ts": ts,
                        "packets": int(observation.packets or 0),
                        "bytes": int(observation.bytes or 0),
                        "flow_count": max(1, int(observation.flow_count or 1)),
                    }
                else:
                    aggregate["packets"] += int(observation.packets or 0)
                    aggregate["bytes"] += int(observation.bytes or 0)
                    aggregate["flow_count"] += max(1, int(observation.flow_count or 1))

        candidates: list[OutboundIocCandidate] = []
        for aggregate in aggregates.values():
            observation = aggregate["observation"]
            context = aggregate["context"]
            entry = aggregate["entry"]
            semantics = aggregate["semantics"]
            candidates.append(
                OutboundIocCandidate(
                    timestamp=aggregate["ts"],
                    sensor=clean_text(observation.sensor),
                    direction="OUTBOUND",
                    src_ip=aggregate["src_ip"],
                    dst_ip=aggregate["dst_ip"],
                    src_role=context.src_role,
                    dst_role=context.dst_role,
                    src_port=int(observation.src_port or 0),
                    dst_port=int(observation.dst_port or 0),
                    protocol=int(observation.protocol or 0),
                    packets=aggregate["packets"],
                    bytes=aggregate["bytes"],
                    flow_count=aggregate["flow_count"],
                    ioc_matched=True,
                    ioc_ip=entry.ip,
                    semantic_tier=semantics["semantic_tier"],
                    signal_class=semantics["signal_class"],
                    providers=semantics["providers"],
                    indicator_types=semantics["indicator_types"],
                    classifications=semantics["classifications"],
                    categories=semantics["categories"],
                    botnet_family=semantics["botnet_family"],
                    tags=semantics["tags"],
                    network_context=context.as_dict(),
                    subscriber_resolution_available=False,
                )
            )

        candidates.sort(
            key=lambda item: (
                item.timestamp,
                item.sensor,
                item.src_ip,
                item.dst_ip,
                item.src_port,
                item.dst_port,
                item.protocol,
            )
        )
        return self._finish_cycle(started, metrics, candidates)


__all__ = [
    "FEATURE_FLAG",
    "OutboundIocCandidate",
    "OutboundIocCycleResult",
    "OutboundIocShadowDetector",
]

