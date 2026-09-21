"""P4 outbound IOC security-event persistence (detect-only).

Transforms the P3 aggregation output (one ``OutboundIocRelationship`` per
client <-> IOC pair) into canonical GMJ-FLOW ``security_events`` rows, reusing
the existing ``upsert_security_event`` path and its idempotent
``event_key``-based dedup.

Design
------
- One event per active ``(internal_identity, external_ioc)`` relationship.
  Sub-cycle hits are UPDATEs (never duplicate rows), because the event key is
  ``canonical_event_key(detector, attack_type, internal_identity,
  external_ioc, "", "OUTBOUND", "")``.
- Persistence is idempotent and restart-safe: the event key is a pure
  function of the relationship identity, so replaying the same cycle or
  restarting the runtime converges to the same rows (``INSERT .. ON CONFLICT
  DO UPDATE``).
- Canonical lifecycle is respected: events are ``active`` while upserted; a
  relationship that leaves the sliding window is no longer upserted (its
  ``last_seen`` freezes) and is eventually removed by the existing
  ``cleanup_security_events`` retention. P4 does NOT invent an ``expired``
  status (the schema has none); it only reports ``events_closed`` for
  observability.
- Detect-only: severity/verdict stay ``INFO``, score ``0``. No policy,
  mitigation, FlowSpec, RTBH or BGP side effects.
- IOC semantics are preserved in ``threat_intel_json`` (providers,
  categories, classifications, botnet families, tags, signal class,
  semantic tier, cumulative hit_count/flows/packets/bytes and bounded
  port/protocol/sensor sets). CGNAT identity is preserved in
  ``network_context_json``.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional

from app.services.outbound_ioc_aggregation import (
    IDENTITY_CUSTOMER_IP,
    OutboundIocAggregationCycle,
    OutboundIocRelationship,
)
from app.services.security_events import (
    ensure_security_event_schema,
    upsert_security_event,
)
from app.services.threat_intelligence import clean_text, sqlite_connection

LOGGER = logging.getLogger("gmj-flow")

FEATURE_FLAG = "GMJFLOW_OUTBOUND_IOC_PERSISTENCE_ENABLED"
DETECTOR = "outbound_ioc"
ATTACK_TYPE = "OUTBOUND_IOC"
WINDOW_SECONDS = 300


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class _IocVector:
    """Minimal vector-like object consumed by ``vector_security_payload``."""

    detector: str
    attack_type: str
    src_ip: str
    target_ip: str
    target_prefix: str
    direction: str
    protocol: str
    first_seen: str
    last_seen: str
    severity: str
    detector_score: int
    confidence: float
    verdict: str
    features: dict[str, Any]
    network_context: dict[str, Any]
    evidence: list[str]
    score_components: dict[str, Any]
    threat_intel: dict[str, Any]
    baseline_deviation: float
    window_seconds: int
    campaign_id: str
    decision_source: str


def build_vector(rel: OutboundIocRelationship) -> _IocVector:
    """Build a canonical payload vector from one P3 relationship."""
    cgnat = rel.cgnat
    network_context: dict[str, Any] = {
        "src_role": "CUSTOMER" if rel.identity_kind == IDENTITY_CUSTOMER_IP else "CGNAT_PUBLIC",
        "dst_role": "EXTERNAL",
        "traffic_direction": "OUTBOUND",
        "identity_kind": rel.identity_kind,
        "internal_identity": rel.internal_identity,
        "external_ioc": rel.external_ioc,
    }
    if rel.identity_kind != IDENTITY_CUSTOMER_IP:
        network_context.update(
            {
                "subscriber_id": cgnat.subscriber_id,
                "subscriber_name": cgnat.subscriber_name,
                "private_ip": cgnat.private_ip,
                "public_ip": cgnat.public_ip,
                "cgnat_resolution_status": cgnat.status,
                "cgnat_confidence": cgnat.confidence,
                "cgnat_source_type": cgnat.source_type,
                "cgnat_pool_name": cgnat.pool_name,
                "cgnat_port_start": cgnat.port_start,
                "cgnat_port_end": cgnat.port_end,
            }
        )
    threat_intel: dict[str, Any] = {
        "providers": sorted(rel.providers),
        "indicator_types": sorted(rel.indicator_types),
        "classifications": sorted(rel.classifications),
        "categories": sorted(rel.categories),
        "botnet_families": sorted(rel.botnet_families),
        "tags": sorted(rel.tags),
        "signal_class": rel.signal_class,
        "semantic_tier": int(rel.semantic_tier),
        "hit_count": int(rel.hit_count),
        "flows": int(rel.flows),
        "packets": int(rel.packets),
        "bytes": int(rel.bytes),
        "protocols": sorted(rel.protocols),
        "src_ports": sorted(rel.src_ports),
        "dst_ports": sorted(rel.dst_ports),
        "sensors": sorted(rel.sensors),
    }
    evidence = [
        "%s to %s (signal=%s tier=%d)"
        % (category.upper(), rel.external_ioc, rel.signal_class, int(rel.semantic_tier))
        for category in sorted(rel.categories)[:10]
    ]
    return _IocVector(
        detector=DETECTOR,
        attack_type=ATTACK_TYPE,
        src_ip=rel.internal_identity,
        target_ip=rel.external_ioc,
        target_prefix="",
        direction="OUTBOUND",
        protocol="",
        first_seen=rel.first_seen,
        last_seen=rel.last_seen,
        severity="INFO",
        detector_score=0,
        confidence=0.0,
        verdict="INFO",
        features={
            "packets": int(rel.packets),
            "bytes": int(rel.bytes),
            "flows": int(rel.flows),
            "flow_count": int(rel.flows),
            "packet_count": int(rel.packets),
            "byte_count": int(rel.bytes),
        },
        network_context=network_context,
        evidence=evidence,
        score_components={},
        threat_intel=threat_intel,
        baseline_deviation=0.0,
        window_seconds=WINDOW_SECONDS,
        campaign_id="",
        decision_source="GMJ_FLOW",
    )


class OutboundIocPersistence:
    """Batched, idempotent persistence of outbound IOC relationships."""

    def __init__(
        self,
        connection_factory: Callable[..., Any] = sqlite_connection,
        *,
        enabled: Optional[bool] = None,
    ) -> None:
        self.connection_factory = connection_factory
        self._enabled_override = enabled
        self._last_active_keys: set[str] = set()
        self._totals: dict[str, Any] = {
            "cycles": 0,
            "relationships_seen": 0,
            "events_created": 0,
            "events_updated": 0,
            "events_closed": 0,
            "events_written": 0,
            "write_errors": 0,
            "db_transactions": 0,
            "rows_written": 0,
            "persistence_ms": 0.0,
            "cycle_errors": 0,
            "last_error": "",
        }

    @property
    def enabled(self) -> bool:
        if self._enabled_override is not None:
            return bool(self._enabled_override)
        return _env_bool(FEATURE_FLAG, False)

    def _empty_metrics(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "relationships_seen": 0,
            "events_created": 0,
            "events_updated": 0,
            "events_closed": 0,
            "events_written": 0,
            "write_errors": 0,
            "db_transactions": 0,
            "rows_written": 0,
            "persistence_ms": 0.0,
            "cycle_errors": 0,
        }

    def persist(
        self, cycle: OutboundIocAggregationCycle
    ) -> dict[str, Any]:
        """Persist one P3 aggregation cycle as security events.

        Returns a metrics dict (idempotent on replay, restart-safe).
        """
        if not self.enabled:
            return {"enabled": False}

        started = time.perf_counter()
        metrics = self._empty_metrics()
        relationships = list(cycle.relationships)
        metrics["relationships_seen"] = len(relationships)

        # Build vectors OUTSIDE the DB transaction (no SQLite work while the
        # writer connection is held longer than necessary).
        vectors = []
        active_keys: set[str] = set()
        for rel in relationships:
            vector = build_vector(rel)
            vectors.append(vector)
            active_keys.add(
                vector.detector + "|" + vector.src_ip + "|" + vector.target_ip
            )

        try:
            with self.connection_factory() as conn:
                metrics["db_transactions"] += 1
                ensure_security_event_schema(conn)
                for vector in vectors:
                    try:
                        upsert_security_event(conn, vector, ensure_schema=False)
                        metrics["events_written"] += 1
                    except Exception as exc:
                        metrics["write_errors"] += 1
                        LOGGER.warning(
                            "outbound_ioc_persistence_write_failed key=%s|%s error=%s",
                            vector.src_ip, vector.target_ip, exc,
                        )
                conn.commit()
        except Exception as exc:
            metrics["cycle_errors"] += 1
            LOGGER.exception("outbound_ioc_persistence_cycle_failed")
            self._totals["cycle_errors"] += 1
            self._totals["last_error"] = f"{exc.__class__.__name__}: {clean_text(exc)}"[:300]

        # Reconcile current keys with the previous cycle for close accounting.
        for key in active_keys:
            if key in self._last_active_keys:
                metrics["events_updated"] += 1
            else:
                metrics["events_created"] += 1
        metrics["events_closed"] = len(self._last_active_keys - active_keys)
        self._last_active_keys = active_keys

        metrics["persistence_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
        for field in (
            "relationships_seen", "events_created", "events_updated", "events_closed",
            "events_written", "write_errors", "db_transactions",
        ):
            self._totals[field] += metrics[field]
        self._totals["rows_written"] += metrics["events_written"]
        self._totals["cycles"] += 1
        self._totals["persistence_ms"] = metrics["persistence_ms"]
        return metrics

    def status(self) -> dict[str, Any]:
        totals = dict(self._totals)
        totals["enabled"] = self.enabled
        return totals


__all__ = [
    "FEATURE_FLAG",
    "DETECTOR",
    "ATTACK_TYPE",
    "OutboundIocPersistence",
    "build_vector",
]
