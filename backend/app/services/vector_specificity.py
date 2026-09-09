"""Vector Specificity — Shadow traffic accounting (Phase 0).

Observability-only: classifies the "specific expected" share of a UDP
aggregate and computes ``raw_packets_s`` / ``specific_packets_s`` /
``residual_packets_s`` WITHOUT changing any detection decision.

This module is pure: no database access, no ClickHouse, no side effects. The
caller (``query_detection_rule_candidates``) supplies the resolved asset
context, the active codec names and the observed volumes, and receives a
``traffic_accounting`` metadata dict.

The threshold basis stays ``"raw"`` in this phase; the caller keeps comparing
the raw ``metric_value`` exactly as before.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

# Fixed vocabulary for the Phase-0 specific case (Google GGC QUIC return).
# Deliberately local constants so this module stays import-light and pure.
# Rule-guard values are compared upper-cased.
SPECIFIC_PROTOCOL = "UDP"
SPECIFIC_DOMAIN = "INTERNAL_IP"
SPECIFIC_DIRECTION = "TRANSMITS"

# Semantic gate values.
SPECIFIC_ROLE = "CDN_CACHE"
SPECIFIC_PROVIDER = "GOOGLE_GGC"
SPECIFIC_CODEC = "QUIC_RETURN"

# Expected-service tuple used with ``expected_services_match``.
SPECIFIC_SERVICE_PROTOCOL = "udp"
SPECIFIC_SERVICE_SOURCE_PORT = 443
SPECIFIC_SERVICE_DIRECTION = "TO_CUSTOMERS"

THRESHOLD_BASIS_RAW = "raw"


def _normalize(value: Any) -> str:
    return str(value or "").strip().upper()


def is_udp_internal_transmits_candidate(
    protocol: Any,
    domain: Any,
    direction: Any,
) -> bool:
    """Cheap guard: only UDP/internal_ip/transmits rules can qualify."""
    return (
        _normalize(protocol) == SPECIFIC_PROTOCOL
        and _normalize(domain) == SPECIFIC_DOMAIN
        and _normalize(direction) == SPECIFIC_DIRECTION
    )


def specific_udp_return_satisfied(
    asset_context: Mapping[str, Any] | None,
    codec_names: Sequence[str] | set[str] | None,
    expected_service: bool,
) -> bool:
    """Full semantic gate: ALL criteria must match.

    ``source_port=443`` alone, ``GOOGLE_GGC`` alone, or ``CDN_CACHE`` alone are
    never sufficient — role, provider, expected service and codec are each
    required.
    """
    context = asset_context or {}
    names = {_normalize(name) for name in (codec_names or [])}
    return (
        _normalize(context.get("role")) == SPECIFIC_ROLE
        and _normalize(context.get("provider")) == SPECIFIC_PROVIDER
        and bool(expected_service)
        and SPECIFIC_CODEC in names
    )


def effective_specific_packets_s(
    port_specific_packets_s: float,
    qualified: bool,
) -> float:
    """The port-level src443 volume only counts as specific when the gate passes."""
    if not qualified:
        return 0.0
    return max(float(port_specific_packets_s or 0), 0.0)


def residual_packets_s(raw_packets_s: float, specific_packets_s: float) -> float:
    """Residual = raw - specific, never negative."""
    return max(float(raw_packets_s or 0) - float(specific_packets_s or 0), 0.0)


def build_traffic_accounting(
    *,
    raw_packets_s: float,
    specific_packets_s: float,
    residual: float | None = None,
    specific_codec: str | None,
    expected_service: bool,
    asset_role: str | None,
    provider: str | None,
    direction: str,
    threshold_basis: str = THRESHOLD_BASIS_RAW,
) -> dict[str, Any]:
    """Assemble the persisted ``traffic_accounting`` metadata dict."""
    if residual is None:
        residual = residual_packets_s(raw_packets_s, specific_packets_s)
    return {
        "raw_packets_s": round(float(raw_packets_s or 0), 2),
        "specific_packets_s": round(float(specific_packets_s or 0), 2),
        "residual_packets_s": round(float(residual or 0), 2),
        "threshold_basis": threshold_basis,
        "specific_codec": specific_codec,
        "expected_service": bool(expected_service),
        "asset_role": asset_role,
        "provider": provider,
        "direction": direction,
    }


__all__ = [
    "SPECIFIC_PROTOCOL",
    "SPECIFIC_DOMAIN",
    "SPECIFIC_DIRECTION",
    "SPECIFIC_ROLE",
    "SPECIFIC_PROVIDER",
    "SPECIFIC_CODEC",
    "SPECIFIC_SERVICE_PROTOCOL",
    "SPECIFIC_SERVICE_SOURCE_PORT",
    "SPECIFIC_SERVICE_DIRECTION",
    "THRESHOLD_BASIS_RAW",
    "is_udp_internal_transmits_candidate",
    "specific_udp_return_satisfied",
    "effective_specific_packets_s",
    "residual_packets_s",
    "build_traffic_accounting",
]
