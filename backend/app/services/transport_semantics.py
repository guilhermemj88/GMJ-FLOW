"""Transport / port semantic classification (P5.0).

Answers ONE descriptive question: *what is the probable ROLE of this traffic?*

It is deliberately NOT a threat verdict, NOT a whitelist and NOT a mitigation
authorization. Three dimensions stay separate:

* TransportSemantic (this module)  -> "what is the role of the traffic?"
* Threat Intelligence              -> "who is the origin/destination?"
* Behavioral detection             -> "how is this traffic behaving?"

Design constraints:

* Pure: no database, no ClickHouse, no network, no side effects.
* Cheap: O(1) over an already-aggregated feature group (reads the bounded
  ``tcp_flag_distribution`` / port details produced by ``flow_features``).
* Reuses existing signals; never re-scans raw observations.

TCP/443 rules (see P5.0 runbook sections 7/13/26):

* dst_port=443 + SYN dominant            -> HTTPS_CLIENT_INITIATION
* src_port=443 + ACK/PSH-ACK dominant    -> HTTPS_SERVER_RESPONSE
* src_port=443 + SYN dominant            -> HTTPS_SOURCE_SYN (never suppressed)
* src/dst 443 + inconclusive flags       -> HTTPS_AMBIGUOUS
* established both ways                  -> HTTPS_BIDIRECTIONAL_ESTABLISHED
* UDP/443 (QUIC)                         -> QUIC_UDP_443 (TCP flags never apply)
* otherwise                              -> NON_HTTPS

``c2_over_https`` is an overlay (OUTBOUND + dst443 + confirmed C2 IOC), never
part of the base transport role and never a score relief.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

# ---------------------------------------------------------------------------
# Connection roles (descriptive — not threat labels).
# ---------------------------------------------------------------------------
HTTPS_CLIENT_INITIATION = "HTTPS_CLIENT_INITIATION"
HTTPS_SERVER_RESPONSE = "HTTPS_SERVER_RESPONSE"
HTTPS_SOURCE_SYN = "HTTPS_SOURCE_SYN"
HTTPS_BIDIRECTIONAL_ESTABLISHED = "HTTPS_BIDIRECTIONAL_ESTABLISHED"
HTTPS_AMBIGUOUS = "HTTPS_AMBIGUOUS"
QUIC_UDP_443 = "QUIC_UDP_443"
NON_HTTPS = "NON_HTTPS"

# ---------------------------------------------------------------------------
# Confidence buckets (no magic score).
# ---------------------------------------------------------------------------
CONF_HIGH = "HIGH"
CONF_MEDIUM = "MEDIUM"
CONF_LOW = "LOW"

# ---------------------------------------------------------------------------
# Auditable reason codes.
# ---------------------------------------------------------------------------
RC_DST_443 = "DST_443"
RC_SRC_443 = "SRC_443"
RC_TCP_SYN_DOMINANT = "TCP_SYN_DOMINANT"
RC_TCP_ACK_DOMINANT = "TCP_ACK_DOMINANT"
RC_TCP_PSH_ACK_RESPONSE = "TCP_PSH_ACK_RESPONSE"
RC_OUTBOUND_CLIENT_DIRECTION = "OUTBOUND_CLIENT_DIRECTION"
RC_INBOUND_SERVER_DIRECTION = "INBOUND_SERVER_DIRECTION"
RC_IOC_C2_DESTINATION = "IOC_C2_DESTINATION"
RC_IOC_BOTNET_DESTINATION = "IOC_BOTNET_DESTINATION"
RC_AMBIGUOUS_FLAGS = "AMBIGUOUS_FLAGS"
RC_NON_HTTPS_PORT = "NON_HTTPS_PORT"
RC_UDP_443 = "UDP_443"
RC_ESTABLISHED_BIDIRECTIONAL = "ESTABLISHED_BIDIRECTIONAL"

# TCP flag bitfield (mirrors behavioral_detection to stay import-light).
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

# Classification thresholds (explicit, auditable, NOT production detection
# thresholds — these only describe transport role).
SYN_DOMINANT_MIN = 0.5
ACK_LOW_MAX = 0.3
ACK_DOMINANT_MIN = 0.5
PSH_ACK_RESPONSE_MIN = 0.3
SYN_LOW_MAX = 0.2
ESTABLISHED_ACK_MIN = 0.7
ESTABLISHED_SYN_MAX = 0.1

_PORT_443 = 443


def _num(value: Any) -> float:
    try:
        return max(0.0, float(value or 0.0))
    except (TypeError, ValueError):
        return 0.0


def _ratio(numerator: float, denominator: float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _syn_only(flags: int) -> bool:
    return bool(flags & TCP_SYN) and not bool(flags & TCP_ACK)


def _ack_only(flags: int) -> bool:
    return bool(flags & TCP_ACK) and not bool(flags & (TCP_SYN | TCP_RST | TCP_FIN))


def _psh_ack(flags: int) -> bool:
    return bool(flags & TCP_PSH) and bool(flags & TCP_ACK) and not bool(flags & TCP_SYN)


def _norm_direction(direction: Any) -> str:
    return str(direction or "UNKNOWN").strip().upper()


def _client_direction(direction: str) -> bool:
    """Customer -> external is client-side (OUTBOUND / INTERNAL)."""
    return direction in {"OUTBOUND", "INTERNAL"}


def _server_direction(direction: str) -> bool:
    """External -> customer is server-side (INBOUND)."""
    return direction == "INBOUND"


def _c2_flag(threat_intel: Mapping[str, Any] | None) -> bool:
    """C2 confirmed via Threat Intelligence (orientation preserved)."""
    if not threat_intel:
        return False
    if _num(threat_intel.get("c2_sources")) > 0:
        return True
    source_intel = threat_intel.get("source_intel")
    intel = source_intel if isinstance(source_intel, Mapping) else threat_intel
    if _num(intel.get("c2_sources")) > 0:
        return True
    classifications = {str(value).lower() for value in (intel.get("classifications") or [])}
    indicator_types = {str(value).upper() for value in (intel.get("indicator_types") or [])}
    return "c2" in classifications or "c2_confirmed" in classifications or "C2" in indicator_types


def classify_transport(
    *,
    protocol: int,
    src_port: int,
    dst_port: int,
    syn_ratio: float = 0.0,
    ack_ratio: float = 0.0,
    psh_ack_ratio: float = 0.0,
    rst_ratio: float = 0.0,
    direction: str = "UNKNOWN",
    c2: bool = False,
    botnet: bool = False,
    malware: bool = False,
) -> dict[str, Any]:
    """Classify the transport role from already-aggregated primitives.

    Primitive-level and directly unit-testable; ``transport_semantics_from_features``
    adapts the ``flow_features`` dict into these primitives.
    """
    direction = _norm_direction(direction)
    syn = _num(syn_ratio)
    ack = _num(ack_ratio)
    psh_ack = _num(psh_ack_ratio)
    rst = _num(rst_ratio)

    service_port = _PORT_443
    reason_codes: list[str] = []

    # QUIC / UDP 443 — TCP flags must never apply.
    if protocol == 17 and (src_port in (443, 8443) or dst_port in (443, 8443)):
        reason_codes.append(RC_UDP_443)
        if dst_port in (443, 8443) and _client_direction(direction):
            reason_codes.append(RC_OUTBOUND_CLIENT_DIRECTION)
        if src_port in (443, 8443) and _server_direction(direction):
            reason_codes.append(RC_INBOUND_SERVER_DIRECTION)
        return _result(QUIC_UDP_443, CONF_HIGH, reason_codes, service_port, "SOURCE" if src_port in (443, 8443) else "DESTINATION", protocol, syn, ack, psh_ack, rst, False)

    # Only TCP with 443 on the dominant side is HTTPS-relevant.
    src443 = src_port == 443
    dst443 = dst_port == 443
    if protocol != 6 or not (src443 or dst443):
        reason_codes.append(RC_NON_HTTPS_PORT)
        return _result(NON_HTTPS, CONF_HIGH, reason_codes, service_port if (src443 or dst443) else (dst_port or src_port), "NONE", protocol, syn, ack, psh_ack, rst, False)

    if src443:
        reason_codes.append(RC_SRC_443)
    if dst443:
        reason_codes.append(RC_DST_443)

    syn_dominant = syn >= SYN_DOMINANT_MIN and ack <= ACK_LOW_MAX
    ack_dominant = ack >= ACK_DOMINANT_MIN or psh_ack >= PSH_ACK_RESPONSE_MIN
    established = ack >= ESTABLISHED_ACK_MIN and syn < ESTABLISHED_SYN_MAX

    # SYN takes precedence over server-response (runbook section 13).
    if src443 and syn_dominant:
        reason_codes.append(RC_TCP_SYN_DOMINANT)
        role = HTTPS_SOURCE_SYN
        confidence = CONF_HIGH
    elif dst443 and syn_dominant:
        reason_codes.append(RC_TCP_SYN_DOMINANT)
        if _client_direction(direction):
            reason_codes.append(RC_OUTBOUND_CLIENT_DIRECTION)
            confidence = CONF_HIGH
        else:
            confidence = CONF_MEDIUM
        role = HTTPS_CLIENT_INITIATION
    elif src443 and dst443 and established:
        reason_codes.append(RC_ESTABLISHED_BIDIRECTIONAL)
        role = HTTPS_BIDIRECTIONAL_ESTABLISHED
        confidence = CONF_MEDIUM
    elif src443 and ack_dominant and syn < SYN_LOW_MAX:
        reason_codes.append(RC_TCP_ACK_DOMINANT if ack >= ACK_DOMINANT_MIN else RC_TCP_PSH_ACK_RESPONSE)
        if _server_direction(direction):
            reason_codes.append(RC_INBOUND_SERVER_DIRECTION)
            confidence = CONF_HIGH
        else:
            confidence = CONF_MEDIUM
        role = HTTPS_SERVER_RESPONSE
    else:
        reason_codes.append(RC_AMBIGUOUS_FLAGS)
        role = HTTPS_AMBIGUOUS
        confidence = CONF_LOW

    service_side = "BOTH" if (src443 and dst443) else ("SOURCE" if src443 else "DESTINATION")

    # c2_over_https overlay: OUTBOUND + dst443 + confirmed C2 IOC.
    c2_over = bool(direction == "OUTBOUND" and dst443 and c2)
    if c2_over:
        reason_codes.append(RC_IOC_C2_DESTINATION)
    elif direction == "OUTBOUND" and dst443 and botnet:
        reason_codes.append(RC_IOC_BOTNET_DESTINATION)

    return _result(role, confidence, reason_codes, service_port, service_side, protocol, syn, ack, psh_ack, rst, c2_over)


def _result(
    role: str,
    confidence: str,
    reason_codes: list[str],
    service_port: int,
    service_side: str,
    protocol: int,
    syn: float,
    ack: float,
    psh_ack: float,
    rst: float,
    c2_over: bool,
) -> dict[str, Any]:
    return {
        "transport_semantic": role,
        "transport_confidence": confidence,
        "transport_reason_codes": reason_codes,
        "service_port": service_port,
        "service_side": service_side,
        "c2_over_https": bool(c2_over),
        "protocol": {1: "icmp", 6: "tcp", 17: "udp"}.get(protocol, str(protocol)),
        "syn_ratio": round(syn, 4),
        "ack_ratio": round(ack, 4),
        "psh_ack_ratio": round(psh_ack, 4),
        "rst_ratio": round(rst, 4),
    }


def _top(items: Sequence[Mapping[str, Any]] | None) -> Mapping[str, Any]:
    for item in items or []:
        if isinstance(item, Mapping):
            return item
    return {}


def _tcp_flag_ratios(flag_distribution: Sequence[Mapping[str, Any]] | None) -> tuple[float, float, float, float]:
    """Packet-based SYN / ACK / PSH+ACK / RST ratios from the bounded flag table."""
    entries = [item for item in (flag_distribution or []) if isinstance(item, Mapping)]
    total = sum(_num(item.get("packets")) for item in entries)
    syn = sum(_num(item.get("packets")) for item in entries if _syn_only(int(_num(item.get("flags")))))
    ack = sum(_num(item.get("packets")) for item in entries if _ack_only(int(_num(item.get("flags")))))
    psh_ack = sum(_num(item.get("packets")) for item in entries if _psh_ack(int(_num(item.get("flags")))))
    rst = sum(_num(item.get("packets")) for item in entries if int(_num(item.get("flags"))) & TCP_RST)
    if total <= 0:
        return 0.0, 0.0, 0.0, 0.0
    return _ratio(syn, total), _ratio(ack, total), _ratio(psh_ack, total), _ratio(rst, total)


def _dominant_protocol(distribution: Sequence[Mapping[str, Any]] | None) -> int:
    top = _top(distribution)
    return int(_num(top.get("protocol_number")))


def _dominant_port(details: Sequence[Mapping[str, Any]] | None) -> int:
    top = _top(details)
    return int(_num(top.get("port")))


def transport_semantics_from_features(
    features: Mapping[str, Any] | None,
    direction: str = "UNKNOWN",
    threat_intel: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Adapt the ``flow_features`` dict into a TransportSemantic classification.

    Reuses already-computed signals; never scans raw observations.
    """
    features = features or {}
    protocol = _dominant_protocol(features.get("protocol_distribution"))
    src_port = _dominant_port(features.get("top_source_port_details"))
    dst_port = _dominant_port(features.get("top_destination_port_details"))
    syn, ack, psh_ack, rst = _tcp_flag_ratios(features.get("tcp_flag_distribution"))
    return classify_transport(
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        syn_ratio=syn,
        ack_ratio=ack,
        psh_ack_ratio=psh_ack,
        rst_ratio=rst,
        direction=direction,
        c2=_c2_flag(threat_intel),
    )


__all__ = [
    "HTTPS_CLIENT_INITIATION",
    "HTTPS_SERVER_RESPONSE",
    "HTTPS_SOURCE_SYN",
    "HTTPS_BIDIRECTIONAL_ESTABLISHED",
    "HTTPS_AMBIGUOUS",
    "QUIC_UDP_443",
    "NON_HTTPS",
    "CONF_HIGH",
    "CONF_MEDIUM",
    "CONF_LOW",
    "classify_transport",
    "transport_semantics_from_features",
]
