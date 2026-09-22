from __future__ import annotations

"""Threat Intelligence / Threat Engine integration for a peak's evidence.

Reuses EXCLUSIVELY the existing infrastructure and never creates a parallel
threat score, attack classification or mitigation path:

  - ``ActiveIocHotSet`` (local, in-memory, O(1) IOC lookup);
  - the canonical TI verdict vocabulary from ``threat_intel_verdict``.

A peak threat assessment only answers: "is there a known signal among the
peak's participants, and how strong is it?" The outcome is a triage label
(normal / noteworthy / suspicious) — not a score, not a decision.
"""

from typing import Any

VERDICT_NORMAL = "normal"
VERDICT_NOTEWORTHY = "noteworthy"
VERDICT_SUSPICIOUS = "suspicious"

# Strong IOC categories that immediately make a peak suspicious.
STRONG_THREAT_TYPES = {
    "c2",
    "botnet",
    "botnet_ddos",
    "malware",
    "malware_compromised",
    "compromised",
}
WEAK_THREAT_TYPES = {"scanner", "abuse", "abuse_scanner", "low_signal", "spam"}


def _entry_signal(entry: Any) -> dict[str, Any]:
    return {
        "ip": getattr(entry, "ip", ""),
        "providers": list(getattr(entry, "providers", ()) or ()),
        "threat_types": list(getattr(entry, "threat_types", ()) or ()),
        "categories": list(getattr(entry, "categories", ()) or ()),
        "botnet_family": getattr(entry, "botnet_family", "") or "",
        "semantic_tier": int(getattr(entry, "semantic_tier", 99) or 99),
    }


def _signal_strength(signal: dict[str, Any]) -> str:
    """Map an IOC entry to strong/weak/none using existing vocabulary."""
    threat_types = {str(value).lower() for value in signal.get("threat_types") or []}
    categories = {str(value).lower() for value in signal.get("categories") or []}
    combined = threat_types | categories
    if combined & STRONG_THREAT_TYPES:
        return "strong"
    if signal.get("semantic_tier", 99) <= 1:
        return "strong"
    if combined & WEAK_THREAT_TYPES:
        return "weak"
    if signal.get("semantic_tier", 99) <= 3:
        return "weak"
    return "none"


def enrich_peak_iocs(hotset: Any, ips: list[str]) -> list[dict[str, Any]]:
    """Batch-enrich IPs against the existing local IOC hot set (no N+1 I/O).

    ``hotset`` may be None or an object exposing ``lookup(ip)`` returning an
    IOC entry or None. Each lookup is an in-memory O(1) operation.
    """
    signals: list[dict[str, Any]] = []
    if hotset is None:
        return signals
    for ip in ips:
        entry = hotset.lookup(ip)
        if entry is None:
            continue
        signal = _entry_signal(entry)
        signal["strength"] = _signal_strength(signal)
        signals.append(signal)
    signals.sort(key=lambda item: item.get("semantic_tier", 99))
    return signals


def _collect_participants(evidence: dict[str, Any]) -> list[str]:
    changed = evidence.get("changed") or {}
    concentration = evidence.get("concentration") or {}
    seen: set[str] = set()
    for kind in ("dst_ips", "src_ips"):
        for row in changed.get(kind) or []:
            key = str(row.get("key") or row.get("label") or "").strip()
            if key and key not in seen:
                seen.add(key)
    for item in concentration.get("top_dst_ips") or []:
        key = str(item.get("dst_ip") or "").strip()
        if key and key not in seen:
            seen.add(key)
    return sorted(seen)


def assess_peak_threat(evidence: dict[str, Any], hotset: Any = None) -> dict[str, Any]:
    """Assess the peak evidence using existing TI infrastructure.

    Returns a triage label plus audit reasons. No mitigation, no new score.
    """
    ips = _collect_participants(evidence)
    ioc_signals = enrich_peak_iocs(hotset, ips)
    reasons: list[str] = []
    verdict = VERDICT_NORMAL
    if any(signal.get("strength") == "strong" for signal in ioc_signals):
        verdict = VERDICT_SUSPICIOUS
        reasons.append("strong_ioc")
    elif ioc_signals:
        verdict = VERDICT_NOTEWORTHY
        reasons.append("ioc_signal")

    deltas = evidence.get("deltas") or {}
    concentration = evidence.get("concentration") or {}
    pps_delta = float(deltas.get("pps_delta_pct") or 0)
    share = float(concentration.get("top_dst_share_pct") or 0)
    if share >= 50.0 and pps_delta >= 100.0:
        reasons.append("concentrated_pps_surge")
        if verdict == VERDICT_NORMAL:
            verdict = VERDICT_NOTEWORTHY
    return {
        "verdict": verdict,
        "reasons": sorted(set(reasons)),
        "ioc_hit_count": len(ioc_signals),
        "ioc_signals": ioc_signals,
        "participants_checked": len(ips),
    }
