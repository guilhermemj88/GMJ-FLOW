from __future__ import annotations

"""Threat handoff layer for a peak's evidence.

This module does NOT create a new threat score or a parallel attack
classifier. It separates two distinct things:

  * PEAK EVIDENCE (objective): deltas, concentration, protocol shift,
    packet-size change, source-count increase, IOC presence. Computed here
    as plain signals — facts, never decisions.

  * THREAT VERDICT (belongs to the existing Threat Engine / Threat
    Intelligence): the canonical verdicts from ``threat_intel_verdict`` and
    the Threat Policy Engine. The Peak Hunter only reuses them.

The returned ``verdict`` is a triage label used to decide the handoff:

  - ``normal``:      no strong objective signal and no IOC;
  - ``noteworthy``:  objective signals present (concentration, surge, shift);
  - ``suspicious``:  an IOC hit from the existing TI infrastructure.

It is a routing hint, NOT an attack classification and NOT a mitigation
decision.
"""

from typing import Any

VERDICT_NORMAL = "normal"
VERDICT_NOTEWORTHY = "noteworthy"
VERDICT_SUSPICIOUS = "suspicious"

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
    """Batch-enrich IPs against the existing local IOC hot set (no N+1 I/O)."""
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
    for kind in ("external_ips", "local_ips", "dst_ips", "src_ips"):
        for row in changed.get(kind) or []:
            key = str(row.get("key") or row.get("label") or "").strip()
            if key and key not in seen:
                seen.add(key)
    for item in concentration.get("top_dst_ips") or []:
        key = str(item.get("dst_ip") or "").strip()
        if key and key not in seen:
            seen.add(key)
    return sorted(seen)


def compute_peak_signals(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Objective signals derived from evidence. Facts, not decisions."""
    deltas = evidence.get("deltas") or {}
    concentration = evidence.get("concentration") or {}
    signals: list[dict[str, Any]] = []

    pps_delta = float(deltas.get("pps_delta_pct") or 0)
    bps_delta = float(deltas.get("bps_delta_pct") or 0)
    share = float(concentration.get("top_dst_share_pct") or 0)
    unique_src = int(concentration.get("unique_src_count") or 0)

    if pps_delta >= 100.0:
        signals.append({"name": "pps_surge", "value": round(pps_delta, 2), "detail": "PPS subiu acima de 100% vs baseline"})
    if bps_delta >= 50.0:
        signals.append({"name": "bps_surge", "value": round(bps_delta, 2), "detail": "BPS subiu acima de 50% vs baseline"})
    if share >= 50.0:
        signals.append({"name": "concentrated_traffic", "value": round(share, 2), "detail": f"Top destino concentra {share:.1f}% do trafego"})
    if unique_src >= 10:
        signals.append({"name": "many_sources", "value": unique_src, "detail": f"{unique_src} origens distintas"})

    before_size = float(deltas.get("avg_packet_size_before") or 0)
    peak_size = float(deltas.get("avg_packet_size_peak") or 0)
    if before_size > 0 and peak_size > 0 and abs(peak_size - before_size) / before_size >= 0.30:
        signals.append({"name": "packet_size_change", "value": round(peak_size, 2), "detail": f"Tamanho medio do pacote mudou de {before_size:.1f} para {peak_size:.1f} bytes"})

    protocols = (evidence.get("changed") or {}).get("protocols") or []
    for row in protocols[:1]:
        if float(row.get("delta_bps_pct") or 0) >= 100.0:
            signals.append({"name": "protocol_shift", "value": row.get("label"), "detail": f"Protocolo {row.get('label')} +{float(row.get('delta_bps_pct') or 0):.0f}%"})
    return signals


def assess_peak_threat(evidence: dict[str, Any], hotset: Any = None) -> dict[str, Any]:
    """Triage a peak using existing TI + objective signals.

    Returns a routing hint (normal/noteworthy/suspicious), the objective
    signals and the IOC signals from the existing TI hot set. No mitigation,
    no new score, no attack classification.
    """
    ips = _collect_participants(evidence)
    ioc_signals = enrich_peak_iocs(hotset, ips)
    signals = compute_peak_signals(evidence)

    verdict = VERDICT_NORMAL
    reasons: list[str] = []
    if any(signal.get("strength") == "strong" for signal in ioc_signals):
        verdict = VERDICT_SUSPICIOUS
        reasons.append("strong_ioc")
    elif ioc_signals:
        verdict = VERDICT_NOTEWORTHY
        reasons.append("ioc_signal")
    if signals:
        if verdict == VERDICT_NORMAL:
            verdict = VERDICT_NOTEWORTHY
        reasons.extend(signal["name"] for signal in signals)

    handoff_recommended = verdict != VERDICT_NORMAL
    return {
        "verdict": verdict,
        "reasons": sorted(set(reasons)),
        "signals": signals,
        "ioc_hit_count": len(ioc_signals),
        "ioc_signals": ioc_signals,
        "participants_checked": len(ips),
        "handoff_recommended": handoff_recommended,
    }
