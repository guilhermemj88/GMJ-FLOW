"""Canonical Threat Intelligence verdict & evidence model (P5.1).

This module is intentionally PURE: it performs no database access, no network
I/O, and holds no mutable state. It converts the heterogeneous provider match
records produced by ``ThreatIntelLookupContext.lookup_ip`` / ``ThreatIntelManager.
lookup_ip`` into a common, auditable representation:

    Layer 1 (provider normalization): raw provider match -> evidence dict
    Layer 2 (evidence aggregation): list[evidence] -> canonical verdict

Nothing here changes detection, thresholds, ThreatScore, event keys, mitigation,
or persistence. It only ADDS verdict/evidence metadata.

Canonical verdicts are THREAT INTELLIGENCE verdicts only. They are never
ALLOW/BLOCK/BENIGN/SAFE and never a traffic-danger score (that is ThreatScore's
job). Confidence answers "how trustworthy is this verdict", not "how dangerous
is this traffic".
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

# ---------------------------------------------------------------------------
# Canonical verdicts
# ---------------------------------------------------------------------------
C2_CONFIRMED = "C2_CONFIRMED"
BOTNET_DDOS = "BOTNET_DDOS"
MALWARE_COMPROMISED = "MALWARE_COMPROMISED"
ABUSE_SCANNER = "ABUSE_SCANNER"
LOW_SIGNAL = "LOW_SIGNAL"
UNKNOWN = "UNKNOWN"

CANONICAL_VERDICTS = {
    C2_CONFIRMED,
    BOTNET_DDOS,
    MALWARE_COMPROMISED,
    ABUSE_SCANNER,
    LOW_SIGNAL,
    UNKNOWN,
}

# Precedence: lower index wins. C2 evidence outranks botnet, botnet outranks
# malware/compromised, etc. This reflects operational priority in GMJ-FLOW:
# an explicit C2 indicator is the strongest TI signal we act on, while abuse /
# scanner noise is common and weak. Conflicts are preserved in ``evidences``.
VERDICT_PRECEDENCE: dict[str, int] = {
    C2_CONFIRMED: 0,
    BOTNET_DDOS: 1,
    MALWARE_COMPROMISED: 2,
    ABUSE_SCANNER: 3,
    LOW_SIGNAL: 4,
    UNKNOWN: 5,
}

# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

_CONFIDENCE_LEVELS = (LOW, MEDIUM, HIGH)


def _shift_confidence(confidence: str, delta: int) -> str:
    try:
        index = _CONFIDENCE_LEVELS.index(confidence)
    except ValueError:
        index = 0
    index = max(0, min(len(_CONFIDENCE_LEVELS) - 1, index + delta))
    return _CONFIDENCE_LEVELS[index]


# ---------------------------------------------------------------------------
# Freshness
# ---------------------------------------------------------------------------
FRESH = "FRESH"
AGING = "AGING"
STALE = "STALE"
UNKNOWN_FRESHNESS = "UNKNOWN"

# Provider-aware freshness cutoffs in seconds: (fresh <= fresh_s, aging <= aging_s).
# A provider that syncs every 8h must not be called stale after 30 minutes, so
# cutoffs follow each provider's real cadence rather than a single global rule.
_PROVIDER_FRESHNESS_SECONDS: dict[str, tuple[int, int]] = {
    # 15m cadence snapshot feeds
    "CEREAL2": (1 * 3600, 24 * 3600),
    "FEODO": (1 * 3600, 24 * 3600),
    # 8h cadence API poll
    "GREYNOISE": (8 * 3600, 48 * 3600),
    # 15m cadence; indicators carry no per-IP timestamp -> feed expiry (48h)
    "BLOCKLIST_DE": (1 * 3600, 48 * 3600),
    # 4h cadence bogon feed (network context only; freshness still reported)
    "TEAM_CYMRU": (4 * 3600, 24 * 3600),
}
_DEFAULT_FRESHNESS_SECONDS = (1 * 3600, 24 * 3600)

# ---------------------------------------------------------------------------
# Reason codes (auditable)
# ---------------------------------------------------------------------------
RC_EXPLICIT_C2 = "EXPLICIT_C2_CATEGORY"
RC_FEODO_BOTNET = "FEODO_BOTNET"
RC_GREYNOISE_MALICIOUS = "GREYNOISE_MALICIOUS"
RC_GREYNOISE_SCANNER = "GREYNOISE_SCANNER"
RC_GREYNOISE_SUSPICIOUS = "GREYNOISE_SUSPICIOUS"
RC_BLOCKLIST_ABUSE = "BLOCKLIST_ABUSE"
RC_GENERIC_MALICIOUS_ONLY = "GENERIC_MALICIOUS_ONLY"
RC_MULTI_PROVIDER_CORROBORATION = "MULTI_PROVIDER_CORROBORATION"
RC_FRESH_INDICATOR = "FRESH_INDICATOR"
RC_AGING_INDICATOR = "AGING_INDICATOR"
RC_STALE_INDICATOR = "STALE_INDICATOR"
RC_STALE_CONFIDENCE_CAP = "STALE_CONFIDENCE_CAP"
RC_PROVIDER_FEED_STALE = "PROVIDER_FEED_STALE"
RC_UNKNOWN_TIMESTAMP = "UNKNOWN_TIMESTAMP"

_PROVIDERS = {"CEREAL2", "FEODO", "GREYNOISE", "BLOCKLIST_DE", "TEAM_CYMRU"}


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse the heterogeneous timestamps providers actually return.

    Handles ISO-8601 (``2026-09-11T03:48:23.902Z``), space-separated
    (``2026-02-17 05:41:23``) and date-only (``2026-02-18``) strings.
    Returns None when the value is empty or unparseable.
    """
    text = _clean(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _age_seconds(timestamp: Any, now: datetime) -> int | None:
    parsed = _parse_timestamp(timestamp)
    if parsed is None:
        return None
    return max(0, int((now - parsed).total_seconds()))


def freshness_label(provider: str, timestamp: Any, now: datetime | None = None) -> str:
    """Provider-aware freshness of an indicator timestamp.

    Uses the timestamp priority documented in the runbook: indicator
    ``last_seen`` (real provider timestamp) first; callers fall back to the
    feed timestamp and finally to local ``updated_at``. A missing/unparseable
    timestamp yields UNKNOWN (never fabricated).
    """
    age = _age_seconds(timestamp, now or datetime.now(timezone.utc))
    if age is None:
        return UNKNOWN_FRESHNESS
    fresh_s, aging_s = _PROVIDER_FRESHNESS_SECONDS.get(
        _clean(provider).upper(), _DEFAULT_FRESHNESS_SECONDS
    )
    if age <= fresh_s:
        return FRESH
    if age <= aging_s:
        return AGING
    return STALE


def _freshness_reason(freshness: str) -> str:
    return {
        FRESH: RC_FRESH_INDICATOR,
        AGING: RC_AGING_INDICATOR,
        STALE: RC_STALE_INDICATOR,
        UNKNOWN_FRESHNESS: RC_UNKNOWN_TIMESTAMP,
    }.get(freshness, RC_UNKNOWN_TIMESTAMP)


# ---------------------------------------------------------------------------
# Layer 1: provider normalization
# ---------------------------------------------------------------------------
def _classify_fallback(classification: str) -> tuple[str, str]:
    """Conservative classification -> (verdict, reason_code) fallback.

    Only used when a match carries no recognized provider-specific mapping.
    It never invents C2 from a generic malicious signal.
    """
    key = _clean(classification).lower()
    if key in {"c2", "c2_confirmed", "botnet_cc", "command_and_control"}:
        return C2_CONFIRMED, RC_EXPLICIT_C2
    if key in {"active_botnet", "ddos", "ddos_source"}:
        return BOTNET_DDOS, ""
    if key in {"malware_distribution", "payload_delivery", "compromised", "compromised_host"}:
        return MALWARE_COMPROMISED, ""
    if key in {
        "scanner", "brute_force", "bruteforce", "abuse",
        "reported_attack_source", "malicious", "reputation_malicious",
    }:
        return ABUSE_SCANNER, RC_GENERIC_MALICIOUS_ONLY if key in {"malicious", "reputation_malicious"} else ""
    if key in {"suspicious", "noise", "benign"}:
        return LOW_SIGNAL, ""
    return UNKNOWN, ""


def _evidence_feed_timestamp(match: Mapping[str, Any]) -> str | None:
    """Feed timestamp priority: metadata.retrieved_at then local updated_at."""
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    retrieved = _clean(metadata.get("retrieved_at"))
    if retrieved:
        return retrieved
    return _clean(match.get("updated_at")) or None


def normalize_provider_evidence(
    match: Mapping[str, Any],
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Layer 1: convert one provider match record into canonical evidence.

    Returns None for records that are NOT threat evidence (e.g. Team Cymru
    bogons, which are network-context signals and must never become a threat
    verdict). Bogons stay visible in ``lookup_ip().matches`` (unchanged), but
    are excluded from verdict aggregation.
    """
    if not isinstance(match, Mapping):
        return None
    now = now or datetime.now(timezone.utc)
    provider = _clean(match.get("provider")).upper()
    if provider == "TEAM_CYMRU":
        return None  # bogons: network context, not a threat verdict
    if provider not in _PROVIDERS:
        return None

    classification = _clean(match.get("classification")).lower()
    indicator_type = _clean(match.get("indicator_type")).upper()
    botnet_family = _clean(match.get("botnet_family"))
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    first_seen = _clean(match.get("first_seen")) or None
    last_seen = _clean(match.get("last_seen")) or None
    feed_updated_at = _evidence_feed_timestamp(match)

    verdict = UNKNOWN
    confidence = LOW
    reason_codes: list[str] = []

    if provider == "CEREAL2":
        # /api/v1/c2 snapshot from botnet.cl: explicit C2.
        if indicator_type == "C2" or classification == "c2":
            verdict = C2_CONFIRMED
            confidence = HIGH
            reason_codes.append(RC_EXPLICIT_C2)
        else:
            verdict, rc = _classify_fallback(classification)
            confidence = MEDIUM
            if rc:
                reason_codes.append(rc)
    elif provider == "FEODO":
        # Feodo Tracker (abuse.ch) tracks botnet C2 infrastructure
        # (Emotet/Dridex/QakBot). Explicit C2; malware family preserved.
        if indicator_type == "C2" or classification == "c2":
            verdict = C2_CONFIRMED
            confidence = HIGH
            reason_codes.append(RC_EXPLICIT_C2)
        else:
            verdict, rc = _classify_fallback(classification)
            confidence = MEDIUM
            if rc:
                reason_codes.append(rc)
        if botnet_family:
            reason_codes.append(RC_FEODO_BOTNET)
    elif provider == "GREYNOISE":
        # GreyNoise mostly describes scanning / internet noise. "malicious" is
        # reputation, never C2 or compromised-host. Respect the real category.
        tags = metadata.get("tags") if isinstance(metadata.get("tags"), list) else match.get("tags") or []
        tag_text: list[str] = []
        for tag in tags if isinstance(tags, list) else []:
            if isinstance(tag, Mapping):
                for field in ("name", "slug", "category", "intention"):
                    value = _clean(tag.get(field)).lower()
                    if value:
                        tag_text.append(value)
            else:
                tag_text.append(_clean(tag).lower())
        if classification == "malicious":
            verdict = ABUSE_SCANNER
            confidence = MEDIUM
            reason_codes.append(RC_GREYNOISE_MALICIOUS)
        elif classification == "suspicious":
            verdict = LOW_SIGNAL
            confidence = LOW
            reason_codes.append(RC_GREYNOISE_SUSPICIOUS)
        else:
            verdict, rc = _classify_fallback(classification)
            if rc:
                reason_codes.append(rc)
        if any("scan" in tag for tag in tag_text) and verdict != C2_CONFIRMED:
            verdict = ABUSE_SCANNER
            reason_codes.append(RC_GREYNOISE_SCANNER)
    elif provider == "BLOCKLIST_DE":
        # Reported attack source (fail2ban-style abuse reports). No per-IP
        # timestamp; feed-level retrieved_at/expires_at only.
        verdict = ABUSE_SCANNER
        confidence = LOW
        reason_codes.append(RC_BLOCKLIST_ABUSE)
    else:
        verdict, rc = _classify_fallback(classification)
        if rc:
            reason_codes.append(rc)

    # Timestamp priority: indicator last_seen -> feed timestamp.
    indicator_ts = last_seen or feed_updated_at
    freshness = freshness_label(provider, indicator_ts, now)
    reason_codes.append(_freshness_reason(freshness))

    # Feed freshness is reported separately and never deletes the IOC.
    feed_freshness = freshness_label(provider, feed_updated_at, now)
    if feed_freshness == STALE:
        reason_codes.append(RC_PROVIDER_FEED_STALE)

    # Confidence reflects category strength AND freshness; staleness weakens it.
    if freshness == STALE:
        confidence = _shift_confidence(confidence, -1)

    raw_metadata = {}
    for key in ("category", "classification_original", "confidence_original", "port", "status", "service"):
        if metadata.get(key) is not None:
            raw_metadata[key] = metadata[key]

    return {
        "provider": provider,
        "indicator": _clean(match.get("ip")) or _clean(match.get("network")),
        "indicator_type": indicator_type,
        "provider_category": classification,
        "canonical_verdict": verdict,
        "confidence": confidence,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "feed_updated_at": feed_updated_at,
        "feed_freshness": feed_freshness,
        "freshness": freshness,
        "reason_codes": sorted(set(reason_codes)),
        "raw_metadata": raw_metadata,
    }


# ---------------------------------------------------------------------------
# Layer 2: evidence aggregation
# ---------------------------------------------------------------------------
def aggregate_threat_intel_evidence(
    evidences: list[dict[str, Any]],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Layer 2: aggregate canonical evidence into a final verdict.

    Corroboration (multiple DISTINCT providers) raises confidence in the
    existing evidence; it never invents a higher category (two scanners do not
    become C2).
    """
    now = now or datetime.now(timezone.utc)
    evidences = [e for e in evidences if isinstance(e, Mapping)]
    if not evidences:
        return {
            "verdict": UNKNOWN,
            "confidence": LOW,
            "freshness": UNKNOWN_FRESHNESS,
            "providers": [],
            "corroboration_count": 0,
            "provider_count": 0,
            "reason_codes": [],
            "first_seen": None,
            "last_seen": None,
            "evidences": [],
        }

    # Final verdict follows precedence (strongest category wins).
    winning = min(
        evidences,
        key=lambda e: VERDICT_PRECEDENCE.get(e.get("canonical_verdict"), 5),
    )
    verdict = winning.get("canonical_verdict") or UNKNOWN

    # Distinct providers (duplicates within one provider never inflate the count).
    providers = sorted({_clean(e.get("provider")).upper() for e in evidences} - {""})
    provider_count = len(providers)
    corroboration_count = provider_count

    confidence = winning.get("confidence") or LOW
    if corroboration_count >= 2:
        confidence = _shift_confidence(confidence, +1)

    # Canonical staleness cap: corroboration confirms the HISTORICAL nature of
    # stale evidence; it never makes an old last_seen look current. A STALE
    # winning verdict never exceeds MEDIUM, regardless of provider count.
    stale_capped = False
    if (winning.get("freshness") or UNKNOWN_FRESHNESS) == STALE and confidence == HIGH:
        confidence = MEDIUM
        stale_capped = True

    reason_codes = sorted({_clean(rc) for e in evidences for rc in (e.get("reason_codes") or []) if _clean(rc)})
    if corroboration_count >= 2:
        reason_codes.append(RC_MULTI_PROVIDER_CORROBORATION)
        reason_codes = sorted(set(reason_codes))
    if stale_capped:
        reason_codes.append(RC_STALE_CONFIDENCE_CAP)
        reason_codes = sorted(set(reason_codes))

    first_seens = [_clean(e.get("first_seen")) for e in evidences if _clean(e.get("first_seen"))]
    last_seens = [_clean(e.get("last_seen")) for e in evidences if _clean(e.get("last_seen"))]

    return {
        "verdict": verdict,
        "confidence": confidence,
        "freshness": winning.get("freshness") or UNKNOWN_FRESHNESS,
        "providers": providers,
        "corroboration_count": corroboration_count,
        "provider_count": provider_count,
        "reason_codes": reason_codes,
        "first_seen": min(first_seens) if first_seens else None,
        "last_seen": max(last_seens) if last_seens else None,
        "evidences": evidences,
    }


def verdict_from_matches(
    matches: list[dict[str, Any]] | tuple[Any, ...],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Convenience entry point used by the lookup hot path.

    ``matches`` is the raw ``lookup_ip().matches`` list. Returns the additive
    verdict metadata merged into ``lookup_ip()`` unchanged (never replacing an
    existing key).
    """
    now = now or datetime.now(timezone.utc)
    evidences: list[dict[str, Any]] = []
    for match in matches if isinstance(matches, (list, tuple)) else []:
        if not isinstance(match, Mapping):
            continue
        evidence = normalize_provider_evidence(match, now)
        if evidence is not None:
            evidences.append(evidence)
    return aggregate_threat_intel_evidence(evidences, now)
