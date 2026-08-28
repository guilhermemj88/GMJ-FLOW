"""Security Situation Map aggregation (Threat Intelligence Map V2).

Deterministic owner for turning internal security_events + campaigns into a
lightweight geo-aggregated "situation" view. It never renders flow/network
traffic: it represents threats, events, campaigns, severity and concentration.

All color/tier decisions are deterministic (no AI). Geolocation reuses the
existing MaxMind `geo_lookup_ip` path already used elsewhere in the app.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from app.services.security_events import ensure_security_event_schema, security_event_row
from app.services.threat_intelligence import clean_text


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

PERIOD_SECONDS = {
    "15m": 900,
    "30m": 1800,
    "1h": 3600,
    "6h": 21600,
    "24h": 86400,
    "7d": 604800,
}

TIER_PRIORITY = {"critical": 4, "elevated": 3, "suspicious": 2, "info": 1, "benign": 0}
TIER_COLOR = {
    "critical": "#ef4444",
    "elevated": "#f97316",
    "suspicious": "#facc15",
    "info": "#818cf8",
    "benign": "#64748b",
}

_BENIGN_STATUSES = {"benign", "resolved", "expired", "false_positive", "not_malicious"}

# Country centroids used as a fallback when the GeoIP lookup resolves a country
# (e.g. via ASN) but returns no precise latitude/longitude. Kept in sync with
# the COUNTRY_CENTERS map used by the frontend provider layer.
COUNTRY_CENTERS = {
    "AR": (-38.4, -63.6), "AU": (-25.3, 133.8), "AT": (47.5, 14.6), "BD": (23.7, 90.4), "BE": (50.5, 4.5),
    "BG": (42.7, 25.5), "BR": (-14.2, -51.9), "CA": (56.1, -106.3), "CH": (46.8, 8.2), "CL": (-35.7, -71.5),
    "CN": (35.9, 104.2), "CO": (4.6, -74.3), "CZ": (49.8, 15.5), "DE": (51.2, 10.5), "DK": (56.3, 9.5),
    "EG": (26.8, 30.8), "ES": (40.5, -3.7), "FI": (61.9, 25.7), "FR": (46.2, 2.2), "GB": (55.4, -3.4),
    "GR": (39.1, 21.8), "HK": (22.3, 114.2), "HU": (47.2, 19.5), "ID": (-0.8, 113.9), "IE": (53.1, -8.2),
    "IL": (31.0, 34.9), "IN": (20.6, 79.0), "IR": (32.4, 53.7), "IT": (41.9, 12.6), "JP": (36.2, 138.3),
    "KR": (35.9, 127.8), "MX": (23.6, -102.6), "MY": (4.2, 101.9), "NG": (9.1, 8.7), "NL": (52.1, 5.3),
    "NO": (60.5, 8.5), "NZ": (-40.9, 174.9), "PE": (-9.2, -75.0), "PH": (12.9, 121.8), "PK": (30.4, 69.3),
    "PL": (51.9, 19.1), "PT": (39.4, -8.2), "RO": (45.9, 24.9), "RS": (44.0, 21.0), "RU": (61.5, 105.3),
    "SA": (23.9, 45.1), "SE": (60.1, 18.6), "SG": (1.35, 103.8), "TH": (15.9, 100.9), "TR": (39.0, 35.2),
    "TW": (23.7, 121.0), "UA": (48.4, 31.2), "US": (37.1, -95.7), "AE": (23.4, 53.8), "VN": (14.1, 108.3),
    "ZA": (-30.6, 22.9),
}

SEVERITY_PRIORITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "": 0}


def severity_priority(severity: Any) -> int:
    return SEVERITY_PRIORITY.get(clean_text(severity).upper(), 1)


def security_severity_tier(verdict: Any, severity: Any, status: Any = "") -> str:
    """Deterministic security-situation tier for one event (no AI)."""
    verdict = clean_text(verdict).upper()
    severity = clean_text(severity).upper()
    status = clean_text(status).lower()
    if status in _BENIGN_STATUSES:
        return "benign"
    if verdict == "CONFIRMED_ATTACK" or severity == "CRITICAL":
        return "critical"
    if verdict == "LIKELY_ATTACK" or severity == "HIGH":
        return "elevated"
    if verdict == "WARNING" or severity == "MEDIUM":
        return "suspicious"
    return "info"


def tier_priority(tier: str) -> int:
    return TIER_PRIORITY.get(clean_text(tier).lower(), 0)


def max_tier(tiers: Sequence[str]) -> str:
    if not tiers:
        return "info"
    return max(tiers, key=tier_priority)


def tier_color(tier: str) -> str:
    return TIER_COLOR.get(clean_text(tier).lower(), TIER_COLOR["info"])


def _geo_lookup() -> Any:
    try:
        from app.main import geo_lookup_ip

        return geo_lookup_ip
    except Exception:
        def _fallback(ip: str, *_a: Any, **_k: Any) -> dict[str, Any]:
            return {
                "ip": clean_text(ip),
                "country_code": "",
                "country_name": "N/D",
                "city": "",
                "region": "",
                "latitude": None,
                "longitude": None,
                "asn": 0,
                "as_name": "",
                "source": "unavailable",
            }

        return _fallback


def _campaign_risk_column(conn: Any) -> bool:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(threat_campaigns)").fetchall()}
    return "campaign_risk_score" in cols


def build_security_map(
    conn: Any,
    *,
    period: str = "24h",
    severity: str = "",
    verdict: str = "",
    attack_type: str = "",
    status: str = "",
    campaign: str = "all",
    ai_status: str = "all",
    group_by: str = "country",
    limit: int = 200,
    geo_lookup: Any = None,
) -> dict[str, Any]:
    """Aggregate security_events into a small set of geo/entity points.

    Filters are applied in SQL (backend), never in the browser. The result is
    bounded: at most `limit` points, each a lightweight aggregate.
    """
    group_by = group_by if group_by in {"country", "city", "asn", "campaign"} else "country"
    seconds = PERIOD_SECONDS.get(period, PERIOD_SECONDS["24h"])
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")

    filters: list[str] = ["last_seen >= ?"]
    values: list[Any] = [cutoff]

    def add_list(column: str, raw: str) -> None:
        parts = [clean_text(p).upper() for p in raw.split(",") if clean_text(p)]
        if parts:
            filters.append(f"{column} IN ({','.join('?' for _ in parts)})")
            values.extend(parts)

    add_list("severity", severity)
    add_list("verdict", verdict)
    add_list("attack_type", attack_type)
    if clean_text(status) and clean_text(status).lower() != "all":
        filters.append("status = ?")
        values.append(clean_text(status).lower())
    if campaign == "with":
        filters.append("campaign_id != ''")
    elif campaign == "without":
        filters.append("campaign_id = ''")
    if ai_status in {"analyzed", "not_analyzed", "campaign"}:
        if ai_status == "analyzed":
            filters.append("ai_analysis_status = 'analyzed'")
        elif ai_status == "not_analyzed":
            filters.append("(ai_analysis_status IS NULL OR ai_analysis_status = '' OR ai_analysis_status = 'not_analyzed')")
        else:  # campaign
            filters.append("campaign_id != ''")

    where = "WHERE " + " AND ".join(filters)

    ensure_security_event_schema(conn)
    rows = conn.execute(
        f"SELECT * FROM security_events {where} ORDER BY last_seen DESC, id DESC LIMIT 5000",
        values,
    ).fetchall()

    geo = geo_lookup or _geo_lookup()
    campaign_risk: dict[str, int] = {}
    has_risk_col = _campaign_risk_column(conn)
    campaign_ids = {clean_text(dict(r).get("campaign_id")) for r in rows if clean_text(dict(r).get("campaign_id"))}
    if campaign_ids and has_risk_col:
        placeholders = ",".join("?" for _ in campaign_ids)
        for crow in conn.execute(
            f"SELECT campaign_id, campaign_risk_score FROM threat_campaigns WHERE campaign_id IN ({placeholders})",
            list(campaign_ids),
        ).fetchall():
            campaign_risk[clean_text(crow["campaign_id"])] = safe_int(crow["campaign_risk_score"])

    geo_cache: dict[str, dict[str, Any]] = {}
    unlocated = 0

    def resolve(src_ip: str) -> dict[str, Any]:
        ip = clean_text(src_ip)
        if ip not in geo_cache:
            geo_cache[ip] = geo(ip) if ip else {"country_code": "", "latitude": None, "longitude": None}
        return geo_cache[ip]

    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in rows:
        event = security_event_row(raw)
        src_ip = clean_text(event.get("src_ip"))
        geo_item = resolve(src_ip)
        lat = geo_item.get("latitude")
        lon = geo_item.get("longitude")
        country_code = clean_text(geo_item.get("country_code")).upper()
        if not country_code:
            unlocated += 1
        # Country-level grouping always gets a coordinate: use the exact GeoIP
        # point when available, otherwise fall back to the country centroid.
        if (lat is None or lon is None) and group_by == "country" and country_code in COUNTRY_CENTERS:
            lat, lon = COUNTRY_CENTERS[country_code]
        campaign_id = clean_text(event.get("campaign_id"))
        risk = campaign_risk.get(campaign_id, 0)

        if group_by == "country":
            key = country_code
            label = clean_text(geo_item.get("country_name")) or key
        elif group_by == "city":
            city = clean_text(geo_item.get("city"))
            key = f"{city}|{country_code}" if city else country_code
            label = city or country_code
        elif group_by == "asn":
            key = str(safe_int(geo_item.get("asn")))
            label = clean_text(geo_item.get("as_name")) or ("AS" + key if key != "0" else "N/D")
        else:  # campaign
            key = campaign_id or "__no_campaign__"
            label = campaign_id or "Sem campanha"

        bucket = groups.setdefault((group_by, key), {
            "key": key,
            "group_by": group_by,
            "label": label,
            "country_code": country_code if group_by != "asn" else "",
            "country": clean_text(geo_item.get("country_name")) if group_by != "asn" else "",
            "city": clean_text(geo_item.get("city")) if group_by == "city" else "",
            "asn": safe_int(geo_item.get("asn")),
            "lat": lat,
            "lon": lon,
            "event_count": 0,
            "confirmed_count": 0,
            "likely_count": 0,
            "max_severity": "",
            "max_threat_score": 0,
            "max_campaign_risk_score": 0,
            "unique_sources": set(),
            "campaign_ids": set(),
            "latest_seen": "",
            "attack_types": Counter(),
            "tiers": [],
        })
        if (bucket["lat"] is None or bucket["lon"] is None) and lat is not None and lon is not None:
            bucket["lat"], bucket["lon"] = lat, lon
        bucket["event_count"] += 1
        verdict_value = clean_text(event.get("verdict")).upper()
        severity_value = clean_text(event.get("severity")).upper()
        if verdict_value == "CONFIRMED_ATTACK":
            bucket["confirmed_count"] += 1
        elif verdict_value == "LIKELY_ATTACK":
            bucket["likely_count"] += 1
        if severity_priority(severity_value) > severity_priority(bucket["max_severity"]):
            bucket["max_severity"] = severity_value
        threat_score_payload_value = event.get("threat_score")
        threat_score_value = threat_score_payload_value.get("score") if isinstance(threat_score_payload_value, Mapping) else threat_score_payload_value
        bucket["max_threat_score"] = max(bucket["max_threat_score"], safe_int(threat_score_value))
        bucket["max_campaign_risk_score"] = max(bucket["max_campaign_risk_score"], risk)
        if src_ip:
            bucket["unique_sources"].add(src_ip)
        if campaign_id:
            bucket["campaign_ids"].add(campaign_id)
        bucket["latest_seen"] = max(bucket["latest_seen"], clean_text(event.get("last_seen")))
        bucket["attack_types"][clean_text(event.get("attack_type")).upper() or "OTHER"] += 1
        bucket["tiers"].append(security_severity_tier(verdict_value, severity_value, event.get("status")))

    points = []
    for (_g, _k), bucket in groups.items():
        if bucket["lat"] is None or bucket["lon"] is None:
            # Unplaceable group (no coordinates); already counted in summary.unlocated.
            continue
        tier = max_tier(bucket["tiers"])
        top_attack_types = [t for t, _c in bucket["attack_types"].most_common(4)]
        points.append({
            "key": bucket["key"],
            "group_by": bucket["group_by"],
            "label": bucket["label"],
            "country": bucket["country"],
            "country_code": bucket["country_code"],
            "city": bucket["city"],
            "asn": bucket["asn"],
            "lat": bucket["lat"],
            "lon": bucket["lon"],
            "tier": tier,
            "color": tier_color(tier),
            "event_count": bucket["event_count"],
            "confirmed_count": bucket["confirmed_count"],
            "likely_count": bucket["likely_count"],
            "max_severity": bucket["max_severity"],
            "max_threat_score": bucket["max_threat_score"],
            "max_campaign_risk_score": bucket["max_campaign_risk_score"],
            "unique_sources": len(bucket["unique_sources"]),
            "campaign_count": len(bucket["campaign_ids"]),
            "latest_seen": bucket["latest_seen"],
            "top_attack_types": top_attack_types,
        })

    points.sort(key=lambda p: (tier_priority(p["tier"]), p["event_count"]), reverse=True)
    points = points[:limit]

    # Ranking follows the same filters + grouping.
    ranking = [
        {
            "key": p["key"],
            "label": p["label"],
            "event_count": p["event_count"],
            "confirmed_count": p["confirmed_count"],
            "tier": p["tier"],
        }
        for p in points[:50]
    ]

    return {
        "summary": {
            "total_events": len(rows),
            "points": len(points),
            "unlocated": unlocated,
            "critical": sum(1 for p in points if p["tier"] == "critical"),
            "elevated": sum(1 for p in points if p["tier"] == "elevated"),
            "suspicious": sum(1 for p in points if p["tier"] == "suspicious"),
        },
        "points": points,
        "ranking": ranking,
        "filters_applied": {
            "period": period,
            "severity": clean_text(severity) or "all",
            "verdict": clean_text(verdict) or "all",
            "attack_type": clean_text(attack_type) or "all",
            "status": clean_text(status) or "all",
            "campaign": campaign,
            "ai_status": ai_status,
            "group_by": group_by,
            "limit": limit,
        },
    }
