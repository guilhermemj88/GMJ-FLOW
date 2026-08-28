"""Security Situation Map aggregation (Threat Intelligence Map V2.1).

Direction-aware, deterministic owner for turning internal security_events into
a lightweight geo-aggregated "situation" view.

Design rules (no AI, no per-event external lookups):

- `resolve_security_map_geo_subject(event)` is the single owner that decides
  which IP (source vs destination) is the *geographic subject* of a threat.
- INBOUND + EXTERNAL source  -> subject = SOURCE  ("de onde a ameaça vem").
- OUTBOUND (CUSTOMER/CGNAT -> EXTERNAL) -> subject = DESTINATION
  ("para onde o tráfego suspeito da nossa rede vai"). The local CGNAT/customer
  address is never treated as the threat origin.
- INTERNAL, private sources, CGNAT-as-source, ambiguous contexts and
  documentation/test IPs are semantically excluded from the world map.
- Geolocation reuses the existing `geo_lookup_ip` (ASN -> country + GeoIP cache)
  and a country-centroid fallback. It never invents coordinates.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
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

SEVERITY_PRIORITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "": 0}

_PRIVATE_V4 = [ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_LOOPBACK = ip_network("127.0.0.0/8")
_LINKLOCAL = ip_network("169.254.0.0/16")
_CGNAT_10064 = ip_network("100.64.0.0/10")
_DOC_IPV6 = ip_network("2001:db8::/32")
_LL_V6 = ip_network("fe80::/10")
_ULA_V6 = ip_network("fc00::/7")


def ip_kind(ip: str) -> str:
    """Classify an IP string: public, private, cgnat_10064, doc_ipv6, invalid."""
    text = clean_text(ip)
    if not text:
        return "invalid"
    try:
        addr = ip_address(text)
    except ValueError:
        return "invalid"
    if addr.version == 6:
        if addr in _DOC_IPV6 or addr in _LL_V6 or addr in _ULA_V6:
            return "private"
        return "public"
    if addr in _LOOPBACK or addr in _LINKLOCAL:
        return "private"
    if addr in _CGNAT_10064:
        return "cgnat_10064"
    for net in _PRIVATE_V4:
        if addr in net:
            return "private"
    return "public"


def first_prefix_ip(prefix: str) -> str:
    """Return the first usable IP of a CIDR prefix (network address + 1)."""
    text = clean_text(prefix)
    if not text:
        return ""
    try:
        net = ip_network(text, strict=False)
    except ValueError:
        return ""
    if net.num_addresses <= 2:
        return str(net.network_address)
    return str(net.network_address + 1)


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
        from app.services.geoip_service import geoip_service

        return geoip_service.lookup_ip
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
                "accuracy_radius": None,
                "asn": 0,
                "as_name": "",
                "source": "NONE",
            }

        return _fallback


def _is_cgnat_source(event: Mapping[str, Any]) -> bool:
    src_role = clean_text(event.get("src_role")).upper()
    cgnat = clean_text(event.get("cgnat_context")).lower()
    nc = event.get("network_context")
    nc_src_cgnat = bool(nc.get("src_is_cgnat")) if isinstance(nc, Mapping) else False
    return src_role == "CGNAT_PUBLIC" or cgnat.startswith("source_cgnat") or nc_src_cgnat


def resolve_security_map_geo_subject(event: Mapping[str, Any]) -> dict[str, Any]:
    """Decide which IP is the geographic subject of a security event.

    Returns `{geo_subject, geo_ip, geo_reason}` where `geo_subject` is one of
    "source", "destination" or "none". This is the single owner of the
    direction-aware rule; it must not be duplicated elsewhere.
    """
    direction = clean_text(event.get("direction")).upper()
    src_role = clean_text(event.get("src_role")).upper()
    dst_role = clean_text(event.get("dst_role")).upper()
    src_ip = clean_text(event.get("src_ip"))
    target_ip = clean_text(event.get("target_ip"))
    target_prefix = clean_text(event.get("target_prefix"))

    if direction == "INTERNAL":
        return {"geo_subject": "none", "geo_ip": "", "geo_reason": "INTERNAL_NO_PUBLIC_GEO"}

    if direction == "INBOUND":
        if src_role == "EXTERNAL":
            if ip_kind(src_ip) == "public":
                return {"geo_subject": "source", "geo_ip": src_ip, "geo_reason": "INBOUND_EXTERNAL_SOURCE"}
            if ip_kind(src_ip) in ("private", "cgnat_10064"):
                return {"geo_subject": "none", "geo_ip": "", "geo_reason": "PRIVATE_SOURCE"}
            return {"geo_subject": "none", "geo_ip": "", "geo_reason": "MISSING_PUBLIC_GEO"}
        # INBOUND vindo de um customer/cgnat interno é ambíguo (não é ameaça externa).
        return {"geo_subject": "none", "geo_ip": "", "geo_reason": "AMBIGUOUS_CONTEXT"}

    if direction == "OUTBOUND":
        if dst_role == "EXTERNAL":
            dest_ip = target_ip or first_prefix_ip(target_prefix)
            if ip_kind(dest_ip) == "public":
                return {"geo_subject": "destination", "geo_ip": dest_ip, "geo_reason": "OUTBOUND_EXTERNAL_DESTINATION"}
            if _is_cgnat_source(event):
                # The local CGNAT address must never be the geo subject.
                return {"geo_subject": "none", "geo_ip": "", "geo_reason": "CGNAT_SOURCE_NOT_GEO_SUBJECT"}
            return {"geo_subject": "none", "geo_ip": "", "geo_reason": "MISSING_PUBLIC_GEO"}
        return {"geo_subject": "none", "geo_ip": "", "geo_reason": "AMBIGUOUS_CONTEXT"}

    # EXTERNAL->EXTERNAL transit (or unknown) without a clear customer context.
    return {"geo_subject": "none", "geo_ip": "", "geo_reason": "AMBIGUOUS_CONTEXT"}


# Reasons that mean "this event must not be placed on the world map".
_EXCLUDED_REASONS = {
    "INTERNAL_NO_PUBLIC_GEO",
    "PRIVATE_SOURCE",
    "CGNAT_SOURCE_NOT_GEO_SUBJECT",
    "AMBIGUOUS_CONTEXT",
}

# Reasons that mean "should be on the map but the geo data is missing".
_MISSING_GEO_REASONS = {"MISSING_PUBLIC_GEO"}

# Reasons assigned to events that WERE successfully placed on the map.
_LOCATED_REASONS = {"INBOUND_EXTERNAL_SOURCE", "OUTBOUND_EXTERNAL_DESTINATION"}


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
    direction: str = "all",
    context: str = "all",
    group_by: str = "country",
    limit: int = 200,
    geo_lookup: Any = None,
) -> dict[str, Any]:
    """Aggregate security_events into a small set of direction-aware geo points.

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

    if direction in {"inbound", "outbound", "internal", "external"}:
        filters.append("direction = ?")
        values.append(direction.upper())

    if context in {"external", "customer", "cgnat", "infrastructure"}:
        role_map = {
            "external": ("EXTERNAL",),
            "customer": ("CUSTOMER",),
            "cgnat": ("CGNAT_PUBLIC",),
            "infrastructure": ("INFRASTRUCTURE", "MANAGEMENT"),
        }
        roles = role_map[context]
        filters.append(f"src_role IN ({','.join('?' for _ in roles)})")
        values.extend(roles)

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

    def resolve(ip: str) -> dict[str, Any]:
        ip_text = clean_text(ip)
        if ip_text not in geo_cache:
            geo_cache[ip_text] = geo(ip_text) if ip_text else {"country_code": "", "latitude": None, "longitude": None}
        return geo_cache[ip_text]

    # Coverage counters.
    total_events = len(rows)
    located_events = 0
    inbound_source_located = 0
    outbound_destination_located = 0
    critical_total = 0
    critical_before = 0
    critical_after = 0
    confirmed_total = 0
    confirmed_before = 0
    confirmed_after = 0
    reason_counter: Counter[str] = Counter()

    groups: dict[tuple[str, str], dict[str, Any]] = {}

    for raw in rows:
        event = security_event_row(raw)
        severity_value = clean_text(event.get("severity")).upper()
        verdict_value = clean_text(event.get("verdict")).upper()
        is_critical = severity_value == "CRITICAL"
        is_confirmed = verdict_value == "CONFIRMED_ATTACK"
        src_ip = clean_text(event.get("src_ip"))

        # "Before" = legacy source-only geolocation (what V2 used).
        src_geo = resolve(src_ip)
        before_located = bool(clean_text(src_geo.get("country_code")))
        if is_critical:
            critical_total += 1
            if before_located:
                critical_before += 1
        if is_confirmed:
            confirmed_total += 1
            if before_located:
                confirmed_before += 1

        subj = resolve_security_map_geo_subject(event)
        geo_subject = subj["geo_subject"]
        geo_reason = subj["geo_reason"]
        geo_ip = subj["geo_ip"]

        lat = None
        lon = None
        country_code = ""
        country_name = ""
        city = ""
        asn = 0
        as_name = ""
        geo_source = ""
        accuracy_radius = None

        if geo_subject in ("source", "destination") and geo_ip:
            geo_item = resolve(geo_ip)
            lat = geo_item.get("latitude")
            lon = geo_item.get("longitude")
            country_code = clean_text(geo_item.get("country_code")).upper()
            country_name = clean_text(geo_item.get("country_name"))
            city = clean_text(geo_item.get("city"))
            asn = safe_int(geo_item.get("asn"))
            as_name = clean_text(geo_item.get("as_name"))
            geo_source = clean_text(geo_item.get("source")).upper()
            accuracy_radius = geo_item.get("accuracy_radius")
            if not country_code and not (lat is not None and lon is not None):
                # Public IP present but unresolved by ASN/GeoIP.
                reason_counter["UNLOCATED_PUBLIC"] += 1
            elif lat is not None and lon is not None:
                located_events += 1
                reason_counter[geo_reason] += 1
                if geo_subject == "source":
                    inbound_source_located += 1
                else:
                    outbound_destination_located += 1
                if is_critical:
                    critical_after += 1
                if is_confirmed:
                    confirmed_after += 1
            else:
                reason_counter["UNLOCATED_PUBLIC"] += 1
        else:
            reason_counter[geo_reason] += 1

        if lat is None or lon is None:
            campaign_id = clean_text(event.get("campaign_id"))
            risk = campaign_risk.get(campaign_id, 0)
            # Non-located events still contribute to the semantic breakdown but
            # never create a map point.
            continue

        campaign_id = clean_text(event.get("campaign_id"))
        risk = campaign_risk.get(campaign_id, 0)

        if group_by == "country":
            key = country_code or "__unresolved__"
            label = country_name or country_code or "N/D"
        elif group_by == "city":
            key = f"{city}|{country_code}" if city else country_code
            label = city or country_code
        elif group_by == "asn":
            key = str(asn) if asn else "__unresolved__"
            label = as_name or (f"AS{asn}" if asn else "N/D")
        else:  # campaign
            key = campaign_id or "__no_campaign__"
            label = campaign_id or "Sem campanha"

        bucket = groups.setdefault((group_by, key), {
            "key": key,
            "group_by": group_by,
            "label": label,
            "country_code": country_code if group_by != "asn" else "",
            "country": country_name if group_by != "asn" else "",
            "city": city if group_by == "city" else "",
            "asn": asn,
            "lat": lat,
            "lon": lon,
            "event_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "warning_count": 0,
            "confirmed_count": 0,
            "likely_count": 0,
            "analyzed_count": 0,
            "not_analyzed_count": 0,
            "max_severity": "",
            "max_threat_score": 0,
            "max_campaign_risk_score": 0,
            "unique_sources": set(),
            "campaign_ids": set(),
            "latest_seen": "",
            "first_seen": "",
            "attack_types": Counter(),
            "directions": Counter(),
            "geo_subjects": Counter(),
            "geo_sources": Counter(),
            "campaign_events": Counter(),
            "tiers": [],
            "ambiguous_geo": False,
        })
        if (bucket["lat"] is None or bucket["lon"] is None) and lat is not None and lon is not None:
            bucket["lat"], bucket["lon"] = lat, lon
        elif bucket["lat"] is not None and lat is not None and (bucket["lat"], bucket["lon"]) != (lat, lon) and group_by == "campaign":
            # A campaign spanning multiple regions must not be pinned arbitrarily.
            bucket["ambiguous_geo"] = True

        bucket["event_count"] += 1
        if severity_value == "CRITICAL":
            bucket["critical_count"] += 1
        elif severity_value == "HIGH":
            bucket["high_count"] += 1
        elif severity_value == "MEDIUM" or verdict_value == "WARNING":
            bucket["warning_count"] += 1
        if verdict_value == "CONFIRMED_ATTACK":
            bucket["confirmed_count"] += 1
        elif verdict_value == "LIKELY_ATTACK":
            bucket["likely_count"] += 1
        ai_status_value = clean_text(event.get("ai_analysis_status")).lower()
        if ai_status_value == "analyzed":
            bucket["analyzed_count"] += 1
        else:
            bucket["not_analyzed_count"] += 1
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
            bucket["campaign_events"][campaign_id] += 1
        bucket["latest_seen"] = max(bucket["latest_seen"], clean_text(event.get("last_seen")))
        bucket["first_seen"] = min(bucket["first_seen"], clean_text(event.get("first_seen"))) if bucket["first_seen"] else clean_text(event.get("first_seen"))
        bucket["attack_types"][clean_text(event.get("attack_type")).upper() or "OTHER"] += 1
        direction_value = clean_text(event.get("direction")).upper() or "UNKNOWN"
        bucket["directions"][direction_value] += 1
        bucket["geo_subjects"][geo_subject] += 1
        if geo_source:
            bucket["geo_sources"][geo_source] += 1
        bucket["tiers"].append(security_severity_tier(verdict_value, severity_value, event.get("status")))

    points = []
    for (_g, _k), bucket in groups.items():
        if bucket["lat"] is None or bucket["lon"] is None:
            continue
        # A campaign whose events span multiple regions cannot be represented by
        # a single honest marker: keep it out of the map (ranking still shows it).
        if bucket["ambiguous_geo"]:
            continue
        tier = max_tier(bucket["tiers"])
        top_attack_types = [t for t, _c in bucket["attack_types"].most_common(4)]
        top_campaign = bucket["campaign_events"].most_common(1)[0][0] if bucket["campaign_events"] else ""
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
            "critical_count": bucket["critical_count"],
            "high_count": bucket["high_count"],
            "warning_count": bucket["warning_count"],
            "confirmed_count": bucket["confirmed_count"],
            "likely_count": bucket["likely_count"],
            "analyzed_count": bucket["analyzed_count"],
            "not_analyzed_count": bucket["not_analyzed_count"],
            "max_severity": bucket["max_severity"],
            "max_threat_score": bucket["max_threat_score"],
            "max_campaign_risk_score": bucket["max_campaign_risk_score"],
            "unique_sources": len(bucket["unique_sources"]),
            "campaign_count": len(bucket["campaign_ids"]),
            "top_campaign": top_campaign,
            "latest_seen": bucket["latest_seen"],
            "first_seen": bucket["first_seen"],
            "top_attack_types": top_attack_types,
            "predominant_direction": bucket["directions"].most_common(1)[0][0] if bucket["directions"] else "",
            "predominant_geo_subject": bucket["geo_subjects"].most_common(1)[0][0] if bucket["geo_subjects"] else "",
            "geo_source": bucket["geo_sources"].most_common(1)[0][0] if bucket["geo_sources"] else "",
        })

    points.sort(key=lambda p: (tier_priority(p["tier"]), p["event_count"]), reverse=True)
    points = points[:limit]

    ranking = [
        {
            "key": p["key"],
            "label": p["label"],
            "event_count": p["event_count"],
            "critical_count": p["critical_count"],
            "confirmed_count": p["confirmed_count"],
            "max_threat_score": p["max_threat_score"],
            "max_campaign_risk_score": p["max_campaign_risk_score"],
            "tier": p["tier"],
        }
        for p in points[:50]
    ]

    excluded_semantically = sum(reason_counter.get(r, 0) for r in _EXCLUDED_REASONS)
    missing_geo = sum(reason_counter.get(r, 0) for r in _MISSING_GEO_REASONS)
    unlocated_public = reason_counter.get("UNLOCATED_PUBLIC", 0)
    unlocated_breakdown = {r: c for r, c in reason_counter.items() if r not in _LOCATED_REASONS}

    return {
        "summary": {
            "total_events": total_events,
            "points": len(points),
            "located_events": located_events,
            "located_percent": round(100 * located_events / total_events, 1) if total_events else 0.0,
            "inbound_source_located": inbound_source_located,
            "outbound_destination_located": outbound_destination_located,
            "unlocated_public": unlocated_public,
            "private_or_internal": reason_counter.get("INTERNAL_NO_PUBLIC_GEO", 0) + reason_counter.get("PRIVATE_SOURCE", 0),
            "cgnat_or_shared": reason_counter.get("CGNAT_SOURCE_NOT_GEO_SUBJECT", 0),
            "missing_geo": missing_geo,
            "ambiguous_context": reason_counter.get("AMBIGUOUS_CONTEXT", 0),
            "excluded_semantically": excluded_semantically,
            "critical": sum(1 for p in points if p["tier"] == "critical"),
            "elevated": sum(1 for p in points if p["tier"] == "elevated"),
            "suspicious": sum(1 for p in points if p["tier"] == "suspicious"),
            "critical_total": critical_total,
            "critical_before": critical_before,
            "critical_after": critical_after,
            "confirmed_total": confirmed_total,
            "confirmed_before": confirmed_before,
            "confirmed_after": confirmed_after,
            "unlocated_breakdown": unlocated_breakdown,
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
            "direction": direction,
            "context": context,
            "group_by": group_by,
            "limit": limit,
        },
    }
