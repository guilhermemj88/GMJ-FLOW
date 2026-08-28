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

from app.services.security_events import ensure_security_event_schema, resolve_event_target, security_event_row
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

# OUTBOUND multi-target events fall back to their persisted top destinations.
_OUTBOUND_NO_TARGET_REASONS = {"MISSING_PUBLIC_GEO", "CGNAT_SOURCE_NOT_GEO_SUBJECT"}

# How many real destinations of a multi-target OUTBOUND event to represent.
MULTI_TARGET_TOP_N = 3


def multi_target_destinations(event: Mapping[str, Any], top_n: int = MULTI_TARGET_TOP_N) -> list[dict[str, Any]]:
    """Extract the top-N real, public destinations of a multi-target event.

    `investigation.top_destinations` is already ranked by packet volume. Only
    public IPs are kept; private/CGNAT/test addresses are skipped. The result
    is bounded and never fabricates a destination.
    """
    investigation = event.get("investigation")
    if not isinstance(investigation, Mapping):
        return []
    tops = investigation.get("top_destinations") or []
    if not isinstance(tops, list):
        return []
    result: list[dict[str, Any]] = []
    for item in tops:
        if len(result) >= max(0, int(top_n)):
            break
        if not isinstance(item, Mapping):
            continue
        dst_ip = clean_text(item.get("destination_ip"))
        if ip_kind(dst_ip) != "public":
            continue
        result.append({
            "dst_ip": dst_ip,
            "share": float(item.get("share") or 0.0),
            "packets": safe_int(item.get("packets")),
            "flows": safe_int(item.get("flows")),
        })
    return result


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
    target_scope: str = "all",
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
    multi_target_events = 0
    multi_target_destinations_considered = 0
    multi_target_destinations_located = 0
    multi_target_events_with_geo = 0
    reason_counter: Counter[str] = Counter()

    groups: dict[tuple[str, str], dict[str, Any]] = {}

    for raw in rows:
        event = security_event_row(raw)
        severity_value = clean_text(event.get("severity")).upper()
        verdict_value = clean_text(event.get("verdict")).upper()
        is_critical = severity_value == "CRITICAL"
        is_confirmed = verdict_value == "CONFIRMED_ATTACK"
        src_ip = clean_text(event.get("src_ip"))

        # target_scope filter (all/single/prefix/multi).
        if target_scope != "all":
            investigation = event.get("investigation")
            event_scope = clean_text(investigation.get("target_scope")) if isinstance(investigation, Mapping) else ""
            if not event_scope:
                event_scope = resolve_event_target(
                    event.get("target_ip"),
                    event.get("target_prefix"),
                    event.get("direction"),
                    {"unique_destinations": event.get("unique_destinations")},
                )["target_scope"]
            if event_scope != target_scope:
                continue

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

        campaign_id = clean_text(event.get("campaign_id"))
        risk = campaign_risk.get(campaign_id, 0)
        event_id = event.get("event_id") or event.get("id")
        total_destinations = safe_int(event.get("unique_destinations"))

        # Build the list of geographic targets this event contributes.
        targets: list[dict[str, Any]] = []
        if geo_subject in ("source", "destination") and geo_ip:
            targets.append({
                "subject": geo_subject, "ip": geo_ip, "rank": 0, "share": 0.0,
                "packets": 0, "flows": 0, "total_destinations": 1,
            })
        elif geo_subject == "none" and geo_reason in _OUTBOUND_NO_TARGET_REASONS:
            destinations = multi_target_destinations(event)
            if destinations:
                multi_target_events += 1
                multi_target_destinations_considered += len(destinations)
                for rank, destination in enumerate(destinations, 1):
                    targets.append({
                        "subject": "multiple_destinations",
                        "ip": destination["dst_ip"],
                        "rank": rank,
                        "share": destination["share"],
                        "packets": destination["packets"],
                        "flows": destination["flows"],
                        "total_destinations": total_destinations or len(destinations),
                    })

        if not targets:
            reason_counter[geo_reason] += 1
            continue

        # Geolocate each target and group located targets by bucket key.
        located_by_bucket: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for target in targets:
            geo_item = resolve(target["ip"])
            lat = geo_item.get("latitude")
            lon = geo_item.get("longitude")
            if lat is None or lon is None:
                continue
            country_code = clean_text(geo_item.get("country_code")).upper()
            country_name = clean_text(geo_item.get("country_name"))
            city = clean_text(geo_item.get("city"))
            asn = safe_int(geo_item.get("asn"))
            as_name = clean_text(geo_item.get("as_name"))
            geo_source = clean_text(geo_item.get("source")).upper()

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

            located_by_bucket.setdefault((group_by, key), []).append({
                "lat": lat, "lon": lon, "country_code": country_code, "country_name": country_name,
                "city": city, "asn": asn, "as_name": as_name, "geo_source": geo_source,
                "label": label, "subject": target["subject"],
            })

        event_located = bool(located_by_bucket)
        if not event_located:
            if geo_subject in ("source", "destination"):
                reason_counter["UNLOCATED_PUBLIC"] += 1
            else:
                reason_counter["OUTBOUND_MULTI_DESTINATION"] += 1
            continue

        # Event-level coverage accounting (once per event, not per target).
        if geo_subject in ("source", "destination"):
            located_events += 1
            reason_counter[geo_reason] += 1
            if geo_subject == "source":
                inbound_source_located += 1
            else:
                outbound_destination_located += 1
        else:
            reason_counter["OUTBOUND_MULTI_DESTINATION"] += 1
            located_events += 1
            multi_target_events_with_geo += 1
        if is_critical:
            critical_after += 1
        if is_confirmed:
            confirmed_after += 1
        multi_target_destinations_located += sum(
            1 for target in targets if target["subject"] == "multiple_destinations"
        )

        for (g, k), located in located_by_bucket.items():
            first = located[0]
            bucket = groups.setdefault((g, k), {
                "key": k,
                "group_by": g,
                "label": first["label"],
                "country_code": first["country_code"] if g != "asn" else "",
                "country": first["country_name"] if g != "asn" else "",
                "city": first["city"] if g == "city" else "",
                "asn": first["asn"],
                "lat": first["lat"],
                "lon": first["lon"],
                "event_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "warning_count": 0,
                "confirmed_count": 0,
                "likely_count": 0,
                "analyzed_count": 0,
                "not_analyzed_count": 0,
                "destination_count": 0,
                "multi_target_events": 0,
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
            # A campaign whose located targets span multiple regions must not be
            # pinned to a single arbitrary coordinate.
            if g == "campaign":
                coords = {(item["lat"], item["lon"]) for item in located}
                coords.add((bucket["lat"], bucket["lon"]))
                if len(coords) > 1:
                    bucket["ambiguous_geo"] = True

            bucket["event_count"] += 1
            bucket["destination_count"] += len(located)
            if first["subject"] == "multiple_destinations":
                bucket["multi_target_events"] += 1
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
            bucket["geo_subjects"][first["subject"]] += 1
            if first["geo_source"]:
                bucket["geo_sources"][first["geo_source"]] += 1
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
            "destination_count": bucket["destination_count"],
            "multi_target_events": bucket["multi_target_events"],
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
            "multi_target_events": multi_target_events,
            "multi_target_destinations_considered": multi_target_destinations_considered,
            "multi_target_destinations_located": multi_target_destinations_located,
            "multi_target_events_with_geo": multi_target_events_with_geo,
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
            "target_scope": target_scope,
            "group_by": group_by,
            "limit": limit,
        },
    }
