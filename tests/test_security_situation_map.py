"""Tests for the Security Situation Map V2.1 (direction-aware geolocation).

Covers the geo-subject owner, direction-aware rules, coverage breakdown,
filters, deterministic color, aggregate priority, ranking and the
"no AI / no external provider for rendering" contract.
"""

from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from app.services.security_events import ensure_security_event_schema
from app.services.security_situation_map import (
    build_security_map,
    first_prefix_ip,
    ip_kind,
    max_tier,
    resolve_security_map_geo_subject,
    security_severity_tier,
    tier_color,
    tier_priority,
)


def now_iso(**delta_kwargs) -> str:
    dt = datetime.now(timezone.utc) + timedelta(**delta_kwargs)
    return dt.isoformat().replace("+00:00", "Z")


# geo_lookup stub simulating the offline GeoIP owner (V2.2): US via MaxMind City,
# BG via ASN+centroid, BR internal (customer), NL external destination,
# 186.232.x.x (customer CGNAT, BR).
GEO = {
    "8.8.8.8": {"country_code": "US", "country_name": "United States", "city": "Mountain View", "latitude": 37.42, "longitude": -122.08, "asn": 15169, "as_name": "GOOGLE", "source": "MAXMIND_CITY", "accuracy_radius": 50},
    "79.124.62.126": {"country_code": "BG", "country_name": "Bulgaria", "city": "", "latitude": 42.7, "longitude": 25.5, "asn": 207812, "as_name": "DM AUTO", "source": "COUNTRY_CENTROID"},
    "186.232.160.10": {"country_code": "BR", "country_name": "Brazil", "city": "", "latitude": -14.2, "longitude": -51.9, "asn": 53194, "as_name": "VIP", "source": "COUNTRY_CENTROID"},
    "186.232.168.250": {"country_code": "BR", "country_name": "Brazil", "city": "", "latitude": -14.2, "longitude": -51.9, "asn": 53194, "as_name": "VIP", "source": "COUNTRY_CENTROID"},
    "45.133.39.1": {"country_code": "NL", "country_name": "Netherlands", "city": "Amsterdam", "latitude": 52.37, "longitude": 4.89, "asn": 9009, "as_name": "M247", "source": "MAXMIND_CITY", "accuracy_radius": 100},
}


def geo_stub(ip: str) -> dict:
    return GEO.get(ip, {"country_code": "", "country_name": "N/D", "city": "", "latitude": None, "longitude": None, "asn": 0, "as_name": "", "source": "NONE"})


def make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    ensure_security_event_schema(conn)
    return conn


def insert_event(conn: sqlite3.Connection, **overrides) -> None:
    count = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    base = {
        "event_key": f"evt-{count + 1}",
        "detector": "test_detector",
        "attack_type": "SYN_FLOOD",
        "severity": "HIGH",
        "verdict": "LIKELY_ATTACK",
        "direction": "INBOUND",
        "src_role": "EXTERNAL",
        "dst_role": "CUSTOMER",
        "src_ip": "8.8.8.8",
        "target_ip": "",
        "target_prefix": "",
        "first_seen": now_iso(minutes=-30),
        "last_seen": now_iso(minutes=-5),
        "created_at": now_iso(minutes=-30),
        "updated_at": now_iso(minutes=-5),
        "detector_score": 70,
        "status": "active",
    }
    base.update(overrides)
    columns = ",".join(base.keys())
    placeholders = ",".join("?" for _ in base)
    conn.execute(f"INSERT INTO security_events ({columns}) VALUES ({placeholders})", list(base.values()))
    conn.commit()


class GeoSecurityTierTest(unittest.TestCase):
    def test_tier_confirmed_or_critical_is_critical(self):
        self.assertEqual(security_severity_tier("CONFIRMED_ATTACK", "INFO"), "critical")
        self.assertEqual(security_severity_tier("INFO", "CRITICAL"), "critical")

    def test_tier_likely_or_high_is_elevated(self):
        self.assertEqual(security_severity_tier("LIKELY_ATTACK", "LOW"), "elevated")
        self.assertEqual(security_severity_tier("INFO", "HIGH"), "elevated")

    def test_tier_warning_or_medium_is_suspicious(self):
        self.assertEqual(security_severity_tier("WARNING", "LOW"), "suspicious")
        self.assertEqual(security_severity_tier("INFO", "MEDIUM"), "suspicious")

    def test_tier_benign_status_wins(self):
        self.assertEqual(security_severity_tier("CONFIRMED_ATTACK", "CRITICAL", "benign"), "benign")

    def test_tier_priority_ordering(self):
        self.assertGreater(tier_priority("critical"), tier_priority("elevated"))
        self.assertGreater(tier_priority("elevated"), tier_priority("suspicious"))
        self.assertGreater(tier_priority("suspicious"), tier_priority("info"))

    def test_max_tier_picks_highest(self):
        self.assertEqual(max_tier(["info", "elevated", "critical"]), "critical")

    def test_tier_color_deterministic(self):
        self.assertEqual(tier_color("critical"), "#ef4444")
        self.assertEqual(tier_color("elevated"), "#f97316")
        self.assertEqual(tier_color("suspicious"), "#facc15")
        self.assertEqual(tier_color("info"), "#818cf8")
        self.assertEqual(tier_color("benign"), "#64748b")


class GeoSubjectTest(unittest.TestCase):
    def test_inbound_external_is_source(self):
        subj = resolve_security_map_geo_subject({
            "direction": "INBOUND", "src_role": "EXTERNAL", "dst_role": "CUSTOMER",
            "src_ip": "8.8.8.8", "target_ip": "", "target_prefix": "",
        })
        self.assertEqual(subj["geo_subject"], "source")
        self.assertEqual(subj["geo_ip"], "8.8.8.8")
        self.assertEqual(subj["geo_reason"], "INBOUND_EXTERNAL_SOURCE")

    def test_outbound_customer_is_destination(self):
        subj = resolve_security_map_geo_subject({
            "direction": "OUTBOUND", "src_role": "CUSTOMER", "dst_role": "EXTERNAL",
            "src_ip": "186.232.160.10", "target_ip": "45.133.39.1", "target_prefix": "",
        })
        self.assertEqual(subj["geo_subject"], "destination")
        self.assertEqual(subj["geo_ip"], "45.133.39.1")
        self.assertEqual(subj["geo_reason"], "OUTBOUND_EXTERNAL_DESTINATION")

    def test_outbound_customer_uses_target_prefix(self):
        subj = resolve_security_map_geo_subject({
            "direction": "OUTBOUND", "src_role": "CUSTOMER", "dst_role": "EXTERNAL",
            "src_ip": "186.232.160.10", "target_ip": "", "target_prefix": "45.133.39.0/24",
        })
        self.assertEqual(subj["geo_subject"], "destination")
        self.assertEqual(subj["geo_ip"], "45.133.39.1")

    def test_outbound_cgnat_is_destination_not_source(self):
        subj = resolve_security_map_geo_subject({
            "direction": "OUTBOUND", "src_role": "CGNAT_PUBLIC", "dst_role": "EXTERNAL",
            "src_ip": "186.232.168.250", "target_ip": "", "target_prefix": "",
            "cgnat_context": "source_cgnat_public",
        })
        self.assertEqual(subj["geo_subject"], "none")
        self.assertEqual(subj["geo_reason"], "CGNAT_SOURCE_NOT_GEO_SUBJECT")

    def test_internal_is_none(self):
        subj = resolve_security_map_geo_subject({
            "direction": "INTERNAL", "src_role": "CUSTOMER", "dst_role": "CUSTOMER",
            "src_ip": "10.0.0.1", "target_ip": "", "target_prefix": "",
        })
        self.assertEqual(subj["geo_subject"], "none")
        self.assertEqual(subj["geo_reason"], "INTERNAL_NO_PUBLIC_GEO")

    def test_rfc1918_is_none(self):
        subj = resolve_security_map_geo_subject({
            "direction": "INBOUND", "src_role": "EXTERNAL", "dst_role": "CUSTOMER",
            "src_ip": "192.168.1.5", "target_ip": "", "target_prefix": "",
        })
        self.assertEqual(subj["geo_subject"], "none")
        self.assertEqual(subj["geo_reason"], "PRIVATE_SOURCE")

    def test_ambiguous_context_is_none(self):
        subj = resolve_security_map_geo_subject({
            "direction": "EXTERNAL", "src_role": "EXTERNAL", "dst_role": "EXTERNAL",
            "src_ip": "8.8.8.8", "target_ip": "", "target_prefix": "",
        })
        self.assertEqual(subj["geo_subject"], "none")
        self.assertEqual(subj["geo_reason"], "AMBIGUOUS_CONTEXT")

    def test_ip_kind(self):
        self.assertEqual(ip_kind("192.168.1.1"), "private")
        self.assertEqual(ip_kind("10.1.2.3"), "private")
        self.assertEqual(ip_kind("100.64.0.1"), "cgnat_10064")
        self.assertEqual(ip_kind("2001:db8::1"), "private")
        self.assertEqual(ip_kind("8.8.8.8"), "public")
        self.assertEqual(ip_kind("not-an-ip"), "invalid")

    def test_first_prefix_ip(self):
        self.assertEqual(first_prefix_ip("45.133.39.0/24"), "45.133.39.1")


class SecuritySituationMapTest(unittest.TestCase):
    def test_inbound_source_geolocated(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8", severity="CRITICAL", verdict="CONFIRMED_ATTACK")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["located_events"], 1)
        self.assertEqual(result["summary"]["inbound_source_located"], 1)
        point = result["points"][0]
        self.assertEqual(point["country_code"], "US")
        self.assertEqual(point["tier"], "critical")
        self.assertEqual(point["critical_count"], 1)
        self.assertEqual(point["confirmed_count"], 1)
        self.assertEqual(point["predominant_geo_subject"], "source")
        self.assertEqual(point["predominant_direction"], "INBOUND")

    def test_outbound_destination_geolocated_not_source(self):
        conn = make_db()
        # source é o customer BR interno; destination é NL externo.
        insert_event(conn, event_key="a", direction="OUTBOUND", src_role="CUSTOMER", dst_role="EXTERNAL",
                     src_ip="186.232.160.10", target_prefix="45.133.39.0/24", severity="CRITICAL", verdict="CONFIRMED_ATTACK")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["outbound_destination_located"], 1)
        point = result["points"][0]
        self.assertEqual(point["country_code"], "NL")
        self.assertEqual(point["predominant_geo_subject"], "destination")
        self.assertEqual(point["predominant_direction"], "OUTBOUND")

    def test_cgnat_source_excluded(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="OUTBOUND", src_role="CGNAT_PUBLIC", dst_role="EXTERNAL",
                     src_ip="186.232.168.250", cgnat_context="source_cgnat_public", severity="HIGH")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["located_events"], 0)
        self.assertEqual(result["summary"]["cgnat_or_shared"], 1)

    def test_internal_excluded(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INTERNAL", src_role="CUSTOMER", dst_role="CUSTOMER", src_ip="10.0.0.1")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["located_events"], 0)
        self.assertEqual(result["summary"]["private_or_internal"], 1)

    def test_country_centroid_fallback(self):
        conn = make_db()
        # O owner (stub) já entrega BG com centroid aplicado.
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER",
                     src_ip="79.124.62.126", severity="HIGH", verdict="LIKELY_ATTACK")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        point = result["points"][0]
        self.assertEqual(point["country_code"], "BG")
        self.assertEqual(point["lat"], 42.7)
        self.assertEqual(point["lon"], 25.5)
        self.assertEqual(point["tier"], "elevated")
        self.assertEqual(point["geo_source"], "COUNTRY_CENTROID")

    def test_public_without_geo_is_unlocated_public(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="203.0.113.99")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["located_events"], 0)
        self.assertEqual(result["summary"]["unlocated_public"], 1)

    def test_direction_filter(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8")
        insert_event(conn, event_key="b", direction="OUTBOUND", src_role="CUSTOMER", dst_role="EXTERNAL",
                     src_ip="186.232.160.10", target_prefix="45.133.39.0/24")
        result = build_security_map(conn, period="24h", direction="inbound", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["total_events"], 1)
        self.assertEqual(result["points"][0]["country_code"], "US")

    def test_context_filter(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8")
        insert_event(conn, event_key="b", direction="OUTBOUND", src_role="CUSTOMER", dst_role="EXTERNAL",
                     src_ip="186.232.160.10", target_prefix="45.133.39.0/24")
        result = build_security_map(conn, period="24h", context="external", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["total_events"], 1)
        self.assertEqual(result["points"][0]["country_code"], "US")

    def test_summary_breakdown(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8")
        insert_event(conn, event_key="b", direction="INTERNAL", src_role="CUSTOMER", dst_role="CUSTOMER", src_ip="10.0.0.1")
        insert_event(conn, event_key="c", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="203.0.113.99")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        summary = result["summary"]
        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["located_events"], 1)
        self.assertEqual(summary["private_or_internal"], 1)
        self.assertEqual(summary["unlocated_public"], 1)
        self.assertIn("INTERNAL_NO_PUBLIC_GEO", summary["unlocated_breakdown"])
        self.assertIn("UNLOCATED_PUBLIC", summary["unlocated_breakdown"])

    def test_max_priority_aggregate(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8", severity="LOW", verdict="INFO", detector_score=10)
        insert_event(conn, event_key="b", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8", severity="CRITICAL", verdict="CONFIRMED_ATTACK", detector_score=90)
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        point = result["points"][0]
        self.assertEqual(point["event_count"], 2)
        self.assertEqual(point["max_severity"], "CRITICAL")
        self.assertEqual(point["critical_count"], 1)
        self.assertGreater(point["max_threat_score"], 0)
        self.assertEqual(point["tier"], "critical")

    def test_ranking_critical_count_and_scores(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8", severity="CRITICAL", verdict="CONFIRMED_ATTACK")
        insert_event(conn, event_key="b", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="79.124.62.126", severity="HIGH")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        top = result["ranking"][0]
        self.assertEqual(top["tier"], "critical")
        self.assertIn("critical_count", top)
        self.assertIn("max_threat_score", top)
        self.assertIn("max_campaign_risk_score", top)

    def test_critical_and_confirmed_coverage(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8", severity="CRITICAL", verdict="CONFIRMED_ATTACK")
        insert_event(conn, event_key="b", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="203.0.113.99", severity="CRITICAL", verdict="CONFIRMED_ATTACK")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        summary = result["summary"]
        self.assertEqual(summary["critical_total"], 2)
        self.assertEqual(summary["critical_after"], 1)
        self.assertEqual(summary["confirmed_total"], 2)
        self.assertEqual(summary["confirmed_after"], 1)
        self.assertEqual(summary["critical_before"], 1)

    def test_bounded_point_count(self):
        conn = make_db()
        for i in range(5):
            insert_event(conn, event_key=f"a{i}", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER",
                         src_ip=f"8.8.8.{i + 1}", severity="CRITICAL")
        result = build_security_map(conn, period="24h", group_by="city", geo_lookup=lambda ip: {
            "country_code": "US", "country_name": "United States", "city": ip.split(".")[-1],
            "latitude": 37.0 + int(ip.split(".")[-1]) / 100, "longitude": -95.7, "asn": 1, "as_name": "X",
        }, limit=3)
        self.assertLessEqual(len(result["points"]), 3)

    def test_group_asn(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8")
        insert_event(conn, event_key="b", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="79.124.62.126")
        result = build_security_map(conn, period="24h", group_by="asn", geo_lookup=geo_stub)
        asns = {p["asn"] for p in result["points"]}
        self.assertEqual(asns, {15169, 207812})

    def test_group_city(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8")
        result = build_security_map(conn, period="24h", group_by="city", geo_lookup=geo_stub)
        self.assertEqual(len(result["points"]), 1)

    def test_group_campaign(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8", campaign_id="cmp1")
        insert_event(conn, event_key="b", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="79.124.62.126", campaign_id="cmp1")
        result = build_security_map(conn, period="24h", group_by="campaign", geo_lookup=geo_stub)
        # cmp1 spans US and BG -> ambiguous geo -> no marker, but ranking keeps it.
        self.assertEqual(result["summary"]["points"], 0)
        self.assertEqual(result["summary"]["located_events"], 2)

    def test_no_ai_or_external_provider_for_rendering(self):
        conn = make_db()
        insert_event(conn, event_key="a", direction="INBOUND", src_role="EXTERNAL", dst_role="CUSTOMER", src_ip="8.8.8.8")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        self.assertTrue(all("analysis" not in p for p in result["points"]))


if __name__ == "__main__":
    unittest.main()
