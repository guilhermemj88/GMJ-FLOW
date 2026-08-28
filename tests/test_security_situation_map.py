"""Tests for the Security Situation Map aggregation (Threat Intelligence Map V2).

Covers the deterministic tier/color mapping, filters, grouping, aggregation
priority, unlocated handling, ranking and the "no AI for rendering" contract.
"""

from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from app.services.security_events import ensure_security_event_schema
from app.services.security_situation_map import (
    build_security_map,
    max_tier,
    security_severity_tier,
    tier_color,
    tier_priority,
)


def now_iso(**delta_kwargs) -> str:
    dt = datetime.now(timezone.utc) + timedelta(**delta_kwargs)
    return dt.isoformat().replace("+00:00", "Z")


GEO = {
    "8.8.8.8": {"country_code": "US", "country_name": "United States", "city": "Mountain View", "latitude": 37.42, "longitude": -122.08, "asn": 15169, "as_name": "GOOGLE"},
    "9.9.9.9": {"country_code": "US", "country_name": "United States", "city": "Berkeley", "latitude": 37.87, "longitude": -122.27, "asn": 19281, "as_name": "QUAD9"},
    "177.128.0.1": {"country_code": "BR", "country_name": "Brazil", "city": "Sao Paulo", "latitude": -23.55, "longitude": -46.63, "asn": 28573, "as_name": "Claro"},
    "203.0.113.7": {"country_code": "AU", "country_name": "Australia", "city": "Sydney", "latitude": -33.87, "longitude": 151.21, "asn": 64500, "as_name": "TEST-NET"},
    "192.0.2.9": {"country_code": "", "country_name": "", "city": "", "latitude": None, "longitude": None, "asn": 0, "as_name": ""},
}


def geo_stub(ip: str) -> dict:
    return GEO.get(ip, {"country_code": "", "country_name": "", "city": "", "latitude": None, "longitude": None, "asn": 0, "as_name": ""})


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
        "src_ip": "8.8.8.8",
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


class SecurityTierTest(unittest.TestCase):
    def test_tier_confirmed_or_critical_is_critical(self):
        self.assertEqual(security_severity_tier("CONFIRMED_ATTACK", "INFO"), "critical")
        self.assertEqual(security_severity_tier("INFO", "CRITICAL"), "critical")

    def test_tier_likely_or_high_is_elevated(self):
        self.assertEqual(security_severity_tier("LIKELY_ATTACK", "LOW"), "elevated")
        self.assertEqual(security_severity_tier("INFO", "HIGH"), "elevated")

    def test_tier_warning_or_medium_is_suspicious(self):
        self.assertEqual(security_severity_tier("WARNING", "LOW"), "suspicious")
        self.assertEqual(security_severity_tier("INFO", "MEDIUM"), "suspicious")

    def test_tier_low_or_unknown_is_info(self):
        self.assertEqual(security_severity_tier("INFO", "LOW"), "info")
        self.assertEqual(security_severity_tier("INFO", "INFO"), "info")

    def test_tier_benign_status_wins_over_verdict(self):
        self.assertEqual(security_severity_tier("CONFIRMED_ATTACK", "CRITICAL", "benign"), "benign")
        self.assertEqual(security_severity_tier("CONFIRMED_ATTACK", "CRITICAL", "resolved"), "benign")

    def test_tier_priority_ordering(self):
        self.assertGreater(tier_priority("critical"), tier_priority("elevated"))
        self.assertGreater(tier_priority("elevated"), tier_priority("suspicious"))
        self.assertGreater(tier_priority("suspicious"), tier_priority("info"))
        self.assertGreater(tier_priority("info"), tier_priority("benign"))

    def test_max_tier_picks_highest_priority(self):
        self.assertEqual(max_tier(["info", "elevated", "critical", "benign"]), "critical")

    def test_tier_color_deterministic(self):
        self.assertEqual(tier_color("critical"), "#ef4444")
        self.assertEqual(tier_color("elevated"), "#f97316")
        self.assertEqual(tier_color("suspicious"), "#facc15")
        self.assertEqual(tier_color("info"), "#818cf8")
        self.assertEqual(tier_color("benign"), "#64748b")


class SecuritySituationMapTest(unittest.TestCase):
    def test_group_country_merges_same_country(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8", verdict="CONFIRMED_ATTACK", severity="CRITICAL")
        insert_event(conn, event_key="b", src_ip="9.9.9.9", verdict="LIKELY_ATTACK", severity="HIGH")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["points"], 1)
        point = result["points"][0]
        self.assertEqual(point["country_code"], "US")
        self.assertEqual(point["event_count"], 2)
        self.assertEqual(point["confirmed_count"], 1)
        self.assertEqual(point["likely_count"], 1)
        self.assertEqual(point["tier"], "critical")
        self.assertEqual(point["unique_sources"], 2)

    def test_max_severity_and_threat_score_are_max_not_sum(self):
        from app.services.security_events import security_event_row

        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8", severity="LOW", detector_score=10)
        insert_event(conn, event_key="b", src_ip="9.9.9.9", severity="CRITICAL", detector_score=90)
        rows = conn.execute("SELECT * FROM security_events").fetchall()
        expected_score = max((security_event_row(r)["threat_score"] or {}).get("score", 0) for r in rows)
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        point = result["points"][0]
        self.assertEqual(point["max_severity"], "CRITICAL")
        self.assertEqual(point["max_threat_score"], expected_score)

    def test_severity_filter(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8", severity="LOW")
        insert_event(conn, event_key="b", src_ip="177.128.0.1", severity="CRITICAL")
        result = build_security_map(conn, period="24h", severity="CRITICAL", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["total_events"], 1)
        self.assertEqual(result["points"][0]["country_code"], "BR")

    def test_verdict_filter(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8", verdict="CONFIRMED_ATTACK")
        insert_event(conn, event_key="b", src_ip="177.128.0.1", verdict="WARNING")
        result = build_security_map(conn, period="24h", verdict="WARNING", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["total_events"], 1)
        self.assertEqual(result["points"][0]["country_code"], "BR")

    def test_attack_type_filter(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8", attack_type="SYN_FLOOD")
        insert_event(conn, event_key="b", src_ip="177.128.0.1", attack_type="BRUTE_FORCE")
        result = build_security_map(conn, period="24h", attack_type="SYN_FLOOD", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["total_events"], 1)
        self.assertEqual(result["points"][0]["country_code"], "US")

    def test_status_filter(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8", status="active")
        insert_event(conn, event_key="b", src_ip="177.128.0.1", status="benign")
        result = build_security_map(conn, period="24h", status="benign", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["total_events"], 1)
        self.assertEqual(result["points"][0]["tier"], "benign")

    def test_campaign_with_and_without(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8", campaign_id="cmp1")
        insert_event(conn, event_key="b", src_ip="177.128.0.1", campaign_id="")
        with_result = build_security_map(conn, period="24h", campaign="with", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(with_result["summary"]["total_events"], 1)
        without_result = build_security_map(conn, period="24h", campaign="without", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(without_result["summary"]["total_events"], 1)
        self.assertEqual(without_result["points"][0]["country_code"], "BR")

    def test_ai_status_filters(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8", ai_analysis_status="analyzed")
        insert_event(conn, event_key="b", src_ip="177.128.0.1", ai_analysis_status="not_analyzed")
        insert_event(conn, event_key="c", src_ip="203.0.113.7", ai_analysis_status="not_analyzed", campaign_id="cmp1")
        analyzed = build_security_map(conn, period="24h", ai_status="analyzed", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(analyzed["summary"]["total_events"], 1)
        not_analyzed = build_security_map(conn, period="24h", ai_status="not_analyzed", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(not_analyzed["summary"]["total_events"], 2)
        campaign = build_security_map(conn, period="24h", ai_status="campaign", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(campaign["summary"]["total_events"], 1)

    def test_group_asn(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8")
        insert_event(conn, event_key="b", src_ip="9.9.9.9")
        result = build_security_map(conn, period="24h", group_by="asn", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["points"], 2)
        self.assertEqual({p["asn"] for p in result["points"]}, {15169, 19281})

    def test_group_city(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8")
        insert_event(conn, event_key="b", src_ip="9.9.9.9")
        result = build_security_map(conn, period="24h", group_by="city", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["points"], 2)
        self.assertEqual({p["city"] for p in result["points"]}, {"Mountain View", "Berkeley"})

    def test_group_campaign(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8", campaign_id="cmp1")
        insert_event(conn, event_key="b", src_ip="177.128.0.1", campaign_id="cmp1")
        insert_event(conn, event_key="c", src_ip="203.0.113.7", campaign_id="")
        result = build_security_map(conn, period="24h", group_by="campaign", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["points"], 2)
        by_key = {p["key"]: p for p in result["points"]}
        self.assertEqual(by_key["cmp1"]["event_count"], 2)
        self.assertEqual(by_key["cmp1"]["campaign_count"], 1)

    def test_unlocated_events_counted_in_summary(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8")
        insert_event(conn, event_key="b", src_ip="192.0.2.9")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["summary"]["unlocated"], 1)
        self.assertEqual(result["summary"]["total_events"], 2)

    def test_limit_caps_points(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8")
        insert_event(conn, event_key="b", src_ip="177.128.0.1")
        insert_event(conn, event_key="c", src_ip="203.0.113.7")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub, limit=2)
        self.assertEqual(len(result["points"]), 2)
        self.assertEqual(result["filters_applied"]["limit"], 2)

    def test_ranking_sorted_by_tier_then_count(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8", verdict="CONFIRMED_ATTACK", severity="CRITICAL")
        insert_event(conn, event_key="b", src_ip="177.128.0.1", verdict="INFO", severity="LOW")
        insert_event(conn, event_key="c", src_ip="9.9.9.9", verdict="INFO", severity="LOW")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["ranking"][0]["tier"], "critical")
        self.assertEqual(result["ranking"][0]["key"], "US")

    def test_no_ai_calls_for_rendering(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        self.assertTrue(all("analysis" not in p for p in result["points"]))

    def test_filters_applied_echoes_params(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8")
        result = build_security_map(conn, period="1h", severity="HIGH", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(result["filters_applied"]["period"], "1h")
        self.assertEqual(result["filters_applied"]["severity"], "HIGH")
        self.assertEqual(result["filters_applied"]["group_by"], "country")

    def test_top_attack_types_present(self):
        conn = make_db()
        insert_event(conn, event_key="a", src_ip="8.8.8.8", attack_type="SYN_FLOOD")
        insert_event(conn, event_key="b", src_ip="9.9.9.9", attack_type="BRUTE_FORCE")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        point = result["points"][0]
        self.assertEqual(set(point["top_attack_types"]), {"SYN_FLOOD", "BRUTE_FORCE"})


if __name__ == "__main__":
    unittest.main()
