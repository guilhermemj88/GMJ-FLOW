"""Tests for multi-target OUTBOUND geo representation (Threat Intelligence Map V2.4).

Covers top-N destination selection, private-IP exclusion, per-destination GeoIP,
regional aggregation, event-level coloring, coverage metrics and the
target_scope filter.
"""

from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from app.services.security_events import ensure_security_event_schema
from app.services.security_situation_map import (
    build_security_map,
    multi_target_destinations,
)


def now_iso(**delta_kwargs) -> str:
    dt = datetime.now(timezone.utc) + timedelta(**delta_kwargs)
    return dt.isoformat().replace("+00:00", "Z")


GEO = {
    "45.133.39.1": {"country_code": "NL", "country_name": "Netherlands", "city": "", "latitude": 52.37, "longitude": 4.89, "asn": 9009, "as_name": "M247", "source": "COUNTRY_CENTROID"},
    "45.133.39.2": {"country_code": "NL", "country_name": "Netherlands", "city": "", "latitude": 52.37, "longitude": 4.89, "asn": 9009, "as_name": "M247", "source": "COUNTRY_CENTROID"},
    "45.133.39.3": {"country_code": "NL", "country_name": "Netherlands", "city": "", "latitude": 52.37, "longitude": 4.89, "asn": 9009, "as_name": "M247", "source": "COUNTRY_CENTROID"},
    "8.8.8.8": {"country_code": "US", "country_name": "United States", "city": "", "latitude": 37.09, "longitude": -95.71, "asn": 15169, "as_name": "GOOGLE", "source": "COUNTRY_CENTROID"},
    "177.128.0.1": {"country_code": "BR", "country_name": "Brazil", "city": "", "latitude": -14.2, "longitude": -51.9, "asn": 28573, "as_name": "Claro", "source": "COUNTRY_CENTROID"},
}


def geo_stub(ip: str) -> dict:
    return GEO.get(ip, {"country_code": "", "country_name": "N/D", "city": "", "latitude": None, "longitude": None, "asn": 0, "as_name": "", "source": "NONE"})


def make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    ensure_security_event_schema(conn)
    return conn


def insert_outbound_multi(conn, event_key, destinations, severity="HIGH", verdict="LIKELY_ATTACK", **overrides):
    base = {
        "event_key": event_key,
        "detector": "port_scan",
        "attack_type": "PORT_SCAN_HORIZONTAL",
        "severity": severity,
        "verdict": verdict,
        "direction": "OUTBOUND",
        "src_role": "CUSTOMER",
        "dst_role": "EXTERNAL",
        "src_ip": "186.232.160.10",
        "target_ip": "",
        "target_prefix": "",
        "first_seen": now_iso(minutes=-30),
        "last_seen": now_iso(minutes=-5),
        "created_at": now_iso(minutes=-30),
        "updated_at": now_iso(minutes=-5),
        "detector_score": 80,
        "status": "active",
        "unique_destinations": len(destinations),
        "investigation_json": json.dumps({
            "target_scope": "multi",
            "top_destinations": destinations,
        }),
    }
    base.update(overrides)
    columns = ",".join(base.keys())
    placeholders = ",".join("?" for _ in base)
    conn.execute(f"INSERT INTO security_events ({columns}) VALUES ({placeholders})", list(base.values()))
    conn.commit()


def dest(ip, share=50.0, packets=10, flows=5):
    return {"destination_ip": ip, "share": share, "packets": packets, "flows": flows}


class MultiTargetDestinationsTest(unittest.TestCase):
    def test_top_n_respected_and_private_excluded(self):
        event = {"investigation": {"top_destinations": [
            dest("45.133.39.1"), dest("8.8.8.8"), dest("192.168.1.5"), dest("177.128.0.1"), dest("10.0.0.1"),
        ]}}
        result = multi_target_destinations(event, top_n=3)
        self.assertEqual(len(result), 3)
        ips = [item["dst_ip"] for item in result]
        self.assertNotIn("192.168.1.5", ips)
        self.assertNotIn("10.0.0.1", ips)
        # Preserva share.
        self.assertEqual(result[0]["share"], 50.0)


class MultiTargetMapTest(unittest.TestCase):
    def test_multi_target_event_contributes_destination_points(self):
        conn = make_db()
        insert_outbound_multi(conn, "a", [dest("45.133.39.1"), dest("8.8.8.8")])
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        summary = result["summary"]
        self.assertEqual(summary["multi_target_events"], 1)
        self.assertEqual(summary["multi_target_destinations_considered"], 2)
        self.assertEqual(summary["multi_target_destinations_located"], 2)
        self.assertEqual(summary["multi_target_events_with_geo"], 1)
        # Dois destinos em países diferentes -> 2 pontos.
        self.assertEqual(len(result["points"]), 2)
        subjects = {p["predominant_geo_subject"] for p in result["points"]}
        self.assertEqual(subjects, {"multiple_destinations"})

    def test_multi_target_same_region_aggregates(self):
        conn = make_db()
        insert_outbound_multi(conn, "a", [dest("45.133.39.1"), dest("45.133.39.2"), dest("45.133.39.3")])
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        # Três destinos no mesmo país (NL) -> 1 ponto agregado.
        self.assertEqual(len(result["points"]), 1)
        point = result["points"][0]
        self.assertEqual(point["country_code"], "NL")
        self.assertEqual(point["destination_count"], 3)
        self.assertEqual(point["multi_target_events"], 1)

    def test_color_comes_from_event_severity(self):
        conn = make_db()
        insert_outbound_multi(conn, "a", [dest("45.133.39.1")], severity="CRITICAL", verdict="CONFIRMED_ATTACK")
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        point = result["points"][0]
        self.assertEqual(point["tier"], "critical")
        self.assertEqual(point["color"], "#ef4444")

    def test_single_and_prefix_unchanged(self):
        conn = make_db()
        # single target
        conn.execute("""INSERT INTO security_events (event_key, detector, attack_type, severity, verdict, direction, src_role, dst_role, src_ip, target_ip, target_prefix, first_seen, last_seen, created_at, updated_at, status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     ("s1", "port_scan", "LOW_SLOW_SCAN", "HIGH", "LIKELY_ATTACK", "OUTBOUND", "CUSTOMER", "EXTERNAL", "186.232.160.10", "51.81.178.81", "", now_iso(minutes=-30), now_iso(minutes=-5), now_iso(minutes=-30), now_iso(minutes=-5), "active"))
        conn.commit()
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        # single target continua geolocalizável via target_ip (51.81.178.81 não está no stub -> unlocated)
        self.assertEqual(result["summary"]["multi_target_events"], 0)

    def test_target_scope_filter(self):
        conn = make_db()
        insert_outbound_multi(conn, "a", [dest("45.133.39.1")])
        insert_outbound_multi(conn, "b", [dest("8.8.8.8")])
        all_result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub)
        multi_result = build_security_map(conn, period="24h", target_scope="multi", group_by="country", geo_lookup=geo_stub)
        self.assertEqual(multi_result["summary"]["multi_target_events"], 2)
        self.assertEqual(all_result["summary"]["multi_target_events"], 2)

    def test_global_point_cap(self):
        conn = make_db()
        insert_outbound_multi(conn, "a", [dest("45.133.39.1"), dest("8.8.8.8"), dest("177.128.0.1")])
        result = build_security_map(conn, period="24h", group_by="country", geo_lookup=geo_stub, limit=2)
        self.assertLessEqual(len(result["points"]), 2)


if __name__ == "__main__":
    unittest.main()
