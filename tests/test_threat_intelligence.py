from __future__ import annotations

import json
import os
import sqlite3
import sys
import unittest
import urllib.error
import urllib.parse
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.threat_intelligence import (  # noqa: E402
    ACTIVE,
    AUTH_ERROR,
    CEREAL2,
    DEGRADED,
    FEODO,
    GREYNOISE,
    ERROR,
    RATE_LIMITED,
    TEAM_CYMRU,
    WAITING_SYNC,
    ThreatIntelManager,
    ensure_threat_intel_schema,
)


class FakeResponse:
    def __init__(self, value):
        self.payload = value if isinstance(value, bytes) else json.dumps(value).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


class ThreatIntelligenceTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.factory = lambda: self.conn
        self.env = mock.patch.dict(
            os.environ,
            {
                "GREYNOISE_API_KEY": "test-secret",
                "GMJFLOW_THREAT_INTEL_GREYNOISE_ENABLED": "true",
                "GMJFLOW_THREAT_INTEL_CEREAL2_ENABLED": "true",
                "GMJFLOW_THREAT_INTEL_TEAM_CYMRU_ENABLED": "true",
                "GMJFLOW_THREAT_INTEL_FEODO_ENABLED": "true",
            },
            clear=False,
        )
        self.env.start()
        ensure_threat_intel_schema(self.conn)
        self.conn.commit()

    def tearDown(self):
        self.env.stop()
        self.conn.close()

    @staticmethod
    def cereal_c2_payload(entries=None):
        items = entries if entries is not None else [
            {
                "ip": "203.0.113.8", "asn": 64510, "asn_name": "C2 ASN",
                "country_code": "BR", "first_seen": "2026-08-11T09:00:00Z",
                "last_seen": "2026-08-11T10:00:00Z", "botnet_family": "Mirai",
            }
        ]
        return {"schema_version": "1.0", "last_updated": "2026-08-11T10:00:00Z", "count": len(items), "entries": items}

    @staticmethod
    def cereal_attack_event(event_id="attack-1", sequence=1):
        return {
            "id": event_id,
            "stream_seq": sequence,
            "observed_at": "2026-08-11T10:00:00Z",
            "target": {"prefix": "177.10.0.0/22", "country_code": "BR", "country_name": "Brazil", "asn": 64511, "asn_name": "Target"},
            "attack": {"method_label": "UDP flood", "protocol": "udp", "target_port": 53, "duration_seconds": 120},
        }

    def test_greynoise_scrolls_and_upserts_each_page(self):
        calls = []

        def opener(request, timeout=0):
            calls.append(request.full_url)
            params = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)
            classification = "malicious" if "malicious" in params["query"][0] else "suspicious"
            scroll = params.get("scroll", [""])[0]
            suffix = "2" if scroll else "1"
            return FakeResponse(
                {
                    "data": [
                        {
                            "ip": f"198.51.100.{len(calls)}",
                            "classification": classification,
                            "actor": "unit-test",
                            "metadata": {"asn": "AS64500", "organization": "Example", "country": "Brazil", "country_code": "BR", "city": "Sao Paulo"},
                            "last_seen": "2026-08-11T10:00:00Z",
                            "tags": [{"slug": "mirai", "name": "Mirai", "recommend_block": True, "cves": []}],
                        }
                    ],
                    "request_metadata": {"complete": bool(scroll), "scroll": "next" + suffix},
                }
            )

        manager = ThreatIntelManager(self.factory, opener)
        result = manager.sync(GREYNOISE)
        self.assertEqual(ACTIVE, result["status"])
        self.assertEqual(4, result["pages"])
        self.assertEqual(4, result["items_processed"])
        self.assertEqual(4, len(calls))
        row = self.conn.execute("SELECT * FROM threat_intel_indicators WHERE provider=? ORDER BY ip LIMIT 1", (GREYNOISE,)).fetchone()
        self.assertNotIn("raw_data", row.keys())
        self.assertEqual(64500, row["asn"])
        self.assertEqual("BR", row["country_code"])
        self.assertTrue(json.loads(row["tags_json"])[0]["recommend_block"])
        classifications = {
            row[0]
            for row in self.conn.execute(
                "SELECT DISTINCT classification FROM threat_intel_indicators WHERE provider=?",
                (GREYNOISE,),
            ).fetchall()
        }
        self.assertEqual({"malicious", "suspicious"}, classifications)

    def test_provider_failure_is_isolated_and_never_raises(self):
        def opener(request, timeout=0):
            raise urllib.error.URLError("network down")

        manager = ThreatIntelManager(self.factory, opener)
        result = manager.sync(FEODO)
        self.assertEqual(ERROR, result["status"])
        self.assertIn("network down", result["error"])
        self.assertEqual([], manager.lookup_ip("203.0.113.10")["matches"])

    def test_missing_greynoise_credential_is_auth_error_and_secret_is_not_persisted(self):
        with mock.patch.dict(os.environ, {"GREYNOISE_API_KEY": ""}, clear=False):
            manager = ThreatIntelManager(self.factory, lambda *_args, **_kwargs: self.fail("network must not be called"))
            result = manager.sync(GREYNOISE)
        self.assertEqual(AUTH_ERROR, result["status"])
        persisted = json.dumps(manager.statuses())
        self.assertNotIn("test-secret", persisted)
        self.assertEqual(AUTH_ERROR, next(item for item in manager.statuses() if item["provider"] == GREYNOISE)["status"])

    def test_cereal2_c2_and_attack_correlation(self):
        def opener(request, timeout=0):
            if "/api/v1/c2" in request.full_url:
                return FakeResponse(self.cereal_c2_payload())
            return FakeResponse(
                {
                    "events": [self.cereal_attack_event()],
                    "next_cursor": "",
                    "watermark": "wm-1",
                }
            )

        manager = ThreatIntelManager(self.factory, opener)
        result = manager.sync(CEREAL2)
        self.assertEqual(ACTIVE, result["status"])
        lookup = manager.lookup_ip("203.0.113.8")
        self.assertEqual([CEREAL2], lookup["intel_sources"])
        matches = manager.external_attack_matches("177.10.1.0/24", "udp", "2026-08-11T10:02:00Z", 300)
        self.assertEqual(1, len(matches))
        self.assertEqual("EXTERNAL_ATTACK_OBSERVATION", matches[0]["observation_type"])

    def test_cereal2_uses_supported_page_size_and_advances_cursor(self):
        attack_urls = []

        def opener(request, timeout=0):
            if "/api/v1/c2" in request.full_url:
                return FakeResponse(self.cereal_c2_payload())
            attack_urls.append(request.full_url)
            params = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)
            self.assertEqual(["200"], params.get("limit"))
            cursor = params.get("cursor", [""])[0]
            if not cursor:
                return FakeResponse({"events": [self.cereal_attack_event("attack-1", 1)], "next_cursor": "cursor-1", "watermark": "wm-1"})
            self.assertEqual("cursor-1", cursor)
            return FakeResponse({"events": [self.cereal_attack_event("attack-2", 2)], "next_cursor": "", "watermark": "wm-1"})

        with mock.patch.dict(os.environ, {"GMJFLOW_CEREAL2_ATTACK_PAGE_SIZE": "250", "GMJFLOW_CEREAL2_ATTACK_MAX_PAGES": "5"}, clear=False):
            result = ThreatIntelManager(self.factory, opener).sync(CEREAL2)
        self.assertEqual(ACTIVE, result["status"])
        self.assertEqual(2, len(attack_urls))
        self.assertEqual(2, self.conn.execute("SELECT COUNT(*) FROM external_attack_observations WHERE active=1").fetchone()[0])

    def test_cereal2_repeated_cursor_is_rejected_and_audited(self):
        calls = 0

        def opener(request, timeout=0):
            nonlocal calls
            if "/api/v1/c2" in request.full_url:
                return FakeResponse(self.cereal_c2_payload())
            calls += 1
            return FakeResponse({"events": [self.cereal_attack_event(f"attack-{calls}", calls)], "next_cursor": "repeat", "watermark": "wm-1"})

        result = ThreatIntelManager(self.factory, opener).sync(CEREAL2)
        self.assertEqual(ERROR, result["status"])
        self.assertIn("repetido", result["error"])
        self.assertEqual(0, self.conn.execute("SELECT COUNT(*) FROM threat_intel_indicators WHERE provider=?", (CEREAL2,)).fetchone()[0])
        audit = self.conn.execute("SELECT * FROM threat_intel_sync_audit ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual("attacks_page_2", audit["phase"])
        self.assertEqual("/api/v1/attacks", audit["endpoint"])

    def test_cereal2_http_400_keeps_endpoint_and_phase_without_query(self):
        def opener(request, timeout=0):
            if "/api/v1/c2" in request.full_url:
                return FakeResponse(self.cereal_c2_payload())
            raise urllib.error.HTTPError(request.full_url, 400, "bad request", None, None)

        result = ThreatIntelManager(self.factory, opener).sync(CEREAL2)
        self.assertEqual(ERROR, result["status"])
        self.assertEqual("attacks_page_1", result["phase"])
        self.assertEqual("/api/v1/attacks", result["endpoint"])
        self.assertNotIn("cursor", result["endpoint"])

    def test_cereal2_incomplete_snapshot_is_rejected(self):
        manager = ThreatIntelManager(self.factory, lambda *_args, **_kwargs: FakeResponse({"entries": []}))
        result = manager.sync(CEREAL2)
        self.assertEqual(ERROR, result["status"])
        self.assertEqual("c2_snapshot", result["phase"])
        self.assertEqual(0, self.conn.execute("SELECT COUNT(*) FROM threat_intel_indicators WHERE provider=?", (CEREAL2,)).fetchone()[0])

    def test_cereal2_incomplete_attack_page_is_rejected_before_commit(self):
        def opener(request, timeout=0):
            if "/api/v1/c2" in request.full_url:
                return FakeResponse(self.cereal_c2_payload())
            return FakeResponse({"events": [], "next_cursor": ""})

        result = ThreatIntelManager(self.factory, opener).sync(CEREAL2)
        self.assertEqual(ERROR, result["status"])
        self.assertEqual("attacks_page_1", result["phase"])
        self.assertEqual(0, self.conn.execute("SELECT COUNT(*) FROM threat_intel_indicators WHERE provider=?", (CEREAL2,)).fetchone()[0])

    def test_cereal2_partial_sync_does_not_corrupt_previous_snapshot(self):
        provider = ThreatIntelManager(self.factory).provider(CEREAL2)
        provider._upsert_indicators(
            [{"indicator_type": "C2", "ip": "198.51.100.99", "classification": "c2", "country_code": "US"}],
            "previous",
        )
        calls = 0

        def opener(request, timeout=0):
            nonlocal calls
            if "/api/v1/c2" in request.full_url:
                return FakeResponse(self.cereal_c2_payload())
            calls += 1
            if calls == 1:
                return FakeResponse({"events": [self.cereal_attack_event()], "next_cursor": "cursor-2", "watermark": "wm-1"})
            raise urllib.error.HTTPError(request.full_url, 400, "bad cursor", None, None)

        result = ThreatIntelManager(self.factory, opener).sync(CEREAL2)
        self.assertEqual(DEGRADED, result["status"])
        previous = self.conn.execute(
            "SELECT active FROM threat_intel_indicators WHERE provider=? AND ip='198.51.100.99'",
            (CEREAL2,),
        ).fetchone()
        staged = self.conn.execute(
            "SELECT * FROM threat_intel_indicators WHERE provider=? AND ip='203.0.113.8'",
            (CEREAL2,),
        ).fetchone()
        self.assertEqual(1, previous["active"])
        self.assertIsNone(staged)
        self.assertEqual(1, result["item_count"])

    def test_feodo_match_is_normalized_as_c2(self):
        manager = ThreatIntelManager(
            self.factory,
            lambda *_args, **_kwargs: FakeResponse(
                [
                    {
                        "ip_address": "192.0.2.44",
                        "port": 443,
                        "status": "online",
                        "malware": "QakBot",
                        "as_number": "AS64520",
                        "as_name": "Example ASN",
                        "country": "US",
                        "first_seen": "2026-08-10 00:00:00",
                        "last_online": "2026-08-11 00:00:00",
                    }
                ]
            ),
        )
        self.assertEqual(ACTIVE, manager.sync(FEODO)["status"])
        match = manager.lookup_ip("192.0.2.44")["matches"][0]
        self.assertEqual("C2", match["indicator_type"])
        self.assertEqual("QakBot", match["botnet_family"])

    def test_provider_state_is_waiting_active_and_greynoise_is_not_false_offline(self):
        manager = ThreatIntelManager(self.factory)
        waiting = next(item for item in manager.statuses() if item["provider"] == CEREAL2)
        self.assertEqual(WAITING_SYNC, waiting["status"])
        manager.provider(GREYNOISE)._upsert_indicators(
            [{"indicator_type": "IP", "ip": "198.51.100.50", "classification": "malicious"}],
            "cached",
        )
        greynoise = next(item for item in manager.statuses() if item["provider"] == GREYNOISE)
        self.assertEqual(ACTIVE, greynoise["status"])
        self.assertTrue(greynoise["data_usable"])

    def test_provider_degraded_and_rate_limited_keep_cached_data(self):
        manager = ThreatIntelManager(self.factory)
        manager.provider(FEODO)._upsert_indicators(
            [{"indicator_type": "C2", "ip": "192.0.2.90", "classification": "c2"}],
            "cached",
        )
        failing = ThreatIntelManager(self.factory, lambda *_args, **_kwargs: (_ for _ in ()).throw(urllib.error.URLError("temporary")))
        degraded = failing.sync(FEODO)
        self.assertEqual(DEGRADED, degraded["status"])
        self.assertEqual(1, degraded["item_count"])
        self.assertEqual(1, self.conn.execute("SELECT active FROM threat_intel_indicators WHERE provider=? AND ip='192.0.2.90'", (FEODO,)).fetchone()[0])

        manager.provider(GREYNOISE)._upsert_indicators(
            [{"indicator_type": "IP", "ip": "198.51.100.91", "classification": "malicious"}],
            "cached",
        )

        def rate_limited(request, timeout=0):
            raise urllib.error.HTTPError(request.full_url, 429, "rate limit", None, None)

        limited = ThreatIntelManager(self.factory, rate_limited).sync(GREYNOISE)
        self.assertEqual(RATE_LIMITED, limited["status"])
        self.assertEqual(1, limited["item_count"])

    def test_team_cymru_cgnat_depends_on_network_context(self):
        manager = ThreatIntelManager(self.factory)
        provider = manager.provider(TEAM_CYMRU)
        item = provider.normalize({"prefix": "100.64.0.0/10", "kind": "BOGON"})
        provider._upsert_bogons(
            [(TEAM_CYMRU, "BOGON", item["prefix"], 4, 10, item["start_bin"], item["end_bin"], "test", "2026-08-11T00:00:00Z")]
        )
        internal = provider.lookup_ip("100.64.0.10", {"context_type": "CGNAT"})[0]
        transit = provider.lookup_ip("100.64.0.10", {"context_type": "TRANSIT"})[0]
        self.assertEqual("context_normal", internal["classification"])
        self.assertEqual(0, internal["spoofing_likelihood"])
        self.assertEqual("anomalous_source", transit["classification"])
        self.assertGreater(transit["spoofing_likelihood"], 0)

    def test_team_cymru_fullbogon_is_normalized_and_matched(self):
        manager = ThreatIntelManager(self.factory)
        provider = manager.provider(TEAM_CYMRU)
        item = provider.normalize({"prefix": "192.0.2.0/24", "kind": "FULLBOGON"})
        provider._upsert_bogons(
            [(TEAM_CYMRU, "FULLBOGON", item["prefix"], 4, 24, item["start_bin"], item["end_bin"], "test", "2026-08-11T00:00:00Z")]
        )
        match = provider.lookup_ip("192.0.2.44", {"context_type": "TRANSIT"})[0]
        self.assertEqual("FULLBOGON", match["indicator_type"])
        self.assertEqual("anomalous_source", match["classification"])

    def test_configured_exporter_context_overrides_unknown_cgnat_context(self):
        manager = ThreatIntelManager(self.factory)
        provider = manager.provider(TEAM_CYMRU)
        item = provider.normalize({"prefix": "100.64.0.0/10", "kind": "BOGON"})
        provider._upsert_bogons(
            [(TEAM_CYMRU, "BOGON", item["prefix"], 4, 10, item["start_bin"], item["end_bin"], "test", "2026-08-11T00:00:00Z")]
        )
        now = "2026-08-11T00:00:00Z"
        self.conn.execute(
            """
            INSERT INTO threat_network_contexts (
                name, sensor_name, exporter_ip, input_if, context_type,
                protected_ranges_json, enabled, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, '[]', 1, ?, ?)
            """,
            ("BRAS uplink", "edge", "192.0.2.1", 10, "CGNAT", now, now),
        )
        self.conn.commit()
        configured = manager.lookup_ip(
            "100.64.0.10",
            {"sensor": "edge", "exporter_ip": "192.0.2.1", "input_if": 10, "context_type": "UNKNOWN"},
        )
        unknown = manager.lookup_ip(
            "100.64.0.10",
            {"sensor": "other", "exporter_ip": "192.0.2.9", "input_if": 99, "context_type": "UNKNOWN"},
        )
        configured_match = next(match for match in configured["matches"] if match["provider"] == TEAM_CYMRU)
        unknown_match = next(match for match in unknown["matches"] if match["provider"] == TEAM_CYMRU)
        self.assertEqual("CGNAT", configured["network_context"]["context_type"])
        self.assertEqual("context_normal", configured_match["classification"])
        self.assertEqual("context_unknown", unknown_match["classification"])
        self.assertEqual(0, unknown_match["spoofing_likelihood"])

    def test_map_aggregates_expose_popup_summary_without_raw_indicators(self):
        manager = ThreatIntelManager(self.factory)
        manager.provider(GREYNOISE)._upsert_indicators(
            [
                {
                    "indicator_type": "IP",
                    "ip": "198.51.100.10",
                    "classification": "malicious",
                    "asn": 64500,
                    "organization": "Hostile Cloud",
                    "country": "United States",
                    "country_code": "US",
                    "city": "Chicago",
                    "tags": [{"name": "Mirai", "slug": "mirai"}],
                },
                {
                    "indicator_type": "IP",
                    "ip": "198.51.100.11",
                    "classification": "malicious",
                    "asn": 64500,
                    "organization": "Hostile Cloud",
                    "country": "United States",
                    "country_code": "US",
                    "city": "Chicago",
                    "tags": [{"name": "Scanner", "slug": "scanner"}],
                },
            ],
            "map-gn",
        )
        manager.provider(CEREAL2)._upsert_indicators(
            [
                {
                    "indicator_type": "C2",
                    "ip": "203.0.113.12",
                    "classification": "c2",
                    "asn": 64501,
                    "organization": "C2 Hosting",
                    "country": "United States",
                    "country_code": "US",
                    "city": "Dallas",
                    "botnet_family": "QakBot",
                }
            ],
            "map-cereal",
        )
        self.conn.commit()

        item = manager.map_aggregates(group_by="country")[0]
        self.assertEqual("US", item["key"])
        self.assertEqual(3, item["unique_ips"])
        self.assertEqual("malicious", item["predominant_classification"])
        self.assertEqual({GREYNOISE, CEREAL2}, set(item["providers"]))
        self.assertEqual("Hostile Cloud", item["top_organizations"][0]["name"])
        self.assertEqual({"Mirai", "Scanner", "QakBot"}, {tag["name"] for tag in item["top_tags"]})
        self.assertNotIn("ip", item)

        asn_items = manager.map_aggregates(group_by="asn")
        self.assertEqual({64500, 64501}, {item["asn"] for item in asn_items})
        self.assertTrue(all(item["country_code"] == "US" for item in asn_items))


if __name__ == "__main__":
    unittest.main()
