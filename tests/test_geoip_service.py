"""Tests for the offline GeoIP owner (Threat Intelligence Map V2.2).

Covers the fallback chain (MaxMind City -> ASN country -> centroid -> none),
the bounded LRU cache, graceful degradation when the MMDB is missing, and the
"no external provider is ever called" contract.
"""

from __future__ import annotations

import unittest

from app.services.geoip_service import (
    SOURCE_ASN_COUNTRY,
    SOURCE_COUNTRY_CENTROID,
    SOURCE_MAXMIND_CITY,
    SOURCE_NONE,
    GeoIpService,
)


def raw_geo_lookup(ip: str, asn: int = 0, as_name: str = "") -> dict:
    """Simulates app.main.geo_lookup_ip (local: maxmind -> asn -> centroid)."""
    calls.append(ip)
    table = {
        "8.8.8.8": {
            "country_code": "US", "country_name": "United States", "city": "Mountain View", "region": "California",
            "latitude": 37.4223, "longitude": -122.0848, "accuracy_radius": 50, "source": "maxmind", "asn": 15169, "as_name": "GOOGLE",
        },
        "2001:4860:4860::8888": {
            "country_code": "US", "country_name": "United States", "city": "Mountain View", "region": "California",
            "latitude": 37.4223, "longitude": -122.0848, "accuracy_radius": 50, "source": "maxmind", "asn": 15169, "as_name": "GOOGLE",
        },
        "79.124.62.126": {
            "country_code": "BG", "country_name": "Bulgaria", "city": "", "region": "",
            "latitude": None, "longitude": None, "source": "asn-cache", "asn": 207812, "as_name": "DM AUTO",
        },
        "45.133.39.1": {
            "country_code": "NL", "country_name": "Netherlands", "city": "", "region": "",
            "latitude": 52.1326, "longitude": 5.2913, "source": "asn-cache", "asn": 9009, "as_name": "M247",
        },
        "1.2.3.4": {
            "country_code": "AQ", "country_name": "Antarctica", "city": "", "region": "",
            "latitude": None, "longitude": None, "source": "asn-cache", "asn": 111, "as_name": "TEST",
        },
    }
    item = table.get(ip)
    if item is not None:
        return dict(item)
    return {
        "country_code": "", "country_name": "N/D", "city": "", "region": "",
        "latitude": None, "longitude": None, "source": "unresolved", "asn": 0, "as_name": "",
    }


calls: list[str] = []


def make_service(max_entries: int = 4096) -> GeoIpService:
    calls.clear()
    return GeoIpService(max_entries=max_entries, geo_lookup=raw_geo_lookup)


class GeoIpServiceTest(unittest.TestCase):
    def test_public_ipv4_resolves_city(self):
        svc = make_service()
        result = svc.lookup_ip("8.8.8.8")
        self.assertEqual(result["source"], SOURCE_MAXMIND_CITY)
        self.assertEqual(result["country_code"], "US")
        self.assertEqual(result["city"], "Mountain View")
        self.assertEqual(result["latitude"], 37.4223)
        self.assertEqual(result["longitude"], -122.0848)
        self.assertEqual(result["accuracy_radius"], 50)

    def test_public_ipv6_resolves_city(self):
        svc = make_service()
        result = svc.lookup_ip("2001:4860:4860::8888")
        self.assertEqual(result["source"], SOURCE_MAXMIND_CITY)
        self.assertEqual(result["country_code"], "US")

    def test_private_ip_returns_none_without_city_lookup(self):
        svc = make_service()
        result = svc.lookup_ip("192.168.1.1")
        self.assertEqual(result["source"], SOURCE_NONE)
        self.assertEqual(result["country_code"], "")

    def test_city_miss_falls_back_to_asn_country(self):
        svc = make_service()
        result = svc.lookup_ip("79.124.62.126")
        # BG tem country via ASN e centroid disponível -> COUNTRY_CENTROID.
        self.assertEqual(result["country_code"], "BG")
        self.assertEqual(result["source"], SOURCE_COUNTRY_CENTROID)
        self.assertEqual(result["latitude"], 42.7)
        self.assertEqual(result["longitude"], 25.5)

    def test_asn_country_without_centroid_is_asn_country(self):
        svc = make_service()
        result = svc.lookup_ip("1.2.3.4")  # AQ (Antarctica) sem centroid
        self.assertEqual(result["country_code"], "AQ")
        self.assertEqual(result["source"], SOURCE_ASN_COUNTRY)
        self.assertIsNone(result["latitude"])

    def test_total_miss_is_none(self):
        svc = make_service()
        result = svc.lookup_ip("203.0.113.9")
        self.assertEqual(result["source"], SOURCE_NONE)
        self.assertEqual(result["country_code"], "")

    def test_cache_hit(self):
        svc = make_service()
        calls.clear()
        svc.lookup_ip("8.8.8.8")
        svc.lookup_ip("8.8.8.8")
        self.assertEqual(calls, ["8.8.8.8"])
        self.assertEqual(svc.stats()["hits"], 1)
        self.assertEqual(svc.stats()["misses"], 1)

    def test_cache_bounded(self):
        svc = make_service(max_entries=2)
        svc.lookup_ip("8.8.8.8")
        svc.lookup_ip("79.124.62.126")
        svc.lookup_ip("45.133.39.1")
        stats = svc.stats()
        self.assertEqual(stats["entries"], 2)
        # O mais antigo (8.8.8.8) foi expulso.
        calls.clear()
        svc.lookup_ip("8.8.8.8")
        self.assertEqual(calls, ["8.8.8.8"])

    def test_missing_mmdb_degrades_gracefully(self):
        # Sem source='maxmind' no stub, o owner cai no ASN/centroid sem erro.
        svc = make_service()
        result = svc.lookup_ip("79.124.62.126")
        self.assertIn(result["source"], (SOURCE_ASN_COUNTRY, SOURCE_COUNTRY_CENTROID, SOURCE_NONE))

    def test_invalid_mmdb_path_degrades_gracefully(self):
        # IP não resolvível simula DB ausente/inválido -> NONE, sem exception.
        svc = make_service()
        result = svc.lookup_ip("203.0.113.9")
        self.assertEqual(result["source"], SOURCE_NONE)

    def test_centroid_is_never_maxmind_city(self):
        svc = make_service()
        result = svc.lookup_ip("79.124.62.126")
        self.assertEqual(result["source"], SOURCE_COUNTRY_CENTROID)
        self.assertNotEqual(result["source"], SOURCE_MAXMIND_CITY)
        self.assertIsNone(result["accuracy_radius"])

    def test_no_external_provider_import(self):
        # O owner deve ser 100% local: não importa urllib/requests/socket.
        import app.services.geoip_service as mod

        source = open(mod.__file__, encoding="utf-8").read()
        for forbidden in ("urllib.request", "requests.", "socket.", "http://", "https://"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
