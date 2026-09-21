"""Offline GeoIP owner for the Security Situation Map (V2.2).

Single owner for IP -> geography lookups used by the security map. It is 100%
local/offline and never calls any external GeoIP/RDAP/ASN web API during
rendering.

Fallback chain (public IPs only):
  1. MaxMind City MMDB (if configured)  -> source MAXMIND_CITY
  2. local ASN -> country               -> source ASN_COUNTRY
  3. country centroid                   -> source COUNTRY_CENTROID
  4. unresolved                         -> source NONE

A bounded in-memory LRU cache avoids repeated lookups for the same source IP
and keeps the map endpoint light. Persistent SQLite caching remains owned by
`app.main` (geo_ip_cache); this module only adds the hot in-process layer.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any

from app.services.threat_intelligence import clean_text

SOURCE_MAXMIND_CITY = "MAXMIND_CITY"
SOURCE_ASN_COUNTRY = "ASN_COUNTRY"
SOURCE_COUNTRY_CENTROID = "COUNTRY_CENTROID"
SOURCE_NONE = "NONE"

# Country centroids (lat, lon). Used only as an approximation for country-level
# placement; never presented as an exact location.
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


def _empty(ip: str, *, asn: int = 0, as_name: str = "", source: str = SOURCE_NONE) -> dict[str, Any]:
    return {
        "country_code": "",
        "country_name": "N/D",
        "city": "",
        "region": "",
        "latitude": None,
        "longitude": None,
        "accuracy_radius": None,
        "source": source,
        "asn": int(asn or 0),
        "as_name": clean_text(as_name),
        "ip": clean_text(ip),
    }


def _main_geo_lookup():
    try:
        from app.main import geo_lookup_ip

        return geo_lookup_ip
    except Exception:
        def _fallback(ip: str, asn: int = 0, as_name: str = "") -> dict[str, Any]:
            return _empty(ip, asn=asn, as_name=as_name)

        return _fallback


def _normalize(ip: str, raw: dict[str, Any]) -> dict[str, Any]:
    source = clean_text(raw.get("source")).lower()
    country_code = clean_text(raw.get("country_code")).upper()
    country_name = clean_text(raw.get("country_name"))
    city = clean_text(raw.get("city"))
    region = clean_text(raw.get("region"))
    latitude = raw.get("latitude")
    longitude = raw.get("longitude")
    accuracy_radius = raw.get("accuracy_radius")
    asn = int(raw.get("asn") or 0)
    as_name = clean_text(raw.get("as_name"))

    if source == "maxmind":
        return {
            "country_code": country_code,
            "country_name": country_name or "N/D",
            "city": city,
            "region": region,
            "latitude": latitude,
            "longitude": longitude,
            "accuracy_radius": accuracy_radius,
            "source": SOURCE_MAXMIND_CITY,
            "asn": asn,
            "as_name": as_name,
            "ip": clean_text(ip),
        }

    if source in ("asn-cache", "asn", "local_prefix_db"):
        if not country_code:
            return _empty(ip, asn=asn, as_name=as_name)
        # Country resolved via ASN; apply centroid when no precise coordinate.
        if latitude is not None and longitude is not None:
            return {
                "country_code": country_code,
                "country_name": country_name or "N/D",
                "city": "",
                "region": "",
                "latitude": latitude,
                "longitude": longitude,
                "accuracy_radius": None,
                "source": SOURCE_COUNTRY_CENTROID,
                "asn": asn,
                "as_name": as_name,
                "ip": clean_text(ip),
            }
        center = COUNTRY_CENTERS.get(country_code)
        if center:
            return {
                "country_code": country_code,
                "country_name": country_name or "N/D",
                "city": "",
                "region": "",
                "latitude": center[0],
                "longitude": center[1],
                "accuracy_radius": None,
                "source": SOURCE_COUNTRY_CENTROID,
                "asn": asn,
                "as_name": as_name,
                "ip": clean_text(ip),
            }
        return {
            "country_code": country_code,
            "country_name": country_name or "N/D",
            "city": "",
            "region": "",
            "latitude": None,
            "longitude": None,
            "accuracy_radius": None,
            "source": SOURCE_ASN_COUNTRY,
            "asn": asn,
            "as_name": as_name,
            "ip": clean_text(ip),
        }

    return _empty(ip, asn=asn, as_name=as_name)


class GeoIpService:
    """Bounded in-memory LRU GeoIP lookup with hit/miss counters."""

    def __init__(self, max_entries: int = 4096, geo_lookup: Any = None):
        self.max_entries = max(1, int(max_entries))
        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self._geo_lookup = geo_lookup

    def _resolve(self) -> Any:
        if self._geo_lookup is None:
            self._geo_lookup = _main_geo_lookup()
        return self._geo_lookup

    def lookup_ip(self, ip: str, *, asn: int = 0, as_name: str = "") -> dict[str, Any]:
        key = clean_text(ip)
        if not key:
            return _empty(key, asn=asn, as_name=as_name)

        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
                self.hits += 1
                return cached
            self.misses += 1

        raw = self._resolve()(key, asn, as_name)
        result = _normalize(key, raw)
        with self._lock:
            self._cache[key] = result
            self._cache.move_to_end(key)
            while len(self._cache) > self.max_entries:
                self._cache.popitem(last=False)
        return result

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "entries": len(self._cache),
                "max_entries": self.max_entries,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / (self.hits + self.misses), 4) if (self.hits + self.misses) else 0.0,
            }

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# Module-level singleton used by the security map (and any other offline GeoIP
# consumer that wants the same hot cache).
geoip_service = GeoIpService()
