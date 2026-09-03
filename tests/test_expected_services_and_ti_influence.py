"""Testes de Network Asset expected services + Threat Intelligence influence.

Cobre:
- expected_services_match: wildcard de portas (None/0 = ANY), direção, disabled.
- Integração de expected services no CARPET_BOMBING (contexto, nunca whitelist).
- Endurecimento de QUIC/443 (udp_quic_hint vs cdn_quic_expected).
- TI influence (NORMAL/REDUCED/ADVISORY_ONLY) nos caminhos de score.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavioral_detection import (  # noqa: E402
    CARPET_BOMBING,
    DISTRIBUTED_SYN_FLOOD,
    EXPECTED_DISTRIBUTED_TRAFFIC,
    MULTI_VECTOR_DDOS,
    SUSPICIOUS_DISTRIBUTED_TRAFFIC,
    SYN_FLOOD,
    TI_INFLUENCE_ADVISORY_ONLY,
    TI_INFLUENCE_NORMAL,
    TI_INFLUENCE_REDUCED,
    UDP_REFLECTION_SUSPECTED,
    CarpetBombingDetector,
    DetectorThresholds,
    FlowObservation,
    apply_ti_influence,
    threat_intel_influence,
)
from app.services.network_assets import (  # noqa: E402
    CDN_CACHE,
    NetworkAssetResolver,
    ensure_network_assets_schema,
    expected_services_match,
    replace_network_asset_services,
    resolve_network_context,
    upsert_network_asset,
)


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)

GOOGLE_GGC_V4 = "45.163.144.32/27"
NETFLIX_OCA_V4 = "45.163.144.64/30"


def _flow(
    source="198.18.0.1",
    destination="203.0.113.10",
    source_port=40000,
    destination_port=443,
    protocol=6,
    flags=0,
    packets=1,
    bytes_count=60,
    seconds_ago=0,
):
    return FlowObservation(
        observed_at=NOW - timedelta(seconds=seconds_ago),
        src_ip=source,
        dst_ip=destination,
        src_port=source_port,
        dst_port=destination_port,
        protocol=protocol,
        tcp_flags=flags,
        packets=packets,
        bytes=bytes_count,
        flow_count=1,
        src_asn=64500,
        sensor="edge",
        exporter_ip="192.0.2.1",
        input_if=10,
    )


class NetworkAssetsDbMixin:
    def _setup_assets(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "db.sqlite")
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        ensure_network_assets_schema(self.conn)
        self.conn.commit()
        self.resolver = NetworkAssetResolver(lambda: sqlite3.connect(self.path))

    def _teardown_assets(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _add_asset(self, prefix, role, name="", provider="", services=None):
        asset = upsert_network_asset(
            self.conn,
            {
                "prefix": prefix,
                "name": name,
                "role": role,
                "addressing_mode": "NONE",
                "provider": provider,
            },
        )
        self.conn.commit()
        if services:
            replace_network_asset_services(self.conn, int(asset["id"]), services)
            self.conn.commit()
        return asset


class ExpectedServicesMatchTest(NetworkAssetsDbMixin, unittest.TestCase):
    def setUp(self):
        self._setup_assets()

    def tearDown(self):
        self._teardown_assets()

    def _ggc_context(self, services):
        self._add_asset(
            GOOGLE_GGC_V4,
            CDN_CACHE,
            "Google GGC",
            provider="GOOGLE",
            services=services,
        )
        return self.resolver.resolve("45.163.144.44")

    # FASE A: None/0 = ANY; porta positiva = exata.
    def test_destination_port_zero_means_any(self):
        context = self._ggc_context([
            {"protocol": "tcp", "source_port": 443, "destination_port": 0, "direction": "TO_CUSTOMERS", "enabled": 1},
        ])
        self.assertTrue(expected_services_match(context, "tcp", 443, 51842, "TO_CUSTOMERS"))
        self.assertTrue(expected_services_match(context, "tcp", 443, 1, "TO_CUSTOMERS"))

    def test_source_port_zero_means_any(self):
        context = self._ggc_context([
            {"protocol": "tcp", "source_port": 0, "destination_port": 51842, "direction": "TO_CUSTOMERS", "enabled": 1},
        ])
        self.assertTrue(expected_services_match(context, "tcp", 443, 51842, "TO_CUSTOMERS"))
        self.assertTrue(expected_services_match(context, "tcp", 80, 51842, "TO_CUSTOMERS"))

    def test_none_port_means_any(self):
        context = self._ggc_context([
            {"protocol": "tcp", "source_port": None, "destination_port": None, "direction": "ANY", "enabled": 1},
        ])
        self.assertTrue(expected_services_match(context, "tcp", 443, 51842, "ANY"))

    def test_specific_port_still_exact(self):
        context = self._ggc_context([
            {"protocol": "tcp", "source_port": 443, "destination_port": 8443, "direction": "TO_CUSTOMERS", "enabled": 1},
        ])
        self.assertTrue(expected_services_match(context, "tcp", 443, 8443, "TO_CUSTOMERS"))
        self.assertFalse(expected_services_match(context, "tcp", 443, 51842, "TO_CUSTOMERS"))
        self.assertFalse(expected_services_match(context, "tcp", 80, 8443, "TO_CUSTOMERS"))

    def test_direction_to_customers_does_not_match_from_customers(self):
        context = self._ggc_context([
            {"protocol": "tcp", "source_port": 443, "direction": "TO_CUSTOMERS", "enabled": 1},
        ])
        self.assertTrue(expected_services_match(context, "tcp", 443, 51842, "TO_CUSTOMERS"))
        self.assertFalse(expected_services_match(context, "tcp", 443, 51842, "FROM_CUSTOMERS"))

    def test_direction_any_matches_both(self):
        context = self._ggc_context([
            {"protocol": "tcp", "source_port": 443, "direction": "ANY", "enabled": 1},
        ])
        self.assertTrue(expected_services_match(context, "tcp", 443, 51842, "TO_CUSTOMERS"))
        self.assertTrue(expected_services_match(context, "tcp", 443, 51842, "FROM_CUSTOMERS"))

    def test_disabled_service_does_not_match(self):
        context = self._ggc_context([
            {"protocol": "tcp", "source_port": 443, "direction": "TO_CUSTOMERS", "enabled": 0},
        ])
        self.assertFalse(expected_services_match(context, "tcp", 443, 51842, "TO_CUSTOMERS"))

    # FASE F #2/#4: Netflix UDP 443 NÃO é esperado (não cadastrado).
    def test_netflix_udp_443_not_expected(self):
        self._add_asset(
            NETFLIX_OCA_V4,
            CDN_CACHE,
            "Netflix OCA",
            provider="NETFLIX",
            services=[
                {"protocol": "tcp", "source_port": 80, "direction": "TO_CUSTOMERS", "enabled": 1},
                {"protocol": "tcp", "source_port": 443, "direction": "TO_CUSTOMERS", "enabled": 1},
            ],
        )
        context = self.resolver.resolve("45.163.144.66")
        self.assertTrue(expected_services_match(context, "tcp", 443, 50000, "TO_CUSTOMERS"))
        self.assertFalse(expected_services_match(context, "udp", 443, 50000, "TO_CUSTOMERS"))


class CarpetExpectedServiceIntegrationTest(NetworkAssetsDbMixin, unittest.TestCase):
    def setUp(self):
        self._setup_assets()
        self._add_asset(
            GOOGLE_GGC_V4,
            CDN_CACHE,
            "Google GGC",
            provider="GOOGLE",
            services=[
                {"protocol": "tcp", "source_port": 80, "direction": "TO_CUSTOMERS", "enabled": 1},
                {"protocol": "tcp", "source_port": 443, "direction": "TO_CUSTOMERS", "enabled": 1},
                {"protocol": "udp", "source_port": 443, "direction": "TO_CUSTOMERS", "enabled": 1},
            ],
        )

    def tearDown(self):
        self._teardown_assets()

    def _cdn_rows(self, protocol=6, flags=0x10, source_port=443):
        rows = []
        for i in range(31):
            rows.append(
                _flow(
                    source=f"45.163.144.{33 + i}",
                    destination=f"203.0.113.{i % 250 + 1}",
                    source_port=source_port,
                    destination_port=32768 + (i % 900),
                    protocol=protocol,
                    flags=flags,
                    packets=600,
                    bytes_count=600 * 1400,
                    seconds_ago=i % 40,
                )
            )
        return rows

    def _detect_carpet(self, rows):
        vectors = CarpetBombingDetector(resolver=self.resolver.resolve).detect(rows)
        return next((v for v in vectors if v.attack_type == CARPET_BOMBING), None)

    # FASE F #1/#6: TCP src443 ACK de CDN conhecido => expected service + EXPECTED.
    def test_cdn_tcp_443_ack_expected_service_and_expected_traffic(self):
        rows = self._cdn_rows(protocol=6, flags=0x10, source_port=443)
        match = self._detect_carpet(rows)
        self.assertIsNotNone(match)
        self.assertGreater(match.features["expected_service_share"], 0.0)
        self.assertGreater(match.features["cdn_expected_service_share"], 0.0)
        self.assertGreater(match.features["expected_service_matches"], 0)
        self.assertIn("GOOGLE", match.features["expected_service_providers"])
        self.assertTrue(match.features["web_return_service_context"]["matched"])

    # FASE C: Google GGC UDP 443 => cdn_quic_expected, pode contribuir p/ retorno.
    def test_cdn_udp_443_quic_expected(self):
        rows = self._cdn_rows(protocol=17, flags=0, source_port=443)
        match = self._detect_carpet(rows)
        self.assertIsNotNone(match)
        self.assertTrue(match.features["cdn_quic_expected"])
        self.assertGreater(match.features["cdn_quic_expected_share"], 0.0)
        self.assertGreater(match.features["expected_service_share"], 0.0)

    # FASE F #5: UDP src443 de origem DESCONHECIDA não vira EXPECTED pela porta.
    def test_unknown_udp_443_is_only_hint_not_expected(self):
        rows = []
        for i in range(60):
            rows.append(
                _flow(
                    source=f"198.18.{i // 250 + 1}.{i % 250 + 1}",
                    destination=f"203.0.113.{i % 250 + 1}",
                    source_port=443,
                    destination_port=40000 + i,
                    protocol=17,
                    packets=200,
                    bytes_count=200 * 1200,
                    seconds_ago=i % 40,
                )
            )
        match = self._detect_carpet(rows)
        self.assertIsNotNone(match)
        self.assertTrue(match.features["udp_quic_hint"])
        self.assertFalse(match.features["cdn_quic_expected"])
        self.assertEqual(0.0, match.features["expected_service_share"])
        self.assertNotEqual(EXPECTED_DISTRIBUTED_TRAFFIC, match.features["traffic_classification"])
        self.assertNotIn("LIKELY_WEB_RETURN_TRAFFIC", match.features["reason_codes"])

    # FASE F #7: ataque TCP dst_port=443 NÃO é neutralizado.
    def test_tcp_dst_443_attack_not_neutralized(self):
        rows = []
        for i in range(500):
            rows.append(
                _flow(
                    source=f"198.51.{i // 250}.{i % 250 + 1}",
                    destination=f"203.0.113.{i % 250 + 1}",
                    source_port=40000 + (i % 1000),
                    destination_port=443,
                    protocol=6,
                    flags=0x02,
                    packets=600,
                    bytes_count=600 * 60,
                    seconds_ago=i % 30,
                )
            )
        match = self._detect_carpet(rows)
        self.assertIsNotNone(match)
        self.assertNotIn("LIKELY_WEB_RETURN_TRAFFIC", match.features["reason_codes"])
        self.assertEqual("CONFIRMED_ATTACK", match.features["traffic_classification"])

    # FASE F #15: expected service sozinho (sem gates) não suprime o vetor.
    def test_expected_service_alone_does_not_suppress_vector(self):
        # CDN source, mas dst_port concentrado (sem diversidade) => ainda ataque.
        rows = []
        for i in range(31):
            rows.append(
                _flow(
                    source=f"45.163.144.{33 + i}",
                    destination=f"203.0.113.{i % 250 + 1}",
                    source_port=443,
                    destination_port=443,
                    protocol=6,
                    flags=0x02,
                    packets=400,
                    bytes_count=400 * 60,
                    seconds_ago=i % 40,
                )
            )
        match = self._detect_carpet(rows)
        self.assertIsNotNone(match)
        self.assertGreater(match.features["expected_service_share"], 0.0)
        self.assertNotIn("LIKELY_WEB_RETURN_TRAFFIC", match.features["reason_codes"])


class ThreatIntelInfluenceTest(unittest.TestCase):
    def test_carpet_expected_is_advisory_only(self):
        influence, reason = threat_intel_influence(CARPET_BOMBING, EXPECTED_DISTRIBUTED_TRAFFIC)
        self.assertEqual(TI_INFLUENCE_ADVISORY_ONLY, influence)
        self.assertEqual(0, apply_ti_influence(8, influence))
        self.assertEqual(0, apply_ti_influence(4, influence))

    def test_carpet_suspicious_is_reduced(self):
        influence, reason = threat_intel_influence(CARPET_BOMBING, SUSPICIOUS_DISTRIBUTED_TRAFFIC)
        self.assertEqual(TI_INFLUENCE_REDUCED, influence)
        self.assertEqual(2, apply_ti_influence(8, influence))
        self.assertEqual(1, apply_ti_influence(1, influence))

    def test_carpet_confirmed_is_normal(self):
        influence, reason = threat_intel_influence(CARPET_BOMBING, "CONFIRMED_ATTACK")
        self.assertEqual(TI_INFLUENCE_NORMAL, influence)
        self.assertEqual(8, apply_ti_influence(8, influence))

    def test_strong_vectors_are_normal(self):
        for attack_type in (SYN_FLOOD, DISTRIBUTED_SYN_FLOOD, UDP_REFLECTION_SUSPECTED, MULTI_VECTOR_DDOS):
            influence, _reason = threat_intel_influence(attack_type)
            self.assertEqual(TI_INFLUENCE_NORMAL, influence)
            self.assertEqual(8, apply_ti_influence(8, influence))

    def test_scan_vectors_are_reduced(self):
        from app.services.behavioral_detection import PORT_SCAN_VERTICAL, NETWORK_SWEEP, LOW_SLOW_SCAN
        for attack_type in (PORT_SCAN_VERTICAL, NETWORK_SWEEP, LOW_SLOW_SCAN):
            influence, _reason = threat_intel_influence(attack_type)
            self.assertEqual(TI_INFLUENCE_REDUCED, influence)
            self.assertEqual(2, apply_ti_influence(8, influence))

    def test_advisory_only_keeps_raw_bonus_zero(self):
        # IOC permanece visível (raw), mas bônus aplicado é zero.
        influence, reason = threat_intel_influence(CARPET_BOMBING, EXPECTED_DISTRIBUTED_TRAFFIC)
        self.assertEqual(0, apply_ti_influence(8, influence))


if __name__ == "__main__":
    unittest.main()
