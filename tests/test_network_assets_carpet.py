"""Testes da evolução de contexto de rede + detector CARPET_BOMBING.

Cobre:
- Longest-prefix-match e roles (seção 18 A-J).
- Projeção de CGNAT pools como CGNAT_POOL (sem segunda fonte de verdade).
- Falso positivo web-return convertido em tráfego esperado (seção 16).
- Ataques positivos (alta taxa, reflexão) continuam detectados (seção 17).
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
    EXPECTED_DISTRIBUTED_TRAFFIC,
    SUSPICIOUS_DISTRIBUTED_TRAFFIC,
    CarpetBombingDetector,
    DetectorThresholds,
    FlowObservation,
)
from app.services.cgnat_mapping import (  # noqa: E402
    create_cgnat_pool,
    ensure_cgnat_schema,
    update_cgnat_pool,
)
from app.services.network_assets import (  # noqa: E402
    CDN_CACHE,
    CGNAT_NON_DETERMINISTIC,
    CGNAT_POOL,
    DNS_RESOLVER,
    DOWNSTREAM_ISP,
    NetworkAssetResolver,
    ensure_network_assets_schema,
    expected_services_match,
    list_network_assets,
    replace_network_asset_services,
    resolve_network_context,
    upsert_network_asset,
)


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)


def flow(
    source="198.18.0.1",
    destination="203.0.113.10",
    source_port=40000,
    destination_port=443,
    protocol=6,
    flags=0,
    packets=1,
    bytes_count=60,
    seconds_ago=0,
    source_asn=64500,
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
        src_asn=source_asn,
        sensor="edge",
        exporter_ip="192.0.2.1",
        input_if=10,
    )


class NetworkAssetResolverTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "db.sqlite")
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        ensure_network_assets_schema(self.conn)
        ensure_cgnat_schema(self.conn)
        self.conn.commit()
        self.resolver = NetworkAssetResolver(lambda: sqlite3.connect(self.path))

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _asset(self, prefix, role, name="", addressing_mode="NONE", provider="", services=None):
        asset = upsert_network_asset(
            self.conn,
            {
                "prefix": prefix,
                "name": name,
                "role": role,
                "addressing_mode": addressing_mode,
                "provider": provider,
            },
        )
        self.conn.commit()
        if services:
            replace_network_asset_services(self.conn, int(asset["id"]), services)
            self.conn.commit()
        return asset

    # A) 45.163.144.44 pertence a /22 e /27; o /27 (CDN) vence.
    def test_a_longest_prefix_match_resolves_cdn_child(self):
        self._asset("45.163.144.0/22", "OTHER", "IMPLANTAR")
        self._asset("45.163.144.32/27", CDN_CACHE, "Google GGC", provider="GOOGLE")
        context = self.resolver.resolve("45.163.144.44")
        self.assertTrue(context["matched"])
        self.assertEqual("45.163.144.32/27", context["prefix"])
        self.assertEqual(CDN_CACHE, context["role"])
        self.assertEqual("GOOGLE", context["provider"])

    # B) /32 DNS vence sobre o /22.
    def test_b_host_prefix_resolves_dns_resolver(self):
        self._asset("45.163.144.0/22", "OTHER", "IMPLANTAR")
        self._asset("45.163.144.18/32", DNS_RESOLVER, "DNS IMPLANTAR")
        context = self.resolver.resolve("45.163.144.18")
        self.assertEqual("45.163.144.18/32", context["prefix"])
        self.assertEqual(DNS_RESOLVER, context["role"])

    # C) CGNAT pool criado aparece automaticamente como CGNAT_POOL.
    def test_c_cgnat_pool_projected_as_asset(self):
        create_cgnat_pool(
            self.conn,
            {"name": "POOL-1", "prefix": "45.168.200.0/25", "mode": "non_deterministic", "active": 1, "notes": ""},
        )
        self.conn.commit()
        assets = list_network_assets(self.conn)
        projected = next(item for item in assets if item["prefix"] == "45.168.200.0/25")
        self.assertEqual(CGNAT_POOL, projected["role"])
        self.assertEqual("cgnat_pool", projected["source_type"])
        self.assertEqual(CGNAT_NON_DETERMINISTIC, projected["addressing_mode"])
        context = self.resolver.resolve("45.168.200.10")
        self.assertEqual(CGNAT_POOL, context["role"])
        self.assertEqual("cgnat_pool", context["source_type"])

    # D) CGNAT desativado deixa de ser ativo no contexto.
    def test_d_deactivated_cgnat_pool_no_longer_active(self):
        pool = create_cgnat_pool(
            self.conn,
            {"name": "POOL-2", "prefix": "45.168.201.128/25", "mode": "non_deterministic", "active": 1, "notes": ""},
        )
        self.conn.commit()
        self.assertEqual(CGNAT_POOL, self.resolver.resolve("45.168.201.130")["role"])
        update_cgnat_pool(self.conn, int(pool["id"]), {"active": 0})
        self.conn.commit()
        self.assertNotEqual(CGNAT_POOL, self.resolver.resolve("45.168.201.130")["role"])

    # E) DOWNSTREAM_ISP + CGNAT coexistem (role != addressing mode).
    def test_e_role_and_addressing_mode_coexist(self):
        self._asset(
            "45.168.202.0/25",
            DOWNSTREAM_ISP,
            "ISP cliente",
            addressing_mode=CGNAT_NON_DETERMINISTIC,
        )
        context = self.resolver.resolve("45.168.202.10")
        self.assertEqual(DOWNSTREAM_ISP, context["role"])
        self.assertEqual(CGNAT_NON_DETERMINISTIC, context["addressing_mode"])

    # F) CDN UDP src-port 443 para clientes => serviço esperado.
    def test_f_cdn_quic_service_matches(self):
        self._asset(
            "45.163.144.32/27",
            CDN_CACHE,
            "Google GGC",
            provider="GOOGLE",
            services=[
                {"protocol": "tcp", "source_port": 443, "direction": "TO_CUSTOMERS", "enabled": 1},
                {"protocol": "udp", "source_port": 443, "direction": "TO_CUSTOMERS", "enabled": 1},
            ],
        )
        context = self.resolver.resolve("45.163.144.44")
        self.assertTrue(
            expected_services_match(context, "udp", 443, 50000, "TO_CUSTOMERS")
        )
        self.assertEqual(CDN_CACHE, context["role"])

    # G) CDN em porta/protocolo inesperado => NÃO é serviço esperado.
    def test_g_cdn_unexpected_service_does_not_match(self):
        self._asset(
            "45.163.144.32/27",
            CDN_CACHE,
            "Google GGC",
            services=[
                {"protocol": "udp", "source_port": 443, "direction": "TO_CUSTOMERS", "enabled": 1},
            ],
        )
        context = self.resolver.resolve("45.163.144.44")
        self.assertFalse(
            expected_services_match(context, "tcp", 23, 23, "ANY")
        )

    # I) DNS_RESOLVER usando UDP/TCP 53 => contexto esperado.
    def test_i_dns_resolver_port_53_is_expected(self):
        self._asset(
            "45.163.144.18/32",
            DNS_RESOLVER,
            "DNS IMPLANTAR",
            services=[
                {"protocol": "udp", "source_port": 53, "direction": "TO_CUSTOMERS", "enabled": 1},
                {"protocol": "tcp", "source_port": 53, "direction": "TO_CUSTOMERS", "enabled": 1},
            ],
        )
        context = self.resolver.resolve("45.163.144.18")
        self.assertTrue(expected_services_match(context, "udp", 53, 40000, "TO_CUSTOMERS"))
        self.assertTrue(expected_services_match(context, "tcp", 53, 40000, "TO_CUSTOMERS"))
        # J) fora do perfil => não é serviço esperado (mas role continua resolvendo).
        self.assertFalse(expected_services_match(context, "tcp", 9999, 9999, "ANY"))
        self.assertEqual(DNS_RESOLVER, context["role"])


class CarpetWebReturnTest(unittest.TestCase):
    # 16) Fixture do falso positivo real: 804 destinos / 7213 fontes / 471.9 pps
    #     / source port 443+80 dominante / ACK / QUIC / destinos efêmeros.
    def test_web_return_false_positive_is_not_confirmed_attack(self):
        rows = []
        destinations = 200
        for i in range(destinations):
            dst = f"203.0.113.{i % 250 + 1}"
            src = f"198.18.{i // 250 + 1}.{i % 250 + 1}"
            rows.append(
                flow(
                    source=src,
                    destination=dst,
                    source_port=443,
                    destination_port=32768 + (i % 1000),
                    protocol=6,
                    flags=0x10,
                    packets=130,
                    bytes_count=130 * 1400,
                    seconds_ago=i % 40,
                    source_asn=64500 + (i % 100),
                )
            )
        for i in range(40):
            rows.append(
                flow(
                    source=f"198.18.20.{i + 1}",
                    destination=f"203.0.113.{i % 250 + 1}",
                    source_port=443,
                    destination_port=40000 + i,
                    protocol=17,
                    packets=50,
                    bytes_count=50 * 1200,
                    seconds_ago=i % 40,
                )
            )
        for i in range(30):
            rows.append(
                flow(
                    source=f"198.18.30.{i + 1}",
                    destination=f"203.0.113.{i % 250 + 1}",
                    source_port=80,
                    destination_port=50000 + i,
                    protocol=6,
                    flags=0x18,
                    packets=10,
                    bytes_count=10 * 1400,
                    seconds_ago=i % 40,
                )
            )
        # Tráfego não-web (ACK em outras portas) para não saturar o share em 100%.
        for i in range(50):
            rows.append(
                flow(
                    source=f"198.18.40.{i + 1}",
                    destination=f"203.0.113.{i % 250 + 1}",
                    source_port=40000 + i,
                    destination_port=60000 + i,
                    protocol=6,
                    flags=0x10,
                    packets=100,
                    bytes_count=100 * 1400,
                    seconds_ago=i % 40,
                )
            )
        baseline = {"203.0.113.0/24": 90.0}
        vectors = CarpetBombingDetector().detect(rows, baseline)
        match = next(item for item in vectors if item.attack_type == CARPET_BOMBING)

        self.assertEqual(EXPECTED_DISTRIBUTED_TRAFFIC, match.features["traffic_classification"])
        self.assertIn("LIKELY_WEB_RETURN_TRAFFIC", match.features["reason_codes"])
        self.assertNotEqual("CONFIRMED_ATTACK", match.verdict)
        self.assertNotEqual("CRITICAL", match.severity)
        self.assertLess(match.detector_score, 90)
        self.assertGreaterEqual(match.features["web_return_share"], 0.6)

    # 17) Ataque real: volume absoluto alto + muitos hosts + persistência, sem
    #     evidência de retorno web => continua CARPET_BOMBING.
    def test_high_volume_carpet_still_confirmed(self):
        rows = []
        hosts = 500
        for i in range(hosts):
            rows.append(
                flow(
                    source=f"198.51.{i // 250}.{i % 250 + 1}",
                    destination=f"203.0.113.{i % 250 + 1}",
                    source_port=40000 + (i % 1000),
                    destination_port=443,
                    protocol=17,
                    packets=600,
                    bytes_count=600 * 1400,
                    seconds_ago=i % 30,
                    source_asn=64500 + (i % 50),
                )
            )
        vectors = CarpetBombingDetector().detect(rows)
        match = next(item for item in vectors if item.attack_type == CARPET_BOMBING)

        self.assertNotIn("LIKELY_WEB_RETURN_TRAFFIC", match.features["reason_codes"])
        self.assertGreaterEqual(match.features["aggregate_pps"], 5000)
        self.assertIn("VOLUME", match.features["evidence_categories_passed"])
        self.assertIn("DISTRIBUTION", match.features["evidence_categories_passed"])
        self.assertIn("ATTACK_PATTERN", match.features["evidence_categories_passed"])
        self.assertEqual("CONFIRMED_ATTACK", match.verdict)

    # 17) Reflexão UDP source-port 53 dominante ainda detectada como ataque.
    def test_reflection_carpet_still_detected(self):
        rows = []
        hosts = 300
        for i in range(hosts):
            rows.append(
                flow(
                    source=f"198.52.{i // 250}.{i % 250 + 1}",
                    destination=f"203.0.114.{i % 250 + 1}",
                    source_port=53,
                    destination_port=40000 + (i % 1000),
                    protocol=17,
                    packets=1000,
                    bytes_count=1000 * 800,
                    seconds_ago=i % 30,
                    source_asn=64500 + (i % 80),
                )
            )
        vectors = CarpetBombingDetector().detect(rows)
        match = next(item for item in vectors if item.attack_type == CARPET_BOMBING)

        self.assertIn("ANOMALOUS_SERVICE", match.features["evidence_categories_passed"])
        self.assertEqual("CONFIRMED_ATTACK", match.verdict)

    # 14) Recorrência não transforma tráfego web normal em ataque: mesma
    #     fingerprint em múltiplas janelas continua EXPECTED.
    def test_recurrence_does_not_confirm_web_return(self):
        rows = []
        for window in range(3):
            for i in range(100):
                rows.append(
                    flow(
                        source=f"198.18.{window}.{i + 1}",
                        destination=f"203.0.113.{i + 1}",
                        source_port=443,
                        destination_port=32768 + (i % 900),
                        protocol=6,
                        flags=0x10,
                        packets=130,
                        bytes_count=130 * 1400,
                        seconds_ago=window * 60 + (i % 40),
                        source_asn=64500 + (i % 100),
                    )
                )
        vectors = CarpetBombingDetector().detect(rows)
        match = next(item for item in vectors if item.attack_type == CARPET_BOMBING)
        self.assertEqual(EXPECTED_DISTRIBUTED_TRAFFIC, match.features["traffic_classification"])


if __name__ == "__main__":
    unittest.main()
