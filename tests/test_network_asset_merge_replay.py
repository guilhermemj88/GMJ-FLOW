"""Testes de merge de contexto (manual + CGNAT) e shadow replay do CARPET_BOMBING."""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavioral_detection import (  # noqa: E402
    EXPECTED_DISTRIBUTED_TRAFFIC,
    DetectorThresholds,
)
from app.services.carpet_replay import (  # noqa: E402
    replay_carpet_decision,
    replay_carpet_event,
    summarize_replay,
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
    list_network_assets,
    upsert_network_asset,
)


def _db():
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "db.sqlite")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    ensure_network_assets_schema(conn)
    ensure_cgnat_schema(conn)
    conn.commit()
    return conn, path, tmp


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.conn, self.path, self.tmp = _db()
        self.resolver = NetworkAssetResolver(lambda: sqlite3.connect(self.path))

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cgnat(self, prefix, mode="non_deterministic", name="POOL"):
        pool = create_cgnat_pool(
            self.conn,
            {"name": name, "prefix": prefix, "mode": mode, "active": 1, "notes": ""},
        )
        self.conn.commit()
        return pool

    def _manual(self, prefix, role, name="", addressing_mode="NONE", provider=""):
        asset = upsert_network_asset(
            self.conn,
            {"prefix": prefix, "name": name, "role": role, "addressing_mode": addressing_mode, "provider": provider},
        )
        self.conn.commit()
        return asset

    # 1) manual role + CGNAT same prefix => merge.
    def test_manual_role_and_cgnat_same_prefix_merge(self):
        pool = self._cgnat("45.168.202.0/25")
        self._manual("45.168.202.0/25", DOWNSTREAM_ISP, "ISP CLIENTE", provider="ISP CLIENTE")
        ctx = self.resolver.resolve("45.168.202.10")

        self.assertEqual(DOWNSTREAM_ISP, ctx["role"])
        self.assertEqual(CGNAT_NON_DETERMINISTIC, ctx["addressing_mode"])
        self.assertEqual("ISP CLIENTE", ctx["provider"])
        self.assertTrue(ctx["is_cgnat"])
        self.assertEqual(int(pool["id"]), ctx["cgnat_pool_id"])
        self.assertEqual(["manual", "cgnat_pool"], ctx["context_sources"])

    # 2) manual asset não apaga addressing CGNAT.
    def test_manual_asset_does_not_erase_cgnat_addressing(self):
        self._cgnat("45.168.202.0/25")
        self._manual("45.168.202.0/25", DOWNSTREAM_ISP, addressing_mode="NONE")
        ctx = self.resolver.resolve("45.168.202.5")
        self.assertEqual(CGNAT_NON_DETERMINISTIC, ctx["addressing_mode"])
        self.assertTrue(ctx["is_cgnat"])

    # 3) CGNAT continua fonte de verdade do mode.
    def test_cgnat_is_source_of_truth_for_mode(self):
        self._cgnat("45.168.202.0/25", mode="deterministic")
        self._manual("45.168.202.0/25", DOWNSTREAM_ISP, addressing_mode="NAT")
        ctx = self.resolver.resolve("45.168.202.5")
        self.assertEqual("CGNAT_DETERMINISTIC", ctx["addressing_mode"])
        self.assertTrue(ctx["is_cgnat"])

    # 4) LPM child > parent.
    def test_child_beats_parent(self):
        self._manual("45.163.144.0/22", "OTHER", "IMPLANTAR")
        self._cgnat("45.163.144.32/27", name="Google GGC")  # child
        ctx = self.resolver.resolve("45.163.144.44")
        self.assertEqual("45.163.144.32/27", ctx["prefix"])
        self.assertTrue(ctx["is_cgnat"])
        self.assertEqual("45.163.144.0/22", ctx["parent"]["prefix"])

    # 5) /32 > /27 > /22.
    def test_host_beats_subnet_beats_parent(self):
        self._manual("45.163.144.0/22", "OTHER", "IMPLANTAR")
        self._manual("45.163.144.32/27", CDN_CACHE, "Google GGC", provider="GOOGLE")
        self._manual("45.163.144.18/32", DNS_RESOLVER, "DNS IMPLANTAR")
        self.assertEqual(DNS_RESOLVER, self.resolver.resolve("45.163.144.18")["role"])
        self.assertEqual(CDN_CACHE, self.resolver.resolve("45.163.144.44")["role"])
        self.assertEqual("OTHER", self.resolver.resolve("45.163.144.5")["role"])

    # 5b) /32 manual herda addressing do parent CGNAT.
    def test_host_inherits_addressing_from_cgnat_parent(self):
        self._cgnat("45.168.202.0/25")
        self._manual("45.168.202.10/32", "SERVER_INFRA", "Servidor")
        ctx = self.resolver.resolve("45.168.202.10")
        self.assertEqual("SERVER_INFRA", ctx["role"])
        self.assertEqual("45.168.202.10/32", ctx["prefix"])
        self.assertTrue(ctx["is_cgnat"])
        self.assertEqual(CGNAT_NON_DETERMINISTIC, ctx["addressing_mode"])
        self.assertEqual(["manual", "cgnat_pool"], ctx["context_sources"])

    # 6) IPv6 LPM.
    def test_ipv6_longest_prefix_match(self):
        self._manual("2001:db8::/32", "OTHER", "v6 parent")
        self._manual("2001:db8:1::/48", CDN_CACHE, "v6 CDN")
        ctx = self.resolver.resolve("2001:db8:1::1234")
        self.assertEqual("2001:db8:1::/48", ctx["prefix"])
        self.assertEqual(CDN_CACHE, ctx["role"])
        self.assertEqual("2001:db8::/32", ctx["parent"]["prefix"])

    # 14) item CGNAT projetado não pode ser alterado como asset manual.
    def test_projected_cgnat_item_is_not_an_editable_asset(self):
        pool = self._cgnat("45.168.203.0/25")
        assets = list_network_assets(self.conn)
        projected = next(item for item in assets if item["prefix"] == "45.168.203.0/25")
        self.assertIsNone(projected["id"])
        self.assertEqual("cgnat_pool", projected["source_type"])
        self.assertEqual(int(pool["id"]), projected["source_id"])
        # Não existe linha editável em network_assets.
        row = self.conn.execute("SELECT COUNT(*) AS n FROM network_assets WHERE prefix=?", ("45.168.203.0/25",)).fetchone()
        self.assertEqual(0, row["n"])

    # 12) editar asset invalida o cache do resolver.
    def test_edit_asset_invalidates_cache(self):
        self._manual("45.168.204.0/25", "OTHER", "antes")
        self.assertEqual("OTHER", self.resolver.resolve("45.168.204.1")["role"])
        upsert_network_asset(self.conn, {"prefix": "45.168.204.0/25", "role": DNS_RESOLVER, "name": "depois"})
        self.conn.commit()
        self.assertEqual(DNS_RESOLVER, self.resolver.resolve("45.168.204.1")["role"])

    # 13) editar CGNAT invalida o contexto.
    def test_edit_cgnat_invalidates_context(self):
        pool = self._cgnat("45.168.205.0/25")
        self.assertEqual(CGNAT_POOL, self.resolver.resolve("45.168.205.1")["role"])
        update_cgnat_pool(self.conn, int(pool["id"]), {"active": 0})
        self.conn.commit()
        self.assertNotEqual(CGNAT_POOL, self.resolver.resolve("45.168.205.1")["role"])


class ReplayTest(unittest.TestCase):
    def test_real_false_positive_is_downgraded(self):
        event = {
            "event_id": 42,
            "attack_type": "CARPET_BOMBING",
            "target_prefix": "45.168.200.0/22",
            "detector_score": 100,
            "verdict": "CONFIRMED_ATTACK",
            "severity": "CRITICAL",
            "packets_per_second": 471.9,
            "bits_per_second": 3_000_000,
            "unique_sources": 7213,
            "unique_destinations": 804,
            "unique_dst_ports": 12413,
            "packets": 28316,
            "baseline_deviation": 5.26,
            "investigation": {
                "network_context": {
                    "web_return_share": 0.82,
                    "udp_quic_share": 0.21,
                    "tcp_ack_ratio": 0.67,
                    "tcp_syn_ratio": 0.03,
                    "dst_port_entropy": 0.95,
                    "target_cgnat_share": 0.55,
                    "target_downstream_isp_share": 0.10,
                }
            },
        }
        result = replay_carpet_event(event)
        self.assertEqual("FALSE_POSITIVE_REDUCED", result["comparison"])
        self.assertEqual(EXPECTED_DISTRIBUTED_TRAFFIC, result["new_traffic_classification"])
        self.assertIn("LIKELY_WEB_RETURN_TRAFFIC", result["reason_codes"])
        self.assertNotEqual("CRITICAL", result["new_severity"])

    def test_real_attack_stays_confirmed(self):
        event = {
            "event_id": 43,
            "attack_type": "CARPET_BOMBING",
            "target_prefix": "203.0.113.0/24",
            "detector_score": 96,
            "verdict": "CONFIRMED_ATTACK",
            "severity": "CRITICAL",
            "packets_per_second": 6000,
            "bits_per_second": 400_000_000,
            "unique_sources": 500,
            "unique_destinations": 500,
            "unique_dst_ports": 900,
            "packets": 360000,
            "baseline_deviation": 8.0,
            "investigation": {
                "network_context": {
                    "web_return_share": 0.01,
                    "udp_quic_share": 0.0,
                    "tcp_ack_ratio": 0.05,
                    "tcp_syn_ratio": 0.9,
                    "dst_port_entropy": 0.3,
                    "target_cgnat_share": 0.0,
                    "target_downstream_isp_share": 0.0,
                    "max_host_pps": 12.0,
                },
                "samples": {"persistent_windows": 3},
            },
        }
        result = replay_carpet_event(event)
        self.assertEqual("UNCHANGED_ATTACK", result["comparison"])
        self.assertEqual("CONFIRMED_ATTACK", result["new_verdict"])

    def test_absolute_floor_downgrade_is_distinct_from_web_return(self):
        # Alto web_return, mas abaixo do floor => os dois códigos aparecem.
        decision = replay_carpet_decision(
            {
                "aggregate_pps": 400,
                "aggregate_bps": 2_000_000,
                "unique_destinations": 300,
                "unique_sources": 2000,
                "packets": 24000,
                "web_return_share": 0.8,
                "tcp_ack_ratio": 0.8,
                "tcp_syn_ratio": 0.01,
                "dst_port_entropy": 0.9,
            }
        )
        self.assertIn("LIKELY_WEB_RETURN_TRAFFIC", decision["reason_codes"])
        self.assertIn("ABSOLUTE_VOLUME_TOO_LOW", decision["reason_codes"])
        # Só volume baixo (sem web return) => apenas ABSOLUTE_VOLUME_TOO_LOW.
        decision2 = replay_carpet_decision(
            {
                "aggregate_pps": 400,
                "aggregate_bps": 2_000_000,
                "unique_destinations": 300,
                "unique_sources": 2000,
                "packets": 24000,
                "web_return_share": 0.0,
                "tcp_ack_ratio": 0.1,
                "tcp_syn_ratio": 0.8,
                "dst_port_entropy": 0.3,
            }
        )
        self.assertIn("ABSOLUTE_VOLUME_TOO_LOW", decision2["reason_codes"])
        self.assertNotIn("LIKELY_WEB_RETURN_TRAFFIC", decision2["reason_codes"])

    def test_replay_is_read_only_and_never_touches_bgp(self):
        from pathlib import Path as _Path

        source = _Path(BACKEND, "app", "services", "carpet_replay.py").read_text(encoding="utf-8").lower()
        self.assertNotIn("exabgp", source)
        self.assertNotIn("announce", source)
        self.assertNotIn("write_pipe", source)
        self.assertNotIn("bgp_", source)
        decision = replay_carpet_decision({"aggregate_pps": 100})
        self.assertEqual("SUSPICIOUS_DISTRIBUTED_TRAFFIC", decision["traffic_classification"])

    def test_summary_counts(self):
        summary = summarize_replay(
            [
                {"comparison": "FALSE_POSITIVE_REDUCED", "reason_codes": ["LIKELY_WEB_RETURN_TRAFFIC", "ABSOLUTE_VOLUME_TOO_LOW"], "old_verdict": "CONFIRMED_ATTACK", "new_verdict": "INFO", "new_traffic_classification": EXPECTED_DISTRIBUTED_TRAFFIC},
                {"comparison": "UNCHANGED_ATTACK", "reason_codes": ["CONFIRMED_CARPET_BOMBING"], "old_verdict": "CONFIRMED_ATTACK", "new_verdict": "CONFIRMED_ATTACK", "new_traffic_classification": "CONFIRMED_ATTACK"},
                {"comparison": "ATTACK_DOWNGRADED", "reason_codes": ["ABSOLUTE_VOLUME_TOO_LOW"], "old_verdict": "CONFIRMED_ATTACK", "new_verdict": "SUSPICIOUS", "new_traffic_classification": "SUSPICIOUS_DISTRIBUTED_TRAFFIC"},
            ]
        )
        self.assertEqual(3, summary["total_events"])
        self.assertEqual(3, summary["old_confirmed"])
        self.assertEqual(1, summary["new_confirmed"])
        self.assertEqual(2, summary["downgraded"])
        self.assertEqual(1, summary["absolute_floor_downgrades"])
        self.assertEqual(1, summary["web_return_downgrades"])
        self.assertIn("LIKELY_WEB_RETURN_TRAFFIC", [code for code, _ in summary["top_reason_codes"]])


class FrontendStaticTest(unittest.TestCase):
    """CRUD da UI usa as APIs corretas (teste estático do frontend)."""

    def setUp(self):
        from pathlib import Path as _Path

        self.html = _Path(ROOT, "frontend", "index.html").read_text(encoding="utf-8")

    def test_frontend_uses_network_assets_api(self):
        self.assertIn("'/api/network-assets'", self.html)
        self.assertIn("/api/network-assets/${", self.html)
        self.assertIn("/api/network-assets/${Number(id)}", self.html)
        self.assertIn("/api/network-assets/${Number(id)}/services", self.html)
        self.assertIn("/api/network-context/resolve?ip=", self.html)

    def test_frontend_crud_controls_exist(self):
        for identifier in (
            "newNetworkAssetButton",
            "newNetworkHostButton",
            "saveNetworkAssetButton",
            "networkAssetRole",
            "networkAssetAddressingMode",
            "networkAssetProvider",
            "networkAssetZone",
            "networkAssetNotes",
            "networkAssetServicesModal",
            "addNetworkAssetServiceButton",
            "saveNetworkAssetServicesButton",
        ):
            self.assertIn(identifier, self.html)

    def test_cgnat_projected_item_links_to_cgnat_view(self):
        self.assertIn("showView('cgnat')", self.html)
        self.assertIn("source_type === 'cgnat_pool'", self.html)

    def test_roles_and_badges_rendered(self):
        for role in ("CDN_CACHE", "DNS_RESOLVER", "CGNAT_POOL", "DOWNSTREAM_ISP", "SERVER_INFRA", "NETWORK_INFRA", "PEERING_INFRA"):
            self.assertIn(role, self.html)


if __name__ == "__main__":
    unittest.main()
