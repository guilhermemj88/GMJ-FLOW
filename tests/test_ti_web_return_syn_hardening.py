"""Hardening regressions: TCP flag semantics, SYN flood vs WEB_RETURN.

Covers the non-negotiable rules:
- 443 alone is never "benign".
- dst_port=443 + SYN is never reduced by web-return.
- src_port=443 + SYN is never WEB_RETURN.
- src_port=443 + ACK/PSH+ACK + TO_CUSTOMERS may be WEB_RETURN.
- Threat Intelligence never deletes an IOC (context, not whitelist).
- TI influence modes (NORMAL/REDUCED/ADVISORY_ONLY/DISABLED).
- Security-event score traceability (current window vs historical max).

The real event ID GMJ-20260830-665C78D2A9 is used only as a regression
fixture — there is no hardcode of the ID anywhere in the detection logic.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavioral_detection import (  # noqa: E402
    DISTRIBUTED_SYN_FLOOD,
    EXPECTED_DISTRIBUTED_TRAFFIC,
    SPOOFED_SYN_FLOOD,
    SYN_FLOOD,
    TI_INFLUENCE_ADVISORY_ONLY,
    TI_INFLUENCE_DISABLED,
    TI_INFLUENCE_NORMAL,
    TI_INFLUENCE_REDUCED,
    AttackVector,
    CarpetBombingDetector,
    DetectorThresholds,
    FlowObservation,
    SynFloodDetector,
    apply_ti_influence,
    attach_ti_influence_metadata,
    is_tcp_syn_only,
    is_tcp_web_return_flags,
    tcp_syn_share,
    tcp_web_return_share,
    threat_intel_influence,
)
from app.services.security_events import ensure_security_event_schema, upsert_security_event  # noqa: E402
from app.services.network_assets import (  # noqa: E402
    CDN_CACHE,
    NetworkAssetResolver,
    ensure_network_assets_schema,
    replace_network_asset_services,
    upsert_network_asset,
)

NOW = datetime(2026, 8, 30, 8, 0, tzinfo=timezone.utc)

SYN = 0x02
ACK = 0x10
PSH_ACK = 0x18
SYN_ACK = 0x12
FIN_ACK = 0x11
RST = 0x04


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


class TcpFlagSemanticsTest(unittest.TestCase):
    def test_is_tcp_syn_only(self):
        self.assertTrue(is_tcp_syn_only(SYN))
        self.assertFalse(is_tcp_syn_only(SYN_ACK))
        self.assertFalse(is_tcp_syn_only(ACK))
        self.assertFalse(is_tcp_syn_only(PSH_ACK))
        self.assertFalse(is_tcp_syn_only(FIN_ACK))
        self.assertFalse(is_tcp_syn_only(0))

    def test_is_tcp_web_return_flags(self):
        self.assertTrue(is_tcp_web_return_flags(ACK))
        self.assertTrue(is_tcp_web_return_flags(PSH_ACK))
        self.assertFalse(is_tcp_web_return_flags(SYN))
        self.assertFalse(is_tcp_web_return_flags(SYN_ACK))
        self.assertFalse(is_tcp_web_return_flags(FIN_ACK))
        self.assertFalse(is_tcp_web_return_flags(RST))
        self.assertFalse(is_tcp_web_return_flags(0))

    def test_shares_count_only_real_states(self):
        rows = [
            _flow(flags=SYN, packets=100),
            _flow(flags=SYN_ACK, packets=100),
            _flow(flags=ACK, packets=100),
            _flow(flags=PSH_ACK, packets=100),
            _flow(flags=FIN_ACK, packets=100),
        ]
        # 500 TCP packets total: 100 pure SYN, 200 established return (ACK/PSH+ACK).
        self.assertAlmostEqual(tcp_syn_share(rows), 100 / 500, places=4)
        self.assertAlmostEqual(tcp_web_return_share(rows), 200 / 500, places=4)


class SynFloodDetectorRegressionTest(unittest.TestCase):
    def _syn_rows(self, destination="203.0.113.10", source_port=40000, flags=SYN, count=40):
        rows = []
        for i in range(count):
            rows.append(
                _flow(
                    source=f"198.51.{i // 250}.{i % 250 + 1}",
                    destination=destination,
                    source_port=source_port + i,
                    destination_port=443,
                    protocol=6,
                    flags=flags,
                    packets=250,
                    bytes_count=250 * 1500,
                    seconds_ago=i % 55,
                )
            )
        return rows

    def _detect(self, rows):
        return SynFloodDetector().detect(rows)

    def test_dst443_high_syn_many_sources_stays_strong(self):
        """Case 1: TCP dst443, SYN share alto, SYN PPS alto, muitas sources."""
        rows = self._syn_rows()
        vectors = self._detect(rows)
        self.assertTrue(vectors)
        vector = vectors[0]
        self.assertIn(vector.attack_type, {SYN_FLOOD, DISTRIBUTED_SYN_FLOOD, SPOOFED_SYN_FLOOD})
        self.assertGreaterEqual(vector.detector_score, 70)
        # Pure SYN: no web-return evidence may reduce the vector.
        self.assertEqual(0.0, vector.features.get("web_return_share", 0.0))
        self.assertGreaterEqual(vector.features["syn_share"], 0.9)

    def test_dst443_syn_predominant_no_web_return_reduction(self):
        """Case 2/7: dst443 + SYN predominante => nenhuma redução por web-return,
        independentemente de porta."""
        rows = self._syn_rows(flags=SYN)
        vectors = self._detect(rows)
        self.assertTrue(vectors)
        vector = vectors[0]
        self.assertIn(vector.attack_type, {SYN_FLOOD, DISTRIBUTED_SYN_FLOOD, SPOOFED_SYN_FLOOD})
        self.assertEqual(0.0, vector.features.get("web_return_share", 0.0))
        self.assertEqual(0, vector.score_components.get("network_context", 0))

    def test_src443_syn_is_not_web_return(self):
        """Case 4: TCP src443 + SYN predominante => NÃO é WEB_RETURN."""
        rows = self._syn_rows(source_port=443)
        vectors = self._detect(rows)
        self.assertTrue(vectors)
        vector = vectors[0]
        self.assertIn(vector.attack_type, {SYN_FLOOD, DISTRIBUTED_SYN_FLOOD, SPOOFED_SYN_FLOOD})
        self.assertEqual(0.0, vector.features.get("web_return_share", 0.0))
        self.assertNotIn("LIKELY_WEB_RETURN_TRAFFIC", vector.features.get("reason_codes", []))

    def test_syn_flood_exposes_flag_shares(self):
        rows = self._syn_rows()
        vectors = self._detect(rows)
        self.assertTrue(vectors)
        features = vectors[0].features
        for key in ("syn_packets" if False else "syn_count", "syn_share", "syn_pps",
                    "syn_ack_share", "psh_ack_share", "rst_share",
                    "unique_sources", "unique_destinations", "max_dst_pps"):
            self.assertIn(key, features)


class CarpetWebReturnHardeningTest(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.join(os.environ.get("TEMP", "/tmp"), f"gmj_webreturn_{os.getpid()}")
        os.makedirs(self.tmp, exist_ok=True)
        self.path = os.path.join(self.tmp, "db.sqlite")
        if os.path.exists(self.path):
            os.remove(self.path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        ensure_network_assets_schema(self.conn)
        self.conn.commit()
        self.resolver = NetworkAssetResolver(lambda: sqlite3.connect(self.path))

    def tearDown(self):
        self.conn.close()

    def _add_cdn(self):
        asset = upsert_network_asset(
            self.conn,
            {
                "prefix": "45.163.144.32/27",
                "name": "Google GGC",
                "role": CDN_CACHE,
                "addressing_mode": "NONE",
                "provider": "GOOGLE",
            },
        )
        self.conn.commit()
        replace_network_asset_services(
            self.conn,
            int(asset["id"]),
            [
                {"protocol": "tcp", "source_port": 80, "direction": "TO_CUSTOMERS", "enabled": 1},
                {"protocol": "tcp", "source_port": 443, "direction": "TO_CUSTOMERS", "enabled": 1},
                {"protocol": "udp", "source_port": 443, "direction": "TO_CUSTOMERS", "enabled": 1},
            ],
        )
        self.conn.commit()

    def _cdn_rows(self, protocol=6, flags=ACK, source_port=443):
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
        return next((v for v in vectors if v.attack_type == "CARPET_BOMBING"), None)

    def test_src443_ack_psh_ack_to_customers_is_web_return(self):
        """Case 3: TCP src443 + ACK/PSH+ACK predominante => WEB_RETURN forte."""
        self._add_cdn()
        rows = self._cdn_rows(protocol=6, flags=PSH_ACK, source_port=443)
        match = self._detect_carpet(rows)
        self.assertIsNotNone(match)
        self.assertTrue(match.features["web_return_likely"])
        self.assertEqual(EXPECTED_DISTRIBUTED_TRAFFIC, match.features["traffic_classification"])
        self.assertIn("LIKELY_WEB_RETURN_TRAFFIC", match.features["reason_codes"])
        # SYN+ACK/FIN+ACK are NOT counted as web return.
        self.assertAlmostEqual(match.features["tcp_fin_ack_share"], 0.0, places=4)
        self.assertAlmostEqual(match.features["tcp_syn_ack_share"], 0.0, places=4)

    def test_src443_ack_with_cdn_provider_expected_service_is_strong_web_return(self):
        """Case 6: src443 ACK + CDN_CACHE + provider + expected service => forte."""
        self._add_cdn()
        rows = self._cdn_rows(protocol=6, flags=ACK, source_port=443)
        match = self._detect_carpet(rows)
        self.assertIsNotNone(match)
        self.assertTrue(match.features["web_return_service_context"]["matched"])
        self.assertIn("GOOGLE", match.features["expected_service_providers"])
        self.assertTrue(match.features["web_return_likely"])

    def test_src443_syn_ack_is_not_web_return(self):
        """SYN+ACK (handshake) must not contribute to web return evidence."""
        self._add_cdn()
        rows = self._cdn_rows(protocol=6, flags=SYN_ACK, source_port=443)
        match = self._detect_carpet(rows)
        self.assertIsNotNone(match)
        # Established return is required; pure handshake replies are not enough.
        self.assertEqual(0.0, match.features["web_return_share"])
        self.assertFalse(match.features["web_return_likely"])

    def test_dst443_syn_not_web_return_via_carpet(self):
        """dst443 + SYN deve continuar candidato de ataque (não reduzido)."""
        rows = []
        for i in range(60):
            rows.append(
                _flow(
                    source=f"198.51.{i // 250}.{i % 250 + 1}",
                    destination=f"203.0.113.{i % 250 + 1}",
                    source_port=40000 + (i % 1000),
                    destination_port=443,
                    protocol=6,
                    flags=SYN,
                    packets=250,
                    bytes_count=250 * 60,
                    seconds_ago=i % 40,
                )
            )
        match = self._detect_carpet(rows)
        self.assertIsNotNone(match)
        self.assertNotIn("LIKELY_WEB_RETURN_TRAFFIC", match.features["reason_codes"])


class TiInfluenceModeTest(unittest.TestCase):
    def test_advisory_only_keeps_ioc_and_zeroes_bonus(self):
        """Case 9: ADVISORY_ONLY => IOC presente, applied bonus = 0."""
        influence, _ = threat_intel_influence("CARPET_BOMBING", EXPECTED_DISTRIBUTED_TRAFFIC)
        self.assertEqual(TI_INFLUENCE_ADVISORY_ONLY, influence)
        self.assertEqual(0, apply_ti_influence(8, influence))
        vector = AttackVector(
            attack_type="CARPET_BOMBING", detector="test", detector_score=10,
            confidence=0.1, first_seen="2026-01-01T00:00:00Z", last_seen="2026-01-01T00:00:00Z",
            threat_intel={"source_intel": {"matches": 3}},
        )
        attach_ti_influence_metadata(vector, influence, "expected_distributed_traffic", 8, 0)
        # IOC metadata preserved (context, not whitelist).
        self.assertIn("source_intel", vector.threat_intel)
        self.assertEqual(3, vector.threat_intel["source_intel"]["matches"])
        self.assertEqual(0, vector.threat_intel["ti_bonus_applied"])
        self.assertEqual(8, vector.threat_intel["ti_bonus_raw"])

    def test_reduced_caps_bonus(self):
        """Case 10: REDUCED => bônus limitado ao cap (2)."""
        influence, _ = threat_intel_influence("NETWORK_SWEEP", "")
        self.assertEqual(TI_INFLUENCE_REDUCED, influence)
        self.assertEqual(2, apply_ti_influence(8, influence))
        self.assertEqual(2, apply_ti_influence(25, influence))
        self.assertEqual(1, apply_ti_influence(1, influence))

    def test_disabled_zeroes_bonus_without_erasing_history(self):
        """Case 11: DISABLED => applied 0, sem apagar histórico existente."""
        self.assertEqual(0, apply_ti_influence(8, TI_INFLUENCE_DISABLED))
        vector = AttackVector(
            attack_type="CARPET_BOMBING", detector="test", detector_score=10,
            confidence=0.1, first_seen="2026-01-01T00:00:00Z", last_seen="2026-01-01T00:00:00Z",
            threat_intel={"source_intel": {"matches": 5}},
        )
        attach_ti_influence_metadata(vector, TI_INFLUENCE_DISABLED, "disabled", 8, 0)
        self.assertIn("source_intel", vector.threat_intel)
        self.assertEqual(5, vector.threat_intel["source_intel"]["matches"])

    def test_normal_keeps_raw_bonus(self):
        self.assertEqual(TI_INFLUENCE_NORMAL, threat_intel_influence("SYN_FLOOD", "")[0])
        self.assertEqual(8, apply_ti_influence(8, TI_INFLUENCE_NORMAL))


class ScoreTraceabilityTest(unittest.TestCase):
    def _vector(self, score):
        return AttackVector(
            attack_type="CARPET_BOMBING",
            detector="prefix_carpet_bombing",
            detector_score=score,
            confidence=score / 100.0,
            first_seen="2026-01-01T00:00:00Z",
            last_seen="2026-01-01T00:01:00Z",
            target_prefix="45.168.200.0/22",
            features={
                "packet_count": 100,
                "persistent_windows": 1,
                "score_components": {"volume": 10, "network_context": -45},
            },
            score_components={"volume": 10, "network_context": -45},
        )

    def test_upsert_keeps_max_but_records_current_window_score(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        ensure_security_event_schema(conn)
        # First window: high score (historical peak).
        upsert_security_event(conn, self._vector(100))
        # Second window: same event key, low current score (web return).
        upsert_security_event(conn, self._vector(54))
        row = dict(conn.execute("SELECT * FROM security_events").fetchone())
        # detector_score stays the historical max (backward-compatible severity).
        self.assertEqual(100, row["detector_score"])
        # current_* fields expose the latest window (traceability fix).
        self.assertEqual(54, row["current_detector_score"])
        self.assertIn("current_verdict", row)
        self.assertEqual(2, row["recurrence_count"])
        conn.close()

    def test_current_columns_exist(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        ensure_security_event_schema(conn)
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(security_events)")}
        self.assertIn("current_detector_score", cols)
        self.assertIn("current_verdict", cols)
        conn.close()


if __name__ == "__main__":
    unittest.main()
