"""Vector Specificity — Shadow (Fase 0).

Cobre:
- Funções puras de vector_specificity (gate semântico, specific/residual,
  traffic_accounting, threshold_basis sempre "raw").
- Caso real Google GGC UDP src443 TO_CUSTOMERS + QUIC_RETURN.
- Negativos (porta/direção/serviço errados) e segurança (critério isolado).
- Contrato estático do caminho Shadow em main.py.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = str(ROOT / "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.vector_specificity import (  # noqa: E402
    SPECIFIC_CODEC,
    SPECIFIC_SERVICE_DIRECTION,
    SPECIFIC_SERVICE_PROTOCOL,
    SPECIFIC_SERVICE_SOURCE_PORT,
    THRESHOLD_BASIS_RAW,
    build_traffic_accounting,
    effective_specific_packets_s,
    is_udp_internal_transmits_candidate,
    residual_packets_s,
    specific_udp_return_satisfied,
)
from app.services.network_assets import expected_services_match  # noqa: E402
from app.services.flow_codecs import (  # noqa: E402
    classify_flow_codecs,
    ensure_flow_codecs_schema,
    list_flow_codecs,
    seed_builtin_flow_codecs,
)

MAIN_SOURCE = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
VS_SOURCE = (ROOT / "backend" / "app" / "services" / "vector_specificity.py").read_text(encoding="utf-8")


def ggc_asset_context():
    return {
        "matched": True,
        "role": "CDN_CACHE",
        "provider": "GOOGLE_GGC",
        "expected_services": [
            {
                "protocol": "udp",
                "source_port": 443,
                "destination_port": 0,
                "direction": "TO_CUSTOMERS",
                "enabled": 1,
            },
        ],
    }


def build_accounting_for(
    raw,
    port_specific,
    asset_context,
    codec_names,
    expected_service,
):
    qualified = specific_udp_return_satisfied(asset_context, codec_names, expected_service)
    specific = effective_specific_packets_s(port_specific, qualified)
    return build_traffic_accounting(
        raw_packets_s=raw,
        specific_packets_s=specific,
        residual=residual_packets_s(raw, specific),
        specific_codec=SPECIFIC_CODEC if qualified else None,
        expected_service=bool(expected_service),
        asset_role=(asset_context or {}).get("role"),
        provider=(asset_context or {}).get("provider"),
        direction=SPECIFIC_SERVICE_DIRECTION,
        threshold_basis=THRESHOLD_BASIS_RAW,
    )


class VectorSpecificityPureTest(unittest.TestCase):
    def test_guard_only_udp_internal_transmits(self):
        self.assertTrue(is_udp_internal_transmits_candidate("UDP", "internal_ip", "transmits"))
        self.assertFalse(is_udp_internal_transmits_candidate("TCP", "internal_ip", "transmits"))
        self.assertFalse(is_udp_internal_transmits_candidate("UDP", "subnet", "transmits"))
        self.assertFalse(is_udp_internal_transmits_candidate("UDP", "internal_ip", "receives"))

    def test_positive_ggc_quic_return_expected(self):
        ctx = ggc_asset_context()
        expected = expected_services_match(ctx, "udp", 443, 0, "TO_CUSTOMERS")
        self.assertTrue(expected)
        self.assertTrue(specific_udp_return_satisfied(ctx, {"QUIC_RETURN"}, expected))

        raw = 141166.67
        port_specific = 141166.67
        accounting = build_accounting_for(raw, port_specific, ctx, {"QUIC_RETURN"}, expected)
        self.assertEqual(accounting["raw_packets_s"], raw)
        self.assertEqual(accounting["specific_packets_s"], port_specific)
        self.assertEqual(accounting["residual_packets_s"], 0.0)
        self.assertEqual(accounting["threshold_basis"], "raw")
        self.assertEqual(accounting["specific_codec"], "QUIC_RETURN")
        self.assertEqual(accounting["expected_service"], True)
        self.assertEqual(accounting["asset_role"], "CDN_CACHE")
        self.assertEqual(accounting["provider"], "GOOGLE_GGC")
        self.assertEqual(accounting["direction"], "TO_CUSTOMERS")

    def test_port_different_from_443_yields_zero_specific(self):
        ctx = ggc_asset_context()
        expected = expected_services_match(ctx, "udp", 1234, 0, "TO_CUSTOMERS")
        self.assertFalse(expected)
        self.assertFalse(specific_udp_return_satisfied(ctx, {"QUIC_RETURN"}, expected))
        accounting = build_accounting_for(141166.67, 141166.67, ctx, {"QUIC_RETURN"}, expected)
        self.assertEqual(accounting["specific_packets_s"], 0.0)
        self.assertEqual(accounting["residual_packets_s"], 141166.67)

    def test_wrong_direction_yields_zero_specific(self):
        ctx = ggc_asset_context()
        expected = expected_services_match(ctx, "udp", 443, 0, "FROM_CUSTOMERS")
        self.assertFalse(expected)
        accounting = build_accounting_for(100000.0, 100000.0, ctx, {"QUIC_RETURN"}, expected)
        self.assertEqual(accounting["specific_packets_s"], 0.0)
        self.assertEqual(accounting["residual_packets_s"], 100000.0)

    def test_expected_service_false_yields_zero_specific(self):
        ctx = {"role": "CDN_CACHE", "provider": "GOOGLE_GGC", "expected_services": []}
        expected = expected_services_match(ctx, "udp", 443, 0, "TO_CUSTOMERS")
        self.assertFalse(expected)
        accounting = build_accounting_for(90000.0, 90000.0, ctx, {"QUIC_RETURN"}, expected)
        self.assertEqual(accounting["specific_packets_s"], 0.0)
        self.assertEqual(accounting["residual_packets_s"], 90000.0)

    def test_src443_alone_not_enough(self):
        # No asset context: only the port signature is present.
        self.assertFalse(specific_udp_return_satisfied({}, {"QUIC_RETURN"}, True))

    def test_ggc_alone_not_enough(self):
        ctx = {"provider": "GOOGLE_GGC"}
        self.assertFalse(specific_udp_return_satisfied(ctx, {"QUIC_RETURN"}, True))

    def test_cdn_alone_not_enough(self):
        ctx = {"role": "CDN_CACHE"}
        self.assertFalse(specific_udp_return_satisfied(ctx, {"QUIC_RETURN"}, True))

    def test_codec_mismatch_not_enough(self):
        ctx = ggc_asset_context()
        expected = expected_services_match(ctx, "udp", 443, 0, "TO_CUSTOMERS")
        self.assertTrue(expected)
        self.assertFalse(specific_udp_return_satisfied(ctx, {"DNS_QUERY_UDP"}, expected))

    def test_residual_equals_raw_minus_specific(self):
        self.assertAlmostEqual(residual_packets_s(141166.67, 40000.0), 101166.67, places=2)

    def test_residual_never_negative(self):
        self.assertEqual(residual_packets_s(100.0, 150.0), 0.0)

    def test_threshold_basis_always_raw(self):
        accounting = build_accounting_for(141166.67, 141166.67, ggc_asset_context(), {"QUIC_RETURN"}, True)
        self.assertEqual(accounting["threshold_basis"], "raw")


class VectorSpecificityCodecIntegrationTest(unittest.TestCase):
    def test_classify_flow_codecs_yields_quic_return(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "flow.db")
            import sqlite3

            conn = sqlite3.connect(path)
            conn.row_factory = sqlite3.Row
            ensure_flow_codecs_schema(conn)
            seed_builtin_flow_codecs(conn)
            codecs = list_flow_codecs(conn, active_only=True)
            names = {
                codec["name"]
                for codec in classify_flow_codecs(
                    {"protocol": 17, "source_port": 443, "destination_port": 0},
                    codecs,
                    source_context=ggc_asset_context(),
                    destination_context=None,
                )
            }
            conn.close()
        self.assertIn("QUIC_RETURN", names)


class VectorSpecificityShadowStaticTest(unittest.TestCase):
    def test_raw_packets_s_metric_value_and_threshold_unchanged(self):
        # packets_s original (raw) permanece.
        self.assertIn("sum(packet_value * multiplier) AS packets", MAIN_SOURCE)
        self.assertIn("packets / {float(window_seconds)} AS packets_s", MAIN_SOURCE)
        # metric_value continua referenciando metric_alias (= packets_s).
        self.assertIn("metric_alias = metric_expression_for_detection(rule[\"metric\"])", MAIN_SOURCE)
        self.assertIn("{metric_alias} AS metric_value", MAIN_SOURCE)
        # specific nunca alimenta metric_value.
        self.assertNotIn("specific_packets AS metric_value", MAIN_SOURCE)
        self.assertNotIn("specific_packets_s AS metric_value", MAIN_SOURCE)

    def test_sumif_is_additive_and_specific_uses_real_window(self):
        self.assertIn("sumIf(packet_value * multiplier, src_port = 443) AS specific_packets", MAIN_SOURCE)
        self.assertIn("specific_packets / {float(window_seconds)} AS specific_packets_s", MAIN_SOURCE)

    def test_threshold_basis_is_raw_and_accounting_is_persisted(self):
        self.assertIn('threshold_basis="raw"', MAIN_SOURCE)
        self.assertIn('"traffic_accounting": candidate.get("traffic_accounting") or {},', MAIN_SOURCE)
        self.assertIn('THRESHOLD_BASIS_RAW = "raw"', VS_SOURCE)
        self.assertIn('"threshold_basis": threshold_basis', VS_SOURCE)


if __name__ == "__main__":
    unittest.main()
