"""P5.0 transport/port semantic classification tests (test matrix, Section 25)."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.transport_semantics import (  # noqa: E402
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    HTTPS_AMBIGUOUS,
    HTTPS_BIDIRECTIONAL_ESTABLISHED,
    HTTPS_CLIENT_INITIATION,
    HTTPS_SERVER_RESPONSE,
    HTTPS_SOURCE_SYN,
    NON_HTTPS,
    QUIC_UDP_443,
    classify_transport,
    transport_semantics_from_features,
)
from app.services.vector_specificity import transport_evidence_context  # noqa: E402

TCP = 6
UDP = 17


class TransportSemanticsTest(unittest.TestCase):
    def test_case1_customer_to_external_dst443_syn(self):
        # CUSTOMER -> EXTERNAL, dst443, SYN, no IOC
        result = classify_transport(
            protocol=TCP, src_port=50000, dst_port=443,
            syn_ratio=0.9, ack_ratio=0.05, direction="OUTBOUND",
        )
        self.assertEqual(result["transport_semantic"], HTTPS_CLIENT_INITIATION)
        self.assertIn("DST_443", result["transport_reason_codes"])
        self.assertFalse(result["c2_over_https"])

    def test_case2_external_to_customer_src443_ack(self):
        # EXTERNAL -> CUSTOMER, src443, ACK/PSH, no SYN
        result = classify_transport(
            protocol=TCP, src_port=443, dst_port=50000,
            syn_ratio=0.0, ack_ratio=0.8, psh_ack_ratio=0.5, direction="INBOUND",
        )
        self.assertEqual(result["transport_semantic"], HTTPS_SERVER_RESPONSE)
        self.assertEqual(result["transport_confidence"], CONF_HIGH)
        self.assertIn("SRC_443", result["transport_reason_codes"])

    def test_case3_external_to_customer_src443_syn(self):
        # EXTERNAL -> CUSTOMER, src443, SYN -> source SYN, NOT suppressed
        result = classify_transport(
            protocol=TCP, src_port=443, dst_port=50000,
            syn_ratio=0.9, ack_ratio=0.05, direction="INBOUND",
        )
        self.assertEqual(result["transport_semantic"], HTTPS_SOURCE_SYN)
        self.assertNotEqual(result["transport_semantic"], HTTPS_SERVER_RESPONSE)

    def test_case4_customer_to_external_dst443_syn_c2(self):
        # CUSTOMER -> EXTERNAL, dst443, SYN, C2_CONFIRMED -> c2_over_https, IOC preserved
        result = classify_transport(
            protocol=TCP, src_port=50000, dst_port=443,
            syn_ratio=0.9, ack_ratio=0.05, direction="OUTBOUND", c2=True,
        )
        self.assertEqual(result["transport_semantic"], HTTPS_CLIENT_INITIATION)
        self.assertTrue(result["c2_over_https"])
        self.assertIn("IOC_C2_DESTINATION", result["transport_reason_codes"])

    def test_case5_customer_to_external_dst443_inconclusive(self):
        # high volume but insufficient SYN -> AMBIGUOUS (never invented)
        result = classify_transport(
            protocol=TCP, src_port=50000, dst_port=443,
            syn_ratio=0.3, ack_ratio=0.4, direction="OUTBOUND",
        )
        self.assertEqual(result["transport_semantic"], HTTPS_AMBIGUOUS)

    def test_case6_src443_ack_scan_cardinality(self):
        # src443 ACK (response role) but scan cardinality stays available
        result = classify_transport(
            protocol=TCP, src_port=443, dst_port=50000,
            syn_ratio=0.0, ack_ratio=0.8, direction="INBOUND",
        )
        self.assertEqual(result["transport_semantic"], HTTPS_SERVER_RESPONSE)
        # transport role never erases detector/cardinality signals (metadata only)
        evidence = transport_evidence_context(result)
        self.assertTrue(evidence["expected_response_context"])

    def test_case7_dst443_syn_flood_detectable(self):
        # dst443 SYN flood -> client initiation role, still detectable (not suppressed)
        result = classify_transport(
            protocol=TCP, src_port=50000, dst_port=443,
            syn_ratio=0.95, ack_ratio=0.0, direction="INBOUND",
        )
        self.assertEqual(result["transport_semantic"], HTTPS_CLIENT_INITIATION)
        evidence = transport_evidence_context(result)
        self.assertFalse(evidence["expected_response_context"])

    def test_case8_dst22_syn_non_https(self):
        # dst22 SYN -> NON_HTTPS, no regression
        result = classify_transport(
            protocol=TCP, src_port=50000, dst_port=22,
            syn_ratio=0.9, ack_ratio=0.0, direction="OUTBOUND",
        )
        self.assertEqual(result["transport_semantic"], NON_HTTPS)

    def test_case9_udp443_quic(self):
        # UDP/443 QUIC -> QUIC_UDP_443, never TCP semantics
        result = classify_transport(
            protocol=UDP, src_port=443, dst_port=50000,
            syn_ratio=0.0, ack_ratio=0.0, direction="INBOUND",
        )
        self.assertEqual(result["transport_semantic"], QUIC_UDP_443)
        self.assertNotIn("TCP_SYN_DOMINANT", result["transport_reason_codes"])

    def test_case10_tcp_src443_no_flags(self):
        # TCP src443 no flags -> AMBIGUOUS, never assume response
        result = classify_transport(
            protocol=TCP, src_port=443, dst_port=50000,
            syn_ratio=0.0, ack_ratio=0.0, direction="UNKNOWN",
        )
        self.assertEqual(result["transport_semantic"], HTTPS_AMBIGUOUS)
        self.assertEqual(result["transport_confidence"], CONF_LOW)

    def test_syn_precedence_over_server_response(self):
        # src443 + SYN dominant must NEVER be classified as server response
        result = classify_transport(
            protocol=TCP, src_port=443, dst_port=50000,
            syn_ratio=0.6, ack_ratio=0.3, direction="INBOUND",
        )
        self.assertEqual(result["transport_semantic"], HTTPS_SOURCE_SYN)

    def test_established_bidirectional(self):
        result = classify_transport(
            protocol=TCP, src_port=443, dst_port=443,
            syn_ratio=0.05, ack_ratio=0.85, direction="UNKNOWN",
        )
        self.assertEqual(result["transport_semantic"], HTTPS_BIDIRECTIONAL_ESTABLISHED)


class TransportSemanticsFeaturesTest(unittest.TestCase):
    def _features(self, protocol_number, top_src, top_dst, flags):
        return {
            "protocol_distribution": [
                {"protocol_number": protocol_number, "packets": 1000},
            ],
            "top_source_port_details": [
                {"port": top_src, "packets": 900, "share": 90.0},
            ],
            "top_destination_port_details": [
                {"port": top_dst, "packets": 900, "share": 90.0},
            ],
            "tcp_flag_distribution": flags,
        }

    def test_adaptor_server_response(self):
        features = self._features(
            6, 443, 50000,
            [
                {"flags": 0x10, "packets": 800},  # ACK
                {"flags": 0x18, "packets": 100},  # PSH+ACK
            ],
        )
        semantic = transport_semantics_from_features(features, direction="INBOUND")
        self.assertEqual(semantic["transport_semantic"], HTTPS_SERVER_RESPONSE)

    def test_adaptor_c2_over_https(self):
        features = self._features(
            6, 50000, 443,
            [{"flags": 0x02, "packets": 900}],  # SYN
        )
        threat_intel = {
            "source_intel": {
                "c2_sources": 1,
                "classifications": ["c2"],
                "indicator_types": ["C2"],
            }
        }
        semantic = transport_semantics_from_features(
            features, direction="OUTBOUND", threat_intel=threat_intel,
        )
        self.assertEqual(semantic["transport_semantic"], HTTPS_CLIENT_INITIATION)
        self.assertTrue(semantic["c2_over_https"])

    def test_adaptor_quic_udp(self):
        features = self._features(17, 443, 50000, [])
        semantic = transport_semantics_from_features(features, direction="INBOUND")
        self.assertEqual(semantic["transport_semantic"], QUIC_UDP_443)


if __name__ == "__main__":
    unittest.main()
