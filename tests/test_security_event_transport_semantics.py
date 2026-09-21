"""P5.0 UI unblock: security event payload carries transport semantics metadata."""
from __future__ import annotations

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.security_events import security_event_row, vector_security_payload  # noqa: E402
from app.services.behavioral_detection import AttackVector  # noqa: E402


def _vector(features: dict, attack_type: str = "CARPET_BOMBING") -> AttackVector:
    return AttackVector(
        attack_type=attack_type,
        detector="carpet",
        detector_score=70,
        confidence=0.7,
        first_seen="2026-09-17T10:00:00Z",
        last_seen="2026-09-17T10:05:00Z",
        target_prefix="192.0.2.0/24",
        direction="INBOUND",
        protocol="udp",
        features=features,
    )


def _semantic(role: str) -> dict:
    return {
        "transport_semantic": role,
        "transport_confidence": "HIGH",
        "transport_reason_codes": ["UDP_443", "INBOUND_SERVER_DIRECTION"],
        "service_port": 443,
        "service_side": "SOURCE",
        "c2_over_https": False,
        "protocol": "udp",
    }


def _investigation(vector: AttackVector) -> dict:
    return json.loads(vector_security_payload(vector)["investigation_json"])


class SecurityEventTransportSemanticsTest(unittest.TestCase):
    def test_role_extracted_from_semantic_dict(self):
        investigation = _investigation(_vector({**_semantic("HTTPS_SERVER_RESPONSE")}))
        self.assertEqual(investigation["transport_semantic"], "HTTPS_SERVER_RESPONSE")

    def test_quic_udp_443(self):
        investigation = _investigation(_vector({**_semantic("QUIC_UDP_443")}))
        self.assertEqual(investigation["transport_semantic"], "QUIC_UDP_443")

    def test_source_syn(self):
        investigation = _investigation(_vector({**_semantic("HTTPS_SOURCE_SYN")}))
        self.assertEqual(investigation["transport_semantic"], "HTTPS_SOURCE_SYN")

    def test_c2_over_https_true(self):
        features = _semantic("HTTPS_CLIENT_INITIATION")
        features["c2_over_https"] = True
        investigation = _investigation(_vector(features))
        self.assertTrue(investigation["c2_over_https"])

    def test_reason_codes_list(self):
        investigation = _investigation(_vector({**_semantic("QUIC_UDP_443")}))
        self.assertEqual(investigation["transport_reason_codes"], ["UDP_443", "INBOUND_SERVER_DIRECTION"])

    def test_service_port_numeric(self):
        investigation = _investigation(_vector({**_semantic("QUIC_UDP_443")}))
        self.assertEqual(investigation["service_port"], 443)

    def test_service_side_string(self):
        investigation = _investigation(_vector({**_semantic("QUIC_UDP_443")}))
        self.assertEqual(investigation["service_side"], "SOURCE")

    def test_confidence_string(self):
        investigation = _investigation(_vector({**_semantic("QUIC_UDP_443")}))
        self.assertEqual(investigation["transport_confidence"], "HIGH")

    def test_missing_p5_fields_backward_compatible(self):
        investigation = _investigation(_vector({"packet_count": 100, "protocol": "udp"}))
        self.assertIsNone(investigation["transport_semantic"])
        self.assertIsNone(investigation["transport_confidence"])
        self.assertEqual(investigation["transport_reason_codes"], [])
        self.assertIsNone(investigation["service_port"])
        self.assertIsNone(investigation["service_side"])
        self.assertIsNone(investigation["c2_over_https"])

    def test_flat_string_role_accepted(self):
        investigation = _investigation(_vector({"transport_semantic": "HTTPS_AMBIGUOUS"}))
        self.assertEqual(investigation["transport_semantic"], "HTTPS_AMBIGUOUS")


class SecurityEventRowTransportSemanticsTest(unittest.TestCase):
    def test_security_event_row_keeps_fields(self):
        vector = _vector({**_semantic("QUIC_UDP_443")})
        payload = vector_security_payload(vector)
        row = {
            "id": 1,
            "event_key": payload["event_key"],
            "public_id": payload["public_id"],
            "detector": payload["detector"],
            "attack_type": payload["attack_type"],
            "attack_family": payload["attack_family"],
            "severity": payload["severity"],
            "detector_score": payload["detector_score"],
            "confidence": payload["confidence"],
            "verdict": payload["verdict"],
            "current_detector_score": payload["current_detector_score"],
            "current_verdict": payload["current_verdict"],
            "src_ip": payload["src_ip"],
            "target_ip": payload["target_ip"],
            "target_prefix": payload["target_prefix"],
            "direction": payload["direction"],
            "protocol": payload["protocol"],
            "first_seen": payload["first_seen"],
            "last_seen": payload["last_seen"],
            "network_context_json": payload["network_context_json"],
            "evidence_json": payload["evidence_json"],
            "score_components_json": payload["score_components_json"],
            "threat_intel_json": payload["threat_intel_json"],
            "investigation_json": payload["investigation_json"],
        }
        item = security_event_row(row)
        self.assertEqual(item["investigation"]["transport_semantic"], "QUIC_UDP_443")
        self.assertEqual(item["investigation"]["transport_confidence"], "HIGH")
        self.assertEqual(item["investigation"]["transport_reason_codes"], ["UDP_443", "INBOUND_SERVER_DIRECTION"])
        self.assertEqual(item["investigation"]["service_port"], 443)
        self.assertEqual(item["investigation"]["service_side"], "SOURCE")
        self.assertFalse(item["investigation"]["c2_over_https"])


if __name__ == "__main__":
    unittest.main()
