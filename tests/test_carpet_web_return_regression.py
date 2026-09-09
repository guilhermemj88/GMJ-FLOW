"""Regressão do evento real GMJ-20260830-44B52D0E27 (CARPET_BOMBING).

O evento foi historicamente classificado como CONFIRMED_ATTACK (detector 100),
mas a assinatura observada (web_return_share ~80%, src 443 dominante,
ACK/PSH+ACK dominante, baixo pps absoluto, baixo pps por host, milhares de
portas efêmeras e muitas origens/destinos) é compatível com retorno web
distribuído — e não deve ser suficiente para CONFIRMED_ATTACK apenas por
distribuição/persistência/low_per_host_rate.

O Event ID é apenas fixture de regressão: NÃO existe hardcode dele na lógica.
"""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavioral_detection import (  # noqa: E402
    CARPET_BOMBING,
    EXPECTED_DISTRIBUTED_TRAFFIC,
    SUSPICIOUS_DISTRIBUTED_TRAFFIC,
    TI_INFLUENCE_ADVISORY_ONLY,
    TI_INFLUENCE_NORMAL,
    TI_INFLUENCE_REDUCED,
    apply_ti_influence,
    threat_intel_influence,
)
from app.services.carpet_replay import replay_carpet_decision  # noqa: E402

EVENT_ID = "GMJ-20260830-44B52D0E27"


def _event_features() -> dict:
    """Janela de 60s do evento real GMJ-20260830-44B52D0E27."""
    return {
        "aggregate_pps": 145.5,
        # 8728 pacotes em 60s com pacote médio ~1500 bytes (ordem de ~1.7 Mbps).
        "aggregate_bps": 1_745_600.0,
        "unique_destinations": 128,
        "unique_sources": 1542,
        "max_host_pps": 3.9,
        "persistent_windows": 2,
        "packets": 8728,
        "baseline_deviation": 1.14,
        "web_return_share": 0.804,
        "udp_quic_share": 0.0,
        "tcp_ack_ratio": 0.90,
        "tcp_syn_ratio": 0.0,
        "dst_port_entropy": 0.6,
        "unique_dst_ports": 4681,
        "top_src_port": 443,
        "top_src_port_share": 0.755,
        "target_cgnat_share": 0.0,
        "target_downstream_isp_share": 0.0,
    }


class CarpetWebReturnRegressionTest(unittest.TestCase):
    def test_real_event_is_expected_distributed_traffic_not_confirmed_attack(self):
        result = replay_carpet_decision(_event_features())
        self.assertEqual(EXPECTED_DISTRIBUTED_TRAFFIC, result["traffic_classification"])
        self.assertNotEqual("CONFIRMED_ATTACK", result["verdict"])
        self.assertEqual("INFO", result["verdict"])
        self.assertEqual("LOW", result["severity"])
        self.assertLessEqual(result["detector_score"], 54)
        self.assertIn("LIKELY_WEB_RETURN_TRAFFIC", result["reason_codes"])
        self.assertIn("ABSOLUTE_VOLUME_TOO_LOW", result["reason_codes"])
        self.assertTrue(result["web_return_likely"])
        self.assertTrue(result["below_absolute_floor"])

    def test_distribution_persistence_and_low_per_host_rate_alone_do_not_confirm(self):
        """Sem WEB_RETURN (src 80/443 + ACK) e com volume absoluto baixo, a
        distribuição/persistência/low_per_host_rate NÃO pode confirmar ataque."""
        features = _event_features()
        features["web_return_share"] = 0.05
        features["tcp_ack_ratio"] = 0.1
        result = replay_carpet_decision(features)
        self.assertNotEqual("CONFIRMED_ATTACK", result["verdict"])
        self.assertEqual(SUSPICIOUS_DISTRIBUTED_TRAFFIC, result["traffic_classification"])
        self.assertIn("ABSOLUTE_VOLUME_TOO_LOW", result["reason_codes"])

    def test_src443_alone_is_not_an_expected_web_return(self):
        """src443 dominante sem ACK/PSH+ACK estabelecido não vira EXPECTED."""
        features = _event_features()
        features["tcp_ack_ratio"] = 0.1
        features["tcp_syn_ratio"] = 0.0
        result = replay_carpet_decision(features)
        self.assertNotEqual(EXPECTED_DISTRIBUTED_TRAFFIC, result["traffic_classification"])

    def test_ti_influence_is_advisory_only_for_expected_web_return(self):
        influence, reason = threat_intel_influence(CARPET_BOMBING, EXPECTED_DISTRIBUTED_TRAFFIC)
        self.assertEqual(TI_INFLUENCE_ADVISORY_ONLY, influence)
        self.assertEqual("expected_distributed_traffic", reason)
        self.assertEqual(0, apply_ti_influence(25, influence))

    def test_ti_influence_reduced_for_suspicious_distributed_traffic(self):
        influence, reason = threat_intel_influence(CARPET_BOMBING, SUSPICIOUS_DISTRIBUTED_TRAFFIC)
        self.assertEqual(TI_INFLUENCE_REDUCED, influence)
        self.assertEqual("suspicious_distributed_traffic", reason)
        self.assertEqual(2, apply_ti_influence(25, influence))

    def test_ti_influence_normal_for_confirmed_carpet_evidence(self):
        influence, _ = threat_intel_influence(CARPET_BOMBING, "CONFIRMED_ATTACK")
        self.assertEqual(TI_INFLUENCE_NORMAL, influence)
        self.assertEqual(25, apply_ti_influence(25, influence))


if __name__ == "__main__":
    unittest.main()
