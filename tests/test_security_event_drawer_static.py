"""Static tests for the Security Event Drawer UX (snapshot vs accumulated).

Verifies, at the source level, that the frontend now separates the detector
snapshot from the accumulated event, keeps Detector Score apart from Threat
Score, handles Scan Family baseline correctly, and uses explicit labels for
recurrence, external reputation, target, mitigation shadow and lineage.
"""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "frontend" / "threat-intelligence.js").read_text(encoding="utf-8")


class SecurityEventDrawerStaticTest(unittest.TestCase):
    def test_snapshot_vs_accumulated_helpers_exist(self):
        self.assertIn("renderSnapshotVsAccumulated", JS)
        self.assertIn("Janela que confirmou a detecção", JS)
        self.assertIn("Evento acumulado", JS)

    def test_scan_family_detection(self):
        self.assertIn("function isScanFamily", JS)
        for attack in ("PORT_SCAN_HORIZONTAL", "PORT_SCAN_VERTICAL", "NETWORK_SWEEP", "LOW_SLOW_SCAN"):
            self.assertIn(attack, JS)

    def test_scan_family_baseline_not_primary(self):
        # O baseline volumétrico para scan deve ser marcado como não principal.
        self.assertIn("Sinal principal da detecção", JS)
        self.assertIn("Não aplicável como sinal principal para esta família", JS)

    def test_detector_score_separated_from_threat_score(self):
        self.assertIn("renderDetectionScoreBlock", JS)
        self.assertIn("Detector score:", JS)
        self.assertIn("Mede a força da evidência da assinatura", JS)
        self.assertIn("Threat Score", JS)
        self.assertIn("Mede risco/prioridade contextual", JS)

    def test_recurrence_badge(self):
        self.assertIn("renderRecurrenceBadge", JS)
        self.assertIn("RECORRENTE", JS)

    def test_external_reputation_empty_keeps_local_detection(self):
        self.assertIn("renderExternalReputation", JS)
        self.assertIn("Sem dados disponíveis.", JS)
        self.assertIn("Detecção local", JS)
        self.assertIn("não invalida a evidência comportamental local", JS)

    def test_campaign_and_anomaly_explicit_labels(self):
        self.assertIn("Não correlacionada", JS)
        self.assertIn("Sem anomalia associada", JS)

    def test_target_aggregated_for_horizontal_scan(self):
        self.assertIn("renderSecurityTarget", JS)
        self.assertIn("Alvo agregado", JS)
        self.assertIn("Múltiplos clientes/destinos", JS)

    def test_mitigation_shadow_labeling(self):
        self.assertIn("Mitigation candidate", JS)
        self.assertIn("WOULD_BLOCK", JS)
        self.assertIn("WOULD_NOT_BLOCK", JS)
        self.assertIn("Advisory only", JS)

    def test_timeline_scope_disclaimer(self):
        self.assertIn("não representa toda a duração acumulada", JS)


if __name__ == "__main__":
    unittest.main()
