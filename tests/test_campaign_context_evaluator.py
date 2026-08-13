from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.campaign_ai import CAMPAIGN_AI_SYSTEM_PROMPT  # noqa: E402
from app.services.campaign_context_evaluator import (  # noqa: E402
    campaign_context_thresholds,
    evaluate_campaign_context,
)
from app.services.security_event_ai import SECURITY_AI_SYSTEM_PROMPT  # noqa: E402


class CampaignContextEvaluatorTest(unittest.TestCase):
    def campaign(self, *, role: str = "CGNAT_PUBLIC", pps: float = 145.0) -> dict:
        return {
            "campaign_id": "GMJ-C-CONTEXT",
            "classification": "CARPET_BOMBING",
            "coordination_score": 71,
            "packets_per_second": pps,
            "bits_per_second": 8_000_000.0,
            "unique_sources": 2371,
            "unique_source_asns": 628,
            "recurrence_count": 4,
            "first_seen": "2026-08-13T10:00:00Z",
            "last_seen": "2026-08-13T10:05:00Z",
            "features": {"target_role": role},
            "threat_intel": {},
        }

    def low_rate_context(self, *, role: str = "CGNAT_PUBLIC") -> dict:
        return {
            "target_role": role,
            "observed_pps": 145.0,
            "observed_bps": 8_000_000.0,
            "baseline_pps": 160.0,
            "baseline_bps": 9_000_000.0,
            "baseline_delta": 0.91,
            "max_per_host_pps": 3.7,
            "max_per_host_bps": 200_000.0,
            "source_count": 2371,
            "asn_diversity": 628,
        }

    def test_cgnat_normal_is_observed_low_confidence_high_fp(self) -> None:
        result = evaluate_campaign_context(self.campaign(), detection_context=self.low_rate_context())
        self.assertEqual("observed", result["state"])
        self.assertEqual("low", result["attack_confidence"])
        self.assertEqual("high", result["false_positive_risk"])
        self.assertFalse(result["should_analyze_ai"])
        self.assertFalse(result["external_lookups_performed"])

    def test_low_rate_cgnat_with_relevant_malicious_top_source_is_suspicious(self) -> None:
        result = evaluate_campaign_context(
            self.campaign(),
            detection_context=self.low_rate_context(),
            top_sources=[{
                "source_ip": "198.51.100.10",
                "packets": 5000,
                "threat_intelligence_classification": "malicious",
                "threat_intelligence_provider": "GREYNOISE",
            }],
        )
        self.assertEqual("suspicious", result["state"])
        self.assertTrue(result["should_analyze_ai"])
        self.assertTrue(result["signals"]["top_source_malicious"])

    def test_one_malicious_source_among_thousands_does_not_corroborate(self) -> None:
        campaign = self.campaign()
        campaign["threat_intel"] = {
            "source_intel": {
                "matched_source_count": 1,
                "sources": {"198.51.100.10": [{"classification": "malicious", "provider": "GREYNOISE"}]},
            }
        }
        result = evaluate_campaign_context(campaign, detection_context=self.low_rate_context())
        self.assertNotEqual("corroborated", result["state"])
        self.assertEqual("low", result["attack_confidence"])
        self.assertTrue(result["signals"]["single_match_is_proportionally_weak"])

    def test_multiple_malicious_top_sources_increase_confidence(self) -> None:
        sources = [
            {"source_ip": f"198.51.100.{index}", "packets": 5000 - index, "threat_intelligence_classification": "scanner"}
            for index in range(1, 4)
        ]
        result = evaluate_campaign_context(
            self.campaign(), detection_context=self.low_rate_context(), top_sources=sources
        )
        self.assertEqual("suspicious", result["state"])
        self.assertEqual("medium", result["attack_confidence"])
        self.assertEqual(3, result["metrics"]["malicious_matches_among_top_sources"])

    def test_correlated_security_event_promotes_campaign_to_corroborated(self) -> None:
        result = evaluate_campaign_context(
            self.campaign(),
            detection_context=self.low_rate_context(),
            correlated_events=[{"public_id": "GMJ-20260813-000001", "event_type": "PORT_SCAN_HORIZONTAL"}],
        )
        self.assertEqual("corroborated", result["state"])
        self.assertEqual("high", result["attack_confidence"])
        self.assertEqual(1, result["metrics"]["correlated_security_event_count"])

    def test_strong_baseline_delta_and_pps_are_suspicious_without_ti(self) -> None:
        context = self.low_rate_context()
        context.update({"observed_pps": 1800.0, "baseline_pps": 500.0, "baseline_delta": 3.6})
        result = evaluate_campaign_context(self.campaign(pps=1800.0), detection_context=context)
        self.assertEqual("suspicious", result["state"])
        self.assertTrue(result["signals"]["strong_traffic_deviation"])

    def test_customer_and_infrastructure_use_non_cgnat_false_positive_context(self) -> None:
        for role in ("CUSTOMER", "INFRASTRUCTURE"):
            with self.subTest(role=role):
                result = evaluate_campaign_context(
                    self.campaign(role=role), detection_context=self.low_rate_context(role=role)
                )
                self.assertEqual(role, result["context"]["target_role"])
                self.assertFalse(result["context"]["is_cgnat_public"])
                self.assertEqual("medium", result["false_positive_risk"])

    def test_behavioral_score_is_separate_from_attack_confidence(self) -> None:
        result = evaluate_campaign_context(self.campaign(), detection_context=self.low_rate_context())
        self.assertEqual(71.0, result["behavioral_score"])
        self.assertEqual("low", result["attack_confidence"])
        self.assertIn("não é probabilidade", result["score_semantics"])

    def test_context_thresholds_are_configurable_and_bounded(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                {
                    "cgnat_min_pps_for_suspicious": 1000.0,
                    "cgnat_min_bps_for_suspicious": 100_000_000.0,
                    "cgnat_min_baseline_ratio": 2.0,
                    "cgnat_min_per_host_pps": 10.0,
                    "cgnat_min_per_host_bps": 10_000_000.0,
                    "ti_min_malicious_ratio": 0.01,
                    "ti_min_top_malicious": 3,
                },
                campaign_context_thresholds(),
            )
        with patch.dict(os.environ, {"GMJFLOW_CAMPAIGN_CGNAT_MIN_PPS_FOR_SUSPICIOUS": "2500"}):
            self.assertEqual(2500.0, campaign_context_thresholds()["cgnat_min_pps_for_suspicious"])
        with patch.dict(os.environ, {"GMJFLOW_CAMPAIGN_CGNAT_MIN_BASELINE_RATIO": "999999"}):
            self.assertEqual(1000.0, campaign_context_thresholds()["cgnat_min_baseline_ratio"])

    def test_ai_prompts_require_portuguese_and_preserve_advisory_semantics(self) -> None:
        for prompt in (CAMPAIGN_AI_SYSTEM_PROMPT, SECURITY_AI_SYSTEM_PROMPT):
            self.assertIn("português do Brasil", prompt)
            self.assertIn("mitigação automática", prompt)


if __name__ == "__main__":
    unittest.main()
