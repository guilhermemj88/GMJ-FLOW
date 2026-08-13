from __future__ import annotations

import json
import os
import sqlite3
import sys
import types
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

try:
    import fastapi  # noqa: F401
except ImportError:
    fastapi_stub = types.ModuleType("fastapi")

    class APIRouter:
        def __init__(self, *args, **kwargs):
            pass

        def get(self, *args, **kwargs):
            return lambda function: function

        def post(self, *args, **kwargs):
            return lambda function: function

    class HTTPException(Exception):
        def __init__(self, status_code, detail=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    def Query(default=None, **_kwargs):
        return default

    fastapi_stub.APIRouter = APIRouter
    fastapi_stub.FastAPI = APIRouter
    fastapi_stub.HTTPException = HTTPException
    fastapi_stub.Query = Query
    sys.modules["fastapi"] = fastapi_stub

from app.api import threat_engine as api  # noqa: E402
from app.services.behavioral_detection import AttackVector, ensure_behavioral_schema  # noqa: E402
from app.services.campaign_ai import analyze_campaign, get_campaign_analysis  # noqa: E402
from app.services.campaign_investigation import campaign_analysis_payload, get_campaign_investigation  # noqa: E402
from app.services.security_events import ensure_security_event_schema, upsert_security_event  # noqa: E402


CAMPAIGN_ID = "GMJ-C-FFAD5239179F4676"


class CampaignInvestigationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(self.conn)
        ensure_security_event_schema(self.conn)
        self.previous_factory = api.BEHAVIORAL_THREAT_RUNTIME.connection_factory
        api.BEHAVIORAL_THREAT_RUNTIME.connection_factory = lambda: self.conn
        self._insert_campaign()
        self._insert_behavioral_vector()
        self.conn.commit()

    def tearDown(self) -> None:
        api.BEHAVIORAL_THREAT_RUNTIME.connection_factory = self.previous_factory
        self.conn.close()

    def _insert_campaign(self, campaign_id: str = CAMPAIGN_ID, *, threat_intel: dict | None = None) -> None:
        features = {
            "attack_family": "FLOOD_FAMILY",
            "concurrent_sources": 2320,
            "source_asn_diversity": 628,
            "persistence_satisfied": True,
            "target_correlation": True,
            "temporal_correlation": 0.75,
            "protocol_similarity": 1.0,
            "attack_types": ["CARPET_BOMBING"],
        }
        persisted_intel = threat_intel if threat_intel is not None else {
            "matches": 1,
            "source_intel": {
                "lookup_count": 2,
                "matched_source_count": 1,
                "classifications": ["malicious"],
                "intel_sources": ["GREYNOISE"],
                "sources": {
                    "198.51.100.10": [{
                        "provider": "GREYNOISE",
                        "classification": "malicious",
                        "organization": "Hostile Cloud",
                        "tags": ["scanner"],
                        "last_seen": "2026-08-12T09:50:00Z",
                    }],
                },
            },
            "target_campaign_intel": {"matches": 0, "observations": []},
        }
        self.conn.execute(
            """
            INSERT INTO threat_campaigns (
                campaign_id, campaign_key, target_prefix, classification, coordination_score,
                unique_sources, unique_source_asns, packets_per_second, bits_per_second,
                flows_per_second, first_seen, last_seen, feature_json, threat_intel_json,
                intel_sources_json, decision_source, status, recurrence_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                campaign_id, f"key-{campaign_id}", "179.189.82.0/23", "CARPET_BOMBING", 71,
                2320, 628, 158.8, 987654.0, 12.5,
                "2026-08-12T10:00:00Z", "2026-08-12T10:05:00Z",
                json.dumps(features), json.dumps(persisted_intel), json.dumps(["GREYNOISE"] if persisted_intel else []),
                "GMJ_FLOW", "active", 3, "2026-08-12T10:00:00Z", "2026-08-12T10:05:00Z",
            ),
        )

    def _insert_behavioral_vector(self) -> None:
        features = {
            "packet_count": 47640,
            "byte_count": 37037025,
            "flow_count": 3750,
            "packets_per_second": 158.8,
            "bits_per_second": 987654,
            "unique_src_ips": 2320,
            "unique_source_asns": 628,
            "top_source_details": [
                {"source_ip": "198.51.100.10", "source_asn": 64510, "packets": 30000, "bytes": 23000000, "flows": 2500, "pps": 100},
                {"source_ip": "198.51.100.11", "source_asn": 64511, "packets": 17640, "bytes": 14037025, "flows": 1250, "pps": 58.8, "asn_organization": "Example Transit"},
            ],
            "protocol_distribution": [{"protocol": "udp", "packets": 47640, "bytes": 37037025, "flows": 3750}],
            "top_destination_port_details": [{"port": 53, "packets": 47640, "bytes": 37037025, "flows": 3750}],
        }
        vector_intel = {
            "source_intel": {
                "matched_source_count": 1,
                "sources": {
                    "198.51.100.10": [{
                        "provider": "GREYNOISE", "classification": "malicious", "organization": "Hostile Cloud",
                    }]
                },
            }
        }
        self.conn.execute(
            """
            INSERT INTO behavioral_attack_vectors (
                event_key, attack_type, detector, detector_score, confidence, src_ip,
                target_ip, target_prefix, direction, window_seconds, baseline_deviation,
                first_seen, last_seen, feature_json, threat_intel_json, intel_sources_json,
                external_correlation, compromised_host_score, campaign_id, decision_source,
                status, recurrence_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "vector-key", "CARPET_BOMBING", "carpet_bombing_detector", 84, .91, "",
                "", "179.189.82.0/23", "INBOUND", 300, 4.2,
                "2026-08-12T10:00:00Z", "2026-08-12T10:05:00Z", json.dumps(features),
                json.dumps(vector_intel), json.dumps(["GREYNOISE"]), 1, 0, CAMPAIGN_ID,
                "GMJ_FLOW", "active", 1, "2026-08-12T10:00:00Z", "2026-08-12T10:05:00Z",
            ),
        )

    def _insert_correlated_event(self) -> int:
        return upsert_security_event(
            self.conn,
            AttackVector(
                attack_type="CARPET_BOMBING",
                detector="carpet_bombing_detector",
                detector_score=84,
                confidence=.91,
                first_seen="2026-08-12T10:00:00Z",
                last_seen="2026-08-12T10:05:00Z",
                target_prefix="179.189.82.0/23",
                direction="INBOUND",
                protocol="udp",
                campaign_id=CAMPAIGN_ID,
                features={
                    "packet_count": 47640,
                    "byte_count": 37037025,
                    "unique_src_ips": 2320,
                    "unique_source_asns": 628,
                    "packets_per_second": 158.8,
                    "bits_per_second": 987654,
                },
                threat_intel={
                    "source_intel": {
                        "matched_source_count": 1,
                        "intel_sources": ["GREYNOISE"],
                        "classifications": ["malicious"],
                    }
                },
            ),
        )

    def test_campaign_without_correlated_events_keeps_its_own_data(self) -> None:
        table_row = api.list_campaigns(limit=100)["items"][0]
        payload = api.get_security_campaign(CAMPAIGN_ID)
        campaign = payload["campaign"]
        self.assertEqual([], payload["correlated_events"])
        self.assertEqual([], payload["events"])
        self.assertEqual("CARPET_BOMBING", campaign["classification"])
        self.assertEqual("FLOOD_FAMILY", campaign["family"])
        self.assertEqual("179.189.82.0/23", campaign["target"])
        self.assertEqual(71, campaign["coordination_score"])
        self.assertEqual(2320, campaign["unique_sources"])
        self.assertEqual(628, campaign["unique_source_asns"])
        self.assertEqual(158.8, campaign["packets_per_second"])
        self.assertEqual(987654.0, campaign["bits_per_second"])
        self.assertEqual(300.0, campaign["duration_seconds"])
        self.assertEqual("satisfied", campaign["persistence"])
        self.assertEqual("campaign_engine", campaign["detector"])
        self.assertFalse(payload["data_sources"]["external_lookups_performed"])
        for field in (
            "campaign_id", "classification", "target_prefix", "coordination_score",
            "unique_sources", "unique_source_asns", "packets_per_second", "bits_per_second",
            "first_seen", "last_seen",
        ):
            self.assertEqual(table_row[field], campaign[field])

    def test_top_sources_asns_and_target_traffic_use_persisted_campaign_vectors(self) -> None:
        payload = get_campaign_investigation(self.conn, CAMPAIGN_ID)
        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual(2, len(payload["top_sources"]))
        self.assertEqual("198.51.100.10", payload["top_sources"][0]["source_ip"])
        self.assertEqual(64510, payload["top_sources"][0]["source_asn"])
        self.assertEqual("Hostile Cloud", payload["top_sources"][0]["asn_organization"])
        self.assertEqual("malicious", payload["top_sources"][0]["threat_intelligence_classification"])
        self.assertEqual(2, len(payload["asn_distribution"]))
        self.assertEqual(47640, payload["target_traffic"]["packets"])
        self.assertEqual(37037025, payload["target_traffic"]["bytes"])
        self.assertEqual("udp", payload["target_traffic"]["protocol"])
        self.assertEqual(53, payload["target_traffic"]["ports"][0]["port"])
        self.assertEqual(2320, payload["target_traffic"]["source_count"])
        self.assertEqual(628, payload["target_traffic"]["asn_diversity"])

    def test_campaign_with_correlated_event_exposes_canonical_event_as_additional_section(self) -> None:
        event_id = self._insert_correlated_event()
        self.conn.commit()
        payload = api.get_security_campaign(CAMPAIGN_ID)
        self.assertEqual(1, len(payload["correlated_events"]))
        event = payload["correlated_events"][0]
        self.assertEqual(event_id, event["id"])
        self.assertTrue(event["public_id"].startswith("GMJ-20260812-"))
        self.assertEqual("CARPET_BOMBING", event["event_type"])
        self.assertEqual(84, event["score"])
        self.assertEqual("179.189.82.0/23", event["target"])
        self.assertEqual(2320, event["source_count"])
        self.assertEqual(["GREYNOISE"], event["threat_intelligence"]["providers"])
        # The campaign summary is still sourced from threat_campaigns.
        self.assertEqual(71, payload["campaign"]["coordination_score"])

    def test_campaign_without_enrichment_has_explicit_empty_summary(self) -> None:
        campaign_id = "GMJ-C-NO-ENRICHMENT"
        self._insert_campaign(campaign_id, threat_intel={})
        self.conn.commit()
        payload = get_campaign_investigation(self.conn, campaign_id)
        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertFalse(payload["campaign"]["enrichment_summary"]["available"])
        self.assertEqual({}, payload["campaign"]["threat_intel"])

    def test_campaign_with_greynoise_enrichment_is_returned_from_persisted_snapshot(self) -> None:
        payload = get_campaign_investigation(self.conn, CAMPAIGN_ID)
        self.assertIsNotNone(payload)
        assert payload is not None
        summary = payload["campaign"]["enrichment_summary"]
        self.assertTrue(summary["available"])
        self.assertEqual(1, summary["matched_sources"])
        self.assertIn("GREYNOISE", summary["providers"])
        self.assertEqual("GREYNOISE", payload["top_sources"][0]["threat_intelligence_provider"])

    def test_campaign_ai_payload_and_analysis_are_separate_and_advisory_only(self) -> None:
        self._insert_correlated_event()
        self.conn.commit()
        investigation = get_campaign_investigation(self.conn, CAMPAIGN_ID)
        self.assertIsNotNone(investigation)
        assert investigation is not None
        payload = campaign_analysis_payload(investigation)
        for key in (
            "campaign_metadata", "target", "coordination_score", "top_sources", "asn_diversity",
            "traffic_metrics", "correlated_events", "threat_intelligence", "detection_correlation_evidence",
        ):
            self.assertIn(key, payload)
        self.assertFalse(payload["analysis_constraints"]["automatic_mitigation_enabled"])
        self.assertFalse(payload["analysis_constraints"]["external_lookups_performed"])

        prompts: list[str] = []

        def executor(_conn, function_key, prompt, **_kwargs):
            prompts.append(prompt)
            self.assertEqual("security_campaign_analysis", function_key)
            return {
                "ok": True,
                "provider": "GROQ",
                "model": "test-model",
                "structured": {
                    "summary": "Campanha coordenada requer validação operacional.",
                    "confidence": "HIGH",
                    "assessment": "Provável campanha hostil",
                    "why_detected": ["coordenação e diversidade de origem"],
                    "important_sources": ["198.51.100.10"],
                    "threat_intelligence_findings": ["GreyNoise é enrichment persistido"],
                    "possible_false_positive_factors": ["tráfego distribuído legítimo"],
                    "recommended_checks": ["validar o destino"],
                    "recommended_actions": ["continuar monitorando"],
                    "mitigation_advisory": "Decisão humana; sem execução automática.",
                    "limitations": ["snapshot agregado"],
                },
            }

        first = analyze_campaign(self.conn, CAMPAIGN_ID, executor=executor)
        second = analyze_campaign(self.conn, CAMPAIGN_ID, executor=executor)
        state = get_campaign_analysis(self.conn, CAMPAIGN_ID)
        self.assertTrue(first["ok"])
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(1, len(prompts))
        self.assertIn(CAMPAIGN_ID, prompts[0])
        self.assertIn("GREYNOISE", prompts[0])
        self.assertFalse(first["mitigation_executed"])
        self.assertTrue(first["advisory_only"])
        self.assertEqual("valid", state["analysis_status"])
        self.assertEqual("campaign-analysis/v1", state["analysis_version"])


if __name__ == "__main__":
    unittest.main()
