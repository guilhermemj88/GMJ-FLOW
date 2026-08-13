from __future__ import annotations

import json
import os
import sqlite3
import sys
import types
import unittest
from pathlib import Path


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
from app.services.campaign_ai import analyze_campaign, build_campaign_analysis_prompt, get_campaign_analysis  # noqa: E402
from app.services.campaign_investigation import campaign_analysis_payload, get_campaign_investigation  # noqa: E402
from app.services.security_events import ensure_security_event_schema, upsert_security_event  # noqa: E402


CAMPAIGN_ID = "GMJ-C-FFAD5239179F4676"


class CampaignInvestigationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(self.conn)
        ensure_security_event_schema(self.conn)
        self._create_local_asn_cache()
        self.previous_factory = api.BEHAVIORAL_THREAT_RUNTIME.connection_factory
        api.BEHAVIORAL_THREAT_RUNTIME.connection_factory = lambda: self.conn
        self._insert_campaign()
        self._insert_behavioral_vector()
        self.conn.commit()

    def tearDown(self) -> None:
        api.BEHAVIORAL_THREAT_RUNTIME.connection_factory = self.previous_factory
        self.conn.close()

    def _create_local_asn_cache(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE asn_info (
                asn INTEGER PRIMARY KEY,
                as_name TEXT NOT NULL DEFAULT '',
                org_name TEXT NOT NULL DEFAULT '',
                country TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                raw_json TEXT NOT NULL DEFAULT '',
                first_seen_at TEXT,
                updated_at TEXT,
                expires_at TEXT,
                last_error TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE asn_resolution_queue (
                ip TEXT PRIMARY KEY,
                asn INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'queued'
            );
            """
        )
        self.conn.executemany(
            """
            INSERT INTO asn_info (asn, as_name, org_name, country, source, updated_at, expires_at)
            VALUES (?, ?, ?, ?, 'local_rdap_cache', '2026-08-12T09:00:00Z', '2099-01-01T00:00:00Z')
            """,
            [
                (64511, "EXAMPLE-TRANSIT", "Example Transit Cached", "BR"),
                (64520, "TARGET-NET", "Target Network Cached", "BR"),
            ],
        )

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
                {"source_ip": "198.51.100.11", "source_asn": 64511, "packets": 17640, "bytes": 14037025, "flows": 1250, "pps": 58.8},
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
                network_context={"src_asn": 64511, "dst_asn": 64520},
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
        cached_source = next(item for item in payload["top_sources"] if item["source_asn"] == 64511)
        self.assertEqual("Example Transit Cached", cached_source["asn_organization"])
        self.assertEqual("BR", cached_source["country"])
        self.assertEqual("local_rdap_cache", cached_source["asn_resolution_source"])
        self.assertEqual(2, len(payload["asn_distribution"]))
        cached_asn = next(item for item in payload["asn_distribution"] if item["asn"] == 64511)
        self.assertEqual("Example Transit Cached", cached_asn["organization"])
        self.assertEqual("BR", cached_asn["country"])
        self.assertEqual(47640, payload["target_traffic"]["packets"])
        self.assertEqual(37037025, payload["target_traffic"]["bytes"])
        self.assertEqual("UDP (17)", payload["target_traffic"]["protocol"])
        self.assertEqual(53, payload["target_traffic"]["ports"][0]["port"])
        self.assertEqual(2320, payload["target_traffic"]["source_count"])
        self.assertEqual(628, payload["target_traffic"]["asn_diversity"])
        self.assertEqual(0, self.conn.execute("SELECT COUNT(*) FROM asn_resolution_queue").fetchone()[0])

    def test_metric_provenance_keeps_peak_rates_separate_from_snapshot_totals(self) -> None:
        payload = get_campaign_investigation(self.conn, CAMPAIGN_ID)
        assert payload is not None
        provenance = payload["metric_provenance"]
        self.assertEqual("peak_detection_window", provenance["pps"]["scope"])
        self.assertEqual("maximum_across_campaign_updates", provenance["pps"]["aggregation"])
        self.assertEqual("threat_campaigns.packets_per_second", provenance["pps"]["source"])
        self.assertEqual("investigation_snapshot", provenance["packets"]["scope"])
        self.assertEqual("sum_of_persisted_contributing_vector_snapshots", provenance["packets"]["aggregation"])
        self.assertEqual("2026-08-12T10:00:00Z", provenance["packets"]["first_seen"])
        self.assertEqual("2026-08-12T10:05:00Z", provenance["packets"]["last_seen"])
        self.assertEqual(300.0, provenance["packets"]["window_seconds"])
        self.assertNotEqual(provenance["pps"]["scope"], provenance["packets"]["scope"])

    def test_protocol_numbers_are_preserved_and_named(self) -> None:
        row = self.conn.execute(
            "SELECT id, feature_json FROM behavioral_attack_vectors WHERE campaign_id=?",
            (CAMPAIGN_ID,),
        ).fetchone()
        features = json.loads(row["feature_json"])
        features["protocol_distribution"] = [
            {"protocol": 47, "packets": 30000, "bytes": 20000000, "flows": 2000},
            {"protocol": 50, "packets": 17640, "bytes": 17037025, "flows": 1750},
        ]
        self.conn.execute("UPDATE behavioral_attack_vectors SET feature_json=? WHERE id=?", (json.dumps(features), row["id"]))
        payload = get_campaign_investigation(self.conn, CAMPAIGN_ID)
        assert payload is not None
        protocols = {item["protocol_number"]: item for item in payload["target_traffic"]["protocols"]}
        self.assertEqual("GRE (47)", protocols[47]["protocol_label"])
        self.assertEqual(47, protocols[47]["protocol"])
        self.assertEqual("ESP (50)", protocols[50]["protocol_label"])
        self.assertEqual(50, protocols[50]["protocol"])

    def test_cgnat_context_exposes_detector_facts_without_changing_score(self) -> None:
        row = self.conn.execute(
            "SELECT id, feature_json FROM behavioral_attack_vectors WHERE campaign_id=?",
            (CAMPAIGN_ID,),
        ).fetchone()
        features = json.loads(row["feature_json"])
        features.update(
            {
                "packets_per_second": 207.35,
                "max_host_pps": 5.2,
                "unique_src_ips": 2836,
                "unique_source_asns": 634,
                "unique_dst_ips": 321,
                "network_context": {"dst_role": "CGNAT_PUBLIC", "dst_is_cgnat": True},
                "evidence": ["diversidade de conexões é contexto esperado e não prova ataque"],
                "score_components": {"baseline": 0, "network_context": 0, "source_diversity": 30},
            }
        )
        self.conn.execute(
            "UPDATE behavioral_attack_vectors SET feature_json=?, baseline_deviation=? WHERE id=?",
            (json.dumps(features), .89, row["id"]),
        )
        payload = get_campaign_investigation(self.conn, CAMPAIGN_ID)
        assert payload is not None
        context = payload["detection_context"]
        self.assertEqual("CGNAT_PUBLIC", context["target_role"])
        self.assertEqual(207.35, context["observed_pps"])
        self.assertAlmostEqual(232.9775, context["baseline_pps"], places=4)
        self.assertEqual(.89, context["baseline_delta"])
        self.assertEqual(5.2, context["max_per_host_pps"])
        self.assertEqual(321, context["destination_count"])
        self.assertIn("abaixo do baseline", context["interpretation"])
        self.assertFalse(context["threat_intelligence_is_detector_trigger"])
        self.assertEqual(84, context["detector_score"])
        self.assertNotIn("probabilistic certainty", context["interpretation"])

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
        self.assertEqual("Example Transit Cached", event["source_asn_organization"])
        self.assertEqual("BR", event["source_country"])
        self.assertEqual("Target Network Cached", event["target_asn_organization"])
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
            "campaign_metadata", "target", "top_sources", "asn_diversity",
            "traffic_metrics", "baseline_and_per_host_context", "correlated_events",
            "threat_intelligence", "detection_correlation_evidence",
        ):
            self.assertIn(key, payload)
        self.assertEqual("peak_detection_window", payload["traffic_metrics"]["peak_rates"]["pps"]["provenance"]["scope"])
        self.assertEqual(4.2, payload["baseline_and_per_host_context"]["baseline_delta"])
        self.assertEqual("GREYNOISE", payload["threat_intelligence"]["matches"]["items"][0]["provider"])
        self.assertEqual("Example Transit Cached", payload["top_sources"]["items"][1]["asn_organization"])
        self.assertFalse(payload["detection_correlation_evidence"]["threat_intelligence_is_detector_trigger"])
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
        self.assertEqual("campaign-analysis/v2", state["analysis_version"])
        request_audit = self.conn.execute(
            "SELECT campaign_vector_json FROM threat_engine_audit WHERE detector='campaign_ai' AND event_type='AI_REQUEST' ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        request_diagnostic = json.loads(request_audit)
        self.assertEqual({"prompt_chars", "approx_tokens", "sections"}, set(request_diagnostic))
        self.assertNotIn(CAMPAIGN_ID, request_audit)
        response_audit = self.conn.execute(
            "SELECT groq_result_json FROM threat_engine_audit WHERE detector='campaign_ai' AND event_type='AI_RESPONSE' ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        self.assertNotIn("Campanha coordenada requer validação operacional.", response_audit)

    def test_campaign_ai_payload_applies_all_section_limits_and_counts(self) -> None:
        investigation = get_campaign_investigation(self.conn, CAMPAIGN_ID)
        assert investigation is not None
        investigation["top_sources"] = [
            {"source_ip": f"198.51.100.{index}", "source_asn": 64500 + index, "packets": 1000 - index}
            for index in range(45)
        ]
        investigation["asn_distribution"] = [
            {"asn": 64500 + index, "organization": f"AS {index}", "sources": 1, "percentage": 1.0}
            for index in range(45)
        ]
        investigation["target_traffic"]["ports"] = [
            {"port": 1000 + index, "packets": 100 - index} for index in range(35)
        ]
        investigation["target_traffic"]["protocols"] = [
            {"protocol": index, "protocol_label": f"PROTO-{index}", "packets": index}
            for index in range(25)
        ]
        investigation["correlated_events"] = [
            {"id": index, "public_id": f"GMJ-E-{index}", "event_type": "CARPET_BOMBING"}
            for index in range(15)
        ]
        source_matches = {
            f"198.51.100.{index}": [{"provider": "GREYNOISE", "classification": "scanner"}]
            for index in range(25)
        }
        investigation["campaign"]["threat_intel"]["source_intel"]["sources"] = source_matches
        investigation["detection_context"]["detector_facts"] = [f"fact-{index}" for index in range(30)]
        investigation["detection_correlation_evidence"]["contributing_vectors"] = [
            {"detector": f"detector-{index}", "detector_facts": [f"contributor-fact-{index}"]}
            for index in range(15)
        ]

        payload = campaign_analysis_payload(investigation)
        expected = {
            "top_sources": (payload["top_sources"], 20, 2320),
            "asn_distribution": (payload["asn_diversity"]["distribution"], 20, 628),
            "ports": (payload["target"]["ports"], 20, 35),
            "correlated_events": (payload["correlated_events"], 10, 15),
            "threat_intelligence": (payload["threat_intelligence"]["matches"], 20, 25),
            "detector_facts": (payload["detection_correlation_evidence"]["detector_facts"], 20, 45),
            "contributors": (payload["detection_correlation_evidence"]["contributors"], 10, 15),
        }
        for name, (section, included, total) in expected.items():
            with self.subTest(section=name):
                self.assertEqual(included, section["included_count"])
                self.assertEqual(included, len(section["items"]))
                self.assertEqual(total, section["total_count"])
        self.assertEqual(25, payload["target"]["protocols"]["included_count"])
        self.assertEqual(25, payload["target"]["protocols"]["total_count"])

    def test_campaign_prompt_hard_cap_preserves_valid_json_and_core_metrics(self) -> None:
        investigation = get_campaign_investigation(self.conn, CAMPAIGN_ID)
        assert investigation is not None
        investigation["top_sources"] = [
            {
                "source_ip": f"198.51.100.{index}",
                "asn_organization": "X" * 5000,
                "packets": 1000 - index,
            }
            for index in range(100)
        ]
        investigation["detection_context"]["detector_facts"] = ["Y" * 5000 for _ in range(100)]
        prompt, bounded_payload, diagnostic = build_campaign_analysis_prompt(investigation, max_prompt_chars=4000)
        self.assertLessEqual(len(prompt), 4000)
        self.assertEqual(len(prompt), diagnostic["prompt_chars"])
        encoded = prompt.split("CAMPAIGN_JSON_BEGIN\n", 1)[1].rsplit("\nCAMPAIGN_JSON_END", 1)[0]
        parsed = json.loads(encoded)
        self.assertEqual(bounded_payload, parsed)
        self.assertEqual(CAMPAIGN_ID, parsed["campaign_metadata"]["campaign_id"])
        self.assertEqual(158.8, parsed["traffic_metrics"]["peak_rates"]["pps"]["value"])
        self.assertEqual(47640, parsed["traffic_metrics"]["snapshot_totals"]["packets"]["value"])
        self.assertEqual(2320, parsed["top_sources"]["total_count"])

    def test_campaign_ai_code_has_no_automatic_mitigation_or_flowspec_side_effect(self) -> None:
        source = Path(sys.modules[analyze_campaign.__module__].__file__).read_text(encoding="utf-8")
        for forbidden in ("execute_flowspec", "apply_mitigation", "announce_bgp", "subprocess"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
