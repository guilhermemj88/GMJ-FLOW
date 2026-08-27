from __future__ import annotations

import os
import sqlite3
import sys
import unittest
from unittest.mock import patch


ROOT = os.path.dirname(os.path.dirname(__file__))
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from app.services.behavioral_detection import AttackVector, ensure_behavioral_schema  # noqa: E402
from app.services.security_event_ai import (  # noqa: E402
    analyze_security_event,
    get_security_event_analysis,
    structured_analysis_payload,
)
from app.services.security_event_investigation import _event_filters, event_evidence, event_sources, event_traffic  # noqa: E402
from app.services.security_events import ensure_security_event_schema, find_security_event, security_event_row, upsert_security_event  # noqa: E402


class SecurityEventInvestigationTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_behavioral_schema(self.conn)
        ensure_security_event_schema(self.conn)
        self.vector = AttackVector(
            attack_type="DISTRIBUTED_UDP_FLOOD",
            detector="udp_flood",
            detector_score=78,
            confidence=.82,
            first_seen="2026-08-12T10:00:00Z",
            last_seen="2026-08-12T10:01:00Z",
            target_prefix="179.189.80.0/22",
            direction="INBOUND",
            protocol="udp",
            window_seconds=60,
            network_context={"src_role": "EXTERNAL", "dst_role": "CUSTOMER", "sensor": "edge-1"},
            features={
                "packet_count": 6000,
                "byte_count": 900000,
                "flow_count": 120,
                "packets_per_second": 100,
                "bits_per_second": 120000,
                "flows_per_second": 2,
                "unique_sources": 2,
                "unique_dst_ips": 4,
                "unique_source_asns": 2,
                "unique_src_ports": 2,
                "unique_dst_ports": 2,
                "persistent_windows": 6,
                "observation_samples": 12,
                "top_source_details": [
                    {"source_ip": "198.51.100.1", "source_asn": 64501, "packets": 4000, "bytes": 600000, "flows": 80, "pps": 66.67, "share": 66.67},
                    {"source_ip": "198.51.100.2", "source_asn": 64502, "packets": 2000, "bytes": 300000, "flows": 40, "pps": 33.33, "share": 33.33},
                ],
                "top_destination_port_details": [{"port": 53, "packets": 6000, "bytes": 900000, "flows": 120}],
                "top_source_port_details": [{"port": 1900, "packets": 6000, "bytes": 900000, "flows": 120}],
                "protocol_distribution": [{"protocol": "udp", "protocol_number": 17, "packets": 6000, "bytes": 900000, "flows": 120}],
            },
            evidence=["6000 pacotes UDP em 60 segundos", "2 fontes e 2 ASNs"],
            score_components={"volume": 30, "source_diversity": 8, "persistence": 20},
            threat_intel={
                "source_intel": {
                    "lookup_count": 2,
                    "matched_source_count": 1,
                    "sources": {
                        "198.51.100.1": [{
                            "provider": "GREYNOISE", "classification": "malicious",
                            "organization": "Example ASN", "country": "US", "tags": ["Mirai"],
                        }],
                    },
                },
            },
        )
        self.event_id = upsert_security_event(self.conn, self.vector)
        self.conn.commit()
        self.event = security_event_row(self.conn.execute("SELECT * FROM security_events WHERE id=?", (self.event_id,)).fetchone())

    def tearDown(self):
        self.conn.close()

    def test_detail_snapshot_contains_bounded_investigation_data(self):
        self.assertTrue(self.event["event_id"].startswith("GMJ-20260812-"))
        self.assertEqual(900000, self.event["bytes"])
        self.assertEqual(2, len(self.event["investigation"]["top_sources"]))
        self.assertEqual(20, self.event["investigation"]["detection_evidence"]["configured_thresholds"]["distributed_sources"])
        self.assertIn("6000 pacotes", self.event["detection_reason"])
        self.assertEqual(self.event_id, find_security_event(self.conn, self.event["event_id"])["id"])

    def test_sources_are_bounded_sortable_and_merge_persisted_intel(self):
        seen = []

        def query(context, sql, params):
            seen.append((context, sql, params))
            return [
                {"source_ip": "198.51.100.2", "source_asn": 64502, "packets": 2000, "bytes": 900000, "flows": 40, "pps": 33.3},
                {"source_ip": "198.51.100.1", "source_asn": 64501, "packets": 4000, "bytes": 600000, "flows": 80, "pps": 66.7},
            ]

        result = event_sources(self.event, sort_by="bytes", limit=500, query_executor=query)
        self.assertEqual(100, result["limit"])
        self.assertEqual("198.51.100.2", result["items"][0]["source_ip"])
        malicious = next(item for item in result["items"] if item["source_ip"] == "198.51.100.1")
        self.assertEqual("malicious", malicious["threat_intelligence_classification"])
        self.assertEqual("GREYNOISE", malicious["threat_intelligence_provider"])
        self.assertIn("PREWHERE bucket >=", seen[0][1])
        self.assertIn("FROM behavior_flow_10s", seen[0][1])
        self.assertIn("LIMIT", seen[0][1])
        self.assertNotIn("flow_raw", seen[0][1])

    def test_traffic_window_and_evidence_queries_are_bounded(self):
        queries = []

        def query(context, sql, params):
            queries.append((context, sql, params))
            if context == "security_event_traffic":
                return [{"timestamp": "2026-08-12T10:00:00Z", "pps": 100, "bps": 120000, "flows": 2, "source_count": 2}]
            if context == "security_event_conversations":
                return [{"source_ip": "198.51.100.1", "destination_ip": "179.189.80.1", "src_port": 1900, "dst_port": 53, "protocol_number": 17, "tcp_flags": 0, "packets": 100, "bytes": 10000, "flows": 2}]
            if context == "security_event_protocols":
                return [{"protocol_number": 17, "packets": 6000, "bytes": 900000, "flows": 120}]
            return [{"port": 53, "packets": 6000, "bytes": 900000, "flows": 120}]

        traffic = event_traffic(self.event, padding_seconds=600, query_executor=query)
        evidence = event_evidence(self.event, sample_limit=1000, query_executor=query)
        self.assertEqual(600, traffic["query_window"]["padding_seconds"])
        self.assertEqual(100, evidence["limits"]["sample_conversations"])
        self.assertFalse(evidence["raw_flows_returned"])
        self.assertTrue(all("PREWHERE bucket >=" in sql and "LIMIT" in sql for _, sql, _ in queries))
        self.assertTrue(all("flow_raw" not in sql for _, sql, _ in queries))

    def test_incomplete_legacy_event_cannot_generate_time_only_global_query(self):
        captured = []

        def query(_context, sql, _params):
            captured.append(sql)
            return []

        legacy = dict(self.event)
        for field in ("sensor", "src_ip", "target_ip", "target_prefix"):
            legacy[field] = ""
        event_traffic(legacy, query_executor=query)
        self.assertIn("AND 0", captured[0])

    def test_event_filters_match_ipv4_stored_as_ipv4_mapped_ipv6(self):
        source_params = {}
        source_event = dict(self.event)
        source_event["src_ip"] = "198.51.100.7"
        source_event["target_ip"] = ""
        source_event["target_prefix"] = ""
        source_sql = " AND ".join(_event_filters(source_event, source_params))
        self.assertIn("src_ip = toIPv6({source_ip:String})", source_sql)
        self.assertNotIn("toString(src_ip) =", source_sql)
        self.assertEqual("198.51.100.7", source_params["source_ip"])

        target_params = {}
        target_event = dict(self.event)
        target_event["src_ip"] = ""
        target_event["target_ip"] = "179.189.80.5"
        target_event["target_prefix"] = ""
        target_sql = " AND ".join(_event_filters(target_event, target_params))
        self.assertIn("dst_ip = toIPv6({target_ip:String})", target_sql)
        self.assertEqual("179.189.80.5", target_params["target_ip"])

        prefix_params = {}
        prefix_event = dict(self.event)
        prefix_event["src_ip"] = ""
        prefix_event["target_ip"] = ""
        prefix_event["target_prefix"] = "179.189.80.0/22"
        prefix_sql = " AND ".join(_event_filters(prefix_event, prefix_params))
        self.assertIn(
            "isIPAddressInRange(replaceRegexpOne(toString(dst_ip), '^::ffff:', ''), {target_prefix:String})",
            prefix_sql,
        )
        self.assertEqual("179.189.80.0/22", prefix_params["target_prefix"])

    def test_empty_aggregate_results_fall_back_to_persisted_snapshot(self):
        def query(_context, _sql, _params):
            return []

        traffic = event_traffic(self.event, padding_seconds=600, query_executor=query)
        self.assertFalse(traffic["available"])
        self.assertEqual("persisted_event_summary", traffic["source"])
        sources = event_sources(self.event, query_executor=query)
        # Fallback keeps the persisted snapshot available for display.
        self.assertEqual("persisted_event_snapshot", sources["source"])
        self.assertEqual(2, len(sources["items"]))
        evidence = event_evidence(self.event, query_executor=query)
        self.assertFalse(evidence["aggregate_available"])

    def test_payload_arrays_are_limited_and_intel_is_separate_from_detection(self):
        payload = structured_analysis_payload(self.conn, self.event)
        self.assertLessEqual(len(payload["top_sources"]), 50)
        self.assertLessEqual(len(payload["top_ports"]["destination"]), 20)
        self.assertLessEqual(len(payload["threat_intelligence"]), 50)
        self.assertTrue(payload["analysis_constraints"]["threat_intelligence_is_enrichment_only"])
        self.assertFalse(payload["analysis_constraints"]["automatic_mitigation_enabled"])
        self.assertNotIn("flow_raw", str(payload))

    def test_ai_disabled_is_safe_and_does_not_create_attempt(self):
        with patch.dict(os.environ, {"GMJFLOW_SECURITY_AI_KILL_SWITCH": "true"}, clear=False):
            result = analyze_security_event(self.conn, self.event_id)
            state = get_security_event_analysis(self.conn, self.event_id)
        self.assertFalse(result["ok"])
        self.assertEqual("disabled", result["error_type"])
        self.assertFalse(state["enabled"])
        self.assertEqual(0, self.conn.execute("SELECT COUNT(*) FROM security_event_ai_analyses").fetchone()[0])

    def test_success_is_cached_and_recurrence_marks_it_stale(self):
        calls = []

        def executor(*_args, **_kwargs):
            calls.append(1)
            return {
                "ok": True, "provider": "GROQ", "model": "test-model",
                "structured": {
                    "summary": "Flood distribuído requer validação operacional.", "confidence": "HIGH", "assessment": "Provável ataque",
                    "why_detected": ["volume e diversidade"], "important_sources": ["198.51.100.1"],
                    "threat_intelligence_findings": ["GreyNoise é enrichment"], "possible_false_positive_factors": ["CGNAT"],
                    "recommended_checks": ["confirmar tráfego no roteador"], "recommended_actions": ["monitorar"],
                    "mitigation_advisory": "Decisão humana", "limitations": ["amostra agregada"],
                },
            }

        first = analyze_security_event(self.conn, self.event_id, executor=executor)
        second = analyze_security_event(self.conn, self.event_id, executor=executor)
        self.assertTrue(first["ok"])
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(1, len(calls))
        self.assertFalse(first["mitigation_executed"])
        upsert_security_event(self.conn, self.vector)
        stale = get_security_event_analysis(self.conn, self.event_id)
        self.assertTrue(stale["stale"])
        self.assertEqual("stale", stale["latest_attempt"]["status"])

    def test_provider_failures_and_malformed_response_are_audited(self):
        for category in ("unavailable", "timeout", "rate_limit"):
            result = analyze_security_event(
                self.conn, self.event_id, force=True,
                executor=lambda *_args, category=category, **_kwargs: {
                    "ok": False, "status": "failed", "error_type": category, "error_message": "provider failure",
                },
            )
            self.assertEqual(category, result["error_type"])
        malformed = analyze_security_event(
            self.conn, self.event_id, force=True,
            executor=lambda *_args, **_kwargs: {"ok": True, "provider": "GROQ", "model": "x", "structured": {"confidence": "LOW"}},
        )
        self.assertEqual("invalid_response", malformed["error_type"])
        statuses = [row[0] for row in self.conn.execute("SELECT status FROM security_event_ai_analyses ORDER BY id").fetchall()]
        self.assertEqual(["failed", "failed", "failed", "failed"], statuses)


if __name__ == "__main__":
    unittest.main()
