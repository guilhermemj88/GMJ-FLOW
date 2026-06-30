import json
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

try:
    import fastapi  # noqa: F401
except ModuleNotFoundError:
    fastapi_stub = types.ModuleType("fastapi")

    class _APIRouter:
        def __init__(self, *args, **kwargs):
            pass

        def post(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

    fastapi_stub.APIRouter = _APIRouter
    sys.modules["fastapi"] = fastapi_stub

from app.services.ai_mitigation_decision import build_ai_prompt
from app.services.flow_grouping import analyze_flow_groups, incident_from_dominant_group
from app.services.mitigation_candidates import generate_mitigation_candidates
from app.services.mitigation_playbook import load_playbook
from app.services.mitigation_validator import validate_mitigation_decision
from app.api.mitigation import analyze_mitigation


class FlowGroupingTest(unittest.TestCase):
    def setUp(self):
        self.playbook = load_playbook()
        self.incident = {
            "incident_id": "inc-dominant",
            "suspected_template": "udp_flood_outbound_cpe",
            "direction": "outbound",
            "src_is_customer": True,
            "src_is_internal": True,
            "dst_is_customer": False,
            "dst_is_external": True,
            "related_flows": _dominant_related_flows(),
        }

    def test_groups_flows_by_dst_ip_dst_port_protocol(self):
        grouping = analyze_flow_groups(self.incident)
        keys = {(group["dst_ip"], group["dst_port"], group["protocol"]) for group in grouping["groups"]}
        self.assertIn(("128.248.145.23", 65535, "udp"), keys)
        self.assertIn(("170.231.120.140", 6941, "udp"), keys)

    def test_detects_dominant_attack_group(self):
        grouping = analyze_flow_groups(self.incident)
        dominant = grouping["dominant_attack_group"]
        self.assertEqual(dominant["dst_ip"], "128.248.145.23")
        self.assertEqual(dominant["dst_port"], 65535)
        self.assertEqual(dominant["protocol"], "udp")
        self.assertEqual(dominant["total_bytes"], 393960)
        self.assertEqual(dominant["total_packets"], 6566)
        self.assertEqual(
            dominant["unique_src_ips"],
            ["168.232.197.35", "168.232.197.37", "168.232.197.40", "168.232.197.42"],
        )
        self.assertEqual(dominant["attack_vector"], "udp_flood_outbound_to_single_destination_port")

    def test_marks_other_destinations_as_noise_tail(self):
        grouping = analyze_flow_groups(self.incident)
        self.assertEqual(grouping["ignored_noise_flows_count"], 2)
        self.assertTrue(all(flow["classification"] == "not_part_of_primary_vector" for flow in grouping["noise_flows"]))
        self.assertEqual({flow["dst_ip"] for flow in grouping["noise_flows"]}, {"170.231.120.140", "170.231.121.104"})

    def test_generates_dst_external_candidate_first_for_multi_source_outbound_group(self):
        enriched = incident_from_dominant_group(self.incident, analyze_flow_groups(self.incident))
        _, candidates = generate_mitigation_candidates(enriched, self.playbook)
        self.assertEqual(candidates[0]["template"], "dst_external_32_proto_dst_port")
        self.assertEqual(
            candidates[0]["match"],
            {"dst_ip": "128.248.145.23/32", "protocol": "udp", "dst_port": 65535},
        )

    def test_does_not_generate_src_customer_candidate_as_principal_for_multi_source_group(self):
        enriched = incident_from_dominant_group(self.incident, analyze_flow_groups(self.incident))
        _, candidates = generate_mitigation_candidates(enriched, self.playbook)
        self.assertNotEqual(candidates[0]["template"], "src_customer_32_dst_external_32_proto_dst_port")
        self.assertEqual(candidates[1]["template"], "dst_external_prefix_proto_dst_port")
        self.assertEqual(candidates[2]["template"], "alert_only")

    def test_outbound_does_not_require_destination_protected_prefix(self):
        enriched = incident_from_dominant_group(self.incident, analyze_flow_groups(self.incident))
        template, candidates = generate_mitigation_candidates(enriched, self.playbook)
        validation = validate_mitigation_decision(
            _decision(0, ttl="2h"), candidates, enriched, self.playbook, template
        )
        self.assertTrue(validation["valid"], validation["violations"])
        self.assertIn("Origem interna/protegida confirmada", " ".join(validation["messages"]))

    def test_outbound_requires_internal_or_protected_origin(self):
        incident = dict(self.incident, src_is_customer=False, src_is_internal=False)
        enriched = incident_from_dominant_group(incident, analyze_flow_groups(incident))
        template, candidates = generate_mitigation_candidates(enriched, self.playbook)
        validation = validate_mitigation_decision(
            _decision(0, ttl="2h"), candidates, enriched, self.playbook, template
        )
        self.assertFalse(validation["valid"])
        self.assertIn("Origem interna/protegida nao confirmada para mitigacao outbound.", validation["violations"])

    def test_inbound_keeps_destination_protected_validation(self):
        incident = {
            "direction": "inbound",
            "dst_is_customer": False,
            "dst_is_external": False,
            "protocol": "udp",
            "dst_port": 443,
            "dst_ip": "100.64.10.20",
        }
        candidate = {
            "candidate_index": 0,
            "template": "dst_customer_32_proto_dst_port",
            "action": "flowspec_block",
            "match": {"dst_ip": "100.64.10.20/32", "protocol": "udp", "dst_port": 443},
            "ttl": "2h",
            "risk": "high",
        }
        validation = validate_mitigation_decision(
            _decision(0, ttl="2h"), [candidate], incident, self.playbook, "udp_flood_outbound_cpe"
        )
        self.assertFalse(validation["valid"])
        self.assertIn("Destino nao confirmado dentro de prefixo protegido.", validation["violations"])

        protected_incident = dict(incident, dst_is_customer=True)
        validation = validate_mitigation_decision(
            _decision(0, ttl="2h"), [candidate], protected_incident, self.playbook, "udp_flood_outbound_cpe"
        )
        self.assertTrue(validation["valid"], validation["violations"])

    def test_ai_prompt_receives_dominant_group_not_raw_tail_list(self):
        enriched = incident_from_dominant_group(self.incident, analyze_flow_groups(self.incident))
        _, candidates = generate_mitigation_candidates(enriched, self.playbook)
        prompt = build_ai_prompt(enriched, candidates, "udp_flood_outbound_cpe")
        self.assertIn("dominant_attack_group", prompt)
        self.assertIn("128.248.145.23", prompt)
        self.assertNotIn("170.231.120.140", prompt)
        self.assertNotIn("170.231.121.104", prompt)
        json.loads(prompt[prompt.find("{") :])

    def test_unclear_dominant_group_keeps_alert_only_manual_review(self):
        incident = {
            "incident_id": "inc-unclear",
            "suspected_template": "udp_flood_outbound_cpe",
            "direction": "outbound",
            "src_is_customer": True,
            "src_is_internal": True,
            "dst_is_external": True,
            "related_flows": [
                {"src_ip": "168.232.197.35", "src_port": 1000, "dst_ip": "198.51.100.1", "dst_port": 1111, "protocol": "udp", "bytes": 1000, "packets": 100},
                {"src_ip": "168.232.197.36", "src_port": 1001, "dst_ip": "198.51.100.2", "dst_port": 2222, "protocol": "udp", "bytes": 1000, "packets": 100},
            ],
        }
        grouping = analyze_flow_groups(incident)
        self.assertIsNone(grouping["dominant_attack_group"])
        enriched = incident_from_dominant_group(incident, grouping)
        _, candidates = generate_mitigation_candidates(enriched, self.playbook)
        self.assertEqual(candidates[0]["template"], "alert_only")

    def test_low_volume_single_udp_flow_is_not_dominant(self):
        incident = {
            "incident_id": "inc-low-flow",
            "direction": "sends",
            "related_flows": [
                {
                    "src_ip": "179.189.80.241",
                    "src_port": 4933,
                    "dst_ip": "189.39.178.6",
                    "dst_port": 38476,
                    "protocol": "udp",
                    "bytes": 25906,
                    "packets": 26,
                    "flow_count": 1,
                }
            ],
        }
        grouping = analyze_flow_groups(incident)
        self.assertIsNone(grouping["dominant_attack_group"])

    def test_100kpps_empty_top_flow_returns_alert_only(self):
        result = analyze_mitigation(
            {
                "incident_id": 102,
                "suspected_template": "udp_flood_outbound_cpe",
                "direction": "sends",
                "src_is_customer": True,
                "src_is_internal": True,
                "dst_is_external": True,
                "protocol": "udp",
                "observed_value": 99916,
                "threshold_value": 40000,
                "top_flow": {"src_ip": "", "dst_ip": "", "packets": 0, "bytes": 0},
                "related_flows": [
                    {
                        "src_ip": "179.189.80.241",
                        "src_port": 4933,
                        "dst_ip": "189.39.178.6",
                        "dst_port": 38476,
                        "protocol": "udp",
                        "bytes": 25906,
                        "packets": 26,
                        "flow_count": 1,
                    }
                ],
            }
        )
        self.assertEqual(result["evidence_status"], "insufficient")
        self.assertFalse(result["mitigation_allowed"])
        self.assertEqual(result["operator_recommendation"]["recommended_action"], "alert_only")
        self.assertTrue(result["operator_recommendation"]["manual_approval_required"])
        self.assertFalse(result["operator_recommendation"]["apply_enabled"])
        self.assertTrue(all(candidate["action"] == "alert_only" for candidate in result["candidates"]))

    def test_generic_udp_without_dominant_group_returns_alert_only(self):
        result = analyze_mitigation(
            {
                "incident_id": "inc-generic-udp",
                "suspected_template": "udp_flood_outbound_cpe",
                "direction": "sends",
                "src_is_customer": True,
                "src_is_internal": True,
                "dst_is_external": True,
                "protocol": "udp",
                "related_flows": [
                    {"src_ip": "198.51.100.1", "src_port": 1000, "dst_ip": "203.0.113.10", "dst_port": 1111, "protocol": "udp", "bytes": 1000, "packets": 100},
                    {"src_ip": "198.51.100.2", "src_port": 1001, "dst_ip": "203.0.113.11", "dst_port": 2222, "protocol": "udp", "bytes": 1000, "packets": 100},
                ],
            }
        )
        self.assertEqual(result["operator_recommendation"]["recommended_action"], "alert_only")


def _dominant_related_flows():
    return [
        {"src_ip": "168.232.197.35", "src_port": 38747, "dst_ip": "128.248.145.23", "dst_port": 65535, "protocol": "udp", "bytes": 89280, "packets": 1488},
        {"src_ip": "168.232.197.40", "src_port": 13407, "dst_ip": "128.248.145.23", "dst_port": 65535, "protocol": "udp", "bytes": 86940, "packets": 1449},
        {"src_ip": "168.232.197.37", "src_port": 34892, "dst_ip": "128.248.145.23", "dst_port": 65535, "protocol": "udp", "bytes": 62100, "packets": 1035},
        {"src_ip": "168.232.197.35", "src_port": 61669, "dst_ip": "128.248.145.23", "dst_port": 65535, "protocol": "udp", "bytes": 43920, "packets": 732},
        {"src_ip": "168.232.197.35", "src_port": 61669, "dst_ip": "128.248.145.23", "dst_port": 65535, "protocol": "udp", "bytes": 39960, "packets": 666},
        {"src_ip": "168.232.197.42", "src_port": 65020, "dst_ip": "128.248.145.23", "dst_port": 65535, "protocol": "udp", "bytes": 36480, "packets": 608},
        {"src_ip": "168.232.197.42", "src_port": 65020, "dst_ip": "128.248.145.23", "dst_port": 65535, "protocol": "udp", "bytes": 35280, "packets": 588},
        {"src_ip": "168.232.197.36", "src_port": 27401, "dst_ip": "170.231.120.140", "dst_port": 6941, "protocol": "udp", "bytes": 7227, "packets": 10},
        {"src_ip": "168.232.197.34", "src_port": 40582, "dst_ip": "170.231.121.104", "dst_port": 37739, "protocol": "udp", "bytes": 6508, "packets": 7},
    ]


def _decision(index, ttl="2h"):
    return {
        "attack_vector": "udp_flood_outbound_cpe",
        "recommended_candidate_index": index,
        "confidence": "high",
        "recommended_ttl": ttl,
        "allow_auto": 0,
        "manual_approval_required": 1,
        "risk": "medium",
        "reason": "test",
    }


if __name__ == "__main__":
    unittest.main()
