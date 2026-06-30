import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.mitigation_candidates import generate_mitigation_candidates
from app.services.mitigation_playbook import load_playbook
from app.services.mitigation_validator import validate_mitigation_decision


class MitigationPlaybookTest(unittest.TestCase):
    def setUp(self):
        self.playbook = load_playbook()
        self.incident = {
            "incident_id": "inc-0001",
            "suspected_template": "udp_flood_outbound_cpe",
            "direction": "outbound",
            "src_is_customer": True,
            "dst_is_customer": False,
            "src_is_internal": True,
            "dst_is_external": True,
            "protocol": "udp",
            "dst_port": 53,
            "src_ip": "100.64.10.20",
            "dst_ip": "94.141.97.109",
            "dst_prefix": "94.141.97.0/24",
            "same_dst_24": True,
            "same_asn": True,
            "burst_detected": True,
            "window_seconds": 60,
            "packets": 280000,
            "bytes": 500000000,
            "pps_score": 12.4,
            "bps_score": 8.1,
            "flows_score": 3.2,
        }

    def test_ai_chooses_valid_candidate(self):
        template, candidates = generate_mitigation_candidates(self.incident, self.playbook)
        validation = validate_mitigation_decision(
            _decision(0, ttl="2h"), candidates, self.incident, self.playbook, template
        )
        self.assertTrue(validation["valid"])

    def test_ai_chooses_missing_candidate_index(self):
        template, candidates = generate_mitigation_candidates(self.incident, self.playbook)
        validation = validate_mitigation_decision(
            _decision(99, ttl="2h"), candidates, self.incident, self.playbook, template
        )
        self.assertFalse(validation["valid"])
        self.assertIn("recommended_candidate_index does not exist", validation["violations"])

    def test_ai_attempts_allow_auto(self):
        template, candidates = generate_mitigation_candidates(self.incident, self.playbook)
        validation = validate_mitigation_decision(
            _decision(0, allow_auto=1, ttl="2h"), candidates, self.incident, self.playbook, template
        )
        self.assertFalse(validation["valid"])
        self.assertEqual(validation["ai_decision"]["allow_auto"], 0)

    def test_ai_attempts_ttl_below_minimum(self):
        template, candidates = generate_mitigation_candidates(self.incident, self.playbook)
        validation = validate_mitigation_decision(
            _decision(0, ttl="30m"), candidates, self.incident, self.playbook, template
        )
        self.assertFalse(validation["valid"])
        self.assertIn("recommended_ttl must be at least 2h", validation["violations"])

    def test_candidate_blocks_customer_ip_only(self):
        candidate = {
            "candidate_index": 0,
            "template": "unsafe",
            "action": "flowspec_block",
            "match": {"src_ip": "100.64.10.20/32"},
            "ttl": "2h",
            "risk": "high",
        }
        validation = validate_mitigation_decision(
            _decision(0, ttl="2h"), [candidate], self.incident, self.playbook, "udp_flood_outbound_cpe"
        )
        self.assertFalse(validation["valid"])
        self.assertIn("block_customer_ip_only", validation["violations"])

    def test_rate_limit_dns_as_customer_destination(self):
        incident = dict(self.incident, dst_is_customer=True, dst_is_external=False)
        candidate = {
            "candidate_index": 0,
            "template": "rate_limit_specific",
            "action": "flowspec_rate_limit",
            "match": {"src_ip": "198.51.100.10/32", "dst_ip": "100.64.10.20/32", "protocol": "udp", "dst_port": 53},
            "ttl": "2h",
            "risk": "medium",
        }
        validation = validate_mitigation_decision(
            _decision(0, ttl="2h"), [candidate], incident, self.playbook, "dns_udp_abuse_outbound"
        )
        self.assertFalse(validation["valid"])
        self.assertIn("rate_limit_dns_as_customer_destination", validation["violations"])

    def test_udp_flood_generates_specific_candidate(self):
        _, candidates = generate_mitigation_candidates(self.incident, self.playbook)
        self.assertEqual(candidates[0]["template"], "src_customer_32_dst_external_32_proto_dst_port")
        self.assertEqual(candidates[0]["match"]["src_ip"], "100.64.10.20/32")
        self.assertEqual(candidates[0]["match"]["dst_ip"], "94.141.97.109/32")
        self.assertEqual(candidates[0]["match"]["protocol"], "udp")
        self.assertEqual(candidates[0]["match"]["dst_port"], 53)

    def test_dns_abuse_outbound_uses_minimum_2h_ttl(self):
        incident = dict(self.incident, suspected_template="dns_udp_abuse_outbound")
        _, candidates = generate_mitigation_candidates(incident, self.playbook)
        self.assertEqual(candidates[0]["ttl"], "2h")

    def test_tcp_syn_flood_requires_syn_flag(self):
        incident = dict(
            self.incident,
            suspected_template="tcp_syn_flood",
            protocol="tcp",
            dst_port=443,
            tcp_flags="ack",
        )
        _, candidates = generate_mitigation_candidates(incident, self.playbook)
        self.assertTrue(all("syn" not in str(candidate.get("match", {}).get("tcp_flags", "")) for candidate in candidates))
        self.assertEqual(candidates[0]["template"], "alert_only")

    def test_possible_l7_http_https_returns_alert_only_without_clear_syn(self):
        incident = dict(
            self.incident,
            suspected_template="possible_l7_http_https",
            protocol="tcp",
            dst_port=443,
            tcp_flags="ack",
        )
        _, candidates = generate_mitigation_candidates(incident, self.playbook)
        self.assertEqual(candidates[0]["template"], "alert_only")

    def test_fallback_top_flow_with_26_packets_is_rejected(self):
        candidate = {
            "candidate_index": 0,
            "source": "fallback_analysis",
            "template": "fallback",
            "action": "flowspec_block",
            "match": {"src_ip": "179.189.80.241/32", "dst_ip": "189.39.178.6/32", "protocol": "udp", "dst_port": 38476},
            "packets": 26,
            "bytes": 25906,
            "share_top_flow_percent": 0,
            "ttl": "2h",
            "risk": "high",
        }
        incident = dict(self.incident, observed_value=99916, threshold_value=40000)
        validation = validate_mitigation_decision(
            _decision(0, ttl="2h"), [candidate], incident, self.playbook, "udp_flood_outbound_cpe"
        )
        self.assertFalse(validation["valid"])
        self.assertIn("fallback_analysis_packets_below_min", validation["violations"])

    def test_share_top_flow_zero_rejects_discard_candidate(self):
        candidate = {
            "candidate_index": 0,
            "source": "fallback_analysis",
            "template": "fallback",
            "action": "flowspec_block",
            "match": {"src_ip": "179.189.80.241/32", "dst_ip": "189.39.178.6/32", "protocol": "udp", "dst_port": 38476},
            "packets": 5000,
            "bytes": 2000000,
            "share_top_flow_percent": 0,
            "ttl": "2h",
            "risk": "high",
        }
        validation = validate_mitigation_decision(
            _decision(0, ttl="2h"), [candidate], self.incident, self.playbook, "udp_flood_outbound_cpe"
        )
        self.assertFalse(validation["valid"])
        self.assertIn("fallback_analysis_share_top_flow_zero", validation["violations"])

    def test_empty_top_flow_rejects_mitigation_candidate(self):
        candidate = {
            "candidate_index": 0,
            "template": "unsafe",
            "action": "flowspec_block",
            "match": {"src_ip": "179.189.80.241/32", "dst_ip": "189.39.178.6/32", "protocol": "udp", "dst_port": 38476},
            "ttl": "2h",
            "risk": "high",
        }
        incident = dict(self.incident, top_flow={"src_ip": "", "dst_ip": "", "packets": 0, "bytes": 0})
        validation = validate_mitigation_decision(
            _decision(0, ttl="2h"), [candidate], incident, self.playbook, "udp_flood_outbound_cpe"
        )
        self.assertFalse(validation["valid"])
        self.assertIn("top_flow_scope_empty", validation["violations"])


def _decision(index, allow_auto=0, ttl="2h"):
    return {
        "attack_vector": "udp_flood_outbound_cpe",
        "recommended_candidate_index": index,
        "confidence": "high",
        "recommended_ttl": ttl,
        "allow_auto": allow_auto,
        "manual_approval_required": 1,
        "risk": "low",
        "reason": "test",
    }


if __name__ == "__main__":
    unittest.main()
