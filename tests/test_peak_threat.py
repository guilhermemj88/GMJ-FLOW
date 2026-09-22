from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.peak_threat import (
    VERDICT_NORMAL,
    VERDICT_NOTEWORTHY,
    VERDICT_SUSPICIOUS,
    assess_peak_threat,
    compute_peak_signals,
    enrich_peak_iocs,
)


class FakeIocEntry:
    def __init__(self, ip, threat_types, semantic_tier, providers=("GREYNOISE",), botnet_family=""):
        self.ip = ip
        self.threat_types = tuple(threat_types)
        self.categories = tuple(threat_types)
        self.providers = tuple(providers)
        self.semantic_tier = semantic_tier
        self.botnet_family = botnet_family


class FakeHotSet:
    def __init__(self, entries):
        self._entries = {entry.ip: entry for entry in entries}

    def lookup(self, ip):
        return self._entries.get(ip)


def evidence(dst_ips=(), src_ips=(), top_dst_ips=(), pps_delta=0.0, bps_delta=0.0, share=0.0, unique_src=0, packet_size=None):
    deltas = {"pps_delta_pct": pps_delta, "bps_delta_pct": bps_delta}
    if packet_size is not None:
        deltas["avg_packet_size_before"] = packet_size[0]
        deltas["avg_packet_size_peak"] = packet_size[1]
    return {
        "changed": {
            "external_ips": [{"key": ip, "label": ip} for ip in dst_ips],
            "local_ips": [{"key": ip, "label": ip} for ip in src_ips],
            "dst_ips": [{"key": ip, "label": ip} for ip in dst_ips],
            "src_ips": [{"key": ip, "label": ip} for ip in src_ips],
            "protocols": [],
        },
        "concentration": {
            "top_dst_ips": [{"dst_ip": ip} for ip in top_dst_ips],
            "top_dst_share_pct": share,
            "unique_src_count": unique_src,
        },
        "deltas": deltas,
    }


class PeakThreatTest(unittest.TestCase):
    def test_enrichment_reuses_existing_hotset(self):
        hotset = FakeHotSet([FakeIocEntry("1.2.3.4", ("c2",), 0)])
        signals = enrich_peak_iocs(hotset, ["1.2.3.4", "9.9.9.9"])
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["ip"], "1.2.3.4")
        self.assertEqual(signals[0]["strength"], "strong")

    def test_normal_when_no_signal(self):
        ev = evidence(dst_ips=["1.2.3.4"], pps_delta=10.0, share=10.0)
        result = assess_peak_threat(ev, FakeHotSet([]))
        self.assertEqual(result["verdict"], VERDICT_NORMAL)
        self.assertFalse(result["handoff_recommended"])

    def test_suspicious_when_strong_ioc(self):
        hotset = FakeHotSet([FakeIocEntry("1.2.3.4", ("botnet",), 0)])
        ev = evidence(dst_ips=["1.2.3.4"], pps_delta=10.0, share=10.0)
        result = assess_peak_threat(ev, hotset)
        self.assertEqual(result["verdict"], VERDICT_SUSPICIOUS)
        self.assertIn("strong_ioc", result["reasons"])
        self.assertTrue(result["handoff_recommended"])

    def test_noteworthy_when_weak_ioc(self):
        hotset = FakeHotSet([FakeIocEntry("1.2.3.4", ("scanner",), 3)])
        ev = evidence(dst_ips=["1.2.3.4"], pps_delta=10.0, share=10.0)
        result = assess_peak_threat(ev, hotset)
        self.assertEqual(result["verdict"], VERDICT_NOTEWORTHY)

    def test_noteworthy_when_objective_signals(self):
        ev = evidence(dst_ips=["1.2.3.4"], pps_delta=250.0, share=70.0, unique_src=12)
        result = assess_peak_threat(ev, FakeHotSet([]))
        self.assertEqual(result["verdict"], VERDICT_NOTEWORTHY)
        names = {signal["name"] for signal in result["signals"]}
        self.assertIn("pps_surge", names)
        self.assertIn("concentrated_traffic", names)
        self.assertIn("many_sources", names)

    def test_objective_signals_packet_size_and_protocol(self):
        ev = evidence(
            dst_ips=["1.2.3.4"],
            pps_delta=0.0,
            share=0.0,
            packet_size=(100.0, 20.0),
        )
        ev["changed"]["protocols"] = [{"key": "17", "label": "udp", "delta_bps_pct": 310.0}]
        signals = compute_peak_signals(ev)
        names = {signal["name"] for signal in signals}
        self.assertIn("packet_size_change", names)
        self.assertIn("protocol_shift", names)

    def test_no_mitigation_imports(self):
        source = Path(__file__).resolve().parents[1].joinpath("backend", "app", "services", "peak_threat.py").read_text(encoding="utf-8")
        for forbidden in (
            "from app.services.mitigation",
            "from app.services.transit_rtbh",
            "from app.services.mitigation_validator",
            "generate_mitigation_candidates",
            "validate_mitigation_decision",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
