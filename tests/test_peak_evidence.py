from __future__ import annotations

import re
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.peak_evidence import (
    PeakEvidenceConfig,
    build_peak_evidence,
    direction_label,
)

PEAK_TIME = datetime(2026, 9, 22, 15, 42, 0, tzinfo=timezone.utc)


class FakeExecutor:
    """Deterministic executor keyed on table and phase (before/peak/after)."""

    def __init__(self, peak_time):
        self.peak_time = peak_time
        self.calls = []

    def _phase(self, params):
        start = params["start"]
        peak = self.peak_time
        if start < peak - timedelta(seconds=60):
            return "baseline_before"
        if start >= peak + timedelta(seconds=60):
            return "after"
        return "peak"

    def __call__(self, query, params):
        self.calls.append((query, params))
        table = re.search(r"FROM\s+(\w+)", query).group(1)
        phase = self._phase(params)
        if "uniqExact(src_ip)" in query:
            return [{"total_bytes": 400.0, "unique_src_count": 12, "unique_dst_count": 4}]
        return self._rows(table, phase)

    def _rows(self, table, phase):
        if table == "flow_dashboard_series_1m":
            if phase == "baseline_before":
                return [{"bytes": 100.0, "packets": 10.0, "flows": 5.0}]
            if phase == "peak":
                return [{"bytes": 400.0, "packets": 40.0, "flows": 20.0}]
            return [{"bytes": 120.0, "packets": 12.0, "flows": 6.0}]
        if table == "flow_dashboard_protocol_1m":
            if phase == "baseline_before":
                return [
                    {"dimension": 6, "bytes": 80.0, "packets": 8.0},
                    {"dimension": 17, "bytes": 20.0, "packets": 2.0},
                ]
            return [
                {"dimension": 17, "bytes": 320.0, "packets": 32.0},
                {"dimension": 6, "bytes": 80.0, "packets": 8.0},
            ]
        if table == "flow_dashboard_dst_port_1m":
            if phase == "baseline_before":
                return [
                    {"dimension": 443, "proto": 6, "bytes": 90.0, "packets": 9.0},
                    {"dimension": 53, "proto": 17, "bytes": 10.0, "packets": 1.0},
                ]
            return [
                {"dimension": 53, "proto": 17, "bytes": 300.0, "packets": 30.0},
                {"dimension": 443, "proto": 6, "bytes": 100.0, "packets": 10.0},
            ]
        if table == "flow_dashboard_asn_dst_1m":
            if phase == "baseline_before":
                return [
                    {"dimension": 64500, "dst_as_name": "EXAMPLE", "bytes": 50.0, "packets": 5.0},
                ]
            return [
                {"dimension": 64500, "dst_as_name": "EXAMPLE", "bytes": 250.0, "packets": 25.0},
            ]
        if table == "flow_dashboard_asn_src_1m":
            if phase == "baseline_before":
                return [
                    {"dimension": 64511, "src_as_name": "EXTERNAL-SRC", "bytes": 40.0, "packets": 4.0},
                ]
            return [
                {"dimension": 64511, "src_as_name": "EXTERNAL-SRC", "bytes": 200.0, "packets": 20.0},
            ]
        if table == "flow_dashboard_prefix_1m":
            if phase == "baseline_before":
                return [
                    {"dimension": 12345, "bytes": 10.0, "packets": 1.0},
                    {"dimension": 443, "bytes": 60.0, "packets": 6.0},
                ]
            return [
                {"dimension": 12345, "bytes": 200.0, "packets": 20.0},
                {"dimension": 443, "bytes": 70.0, "packets": 7.0},
            ]
        if table == "flow_dashboard_src_ip_1m":
            if phase == "baseline_before":
                return [{"dimension": "10.0.0.1", "bytes": 60.0, "packets": 6.0}]
            return [{"dimension": "10.0.0.1", "bytes": 200.0, "packets": 20.0}]
        if table == "flow_dashboard_dst_ip_1m":
            if phase == "baseline_before":
                return [{"dimension": "45.0.0.1", "bytes": 60.0, "packets": 6.0}]
            return [
                {"dimension": "45.0.0.1", "bytes": 280.0, "packets": 28.0},
                {"dimension": "45.0.0.2", "bytes": 60.0, "packets": 6.0},
            ]
        return []


class PeakEvidenceTest(unittest.TestCase):
    def test_before_vs_peak_deltas(self):
        executor = FakeExecutor(PEAK_TIME)
        evidence = build_peak_evidence(executor, "sensor-A", 7, "receives", PEAK_TIME)
        self.assertEqual(evidence["scope"]["direction_label"], "download")
        self.assertGreater(evidence["deltas"]["bps_peak"], evidence["deltas"]["bps"])
        self.assertAlmostEqual(evidence["deltas"]["bps_delta_pct"], 300.0, delta=3.0)
        self.assertAlmostEqual(evidence["deltas"]["pps_delta_pct"], 300.0, delta=3.0)

    def test_protocol_that_changed(self):
        executor = FakeExecutor(PEAK_TIME)
        evidence = build_peak_evidence(executor, "sensor-A", 7, "receives", PEAK_TIME)
        protocols = evidence["changed"]["protocols"]
        udp = next(p for p in protocols if p["key"] == "17")
        self.assertEqual(udp["label"], "udp")
        self.assertGreater(udp["delta_bps_pct"], 1000.0)
        self.assertEqual(protocols[0]["key"], "17")  # udp now dominant

    def test_dst_port_that_changed(self):
        executor = FakeExecutor(PEAK_TIME)
        evidence = build_peak_evidence(executor, "sensor-A", 7, "receives", PEAK_TIME)
        ports = evidence["changed"]["dst_ports"]
        self.assertEqual(ports[0]["key"], "53")  # DNS becomes top

    def test_asn_that_changed(self):
        executor = FakeExecutor(PEAK_TIME)
        evidence = build_peak_evidence(executor, "sensor-A", 7, "receives", PEAK_TIME)
        asns = evidence["changed"]["dst_asns"]
        self.assertEqual(len(asns), 1)
        self.assertEqual(asns[0]["key"], "64511")  # download -> external = src ASN
        self.assertGreater(asns[0]["delta_bps_pct"], 100.0)

    def test_concentrated_local_ip(self):
        executor = FakeExecutor(PEAK_TIME)
        evidence = build_peak_evidence(executor, "sensor-A", 7, "receives", PEAK_TIME)
        concentration = evidence["concentration"]
        self.assertEqual(concentration["unique_src_count"], 12)
        self.assertEqual(concentration["unique_dst_count"], 4)
        self.assertEqual(concentration["top_dst_ips"][0]["dst_ip"], "45.0.0.1")
        self.assertGreater(concentration["top_dst_share_pct"], 0.0)

    def test_direction_labels(self):
        self.assertEqual(direction_label("sends"), "upload")
        self.assertEqual(direction_label("receives"), "download")
        self.assertEqual(direction_label("total"), "total")
        self.assertEqual(direction_label("outbound"), "upload")

    def test_services_are_labelled(self):
        executor = FakeExecutor(PEAK_TIME)
        evidence = build_peak_evidence(executor, "sensor-A", 7, "receives", PEAK_TIME)
        services = evidence["changed"]["services"]
        dns = next(s for s in services if s["key"] == "53")
        self.assertEqual(dns["label"], "DNS")

    def test_src_ports_present(self):
        executor = FakeExecutor(PEAK_TIME)
        evidence = build_peak_evidence(executor, "sensor-A", 7, "receives", PEAK_TIME)
        src_ports = evidence["changed"]["src_ports"]
        self.assertTrue(any(row["key"] == "12345" for row in src_ports))

    def test_external_asns_respect_direction_download(self):
        executor = FakeExecutor(PEAK_TIME)
        evidence = build_peak_evidence(executor, "sensor-A", 7, "receives", PEAK_TIME)
        asns = evidence["changed"]["external_asns"]
        # download -> external = src ASN (64511)
        self.assertTrue(any(row["key"] == "64511" for row in asns))

    def test_external_asns_respect_direction_upload(self):
        executor = FakeExecutor(PEAK_TIME)
        evidence = build_peak_evidence(executor, "sensor-A", 7, "sends", PEAK_TIME)
        asns = evidence["changed"]["external_asns"]
        # upload -> external = dst ASN (64500)
        self.assertTrue(any(row["key"] == "64500" for row in asns))

    def test_external_local_ips_by_direction(self):
        executor = FakeExecutor(PEAK_TIME)
        download = build_peak_evidence(executor, "sensor-A", 7, "receives", PEAK_TIME)
        # download: external = src (10.0.0.1), local = dst (45.0.0.1)
        self.assertTrue(any(row["key"] == "10.0.0.1" for row in download["changed"]["external_ips"]))
        self.assertTrue(any(row["key"] == "45.0.0.1" for row in download["changed"]["local_ips"]))
        upload = build_peak_evidence(executor, "sensor-A", 7, "sends", PEAK_TIME)
        # upload: external = dst (45.0.0.1), local = src (10.0.0.1)
        self.assertTrue(any(row["key"] == "45.0.0.1" for row in upload["changed"]["external_ips"]))
        self.assertTrue(any(row["key"] == "10.0.0.1" for row in upload["changed"]["local_ips"]))

    def test_flows_and_packet_size(self):
        executor = FakeExecutor(PEAK_TIME)
        evidence = build_peak_evidence(executor, "sensor-A", 7, "receives", PEAK_TIME)
        self.assertGreater(evidence["deltas"]["flows_s_peak"], 0)
        self.assertIn("avg_packet_size_peak", evidence["deltas"])


if __name__ == "__main__":
    unittest.main()
