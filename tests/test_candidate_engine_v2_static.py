from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.behavioral_detection import DetectorThresholds  # noqa: E402


class CandidateEngineV2StaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidates = (ROOT / "backend" / "app" / "services" / "behavioral_candidates.py").read_text(encoding="utf-8")
        executable = cls.candidates.replace(
            "from app.services.clickhouse import query_clickhouse",
            "query_clickhouse = None",
        )
        cls.candidate_namespace = {}
        exec(compile(executable, "behavioral_candidates.py", "exec"), cls.candidate_namespace)
        cls.runtime = (ROOT / "backend" / "app" / "services" / "behavioral_detection.py").read_text(encoding="utf-8")
        cls.main = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        cls.env = (ROOT / ".env.example").read_text(encoding="utf-8")
        cls.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    def test_detector_specific_queries_preaggregate_in_clickhouse(self):
        for function_name in (
            "scan_candidates",
            "syn_flood_candidates",
            "udp_flood_candidates",
            "carpet_candidates",
        ):
            self.assertIn(f"def {function_name}", self.candidates)
        for aggregate in ("sum(packets)", "sum(bytes)", "uniqExact(src_ip)", "topKWeighted"):
            self.assertIn(aggregate, self.candidates)

    def test_v2_is_opt_in_shadow_and_cannot_drive_mitigation(self):
        self.assertIn("GMJFLOW_BEHAVIOR_CANDIDATE_ENGINE_V2=false", self.env)
        self.assertIn("GMJFLOW_BEHAVIOR_CANDIDATE_ENGINE_V2-false", self.compose)
        self.assertIn("CANDIDATE_ENGINE_SHADOW_COMPARISON", self.runtime)
        self.assertIn('"production_source": "V1"', self.runtime)
        self.assertIn("candidate_engine_v2_does_not_drive_mitigation", self.runtime)

    def test_automatic_mitigation_is_off_by_default_everywhere(self):
        self.assertIn("GMJFLOW_AUTO_MITIGATION_ENABLED=false", self.env)
        self.assertIn("GMJFLOW_AUTO_MITIGATION_ENABLED-false", self.compose)
        self.assertIn('"auto_mitigation_enabled": "GMJFLOW_AUTO_MITIGATION_ENABLED"', self.main)
        self.assertIn("GMJFLOW_AUTO_MITIGATION_KILL_SWITCH", self.env)
        self.assertIn("GMJFLOW_AUTO_MITIGATION_KILL_SWITCH", self.compose)

    def test_v2_receives_the_same_effective_detector_thresholds_as_v1(self):
        thresholds = DetectorThresholds(
            vertical_ports=31,
            horizontal_hosts=41,
            low_slow_unique=17,
            syn_min_packets=3101,
            syn_min_pps=111.5,
            syn_min_bps=1_100_001,
            udp_min_packets=3202,
            udp_min_pps=122.5,
            udp_min_bps=1_200_002,
            carpet_min_packets=3303,
            carpet_unique_hosts=13,
            carpet_prefix_pps=233.5,
            carpet_min_bps=1_300_003,
            carpet_host_pps=77.5,
        )
        captured = []

        def query(_sql, parameters):
            captured.append(parameters)
            return []

        self.candidate_namespace["query_clickhouse"] = query
        self.candidate_namespace["fetch_candidate_summary_v2"](300, 5000, thresholds=thresholds)

        merged = {key: value for item in captured for key, value in item.items()}
        expected = {
            "scan_vertical_ports": 31,
            "scan_horizontal_hosts": 41,
            "scan_low_slow_unique": 17,
            "syn_min_packets": 3101,
            "syn_min_pps": 111.5,
            "syn_min_bps": 1_100_001.0,
            "udp_min_packets": 3202,
            "udp_min_pps": 122.5,
            "udp_min_bps": 1_200_002.0,
            "carpet_min_packets": 3303,
            "carpet_min_hosts": 13,
            "carpet_min_pps": 233.5,
            "carpet_min_bps": 1_300_003.0,
            "carpet_max_host_pps": 77.5,
        }
        for key, value in expected.items():
            self.assertEqual(value, merged[key])
        self.assertIn("thresholds=self.engine.thresholds", self.runtime)

    def test_environment_override_changes_v1_and_v2_udp_threshold(self):
        with mock.patch.dict(os.environ, {"GMJFLOW_UDP_FLOOD_MIN_PACKETS": "9876"}, clear=False):
            thresholds = DetectorThresholds.from_env()
            captured = {}

            def query(_sql, parameters):
                captured.update(parameters)
                return []

            self.candidate_namespace["query_clickhouse"] = query
            self.candidate_namespace["udp_flood_candidates"](thresholds=thresholds)
        self.assertEqual(9876, thresholds.udp_min_packets)
        self.assertEqual(9876, captured["udp_min_packets"])


if __name__ == "__main__":
    unittest.main()
