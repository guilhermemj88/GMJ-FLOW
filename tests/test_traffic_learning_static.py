import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
RUNNER = (ROOT / "backend" / "app" / "services" / "peak_hunter_runner.py").read_text(encoding="utf-8")
API = (ROOT / "backend" / "app" / "api" / "peak_hunter.py").read_text(encoding="utf-8")


class TrafficLearningStaticTest(unittest.TestCase):
    def test_learn_from_traffic_endpoint_contract_exists(self):
        self.assertIn('/api/detection-templates/{template_id}/learn-from-traffic', MAIN)
        self.assertIn('/api/detection/templates/{template_id}/learn-from-traffic', MAIN)
        self.assertIn('fetch_learning_traffic_series', MAIN)
        self.assertIn('exclude_peak_hunter_peaks', MAIN)
        self.assertIn('is_negative_sample', MAIN)
        self.assertIn('"suggested_rule"', MAIN)
        self.assertIn('"A sugestao nao foi salva automaticamente."', MAIN)

    def test_peak_hunter_automation_status_contract_exists(self):
        self.assertIn('/automation/status', API)
        self.assertIn('def peak_hunter_automation_status', RUNNER)
        self.assertIn('"scheduler_running"', RUNNER)
        self.assertIn('"last_tick_at"', RUNNER)
        self.assertIn('"jobs_due"', RUNNER)
        self.assertIn('[peak-hunter-runner] scheduler tick', RUNNER)
        self.assertIn('[peak-hunter-runner] run started', RUNNER)


if __name__ == "__main__":
    unittest.main()
