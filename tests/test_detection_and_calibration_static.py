import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")


class DetectionAndCalibrationStaticTest(unittest.TestCase):
    def test_worker_evaluates_detection_template_rules_before_legacy_vectors(self):
        worker = SOURCE[SOURCE.find("def detect_anomalies_once"):SOURCE.find("def anomaly_detection_enabled")]
        self.assertIn("run_detection_template_rules_once(create_anomalies=True)", worker)
        self.assertIn("active_attack_vectors(conn)", worker)

    def test_detection_status_and_run_now_endpoints_exist(self):
        self.assertIn('@app.get("/api/detection/status")', SOURCE)
        self.assertIn('@app.post("/api/detection/run-now")', SOURCE)
        self.assertIn("GMJFLOW_DETECTION_INTERVAL_SECONDS", SOURCE)
        self.assertIn("detection scheduler started", SOURCE)

    def test_detection_template_anomaly_source_fields_are_persisted(self):
        self.assertIn("anomaly_source", SOURCE)
        self.assertIn('"detection_template_rule"', SOURCE)
        self.assertIn('"detection_templates"', SOURCE)
        self.assertIn("source_details_json", SOURCE)
        self.assertIn("rule_config", SOURCE)
        self.assertIn("observed", SOURCE)

    def test_detection_run_reports_cooldown_disabled_whitelist_and_no_flow(self):
        self.assertIn("rule skipped: cooldown", SOURCE)
        self.assertIn("rule skipped: disabled", SOURCE)
        self.assertIn("rule skipped: no zone/prefix match", SOURCE)
        self.assertIn("rule skipped: no flow rows", SOURCE)
        self.assertIn("global_whitelist", SOURCE)

    def test_detection_only_still_creates_anomaly_without_mitigation(self):
        detection_run = SOURCE[SOURCE.find("def evaluate_detection_template_rule"):SOURCE.find("def run_detection_template_rules_once")]
        self.assertIn("upsert_security_anomaly(conn, item)", detection_run)
        self.assertNotIn("rule.get(\"mitigation_mode\")", detection_run)
        self.assertNotIn("apply_mitigation_candidate", detection_run)

    def test_subnet_detection_uses_null_ip_fields_and_prefix_scope(self):
        query_builder = SOURCE[SOURCE.find("def query_detection_rule_candidates"):SOURCE.find("def security_anomaly_dedupe_key")]
        self.assertIn('if grouping == "subnet":', query_builder)
        self.assertIn("src_expr = \"CAST(NULL, 'Nullable(String)')\"", query_builder)
        self.assertIn("dst_expr = \"CAST(NULL, 'Nullable(String)')\"", query_builder)
        self.assertIn("internal_expr = \"CAST(NULL, 'Nullable(String)')\"", query_builder)
        self.assertIn('"target_cidr": prefix["cidr"]', query_builder)
        self.assertIn('"scope_type": "subnet"', query_builder)

    def test_anomaly_threshold_uses_metric_unit_not_pps_default(self):
        self.assertIn("configured_metric = clean_text(rule_config.get(\"metric\")", SOURCE)
        self.assertIn('"metric_unit": metric_unit', SOURCE)
        self.assertIn('"threshold_value": threshold_value', SOURCE)
        self.assertIn("formatMetricValue(event.threshold_value, event.metric_unit)", FRONTEND)

    def test_calibration_does_not_persist_failed_or_zero_confidence_results(self):
        calibration = SOURCE[SOURCE.find("def calibrate_interface_sample_rate"):SOURCE.find("def calibration_detail")]
        self.assertIn("should_persist = confidence > 0 and snmp_ok and flow_ok", calibration)
        self.assertIn("if should_persist:", calibration)
        self.assertIn('"snmp_ok": snmp_ok', calibration)
        self.assertIn('"flow_ok": flow_ok', calibration)
        self.assertIn('"reason": reason', calibration)

    def test_calibration_diagnostics_endpoint_and_ui_controls_exist(self):
        self.assertIn('@app.get("/api/sensors/{sensor_id}/interfaces/{if_index}/calibration-diagnostics")', SOURCE)
        self.assertIn("Testar SNMP", FRONTEND)
        self.assertIn("Testar Flow bruto", FRONTEND)
        self.assertIn("Janela: ultimos 15 min", FRONTEND)
        self.assertIn("calibration-diagnostics?window_minutes=5", FRONTEND)


if __name__ == "__main__":
    unittest.main()
