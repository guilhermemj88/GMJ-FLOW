import os
import shutil
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from tests.test_collector_apply_static import backend_main


class AiAnomalyIdentifierTest(unittest.TestCase):
    def test_security_anomaly_id_is_action_id_for_ai_analysis(self):
        tmpdir = tempfile.mkdtemp()
        try:
            db_path = str(Path(tmpdir) / "gmjflow.db")
            env = {"GMJFLOW_DB_PATH": db_path}
            request = types.SimpleNamespace(state=types.SimpleNamespace(user={"role": "admin"}))
            anomaly_id = 24
            now = "2026-01-01T00:00:00Z"
            with mock.patch.dict(os.environ, env, clear=False), \
                 mock.patch.object(backend_main, "hash_password", return_value="test-hash"):
                with backend_main.sqlite_connection() as conn:
                    backend_main.ensure_sensor_db()
                    conn.execute(
                        """
                        INSERT INTO security_anomalies (
                            id, vector, severity, status, zone_id, zone_name, template_id, template_name,
                            rule_id, prefix_id, prefix_cidr, domain, direction, src_ip, dst_ip,
                            target_ip, target_cidr, target_role, scope_type, invalid_scope, protocol,
                            packets_s, bits_s, flows, flows_s, packets, bytes, unique_dst_ips,
                            unique_dst_ports, unique_src_ports, first_seen, last_seen, message,
                            recommended_action, response, dedupe_key, anomaly_source, source_engine,
                            source_id, source_name, source_details_json, created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            anomaly_id,
                            "DNS_INTERNAL_IP_HIGH_BITS",
                            "critical",
                            "active",
                            1,
                            "clientes",
                            1,
                            "CLIENTES-PUBLICOS-DEFAULT",
                            5,
                            1,
                            "186.232.172.0/24",
                            "internal_ip",
                            "transmits",
                            "186.232.172.245",
                            "",
                            "186.232.172.245",
                            "186.232.172.245/32",
                            "src_ip",
                            "internal_ip_32",
                            0,
                            "DNS",
                            1200.0,
                            900000.0,
                            10.0,
                            1.0,
                            72000.0,
                            12000000.0,
                            4,
                            1,
                            1,
                            now,
                            now,
                            "DNS alto",
                            "Revisar cliente",
                            "DETECTION_ONLY",
                            "dns|24",
                            "detection_template_rule",
                            "detection_templates",
                            "5",
                            "PREFIX_SUBNET_HIGH_PPS",
                            "{}",
                            now,
                            now,
                        ),
                    )
                    conn.commit()

                payload = backend_main.active_anomalies(request, limit=200)
                item = payload["items"][0]
                self.assertEqual(item["id"], anomaly_id)
                self.assertEqual(item["action_id"], anomaly_id)
                self.assertEqual(item["security_anomaly_id"], anomaly_id)

                analysis = backend_main.get_anomaly_ai_analysis(request, anomaly_id)
                self.assertEqual(analysis["anomaly_id"], anomaly_id)
                self.assertFalse(analysis["available"])

                with self.assertRaises(backend_main.HTTPException) as missing:
                    backend_main.get_anomaly_ai_analysis(request, 688471734)
                self.assertEqual(missing.exception.status_code, 404)
                self.assertEqual(missing.exception.detail["identifier"], 688471734)
                self.assertIn("security_anomalies", missing.exception.detail["tables_checked"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
