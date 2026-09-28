"""COVERAGE-PERF-01 — contrato e equivalencia do payload de flow coverage (sem ClickHouse)."""
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from tests.test_collector_apply_static import backend_main


class _FakeResult:
    column_names: list = []
    result_rows: list = []


def groups_for(seconds=3600):
    """Grupos sinteticos (input_if, output_if) com as 15 colunas da passada unica."""
    rows = []
    for index in range(12):
        general = 1000 * (13 - index)
        rows.append({
            "input_if": 90 + index,
            "output_if": 300 + index,
            "general_bytes": general,
            "general_packets": general // 10,
            "general_flows": index + 1,
            "src_bytes": general - 100,
            "src_packets": (general - 100) // 10,
            "src_flows": index + 2,
            "dst_bytes": general - 200,
            "dst_packets": (general - 200) // 10,
            "dst_flows": index + 3,
            "bytes_src_in_zone": general - 100,
            "bytes_dst_in_zone": general - 200,
            "packets_src_in_zone": (general - 100) // 10,
            "packets_dst_in_zone": (general - 200) // 10,
            "total_flows_src_in_zone": index + 2,
            "total_flows_dst_in_zone": index + 3,
        })
    return rows


class ZoneFlowCoverageTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmpdir) / "gmjflow.db")
        self._patchers = [
            mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": self.db_path}, clear=False),
            mock.patch.object(backend_main, "SENSOR_DB_READY", False),
            mock.patch.object(backend_main, "hash_password", return_value="test-hash"),
            mock.patch.object(backend_main, "ensure_clickhouse_schema", lambda *a, **k: None),
        ]
        for patcher in self._patchers:
            patcher.start()
        backend_main.ensure_sensor_db()
        with backend_main.sqlite_connection() as conn:
            backend_main.ensure_ip_zone_detection_db(conn)
            conn.execute(
                "INSERT INTO ip_zones (name, description, active, detection_template_id, connector_id,"
                " subscriber_addressing_mode, created_at, updated_at)"
                " VALUES ('Zona Teste', '', 1, NULL, NULL, 'cgnat', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')"
            )
            for cidr in ("168.232.197.0/24", "2804:73e0::/32"):
                conn.execute(
                    "INSERT INTO ip_zone_prefixes (zone_id, cidr, name, description, prefix_type, active,"
                    " created_at, updated_at) VALUES (1, ?, '', '', 'client', 1, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')",
                    (cidr,),
                )
            conn.commit()

    def tearDown(self):
        for patcher in reversed(self._patchers):
            patcher.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, groups, calls):
        def fake_query(sql, params=None):
            calls.append(" ".join(str(sql).split()))
            if "GROUP BY input_if, output_if" in sql:
                return _FakeResult()
            rows = groups if False else []
            return _FakeResult()

        # devolve os grupos na 1a chamada e vazio nas demais (top IPs)
        calls.clear()
        state = {"n": 0}

        def fake_query2(sql, params=None):
            state["n"] += 1
            calls.append(" ".join(str(sql).split()))
            result = _FakeResult()
            if "GROUP BY input_if, output_if" in sql:
                result.result_rows = [list(row.values()) for row in groups]
                result.column_names = list(groups[0].keys())
            else:
                result.result_rows = []
                result.column_names = ["ip", "total_bytes", "total_packets", "flows", "bps"]
            return result

        with mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query2), \
             mock.patch.object(backend_main, "rows_as_dicts", side_effect=lambda r: [
                 dict(zip(r.column_names, values)) for values in (r.result_rows or [])
             ]):
            return backend_main.ip_zone_flow_coverage(
                zone_id=1,
                range_minutes=60,
                start=datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc),
                end=datetime(2026, 9, 25, 13, 0, tzinfo=timezone.utc),
                start_time=None,
                end_time=None,
                sensor_id=None,
            )

    def test_payload_contract_and_totals_are_derived_from_single_pass(self):
        groups = groups_for()
        calls = []
        payload = self._run(groups, calls)
        for key in (
            "zone_id", "zone_name", "active_prefixes", "total_bps_src_in_zone", "total_bps_dst_in_zone",
            "total_bytes_src_in_zone", "total_bytes_dst_in_zone", "top_input_output_general",
            "top_input_output_when_src_in_zone", "top_input_output_when_dst_in_zone",
            "top_src_ips_in_zone", "top_dst_ips_in_zone", "warnings",
        ):
            self.assertIn(key, payload)
        seconds = 3600
        self.assertEqual(payload["total_bytes_src_in_zone"], sum(r["bytes_src_in_zone"] for r in groups))
        self.assertEqual(payload["total_bytes_dst_in_zone"], sum(r["bytes_dst_in_zone"] for r in groups))
        self.assertEqual(payload["total_flows_src_in_zone"], sum(r["total_flows_src_in_zone"] for r in groups))
        self.assertEqual(payload["total_packets_dst_in_zone"], sum(r["packets_dst_in_zone"] for r in groups))
        self.assertAlmostEqual(
            payload["total_bps_src_in_zone"],
            round(sum(r["bytes_src_in_zone"] for r in groups) * 8 / seconds, 2),
        )
        # os prefixos canonicos (IPv4 + IPv6) entram no payload
        cidrs = {p["cidr"] for p in payload["active_prefixes"]}
        self.assertEqual(cidrs, {"168.232.197.0/24", "2804:73e0::/32"})

    def test_top_n_and_ordering_per_metric(self):
        groups = groups_for()
        payload = self._run(groups, [])
        general = payload["top_input_output_general"]
        self.assertEqual(len(general), 10)  # Top N preservado
        bps = [item["bps"] for item in general]
        self.assertEqual(bps, sorted(bps, reverse=True))
        # maior general_bytes -> primeiro item (input_if 90)
        self.assertEqual(general[0]["input_if"], 90)
        self.assertEqual(general[0]["output_if"], 300)
        src = payload["top_input_output_when_src_in_zone"]
        self.assertEqual([i["bps"] for i in src], sorted([i["bps"] for i in src], reverse=True))
        dst = payload["top_input_output_when_dst_in_zone"]
        self.assertEqual([i["bps"] for i in dst], sorted([i["bps"] for i in dst], reverse=True))

    def test_single_pass_and_fallback_use_the_same_contract(self):
        # 1a chamada: passada unica; 2 seguintes: top IPs
        calls = []
        self._run(groups_for(), calls)
        self.assertEqual(len(calls), 3, "esperado 3 statements (1 consolidada + 2 de IP)")
        self.assertIn("GROUP BY input_if, output_if", calls[0])
        self.assertIn("sumIf", calls[0])
        self.assertNotIn("WITH TOTALS", calls[0])


if __name__ == "__main__":
    unittest.main()
