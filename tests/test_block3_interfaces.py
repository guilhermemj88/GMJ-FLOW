"""BLOCO 3 — contratos de Sensores/Interfaces, resolver (exporter_ip, ifIndex) e enriquecimento de flows."""
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_collector_apply_static import backend_main


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")


class Block3InterfacesTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmpdir) / "gmjflow.db")
        self._patchers = [
            mock.patch.dict(os.environ, {"GMJFLOW_DB_PATH": self.db_path}, clear=False),
            mock.patch.object(backend_main, "SENSOR_DB_READY", False),
            mock.patch.object(backend_main, "hash_password", return_value="test-hash"),
        ]
        for patcher in self._patchers:
            patcher.start()
        backend_main.ensure_sensor_db()
        backend_main.invalidate_sensor_sample_rate_cache()
        with backend_main.sqlite_connection() as conn:
            conn.executemany(
                "INSERT INTO sensors (name, exporter_ip, active, listener_port, sample_rate_default_in,"
                " sample_rate_default_out, sample_rate_mode, created_at, updated_at)"
                " VALUES (?, ?, 1, ?, 1000, 1000, 'sensor_default', '2026-09-26T00:00:00Z', '2026-09-26T00:00:00Z')",
                [
                    ("NE8000-BGP-FIBINET", "179.189.80.0", 9995),
                    ("NE8000-F1A-IMPLANTAR", "45.163.144.1", 9997),
                ],
            )
            # colisao real de ifIndex entre exporters diferentes
            conn.executemany(
                "INSERT INTO sensor_interfaces (sensor_id, if_index, if_name, if_descr, if_alias, direction,"
                " sample_rate_in, sample_rate_out, sample_rate_override, monitor_enabled, created_at, updated_at)"
                " VALUES (?, ?, ?, '', '', 'Unset', ?, ?, ?, ?, '2026-09-26T00:00:00Z', '2026-09-26T00:00:00Z')",
                [
                    (1, 138, "LINk_AMT_REAL", 908, 708, 1, 1),
                    (1, 140, "IX.SP.IPV4", 1009, 776, 1, 1),
                    (2, 138, "LINK_IP_FALCONNET", 1000, 1000, 1, 0),
                    (2, 90, "Eth-Trunk1", 1000, 1000, 0, 1),
                ],
            )
            conn.commit()

    def tearDown(self):
        for patcher in reversed(self._patchers):
            patcher.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # 1-2. /api/sensors: contrato antigo vs modo leve ---------------------------
    def test_sensors_default_keeps_inline_interfaces_and_light_mode_skips_them(self):
        self.assertTrue(
            "def list_sensors(include_interfaces: bool = Query(True)):" in SOURCE,
            "list_sensors precisa do parametro include_interfaces (default True)",
        )
        with backend_main.sqlite_connection() as conn:
            row = conn.execute("SELECT * FROM sensors WHERE id = 1").fetchone()
            heavy = backend_main.sensor_row_to_dict(conn, row)
            light = backend_main.sensor_row_to_dict(conn, row, include_interfaces=False)
        self.assertIn("interfaces", heavy)
        self.assertEqual(len(heavy["interfaces"]), 2)
        self.assertNotIn("interfaces", light)
        self.assertEqual(light["name"], "NE8000-BGP-FIBINET")

    # 3. cache de sample-rate evita o fan-out O(N^2) ---------------------------
    def test_sample_rate_config_is_cached_per_sensor(self):
        with mock.patch.object(
            backend_main, "sensor_sample_rate_config", wraps=backend_main.sensor_sample_rate_config
        ) as spied:
            for _ in range(5):
                backend_main.get_effective_sample_rate(1, 138, "input")
                backend_main.get_effective_sample_rate(1, 140, "output")
        self.assertEqual(spied.call_count, 1)
        self.assertEqual(backend_main.get_effective_sample_rate(1, 138, "input"), 908)
        self.assertEqual(backend_main.get_effective_sample_rate(1, 140, "output"), 776)
        backend_main.invalidate_sensor_sample_rate_cache(1)
        with mock.patch.object(
            backend_main, "sensor_sample_rate_config", wraps=backend_main.sensor_sample_rate_config
        ) as spied2:
            backend_main.get_effective_sample_rate(1, 138, "input")
        self.assertEqual(spied2.call_count, 1)

    # 4-6. /api/interfaces: paginacao, filtros e source ------------------------
    def test_interfaces_endpoint_is_paginated_server_side(self):
        self.assertTrue('@app.get("/api/interfaces")' in SOURCE, "rota /api/interfaces ausente")
        with backend_main.sqlite_connection() as conn:
            rows, total = backend_main.interface_inventory_rows(conn, limit=2, offset=0)
            self.assertEqual(total, 4)
            self.assertEqual(len(rows), 2)
            page2, _ = backend_main.interface_inventory_rows(conn, limit=2, offset=2)
            self.assertEqual(len(page2), 2)
            items = [backend_main.interface_inventory_item(r) for r in rows]
        self.assertTrue(all(i["source"] == "inventory" for i in items))
        self.assertTrue(all(i["observed"] is None for i in items))

    def test_interfaces_filters_by_sensor_exporter_monitor_and_query(self):
        with backend_main.sqlite_connection() as conn:
            by_sensor, n1 = backend_main.interface_inventory_rows(conn, sensor_id=2)
            by_exporter, n2 = backend_main.interface_inventory_rows(conn, exporter_ip="179.189.80.0")
            only_monitored, n3 = backend_main.interface_inventory_rows(conn, monitor="enabled")
            by_query, n4 = backend_main.interface_inventory_rows(conn, q="Eth-Trunk")
            all_rows, _ = backend_main.interface_inventory_rows(conn)
        self.assertEqual((n1, n2, n3, n4), (2, 2, 3, 1))
        self.assertEqual(len(all_rows), 4)
        self.assertEqual(by_query[0]["if_index"], 90)
        self.assertEqual(n3, 3)

    # 7-11. resolver: chave (exporter_ip, ifIndex) ----------------------------
    def test_same_ifindex_resolves_differently_per_exporter(self):
        with backend_main.sqlite_connection() as conn:
            name_map = backend_main.interface_name_map_for_exporters(
                conn, {"179.189.80.0", "45.163.144.1"}
            )
        self.assertEqual(name_map[("179.189.80.0", 138)]["if_name"], "LINk_AMT_REAL")
        self.assertEqual(name_map[("45.163.144.1", 138)]["if_name"], "LINK_IP_FALCONNET")
        self.assertEqual(len(name_map), 4)

    def test_wrong_exporter_does_not_resolve_and_falls_back_to_raw_ifindex(self):
        with backend_main.sqlite_connection() as conn:
            name_map = backend_main.interface_name_map_for_exporters(conn, {"179.189.80.0"})
        items = [{"exporter_ip": "45.163.144.1", "input_if": 138, "output_if": 999}]
        backend_main.enrich_flow_rows_with_interfaces(items, name_map)
        row = items[0]
        # exporter errado: nao resolve nome, mas o ifIndex cru permanece intacto
        self.assertEqual(row["input_if"], 138)
        self.assertEqual(row["input_if_name"], "")
        self.assertEqual(row["input_interface_source"], "observed")
        self.assertEqual(row["input_interface_key"], "45.163.144.1|138")
        self.assertEqual(row["output_if"], 999)
        self.assertEqual(row["output_interface_source"], "observed")

    def test_inventory_wins_over_observed_and_ingress_egress_are_independent(self):
        with backend_main.sqlite_connection() as conn:
            name_map = backend_main.interface_name_map_for_exporters(conn, {"179.189.80.0"})
        items = [{"exporter_ip": "179.189.80.0", "input_if": 138, "output_if": 140}]
        backend_main.enrich_flow_rows_with_interfaces(items, name_map)
        row = items[0]
        self.assertEqual(row["input_if_name"], "LINk_AMT_REAL")
        self.assertEqual(row["output_if_name"], "IX.SP.IPV4")
        self.assertEqual(row["input_interface_source"], "inventory")
        self.assertEqual(row["output_interface_source"], "inventory")
        self.assertEqual(row["input_interface_sensor_id"], 1)
        self.assertNotEqual(row["input_if_name"], row["output_if_name"])

    # 12. options/interfaces: contrato de source documentado -------------------
    def test_options_interfaces_contract_declares_source(self):
        peak_api = (ROOT / "backend" / "app" / "api" / "peak_hunter.py").read_text(encoding="utf-8")
        self.assertTrue("def peak_hunter_interface_options" in peak_api, "endpoint do Peak Hunter ausente")
        self.assertTrue('"source": "inventory"' in SOURCE, "itens de /api/interfaces precisam declarar origem")

    def test_flows_search_keeps_raw_ifindex_and_adds_resolved_names(self):
        self.assertTrue(
            "            input_if,\n            output_if," in SOURCE,
            "o SELECT do flows/search deve manter input_if/output_if crus",
        )
        self.assertTrue(
            "enrich_flow_rows_with_interfaces(items, name_map)" in SOURCE,
            "flows/search deve chamar o enriquecimento aditivo",
        )
        self.assertTrue(
            '_interface_key"] = f"' in SOURCE,
            "o enriquecimento deve montar a chave (exporter|ifIndex)",
        )


if __name__ == "__main__":
    unittest.main()
