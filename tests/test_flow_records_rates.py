import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from tests.test_collector_apply_static import backend_main


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
CLICKHOUSE_INIT = (ROOT / "clickhouse" / "init.sql").read_text(encoding="utf-8")
PARSER = (ROOT / "collector" / "pmacct" / "parse_pmacct.py").read_text(encoding="utf-8")


class FakeClickHouseResult:
    def __init__(self, columns, rows):
        self.column_names = columns
        self.result_rows = rows


FLOW_COLUMNS = [
    "flow_time",
    "sensor",
    "exporter_ip",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "tcp_flags",
    "input_if",
    "output_if",
    "raw_bytes",
    "raw_packets",
    "bytes",
    "packets",
    "flow_count",
    "flow_start",
    "flow_end",
    "duration_ms",
    "duration_seconds",
    "flow_type",
    "sample_rate",
    "sample_rate_applied",
    "src_asn",
    "dst_asn",
    "src_as_name",
    "dst_as_name",
]


class FlowRecordsRatesTest(unittest.TestCase):
    def test_flow_records_ui_marks_rates_unavailable_and_top_flow_keeps_rates(self):
        records_section = FRONTEND[
            FRONTEND.find('<section id="flowRecordsPanel"'):
            FRONTEND.find('<section id="flowTopPanel"')
        ]
        self.assertIn("<th>Taxa</th>", records_section)
        self.assertIn("Taxa indisponivel sem duracao real", FRONTEND)
        self.assertIn("flow.rate_status === 'estimated_from_flow_duration'", FRONTEND)
        self.assertNotIn('data-flow-sort="bits_s"', records_section)
        self.assertNotIn('data-flow-sort="packets_s"', records_section)
        self.assertIn('data-top-flow-sort="bits_s"', FRONTEND)
        self.assertIn('data-top-flow-sort="packets_s"', FRONTEND)

    def test_flow_raw_schema_and_decoder_have_future_duration_fields(self):
        self.assertIn("flow_start Nullable(DateTime64(3, 'UTC')) DEFAULT NULL", CLICKHOUSE_INIT)
        self.assertIn("flow_end Nullable(DateTime64(3, 'UTC')) DEFAULT NULL", CLICKHOUSE_INIT)
        self.assertIn("duration_ms UInt64 DEFAULT 0", CLICKHOUSE_INIT)
        self.assertIn('"flow_start"', PARSER)
        self.assertIn('"flow_end"', PARSER)
        self.assertIn('"duration_ms"', PARSER)

    def test_flow_search_without_sensor_uses_typed_sample_rates_for_two_exporters(self):
        calls = []
        sensor_configs = [
            {
                "sensor_id": 1,
                "exporter_ip": "::ffff:192.0.2.10",
                "default_in": 100,
                "default_out": 200,
                "mode": "sensor_default",
                "interfaces": {},
            },
            {
                "sensor_id": 2,
                "exporter_ip": "2001:db8::20",
                "default_in": 300,
                "default_out": 400,
                "mode": "sensor_default",
                "interfaces": {},
            },
        ]

        def fake_query_clickhouse(query, params=None):
            calls.append((query, dict(params or {})))
            return FakeClickHouseResult(FLOW_COLUMNS, [])

        with (
            mock.patch.object(backend_main, "ensure_clickhouse_schema", return_value=None),
            mock.patch.object(backend_main, "clickhouse_flow_raw_schema", return_value={}),
            mock.patch.object(backend_main, "sensor_sample_rate_config", return_value=None),
            mock.patch.object(backend_main, "sensor_sample_rate_configs", return_value=sensor_configs),
            mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse),
        ):
            payload = backend_main.search_flows_payload(
                range_minutes=60,
                start=None,
                end=None,
                start_time=datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc),
                end_time=datetime(2026, 7, 10, 13, 0, tzinfo=timezone.utc),
                sensor=None,
                sensor_id=None,
                interface_id=None,
                if_index=None,
                ip=None,
                src_ip=None,
                dst_ip=None,
                port=None,
                src_port=None,
                dst_port=None,
                proto=None,
                tcp_flags=None,
                decoder=None,
                limit=10,
                order_by="flow_time",
                order_dir="desc",
            )

        self.assertEqual(payload["items"], [])
        query = calls[0][0]
        self.assertIn("toString(exporter_ip) AS exporter_ip", query)
        self.assertIn("flow_raw.exporter_ip = toIPv6('::ffff:192.0.2.10')", query)
        self.assertIn("flow_raw.exporter_ip = toIPv6('2001:db8::20')", query)
        self.assertNotIn("toString(exporter_ip) = toIPv6", query)
        for rate in (100, 200, 300, 400):
            self.assertIn(f"toFloat64({rate})", query)
        self.assertIn("greatest(toFloat64(sample_rate), 1.0)", query)

    def test_sample_rate_expression_with_sensor_id_keeps_existing_behavior(self):
        config = {
            "default_in": 100,
            "default_out": 200,
            "mode": "per_interface",
            "interfaces": {
                10: {"in": 150, "out": 250, "override": True},
            },
        }

        with (
            mock.patch.object(backend_main, "sensor_sample_rate_config", return_value=config),
            mock.patch.object(
                backend_main,
                "sensor_sample_rate_configs",
                side_effect=AssertionError("multi-exporter config must not be loaded"),
            ),
        ):
            expression = backend_main.clickhouse_sample_rate_expr(
                1,
                "auto",
                10,
                exporter_ip_column="flow_raw.exporter_ip",
            )

        self.assertNotIn("exporter_ip", expression)
        self.assertEqual(
            expression,
            "multiIf(input_if = 10, toFloat64(150), output_if = 10, toFloat64(250), "
            "multiIf(input_if > 0, toFloat64(100), output_if > 0, toFloat64(200), "
            "greatest(toFloat64(sample_rate), 1.0)))",
        )

    def _payload(self, row, schema=None):
        calls = []

        def fake_query_clickhouse(query, params=None):
            calls.append((query, dict(params or {})))
            self.assertNotIn("received_at", query)
            self.assertNotIn("{seconds:Float64}", query)
            self.assertNotIn("/ {{seconds:Float64}}", query)
            return FakeClickHouseResult(FLOW_COLUMNS, [row])

        with mock.patch.object(backend_main, "ensure_clickhouse_schema", return_value=None), \
             mock.patch.object(backend_main, "clickhouse_flow_raw_schema", return_value=schema or {}), \
             mock.patch.object(backend_main, "clickhouse_sample_rate_expr", return_value="1000"), \
             mock.patch.object(backend_main, "query_clickhouse", side_effect=fake_query_clickhouse):
            payload = backend_main.search_flows_payload(
                range_minutes=60,
                start=None,
                end=None,
                start_time=datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc),
                end_time=datetime(2026, 7, 10, 13, 0, tzinfo=timezone.utc),
                sensor=None,
                sensor_id=None,
                interface_id=None,
                if_index=None,
                ip=None,
                src_ip=None,
                dst_ip=None,
                port=None,
                src_port=None,
                dst_port=None,
                proto=None,
                tcp_flags=None,
                decoder=None,
                limit=10,
                order_by="bits_s",
                order_dir="desc",
            )
        return payload, calls

    def test_flow_records_do_not_calculate_rate_without_real_duration(self):
        flow_time = datetime(2026, 7, 10, 12, 30, tzinfo=timezone.utc)
        row = (
            flow_time,
            "edge-a",
            "192.0.2.10",
            "100.64.0.10",
            "8.8.8.8",
            53000,
            53,
            17,
            0,
            10,
            20,
            9000,
            150,
            9_000_000,
            150_000,
            1,
            None,
            None,
            0,
            0,
            "netflow-v9",
            1,
            1000,
            0,
            0,
            "",
            "",
        )
        payload, calls = self._payload(row, schema={})
        item = payload["items"][0]
        self.assertEqual(item["bytes"], 9_000_000)
        self.assertEqual(item["packets"], 150_000)
        self.assertIsNone(item["bits_s"])
        self.assertIsNone(item["packets_s"])
        self.assertIsNone(item["duration_seconds"])
        self.assertEqual(item["rate_status"], "unavailable_no_flow_duration")
        self.assertEqual(payload["order_by"], "bits_s")
        self.assertIn("ORDER BY flow_time DESC", calls[0][0])

    def test_flow_records_reject_subsecond_duration_for_rates(self):
        flow_time = datetime(2026, 7, 10, 12, 30, tzinfo=timezone.utc)
        row = (
            flow_time,
            "edge-a",
            "192.0.2.10",
            "100.64.0.10",
            "8.8.8.8",
            53000,
            53,
            17,
            0,
            10,
            20,
            9000,
            150,
            9_000_000,
            150_000,
            1,
            None,
            None,
            500,
            0.5,
            "netflow-v9",
            1,
            1000,
            0,
            0,
            "",
            "",
        )
        payload, _ = self._payload(row, schema={"duration_ms": "UInt64"})
        item = payload["items"][0]
        self.assertIsNone(item["bits_s"])
        self.assertIsNone(item["packets_s"])
        self.assertEqual(item["duration_seconds"], 0.5)
        self.assertEqual(item["rate_status"], "unavailable_no_flow_duration")

    def test_flow_records_calculate_rate_only_from_exported_duration(self):
        flow_time = datetime(2026, 7, 10, 12, 30, tzinfo=timezone.utc)
        row = (
            flow_time,
            "edge-a",
            "192.0.2.10",
            "100.64.0.10",
            "8.8.8.8",
            53000,
            53,
            17,
            0,
            10,
            20,
            9000,
            150,
            9_000_000,
            150_000,
            1,
            flow_time,
            flow_time,
            2000,
            2.0,
            "netflow-v9",
            1,
            1000,
            0,
            0,
            "",
            "",
        )
        payload, calls = self._payload(row, schema={"duration_ms": "UInt64", "flow_start": "Nullable(DateTime64(3, 'UTC'))", "flow_end": "Nullable(DateTime64(3, 'UTC'))"})
        item = payload["items"][0]
        self.assertEqual(item["bits_s"], 36_000_000)
        self.assertEqual(item["packets_s"], 75_000)
        self.assertEqual(item["duration_seconds"], 2.0)
        self.assertEqual(item["rate_status"], "estimated_from_flow_duration")
        self.assertIn("duration_ms > 0", calls[0][0])
        self.assertIn("dateDiff('millisecond', flow_start, flow_end)", calls[0][0])


if __name__ == "__main__":
    unittest.main()
